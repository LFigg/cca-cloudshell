"""
AWS database resource collection.

Collects RDS instances/clusters, DynamoDB, ElastiCache, Redshift, DocumentDB,
Neptune, OpenSearch, MemoryDB, and Timestream.
"""
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import boto3

from lib.constants import BYTES_PER_GB
from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error, format_bytes_to_gb

logger = logging.getLogger(__name__)


# =============================================================================
# RDS Collectors
# =============================================================================

def _get_tde_option_groups(rds_client) -> set:
    """Get set of option group names that have TDE enabled.

    TDE (Transparent Data Encryption) is enabled via Option Groups for:
    - SQL Server: TRANSPARENT_DATA_ENCRYPTION option
    - Oracle: TDE or TDE_HSM option

    Returns:
        Set of option group names with TDE enabled
    """
    tde_option_groups = set()
    tde_options = {'TRANSPARENT_DATA_ENCRYPTION', 'TDE', 'TDE_HSM'}

    try:
        paginator = rds_client.get_paginator('describe_option_groups')
        for page in paginator.paginate():
            for og in page.get('OptionGroupsList', []):
                og_name = og.get('OptionGroupName', '')
                for option in og.get('Options', []):
                    if option.get('OptionName', '').upper() in tde_options:
                        tde_option_groups.add(og_name)
                        break
    except Exception as e:
        logger.debug(f"Failed to check option groups for TDE: {e}")

    return tde_option_groups


def collect_rds_instances(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect RDS database instances."""
    resources = []
    try:
        rds = session.client('rds', region_name=region)
        paginator = rds.get_paginator('describe_db_instances')

        # Cache option groups with TDE enabled for this region
        tde_option_groups = _get_tde_option_groups(rds)

        for page in paginator.paginate():
            for db in page['DBInstances']:
                # Check if this is a read replica
                replica_source = db.get('ReadReplicaSourceDBInstanceIdentifier')
                replica_ids = db.get('ReadReplicaDBInstanceIdentifiers', [])

                # Check for TDE (SQL Server/Oracle use Option Groups, others use StorageEncrypted)
                engine = db.get('Engine', '').lower()
                option_group_name = None
                for og in db.get('OptionGroupMemberships', []):
                    option_group_name = og.get('OptionGroupName')
                    break

                # Determine TDE status
                tde_enabled = False
                if engine in ['sqlserver-ee', 'sqlserver-se', 'oracle-ee', 'oracle-se2']:
                    # SQL Server Enterprise/Standard and Oracle use Option Groups for TDE
                    if option_group_name and option_group_name in tde_option_groups:
                        tde_enabled = True
                # Note: Aurora and other engines don't support TDE, only storage encryption

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:rds:instance",
                    service_family="RDS",
                    resource_id=db.get('DBInstanceArn', ''),
                    name=db.get('DBInstanceIdentifier', ''),
                    tags={},
                    size_gb=float(db.get('AllocatedStorage', 0)),
                    metadata={
                        'engine': db.get('Engine'),
                        'engine_version': db.get('EngineVersion'),
                        'instance_class': db.get('DBInstanceClass'),
                        'status': db.get('DBInstanceStatus'),
                        'multi_az': db.get('MultiAZ', False),
                        'encrypted': db.get('StorageEncrypted', False),
                        'tde_enabled': tde_enabled,
                        'option_group': option_group_name,
                        'is_read_replica': bool(replica_source),
                        'read_replica_source': replica_source,
                        'read_replica_ids': replica_ids,
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} RDS instances")
    except Exception as e:
        check_and_raise_auth_error(e, "collect RDS instances", "aws")
        logger.error(f"[{region}] Failed to collect RDS instances: {e}")

    return resources


def get_aurora_cluster_storage(session: boto3.Session, region: str, cluster_id: str) -> float:
    """Get actual storage used by an Aurora cluster from CloudWatch metrics.

    Aurora clusters report AllocatedStorage as 1 in the RDS API, but the actual
    storage can be retrieved from CloudWatch's VolumeBytesUsed metric.

    Note: For multiple clusters, use get_aurora_cluster_storage_batch() which is
    more efficient (single API call vs N calls).

    Args:
        session: boto3 session
        region: AWS region
        cluster_id: Aurora cluster identifier (not ARN)

    Returns:
        Storage in GB, or 0.0 if metric unavailable
    """
    try:
        cloudwatch = session.client('cloudwatch', region_name=region)

        # Get the most recent VolumeBytesUsed metric (last 24 hours)
        response = cloudwatch.get_metric_statistics(
            Namespace='AWS/RDS',
            MetricName='VolumeBytesUsed',
            Dimensions=[
                {'Name': 'DBClusterIdentifier', 'Value': cluster_id}
            ],
            StartTime=datetime.now(timezone.utc) - timedelta(hours=24),
            EndTime=datetime.now(timezone.utc),
            Period=3600,  # 1 hour granularity
            Statistics=['Average']
        )

        datapoints = response.get('Datapoints', [])
        if datapoints:
            # Get the most recent datapoint
            latest = max(datapoints, key=lambda x: x['Timestamp'])
            bytes_used = latest.get('Average', 0)
            # Convert bytes to GB
            return round(bytes_used / (1024 ** 3), 2)
    except Exception as e:
        logger.debug(f"[{region}] Could not get CloudWatch storage for Aurora cluster {cluster_id}: {e}")

    return 0.0


def get_aurora_cluster_storage_batch(session: boto3.Session, region: str, cluster_ids: List[str]) -> Dict[str, float]:
    """Batch fetch storage for multiple Aurora clusters using GetMetricData API.

    Uses CloudWatch's get_metric_data API which can fetch up to 500 metrics
    in a single call, much more efficient than individual get_metric_statistics calls.

    Args:
        session: boto3 session
        region: AWS region
        cluster_ids: List of Aurora cluster identifiers

    Returns:
        Dict mapping cluster_id to storage in GB (missing clusters return 0.0)
    """
    if not cluster_ids:
        return {}

    results = {cid: 0.0 for cid in cluster_ids}

    try:
        cloudwatch = session.client('cloudwatch', region_name=region)

        # Build metric queries for all clusters (max 500 per API call)
        # Use sanitized IDs for metric query IDs (must match [a-z][a-zA-Z0-9_]*)
        queries = []
        id_map = {}  # Map query ID back to cluster ID

        for i, cluster_id in enumerate(cluster_ids):
            query_id = f"m{i}"
            id_map[query_id] = cluster_id
            queries.append({
                'Id': query_id,
                'MetricStat': {
                    'Metric': {
                        'Namespace': 'AWS/RDS',
                        'MetricName': 'VolumeBytesUsed',
                        'Dimensions': [{'Name': 'DBClusterIdentifier', 'Value': cluster_id}]
                    },
                    'Period': 3600,
                    'Stat': 'Average'
                },
                'ReturnData': True
            })

        # Batch in groups of 500 (CloudWatch limit)
        start_time = datetime.now(timezone.utc) - timedelta(hours=24)
        end_time = datetime.now(timezone.utc)

        for batch_start in range(0, len(queries), 500):
            batch_queries = queries[batch_start:batch_start + 500]

            response = cloudwatch.get_metric_data(
                MetricDataQueries=batch_queries,
                StartTime=start_time,
                EndTime=end_time
            )

            # Process results
            for metric_result in response.get('MetricDataResults', []):
                query_id = metric_result.get('Id', '')
                values = metric_result.get('Values', [])

                if query_id in id_map and values:
                    # Get most recent value (values are sorted newest first)
                    bytes_used = values[0]
                    cluster_id = id_map[query_id]
                    results[cluster_id] = round(bytes_used / BYTES_PER_GB, 2)

        logger.debug(f"[{region}] Batch fetched CloudWatch storage for {len(cluster_ids)} Aurora clusters")
    except Exception as e:
        logger.debug(f"[{region}] Could not batch fetch CloudWatch storage: {e}")

    return results


def collect_rds_clusters(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect RDS Aurora clusters.

    Optimized with batch CloudWatch metrics fetch (CR-023).
    """
    resources = []
    try:
        rds = session.client('rds', region_name=region)
        paginator = rds.get_paginator('describe_db_clusters')

        # Phase 1: Collect all cluster data
        clusters_data = []
        aurora_cluster_ids = []

        for page in paginator.paginate():
            for cluster in page['DBClusters']:
                cluster_id = cluster.get('DBClusterIdentifier', '')
                api_storage = float(cluster.get('AllocatedStorage', 0))

                clusters_data.append({
                    'cluster': cluster,
                    'cluster_id': cluster_id,
                    'api_storage': api_storage
                })

                # Track Aurora clusters that need CloudWatch lookup (API reports 1 for Aurora)
                if api_storage <= 1:
                    aurora_cluster_ids.append(cluster_id)

        if not clusters_data:
            logger.info(f"[{region}] Found 0 RDS clusters")
            return resources

        # Phase 2: Batch fetch CloudWatch storage for Aurora clusters
        cloudwatch_storage = {}
        if aurora_cluster_ids:
            cloudwatch_storage = get_aurora_cluster_storage_batch(session, region, aurora_cluster_ids)

        # Phase 3: Build CloudResource objects
        for data in clusters_data:
            cluster = data['cluster']
            cluster_id = data['cluster_id']
            api_storage = data['api_storage']

            # Use CloudWatch value if available and API reports placeholder value
            cw_storage = cloudwatch_storage.get(cluster_id, 0.0)
            actual_storage = cw_storage if cw_storage > 0 and api_storage <= 1 else api_storage

            resource = CloudResource(
                provider="aws",
                account_id=account_id,
                region=region,
                resource_type="aws:rds:cluster",
                service_family="RDS",
                resource_id=cluster.get('DBClusterArn', ''),
                name=cluster_id,
                tags={},
                size_gb=actual_storage,
                metadata={
                    'engine': cluster.get('Engine'),
                    'engine_version': cluster.get('EngineVersion'),
                    'status': cluster.get('Status'),
                    'multi_az': cluster.get('MultiAZ', False),
                    'encrypted': cluster.get('StorageEncrypted', False),
                    'storage_source': 'cloudwatch' if cw_storage > 0 and api_storage <= 1 else 'api'
                }
            )
            resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} RDS clusters")
    except Exception as e:
        check_and_raise_auth_error(e, "collect RDS clusters", "aws")
        logger.error(f"[{region}] Failed to collect RDS clusters: {e}")

    return resources


def collect_rds_snapshots(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect RDS DB snapshots."""
    resources = []
    try:
        rds = session.client('rds', region_name=region)
        paginator = rds.get_paginator('describe_db_snapshots')

        for page in paginator.paginate():
            for snapshot in page.get('DBSnapshots', []):
                snapshot_id = snapshot.get('DBSnapshotIdentifier', '')

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:rds:snapshot",
                    service_family="RDS",
                    resource_id=snapshot.get('DBSnapshotArn', ''),
                    name=snapshot_id,
                    tags={},
                    size_gb=float(snapshot.get('AllocatedStorage', 0)),
                    parent_resource_id=snapshot.get('DBInstanceIdentifier'),
                    metadata={
                        'db_instance_id': snapshot.get('DBInstanceIdentifier'),
                        'engine': snapshot.get('Engine'),
                        'status': snapshot.get('Status'),
                        'snapshot_type': snapshot.get('SnapshotType'),
                        'encrypted': snapshot.get('Encrypted', False),
                        'snapshot_create_time': str(snapshot.get('SnapshotCreateTime', ''))
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} RDS snapshots")
    except Exception as e:
        check_and_raise_auth_error(e, "collect RDS snapshots", "aws")
        logger.error(f"[{region}] Failed to collect RDS snapshots: {e}")

    return resources


def collect_rds_cluster_snapshots(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect RDS Aurora cluster snapshots."""
    resources = []
    try:
        rds = session.client('rds', region_name=region)
        paginator = rds.get_paginator('describe_db_cluster_snapshots')

        for page in paginator.paginate():
            for snapshot in page.get('DBClusterSnapshots', []):
                snapshot_id = snapshot.get('DBClusterSnapshotIdentifier', '')

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:rds:cluster-snapshot",
                    service_family="RDS",
                    resource_id=snapshot.get('DBClusterSnapshotArn', ''),
                    name=snapshot_id,
                    tags={},
                    size_gb=float(snapshot.get('AllocatedStorage', 0)),
                    parent_resource_id=snapshot.get('DBClusterIdentifier'),
                    metadata={
                        'db_cluster_id': snapshot.get('DBClusterIdentifier'),
                        'engine': snapshot.get('Engine'),
                        'status': snapshot.get('Status'),
                        'snapshot_type': snapshot.get('SnapshotType'),
                        'encrypted': snapshot.get('StorageEncrypted', False),
                        'snapshot_create_time': str(snapshot.get('SnapshotCreateTime', ''))
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} RDS cluster snapshots")
    except Exception as e:
        check_and_raise_auth_error(e, "collect RDS cluster snapshots", "aws")
        logger.error(f"[{region}] Failed to collect RDS cluster snapshots: {e}")

    return resources


# =============================================================================
# DynamoDB Collector
# =============================================================================

def collect_dynamodb_tables(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect DynamoDB tables.

    Note: DynamoDB has no batch describe API, so we parallelize describe_table
    calls to improve performance. API call count remains O(n) but wall-clock
    time is significantly reduced.
    """
    resources = []
    try:
        dynamodb = session.client('dynamodb', region_name=region)
        paginator = dynamodb.get_paginator('list_tables')

        # Collect all table names first
        table_names = []
        for page in paginator.paginate():
            table_names.extend(page['TableNames'])

        if not table_names:
            logger.info(f"[{region}] Found 0 DynamoDB tables")
            return resources

        def describe_table(table_name: str) -> Optional[CloudResource]:
            """Describe a single table and return CloudResource."""
            try:
                table = dynamodb.describe_table(TableName=table_name)['Table']
                size_bytes = table.get('TableSizeBytes', 0)

                return CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:dynamodb:table",
                    service_family="DynamoDB",
                    resource_id=table.get('TableArn', ''),
                    name=table_name,
                    tags={},
                    size_gb=format_bytes_to_gb(size_bytes),
                    metadata={
                        'status': table.get('TableStatus'),
                        'item_count': table.get('ItemCount', 0),
                        'billing_mode': table.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED')
                    }
                )
            except Exception as e:
                check_and_raise_auth_error(e, f"describe DynamoDB table {table_name}", "aws")
                logger.warning(f"[{region}] Failed to describe DynamoDB table {table_name}: {e}")
                return None

        # Parallelize describe_table calls (max 10 concurrent to avoid throttling)
        max_workers = min(10, len(table_names))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(describe_table, name): name for name in table_names}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    resources.append(result)

        logger.info(f"[{region}] Found {len(resources)} DynamoDB tables")
    except Exception as e:
        check_and_raise_auth_error(e, "collect DynamoDB tables", "aws")
        logger.error(f"[{region}] Failed to collect DynamoDB tables: {e}")

    return resources


# =============================================================================
# ElastiCache Collector
# =============================================================================

def collect_elasticache_clusters(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect ElastiCache clusters."""
    resources = []
    try:
        elasticache = session.client('elasticache', region_name=region)
        paginator = elasticache.get_paginator('describe_cache_clusters')

        for page in paginator.paginate(ShowCacheNodeInfo=True):
            for cluster in page['CacheClusters']:
                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:elasticache:cluster",
                    service_family="ElastiCache",
                    resource_id=cluster.get('ARN', cluster['CacheClusterId']),
                    name=cluster['CacheClusterId'],
                    tags={},
                    size_gb=0.0,
                    metadata={
                        'engine': cluster.get('Engine'),
                        'engine_version': cluster.get('EngineVersion'),
                        'node_type': cluster.get('CacheNodeType'),
                        'num_nodes': cluster.get('NumCacheNodes', 0),
                        'status': cluster.get('CacheClusterStatus')
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} ElastiCache clusters")
    except Exception as e:
        check_and_raise_auth_error(e, "collect ElastiCache", "aws")
        logger.error(f"[{region}] Failed to collect ElastiCache: {e}")

    return resources


# =============================================================================
# Redshift Collector
# =============================================================================

def collect_redshift_clusters(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect Amazon Redshift clusters."""
    resources = []
    try:
        redshift = session.client('redshift', region_name=region)
        paginator = redshift.get_paginator('describe_clusters')

        for page in paginator.paginate():
            for cluster in page.get('Clusters', []):
                cluster_id = cluster.get('ClusterIdentifier', '')

                # Calculate total storage from number of nodes * node storage
                num_nodes = cluster.get('NumberOfNodes', 1)
                node_type = cluster.get('NodeType', '')

                # Redshift node storage estimates (GB per node)
                node_storage_map = {
                    'dc2.large': 160, 'dc2.8xlarge': 2560,
                    'ra3.xlplus': 32000, 'ra3.4xlarge': 128000, 'ra3.16xlarge': 128000,
                    'ds2.xlarge': 2000, 'ds2.8xlarge': 16000,
                }
                storage_per_node = node_storage_map.get(node_type, 0)
                total_storage_gb = num_nodes * storage_per_node

                tags = {t['Key']: t['Value'] for t in cluster.get('Tags', [])}

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:redshift:cluster",
                    service_family="Redshift",
                    resource_id=f"arn:aws:redshift:{region}:{account_id}:cluster:{cluster_id}",
                    name=cluster_id,
                    tags=tags,
                    size_gb=float(total_storage_gb),
                    metadata={
                        'node_type': node_type,
                        'number_of_nodes': num_nodes,
                        'cluster_status': cluster.get('ClusterStatus'),
                        'db_name': cluster.get('DBName'),
                        'encrypted': cluster.get('Encrypted', False),
                        'total_storage_capacity_gb': total_storage_gb,
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} Redshift clusters")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Redshift clusters", "aws")
        logger.error(f"[{region}] Failed to collect Redshift clusters: {e}")

    return resources


# =============================================================================
# DocumentDB Collector
# =============================================================================

def collect_documentdb_clusters(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect Amazon DocumentDB (MongoDB-compatible) clusters."""
    resources = []
    try:
        docdb = session.client('docdb', region_name=region)
        paginator = docdb.get_paginator('describe_db_clusters')

        for page in paginator.paginate(Filters=[{'Name': 'engine', 'Values': ['docdb']}]):
            for cluster in page.get('DBClusters', []):
                cluster_id = cluster.get('DBClusterIdentifier', '')

                # Get storage used if available
                storage_gb = float(cluster.get('AllocatedStorage', 0))

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:docdb:cluster",
                    service_family="DocumentDB",
                    resource_id=cluster.get('DBClusterArn', ''),
                    name=cluster_id,
                    tags={},
                    size_gb=storage_gb,
                    metadata={
                        'status': cluster.get('Status'),
                        'engine': cluster.get('Engine'),
                        'engine_version': cluster.get('EngineVersion'),
                        'db_cluster_members': len(cluster.get('DBClusterMembers', [])),
                        'storage_encrypted': cluster.get('StorageEncrypted', False),
                        'backup_retention_period': cluster.get('BackupRetentionPeriod'),
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} DocumentDB clusters")
    except Exception as e:
        check_and_raise_auth_error(e, "collect DocumentDB clusters", "aws")
        logger.error(f"[{region}] Failed to collect DocumentDB clusters: {e}")

    return resources


# =============================================================================
# Neptune Collector
# =============================================================================

def collect_neptune_clusters(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect Amazon Neptune (graph database) clusters."""
    resources = []
    try:
        neptune = session.client('neptune', region_name=region)
        paginator = neptune.get_paginator('describe_db_clusters')

        for page in paginator.paginate(Filters=[{'Name': 'engine', 'Values': ['neptune']}]):
            for cluster in page.get('DBClusters', []):
                cluster_id = cluster.get('DBClusterIdentifier', '')

                # Neptune storage is auto-scaling, allocated storage is estimate
                storage_gb = float(cluster.get('AllocatedStorage', 0))

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:neptune:cluster",
                    service_family="Neptune",
                    resource_id=cluster.get('DBClusterArn', ''),
                    name=cluster_id,
                    tags={},
                    size_gb=storage_gb,
                    metadata={
                        'status': cluster.get('Status'),
                        'engine': cluster.get('Engine'),
                        'engine_version': cluster.get('EngineVersion'),
                        'db_cluster_members': len(cluster.get('DBClusterMembers', [])),
                        'storage_encrypted': cluster.get('StorageEncrypted', False),
                        'backup_retention_period': cluster.get('BackupRetentionPeriod'),
                        'serverless': cluster.get('ServerlessV2ScalingConfiguration') is not None,
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} Neptune clusters")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Neptune clusters", "aws")
        logger.error(f"[{region}] Failed to collect Neptune clusters: {e}")

    return resources


# =============================================================================
# OpenSearch Service Collector
# =============================================================================

def collect_opensearch_domains(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect Amazon OpenSearch Service domains."""
    resources = []
    try:
        opensearch = session.client('opensearch', region_name=region)

        # List all domain names first
        domain_list = opensearch.list_domain_names().get('DomainNames', [])
        domain_names = [d['DomainName'] for d in domain_list]

        if domain_names:
            # Describe domains in batches (max 5 per call)
            for i in range(0, len(domain_names), 5):
                batch = domain_names[i:i+5]
                domains_info = opensearch.describe_domains(DomainNames=batch)

                for domain in domains_info.get('DomainStatusList', []):
                    domain_name = domain.get('DomainName', '')

                    # Calculate storage from EBS config
                    ebs_options = domain.get('EBSOptions', {})
                    cluster_config = domain.get('ClusterConfig', {})

                    volume_size = ebs_options.get('VolumeSize', 0)
                    instance_count = cluster_config.get('InstanceCount', 1)
                    total_storage_gb = volume_size * instance_count

                    # Add warm storage if configured
                    if cluster_config.get('WarmEnabled'):
                        warm_count = cluster_config.get('WarmCount', 0)
                        # Warm nodes have fixed storage based on type
                        warm_storage = warm_count * 500  # Approximate
                        total_storage_gb += warm_storage

                    tags = domain.get('Tags', {})
                    if isinstance(tags, list):
                        tags = {t['Key']: t['Value'] for t in tags}

                    resource = CloudResource(
                        provider="aws",
                        account_id=account_id,
                        region=region,
                        resource_type="aws:opensearch:domain",
                        service_family="OpenSearch",
                        resource_id=domain.get('ARN', ''),
                        name=domain_name,
                        tags=tags,
                        size_gb=float(total_storage_gb),
                        metadata={
                            'engine_version': domain.get('EngineVersion'),
                            'instance_type': cluster_config.get('InstanceType'),
                            'instance_count': instance_count,
                            'dedicated_master_enabled': cluster_config.get('DedicatedMasterEnabled', False),
                            'zone_awareness_enabled': cluster_config.get('ZoneAwarenessEnabled', False),
                            'warm_enabled': cluster_config.get('WarmEnabled', False),
                            'ebs_enabled': ebs_options.get('EBSEnabled', False),
                            'volume_type': ebs_options.get('VolumeType'),
                            'processing': domain.get('Processing', False),
                        }
                    )
                    resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} OpenSearch domains")
    except Exception as e:
        check_and_raise_auth_error(e, "collect OpenSearch domains", "aws")
        logger.error(f"[{region}] Failed to collect OpenSearch domains: {e}")

    return resources


# =============================================================================
# MemoryDB for Redis Collector
# =============================================================================

def collect_memorydb_clusters(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect Amazon MemoryDB for Redis clusters."""
    resources = []
    try:
        memorydb = session.client('memorydb', region_name=region)

        # List all clusters
        clusters_response = memorydb.describe_clusters()

        for cluster in clusters_response.get('Clusters', []):
            cluster_name = cluster.get('Name', '')

            # Calculate data size from shards and node type
            num_shards = cluster.get('NumberOfShards', 1)
            node_type = cluster.get('NodeType', '')

            # MemoryDB node memory sizes (GB) - data size estimate
            node_memory_map = {
                'db.t4g.small': 1.37, 'db.t4g.medium': 3.09,
                'db.r6g.large': 13.07, 'db.r6g.xlarge': 26.32,
                'db.r6g.2xlarge': 52.82, 'db.r6g.4xlarge': 105.81,
                'db.r6g.8xlarge': 209.55, 'db.r6g.12xlarge': 317.77,
                'db.r6g.16xlarge': 419.09,
                'db.r7g.large': 13.07, 'db.r7g.xlarge': 26.32,
                'db.r7g.2xlarge': 52.82, 'db.r7g.4xlarge': 105.81,
            }
            memory_per_node = node_memory_map.get(node_type, 0)
            replicas = cluster.get('NumReplicasPerShard', 0) + 1  # +1 for primary
            total_memory_gb = num_shards * replicas * memory_per_node

            resource = CloudResource(
                provider="aws",
                account_id=account_id,
                region=region,
                resource_type="aws:memorydb:cluster",
                service_family="MemoryDB",
                resource_id=cluster.get('ARN', ''),
                name=cluster_name,
                tags={},
                size_gb=float(total_memory_gb),
                metadata={
                    'status': cluster.get('Status'),
                    'node_type': node_type,
                    'number_of_shards': num_shards,
                    'num_replicas_per_shard': cluster.get('NumReplicasPerShard', 0),
                    'engine_version': cluster.get('EngineVersion'),
                    'tls_enabled': cluster.get('TLSEnabled', False),
                    'snapshot_retention_limit': cluster.get('SnapshotRetentionLimit', 0),
                    'data_tiering': cluster.get('DataTiering', 'false'),
                }
            )
            resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} MemoryDB clusters")
    except Exception as e:
        check_and_raise_auth_error(e, "collect MemoryDB clusters", "aws")
        logger.error(f"[{region}] Failed to collect MemoryDB clusters: {e}")

    return resources


# =============================================================================
# Timestream Collector
# =============================================================================

def collect_timestream_databases(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect Amazon Timestream databases and tables."""
    resources = []
    try:
        timestream = session.client('timestream-write', region_name=region)

        # List databases
        paginator = timestream.get_paginator('list_databases')

        for page in paginator.paginate():
            for db in page.get('Databases', []):
                db_name = db.get('DatabaseName', '')

                # List tables in database
                table_paginator = timestream.get_paginator('list_tables')
                for table_page in table_paginator.paginate(DatabaseName=db_name):
                    for table in table_page.get('Tables', []):
                        table_name = table.get('TableName', '')

                        # Get table details for metrics
                        try:
                            table_details = timestream.describe_table(
                                DatabaseName=db_name,
                                TableName=table_name
                            ).get('Table', {})

                            # Storage metrics (if available)
                            table_details.get('MagneticStoreWriteProperties', {}).get('MagneticStoreRejectedDataLocation', {})
                            retention_memory = table_details.get('RetentionProperties', {}).get('MemoryStoreRetentionPeriodInHours', 0)
                            retention_magnetic = table_details.get('RetentionProperties', {}).get('MagneticStoreRetentionPeriodInDays', 0)
                        except Exception:
                            retention_memory = 0
                            retention_magnetic = 0

                        resource = CloudResource(
                            provider="aws",
                            account_id=account_id,
                            region=region,
                            resource_type="aws:timestream:table",
                            service_family="Timestream",
                            resource_id=table.get('Arn', ''),
                            name=f"{db_name}/{table_name}",
                            tags={},
                            size_gb=0.0,  # Timestream doesn't expose storage size directly
                            metadata={
                                'database_name': db_name,
                                'table_name': table_name,
                                'table_status': table.get('TableStatus'),
                                'memory_retention_hours': retention_memory,
                                'magnetic_retention_days': retention_magnetic,
                            }
                        )
                        resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} Timestream tables")
    except Exception as e:
        # Timestream is not available in all regions
        if 'not available' in str(e).lower() or 'not supported' in str(e).lower():
            logger.debug(f"[{region}] Timestream not available in this region")
        else:
            logger.error(f"[{region}] Failed to collect Timestream: {e}")

    return resources
