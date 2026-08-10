# GCP Database collectors
"""Collectors for Cloud SQL, Memorystore, BigQuery, Spanner, Bigtable, and AlloyDB."""

import logging
from typing import List

from lib.gcp.utils import extract_location_from_name
from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error

logger = logging.getLogger(__name__)


def collect_cloud_sql_instances(project_id: str) -> List[CloudResource]:
    """
    Collect Cloud SQL instances using Discovery API.

    Args:
        project_id: GCP project ID

    Returns:
        List of CloudResource objects for Cloud SQL instances

    Example:
        instances = collect_cloud_sql_instances("my-gcp-project")
    """
    import google.auth
    from googleapiclient.discovery import build as discovery_build

    resources = []
    try:
        credentials, _ = google.auth.default()
        service = discovery_build('sqladmin', 'v1beta4', credentials=credentials)

        request = service.instances().list(project=project_id)
        while request is not None:
            response = request.execute()
            for instance in response.get('items', []):
                settings = instance.get('settings', {})
                labels = settings.get('userLabels', {})
                # dataDiskSizeGb is the provisioned disk size, not actual data
                # used. Cloud Monitoring likely has a real-usage metric (e.g.
                # cloudsql.googleapis.com/database/disk/bytes_used), but it
                # hasn't been verified against docs/SDK yet, so size_gb stays
                # 0.0/unavailable. See docs/v2-refactor-plan.md.
                provisioned_gb = int(settings.get('dataDiskSizeGb', 0))
                is_read_replica = bool(instance.get('masterInstanceName'))

                resource = CloudResource(
                    provider="gcp",
                    account_id=project_id,
                    region=instance.get('region', ''),
                    resource_type="gcp:sql:instance",
                    service_family="SQL",
                    resource_id=f"projects/{project_id}/instances/{instance.get('name')}",
                    name=instance.get('name', ''),
                    tags=labels,
                    size_gb=0.0,
                    metadata={
                        'database_version': instance.get('databaseVersion', ''),
                        'tier': settings.get('tier', ''),
                        'state': instance.get('state', ''),
                        'backend_type': instance.get('backendType', ''),
                        'availability_type': settings.get('availabilityType', ''),
                        'backup_enabled': settings.get('backupConfiguration', {}).get('enabled', False),
                        'is_read_replica': is_read_replica,
                        'master_instance_name': instance.get('masterInstanceName'),
                        'encrypted': True,
                        'provisioned_storage_gb': float(provisioned_gb),
                        'size_source': 'unavailable',
                    }
                )
                resources.append(resource)
            request = service.instances().list_next(previous_request=request, previous_response=response)

        logger.info(f"Found {len(resources)} Cloud SQL instances")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Cloud SQL instances", "gcp")
        logger.error(f"Failed to collect Cloud SQL instances: {e}")

    return resources


def collect_memorystore_redis(project_id: str) -> List[CloudResource]:
    """
    Collect Memorystore for Redis instances.

    Args:
        project_id: GCP project ID

    Returns:
        List of CloudResource objects for Redis instances
    """
    resources = []
    try:
        from google.cloud import redis_v1

        client = redis_v1.CloudRedisClient()

        # List instances in all locations
        parent = f"projects/{project_id}/locations/-"

        for instance in client.list_instances(parent=parent):
            labels = dict(instance.labels) if instance.labels else {}

            # Extract location
            location = extract_location_from_name(instance.name)

            # memory_size_gb is the provisioned instance capacity, not actual
            # used memory. Cloud Monitoring likely has a real-usage metric
            # (e.g. redis.googleapis.com/stats/memory/usage_ratio, multiplied
            # against this capacity), but it hasn't been verified against
            # docs/SDK yet, so size_gb stays 0.0/unavailable. See
            # docs/v2-refactor-plan.md.
            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region=location,
                resource_type="gcp:redis:instance",
                service_family="Redis",
                resource_id=instance.name,
                name=instance.display_name or instance.name.split('/')[-1],
                tags=labels,
                size_gb=0.0,
                metadata={
                    'state': instance.state.name if instance.state else '',
                    'tier': instance.tier.name if instance.tier else '',
                    'redis_version': instance.redis_version,
                    'provisioned_capacity_gb': float(instance.memory_size_gb) if instance.memory_size_gb else 0.0,
                    'host': instance.host,
                    'port': instance.port,
                    'size_source': 'unavailable',
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Memorystore Redis instances")
    except ImportError:
        logger.warning("Redis client not available")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Memorystore Redis instances", "gcp")
        logger.error(f"Failed to collect Memorystore Redis instances: {e}")

    return resources


def collect_bigquery_datasets(project_id: str) -> List[CloudResource]:
    """
    Collect BigQuery datasets and tables with storage size.

    Args:
        project_id: GCP project ID

    Returns:
        List of CloudResource objects for BigQuery datasets
    """
    resources = []
    try:
        from google.cloud import bigquery

        client = bigquery.Client(project=project_id)

        # List all datasets
        for dataset_ref in client.list_datasets():
            dataset = client.get_dataset(dataset_ref.reference)

            labels = dict(dataset.labels) if dataset.labels else {}
            location = dataset.location or 'US'

            # Calculate total size from all tables
            total_bytes = 0
            table_count = 0

            for table_ref in client.list_tables(dataset.reference):
                table_count += 1
                try:
                    table = client.get_table(table_ref.reference)
                    if table.num_bytes:
                        total_bytes += table.num_bytes
                except Exception:
                    pass

            # num_bytes is BigQuery's own real, measured stored bytes per
            # table (not a quota/estimate) - summing across tables is a real
            # measurement already.
            total_gb = float(total_bytes) / (1024 ** 3) if total_bytes else 0.0

            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region=location,
                resource_type="gcp:bigquery:dataset",
                service_family="BigQuery",
                resource_id=f"projects/{project_id}/datasets/{dataset.dataset_id}",
                name=dataset.dataset_id,
                tags=labels,
                size_gb=total_gb,
                metadata={
                    'location': location,
                    'table_count': table_count,
                    'total_bytes': total_bytes,
                    'default_table_expiration_ms': dataset.default_table_expiration_ms,
                    'creation_time': str(dataset.created),
                    'modified_time': str(dataset.modified),
                    'size_source': 'usage',
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} BigQuery datasets")
    except ImportError:
        logger.warning("BigQuery client not available. Install with: pip install google-cloud-bigquery")
    except Exception as e:
        check_and_raise_auth_error(e, "collect BigQuery datasets", "gcp")
        logger.error(f"Failed to collect BigQuery datasets: {e}")

    return resources


def collect_spanner_instances(project_id: str) -> List[CloudResource]:
    """
    Collect Cloud Spanner instances and databases.

    Args:
        project_id: GCP project ID

    Returns:
        List of CloudResource objects for Spanner instances
    """
    resources = []
    try:
        from google.cloud import spanner_v1

        client = spanner_v1.InstanceAdminClient()  # type: ignore[attr-defined]

        parent = f"projects/{project_id}"

        for instance in client.list_instances(parent=parent):
            labels = dict(instance.labels) if instance.labels else {}

            # Extract region from instance config
            config_name = instance.config or ''
            location = 'global'
            if 'regional' in config_name:
                location = config_name.split('-')[-1] if '-' in config_name else 'unknown'

            # Node count and processing units for sizing
            node_count = instance.node_count or 0
            processing_units = instance.processing_units or 0

            # Estimate storage (Spanner charges per GB stored)
            # No direct API, but we can list databases and get metadata
            db_client = spanner_v1.DatabaseAdminClient()  # type: ignore[attr-defined]
            db_parent = instance.name

            db_count = 0
            try:
                for _db in db_client.list_databases(parent=db_parent):
                    db_count += 1
            except Exception:
                pass

            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region=location,
                resource_type="gcp:spanner:instance",
                service_family="Spanner",
                resource_id=instance.name,
                name=instance.display_name or instance.name.split('/')[-1],
                tags=labels,
                # Storage size isn't exposed via the Instance/Database admin
                # APIs used here. Cloud Monitoring likely has a real-usage
                # metric (e.g. spanner.googleapis.com/instance/storage/used_bytes),
                # but it hasn't been verified against docs/SDK yet. See
                # docs/v2-refactor-plan.md.
                size_gb=0.0,
                metadata={
                    'state': instance.state.name if instance.state else '',
                    'config': config_name,
                    'node_count': node_count,
                    'processing_units': processing_units,
                    'database_count': db_count,
                    'size_source': 'unavailable',
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Cloud Spanner instances")
    except ImportError:
        logger.warning("Spanner client not available. Install with: pip install google-cloud-spanner")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Spanner instances", "gcp")
        logger.error(f"Failed to collect Spanner instances: {e}")

    return resources


def collect_bigtable_instances(project_id: str) -> List[CloudResource]:
    """
    Collect Cloud Bigtable instances and clusters.

    Args:
        project_id: GCP project ID

    Returns:
        List of CloudResource objects for Bigtable instances
    """
    resources = []
    try:
        from google.cloud import bigtable
        from google.cloud.bigtable import enums  # noqa: F401 - used for storage type enum

        client = bigtable.Client(project=project_id, admin=True)

        for instance in client.list_instances()[0]:  # Returns (instances, failed_locations)
            labels = dict(instance.labels) if hasattr(instance, 'labels') and instance.labels else {}

            # Get clusters for this instance
            cluster_count = 0
            total_nodes = 0
            locations = []
            storage_type = 'unknown'

            try:
                clusters = instance.list_clusters()[0]  # Returns (clusters, failed_locations)
                for cluster in clusters:
                    cluster_count += 1
                    if hasattr(cluster, 'serve_nodes') and cluster.serve_nodes:
                        total_nodes += cluster.serve_nodes
                    if hasattr(cluster, 'location_id') and cluster.location_id:
                        locations.append(cluster.location_id)
                    if hasattr(cluster, 'default_storage_type'):
                        storage_type = str(cluster.default_storage_type)
            except Exception as e:
                check_and_raise_auth_error(e, f"get clusters for instance {instance.instance_id}", "gcp")
                logger.warning(f"Failed to get clusters for instance {instance.instance_id}: {e}")

            location = locations[0] if locations else 'unknown'

            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region=location,
                resource_type="gcp:bigtable:instance",
                service_family="Bigtable",
                resource_id=f"projects/{project_id}/instances/{instance.instance_id}",
                name=instance.display_name or instance.instance_id,
                tags=labels,
                # Storage size isn't exposed via the Instance/Cluster admin
                # client used here. Cloud Monitoring likely has a real-usage
                # metric (e.g. bigtable.googleapis.com/cluster/storage_utilization
                # combined with per-cluster storage capacity), but it hasn't
                # been verified against docs/SDK yet. See
                # docs/v2-refactor-plan.md.
                size_gb=0.0,
                metadata={
                    'instance_type': str(instance.type_) if hasattr(instance, 'type_') else 'unknown',
                    'cluster_count': cluster_count,
                    'total_nodes': total_nodes,
                    'locations': locations,
                    'storage_type': storage_type,
                    'size_source': 'unavailable',
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Bigtable instances")
    except ImportError:
        logger.warning("Bigtable client not available. Install with: pip install google-cloud-bigtable")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Bigtable instances", "gcp")
        logger.error(f"Failed to collect Bigtable instances: {e}")

    return resources


def collect_alloydb_clusters(project_id: str) -> List[CloudResource]:
    """
    Collect AlloyDB for PostgreSQL clusters and instances.

    Args:
        project_id: GCP project ID

    Returns:
        List of CloudResource objects for AlloyDB clusters and instances
    """
    resources = []
    try:
        from google.cloud import alloydb_v1

        client = alloydb_v1.AlloyDBAdminClient()

        # List clusters in all locations
        parent = f"projects/{project_id}/locations/-"

        for cluster in client.list_clusters(parent=parent):
            labels = dict(cluster.labels) if cluster.labels else {}

            # Extract location from cluster name
            location = extract_location_from_name(cluster.name)

            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region=location,
                resource_type="gcp:alloydb:cluster",
                service_family="AlloyDB",
                resource_id=cluster.name,
                name=cluster.display_name or cluster.name.split('/')[-1],
                tags=labels,
                # Storage auto-scales and isn't exposed via the Cluster admin
                # client used here. It's unverified whether real usage lives
                # at the cluster level (shared storage pool, like Aurora) or
                # would need per-instance metrics - either way, no Cloud
                # Monitoring metric has been confirmed against docs/SDK yet,
                # so this stays 0.0/unavailable rather than assuming "no size
                # concept" without verification. See docs/v2-refactor-plan.md.
                size_gb=0.0,
                metadata={
                    'state': cluster.state.name if hasattr(cluster, 'state') and cluster.state else '',
                    'cluster_type': cluster.cluster_type.name if hasattr(cluster, 'cluster_type') and cluster.cluster_type else 'unknown',
                    'database_version': str(cluster.database_version) if hasattr(cluster, 'database_version') else '',
                    'size_source': 'unavailable',
                }
            )
            resources.append(resource)

            # List instances for this cluster
            try:
                for instance in client.list_instances(parent=cluster.name):
                    instance_labels = dict(instance.labels) if instance.labels else {}

                    # Get instance size from machine config
                    machine_config = instance.machine_config if hasattr(instance, 'machine_config') else None
                    cpu_count = getattr(machine_config, 'cpu_count', 0) if machine_config else 0

                    instance_resource = CloudResource(
                        provider="gcp",
                        account_id=project_id,
                        region=location,
                        resource_type="gcp:alloydb:instance",
                        service_family="AlloyDB",
                        resource_id=instance.name,
                        name=instance.display_name or instance.name.split('/')[-1],
                        tags=instance_labels,
                        size_gb=0.0,
                        parent_resource_id=cluster.name,
                        metadata={
                            'state': instance.state.name if hasattr(instance, 'state') and instance.state else '',
                            'instance_type': instance.instance_type.name if hasattr(instance, 'instance_type') and instance.instance_type else 'unknown',
                            'cpu_count': cpu_count,
                            'availability_type': instance.availability_type.name if hasattr(instance, 'availability_type') and instance.availability_type else 'unknown',
                            'size_source': 'unavailable',
                        }
                    )
                    resources.append(instance_resource)
            except Exception as e:
                check_and_raise_auth_error(e, f"list instances for cluster {cluster.name}", "gcp")
                logger.warning(f"Failed to list instances for cluster {cluster.name}: {e}")

        logger.info(f"Found {len(resources)} AlloyDB clusters and instances")
    except ImportError:
        logger.warning("AlloyDB client not available. Install with: pip install google-cloud-alloydb")
    except Exception as e:
        check_and_raise_auth_error(e, "collect AlloyDB clusters", "gcp")
        logger.error(f"Failed to collect AlloyDB clusters: {e}")

    return resources
