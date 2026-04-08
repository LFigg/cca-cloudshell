# GCP Database collectors
"""Collectors for Cloud SQL, Memorystore, BigQuery, Spanner, Bigtable, and AlloyDB."""

import logging
from typing import List

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
                storage_gb = int(settings.get('dataDiskSizeGb', 0))
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
                    size_gb=float(storage_gb),
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
            location = instance.name.split('/')[3] if '/' in instance.name else 'unknown'

            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region=location,
                resource_type="gcp:redis:instance",
                service_family="Redis",
                resource_id=instance.name,
                name=instance.display_name or instance.name.split('/')[-1],
                tags=labels,
                size_gb=float(instance.memory_size_gb) if instance.memory_size_gb else 0.0,
                metadata={
                    'state': instance.state.name if instance.state else '',
                    'tier': instance.tier.name if instance.tier else '',
                    'redis_version': instance.redis_version,
                    'memory_size_gb': instance.memory_size_gb,
                    'host': instance.host,
                    'port': instance.port,
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
                size_gb=0.0,  # Storage size not directly available via API
                metadata={
                    'state': instance.state.name if instance.state else '',
                    'config': config_name,
                    'node_count': node_count,
                    'processing_units': processing_units,
                    'database_count': db_count,
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
                logger.debug(f"Failed to get clusters for instance {instance.instance_id}: {e}")

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
                size_gb=0.0,  # Bigtable storage size not directly available
                metadata={
                    'instance_type': str(instance.type_) if hasattr(instance, 'type_') else 'unknown',
                    'cluster_count': cluster_count,
                    'total_nodes': total_nodes,
                    'locations': locations,
                    'storage_type': storage_type,
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
            location = cluster.name.split('/')[3] if '/' in cluster.name else 'unknown'

            # Get cluster network config
            cluster.network_config if hasattr(cluster, 'network_config') else None

            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region=location,
                resource_type="gcp:alloydb:cluster",
                service_family="AlloyDB",
                resource_id=cluster.name,
                name=cluster.display_name or cluster.name.split('/')[-1],
                tags=labels,
                size_gb=0.0,  # Storage auto-scales; size tracked by instances
                metadata={
                    'state': cluster.state.name if hasattr(cluster, 'state') and cluster.state else '',
                    'cluster_type': cluster.cluster_type.name if hasattr(cluster, 'cluster_type') and cluster.cluster_type else 'unknown',
                    'database_version': str(cluster.database_version) if hasattr(cluster, 'database_version') else '',
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
                        }
                    )
                    resources.append(instance_resource)
            except Exception as e:
                logger.debug(f"Failed to list instances for cluster {cluster.name}: {e}")

        logger.info(f"Found {len(resources)} AlloyDB clusters and instances")
    except ImportError:
        logger.warning("AlloyDB client not available. Install with: pip install google-cloud-alloydb")
    except Exception as e:
        check_and_raise_auth_error(e, "collect AlloyDB clusters", "gcp")
        logger.error(f"Failed to collect AlloyDB clusters: {e}")

    return resources
