#!/usr/bin/env python3
"""
CCA CloudShell - Google Cloud Resource Collector

Collects GCP resources for cloud protection assessment.
Optimized for Google Cloud Shell with minimal dependencies.

Usage:
    python3 gcp_collect.py
    python3 gcp_collect.py --project my-project-id
    python3 gcp_collect.py --output gs://my-bucket/assessments/
"""
import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, TYPE_CHECKING

# Google Cloud SDK - pre-installed in Cloud Shell
try:
    from google.cloud import compute_v1  # type: ignore[import-untyped]
    from google.cloud import storage  # type: ignore[import-untyped]
    from google.cloud import sqladmin_v1  # type: ignore[import-untyped]
    from google.cloud.sql_v1 import SqlInstancesServiceClient  # type: ignore[import-untyped,import-not-found]
    from google.api_core.exceptions import NotFound, PermissionDenied  # type: ignore[import-untyped]
    import google.auth  # type: ignore[import-untyped]
    HAS_GCP_SDK = True
except ImportError:
    HAS_GCP_SDK = False
    compute_v1: Any = None
    storage: Any = None
    sqladmin_v1: Any = None
    google: Any = None

# Add lib to path for imports
sys.path.insert(0, '.')
from lib.models import CloudResource, aggregate_sizing
from lib.utils import (
    generate_run_id, get_timestamp, format_bytes_to_gb,
    write_json, write_csv, setup_logging, print_summary_table,
    retry_with_backoff, ProgressTracker
)
from lib.change_rate import (
    DataChangeMetrics, TransactionLogMetrics, ChangeRateSummary,
    aggregate_change_rates, format_change_rate_output,
    get_gcp_monitoring_client, get_gcp_disk_change_rate, get_cloudsql_change_rate
)
from lib.k8s import collect_gke_pvcs

logger = logging.getLogger(__name__)


# =============================================================================
# Authentication & Projects
# =============================================================================

def get_credentials():
    """Get GCP credentials. In Cloud Shell, uses application default credentials."""
    if not HAS_GCP_SDK:
        raise ImportError("Google Cloud SDK not installed. Run: pip install google-cloud-compute google-cloud-storage google-cloud-sql")
    credentials, project = google.auth.default()
    return credentials, project


def get_projects(credentials) -> List[Dict]:
    """Get all accessible projects."""
    from google.cloud import resourcemanager_v3  # type: ignore[import-untyped]
    
    client = resourcemanager_v3.ProjectsClient(credentials=credentials)
    projects = []
    
    try:
        for project in client.search_projects():
            if project.state.name == 'ACTIVE':
                projects.append({
                    'id': project.project_id,
                    'name': project.display_name,
                    'number': project.name.split('/')[-1]
                })
    except Exception as e:
        logger.warning(f"Could not list projects: {e}")
    
    return projects


def get_regions(project_id: str) -> List[str]:
    """Get all available regions."""
    client = compute_v1.RegionsClient()
    regions = []
    
    try:
        for region in client.list(project=project_id):
            if region.status == 'UP':
                regions.append(region.name)
    except Exception as e:
        logger.warning(f"Could not list regions: {e}")
    
    return sorted(regions)


def get_zones(project_id: str) -> List[str]:
    """Get all available zones."""
    client = compute_v1.ZonesClient()
    zones = []
    
    try:
        for zone in client.list(project=project_id):
            if zone.status == 'UP':
                zones.append(zone.name)
    except Exception as e:
        logger.warning(f"Could not list zones: {e}")
    
    return sorted(zones)


# =============================================================================
# Compute Engine Collectors
# =============================================================================

@retry_with_backoff(max_attempts=3)
def collect_compute_instances(project_id: str) -> List[CloudResource]:
    """Collect Compute Engine instances across all zones."""
    resources = []
    try:
        client = compute_v1.InstancesClient()
        
        # Use aggregated list to get instances from all zones
        request = compute_v1.AggregatedListInstancesRequest(project=project_id)
        
        for zone, response in client.aggregated_list(request=request):
            if response.instances:
                for instance in response.instances:
                    # Extract zone name from zone URL
                    zone_name = zone.split('/')[-1] if '/' in zone else zone
                    region = '-'.join(zone_name.split('-')[:-1])  # e.g., us-central1 from us-central1-a
                    
                    # Get attached disks
                    attached_disks = []
                    total_disk_size_gb = 0
                    for disk in instance.disks:
                        if disk.source:
                            disk_name = disk.source.split('/')[-1]
                            attached_disks.append(disk_name)
                        if disk.disk_size_gb:
                            total_disk_size_gb += disk.disk_size_gb
                    
                    # Parse labels (GCP's equivalent of tags)
                    labels = dict(instance.labels) if instance.labels else {}
                    
                    resource = CloudResource(
                        provider="gcp",
                        account_id=project_id,
                        region=region,
                        resource_type="gcp:compute:instance",
                        service_family="Compute",
                        resource_id=f"projects/{project_id}/zones/{zone_name}/instances/{instance.name}",
                        name=instance.name,
                        tags=labels,
                        size_gb=float(total_disk_size_gb),
                        metadata={
                            'machine_type': instance.machine_type.split('/')[-1] if instance.machine_type else '',
                            'status': instance.status,
                            'zone': zone_name,
                            'attached_disks': attached_disks,
                            'network_interfaces': len(instance.network_interfaces) if instance.network_interfaces else 0,
                            'preemptible': instance.scheduling.preemptible if instance.scheduling else False,
                        }
                    )
                    resources.append(resource)
        
        logger.info(f"Found {len(resources)} Compute Engine instances")
    except Exception as e:
        logger.error(f"Failed to collect Compute Engine instances: {e}")
    
    return resources


def collect_persistent_disks(project_id: str) -> List[CloudResource]:
    """Collect Persistent Disks across all zones."""
    resources = []
    try:
        client = compute_v1.DisksClient()
        
        request = compute_v1.AggregatedListDisksRequest(project=project_id)
        
        for zone, response in client.aggregated_list(request=request):
            if response.disks:
                for disk in response.disks:
                    zone_name = zone.split('/')[-1] if '/' in zone else zone
                    region = '-'.join(zone_name.split('-')[:-1])
                    
                    labels = dict(disk.labels) if disk.labels else {}
                    
                    # Get attached instances
                    attached_to = []
                    if disk.users:
                        for user in disk.users:
                            attached_to.append(user.split('/')[-1])
                    
                    resource = CloudResource(
                        provider="gcp",
                        account_id=project_id,
                        region=region,
                        resource_type="gcp:compute:disk",
                        service_family="Compute",
                        resource_id=disk.self_link or f"projects/{project_id}/zones/{zone_name}/disks/{disk.name}",
                        name=disk.name,
                        tags=labels,
                        size_gb=float(disk.size_gb) if disk.size_gb else 0.0,
                        parent_resource_id=attached_to[0] if attached_to else None,
                        metadata={
                            'zone': zone_name,
                            'disk_type': disk.type_.split('/')[-1] if disk.type_ else '',
                            'status': disk.status,
                            'attached_to': attached_to,
                            'source_image': disk.source_image.split('/')[-1] if disk.source_image else '',
                            'source_snapshot': disk.source_snapshot.split('/')[-1] if disk.source_snapshot else '',
                        }
                    )
                    resources.append(resource)
        
        logger.info(f"Found {len(resources)} Persistent Disks")
    except Exception as e:
        logger.error(f"Failed to collect Persistent Disks: {e}")
    
    return resources


def collect_disk_snapshots(project_id: str) -> List[CloudResource]:
    """Collect disk snapshots."""
    resources = []
    try:
        client = compute_v1.SnapshotsClient()
        
        for snapshot in client.list(project=project_id):
            labels = dict(snapshot.labels) if snapshot.labels else {}
            
            # Extract source disk name
            source_disk = ''
            if snapshot.source_disk:
                source_disk = snapshot.source_disk.split('/')[-1]
            
            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region="global",  # Snapshots are global resources
                resource_type="gcp:compute:snapshot",
                service_family="Compute",
                resource_id=snapshot.self_link or f"projects/{project_id}/global/snapshots/{snapshot.name}",
                name=snapshot.name,
                tags=labels,
                size_gb=float(snapshot.storage_bytes or 0) / (1024**3),  # Convert bytes to GB
                parent_resource_id=source_disk,
                metadata={
                    'status': snapshot.status,
                    'source_disk': source_disk,
                    'disk_size_gb': snapshot.disk_size_gb,
                    'storage_bytes': snapshot.storage_bytes,
                    'storage_locations': list(snapshot.storage_locations) if snapshot.storage_locations else [],
                    'creation_timestamp': snapshot.creation_timestamp,
                    'auto_created': snapshot.auto_created if hasattr(snapshot, 'auto_created') else False,
                }
            )
            resources.append(resource)
        
        logger.info(f"Found {len(resources)} disk snapshots")
    except Exception as e:
        logger.error(f"Failed to collect disk snapshots: {e}")
    
    return resources


# =============================================================================
# Cloud Storage Collector
# =============================================================================

def collect_storage_buckets(project_id: str) -> List[CloudResource]:
    """Collect Cloud Storage buckets."""
    resources = []
    try:
        client = storage.Client(project=project_id)
        
        for bucket in client.list_buckets():
            labels = dict(bucket.labels) if bucket.labels else {}
            
            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region=bucket.location.lower() if bucket.location else 'unknown',
                resource_type="gcp:storage:bucket",
                service_family="Storage",
                resource_id=f"projects/{project_id}/buckets/{bucket.name}",
                name=bucket.name,
                tags=labels,
                size_gb=0.0,  # Would require listing all objects to calculate
                metadata={
                    'location': bucket.location,
                    'location_type': bucket.location_type,
                    'storage_class': bucket.storage_class,
                    'versioning_enabled': bucket.versioning_enabled,
                    'lifecycle_rules': len(bucket.lifecycle_rules) if bucket.lifecycle_rules else 0,
                    'created': bucket.time_created.isoformat() if bucket.time_created else '',
                }
            )
            resources.append(resource)
        
        logger.info(f"Found {len(resources)} Cloud Storage buckets")
    except Exception as e:
        logger.error(f"Failed to collect Cloud Storage buckets: {e}")
    
    return resources


# =============================================================================
# Cloud SQL Collector
# =============================================================================

def collect_cloud_sql_instances(project_id: str) -> List[CloudResource]:
    """Collect Cloud SQL instances."""
    resources = []
    try:
        from google.cloud.sql_v1 import SqlInstancesServiceClient  # type: ignore[import-untyped,import-not-found]
        
        client = SqlInstancesServiceClient()
        
        request = sqladmin_v1.SqlInstancesListRequest(project=project_id)
        
        for instance in client.list(request=request):
            labels = dict(instance.settings.user_labels) if instance.settings and instance.settings.user_labels else {}
            
            # Get storage size
            storage_gb = 0
            if instance.settings and instance.settings.data_disk_size_gb:
                storage_gb = instance.settings.data_disk_size_gb
            
            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region=instance.region,
                resource_type="gcp:sql:instance",
                service_family="SQL",
                resource_id=f"projects/{project_id}/instances/{instance.name}",
                name=instance.name,
                tags=labels,
                size_gb=float(storage_gb),
                metadata={
                    'database_version': instance.database_version,
                    'tier': instance.settings.tier if instance.settings else '',
                    'state': instance.state,
                    'backend_type': instance.backend_type,
                    'availability_type': instance.settings.availability_type if instance.settings else '',
                    'backup_enabled': instance.settings.backup_configuration.enabled if instance.settings and instance.settings.backup_configuration else False,
                }
            )
            resources.append(resource)
        
        logger.info(f"Found {len(resources)} Cloud SQL instances")
    except ImportError:
        logger.warning("Cloud SQL client not available")
    except Exception as e:
        logger.error(f"Failed to collect Cloud SQL instances: {e}")
    
    return resources


# =============================================================================
# GKE Collector
# =============================================================================

def collect_gke_clusters(project_id: str) -> List[CloudResource]:
    """Collect GKE clusters."""
    resources = []
    try:
        from google.cloud import container_v1  # type: ignore[import-untyped]
        
        client = container_v1.ClusterManagerClient()
        
        # List clusters in all locations
        parent = f"projects/{project_id}/locations/-"
        
        response = client.list_clusters(parent=parent)
        
        for cluster in response.clusters:
            labels = dict(cluster.resource_labels) if cluster.resource_labels else {}
            
            # Count total nodes
            total_nodes = 0
            node_pools = []
            if cluster.node_pools:
                for pool in cluster.node_pools:
                    node_pools.append(pool.name)
                    total_nodes += pool.initial_node_count or 0
            
            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region=cluster.location,
                resource_type="gcp:container:cluster",
                service_family="GKE",
                resource_id=f"projects/{project_id}/locations/{cluster.location}/clusters/{cluster.name}",
                name=cluster.name,
                tags=labels,
                size_gb=0.0,
                metadata={
                    'status': cluster.status.name if cluster.status else '',
                    'current_master_version': cluster.current_master_version,
                    'current_node_version': cluster.current_node_version,
                    'node_pools': node_pools,
                    'total_nodes': total_nodes,
                    'network': cluster.network,
                    'subnetwork': cluster.subnetwork,
                    'endpoint': cluster.endpoint,
                }
            )
            resources.append(resource)
        
        logger.info(f"Found {len(resources)} GKE clusters")
    except ImportError:
        logger.warning("GKE client not available")
    except Exception as e:
        logger.error(f"Failed to collect GKE clusters: {e}")
    
    return resources


# =============================================================================
# Cloud Functions Collector
# =============================================================================

def collect_cloud_functions(project_id: str) -> List[CloudResource]:
    """Collect Cloud Functions."""
    resources = []
    try:
        from google.cloud import functions_v2  # type: ignore[import-untyped]
        
        client = functions_v2.FunctionServiceClient()
        
        # List functions in all locations
        parent = f"projects/{project_id}/locations/-"
        
        for function in client.list_functions(parent=parent):
            labels = dict(function.labels) if function.labels else {}
            
            # Extract location from name
            location = function.name.split('/')[3] if '/' in function.name else 'unknown'
            
            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region=location,
                resource_type="gcp:functions:function",
                service_family="Functions",
                resource_id=function.name,
                name=function.name.split('/')[-1],
                tags=labels,
                size_gb=0.0,
                metadata={
                    'state': function.state.name if function.state else '',
                    'runtime': function.build_config.runtime if function.build_config else '',
                    'entry_point': function.build_config.entry_point if function.build_config else '',
                    'available_memory': function.service_config.available_memory if function.service_config else '',
                    'timeout_seconds': function.service_config.timeout_seconds if function.service_config else 0,
                    'environment': function.environment.name if function.environment else '',
                }
            )
            resources.append(resource)
        
        logger.info(f"Found {len(resources)} Cloud Functions")
    except ImportError:
        logger.warning("Cloud Functions client not available")
    except Exception as e:
        logger.error(f"Failed to collect Cloud Functions: {e}")
    
    return resources


# =============================================================================
# Filestore Collector
# =============================================================================

def collect_filestore_instances(project_id: str) -> List[CloudResource]:
    """Collect Filestore instances."""
    resources = []
    try:
        from google.cloud import filestore_v1  # type: ignore[import-untyped]
        
        client = filestore_v1.CloudFilestoreManagerClient()
        
        # List instances in all locations
        parent = f"projects/{project_id}/locations/-"
        
        for instance in client.list_instances(parent=parent):
            labels = dict(instance.labels) if instance.labels else {}
            
            # Get total capacity
            total_capacity_gb = 0
            if instance.file_shares:
                for share in instance.file_shares:
                    total_capacity_gb += share.capacity_gb or 0
            
            # Extract location
            location = instance.name.split('/')[3] if '/' in instance.name else 'unknown'
            
            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region=location,
                resource_type="gcp:filestore:instance",
                service_family="Filestore",
                resource_id=instance.name,
                name=instance.name.split('/')[-1],
                tags=labels,
                size_gb=float(total_capacity_gb),
                metadata={
                    'state': instance.state.name if instance.state else '',
                    'tier': instance.tier.name if instance.tier else '',
                    'file_shares': [{'name': s.name, 'capacity_gb': s.capacity_gb} for s in instance.file_shares] if instance.file_shares else [],
                    'networks': [n.network for n in instance.networks] if instance.networks else [],
                }
            )
            resources.append(resource)
        
        logger.info(f"Found {len(resources)} Filestore instances")
    except ImportError:
        logger.warning("Filestore client not available")
    except Exception as e:
        logger.error(f"Failed to collect Filestore instances: {e}")
    
    return resources


# =============================================================================
# Memorystore (Redis) Collector
# =============================================================================

def collect_memorystore_redis(project_id: str) -> List[CloudResource]:
    """Collect Memorystore for Redis instances."""
    resources = []
    try:
        from google.cloud import redis_v1  # type: ignore[import-untyped]
        
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
        logger.error(f"Failed to collect Memorystore Redis instances: {e}")
    
    return resources


# =============================================================================
# Backup & DR Collectors
# =============================================================================

def collect_backup_plans(project_id: str) -> List[CloudResource]:
    """Collect Backup & DR backup plans."""
    resources = []
    try:
        from google.cloud import backupdr_v1  # type: ignore[import-untyped]
        
        client = backupdr_v1.BackupDRClient()
        
        # List backup plans in all locations
        parent = f"projects/{project_id}/locations/-"
        
        for plan in client.list_backup_plans(parent=parent):
            labels = dict(plan.labels) if plan.labels else {}
            
            location = plan.name.split('/')[3] if '/' in plan.name else 'unknown'
            
            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region=location,
                resource_type="gcp:backupdr:plan",
                service_family="Backup",
                resource_id=plan.name,
                name=plan.name.split('/')[-1],
                tags=labels,
                size_gb=0.0,
                metadata={
                    'state': plan.state.name if hasattr(plan, 'state') and plan.state else '',
                    'description': plan.description if hasattr(plan, 'description') else '',
                }
            )
            resources.append(resource)
        
        logger.info(f"Found {len(resources)} Backup & DR plans")
    except ImportError:
        logger.warning("Backup & DR client not available")
    except Exception as e:
        logger.error(f"Failed to collect Backup & DR plans: {e}")
    
    return resources


def collect_backup_vaults(project_id: str) -> List[CloudResource]:
    """Collect Backup & DR backup vaults."""
    resources = []
    try:
        from google.cloud import backupdr_v1  # type: ignore[import-untyped]
        
        client = backupdr_v1.BackupDRClient()
        
        # List backup vaults in all locations
        parent = f"projects/{project_id}/locations/-"
        
        for vault in client.list_backup_vaults(parent=parent):
            labels = dict(vault.labels) if vault.labels else {}
            
            location = vault.name.split('/')[3] if '/' in vault.name else 'unknown'
            
            # Get total backup size if available
            total_size_bytes = getattr(vault, 'total_stored_bytes', 0) or 0
            size_gb = total_size_bytes / (1024 ** 3)
            
            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region=location,
                resource_type="gcp:backupdr:vault",
                service_family="Backup",
                resource_id=vault.name,
                name=vault.name.split('/')[-1],
                tags=labels,
                size_gb=round(size_gb, 2),
                metadata={
                    'state': vault.state.name if hasattr(vault, 'state') and vault.state else '',
                    'description': getattr(vault, 'description', ''),
                    'backup_count': getattr(vault, 'backup_count', 0),
                    'total_stored_bytes': total_size_bytes,
                    'deletable': getattr(vault, 'deletable', True),
                    'etag': getattr(vault, 'etag', ''),
                }
            )
            resources.append(resource)
        
        logger.info(f"Found {len(resources)} Backup & DR vaults")
    except ImportError:
        logger.warning("Backup & DR client not available")
    except Exception as e:
        logger.error(f"Failed to collect Backup & DR vaults: {e}")
    
    return resources


def collect_backup_data_sources(project_id: str) -> List[CloudResource]:
    """Collect Backup & DR data sources (protected resources)."""
    resources = []
    try:
        from google.cloud import backupdr_v1  # type: ignore[import-untyped]
        
        client = backupdr_v1.BackupDRClient()
        
        # First get all backup vaults
        parent = f"projects/{project_id}/locations/-"
        vault_names = []
        
        try:
            for vault in client.list_backup_vaults(parent=parent):
                vault_names.append(vault.name)
        except Exception:
            pass
        
        # Then get data sources from each vault
        for vault_name in vault_names:
            try:
                for ds in client.list_data_sources(parent=vault_name):
                    labels = dict(ds.labels) if hasattr(ds, 'labels') and ds.labels else {}
                    
                    location = ds.name.split('/')[3] if '/' in ds.name else 'unknown'
                    
                    # Get total backup size
                    total_size_bytes = getattr(ds, 'total_stored_bytes', 0) or 0
                    size_gb = total_size_bytes / (1024 ** 3)
                    
                    resource = CloudResource(
                        provider="gcp",
                        account_id=project_id,
                        region=location,
                        resource_type="gcp:backupdr:datasource",
                        service_family="Backup",
                        resource_id=ds.name,
                        name=ds.name.split('/')[-1],
                        tags=labels,
                        size_gb=round(size_gb, 2),
                        parent_resource_id=vault_name,
                        metadata={
                            'state': ds.state.name if hasattr(ds, 'state') and ds.state else '',
                            'data_source_gcp_resource': getattr(ds, 'data_source_gcp_resource', {}).get('gcp_resourcename', ''),
                            'backup_count': getattr(ds, 'backup_count', 0),
                            'total_stored_bytes': total_size_bytes,
                            'backup_vault': vault_name.split('/')[-1],
                        }
                    )
                    resources.append(resource)
            except Exception as e:
                logger.warning(f"Failed to collect data sources from vault {vault_name}: {e}")
        
        logger.info(f"Found {len(resources)} Backup & DR data sources")
    except ImportError:
        logger.warning("Backup & DR client not available")
    except Exception as e:
        logger.error(f"Failed to collect Backup & DR data sources: {e}")
    
    return resources


def collect_backups(project_id: str) -> List[CloudResource]:
    """Collect Backup & DR backups (recovery points)."""
    resources = []
    try:
        from google.cloud import backupdr_v1  # type: ignore[import-untyped]
        
        client = backupdr_v1.BackupDRClient()
        
        # First get all backup vaults
        parent = f"projects/{project_id}/locations/-"
        vault_names = []
        
        try:
            for vault in client.list_backup_vaults(parent=parent):
                vault_names.append(vault.name)
        except Exception:
            pass
        
        # Get data sources from each vault, then backups from each data source
        for vault_name in vault_names:
            try:
                for ds in client.list_data_sources(parent=vault_name):
                    try:
                        for backup in client.list_backups(parent=ds.name):
                            labels = dict(backup.labels) if hasattr(backup, 'labels') and backup.labels else {}
                            
                            location = backup.name.split('/')[3] if '/' in backup.name else 'unknown'
                            
                            # Get backup size
                            size_bytes = getattr(backup, 'backup_appliance_backup_size_bytes', 0) or 0
                            if not size_bytes:
                                size_bytes = getattr(backup, 'gc_backup_size_bytes', 0) or 0
                            size_gb = size_bytes / (1024 ** 3)
                            
                            resource = CloudResource(
                                provider="gcp",
                                account_id=project_id,
                                region=location,
                                resource_type="gcp:backupdr:backup",
                                service_family="Backup",
                                resource_id=backup.name,
                                name=backup.name.split('/')[-1],
                                tags=labels,
                                size_gb=round(size_gb, 2),
                                parent_resource_id=ds.name,
                                metadata={
                                    'state': backup.state.name if hasattr(backup, 'state') and backup.state else '',
                                    'backup_type': backup.backup_type.name if hasattr(backup, 'backup_type') and backup.backup_type else '',
                                    'create_time': str(getattr(backup, 'create_time', '')),
                                    'expire_time': str(getattr(backup, 'expire_time', '')),
                                    'consistency_time': str(getattr(backup, 'consistency_time', '')),
                                    'data_source': ds.name.split('/')[-1],
                                    'backup_vault': vault_name.split('/')[-1],
                                    'size_bytes': size_bytes,
                                }
                            )
                            resources.append(resource)
                    except Exception as e:
                        logger.warning(f"Failed to collect backups from data source {ds.name}: {e}")
            except Exception as e:
                logger.warning(f"Failed to collect data sources from vault {vault_name}: {e}")
        
        logger.info(f"Found {len(resources)} Backup & DR backups")
    except ImportError:
        logger.warning("Backup & DR client not available")
    except Exception as e:
        logger.error(f"Failed to collect Backup & DR backups: {e}")
    
    return resources


# =============================================================================
# BigQuery Collector
# =============================================================================

def collect_bigquery_datasets(project_id: str) -> List[CloudResource]:
    """Collect BigQuery datasets and tables with storage size."""
    resources = []
    try:
        from google.cloud import bigquery  # type: ignore[import-untyped]
        
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
        logger.error(f"Failed to collect BigQuery datasets: {e}")
    
    return resources


# =============================================================================
# Cloud Spanner Collector
# =============================================================================

def collect_spanner_instances(project_id: str) -> List[CloudResource]:
    """Collect Cloud Spanner instances and databases."""
    resources = []
    try:
        from google.cloud import spanner_v1  # type: ignore[import-untyped]
        
        client = spanner_v1.InstanceAdminClient()
        
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
            db_client = spanner_v1.DatabaseAdminClient()
            db_parent = instance.name
            
            db_count = 0
            try:
                for db in db_client.list_databases(parent=db_parent):
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
        logger.error(f"Failed to collect Spanner instances: {e}")
    
    return resources


# =============================================================================
# Bigtable Collector
# =============================================================================

def collect_bigtable_instances(project_id: str) -> List[CloudResource]:
    """Collect Cloud Bigtable instances and clusters."""
    resources = []
    try:
        from google.cloud import bigtable  # type: ignore[import-untyped]
        from google.cloud.bigtable import enums
        
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
                    if hasattr(cluster, 'serve_nodes'):
                        total_nodes += cluster.serve_nodes
                    if hasattr(cluster, 'location'):
                        locations.append(cluster.location_id if hasattr(cluster, 'location_id') else str(cluster.location))
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
        logger.error(f"Failed to collect Bigtable instances: {e}")
    
    return resources


# =============================================================================
# AlloyDB Collector
# =============================================================================

def collect_alloydb_clusters(project_id: str) -> List[CloudResource]:
    """Collect AlloyDB for PostgreSQL clusters and instances."""
    resources = []
    try:
        from google.cloud import alloydb_v1  # type: ignore[import-untyped]
        
        client = alloydb_v1.AlloyDBAdminClient()
        
        # List clusters in all locations
        parent = f"projects/{project_id}/locations/-"
        
        for cluster in client.list_clusters(parent=parent):
            labels = dict(cluster.labels) if cluster.labels else {}
            
            # Extract location from cluster name
            location = cluster.name.split('/')[3] if '/' in cluster.name else 'unknown'
            
            # Get cluster network config
            network_config = cluster.network_config if hasattr(cluster, 'network_config') else None
            
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
        logger.error(f"Failed to collect AlloyDB clusters: {e}")
    
    return resources


# =============================================================================
# Main Collection
# =============================================================================

def collect_project(project_id: str, tracker: Optional[ProgressTracker] = None) -> List[CloudResource]:
    """Collect all resources for a project."""
    logger.info(f"Collecting resources for project: {project_id}")
    
    all_resources = []
    
    def collect_and_track(name: str, collect_fn, *args):
        """Helper to collect resources and update tracker."""
        if tracker:
            tracker.update_task(f"Collecting {name}...")
        result = collect_fn(*args)
        if tracker and result:
            tracker.add_resources(len(result), sum(r.size_gb for r in result))
        return result
    
    # Compute Engine
    all_resources.extend(collect_and_track("Compute instances", collect_compute_instances, project_id))
    all_resources.extend(collect_and_track("Persistent disks", collect_persistent_disks, project_id))
    all_resources.extend(collect_and_track("Disk snapshots", collect_disk_snapshots, project_id))
    
    # Storage
    all_resources.extend(collect_and_track("Cloud Storage buckets", collect_storage_buckets, project_id))
    all_resources.extend(collect_and_track("Filestore instances", collect_filestore_instances, project_id))
    
    # Databases
    all_resources.extend(collect_and_track("Cloud SQL instances", collect_cloud_sql_instances, project_id))
    all_resources.extend(collect_and_track("Memorystore Redis", collect_memorystore_redis, project_id))
    all_resources.extend(collect_and_track("Cloud Spanner instances", collect_spanner_instances, project_id))
    all_resources.extend(collect_and_track("AlloyDB clusters", collect_alloydb_clusters, project_id))
    
    # Analytics
    all_resources.extend(collect_and_track("BigQuery datasets", collect_bigquery_datasets, project_id))
    all_resources.extend(collect_and_track("Bigtable instances", collect_bigtable_instances, project_id))
    
    # Containers & Compute
    all_resources.extend(collect_and_track("GKE clusters", collect_gke_clusters, project_id))
    all_resources.extend(collect_and_track("Cloud Functions", collect_cloud_functions, project_id))
    
    # Backup & DR
    all_resources.extend(collect_and_track("Backup plans", collect_backup_plans, project_id))
    all_resources.extend(collect_and_track("Backup vaults", collect_backup_vaults, project_id))
    all_resources.extend(collect_and_track("Backup data sources", collect_backup_data_sources, project_id))
    all_resources.extend(collect_and_track("Backups", collect_backups, project_id))
    
    return all_resources


# =============================================================================
# Change Rate Collection
# =============================================================================

def collect_gcp_change_rates(
    project_id: str,
    resources: List[CloudResource],
    days: int = 7
) -> Dict[str, Any]:
    """
    Collect change rate metrics from Cloud Monitoring for the collected resources.
    
    Args:
        project_id: GCP project ID
        resources: List of CloudResource objects collected from the project
        days: Number of days to sample for metrics
    
    Returns:
        Dict with change rate summaries by service family
    """
    change_rates = []
    
    # Get Monitoring client
    monitoring_client = get_gcp_monitoring_client(project_id)
    if not monitoring_client:
        logger.warning("Cloud Monitoring client not available, skipping change rate collection")
        return {}
    
    for resource in resources:
        try:
            rate_entry = _collect_gcp_resource_change_rate(
                monitoring_client, project_id, resource, days
            )
            if rate_entry:
                change_rates.append(rate_entry)
        except Exception as e:
            logger.debug(f"Error collecting change rate for {resource.resource_id}: {e}")
            continue
    
    # Aggregate change rates by service family
    summaries = aggregate_change_rates(change_rates)
    return format_change_rate_output(summaries)


def _collect_gcp_resource_change_rate(
    monitoring_client,
    project_id: str,
    resource: CloudResource,
    days: int
) -> Optional[Dict[str, Any]]:
    """
    Collect change rate for a single GCP resource based on its type.
    """
    service_family = resource.service_family
    
    if service_family == 'PersistentDisk':
        # GCP persistent disks
        disk_name = resource.metadata.get('disk_name', resource.name)
        zone = resource.region  # For zonal disks, this would be the zone
        
        if disk_name and zone:
            data_change = get_gcp_disk_change_rate(
                monitoring_client, project_id, disk_name, zone, resource.size_gb, days
            )
            if data_change:
                return {
                    'provider': 'gcp',
                    'service_family': 'PersistentDisk',
                    'size_gb': resource.size_gb,
                    'data_change': data_change
                }
    
    elif service_family == 'CloudSQL':
        # Cloud SQL instances
        instance_id = resource.metadata.get('instance_name', resource.name)
        
        if instance_id:
            data_change = get_cloudsql_change_rate(
                monitoring_client, project_id, instance_id, resource.size_gb, days
            )
            if data_change:
                return {
                    'provider': 'gcp',
                    'service_family': 'CloudSQL',
                    'size_gb': resource.size_gb,
                    'data_change': data_change
                }
    
    return None


def main():
    parser = argparse.ArgumentParser(description='CCA CloudShell - GCP Resource Collector')
    parser.add_argument('--project', help='GCP project ID (default: current project)')
    parser.add_argument('--all-projects', action='store_true', help='Collect from all accessible projects')
    parser.add_argument('--regions', help='Comma-separated list of regions to filter (e.g., us-central1,us-east1)')
    parser.add_argument('--output', help='Output directory or GCS path', default='.')
    parser.add_argument('--log-level', help='Logging level', default='INFO')
    parser.add_argument(
        '--include-change-rate',
        action='store_true',
        help='Collect data change rates from Cloud Monitoring (for sizing tool DCR overrides)'
    )
    parser.add_argument(
        '--skip-pvc',
        action='store_true',
        help='Skip PVC collection from GKE clusters (PVCs are collected by default when clusters are found)'
    )
    parser.add_argument(
        '--change-rate-days',
        type=int,
        default=7,
        help='Number of days to sample for change rate metrics (default: 7)'
    )
    
    args = parser.parse_args()
    
    setup_logging(args.log_level)
    
    if not HAS_GCP_SDK:
        logger.error("Google Cloud SDK not installed. Run: pip install google-cloud-compute google-cloud-storage")
        sys.exit(1)
    
    try:
        credentials, default_project = get_credentials()
        
        # Determine which projects to collect
        if args.all_projects:
            projects = get_projects(credentials)
            project_ids = [p['id'] for p in projects]
        elif args.project:
            project_ids = [args.project]
        elif default_project:
            project_ids = [default_project]
        else:
            logger.error("No project specified and no default project found")
            sys.exit(1)
        
        logger.info(f"Collecting from {len(project_ids)} project(s)")
        
        all_resources = []
        failed_projects = []
        
        with ProgressTracker("GCP", total_accounts=len(project_ids)) as tracker:
            for project_id in project_ids:
                try:
                    tracker.start_account(project_id)
                    resources = collect_project(project_id, tracker)
                    all_resources.extend(resources)
                    tracker.complete_account()
                except Exception as e:
                    logger.error(f"Failed to collect from project {project_id}: {e}")
                    failed_projects.append({'project_id': project_id, 'error': str(e)})
                    continue
        
        if failed_projects:
            logger.warning(f"Collection failed for {len(failed_projects)} project(s)")
        
        # Filter by regions if specified
        if args.regions:
            region_filter = {r.strip().lower() for r in args.regions.split(',')}
            original_count = len(all_resources)
            all_resources = [r for r in all_resources if r.region and r.region.lower() in region_filter]
            logger.info(f"Filtered to {len(all_resources)} resources in regions: {', '.join(sorted(region_filter))} (from {original_count} total)")
        
        # Generate run ID and timestamp
        run_id = generate_run_id()
        timestamp = get_timestamp()
        
        # Aggregate sizing
        sizing = aggregate_sizing(all_resources)
        
        # Collect change rates if requested
        change_rate_data = None
        if args.include_change_rate:
            logger.info("Collecting change rate metrics from Cloud Monitoring...")
            print("Collecting change rate metrics from Cloud Monitoring...")
            all_change_rates = {}
            for project_id in project_ids:
                if project_id in [p['project_id'] for p in failed_projects]:
                    continue  # Skip failed projects
                try:
                    # Filter resources for this project
                    proj_resources = [r for r in all_resources if r.metadata.get('project_id') == project_id or r.resource_id.startswith(f"projects/{project_id}")]
                    cr_data = collect_gcp_change_rates(project_id, proj_resources, args.change_rate_days)
                    # Merge into overall change rates
                    for key, summary in cr_data.get('change_rates', {}).items():
                        if key not in all_change_rates:
                            all_change_rates[key] = summary
                        else:
                            # Aggregate across projects
                            existing = all_change_rates[key]
                            existing['resource_count'] += summary['resource_count']
                            existing['total_size_gb'] += summary['total_size_gb']
                            existing['data_change']['daily_change_gb'] += summary['data_change']['daily_change_gb']
                            existing['data_change']['data_points'] += summary['data_change']['data_points']
                            if summary.get('transaction_logs'):
                                if existing.get('transaction_logs'):
                                    existing['transaction_logs']['daily_generation_gb'] += summary['transaction_logs']['daily_generation_gb']
                                else:
                                    existing['transaction_logs'] = summary['transaction_logs']
                except Exception as e:
                    logger.warning(f"Failed to collect change rates for project {project_id}: {e}")
            
            if all_change_rates:
                # Recalculate percentages after aggregation
                for key, summary in all_change_rates.items():
                    if summary['total_size_gb'] > 0 and summary['data_change']['daily_change_gb'] > 0:
                        summary['data_change']['daily_change_percent'] = (
                            summary['data_change']['daily_change_gb'] / summary['total_size_gb'] * 100
                        )
                
                change_rate_data = {
                    'change_rates': all_change_rates,
                    'collection_metadata': {
                        'collected_at': timestamp,
                        'sample_period_days': args.change_rate_days,
                        'notes': [
                            'Data change rates are estimates based on Cloud Monitoring write throughput metrics',
                            'Transaction log rates apply to database services (always 100% capture)',
                            'Use these values to override default DCR assumptions in sizing tools'
                        ]
                    }
                }
                logger.info(f"Collected change rates for {len(all_change_rates)} service families")
        
        # Collect PVCs from GKE clusters (automatic when clusters are discovered)
        gke_clusters = [r for r in all_resources if r.resource_type == 'gcp:container:cluster']
        
        if gke_clusters and not args.skip_pvc:
            logger.info("Collecting PVCs from GKE clusters...")
            print("Collecting PVCs from GKE clusters...")
            
            pvc_count = 0
            k8s_available = True
            for cluster in gke_clusters:
                if not k8s_available:
                    break
                try:
                    # Extract project_id from resource_id: projects/{project}/locations/{location}/clusters/{name}
                    parts = cluster.resource_id.split('/')
                    project_id = parts[1] if len(parts) > 1 else cluster.account_id
                    
                    cluster_pvcs = collect_gke_pvcs(
                        project_id,
                        cluster.region,  # This is the location
                        cluster.name
                    )
                    all_resources.extend(cluster_pvcs)
                    pvc_count += len(cluster_pvcs)
                    if cluster_pvcs:
                        logger.info(f"Found {len(cluster_pvcs)} PVCs in GKE cluster {cluster.name}")
                except ImportError:
                    logger.info("kubernetes package not installed - skipping PVC collection (pip install kubernetes)")
                    print("Note: Install 'kubernetes' package for PVC collection: pip install kubernetes")
                    k8s_available = False
                except Exception as e:
                    logger.warning(f"Failed to collect PVCs from GKE cluster {cluster.name}: {e}")
            
            if pvc_count > 0:
                print(f"Collected {pvc_count} PVCs from {len(gke_clusters)} GKE clusters")
        elif gke_clusters and args.skip_pvc:
            logger.info("Skipping PVC collection (--skip-pvc specified)")
        
        # Prepare output data
        inventory_data = {
            'run_id': run_id,
            'timestamp': timestamp,
            'provider': 'gcp',
            'project_ids': project_ids,
            'resources': [r.to_dict() for r in all_resources]
        }
        
        summary_data = {
            'run_id': run_id,
            'timestamp': timestamp,
            'provider': 'gcp',
            'project_ids': project_ids,
            'total_resources': len(all_resources),
            'sizing': [s.to_dict() for s in sizing],
            'change_rates': change_rate_data if change_rate_data else None
        }
        
        # Remove None values
        summary_data = {k: v for k, v in summary_data.items() if v is not None}
        
        # Write outputs
        output_dir = args.output.rstrip('/')
        
        # Ensure output directory exists
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        # Short timestamp for filenames (HHMMSS)
        file_ts = timestamp[11:19].replace(":", "")
        inv_file = f"{output_dir}/cca_gcp_inv_{file_ts}.json"
        sum_file = f"{output_dir}/cca_gcp_sum_{file_ts}.json"
        csv_file = f"{output_dir}/cca_gcp_sizing.csv"
        
        write_json(inventory_data, inv_file)
        write_json(summary_data, sum_file)
        
        # Write change rate data to separate file if collected
        if change_rate_data:
            change_rate_file = f"{output_dir}/cca_gcp_change_rates_{file_ts}.json"
            change_rate_output = {
                'run_id': run_id,
                'timestamp': timestamp,
                'provider': 'gcp',
                'project_ids': project_ids,
                **change_rate_data
            }
            write_json(change_rate_output, change_rate_file)
        
        # Write CSV for spreadsheet use
        csv_data = [s.to_dict() for s in sizing]
        write_csv(csv_data, csv_file)
        
        # Print detailed results (ProgressTracker already showed collection summary)
        print(f"\nOutput files:")
        print(f"  Inventory: {inv_file}")
        print(f"  Summary: {sum_file}")
        print(f"  Sizing: {csv_file}")
        
        # Print sizing table
        print_summary_table([s.to_dict() for s in sizing])
        
    except Exception as e:
        logger.error(f"Collection failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
