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
    write_json, write_csv, setup_logging, print_summary_table
)

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
# Backup & DR Collector
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


# =============================================================================
# Main Collection
# =============================================================================

def collect_project(project_id: str) -> List[CloudResource]:
    """Collect all resources for a project."""
    logger.info(f"Collecting resources for project: {project_id}")
    
    all_resources = []
    
    # Compute Engine
    all_resources.extend(collect_compute_instances(project_id))
    all_resources.extend(collect_persistent_disks(project_id))
    all_resources.extend(collect_disk_snapshots(project_id))
    
    # Storage
    all_resources.extend(collect_storage_buckets(project_id))
    all_resources.extend(collect_filestore_instances(project_id))
    
    # Databases
    all_resources.extend(collect_cloud_sql_instances(project_id))
    all_resources.extend(collect_memorystore_redis(project_id))
    
    # Containers & Compute
    all_resources.extend(collect_gke_clusters(project_id))
    all_resources.extend(collect_cloud_functions(project_id))
    
    # Backup & DR
    all_resources.extend(collect_backup_plans(project_id))
    
    return all_resources


def main():
    parser = argparse.ArgumentParser(description='CCA CloudShell - GCP Resource Collector')
    parser.add_argument('--project', help='GCP project ID (default: current project)')
    parser.add_argument('--all-projects', action='store_true', help='Collect from all accessible projects')
    parser.add_argument('--output', help='Output directory or GCS path', default='.')
    parser.add_argument('--log-level', help='Logging level', default='INFO')
    
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
        
        for project_id in project_ids:
            resources = collect_project(project_id)
            all_resources.extend(resources)
        
        # Generate run ID and timestamp
        run_id = generate_run_id()
        timestamp = get_timestamp()
        
        # Aggregate sizing
        sizing = aggregate_sizing(all_resources)
        
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
            'sizing': [s.to_dict() for s in sizing]
        }
        
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
        
        # Write CSV for spreadsheet use
        csv_data = [s.to_dict() for s in sizing]
        write_csv(csv_data, csv_file)
        
        # Print summary
        print("\n" + "=" * 60)
        print(f"GCP Collection Complete")
        print("=" * 60)
        print(f"Projects: {len(project_ids)}")
        print(f"Total Resources: {len(all_resources)}")
        print(f"\nResources by Type:")
        
        type_counts = {}
        for r in all_resources:
            type_counts[r.resource_type] = type_counts.get(r.resource_type, 0) + 1
        
        for rt, count in sorted(type_counts.items()):
            print(f"  {rt}: {count}")
        
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
