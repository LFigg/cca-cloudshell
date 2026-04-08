# GCP Compute Engine collectors
"""Collectors for Compute Engine instances, disks, and snapshots."""

import logging
from typing import List

from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error

logger = logging.getLogger(__name__)


def collect_compute_instances(project_id: str) -> List[CloudResource]:
    """
    Collect Compute Engine instances across all zones using aggregated list.

    Args:
        project_id: GCP project ID

    Returns:
        List of CloudResource objects for VM instances
    """
    from google.cloud import compute_v1

    resources = []
    try:
        client = compute_v1.InstancesClient()

        request = compute_v1.AggregatedListInstancesRequest(project=project_id)

        for zone, response in client.aggregated_list(request=request):
            if response.instances:
                for instance in response.instances:
                    # Zone format: "zones/us-central1-a"
                    zone_name = zone.split('/')[-1] if '/' in zone else zone
                    region = '-'.join(zone_name.split('-')[:-1])

                    # Calculate total attached disk size
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
        check_and_raise_auth_error(e, "collect Compute Engine instances", "gcp")
        logger.error(f"Failed to collect Compute Engine instances: {e}")

    return resources


def collect_persistent_disks(project_id: str) -> List[CloudResource]:
    """
    Collect Persistent Disks across all zones.

    Args:
        project_id: GCP project ID

    Returns:
        List of CloudResource objects for persistent disks
    """
    from google.cloud import compute_v1

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
                            'encrypted': True,  # All GCP disks are encrypted at rest by default
                            'cmek_enabled': bool(disk.disk_encryption_key),  # Customer-managed keys
                        }
                    )
                    resources.append(resource)

        logger.info(f"Found {len(resources)} Persistent Disks")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Persistent Disks", "gcp")
        logger.error(f"Failed to collect Persistent Disks: {e}")

    return resources


def collect_disk_snapshots(project_id: str) -> List[CloudResource]:
    """
    Collect disk snapshots.

    Args:
        project_id: GCP project ID

    Returns:
        List of CloudResource objects for disk snapshots
    """
    from google.cloud import compute_v1

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
        check_and_raise_auth_error(e, "collect disk snapshots", "gcp")
        logger.error(f"Failed to collect disk snapshots: {e}")

    return resources
