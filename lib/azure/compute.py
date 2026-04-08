"""Azure compute resource collection (VMs, disks, snapshots)."""
import logging
from typing import List

from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error, retry_with_backoff
from lib.azure.helpers import extract_resource_group

logger = logging.getLogger(__name__)


@retry_with_backoff(max_attempts=3)
def collect_vms(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Virtual Machines."""
    from azure.mgmt.compute import ComputeManagementClient
    
    resources = []
    try:
        compute_client = ComputeManagementClient(credential, subscription_id)

        for vm in compute_client.virtual_machines.list_all():
            if not vm.id:
                continue

            rg = extract_resource_group(vm.id)

            # Get OS disk size
            os_disk_size = 0.0
            if vm.storage_profile and vm.storage_profile.os_disk:
                os_disk_size = float(vm.storage_profile.os_disk.disk_size_gb or 0)

            # Count data disks
            data_disk_count = 0
            data_disk_ids = []
            if vm.storage_profile and vm.storage_profile.data_disks:
                data_disk_count = len(vm.storage_profile.data_disks)
                for dd in vm.storage_profile.data_disks:
                    if dd.managed_disk and dd.managed_disk.id:
                        data_disk_ids.append(dd.managed_disk.id)

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=vm.location,
                resource_type="azure:vm",
                service_family="AzureVM",
                resource_id=vm.id,
                name=vm.name,
                tags=vm.tags or {},
                size_gb=os_disk_size,
                metadata={
                    'resource_group': rg,
                    'vm_size': vm.hardware_profile.vm_size if vm.hardware_profile else 'unknown',
                    'os_type': vm.storage_profile.os_disk.os_type if vm.storage_profile and vm.storage_profile.os_disk else 'unknown',
                    'data_disk_count': data_disk_count,
                    'attached_disks': data_disk_ids,
                    'provisioning_state': vm.provisioning_state
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure VMs")
    except Exception as e:
        check_and_raise_auth_error(e, "collect VMs", "azure")
        logger.error(f"Failed to collect VMs: {e}")

    return resources


def collect_disks(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Managed Disks."""
    from azure.mgmt.compute import ComputeManagementClient
    
    resources = []
    try:
        compute_client = ComputeManagementClient(credential, subscription_id)

        for disk in compute_client.disks.list():
            if not disk.id:
                continue

            rg = extract_resource_group(disk.id)

            # Get attached VM if any
            attached_vm = None
            if disk.managed_by:
                attached_vm = disk.managed_by.split('/')[-1]

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=disk.location,
                resource_type="azure:disk",
                service_family="AzureVM",
                resource_id=disk.id,
                name=disk.name,
                tags=disk.tags or {},
                size_gb=float(disk.disk_size_gb or 0),
                parent_resource_id=disk.managed_by,
                metadata={
                    'resource_group': rg,
                    'disk_state': disk.disk_state,
                    'sku': disk.sku.name if disk.sku else 'unknown',
                    'os_type': str(disk.os_type) if disk.os_type else None,
                    'attached_vm': attached_vm,
                    'encryption_type': disk.encryption.type if disk.encryption else 'None',
                    'encrypted': True,  # All Azure managed disks are encrypted at rest by default
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure Managed Disks")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Disks", "azure")
        logger.error(f"Failed to collect Disks: {e}")

    return resources


def collect_disk_snapshots(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Managed Disk Snapshots."""
    from azure.mgmt.compute import ComputeManagementClient
    
    resources = []
    try:
        compute_client = ComputeManagementClient(credential, subscription_id)

        for snapshot in compute_client.snapshots.list():
            snapshot_id = getattr(snapshot, 'id', None)
            if not snapshot_id:
                continue

            rg = extract_resource_group(snapshot_id)

            # Get source disk if available
            source_disk = None
            creation_data = getattr(snapshot, 'creation_data', None)
            if creation_data:
                source_uri = getattr(creation_data, 'source_uri', None) or getattr(creation_data, 'source_resource_id', None)
                if source_uri:
                    source_disk = source_uri.split('/')[-1] if '/' in str(source_uri) else source_uri

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=getattr(snapshot, 'location', ''),
                resource_type="azure:snapshot",
                service_family="AzureVM",
                resource_id=snapshot_id,
                name=getattr(snapshot, 'name', ''),
                tags=getattr(snapshot, 'tags', None) or {},
                size_gb=float(getattr(snapshot, 'disk_size_gb', 0) or 0),
                parent_resource_id=getattr(creation_data, 'source_resource_id', None) if creation_data else None,
                metadata={
                    'resource_group': rg,
                    'source_disk': source_disk,
                    'time_created': str(getattr(snapshot, 'time_created', '')),
                    'sku': getattr(getattr(snapshot, 'sku', None), 'name', 'unknown') if getattr(snapshot, 'sku', None) else 'unknown',
                    'incremental': getattr(snapshot, 'incremental', False),
                    'os_type': str(getattr(snapshot, 'os_type', '')) if getattr(snapshot, 'os_type', None) else None
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure Disk Snapshots")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Disk Snapshots", "azure")
        logger.error(f"Failed to collect Disk Snapshots: {e}")

    return resources
