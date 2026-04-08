"""Azure backup resource collection (Recovery Services, protected items, recovery points)."""
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error
from lib.azure.helpers import extract_resource_group

logger = logging.getLogger(__name__)


def collect_recovery_services_vaults(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Recovery Services Vaults."""
    from azure.mgmt.recoveryservices import RecoveryServicesClient
    
    resources = []
    try:
        rs_client = RecoveryServicesClient(credential, subscription_id)

        for vault in rs_client.vaults.list_by_subscription_id():
            vault_id = getattr(vault, 'id', None)
            if not vault_id:
                continue

            rg = extract_resource_group(vault_id)
            vault_sku = getattr(vault, 'sku', None)
            vault_props = getattr(vault, 'properties', None)

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=getattr(vault, 'location', ''),
                resource_type="azure:recoveryservices:vault",
                service_family="AzureBackup",
                resource_id=vault_id,
                name=getattr(vault, 'name', ''),
                tags=getattr(vault, 'tags', None) or {},
                size_gb=0.0,  # Size is in protected items
                metadata={
                    'resource_group': rg,
                    'sku': getattr(vault_sku, 'name', 'unknown') if vault_sku else 'unknown',
                    'provisioning_state': getattr(vault_props, 'provisioning_state', None) if vault_props else None
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Recovery Services Vaults")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Recovery Services Vaults", "azure")
        logger.error(f"Failed to collect Recovery Services Vaults: {e}")

    return resources


def collect_backup_policies(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Backup Policies from all Recovery Services Vaults."""
    from azure.mgmt.recoveryservices import RecoveryServicesClient
    from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
    
    resources = []
    try:
        rs_client = RecoveryServicesClient(credential, subscription_id)

        # First get all vaults
        for vault in rs_client.vaults.list_by_subscription_id():
            vault_id = getattr(vault, 'id', None)
            vault_name = getattr(vault, 'name', '')
            if not vault_id or not vault_name:
                continue

            rg = extract_resource_group(vault_id)

            try:
                backup_client = RecoveryServicesBackupClient(credential, subscription_id)

                # List policies in this vault
                for policy in backup_client.backup_policies.list(vault_name, rg):
                    policy_id = getattr(policy, 'id', None)
                    policy_props = getattr(policy, 'properties', None)

                    # Extract retention and schedule info
                    policy_type = 'unknown'
                    retention_days = None
                    if policy_props:
                        policy_type = getattr(policy_props, 'backup_management_type', 'unknown')
                        # Try to get retention info
                        retention_policy = getattr(policy_props, 'retention_policy', None)
                        if retention_policy:
                            daily_retention = getattr(retention_policy, 'daily_schedule', None)
                            if daily_retention:
                                retention_duration = getattr(daily_retention, 'retention_duration', None)
                                if retention_duration:
                                    retention_days = getattr(retention_duration, 'count', None)

                    resource = CloudResource(
                        provider="azure",
                        subscription_id=subscription_id,
                        region=getattr(vault, 'location', ''),
                        resource_type="azure:backup:policy",
                        service_family="AzureBackup",
                        resource_id=policy_id or '',
                        name=getattr(policy, 'name', ''),
                        tags={},
                        size_gb=0.0,
                        parent_resource_id=vault_id,
                        metadata={
                            'resource_group': rg,
                            'vault_name': vault_name,
                            'policy_type': policy_type,
                            'retention_days': retention_days
                        }
                    )
                    resources.append(resource)
            except Exception as e:
                check_and_raise_auth_error(e, f"list backup policies for vault {vault_name}", "azure")
                logger.warning(f"Failed to list backup policies for vault {vault_name}: {e}")

        logger.info(f"Found {len(resources)} Backup Policies")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Backup Policies", "azure")
        logger.error(f"Failed to collect Backup Policies: {e}")

    return resources


def collect_backup_protected_items(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Backup Protected Items with recovery point counts.

    Recovery point count is included in metadata for each protected item,
    allowing protection status determination without collecting individual RPs.
    """
    from azure.mgmt.recoveryservices import RecoveryServicesClient
    from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
    
    resources = []
    try:
        rs_client = RecoveryServicesClient(credential, subscription_id)

        # First get all vaults
        for vault in rs_client.vaults.list_by_subscription_id():
            vault_id = getattr(vault, 'id', None)
            vault_name = getattr(vault, 'name', '')
            if not vault_id or not vault_name:
                continue

            rg = extract_resource_group(vault_id)
            vault_location = getattr(vault, 'location', '')

            try:
                backup_client = RecoveryServicesBackupClient(credential, subscription_id)

                # List protected items in this vault
                for item in backup_client.backup_protected_items.list(vault_name, rg):
                    item_id = getattr(item, 'id', None)
                    item_props = getattr(item, 'properties', None)

                    # Extract backup details
                    source_resource_id = None
                    workload_type = 'unknown'
                    protection_status = 'unknown'
                    last_backup_time = None
                    backup_size_bytes = 0
                    container_name = ''
                    protected_item_name = getattr(item, 'name', '')

                    if item_props:
                        source_resource_id = getattr(item_props, 'source_resource_id', None)
                        workload_type = getattr(item_props, 'workload_type', 'unknown')
                        protection_status = getattr(item_props, 'protection_status', 'unknown')
                        last_backup_time = getattr(item_props, 'last_backup_time', None)
                        container_name = getattr(item_props, 'container_name', '')
                        friendly_name = getattr(item_props, 'friendly_name', None)
                        if friendly_name:
                            protected_item_name = friendly_name

                        # Try to get backup size from extended info
                        extended_info = getattr(item_props, 'extended_info', None)
                        if extended_info:
                            getattr(extended_info, 'policy_inconsistent', None)

                    # Get recovery point count (lightweight - just count, don't fetch details)
                    recovery_point_count = 0
                    try:
                        rp_list = backup_client.recovery_points.list(
                            vault_name, rg, 'Azure', container_name, protected_item_name
                        )
                        recovery_point_count = sum(1 for _ in rp_list)
                    except Exception as e:
                        logger.debug(f"Could not count recovery points for {protected_item_name}: {e}")

                    # Convert size to GB
                    size_gb = backup_size_bytes / (1024 ** 3) if backup_size_bytes else 0.0

                    resource = CloudResource(
                        provider="azure",
                        subscription_id=subscription_id,
                        region=vault_location,
                        resource_type="azure:backup:protecteditem",
                        service_family="AzureBackup",
                        resource_id=item_id or '',
                        name=getattr(item, 'name', ''),
                        tags={},
                        size_gb=round(size_gb, 2),
                        parent_resource_id=source_resource_id,
                        metadata={
                            'resource_group': rg,
                            'vault_name': vault_name,
                            'workload_type': workload_type,
                            'protection_status': protection_status,
                            'last_backup_time': str(last_backup_time) if last_backup_time else None,
                            'source_resource_id': source_resource_id,
                            'recovery_point_count': recovery_point_count
                        }
                    )
                    resources.append(resource)
            except Exception as e:
                check_and_raise_auth_error(e, f"list protected items for vault {vault_name}", "azure")
                logger.warning(f"Failed to list protected items for vault {vault_name}: {e}")

        logger.info(f"Found {len(resources)} Backup Protected Items")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Backup Protected Items", "azure")
        logger.error(f"Failed to collect Backup Protected Items: {e}")

    return resources


def collect_backup_recovery_points(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Backup Recovery Points (actual backups) with sizes.

    WARNING: This is slow for large backup environments (O(vaults × items × points)).
    Use --include-recovery-points flag to enable. Parallelized across vaults to reduce wall time.
    """
    from azure.mgmt.recoveryservices import RecoveryServicesClient
    from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
    
    resources = []
    try:
        rs_client = RecoveryServicesClient(credential, subscription_id)

        # First get all vaults
        vaults = list(rs_client.vaults.list_by_subscription_id())

        if not vaults:
            logger.info("Found 0 Backup Recovery Points (no vaults)")
            return resources

        def process_vault(vault) -> List[CloudResource]:
            """Process a single vault and return its recovery points."""
            vault_resources = []
            vault_id = getattr(vault, 'id', None)
            vault_name = getattr(vault, 'name', '')
            vault_location = getattr(vault, 'location', '')

            if not vault_id or not vault_name:
                return vault_resources

            rg = extract_resource_group(vault_id)

            try:
                backup_client = RecoveryServicesBackupClient(credential, subscription_id)

                # List protected items to get their recovery points
                for item in backup_client.backup_protected_items.list(vault_name, rg):
                    item_name = getattr(item, 'name', '')
                    item_props = getattr(item, 'properties', None)

                    if not item_name or not item_props:
                        continue

                    container_name = getattr(item_props, 'container_name', '')
                    protected_item_name = getattr(item_props, 'friendly_name', item_name)
                    source_resource_id = getattr(item_props, 'source_resource_id', None)

                    try:
                        for rp in backup_client.recovery_points.list(vault_name, rg, 'Azure', container_name, protected_item_name):
                            rp_id = getattr(rp, 'id', None)
                            rp_name = getattr(rp, 'name', '')
                            rp_props = getattr(rp, 'properties', None)

                            recovery_point_time = None
                            recovery_point_type = 'unknown'
                            recovery_point_size_bytes = 0

                            if rp_props:
                                recovery_point_time = getattr(rp_props, 'recovery_point_time', None)
                                recovery_point_type = getattr(rp_props, 'recovery_point_type', 'unknown')
                                recovery_point_size_bytes = getattr(rp_props, 'recovery_point_size_in_bytes', 0) or 0

                            size_gb = recovery_point_size_bytes / (1024 ** 3) if recovery_point_size_bytes else 0.0

                            resource = CloudResource(
                                provider="azure",
                                subscription_id=subscription_id,
                                region=vault_location,
                                resource_type="azure:backup:recoverypoint",
                                service_family="AzureBackup",
                                resource_id=rp_id or '',
                                name=rp_name,
                                tags={},
                                size_gb=round(size_gb, 2),
                                parent_resource_id=source_resource_id,
                                metadata={
                                    'vault_name': vault_name,
                                    'resource_group': rg,
                                    'recovery_point_time': str(recovery_point_time) if recovery_point_time else None,
                                    'recovery_point_type': recovery_point_type,
                                    'protected_item': protected_item_name,
                                    'container_name': container_name,
                                    'source_resource_id': source_resource_id
                                }
                            )
                            vault_resources.append(resource)
                    except Exception as e:
                        logger.debug(f"Failed to list recovery points for {protected_item_name}: {e}")
            except Exception as e:
                check_and_raise_auth_error(e, f"process vault {vault_name} for recovery points", "azure")
                logger.warning(f"Failed to process vault {vault_name} for recovery points: {e}")

            return vault_resources

        # Parallelize across vaults (max 4 concurrent to avoid throttling)
        max_workers = min(4, len(vaults))
        logger.info(f"Collecting recovery points from {len(vaults)} vaults (parallelized, max {max_workers} concurrent)...")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(process_vault, v): v for v in vaults}
            for future in as_completed(futures):
                try:
                    vault_results = future.result()
                    resources.extend(vault_results)
                except Exception as e:
                    vault = futures[future]
                    logger.warning(f"Failed to process vault {getattr(vault, 'name', 'unknown')}: {e}")

        logger.info(f"Found {len(resources)} Backup Recovery Points")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Backup Recovery Points", "azure")
        logger.error(f"Failed to collect Backup Recovery Points: {e}")

    return resources
