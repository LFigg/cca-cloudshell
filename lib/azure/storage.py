"""Azure storage resource collection (Storage accounts, File shares, NetApp)."""
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from lib.azure.helpers import extract_resource_group, normalize_region
from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error

logger = logging.getLogger(__name__)


def collect_storage_accounts(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Storage Accounts.

    Args:
        credential: Azure credential object
        subscription_id: Azure subscription ID

    Returns:
        List of CloudResource objects, one per storage account

    Example:
        resources = collect_storage_accounts(credential, subscription_id)
    """
    from azure.mgmt.storage import StorageManagementClient

    resources = []
    try:
        storage_client = StorageManagementClient(credential, subscription_id)

        for account in storage_client.storage_accounts.list():
            if not account.id:
                continue

            rg = extract_resource_group(account.id)

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=normalize_region(account.location),
                resource_type="azure:storage:blob",
                service_family="AzureStorage",
                resource_id=account.id,
                name=account.name,
                tags=account.tags or {},
                size_gb=0.0,  # Patched with actual usage below via Azure Monitor - never a quota/estimate
                metadata={
                    'resource_group': rg,
                    'sku_name': account.sku.name if account.sku else 'unknown',
                    'kind': str(account.kind),
                    'https_only': account.enable_https_traffic_only,
                    'provisioning_state': account.provisioning_state,
                    # 'unavailable' until the Azure Monitor pass (lib/azure/monitoring.py)
                    # patches this to 'usage' - size_gb stays 0.0, never a guessed value,
                    # if that pass fails or is skipped (--skip-change-rate).
                    'size_source': 'unavailable',
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure Storage Accounts")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Storage Accounts", "azure")
        logger.error(f"Failed to collect Storage Accounts: {e}")

    return resources


def collect_file_shares(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure File Shares from storage accounts.

    Real usage comes from file_shares.get(..., expand='stats')'s share_usage_bytes
    field - a per-share ARM call, fetched in a second pass (parallelized) after
    listing. Note this is the *singular* get() operation: list()'s expand param
    only supports 'deleted'/'snapshots', not 'stats' - trying expand='stats' on
    list() 400s. get() with expand='stats' is a different, documented operation
    that does support it (see https://learn.microsoft.com/rest/api/storagerp/file-shares/get),
    and the installed SDK's FileShare model does have a share_usage_bytes field.

    size_gb is 0.0 (never the provisioned quota) until real usage is confirmed -
    a share whose actual usage couldn't be measured must not silently report its
    quota as if that were sizing data.

    Args:
        credential: Azure credential object
        subscription_id: Azure subscription ID

    Returns:
        List of CloudResource objects, one per file share
    """
    from azure.mgmt.storage import StorageManagementClient

    resources = []
    try:
        storage_client = StorageManagementClient(credential, subscription_id)

        for account in storage_client.storage_accounts.list():
            account_id = getattr(account, 'id', None)
            account_name = getattr(account, 'name', '')
            if not account_id or not account_name:
                continue

            rg = extract_resource_group(account_id)
            account_location = normalize_region(getattr(account, 'location', ''))

            try:
                shares = list(storage_client.file_shares.list(rg, account_name))

                for share in shares:
                    share_id = getattr(share, 'id', None)
                    share_name = getattr(share, 'name', '')

                    # Get share quota (provisioned max size in GB)
                    share_quota = getattr(share, 'share_quota', 0) or 0

                    # Get access tier
                    access_tier = getattr(share, 'access_tier', 'TransactionOptimized')

                    # Get enabled protocols
                    enabled_protocols = getattr(share, 'enabled_protocols', 'SMB')

                    resource = CloudResource(
                        provider="azure",
                        subscription_id=subscription_id,
                        region=account_location,
                        resource_type="azure:storage:fileshare",
                        service_family="AzureFiles",
                        resource_id=share_id or f"{account_id}/fileServices/default/shares/{share_name}",
                        name=share_name,
                        tags={},
                        size_gb=0.0,  # Patched with actual usage below - never the provisioned quota
                        parent_resource_id=account_id,
                        metadata={
                            'resource_group': rg,
                            'storage_account': account_name,
                            'share_quota_gb': share_quota,  # provisioned max - context only, not a size estimate
                            'share_usage_gb': None,
                            'size_source': 'unavailable',
                            'access_tier': str(access_tier) if access_tier else None,
                            'enabled_protocols': str(enabled_protocols) if enabled_protocols else 'SMB',
                            'last_modified_time': str(getattr(share, 'last_modified_time', '')) if getattr(share, 'last_modified_time', None) else None,
                        }
                    )
                    resources.append(resource)
            except Exception as e:
                check_and_raise_auth_error(e, f"list file shares for storage account {account_name}", "azure")
                logger.warning(f"Failed to list file shares for storage account {account_name}: {e}")

        logger.info(f"Found {len(resources)} Azure File Shares")

        if resources:
            _fill_file_share_usage(storage_client, resources)
    except Exception as e:
        check_and_raise_auth_error(e, "collect File Shares", "azure")
        logger.error(f"Failed to collect File Shares: {e}")

    return resources


def _fill_file_share_usage(storage_client, resources: List[CloudResource]) -> None:
    """Patch each file share's size_gb with real usage via file_shares.get(expand='stats').

    Mutates resources in place. Runs in parallel since this is one extra ARM
    call per share on top of the list() already done above.
    """
    def fetch_usage(resource: CloudResource):
        rg = resource.metadata['resource_group']
        account_name = resource.metadata['storage_account']
        share = storage_client.file_shares.get(rg, account_name, resource.name, expand='stats')
        return getattr(share, 'share_usage_bytes', None)

    max_workers = min(16, len(resources))
    logger.info(f"Fetching real usage for {len(resources)} Azure File Shares (parallelized, max {max_workers} concurrent)...")

    patched = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(fetch_usage, r): r for r in resources}
        for future in as_completed(futures):
            resource = futures[future]
            try:
                usage_bytes = future.result()
            except Exception as e:
                check_and_raise_auth_error(e, f"get usage stats for file share {resource.name}", "azure")
                logger.warning(f"Failed to get usage stats for file share {resource.name}: {e}")
                continue

            if usage_bytes is None:
                continue

            usage_gb = usage_bytes / (1024 ** 3)
            resource.size_gb = usage_gb
            resource.metadata['share_usage_gb'] = round(usage_gb, 2)
            resource.metadata['size_source'] = 'usage'
            patched += 1

    if patched < len(resources):
        level = logger.error if patched == 0 else logger.warning
        level(
            f"File share usage stats succeeded for {patched}/{len(resources)} shares; "
            f"the other {len(resources) - patched} report size_gb=0.0 (actual usage "
            "unavailable) rather than their provisioned quota."
        )


def collect_netapp_files(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure NetApp Files volumes.

    Args:
        credential: Azure credential object
        subscription_id: Azure subscription ID

    Returns:
        List of CloudResource objects, one per NetApp Files volume
    """
    resources = []
    try:
        from azure.mgmt.netapp import NetAppManagementClient

        client = NetAppManagementClient(credential, subscription_id)

        # List all NetApp accounts across subscription
        for account in client.accounts.list_by_subscription():
            account_name = account.name or ''
            rg = account.id.split('/')[4] if account.id else ''
            location = normalize_region(getattr(account, 'location', ''))

            # List capacity pools in this account
            try:
                for pool in client.pools.list(rg, account_name):
                    pool_name = (pool.name or '').split('/')[-1] if pool.name and '/' in pool.name else (pool.name or '')

                    # List volumes in this pool
                    try:
                        for volume in client.volumes.list(rg, account_name, pool_name):
                            vol_name = (volume.name or '').split('/')[-1] if volume.name and '/' in volume.name else (volume.name or '')
                            vol_id = getattr(volume, 'id', '')

                            # usage_threshold is the volume's PROVISIONED capacity pool
                            # allocation (despite the SDK's name for it) - it is not
                            # actual bytes used. size_gb starts at 0.0/unavailable here
                            # and is patched later via Azure Monitor's VolumeLogicalSize
                            # metric (see lib/azure/monitoring.py's netapp:volume
                            # branch); it stays 0.0/unavailable if that pass fails or
                            # is skipped.
                            provisioned_bytes = getattr(volume, 'usage_threshold', 0) or 0
                            provisioned_gb = provisioned_bytes / (1024 ** 3)

                            # Get service level (Standard, Premium, Ultra)
                            service_level = getattr(volume, 'service_level', 'Standard')

                            resource = CloudResource(
                                provider="azure",
                                subscription_id=subscription_id,
                                region=location,
                                resource_type="azure:netapp:volume",
                                service_family="NetAppFiles",
                                resource_id=vol_id,
                                name=vol_name,
                                tags=getattr(volume, 'tags', None) or {},
                                size_gb=0.0,
                                metadata={
                                    'resource_group': rg,
                                    'netapp_account': account_name,
                                    'capacity_pool': pool_name,
                                    'service_level': service_level,
                                    'protocol_types': list(getattr(volume, 'protocol_types', []) or []),
                                    'provisioning_state': getattr(volume, 'provisioning_state', ''),
                                    'subnet_id': getattr(volume, 'subnet_id', ''),
                                    'mount_targets': [
                                        {'ip_address': mt.ip_address}
                                        for mt in (getattr(volume, 'mount_targets', []) or [])
                                        if hasattr(mt, 'ip_address')
                                    ],
                                    'snapshot_policy_id': getattr(volume, 'data_protection', {}).get('snapshot', {}).get('snapshot_policy_id') if hasattr(volume, 'data_protection') else None,
                                    'backup_enabled': bool(getattr(volume, 'data_protection', {}).get('backup')) if hasattr(volume, 'data_protection') else False,
                                    'provisioned_capacity_gb': round(provisioned_gb, 2),
                                    'size_source': 'unavailable',
                                }
                            )
                            resources.append(resource)
                    except Exception as e:
                        check_and_raise_auth_error(e, f"list volumes in pool {pool_name}", "azure")
                        logger.warning(f"Failed to list volumes in pool {pool_name}: {e}")
            except Exception as e:
                check_and_raise_auth_error(e, f"list pools in account {account_name}", "azure")
                logger.warning(f"Failed to list pools in account {account_name}: {e}")

        logger.info(f"Found {len(resources)} Azure NetApp Files volumes")
    except ImportError:
        logger.warning("azure-mgmt-netapp not installed. Skipping NetApp collection. Install with: pip install azure-mgmt-netapp")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Azure NetApp Files", "azure")
        logger.error(f"Failed to collect Azure NetApp Files: {e}")

    return resources
