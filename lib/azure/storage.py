"""Azure storage resource collection (Storage accounts, File shares, NetApp)."""
import logging
from typing import List

from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error
from lib.azure.helpers import extract_resource_group

logger = logging.getLogger(__name__)


def collect_storage_accounts(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Storage Accounts."""
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
                region=account.location,
                resource_type="azure:storage:blob",
                service_family="AzureStorage",
                resource_id=account.id,
                name=account.name,
                tags=account.tags or {},
                size_gb=0.0,  # Requires Monitor API for actual usage
                metadata={
                    'resource_group': rg,
                    'sku_name': account.sku.name if account.sku else 'unknown',
                    'kind': str(account.kind),
                    'https_only': account.enable_https_traffic_only,
                    'provisioning_state': account.provisioning_state,
                    'size_note': 'Use Azure Monitor for actual usage'
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure Storage Accounts")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Storage Accounts", "azure")
        logger.error(f"Failed to collect Storage Accounts: {e}")

    return resources


def collect_file_shares(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure File Shares from storage accounts."""
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
            account_location = getattr(account, 'location', '')

            try:
                # List file shares - try with stats first, fall back to basic if it fails
                try:
                    shares = list(storage_client.file_shares.list(rg, account_name, expand='stats'))
                    has_stats = True
                except Exception as stats_err:
                    logger.debug(f"expand='stats' failed for {account_name}, falling back to basic list: {stats_err}")
                    shares = list(storage_client.file_shares.list(rg, account_name))
                    has_stats = False

                for share in shares:
                    share_id = getattr(share, 'id', None)
                    share_name = getattr(share, 'name', '')

                    # Get share quota (provisioned max size in GB)
                    share_quota = getattr(share, 'share_quota', 0) or 0

                    # Get actual usage in bytes (only available with expand='stats')
                    if has_stats:
                        share_usage_bytes = getattr(share, 'share_usage_bytes', 0) or 0
                        share_usage_gb = share_usage_bytes / (1024 * 1024 * 1024) if share_usage_bytes else 0
                    else:
                        share_usage_bytes = 0
                        share_usage_gb = float(share_quota)  # Fall back to quota if no stats

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
                        size_gb=float(share_usage_gb),  # Actual usage if available, else quota
                        parent_resource_id=account_id,
                        metadata={
                            'resource_group': rg,
                            'storage_account': account_name,
                            'share_quota_gb': share_quota,
                            'share_usage_gb': round(share_usage_gb, 2) if has_stats else None,
                            'size_source': 'usage' if has_stats else 'quota',
                            'access_tier': str(access_tier) if access_tier else None,
                            'enabled_protocols': str(enabled_protocols) if enabled_protocols else 'SMB',
                            'last_modified_time': str(getattr(share, 'last_modified_time', '')) if getattr(share, 'last_modified_time', None) else None,
                        }
                    )
                    resources.append(resource)
            except Exception as e:
                logger.debug(f"Failed to list file shares for storage account {account_name}: {e}")

        logger.info(f"Found {len(resources)} Azure File Shares")
    except Exception as e:
        check_and_raise_auth_error(e, "collect File Shares", "azure")
        logger.error(f"Failed to collect File Shares: {e}")

    return resources


def collect_netapp_files(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure NetApp Files volumes."""
    resources = []
    try:
        from azure.mgmt.netapp import NetAppManagementClient

        client = NetAppManagementClient(credential, subscription_id)

        # List all NetApp accounts across subscription
        for account in client.accounts.list_by_subscription():
            account_name = account.name or ''
            rg = account.id.split('/')[4] if account.id else ''
            location = getattr(account, 'location', '')

            # List capacity pools in this account
            try:
                for pool in client.pools.list(rg, account_name):
                    pool_name = (pool.name or '').split('/')[-1] if pool.name and '/' in pool.name else (pool.name or '')

                    # List volumes in this pool
                    try:
                        for volume in client.volumes.list(rg, account_name, pool_name):
                            vol_name = (volume.name or '').split('/')[-1] if volume.name and '/' in volume.name else (volume.name or '')
                            vol_id = getattr(volume, 'id', '')

                            # Volume size in bytes, convert to GB
                            usage_bytes = getattr(volume, 'usage_threshold', 0) or 0
                            size_gb = usage_bytes / (1024 ** 3)

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
                                size_gb=round(size_gb, 2),
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
