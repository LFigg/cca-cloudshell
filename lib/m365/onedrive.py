"""
M365 Collection Module - OneDrive

OneDrive for Business account collection and usage reporting.
"""

import logging
from typing import Any, Dict, List, Optional

from msgraph.graph_service_client import GraphServiceClient

from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error

from .helpers import (
    collect_all_pages_sync,
    get_usage_report,
    parse_usage_report_csv,
    run_sync,
)

logger = logging.getLogger(__name__)


def collect_onedrive_accounts(
    graph_client: GraphServiceClient,
    tenant_id: str,
    onedrive_usage: Optional[Dict[str, Dict[str, Any]]] = None,
    credential: Optional[Any] = None,
) -> List[CloudResource]:
    """Collect OneDrive for Business accounts.

    Args:
        graph_client: Microsoft Graph client
        tenant_id: Azure AD tenant ID
        onedrive_usage: Dict from collect_onedrive_usage_report() - if provided, creates
                        resources from usage report (recommended for complete data)
        credential: The Graph credential from get_graph_client(), needed only
            for the per-user fallback path (pagination beyond page 1)

    Returns:
        List of CloudResource objects, one per OneDrive account
        (sizing_relevant=True)

    Example:
        graph_client, credential = get_graph_client(tenant_id, client_id, secret)
        onedrive_usage = collect_onedrive_usage_report(graph_client, credential)
        accounts = collect_onedrive_accounts(graph_client, tenant_id, onedrive_usage, credential)
    """
    resources = []

    try:
        # If usage report provided, use it (much more complete than iterating users)
        if onedrive_usage:
            logger.info("Creating OneDrive resources from usage report...")
            for upn, account_data in onedrive_usage.items():
                storage_gb = account_data.get('storage_gb', 0.0)

                resource = CloudResource(
                    provider="microsoft365",
                    subscription_id=tenant_id,
                    region="global",
                    resource_type="m365:onedrive:account",
                    service_family="OneDrive",
                    resource_id=upn,
                    name=upn,
                    tags={},
                    size_gb=storage_gb,
                    sizing_relevant=True,
                    metadata={
                        'user_principal_name': upn,
                        'storage_used_gb': round(storage_gb, 2),
                        'file_count': account_data.get('file_count', 0),
                        'active_file_count': account_data.get('active_file_count', 0),
                        'last_activity_date': account_data.get('last_activity_date', ''),

                        # storage_gb comes from getOneDriveUsageAccountDetail's "Storage
                        # Used (Byte)" column - real measured usage, distinct from that
                        # report's separate "Storage Allocated (Byte)" quota column.
                        'size_source': 'usage',
                    }
                )
                resources.append(resource)

            logger.info(f"Collected {len(resources)} OneDrive accounts from usage report")
            return resources

        # Fallback: Iterate users and get drive (VERY SLOW for large tenants)
        logger.warning(
            "OneDrive usage report not available - falling back to per-user API calls. "
            "This can take HOURS for large tenants (1000+ users). "
            "To fix: Add 'Reports.Read.All' permission to your app registration, "
            "or use --skip-onedrive flag to skip OneDrive collection."
        )
        logger.info("Collecting OneDrive accounts via user iteration...")
        users_response = run_sync(graph_client.users.get())

        # Collect all users across all pages
        all_users = collect_all_pages_sync(users_response, credential)

        failed_count = 0
        no_drive_count = 0
        if all_users:
            for user in all_users:
                try:
                    drive = run_sync(graph_client.users.by_user_id(user.id).drive.get())

                    if drive:
                        storage_used = 0.0
                        storage_quota = 0.0
                        has_quota = False

                        if hasattr(drive, 'quota') and drive.quota:
                            # quota.used is the drive's real measured usage in bytes
                            # (Microsoft Graph `quota` resource type), not an allocation.
                            storage_used = float(drive.quota.used or 0) / (1024**3)
                            storage_quota = float(drive.quota.total or 0) / (1024**3)
                            has_quota = True

                        resource = CloudResource(
                            provider="microsoft365",
                            subscription_id=tenant_id,
                            region="global",
                            resource_type="m365:onedrive:account",
                            service_family="OneDrive",
                            resource_id=drive.id,
                            name=user.user_principal_name or user.display_name or "Unknown",
                            tags={},
                            size_gb=storage_used,
                            sizing_relevant=True,
                            metadata={
                                'user_id': user.id,
                                'user_principal_name': user.user_principal_name,
                                'display_name': user.display_name,
                                'mail': user.mail,
                                'storage_quota_gb': round(storage_quota, 2),
                                'storage_used_gb': round(storage_used, 2),
                                'storage_used_percentage': round((storage_used / storage_quota * 100) if storage_quota > 0 else 0, 2),
                                'drive_type': drive.drive_type if hasattr(drive, 'drive_type') else 'business',
                                'web_url': drive.web_url if hasattr(drive, 'web_url') else None,
                                'size_source': 'usage' if has_quota else 'unavailable',
                            }
                        )
                        resources.append(resource)
                    else:
                        no_drive_count += 1
                except Exception as e:
                    failed_count += 1
                    check_and_raise_auth_error(e, f"process OneDrive for user {user.id}", "m365")
                    logger.warning(f"Failed to process OneDrive for user {user.id}: {e}")
                    continue

        if failed_count > 0:
            logger.warning(f"Failed to process OneDrive for {failed_count} users")
        logger.info(f"Collected {len(resources)} OneDrive accounts ({no_drive_count} users without OneDrive)")

    except Exception as e:
        check_and_raise_auth_error(e, "collect OneDrive accounts", "m365")
        logger.error(f"Failed to collect OneDrive accounts: {e}")

    return resources


def collect_onedrive_usage_report(
    graph_client: GraphServiceClient,
    credential: Optional[Any] = None,
) -> Dict[str, Dict[str, Any]]:
    """Collect OneDrive usage report with historical storage data.

    Returns dict keyed by user principal name with storage history.

    Args:
        graph_client: Microsoft Graph client (kept for API symmetry - the
            report is fetched by credential-authenticated raw HTTP)
        credential: The Graph credential from get_graph_client()

    Returns:
        Dict keyed by lowercased user principal name, each value holding
        storage_bytes, storage_gb, last_activity_date, file_count, and
        active_file_count. Empty dict if the report is unavailable.
    """
    logger.info("Collecting OneDrive usage report...")

    csv_content = get_usage_report('getOneDriveUsageAccountDetail', credential)
    if not csv_content:
        return {}

    rows = parse_usage_report_csv(csv_content)

    # Build lookup by user principal name
    accounts = {}
    for row in rows:
        upn = row.get('Owner Principal Name', row.get('User Principal Name', ''))
        if not upn:
            continue

        # Get storage
        storage_bytes = 0
        for key in ['Storage Used (Byte)', 'Storage Used (Bytes)', 'storageUsedInBytes']:
            if key in row and row[key]:
                try:
                    storage_bytes = int(row[key])
                    break
                except (ValueError, TypeError):
                    pass

        accounts[upn.lower()] = {
            'storage_bytes': storage_bytes,
            'storage_gb': storage_bytes / (1024**3),
            'last_activity_date': row.get('Last Activity Date', ''),
            'file_count': int(row.get('File Count', 0) or 0),
            'active_file_count': int(row.get('Active File Count', 0) or 0)
        }

    logger.info(f"Collected usage data for {len(accounts)} OneDrive accounts")
    return accounts
