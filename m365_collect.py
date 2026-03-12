#!/usr/bin/env python3
"""
CCA CloudShell - Microsoft 365 Collector
Standalone collector for M365 resources using Microsoft Graph API.

Authentication Options:
1. DefaultAzureCredential (recommended) - Uses Azure CLI, Managed Identity, etc.
   - In Azure Cloud Shell: credentials are automatic
   - Local with Azure CLI: run 'az login' first

2. App Registration with client secret (for automated/service scenarios)
   - Create App Registration in Entra ID
   - Set MS365_TENANT_ID, MS365_CLIENT_ID, MS365_CLIENT_SECRET env vars

Required Azure AD App Permissions (Application type):
  - Sites.Read.All (SharePoint)
  - Files.Read.All (OneDrive storage)
  - User.Read.All (Users, OneDrive, Exchange)
  - Mail.Read (Exchange mailbox metadata)
  - Group.Read.All (Groups, Teams)
  - Team.ReadBasic.All (Teams details)
  - Reports.Read.All (Usage reports for change rate and growth metrics)

Usage:
    # Option 1: Using Azure CLI (recommended)
    az login
    python m365_collect.py --use-default-credential

    # Option 2: Using environment variables
    export MS365_TENANT_ID="your-tenant-id"
    export MS365_CLIENT_ID="your-client-id"
    export MS365_CLIENT_SECRET="your-client-secret"
    python m365_collect.py

    # Include Entra ID collection
    python m365_collect.py --include-entra
"""

import argparse
import csv
import io
import logging
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Module-level credential storage (avoids accessing SDK internals which change between versions)
_graph_credential = None

# Check for required packages
try:
    from azure.identity import ClientSecretCredential, DefaultAzureCredential
    from msgraph.graph_service_client import GraphServiceClient
except ImportError:
    print("ERROR: Required packages not found.")
    print("")
    print("Please install the required packages manually:")
    print("    pip install msgraph-sdk azure-identity")
    print("")
    print("Or if using a virtual environment:")
    print("    python -m pip install msgraph-sdk azure-identity")
    sys.exit(1)

logger = logging.getLogger(__name__)


# =============================================================================
# Data Models
# =============================================================================

# Add lib to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib.models import CloudResource  # noqa: E402
from lib.utils import ProgressTracker, check_and_raise_auth_error, setup_logging  # noqa: E402
from lib.utils import write_json as _write_json_to_path  # noqa: E402

# Constants for usage report collection
USAGE_REPORT_PERIOD = 'D180'  # 180 days of historical data
USAGE_REPORT_PERIOD_DAYS = 180


@dataclass
class UsageDataPoint:
    """Single data point from a usage report."""
    date: datetime
    storage_bytes: int
    item_count: Optional[int] = None


@dataclass
class ServiceUsageMetrics:
    """Aggregated usage metrics for a service."""
    service_family: str
    resource_count: int = 0
    total_size_gb: float = 0.0
    daily_change_gb: float = 0.0
    daily_change_percent: float = 0.0
    annual_growth_rate_percent: float = 0.0
    sample_period_days: int = USAGE_REPORT_PERIOD_DAYS
    data_points_collected: int = 0

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'service_family': self.service_family,
            'resource_count': self.resource_count,
            'total_size_gb': round(self.total_size_gb, 2),
            'daily_change_gb': round(self.daily_change_gb, 2),
            'daily_change_percent': round(self.daily_change_percent, 2),
            'annual_growth_rate_percent': round(self.annual_growth_rate_percent, 2),
            'sample_period_days': self.sample_period_days,
            'data_points_collected': self.data_points_collected
        }

# =============================================================================
# Graph Client
# =============================================================================

def get_graph_client(tenant_id: str, client_id: str, client_secret: str) -> GraphServiceClient:
    """Create Microsoft Graph API client using client credentials."""
    global _graph_credential
    credential = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret
    )
    _graph_credential = credential  # Store for direct API calls
    scopes = ['https://graph.microsoft.com/.default']
    return GraphServiceClient(credentials=credential, scopes=scopes)


def _is_azure_environment() -> bool:
    """Check if running in Azure Cloud Shell or Azure VM."""
    # Azure Cloud Shell sets these
    if os.environ.get('AZURE_HTTP_USER_AGENT') or os.environ.get('ACC_CLOUD'):
        return True
    # Azure IMDS is only available on Azure VMs
    if os.environ.get('MSI_ENDPOINT') or os.environ.get('IDENTITY_ENDPOINT'):
        return True
    return False


def get_graph_client_default_credential() -> GraphServiceClient:
    """Create Microsoft Graph API client using DefaultAzureCredential.

    This uses the Azure Identity credential chain, which tries (in order):
    1. Environment variables (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
    2. Managed Identity (when running on Azure VMs, App Service, etc.)
    3. Azure CLI credentials (az login)
    4. Azure PowerShell credentials
    5. Interactive browser login (if enabled)

    This is the recommended approach for:
    - Azure Cloud Shell (uses managed identity automatically)
    - Azure VMs with managed identity
    - Local development with Azure CLI login
    """
    # Skip ManagedIdentityCredential on non-Azure machines to avoid IMDS timeout
    # IMDS endpoint doesn't exist outside Azure, causing long hangs
    exclude_mi = not _is_azure_environment()
    if exclude_mi:
        logger.debug("Not in Azure environment, skipping ManagedIdentityCredential")

    global _graph_credential
    credential = DefaultAzureCredential(
        exclude_managed_identity_credential=exclude_mi
    )
    _graph_credential = credential  # Store for direct API calls
    scopes = ['https://graph.microsoft.com/.default']
    return GraphServiceClient(credentials=credential, scopes=scopes)


async def collect_all_pages(initial_response, get_next_page_func) -> List[Any]:
    """Helper to collect all pages from a paginated Graph API response.

    Microsoft Graph API returns max 100 items per page by default.
    This helper follows odata_next_link to collect all items.

    Args:
        initial_response: The first response from a Graph API call
        get_next_page_func: Async function to get next page given a next_link

    Returns:
        List of all items from all pages
    """
    all_items = []
    response = initial_response

    while response:
        if hasattr(response, 'value') and response.value:
            all_items.extend(response.value)

        # Check for next page
        if hasattr(response, 'odata_next_link') and response.odata_next_link:
            try:
                response = await get_next_page_func(response.odata_next_link)
            except Exception as e:
                logger.warning(f"Failed to fetch next page: {e}")
                break
        else:
            break

    return all_items


def collect_all_pages_sync(initial_response) -> List[Any]:
    """Synchronous helper to collect all items from paginated Graph API response.

    For the sync SDK, we simply collect from the initial response's value.
    The msgraph-sdk handles pagination internally for most operations.

    Args:
        initial_response: Response from a Graph API call

    Returns:
        List of all items from the response
    """
    items = []
    if initial_response and hasattr(initial_response, 'value') and initial_response.value:
        items.extend(initial_response.value)

        # Log if there might be more pages (SDK should handle internally, but warn if not)
        if hasattr(initial_response, 'odata_next_link') and initial_response.odata_next_link:
            logger.warning("Response has more pages - large tenants may have incomplete data. "
                         "Consider using async methods for full pagination support.")

    return items


# =============================================================================
# SharePoint Collector
# =============================================================================

def collect_sharepoint_sites(graph_client: GraphServiceClient, tenant_id: str) -> List[CloudResource]:
    """Collect SharePoint sites."""
    resources = []

    try:
        logger.info("Collecting SharePoint sites...")
        sites_response = graph_client.sites.get()

        # Collect all sites across all pages
        all_sites = collect_all_pages_sync(sites_response)

        if all_sites:
            for site in all_sites:
                try:
                    storage_used = 0.0
                    storage_quota = 0.0

                    if hasattr(site, 'quota') and site.quota:
                        storage_used = float(site.quota.used or 0) / (1024**3)
                        storage_quota = float(site.quota.total or 0) / (1024**3)

                    resource = CloudResource(
                        provider="microsoft365",
                        subscription_id=tenant_id,
                        region="global",
                        resource_type="m365:sharepoint:site",
                        service_family="SharePoint",
                        resource_id=site.id,
                        name=site.display_name or site.name or "Unknown",
                        tags={},
                        size_gb=storage_used,
                        metadata={
                            'web_url': site.web_url,
                            'created_datetime': str(site.created_date_time) if hasattr(site, 'created_date_time') and site.created_date_time else None,
                            'last_modified': str(site.last_modified_date_time) if hasattr(site, 'last_modified_date_time') and site.last_modified_date_time else None,
                            'storage_quota_gb': round(storage_quota, 2),
                            'storage_used_gb': round(storage_used, 2),
                            'storage_used_percentage': round((storage_used / storage_quota * 100) if storage_quota > 0 else 0, 2)
                        }
                    )
                    resources.append(resource)
                except Exception as e:
                    logger.debug(f"Failed to process SharePoint site: {e}")
                    continue

        logger.info(f"Collected {len(resources)} SharePoint sites")

    except Exception as e:
        check_and_raise_auth_error(e, "collect SharePoint sites", "m365")
        logger.error(f"Failed to collect SharePoint sites: {e}")

    return resources


# =============================================================================
# OneDrive Collector
# =============================================================================

def collect_onedrive_accounts(graph_client: GraphServiceClient, tenant_id: str) -> List[CloudResource]:
    """Collect OneDrive for Business accounts."""
    resources = []

    try:
        logger.info("Collecting OneDrive accounts...")
        users_response = graph_client.users.get()

        # Collect all users across all pages
        all_users = collect_all_pages_sync(users_response)

        if all_users:
            for user in all_users:
                try:
                    drive = graph_client.users.by_user_id(user.id).drive.get()

                    if drive:
                        storage_used = 0.0
                        storage_quota = 0.0

                        if hasattr(drive, 'quota') and drive.quota:
                            storage_used = float(drive.quota.used or 0) / (1024**3)
                            storage_quota = float(drive.quota.total or 0) / (1024**3)

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
                            metadata={
                                'user_id': user.id,
                                'user_principal_name': user.user_principal_name,
                                'display_name': user.display_name,
                                'mail': user.mail,
                                'storage_quota_gb': round(storage_quota, 2),
                                'storage_used_gb': round(storage_used, 2),
                                'storage_used_percentage': round((storage_used / storage_quota * 100) if storage_quota > 0 else 0, 2),
                                'drive_type': drive.drive_type if hasattr(drive, 'drive_type') else 'business',
                                'web_url': drive.web_url if hasattr(drive, 'web_url') else None
                            }
                        )
                        resources.append(resource)
                except Exception as e:
                    logger.debug(f"Failed to process OneDrive for user {user.id}: {e}")
                    continue

        logger.info(f"Collected {len(resources)} OneDrive accounts")

    except Exception as e:
        check_and_raise_auth_error(e, "collect OneDrive accounts", "m365")
        logger.error(f"Failed to collect OneDrive accounts: {e}")

    return resources


# =============================================================================
# Exchange Collector
# =============================================================================

def collect_exchange_mailboxes(
    graph_client: GraphServiceClient,
    tenant_id: str,
    mailbox_usage: Optional[Dict[str, Dict[str, Any]]] = None
) -> List[CloudResource]:
    """Collect Exchange Online mailboxes from usage report data.

    The usage report is the authoritative source as it includes all mailbox types:
    - User mailboxes (regular user mailboxes)
    - Shared mailboxes (shared departmental mailboxes)
    - Room/Equipment mailboxes (scheduling mailboxes)
    - Group mailboxes (M365 Group mailboxes)

    Args:
        graph_client: Microsoft Graph client
        tenant_id: Azure AD tenant ID
        mailbox_usage: Dict from collect_mailbox_usage_report() - if not provided, will collect
    """
    resources = []

    try:
        logger.info("Collecting Exchange mailboxes...")

        # Get mailbox data from usage report if not provided
        if mailbox_usage is None:
            mailbox_usage = collect_mailbox_usage_report(graph_client)

        if not mailbox_usage:
            logger.warning("No mailbox usage data available - mailbox collection may be incomplete")
            # Fall back to user-based collection
            return _collect_exchange_mailboxes_from_users(graph_client, tenant_id)

        # Create resources from usage report data (includes all mailbox types)
        for upn, usage_data in mailbox_usage.items():
            try:
                # Skip deleted mailboxes unless specifically tracking them
                if usage_data.get('is_deleted', False):
                    continue

                storage_gb = usage_data.get('storage_gb', 0.0)

                resource = CloudResource(
                    provider="microsoft365",
                    subscription_id=tenant_id,
                    region="global",
                    resource_type="m365:exchange:mailbox",
                    service_family="Exchange",
                    resource_id=upn,  # UPN as resource ID
                    name=usage_data.get('display_name') or upn,
                    tags={},
                    size_gb=storage_gb,
                    metadata={
                        'user_principal_name': usage_data.get('user_principal_name', upn),
                        'display_name': usage_data.get('display_name', ''),

                        # Mailbox type info
                        'mailbox_type': usage_data.get('mailbox_type', 'User'),
                        'recipient_type': usage_data.get('recipient_type', 'UserMailbox'),
                        'has_archive': usage_data.get('has_archive', False),

                        # Storage
                        'storage_used_gb': round(storage_gb, 2),
                        'item_count': usage_data.get('item_count', 0),

                        # Deleted items (recoverable items)
                        'deleted_item_count': usage_data.get('deleted_item_count', 0),
                        'deleted_item_size_gb': round(usage_data.get('deleted_item_size_gb', 0.0), 2),

                        # Quotas
                        'prohibit_send_receive_quota_gb': round(usage_data.get('prohibit_send_receive_quota_gb', 0.0), 2),
                        'quota_usage_percent': round(usage_data.get('quota_usage_percent', 0.0), 1),

                        # Activity
                        'last_activity_date': usage_data.get('last_activity_date', ''),
                        'created_date': usage_data.get('created_date', ''),
                    }
                )
                resources.append(resource)
            except Exception as e:
                logger.debug(f"Failed to process mailbox {upn}: {e}")
                continue

        # Log summary by type
        type_counts = {}
        for r in resources:
            t = r.metadata.get('mailbox_type', 'Unknown')
            type_counts[t] = type_counts.get(t, 0) + 1

        logger.info(f"Collected {len(resources)} Exchange mailboxes by type: {type_counts}")

    except Exception as e:
        check_and_raise_auth_error(e, "collect Exchange mailboxes", "m365")
        logger.error(f"Failed to collect Exchange mailboxes: {e}")

    return resources


def _collect_exchange_mailboxes_from_users(
    graph_client: GraphServiceClient,
    tenant_id: str
) -> List[CloudResource]:
    """Fallback: Collect Exchange mailboxes by iterating users.

    This is used when usage report data is not available.
    Note: This only captures user mailboxes, not shared/room/group mailboxes.
    """
    resources = []

    try:
        logger.info("Collecting Exchange mailboxes from users (fallback)...")
        users_response = graph_client.users.get()
        all_users = collect_all_pages_sync(users_response)

        if all_users:
            for user in all_users:
                try:
                    if not user.mail:
                        continue

                    resource = CloudResource(
                        provider="microsoft365",
                        subscription_id=tenant_id,
                        region="global",
                        resource_type="m365:exchange:mailbox",
                        service_family="Exchange",
                        resource_id=user.id,
                        name=user.user_principal_name or user.display_name or "Unknown",
                        tags={},
                        size_gb=0.0,  # Size unknown without usage report
                        metadata={
                            'user_id': user.id,
                            'user_principal_name': user.user_principal_name,
                            'display_name': user.display_name,
                            'mail': user.mail,
                            'mailbox_type': 'User',
                            'recipient_type': 'UserMailbox',
                            'has_archive': False,
                            'account_enabled': user.account_enabled if hasattr(user, 'account_enabled') else True,
                            'created_datetime': str(user.created_date_time) if hasattr(user, 'created_date_time') and user.created_date_time else None,
                        }
                    )
                    resources.append(resource)
                except Exception as e:
                    logger.debug(f"Failed to process mailbox for user {user.id}: {e}")
                    continue

        logger.info(f"Collected {len(resources)} user mailboxes (fallback mode)")

    except Exception as e:
        check_and_raise_auth_error(e, "collect Exchange mailboxes from users", "m365")
        logger.error(f"Failed to collect Exchange mailboxes: {e}")

    return resources


# =============================================================================
# Teams Collector
# =============================================================================

def collect_teams(graph_client: GraphServiceClient, tenant_id: str) -> List[CloudResource]:
    """Collect Microsoft Teams."""
    resources = []

    try:
        logger.info("Collecting Microsoft Teams...")
        groups_response = graph_client.groups.get()

        # Collect all groups across all pages
        all_groups = collect_all_pages_sync(groups_response)

        if all_groups:
            for group in all_groups:
                try:
                    if not hasattr(group, 'resource_provisioning_options') or \
                       'Team' not in (group.resource_provisioning_options or []):
                        continue

                    # Get team details
                    try:
                        team = graph_client.teams.by_team_id(group.id).get()
                    except Exception as e:
                        logger.debug(f"Could not fetch team details for {group.id}: {e}")
                        team = None

                    resource = CloudResource(
                        provider="microsoft365",
                        subscription_id=tenant_id,
                        region="global",
                        resource_type="m365:teams:team",
                        service_family="Teams",
                        resource_id=group.id,
                        name=team.display_name if team else group.display_name or "Unknown",
                        tags={},
                        size_gb=0.0,  # Teams storage is part of SharePoint
                        metadata={
                            'group_id': group.id,
                            'description': (team.description if team else group.description) or None,
                            'visibility': (team.visibility if team and hasattr(team, 'visibility') else group.visibility) if hasattr(group, 'visibility') else None,
                            'created_datetime': str(group.created_date_time) if hasattr(group, 'created_date_time') and group.created_date_time else None,
                            'is_archived': team.is_archived if team and hasattr(team, 'is_archived') else False,
                            'web_url': team.web_url if team and hasattr(team, 'web_url') else None
                        }
                    )
                    resources.append(resource)
                except Exception as e:
                    logger.debug(f"Failed to process Team {group.id}: {e}")
                    continue

        logger.info(f"Collected {len(resources)} Teams")

    except Exception as e:
        check_and_raise_auth_error(e, "collect Teams", "m365")
        logger.error(f"Failed to collect Teams: {e}")

    return resources


def get_total_user_count(graph_client: GraphServiceClient) -> int:
    """Get total user count in the tenant.

    Returns count of all users (including disabled accounts).
    """
    try:
        logger.info("Getting total user count...")
        users_response = graph_client.users.get()
        all_users = collect_all_pages_sync(users_response)
        count = len(all_users) if all_users else 0
        logger.info(f"Total users in tenant: {count}")
        return count
    except Exception as e:
        logger.warning(f"Failed to get user count: {e}")
        return 0


# =============================================================================
# Usage Reports Collection (Change Rate & Growth)
# =============================================================================

def _parse_usage_report_csv(csv_content: str) -> List[Dict[str, Any]]:
    """Parse CSV content from Microsoft Graph usage reports.

    Microsoft Graph reports API returns CSV with a BOM marker and
    the first line contains report metadata that we skip.
    """
    # Remove BOM if present
    if csv_content.startswith('\ufeff'):
        csv_content = csv_content[1:]

    # Parse CSV
    reader = csv.DictReader(io.StringIO(csv_content))
    return list(reader)


def _get_usage_report(graph_client: GraphServiceClient, report_name: str) -> Optional[str]:
    """Fetch a usage report from Microsoft Graph.

    Args:
        graph_client: Microsoft Graph client
        report_name: Report name like 'getSharePointSiteUsageDetail'

    Returns:
        CSV content as string, or None on failure
    """
    try:
        # Build the report URL with period parameter
        # Note: The msgraph-sdk doesn't have typed methods for all reports,
        # so we use the underlying request builder
        import httpx

        # Get access token from stored credential (avoids accessing SDK internals)
        # We need to make a raw HTTP request for the reports API
        if _graph_credential is None:
            raise RuntimeError("Graph credential not initialized. Call get_graph_client first.")
        token = _graph_credential.get_token("https://graph.microsoft.com/.default")

        url = f"https://graph.microsoft.com/v1.0/reports/{report_name}(period='{USAGE_REPORT_PERIOD}')"

        headers = {
            'Authorization': f'Bearer {token.token}',
            'Accept': 'application/json'
        }

        with httpx.Client(follow_redirects=True, timeout=120.0) as client:
            response = client.get(url, headers=headers)
            response.raise_for_status()
            return response.text

    except Exception as e:
        logger.warning(f"Failed to fetch usage report {report_name}: {e}")
        return None


def collect_sharepoint_usage_report(graph_client: GraphServiceClient) -> Dict[str, Dict[str, Any]]:
    """Collect SharePoint site usage report with historical storage data.

    Returns dict keyed by site URL with storage and site type.
    """
    logger.info("Collecting SharePoint usage report...")

    csv_content = _get_usage_report(graph_client, 'getSharePointSiteUsageDetail')
    if not csv_content:
        return {}

    rows = _parse_usage_report_csv(csv_content)

    # Build lookup by site URL
    # Report includes: Site URL, Site Type, Root Web Template, Storage Used (Byte), etc.
    sites = {}
    for row in rows:
        site_url = _get_csv_field(row, 'Site URL', 'Site Url', 'siteUrl')
        if not site_url:
            continue

        # Get storage
        storage_bytes = _safe_int(_get_csv_field(
            row, 'Storage Used (Byte)', 'Storage Used (Bytes)', 'storageUsedInBytes'
        ))

        # Get site type - this distinguishes Team Sites from SharePoint Sites
        # Common values: Team Site, Communication Site, Group, Personal Site (OneDrive)
        site_type = _get_csv_field(row, 'Site Type', 'siteType') or ''
        root_web_template = _get_csv_field(row, 'Root Web Template', 'rootWebTemplate') or ''

        # Determine if it's a Team Site (Teams-connected) or SharePoint Site
        is_team_site = (
            'group' in site_type.lower() or
            'team' in site_type.lower() or
            root_web_template in ('GROUP', 'Group#0', 'TEAMCHANNEL')
        )

        # Is deleted
        is_deleted_raw = _get_csv_field(row, 'Is Deleted', 'isDeleted')
        is_deleted = str(is_deleted_raw).lower() in ('yes', 'true', '1') if is_deleted_raw else False

        sites[site_url] = {
            'storage_bytes': storage_bytes,
            'storage_gb': storage_bytes / (1024**3),
            'last_activity_date': _get_csv_field(row, 'Last Activity Date', 'lastActivityDate') or '',
            'file_count': _safe_int(_get_csv_field(row, 'File Count', 'fileCount')),
            'active_file_count': _safe_int(_get_csv_field(row, 'Active File Count', 'activeFileCount')),
            'page_view_count': _safe_int(_get_csv_field(row, 'Page View Count', 'pageViewCount')),
            'site_id': _get_csv_field(row, 'Site Id', 'siteId') or '',
            'site_type': site_type,
            'root_web_template': root_web_template,
            'is_team_site': is_team_site,
            'is_deleted': is_deleted,
            'owner_display_name': _get_csv_field(row, 'Owner Display Name', 'ownerDisplayName') or '',
        }

    # Log summary
    team_sites = sum(1 for s in sites.values() if s['is_team_site'])
    sp_sites = len(sites) - team_sites
    logger.info(f"Collected usage data for {len(sites)} SharePoint sites ({team_sites} Team Sites, {sp_sites} SharePoint Sites)")
    return sites


def collect_onedrive_usage_report(graph_client: GraphServiceClient) -> Dict[str, Dict[str, Any]]:
    """Collect OneDrive usage report with historical storage data.

    Returns dict keyed by user principal name with storage history.
    """
    logger.info("Collecting OneDrive usage report...")

    csv_content = _get_usage_report(graph_client, 'getOneDriveUsageAccountDetail')
    if not csv_content:
        return {}

    rows = _parse_usage_report_csv(csv_content)

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


def _safe_int(value: Any, default: int = 0) -> int:
    """Safely convert value to int."""
    if value is None or value == '':
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert value to float."""
    if value is None or value == '':
        return default
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def _get_csv_field(row: Dict[str, Any], *keys: str) -> Any:
    """Get field value trying multiple possible key names."""
    for key in keys:
        if key in row and row[key] is not None and row[key] != '':
            return row[key]
    return None


def collect_mailbox_usage_report(graph_client: GraphServiceClient) -> Dict[str, Dict[str, Any]]:
    """Collect Exchange mailbox usage report with comprehensive data.

    Returns dict keyed by user principal name with full mailbox details including:
    - Storage size (primary mailbox)
    - Item counts
    - Mailbox type (UserMailbox, SharedMailbox, SchedulingMailbox, GroupMailbox)
    - Archive status
    - Quotas
    - Activity dates
    - Deleted item info
    """
    logger.info("Collecting Exchange mailbox usage report...")

    csv_content = _get_usage_report(graph_client, 'getMailboxUsageDetail')
    if not csv_content:
        return {}

    rows = _parse_usage_report_csv(csv_content)

    # Build lookup by user principal name
    mailboxes = {}
    for row in rows:
        upn = _get_csv_field(row, 'User Principal Name', 'userPrincipalName')
        if not upn:
            continue

        # Storage used (bytes)
        storage_bytes = _safe_int(_get_csv_field(
            row, 'Storage Used (Byte)', 'Storage Used (Bytes)', 'storageUsedInBytes'
        ))

        # Item count
        item_count = _safe_int(_get_csv_field(row, 'Item Count', 'itemCount'))

        # Deleted items
        deleted_item_count = _safe_int(_get_csv_field(
            row, 'Deleted Item Count', 'deletedItemCount'
        ))
        deleted_item_size_bytes = _safe_int(_get_csv_field(
            row, 'Deleted Item Size (Byte)', 'Deleted Item Size (Bytes)', 'deletedItemSizeInBytes'
        ))

        # Mailbox type from Recipient Type field
        recipient_type = _get_csv_field(row, 'Recipient Type', 'recipientType')

        # Map recipient types to friendly names
        mailbox_type_map = {
            'UserMailbox': 'User',
            'SharedMailbox': 'Shared',
            'RoomMailbox': 'Room',
            'EquipmentMailbox': 'Equipment',
            'SchedulingMailbox': 'Scheduling',
            'GroupMailbox': 'Group',
            'DiscoveryMailbox': 'Discovery',
        }
        mailbox_type = mailbox_type_map.get(recipient_type, recipient_type or 'User')

        # Archive status
        has_archive_raw = _get_csv_field(row, 'Has Archive', 'hasArchive')
        has_archive = str(has_archive_raw).lower() in ('yes', 'true', '1') if has_archive_raw else False

        # Is deleted
        is_deleted_raw = _get_csv_field(row, 'Is Deleted', 'isDeleted')
        is_deleted = str(is_deleted_raw).lower() in ('yes', 'true', '1') if is_deleted_raw else False

        # Quotas (bytes)
        issue_warning_quota = _safe_int(_get_csv_field(
            row, 'Issue Warning Quota (Byte)', 'Issue Warning Quota (Bytes)', 'issueWarningQuotaInBytes'
        ))
        prohibit_send_quota = _safe_int(_get_csv_field(
            row, 'Prohibit Send Quota (Byte)', 'Prohibit Send Quota (Bytes)', 'prohibitSendQuotaInBytes'
        ))
        prohibit_send_receive_quota = _safe_int(_get_csv_field(
            row, 'Prohibit Send/Receive Quota (Byte)', 'Prohibit Send/Receive Quota (Bytes)',
            'prohibitSendReceiveQuotaInBytes'
        ))
        deleted_item_quota = _safe_int(_get_csv_field(
            row, 'Deleted Item Quota (Byte)', 'Deleted Item Quota (Bytes)', 'deletedItemQuotaInBytes'
        ))

        # Dates
        display_name = _get_csv_field(row, 'Display Name', 'displayName') or ''
        last_activity_date = _get_csv_field(row, 'Last Activity Date', 'lastActivityDate') or ''
        created_date = _get_csv_field(row, 'Created Date', 'createdDate') or ''
        deleted_date = _get_csv_field(row, 'Deleted Date', 'deletedDate') or ''

        mailboxes[upn.lower()] = {
            # Identity
            'user_principal_name': upn,
            'display_name': display_name,

            # Type and status
            'recipient_type': recipient_type or 'UserMailbox',
            'mailbox_type': mailbox_type,
            'has_archive': has_archive,
            'is_deleted': is_deleted,

            # Storage
            'storage_bytes': storage_bytes,
            'storage_gb': storage_bytes / (1024**3),
            'item_count': item_count,

            # Deleted items (recoverable)
            'deleted_item_count': deleted_item_count,
            'deleted_item_size_bytes': deleted_item_size_bytes,
            'deleted_item_size_gb': deleted_item_size_bytes / (1024**3),

            # Quotas (in GB for readability)
            'issue_warning_quota_gb': issue_warning_quota / (1024**3) if issue_warning_quota else 0.0,
            'prohibit_send_quota_gb': prohibit_send_quota / (1024**3) if prohibit_send_quota else 0.0,
            'prohibit_send_receive_quota_gb': prohibit_send_receive_quota / (1024**3) if prohibit_send_receive_quota else 0.0,
            'deleted_item_quota_gb': deleted_item_quota / (1024**3) if deleted_item_quota else 0.0,

            # Calculate quota usage percentage
            'quota_usage_percent': (storage_bytes / prohibit_send_receive_quota * 100) if prohibit_send_receive_quota else 0.0,

            # Dates
            'last_activity_date': last_activity_date,
            'created_date': created_date,
            'deleted_date': deleted_date,
        }

    # Log summary by type
    type_counts = {}
    for mb in mailboxes.values():
        t = mb['mailbox_type']
        type_counts[t] = type_counts.get(t, 0) + 1

    logger.info(f"Collected usage data for {len(mailboxes)} Exchange mailboxes: {type_counts}")
    return mailboxes


def collect_teams_activity_report(graph_client: GraphServiceClient) -> Dict[str, Any]:
    """Collect Teams activity report for chat/meeting metrics.

    Returns dict with Teams chat and meeting activity data including:
    - Team chat message counts
    - Private chat message counts
    - Calls and meetings counts
    - Total estimated metered units
    """
    logger.info("Collecting Teams activity report...")

    csv_content = _get_usage_report(graph_client, 'getTeamsUserActivityUserDetail')
    if not csv_content:
        return {}

    rows = _parse_usage_report_csv(csv_content)

    # Aggregate activity across all users
    totals = {
        'team_chat_message_count': 0,
        'private_chat_message_count': 0,
        'call_count': 0,
        'meeting_count': 0,
        'meetings_organized_count': 0,
        'meetings_attended_count': 0,
        'ad_hoc_meetings_organized_count': 0,
        'scheduled_one_time_meetings_organized_count': 0,
        'scheduled_recurring_meetings_organized_count': 0,
        'audio_duration_seconds': 0,
        'video_duration_seconds': 0,
        'screen_share_duration_seconds': 0,
        'active_users': 0,
        'users_with_activity': 0,
    }

    for row in rows:
        # Check if user had any activity
        has_activity = any([
            _safe_int(_get_csv_field(row, 'Team Chat Message Count', 'teamChatMessageCount')) > 0,
            _safe_int(_get_csv_field(row, 'Private Chat Message Count', 'privateChatMessageCount')) > 0,
            _safe_int(_get_csv_field(row, 'Call Count', 'callCount')) > 0,
            _safe_int(_get_csv_field(row, 'Meeting Count', 'meetingCount')) > 0,
        ])

        if has_activity:
            totals['users_with_activity'] += 1

        # Aggregate message counts
        totals['team_chat_message_count'] += _safe_int(_get_csv_field(
            row, 'Team Chat Message Count', 'teamChatMessageCount'
        ))
        totals['private_chat_message_count'] += _safe_int(_get_csv_field(
            row, 'Private Chat Message Count', 'privateChatMessageCount'
        ))

        # Aggregate calls/meetings
        totals['call_count'] += _safe_int(_get_csv_field(row, 'Call Count', 'callCount'))
        totals['meeting_count'] += _safe_int(_get_csv_field(row, 'Meeting Count', 'meetingCount'))
        totals['meetings_organized_count'] += _safe_int(_get_csv_field(
            row, 'Meetings Organized Count', 'meetingsOrganizedCount'
        ))
        totals['meetings_attended_count'] += _safe_int(_get_csv_field(
            row, 'Meetings Attended Count', 'meetingsAttendedCount'
        ))

        # Duration tracking (in seconds)
        totals['audio_duration_seconds'] += _safe_int(_get_csv_field(
            row, 'Audio Duration In Seconds', 'audioDurationInSeconds'
        ))
        totals['video_duration_seconds'] += _safe_int(_get_csv_field(
            row, 'Video Duration In Seconds', 'videoDurationInSeconds'
        ))
        totals['screen_share_duration_seconds'] += _safe_int(_get_csv_field(
            row, 'Screen Share Duration In Seconds', 'screenShareDurationInSeconds'
        ))

        totals['active_users'] += 1

    # Calculate estimated metered units (messages are the primary metered resource)
    # Microsoft's metering is complex, but chat messages are primary
    totals['estimated_metered_units_user_chats'] = totals['private_chat_message_count']
    totals['estimated_metered_units_channel_conversations'] = totals['team_chat_message_count']
    totals['total_estimated_metered_units'] = (
        totals['private_chat_message_count'] + totals['team_chat_message_count']
    )

    # Project for next year (linear projection from 180-day report period)
    days_in_period = USAGE_REPORT_PERIOD_DAYS
    projection_factor = 365 / days_in_period
    totals['projected_annual_metered_units'] = int(totals['total_estimated_metered_units'] * projection_factor)
    totals['total_metered_units_with_projection'] = (
        totals['total_estimated_metered_units'] + totals['projected_annual_metered_units']
    )

    logger.info(f"Collected Teams activity for {totals['active_users']} users: "
                f"{totals['total_estimated_metered_units']:,} metered units")
    return totals


def generate_exchange_summary(mailbox_usage: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Generate comprehensive Exchange Online summary matching sizing spreadsheet format.

    Categories:
    - User Active Mailboxes (active, not deleted, recipient type UserMailbox)
    - User Archive Mailboxes (has archive enabled - note: archive SIZE requires PowerShell)
    - SoftDeleted Active Mailboxes (is_deleted=True)
    - SoftDeleted Archive Mailboxes (is_deleted=True with archive)
    - Group Active Mailboxes (GroupMailbox recipient type)
    - Group Archive Mailboxes (GroupMailbox with archive)
    - PublicFolder Active Mailboxes (PublicFolderMailbox recipient type)
    """
    summary = {
        'user_active': {'count': 0, 'item_count': 0, 'item_size_gib': 0.0,
                        'recoverable_item_count': 0, 'recoverable_item_size_gib': 0.0},
        'user_archive_enabled': {'count': 0},  # Note: Archive SIZE not available via Graph API
        'softdeleted_active': {'count': 0, 'item_count': 0, 'item_size_gib': 0.0,
                               'recoverable_item_count': 0, 'recoverable_item_size_gib': 0.0},
        'softdeleted_archive': {'count': 0},
        'group_active': {'count': 0, 'item_count': 0, 'item_size_gib': 0.0,
                         'recoverable_item_count': 0, 'recoverable_item_size_gib': 0.0},
        'group_archive': {'count': 0},
        'publicfolder_active': {'count': 0, 'item_count': 0, 'item_size_gib': 0.0,
                                'recoverable_item_count': 0, 'recoverable_item_size_gib': 0.0},
        'shared_active': {'count': 0, 'item_count': 0, 'item_size_gib': 0.0,
                          'recoverable_item_count': 0, 'recoverable_item_size_gib': 0.0},
        'room_equipment_active': {'count': 0, 'item_count': 0, 'item_size_gib': 0.0,
                                   'recoverable_item_count': 0, 'recoverable_item_size_gib': 0.0},
    }

    for _upn, mb in mailbox_usage.items():
        recipient_type = mb.get('recipient_type', 'UserMailbox')
        is_deleted = mb.get('is_deleted', False)
        has_archive = mb.get('has_archive', False)

        item_count = mb.get('item_count', 0)
        item_size_gib = mb.get('storage_gb', 0.0)
        recoverable_count = mb.get('deleted_item_count', 0)
        recoverable_size_gib = mb.get('deleted_item_size_gb', 0.0)

        # Categorize by recipient type and status
        if recipient_type == 'GroupMailbox':
            if is_deleted:
                summary['softdeleted_active']['count'] += 1  # Soft-deleted groups
            else:
                summary['group_active']['count'] += 1
                summary['group_active']['item_count'] += item_count
                summary['group_active']['item_size_gib'] += item_size_gib
                summary['group_active']['recoverable_item_count'] += recoverable_count
                summary['group_active']['recoverable_item_size_gib'] += recoverable_size_gib
                if has_archive:
                    summary['group_archive']['count'] += 1

        elif recipient_type == 'PublicFolderMailbox':
            summary['publicfolder_active']['count'] += 1
            summary['publicfolder_active']['item_count'] += item_count
            summary['publicfolder_active']['item_size_gib'] += item_size_gib
            summary['publicfolder_active']['recoverable_item_count'] += recoverable_count
            summary['publicfolder_active']['recoverable_item_size_gib'] += recoverable_size_gib

        elif recipient_type == 'SharedMailbox':
            if is_deleted:
                summary['softdeleted_active']['count'] += 1
            else:
                summary['shared_active']['count'] += 1
                summary['shared_active']['item_count'] += item_count
                summary['shared_active']['item_size_gib'] += item_size_gib
                summary['shared_active']['recoverable_item_count'] += recoverable_count
                summary['shared_active']['recoverable_item_size_gib'] += recoverable_size_gib

        elif recipient_type in ('RoomMailbox', 'EquipmentMailbox', 'SchedulingMailbox'):
            summary['room_equipment_active']['count'] += 1
            summary['room_equipment_active']['item_count'] += item_count
            summary['room_equipment_active']['item_size_gib'] += item_size_gib
            summary['room_equipment_active']['recoverable_item_count'] += recoverable_count
            summary['room_equipment_active']['recoverable_item_size_gib'] += recoverable_size_gib

        else:  # UserMailbox or unknown
            if is_deleted:
                summary['softdeleted_active']['count'] += 1
                summary['softdeleted_active']['item_count'] += item_count
                summary['softdeleted_active']['item_size_gib'] += item_size_gib
                summary['softdeleted_active']['recoverable_item_count'] += recoverable_count
                summary['softdeleted_active']['recoverable_item_size_gib'] += recoverable_size_gib
                if has_archive:
                    summary['softdeleted_archive']['count'] += 1
            else:
                summary['user_active']['count'] += 1
                summary['user_active']['item_count'] += item_count
                summary['user_active']['item_size_gib'] += item_size_gib
                summary['user_active']['recoverable_item_count'] += recoverable_count
                summary['user_active']['recoverable_item_size_gib'] += recoverable_size_gib
                if has_archive:
                    summary['user_archive_enabled']['count'] += 1

    # Calculate totals for each category
    for category in summary.values():
        if 'item_count' in category:
            category['total_item_count'] = category['item_count'] + category.get('recoverable_item_count', 0)
            category['total_item_size_gib'] = round(
                category['item_size_gib'] + category.get('recoverable_item_size_gib', 0.0), 3
            )
            # Round individual values
            category['item_size_gib'] = round(category['item_size_gib'], 3)
            category['recoverable_item_size_gib'] = round(category.get('recoverable_item_size_gib', 0.0), 3)

    # Calculate grand totals
    summary['totals_default'] = {
        'count': summary['user_active']['count'],
        'item_count': summary['user_active']['item_count'],
        'item_size_gib': summary['user_active']['item_size_gib'],
        'recoverable_item_count': summary['user_active']['recoverable_item_count'],
        'recoverable_item_size_gib': summary['user_active']['recoverable_item_size_gib'],
        'total_item_count': summary['user_active']['total_item_count'],
        'total_item_size_gib': summary['user_active']['total_item_size_gib'],
    }

    # Totals with all options (including deleted, groups, shared, etc.)
    all_active_categories = ['user_active', 'group_active', 'publicfolder_active',
                              'shared_active', 'room_equipment_active', 'softdeleted_active']
    summary['totals_all'] = {
        'count': sum(summary[cat]['count'] for cat in all_active_categories),
        'item_count': sum(summary[cat].get('item_count', 0) for cat in all_active_categories),
        'item_size_gib': round(sum(summary[cat].get('item_size_gib', 0.0) for cat in all_active_categories), 3),
        'recoverable_item_count': sum(summary[cat].get('recoverable_item_count', 0) for cat in all_active_categories),
        'recoverable_item_size_gib': round(sum(summary[cat].get('recoverable_item_size_gib', 0.0) for cat in all_active_categories), 3),
    }
    summary['totals_all']['total_item_count'] = (
        summary['totals_all']['item_count'] + summary['totals_all']['recoverable_item_count']
    )
    summary['totals_all']['total_item_size_gib'] = round(
        summary['totals_all']['item_size_gib'] + summary['totals_all']['recoverable_item_size_gib'], 3
    )

    return summary


def generate_sharepoint_summary(site_usage: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Generate SharePoint Online summary with site type breakdown.

    Categories:
    - SharePoint Sites (Communication sites, Publishing sites)
    - Team Sites (Teams-connected sites)
    """
    summary = {
        'sharepoint_sites': {'count': 0, 'storage_gib': 0.0},
        'team_sites': {'count': 0, 'storage_gib': 0.0},
        'deleted_sites': {'count': 0, 'storage_gib': 0.0},
        'total': {'count': 0, 'storage_gib': 0.0},
    }

    for _url, site in site_usage.items():
        if site.get('is_deleted', False):
            summary['deleted_sites']['count'] += 1
            summary['deleted_sites']['storage_gib'] += site.get('storage_gb', 0.0)
        elif site.get('is_team_site', False):
            summary['team_sites']['count'] += 1
            summary['team_sites']['storage_gib'] += site.get('storage_gb', 0.0)
        else:
            summary['sharepoint_sites']['count'] += 1
            summary['sharepoint_sites']['storage_gib'] += site.get('storage_gb', 0.0)

    # Total (excluding deleted)
    summary['total']['count'] = summary['sharepoint_sites']['count'] + summary['team_sites']['count']
    summary['total']['storage_gib'] = round(
        summary['sharepoint_sites']['storage_gib'] + summary['team_sites']['storage_gib'], 3
    )

    # Round values
    for cat in summary.values():
        cat['storage_gib'] = round(cat['storage_gib'], 3)

    return summary


def collect_storage_history_report(graph_client: GraphServiceClient, service: str) -> List[Dict[str, Any]]:
    """Collect storage history to calculate change rate and growth.

    Args:
        service: 'sharepoint', 'onedrive', or 'mailbox'

    Returns:
        List of daily totals with date and storage_bytes
    """
    report_map = {
        'sharepoint': 'getSharePointSiteUsageStorage',
        'onedrive': 'getOneDriveUsageStorage',
        'mailbox': 'getMailboxUsageStorage'
    }

    report_name = report_map.get(service)
    if not report_name:
        return []

    logger.info(f"Collecting {service} storage history...")

    csv_content = _get_usage_report(graph_client, report_name)
    if not csv_content:
        return []

    rows = _parse_usage_report_csv(csv_content)

    history = []
    for row in rows:
        date_str = row.get('Report Date', '')
        if not date_str:
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

        try:
            datetime.strptime(date_str, '%Y-%m-%d')
            history.append({
                'date': date_str,
                'storage_bytes': storage_bytes
            })
        except ValueError:
            continue

    # Sort by date
    history.sort(key=lambda x: x['date'])

    logger.info(f"Collected {len(history)} days of {service} storage history")
    return history


def calculate_change_rate_and_growth(history: List[Dict[str, Any]]) -> Dict[str, float]:
    """Calculate daily change rate and annual growth from storage history.

    Args:
        history: List of {'date': str, 'storage_bytes': int} sorted by date

    Returns:
        Dict with daily_change_gb, daily_change_percent, annual_growth_percent
    """
    if len(history) < 7:
        return {
            'daily_change_gb': 0.0,
            'daily_change_percent': 0.0,
            'annual_growth_percent': 0.0
        }

    # Calculate daily deltas
    daily_deltas = []
    for i in range(1, len(history)):
        prev = history[i-1]['storage_bytes']
        curr = history[i]['storage_bytes']
        if prev > 0:
            delta_bytes = curr - prev
            delta_percent = (delta_bytes / prev) * 100
            daily_deltas.append({
                'delta_bytes': delta_bytes,
                'delta_percent': delta_percent
            })

    if not daily_deltas:
        return {
            'daily_change_gb': 0.0,
            'daily_change_percent': 0.0,
            'annual_growth_percent': 0.0
        }

    # Average daily change (use absolute values for change rate - it's about backup data volume)
    avg_daily_change_bytes = sum(abs(d['delta_bytes']) for d in daily_deltas) / len(daily_deltas)

    # Current storage for percentage calculation
    current_storage = history[-1]['storage_bytes']
    avg_daily_change_pct = (avg_daily_change_bytes / current_storage * 100) if current_storage > 0 else 0

    # Annual growth: compare first and last values, extrapolate to a year
    first_storage = history[0]['storage_bytes']
    last_storage = history[-1]['storage_bytes']
    period_days = len(history)

    if first_storage > 0 and period_days > 0:
        period_growth = (last_storage - first_storage) / first_storage
        # Extrapolate to annual (365 days)
        annual_growth = period_growth * (365 / period_days) * 100
    else:
        annual_growth = 0.0

    return {
        'daily_change_gb': avg_daily_change_bytes / (1024**3),
        'daily_change_percent': avg_daily_change_pct,
        'annual_growth_percent': annual_growth
    }


# =============================================================================
# Entra ID Collectors
# =============================================================================

def collect_entra_users(graph_client: GraphServiceClient, tenant_id: str) -> List[CloudResource]:
    """Collect Entra ID (Azure AD) users."""
    resources = []

    try:
        logger.info("Collecting Entra ID users...")
        users_response = graph_client.users.get()

        # Collect all users across all pages
        all_users = collect_all_pages_sync(users_response)

        if all_users:
            for user in all_users:
                try:
                    resource = CloudResource(
                        provider="entraid",
                        subscription_id=tenant_id,
                        region="global",
                        resource_type="entraid:user",
                        service_family="EntraID",
                        resource_id=user.id,
                        name=user.user_principal_name or user.display_name or "Unknown",
                        tags={},
                        size_gb=0.0,
                        metadata={
                            'user_principal_name': user.user_principal_name,
                            'display_name': user.display_name,
                            'mail': user.mail,
                            'account_enabled': user.account_enabled if hasattr(user, 'account_enabled') else True,
                            'user_type': user.user_type if hasattr(user, 'user_type') else 'Member',
                            'job_title': user.job_title if hasattr(user, 'job_title') else None,
                            'department': user.department if hasattr(user, 'department') else None,
                            'created_datetime': str(user.created_date_time) if hasattr(user, 'created_date_time') and user.created_date_time else None
                        }
                    )
                    resources.append(resource)
                except Exception as e:
                    logger.debug(f"Failed to process user {user.id}: {e}")
                    continue

        logger.info(f"Collected {len(resources)} Entra ID users")

    except Exception as e:
        check_and_raise_auth_error(e, "collect Entra ID users", "m365")
        logger.error(f"Failed to collect Entra ID users: {e}")

    return resources


def collect_entra_groups(graph_client: GraphServiceClient, tenant_id: str) -> List[CloudResource]:
    """Collect Entra ID (Azure AD) groups."""
    resources = []

    try:
        logger.info("Collecting Entra ID groups...")
        groups_response = graph_client.groups.get()

        # Collect all groups across all pages
        all_groups = collect_all_pages_sync(groups_response)

        if all_groups:
            for group in all_groups:
                try:
                    member_count = 0
                    try:
                        members = graph_client.groups.by_group_id(group.id).members.get()
                        member_count = len(members.value) if members and members.value else 0
                    except Exception as e:
                        logger.debug(f"Could not fetch member count for group {group.id}: {e}")
                        pass

                    resource = CloudResource(
                        provider="entraid",
                        subscription_id=tenant_id,
                        region="global",
                        resource_type="entraid:group",
                        service_family="EntraID",
                        resource_id=group.id,
                        name=group.display_name or "Unknown",
                        tags={},
                        size_gb=0.0,
                        metadata={
                            'display_name': group.display_name,
                            'description': group.description,
                            'mail': group.mail,
                            'mail_enabled': group.mail_enabled if hasattr(group, 'mail_enabled') else False,
                            'security_enabled': group.security_enabled if hasattr(group, 'security_enabled') else False,
                            'group_types': list(group.group_types) if hasattr(group, 'group_types') and group.group_types else [],
                            'member_count': member_count,
                            'created_datetime': str(group.created_date_time) if hasattr(group, 'created_date_time') and group.created_date_time else None,
                            'visibility': group.visibility if hasattr(group, 'visibility') else None
                        }
                    )
                    resources.append(resource)
                except Exception as e:
                    logger.debug(f"Failed to process group {group.id}: {e}")
                    continue

        logger.info(f"Collected {len(resources)} Entra ID groups")

    except Exception as e:
        check_and_raise_auth_error(e, "collect Entra ID groups", "m365")
        logger.error(f"Failed to collect Entra ID groups: {e}")

    return resources


# =============================================================================
# Output Utilities (M365-specific helpers)
# =============================================================================

def write_json_file(data: Any, filename: str, output_dir: str) -> str:
    """Write data to JSON file and return filepath.

    This is a thin wrapper around lib/utils.write_json that handles
    filename + output_dir separately for convenience.
    """
    filepath = os.path.join(output_dir, filename)
    _write_json_to_path(data, filepath)
    return filepath


def aggregate_m365_sizing(resources: List[CloudResource]) -> Dict[str, Any]:
    """Aggregate sizing information from resources."""
    summary = {
        'total_resources': len(resources),
        'total_storage_gb': 0.0,
        'by_service': {},
        'by_type': {}
    }

    for r in resources:
        summary['total_storage_gb'] += r.size_gb

        if r.service_family not in summary['by_service']:
            summary['by_service'][r.service_family] = {'count': 0, 'storage_gb': 0.0}
        summary['by_service'][r.service_family]['count'] += 1
        summary['by_service'][r.service_family]['storage_gb'] += r.size_gb

        if r.resource_type not in summary['by_type']:
            summary['by_type'][r.resource_type] = {'count': 0, 'storage_gb': 0.0}
        summary['by_type'][r.resource_type]['count'] += 1
        summary['by_type'][r.resource_type]['storage_gb'] += r.size_gb

    summary['total_storage_gb'] = round(summary['total_storage_gb'], 2)
    for svc in summary['by_service'].values():
        svc['storage_gb'] = round(svc['storage_gb'], 2)
    for typ in summary['by_type'].values():
        typ['storage_gb'] = round(typ['storage_gb'], 2)

    return summary


def print_m365_summary_table(resources: List[CloudResource]):
    """Print M365-specific summary table to console."""
    by_type = {}
    for r in resources:
        if r.resource_type not in by_type:
            by_type[r.resource_type] = {'count': 0, 'size_gb': 0.0}
        by_type[r.resource_type]['count'] += 1
        by_type[r.resource_type]['size_gb'] += r.size_gb

    print("\n" + "="*70)
    print("M365 RESOURCE SUMMARY")
    print("="*70)
    print(f"{'Resource Type':<35} {'Count':>10} {'Size (GB)':>15}")
    print("-"*70)

    total_count = 0
    total_size = 0.0
    for rtype, data in sorted(by_type.items()):
        print(f"{rtype:<35} {data['count']:>10} {data['size_gb']:>15.2f}")
        total_count += data['count']
        total_size += data['size_gb']

    print("-"*70)
    print(f"{'TOTAL':<35} {total_count:>10} {total_size:>15.2f}")
    print("="*70 + "\n")


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='CCA CloudShell - Microsoft 365 Collector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Option 1: Azure CLI / Managed Identity (recommended)
    az login
    python m365_collect.py --use-default-credential

    # Option 2: Environment variables with App Registration
    export MS365_TENANT_ID="your-tenant-id"
    export MS365_CLIENT_ID="your-client-id"
    export MS365_CLIENT_SECRET="your-client-secret"
    python m365_collect.py

    # Include Entra ID users and groups
    python m365_collect.py --include-entra

Authentication:
    DefaultAzureCredential (--use-default-credential) uses the Azure identity
    chain: Managed Identity > Azure CLI > Environment variables. This is the
    recommended approach for Azure Cloud Shell and local development.

Required Azure AD App Permissions (Application type):
    - Sites.Read.All (SharePoint sites)
    - Files.Read.All (OneDrive storage)
    - User.Read.All (Users, OneDrive, Exchange)
    - Mail.Read (Exchange mailbox metadata)
    - Group.Read.All (Groups, Teams)
    - Team.ReadBasic.All (Teams details)
    - Reports.Read.All (Usage reports for change rate and growth metrics)
        """
    )

    parser.add_argument('--tenant-id',
                        default=os.environ.get('MS365_TENANT_ID'),
                        help='Azure AD tenant ID (or set MS365_TENANT_ID env var)')
    parser.add_argument('--client-id',
                        default=os.environ.get('MS365_CLIENT_ID'),
                        help='Azure AD application (client) ID (or set MS365_CLIENT_ID env var)')
    # Client secret is env-var only for security (no CLI arg to avoid shell history exposure)
    parser.add_argument('--use-default-credential', action='store_true',
                        help='Use Azure DefaultAzureCredential (managed identity, Azure CLI, etc.)')
    parser.add_argument('--output', '--output-dir', '-o',
                        dest='output',
                        default='./cca_m365_output',
                        help='Output directory (default: ./cca_m365_output)')
    parser.add_argument('--include-entra', action='store_true',
                        help='Include Entra ID (Azure AD) users and groups')
    parser.add_argument('--skip-sharepoint', action='store_true',
                        help='Skip SharePoint site collection')
    parser.add_argument('--skip-onedrive', action='store_true',
                        help='Skip OneDrive account collection')
    parser.add_argument('--skip-exchange', action='store_true',
                        help='Skip Exchange mailbox collection')
    parser.add_argument('--skip-teams', action='store_true',
                        help='Skip Teams collection')
    parser.add_argument('--log-level', default='INFO',
                        help='Logging level (DEBUG, INFO, WARNING, ERROR)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose logging (same as --log-level DEBUG)')

    args = parser.parse_args()

    # Setup logging - write to file in output directory
    log_level = 'DEBUG' if args.verbose else args.log_level
    setup_logging(log_level, output_dir=args.output)

    # Get client secret from environment only (security: not from CLI args)
    client_secret = os.environ.get('MS365_CLIENT_SECRET')

    # Check for partial environment variable configuration (common mistake)
    ms365_vars = {
        'MS365_TENANT_ID': os.environ.get('MS365_TENANT_ID'),
        'MS365_CLIENT_ID': os.environ.get('MS365_CLIENT_ID'),
        'MS365_CLIENT_SECRET': client_secret
    }
    set_vars = [k for k, v in ms365_vars.items() if v]
    missing_vars = [k for k, v in ms365_vars.items() if not v]

    if set_vars and missing_vars:
        print(f"ERROR: Partial credentials detected. You set: {', '.join(set_vars)}")
        print(f"       But missing: {', '.join(missing_vars)}")
        print("")
        print("Please set ALL three environment variables:")
        print('  export MS365_TENANT_ID="your-tenant-id"')
        print('  export MS365_CLIENT_ID="your-client-id"')
        print('  export MS365_CLIENT_SECRET="your-client-secret"')
        print("")
        print("Or use Azure CLI authentication instead:")
        print("  az login")
        print("  python m365_collect.py --use-default-credential")
        sys.exit(1)

    # Determine credential mode
    use_default_credential = args.use_default_credential

    # Auto-detect: if no explicit credentials provided, try DefaultAzureCredential
    if not use_default_credential and not (args.tenant_id and args.client_id and client_secret):
        # Check if we're in Azure Cloud Shell or have Azure CLI logged in
        logger.info("No explicit credentials provided, attempting DefaultAzureCredential...")
        use_default_credential = True

    # Validate credentials based on mode
    if not use_default_credential:
        if not args.tenant_id or not args.client_id or not client_secret:
            print("ERROR: Missing credentials. Please either:")
            print("")
            print("Option 1: Use Azure CLI / Managed Identity (recommended):")
            print("  az login")
            print("  python m365_collect.py --use-default-credential")
            print("")
            print("Option 2: Use App Registration with client secret:")
            print("  export MS365_TENANT_ID=\"your-tenant-id\"")
            print("  export MS365_CLIENT_ID=\"your-client-id\"")
            print("  export MS365_CLIENT_SECRET=\"your-secret\"")
            print("  python m365_collect.py")
            print("")
            print("Note: In Azure Cloud Shell, --use-default-credential works automatically.")
            sys.exit(1)

    # Create output directory
    os.makedirs(args.output, exist_ok=True)

    # Initialize Graph client
    try:
        if use_default_credential:
            logger.info("Initializing Microsoft Graph client with DefaultAzureCredential...")
            print("Auth: Using DefaultAzureCredential (Azure CLI / Managed Identity)")
            graph_client = get_graph_client_default_credential()
            # For DefaultAzureCredential, we need to discover tenant ID
            tenant_id = args.tenant_id or "default"
        else:
            logger.info("Initializing Microsoft Graph client with client credentials...")
            print(f"Tenant: {args.tenant_id[:8]}...{args.tenant_id[-4:]}")
            graph_client = get_graph_client(
                args.tenant_id,
                args.client_id,
                client_secret
            )
            tenant_id = args.tenant_id
        print(f"Output: {args.output}\n")
    except Exception as e:
        print(f"ERROR: Failed to initialize Graph client: {e}")
        if use_default_credential:
            print("\nTroubleshooting DefaultAzureCredential:")
            print("  1. Install Azure CLI: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli")
            print("  2. Run: az login")
            print("  3. Run: python m365_collect.py --use-default-credential")
            print("")
            print("  Or use App Registration credentials instead:")
            print('    export MS365_TENANT_ID="your-tenant-id"')
            print('    export MS365_CLIENT_ID="your-client-id"')
            print('    export MS365_CLIENT_SECRET="your-secret"')
            print("    python m365_collect.py")
        sys.exit(1)

    # Count total collection tasks (add usage reports collection)
    num_tasks = 1  # Usage reports collection
    if not args.skip_sharepoint:
        num_tasks += 1
    if not args.skip_onedrive:
        num_tasks += 1
    if not args.skip_exchange:
        num_tasks += 1
    if not args.skip_teams:
        num_tasks += 1
    if args.include_entra:
        num_tasks += 2  # users + groups

    # Collect resources with progress tracking
    all_resources: List[CloudResource] = []
    change_rate_data: Dict[str, Any] = {}
    total_user_count: int = 0

    # Pre-fetch usage reports for accurate sizes and change rates
    mailbox_usage: Dict[str, Dict[str, Any]] = {}
    sharepoint_usage: Dict[str, Dict[str, Any]] = {}
    teams_activity: Dict[str, Any] = {}
    exchange_summary: Dict[str, Any] = {}
    sharepoint_summary: Dict[str, Any] = {}

    with ProgressTracker("M365", total_accounts=num_tasks) as tracker:
        # First: Collect usage reports (needed for accurate mailbox sizes)
        tracker.update_task("Collecting usage reports...")
        try:
            # Get total user count for the tenant
            total_user_count = get_total_user_count(graph_client)

            # Collect usage reports for each service
            mailbox_usage = collect_mailbox_usage_report(graph_client)
            sharepoint_usage = collect_sharepoint_usage_report(graph_client) if not args.skip_sharepoint else {}
            collect_onedrive_usage_report(graph_client) if not args.skip_onedrive else {}

            # Collect Teams activity data
            if not args.skip_teams:
                teams_activity = collect_teams_activity_report(graph_client)

            # Generate summaries from usage reports
            if mailbox_usage:
                exchange_summary = generate_exchange_summary(mailbox_usage)
            if sharepoint_usage:
                sharepoint_summary = generate_sharepoint_summary(sharepoint_usage)

            # Collect storage history for change rate calculation
            sharepoint_history = collect_storage_history_report(graph_client, 'sharepoint') if not args.skip_sharepoint else []
            onedrive_history = collect_storage_history_report(graph_client, 'onedrive') if not args.skip_onedrive else []
            mailbox_history = collect_storage_history_report(graph_client, 'mailbox') if not args.skip_exchange else []

            # Calculate change rates
            if sharepoint_history:
                sp_metrics = calculate_change_rate_and_growth(sharepoint_history)
                change_rate_data['SharePoint'] = {
                    'daily_change_gb': sp_metrics['daily_change_gb'],
                    'daily_change_percent': sp_metrics['daily_change_percent'],
                    'annual_growth_percent': sp_metrics['annual_growth_percent'],
                    'sample_period_days': len(sharepoint_history)
                }

            if onedrive_history:
                od_metrics = calculate_change_rate_and_growth(onedrive_history)
                change_rate_data['OneDrive'] = {
                    'daily_change_gb': od_metrics['daily_change_gb'],
                    'daily_change_percent': od_metrics['daily_change_percent'],
                    'annual_growth_percent': od_metrics['annual_growth_percent'],
                    'sample_period_days': len(onedrive_history)
                }

            if mailbox_history:
                ex_metrics = calculate_change_rate_and_growth(mailbox_history)
                change_rate_data['Exchange'] = {
                    'daily_change_gb': ex_metrics['daily_change_gb'],
                    'daily_change_percent': ex_metrics['daily_change_percent'],
                    'annual_growth_percent': ex_metrics['annual_growth_percent'],
                    'sample_period_days': len(mailbox_history)
                }

        except Exception as e:
            logger.warning(f"Failed to collect usage reports (change rate data will be unavailable): {e}")
        tracker.complete_account()

        if not args.skip_sharepoint:
            tracker.update_task("Collecting SharePoint sites...")
            resources = collect_sharepoint_sites(graph_client, tenant_id)
            all_resources.extend(resources)
            tracker.add_resources(len(resources), sum(r.size_gb for r in resources))
            tracker.complete_account()

        if not args.skip_onedrive:
            tracker.update_task("Collecting OneDrive accounts...")
            resources = collect_onedrive_accounts(graph_client, tenant_id)
            all_resources.extend(resources)
            tracker.add_resources(len(resources), sum(r.size_gb for r in resources))
            tracker.complete_account()

        if not args.skip_exchange:
            tracker.update_task("Collecting Exchange mailboxes...")
            resources = collect_exchange_mailboxes(graph_client, tenant_id, mailbox_usage)
            all_resources.extend(resources)
            tracker.add_resources(len(resources), sum(r.size_gb for r in resources))
            tracker.complete_account()

        if not args.skip_teams:
            tracker.update_task("Collecting Teams...")
            resources = collect_teams(graph_client, tenant_id)
            all_resources.extend(resources)
            tracker.add_resources(len(resources), sum(r.size_gb for r in resources))
            tracker.complete_account()

        if args.include_entra:
            tracker.update_task("Collecting Entra ID users...")
            resources = collect_entra_users(graph_client, tenant_id)
            all_resources.extend(resources)
            tracker.add_resources(len(resources), sum(r.size_gb for r in resources))
            tracker.complete_account()

            tracker.update_task("Collecting Entra ID groups...")
            resources = collect_entra_groups(graph_client, tenant_id)
            all_resources.extend(resources)
            tracker.add_resources(len(resources), sum(r.size_gb for r in resources))
            tracker.complete_account()

    # Print basic summary
    print_m365_summary_table(all_resources)

    # Enrich change_rate_data with resource counts and sizes from collected resources
    if change_rate_data:
        service_map = {
            'SharePoint': 'm365:sharepoint:site',
            'OneDrive': 'm365:onedrive:account',
            'Exchange': 'm365:exchange:mailbox'
        }
        for service_name, resource_type in service_map.items():
            if service_name in change_rate_data:
                service_resources = [r for r in all_resources if r.resource_type == resource_type]
                change_rate_data[service_name]['resource_count'] = len(service_resources)
                change_rate_data[service_name]['total_size_gb'] = round(sum(r.size_gb for r in service_resources), 2)

    # Print comprehensive sizing report
    print("\n")
    print("=" * 120)
    print("M365 COMPREHENSIVE SIZING REPORT")
    print("=" * 120)
    print(f"Licensed Users: {total_user_count:,}")
    print("=" * 120)

    # Exchange Online Section
    if exchange_summary:
        print("\nEXCHANGE ONLINE")
        print("-" * 120)
        print(f"{'Type':<40} {'Count':>8} {'Items':>12} {'Size (GiB)':>12} {'Recov Items':>12} {'Recov (GiB)':>12} {'Total (GiB)':>12}")
        print("-" * 120)

        # User Active Mailboxes
        ua = exchange_summary.get('user_active', {})
        print(f"{'User Active Mailboxes':<40} {ua.get('count', 0):>8,} {ua.get('item_count', 0):>12,} {ua.get('item_size_gib', 0):>12.3f} {ua.get('recoverable_item_count', 0):>12,} {ua.get('recoverable_item_size_gib', 0):>12.3f} {ua.get('total_item_size_gib', 0):>12.3f}")

        # User Archive Enabled (note: sizes not available from Graph API)
        archive_count = exchange_summary.get('user_archive_enabled', {}).get('count', 0)
        print(f"{'User Archive Mailboxes (enabled)':<40} {archive_count:>8,} {'N/A':>12} {'N/A':>12} {'N/A':>12} {'N/A':>12} {'N/A':>12}")

        # SoftDeleted
        sd = exchange_summary.get('softdeleted_active', {})
        if sd.get('count', 0) > 0:
            print(f"{'SoftDeleted Active Mailboxes':<40} {sd.get('count', 0):>8,} {sd.get('item_count', 0):>12,} {sd.get('item_size_gib', 0):>12.3f} {sd.get('recoverable_item_count', 0):>12,} {sd.get('recoverable_item_size_gib', 0):>12.3f} {sd.get('total_item_size_gib', 0):>12.3f}")

        sd_arch = exchange_summary.get('softdeleted_archive', {})
        if sd_arch.get('count', 0) > 0:
            print(f"{'SoftDeleted Archive Mailboxes':<40} {sd_arch.get('count', 0):>8,}")

        # Group Mailboxes
        ga = exchange_summary.get('group_active', {})
        if ga.get('count', 0) > 0:
            print(f"{'Group Active Mailboxes':<40} {ga.get('count', 0):>8,} {ga.get('item_count', 0):>12,} {ga.get('item_size_gib', 0):>12.3f} {ga.get('recoverable_item_count', 0):>12,} {ga.get('recoverable_item_size_gib', 0):>12.3f} {ga.get('total_item_size_gib', 0):>12.3f}")

        ga_arch = exchange_summary.get('group_archive', {})
        if ga_arch.get('count', 0) > 0:
            print(f"{'Group Archive Mailboxes':<40} {ga_arch.get('count', 0):>8,}")

        # Public Folder
        pf = exchange_summary.get('publicfolder_active', {})
        if pf.get('count', 0) > 0:
            print(f"{'PublicFolder Active Mailboxes':<40} {pf.get('count', 0):>8,} {pf.get('item_count', 0):>12,} {pf.get('item_size_gib', 0):>12.3f} {pf.get('recoverable_item_count', 0):>12,} {pf.get('recoverable_item_size_gib', 0):>12.3f} {pf.get('total_item_size_gib', 0):>12.3f}")

        # Shared Mailboxes
        sh = exchange_summary.get('shared_active', {})
        if sh.get('count', 0) > 0:
            print(f"{'Shared Mailboxes':<40} {sh.get('count', 0):>8,} {sh.get('item_count', 0):>12,} {sh.get('item_size_gib', 0):>12.3f} {sh.get('recoverable_item_count', 0):>12,} {sh.get('recoverable_item_size_gib', 0):>12.3f} {sh.get('total_item_size_gib', 0):>12.3f}")

        # Room/Equipment
        re = exchange_summary.get('room_equipment_active', {})
        if re.get('count', 0) > 0:
            print(f"{'Room/Equipment Mailboxes':<40} {re.get('count', 0):>8,} {re.get('item_count', 0):>12,} {re.get('item_size_gib', 0):>12.3f} {re.get('recoverable_item_count', 0):>12,} {re.get('recoverable_item_size_gib', 0):>12.3f} {re.get('total_item_size_gib', 0):>12.3f}")

        print("-" * 120)
        # Totals
        td = exchange_summary.get('totals_default', {})
        print(f"{'Total (Default Options)':<40} {td.get('count', 0):>8,} {td.get('item_count', 0):>12,} {td.get('item_size_gib', 0):>12.3f} {td.get('recoverable_item_count', 0):>12,} {td.get('recoverable_item_size_gib', 0):>12.3f} {td.get('total_item_size_gib', 0):>12.3f}")

        ta = exchange_summary.get('totals_all', {})
        print(f"{'Total (All Options)':<40} {ta.get('count', 0):>8,} {ta.get('item_count', 0):>12,} {ta.get('item_size_gib', 0):>12.3f} {ta.get('recoverable_item_count', 0):>12,} {ta.get('recoverable_item_size_gib', 0):>12.3f} {ta.get('total_item_size_gib', 0):>12.3f}")

        # Add growth data if available
        if 'Exchange' in change_rate_data:
            ex_growth = change_rate_data['Exchange']
            growth_180d = ex_growth['daily_change_gb'] * 180
            growth_pct = ex_growth['annual_growth_percent'] / 2  # 180 days is roughly half a year
            print(f"{'Data Growth (180 days)':<40} {growth_180d:>8.2f} GiB")
            print(f"{'Growth Rate (180 days)':<40} {growth_pct:>8.2f}%")

    # SharePoint Online Section
    if sharepoint_summary:
        print("\nSHAREPOINT ONLINE")
        print("-" * 120)
        print(f"{'Type':<40} {'Count':>12} {'Size (GiB)':>15}")
        print("-" * 120)

        sp = sharepoint_summary.get('sharepoint_sites', {})
        ts = sharepoint_summary.get('team_sites', {})
        total_sp = sharepoint_summary.get('total', {})

        print(f"{'SharePoint Sites':<40} {sp.get('count', 0):>12,} {sp.get('storage_gib', 0):>15.3f}")
        print(f"{'Team Sites':<40} {ts.get('count', 0):>12,} {ts.get('storage_gib', 0):>15.3f}")
        print("-" * 120)
        print(f"{'Total Sites':<40} {total_sp.get('count', 0):>12,} {total_sp.get('storage_gib', 0):>15.3f}")

        # Add growth data if available
        if 'SharePoint' in change_rate_data:
            sp_growth = change_rate_data['SharePoint']
            growth_180d = sp_growth['daily_change_gb'] * 180
            growth_pct = sp_growth['annual_growth_percent'] / 2
            print(f"{'Data Growth (180 days)':<40} {growth_180d:>12.2f} GiB  {growth_pct:>15.2f}%")

    # OneDrive Section
    onedrive_resources = [r for r in all_resources if r.resource_type == 'm365:onedrive:account']
    if onedrive_resources:
        print("\nONEDRIVE FOR BUSINESS")
        print("-" * 120)
        print(f"{'Type':<40} {'Count':>12} {'Size (GiB)':>15}")
        print("-" * 120)

        od_count = len(onedrive_resources)
        od_size = sum(r.size_gb for r in onedrive_resources)
        print(f"{'Personal Sites':<40} {od_count:>12,} {od_size:>15.3f}")

        # Add growth data if available
        if 'OneDrive' in change_rate_data:
            od_growth = change_rate_data['OneDrive']
            growth_180d = od_growth['daily_change_gb'] * 180
            growth_pct = od_growth['annual_growth_percent'] / 2
            print(f"{'Data Growth (180 days)':<40} {growth_180d:>12.2f} GiB  {growth_pct:>15.2f}%")

    # Teams Chat Section
    if teams_activity:
        print("\nTEAMS CHAT")
        print("-" * 120)
        print(f"{'Metric':<50} {'Count':>15}")
        print("-" * 120)
        print(f"{'Estimated Metered Units for User Chats':<50} {teams_activity.get('estimated_metered_units_user_chats', 0):>15,}")
        print(f"{'Estimated Metered Units for Teams Channel Conversations':<50} {teams_activity.get('estimated_metered_units_channel_conversations', 0):>15,}")
        print(f"{'Total Estimated Metered Units (Last 180 Days)':<50} {teams_activity.get('total_estimated_metered_units', 0):>15,}")
        print(f"{'Total Estimated Metered Units (Last 180 Days + Next 1 Year)':<50} {teams_activity.get('total_metered_units_with_projection', 0):>15,}")

    # M365 Tenant Totals
    print("\n" + "=" * 120)
    print("M365 TENANT TOTALS")
    print("=" * 120)
    print(f"{'Licensed Users':<50} {total_user_count:>15,}")

    # Calculate total size
    total_size_gib = sum(r.size_gb for r in all_resources)
    print(f"{'Total Size (GiB)':<50} {total_size_gib:>15.3f}")
    print("=" * 120)

    print("\nNote: Archive mailbox SIZES require Exchange Online PowerShell (Get-MailboxStatistics -Archive).")
    print("      The Graph API only reports whether archive is enabled, not archive storage size.\n")

    if not all_resources:
        print("No resources collected. Check permissions and tenant configuration.")
        return

    # Generate outputs
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # Raw inventory
    inventory = [asdict(r) for r in all_resources]
    # Use HHMMSS format for timestamp in filenames
    file_ts = datetime.now(timezone.utc).strftime('%H%M%S')
    inventory_file = write_json_file(inventory, f'cca_m365_inv_{file_ts}.json', args.output)
    print(f"Inventory saved: {inventory_file}")

    # Sizing summary with change rate data
    sizing = aggregate_m365_sizing(all_resources)
    sizing['tenant_id'] = tenant_id
    sizing['collection_timestamp'] = timestamp
    sizing['total_user_count'] = total_user_count

    # Add change rate data to sizing summary
    if change_rate_data:
        sizing['change_rates'] = change_rate_data

    # Add comprehensive Exchange summary
    if exchange_summary:
        sizing['exchange_detailed'] = exchange_summary

    # Add SharePoint summary
    if sharepoint_summary:
        sizing['sharepoint_detailed'] = sharepoint_summary

    # Add Teams activity data
    if teams_activity:
        sizing['teams_activity'] = teams_activity

    sizing_file = write_json_file(sizing, f'cca_m365_sum_{file_ts}.json', args.output)
    print(f"Sizing summary saved: {sizing_file}")

    # Executive summary
    exec_summary = {
        'collection_timestamp': timestamp,
        'tenant_id': tenant_id,
        'total_user_count': total_user_count,
        'total_resources': len(all_resources),
        'total_storage_gb': sizing['total_storage_gb'],
        'resource_breakdown': {
            'sharepoint_sites': len([r for r in all_resources if r.resource_type == 'm365:sharepoint:site']),
            'onedrive_accounts': len([r for r in all_resources if r.resource_type == 'm365:onedrive:account']),
            'exchange_mailboxes': len([r for r in all_resources if r.resource_type == 'm365:exchange:mailbox']),
            'teams': len([r for r in all_resources if r.resource_type == 'm365:teams:team']),
            'entra_users': len([r for r in all_resources if r.resource_type == 'entraid:user']),
            'entra_groups': len([r for r in all_resources if r.resource_type == 'entraid:group'])
        }
    }

    # Add change rate data to executive summary
    if change_rate_data:
        exec_summary['change_rates'] = change_rate_data

    exec_file = write_json_file(exec_summary, f'executive_summary_{timestamp}.json', args.output)
    print(f"Executive summary saved: {exec_file}")

    print(f"\nOutput files in: {args.output}")


if __name__ == '__main__':
    main()
