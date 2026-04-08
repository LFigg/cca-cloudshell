#!/usr/bin/env python3
"""
CCA CloudShell - Microsoft 365 Collector
Standalone collector for M365 resources using Microsoft Graph API.

Authentication Options:
1. App Registration with client secret (RECOMMENDED for full functionality)
   - Create App Registration in Entra ID with Application permissions
   - Set MS365_TENANT_ID, MS365_CLIENT_ID, MS365_CLIENT_SECRET env vars
   - Required for usage reports API (Reports.Read.All) which enables:
     * Bulk mailbox data collection (all mailbox types, storage, quotas)
     * SharePoint/OneDrive usage reports with accurate storage metrics
     * Teams activity and storage reports
     * Change rate and growth metrics

2. DefaultAzureCredential (limited - for quick testing only)
   - Uses Azure CLI, Managed Identity, etc. with Delegated permissions
   - Falls back to slower user-by-user iteration (no usage reports)
   - Only collects user mailboxes, not shared/room/group mailboxes
   - No storage metrics for SharePoint/Teams without Reports.Read.All

Required Azure AD App Permissions (Application type):
  - Sites.Read.All (SharePoint)
  - Files.Read.All (OneDrive storage)
  - User.Read.All (Users, OneDrive, Exchange)
  - Mail.Read (Exchange mailbox metadata)
  - Group.Read.All (Groups, Teams)
  - Team.ReadBasic.All (Teams details)
  - Reports.Read.All (Usage reports - CRITICAL for complete data collection)
  - Organization.Read.All (Tenant licensing info)
  - Directory.Read.All (Optional - for --include-entra)

Usage:
    # Option 1: App Registration (RECOMMENDED)
    export MS365_TENANT_ID="your-tenant-id"
    export MS365_CLIENT_ID="your-client-id"
    export MS365_CLIENT_SECRET="your-client-secret"
    python m365_collect.py

    # Option 2: Azure CLI (limited functionality)
    az login
    python m365_collect.py --use-default-credential

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

# Check for required packages
try:
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

# Add lib to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import from modularized lib.m365
from lib.m365 import (
    AttrDict,
    USAGE_REPORT_PERIOD,
    USAGE_REPORT_PERIOD_DAYS,
    collect_all_pages_sync,
    collect_entra_groups,
    collect_entra_users,
    collect_exchange_mailboxes,
    collect_mailbox_usage_report,
    collect_onedrive_accounts,
    collect_onedrive_usage_report,
    collect_sharepoint_sites,
    collect_sharepoint_usage_report,
    collect_teams,
    collect_teams_activity_report,
    collect_teams_usage_report,
    generate_exchange_summary,
    generate_sharepoint_summary,
    get_csv_field,
    get_graph_client,
    get_graph_client_default_credential,
    get_graph_credential,
    get_usage_report,
    parse_usage_report_csv,
    run_sync,
    safe_float,
    safe_int,
)

logger = logging.getLogger(__name__)

# Internal library imports
from lib.__version__ import __version__
from lib.models import CloudResource
from lib.utils import (
    ProgressTracker,
    check_and_raise_auth_error,
    get_collector_metadata,
    log_arguments,
    setup_logging,
    write_json as _write_json_to_path,
)


# =============================================================================
# Data Models
# =============================================================================


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


def get_total_user_count(graph_client: GraphServiceClient) -> int:
    """Get total user count in the tenant.

    Returns count of all users (including disabled accounts).
    """
    try:
        logger.info("Getting total user count...")
        users_response = run_sync(graph_client.users.get())
        all_users = collect_all_pages_sync(users_response)
        count = len(all_users) if all_users else 0
        logger.info(f"Total users in tenant: {count}")
        return count
    except Exception as e:
        logger.warning(f"Failed to get user count: {e}")
        return 0


def get_tenant_licensing(graph_client: GraphServiceClient) -> Dict[str, Any]:
    """Get tenant licensing information from Microsoft Graph.

    Returns subscribed SKUs (licenses) with counts for:
    - Total licenses purchased (prepaidUnits.enabled)
    - Licenses consumed (consumedUnits)
    - Service plans included in each SKU

    Requires: Organization.Read.All or Directory.Read.All permission
    """
    import httpx

    licensing = {
        'skus': [],
        'total_licenses': 0,
        'total_consumed': 0,
        'services': set(),
    }

    try:
        logger.info("Getting tenant licensing information...")

        credential = get_graph_credential()
        if credential is None:
            logger.warning("Graph credential not initialized - cannot fetch licensing")
            return licensing

        token = credential.get_token("https://graph.microsoft.com/.default")
        headers = {
            'Authorization': f'Bearer {token.token}',
            'Accept': 'application/json'
        }

        with httpx.Client(timeout=60.0) as client:
            # Get subscribed SKUs (purchased licenses)
            response = client.get(
                "https://graph.microsoft.com/v1.0/subscribedSkus",
                headers=headers
            )
            response.raise_for_status()
            data = response.json()

            for sku in data.get('value', []):
                sku_name = sku.get('skuPartNumber', 'Unknown')
                prepaid = sku.get('prepaidUnits', {})
                enabled = prepaid.get('enabled', 0)
                consumed = sku.get('consumedUnits', 0)

                # Extract service plan names
                service_plans = []
                for plan in sku.get('servicePlans', []):
                    plan_name = plan.get('servicePlanName', '')
                    if plan_name:
                        service_plans.append(plan_name)
                        licensing['services'].add(plan_name)

                sku_info = {
                    'sku_id': sku.get('skuId'),
                    'sku_name': sku_name,
                    'licenses_purchased': enabled,
                    'licenses_consumed': consumed,
                    'licenses_available': enabled - consumed,
                    'applies_to': sku.get('appliesTo', 'User'),
                    'capability_status': sku.get('capabilityStatus', 'Unknown'),
                    'service_plans': service_plans,
                }
                licensing['skus'].append(sku_info)
                licensing['total_licenses'] += enabled
                licensing['total_consumed'] += consumed

            # Convert services set to sorted list
            licensing['services'] = sorted(licensing['services'])

        logger.info(f"Found {len(licensing['skus'])} subscribed SKUs, "
                   f"{licensing['total_licenses']:,} total licenses, "
                   f"{licensing['total_consumed']:,} consumed")

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 403:
            logger.warning("Insufficient permissions to read licensing info. "
                         "Requires Organization.Read.All or Directory.Read.All")
        else:
            logger.warning(f"Failed to get licensing info: {e}")
    except Exception as e:
        logger.warning(f"Failed to get licensing info: {e}")

    return licensing


def get_user_license_assignments(
    graph_client: GraphServiceClient,
    sku_mapping: Dict[str, str]
) -> List[Dict[str, Any]]:
    """Get license assignments for all users in the tenant.

    Args:
        graph_client: Microsoft Graph client
        sku_mapping: Dict mapping SKU IDs to friendly SKU names

    Returns:
        List of dicts with user info and assigned license names.
        Each dict contains:
        - user_principal_name: User's UPN (email)
        - display_name: User's display name
        - user_id: User's object ID
        - account_enabled: Whether account is active
        - licenses: List of assigned license names (e.g., ['ENTERPRISEPACK', 'POWER_BI_PRO'])
        - license_count: Number of licenses assigned
    """
    import httpx

    license_assignments = []

    try:
        logger.info("Collecting user license assignments...")

        credential = get_graph_credential()
        if credential is None:
            logger.warning("Graph credential not initialized - cannot fetch license assignments")
            return license_assignments

        token = credential.get_token("https://graph.microsoft.com/.default")
        headers = {
            'Authorization': f'Bearer {token.token}',
            'Accept': 'application/json'
        }

        # Query users with assignedLicenses - paginate through all results
        next_url: Optional[str] = (
            "https://graph.microsoft.com/v1.0/users"
            "?$select=id,userPrincipalName,displayName,accountEnabled,assignedLicenses"
            "&$top=999"
        )
        page_count = 0
        max_pages = 1000  # Safety limit

        with httpx.Client(timeout=60.0) as client:
            while next_url and page_count < max_pages:
                response = client.get(next_url, headers=headers)
                response.raise_for_status()
                data = response.json()

                for user in data.get('value', []):
                    upn = user.get('userPrincipalName', '')
                    if not upn:
                        continue

                    assigned = user.get('assignedLicenses', [])
                    license_names = []

                    for lic in assigned:
                        sku_id = lic.get('skuId', '')
                        # Map SKU ID to friendly name, fallback to SKU ID itself
                        sku_name = sku_mapping.get(sku_id, sku_id)
                        if sku_name:
                            license_names.append(sku_name)

                    license_assignments.append({
                        'user_principal_name': upn,
                        'display_name': user.get('displayName', ''),
                        'user_id': user.get('id', ''),
                        'account_enabled': user.get('accountEnabled', False),
                        'licenses': sorted(license_names),
                        'license_count': len(license_names),
                    })

                # Get next page URL
                next_url = data.get('@odata.nextLink')
                page_count += 1

        # Sort by license count (descending), then by UPN
        license_assignments.sort(key=lambda x: (-x['license_count'], x['user_principal_name']))

        licensed_count = sum(1 for u in license_assignments if u['license_count'] > 0)
        logger.info(f"Collected license assignments for {len(license_assignments)} users "
                   f"({licensed_count} with licenses)")

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 403:
            logger.warning("Insufficient permissions to read user license assignments. "
                         "Requires User.Read.All permission")
        else:
            logger.warning(f"Failed to get user license assignments: {e}")
    except Exception as e:
        logger.warning(f"Failed to get user license assignments: {e}")

    return license_assignments


def get_tenant_info(graph_client: GraphServiceClient) -> Dict[str, Any]:
    """Get tenant organization information from Microsoft Graph.

    Returns tenant details including:
    - Display name (organization name)
    - Verified domains
    - Technical contact info
    - Tenant type

    Requires: Organization.Read.All or Directory.Read.All permission
    """
    import httpx

    tenant_info = {
        'tenant_name': None,
        'display_name': None,
        'verified_domains': [],
        'primary_domain': None,
        'tenant_type': None,
        'country': None,
        'state': None,
        'city': None,
    }

    try:
        logger.info("Getting tenant organization information...")

        credential = get_graph_credential()
        if credential is None:
            logger.warning("Graph credential not initialized - cannot fetch tenant info")
            return tenant_info

        token = credential.get_token("https://graph.microsoft.com/.default")
        headers = {
            'Authorization': f'Bearer {token.token}',
            'Accept': 'application/json'
        }

        with httpx.Client(timeout=60.0) as client:
            # Get organization info
            response = client.get(
                "https://graph.microsoft.com/v1.0/organization",
                headers=headers
            )
            response.raise_for_status()
            data = response.json()

            orgs = data.get('value', [])
            if orgs:
                org = orgs[0]  # Usually only one organization
                tenant_info['display_name'] = org.get('displayName')
                tenant_info['tenant_name'] = org.get('displayName')  # Alias for convenience
                tenant_info['tenant_type'] = org.get('tenantType')
                tenant_info['country'] = org.get('countryLetterCode')
                tenant_info['state'] = org.get('state')
                tenant_info['city'] = org.get('city')

                # Get verified domains
                domains = org.get('verifiedDomains', [])
                for domain in domains:
                    domain_name = domain.get('name')
                    if domain_name:
                        tenant_info['verified_domains'].append(domain_name)
                        if domain.get('isDefault'):
                            tenant_info['primary_domain'] = domain_name

        if tenant_info['display_name']:
            logger.info(f"Tenant: {tenant_info['display_name']} ({tenant_info['primary_domain']})")

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 403:
            logger.warning("Insufficient permissions to read organization info. "
                         "Requires Organization.Read.All or Directory.Read.All")
        else:
            logger.warning(f"Failed to get tenant info: {e}")
    except Exception as e:
        logger.warning(f"Failed to get tenant info: {e}")

    return tenant_info


# =============================================================================
# Change Rate & Growth Metrics
# =============================================================================

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

    csv_content = get_usage_report(report_name)
    if not csv_content:
        return []

    rows = parse_usage_report_csv(csv_content)

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
    # Option 1: App Registration (RECOMMENDED for full functionality)
    export MS365_TENANT_ID="your-tenant-id"
    export MS365_CLIENT_ID="your-client-id"
    export MS365_CLIENT_SECRET="your-client-secret"
    python m365_collect.py

    # Option 2: Azure CLI / Managed Identity (limited - no usage reports)
    az login
    python m365_collect.py --use-default-credential

    # Include Entra ID users and groups
    python m365_collect.py --include-entra

Authentication:
    App Registration with Application permissions is RECOMMENDED because
    Reports.Read.All (required for usage reports) only works with Application
    permissions. Without usage reports, collection falls back to slower
    per-user iteration and some data (shared/room mailboxes) is unavailable.

    DefaultAzureCredential (--use-default-credential) uses Delegated permissions
    which cannot access usage reports. Use only for quick testing.

Required Azure AD App Permissions (Application type):
    - Sites.Read.All (SharePoint sites)
    - Files.Read.All (OneDrive storage)
    - User.Read.All (Users, OneDrive, Exchange)
    - Mail.Read (Exchange mailbox metadata)
    - Group.Read.All (Groups, Teams)
    - Team.ReadBasic.All (Teams details)
    - Reports.Read.All (CRITICAL - enables bulk collection via usage reports)
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
                        help='Use Azure DefaultAzureCredential (limited functionality - no usage reports)')
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
    log_arguments(args, "M365 collector")

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
            print("Option 1: Use App Registration with client secret (RECOMMENDED):")
            print("  export MS365_TENANT_ID=\"your-tenant-id\"")
            print("  export MS365_CLIENT_ID=\"your-client-id\"")
            print("  export MS365_CLIENT_SECRET=\"your-secret\"")
            print("  python m365_collect.py")
            print("")
            print("Option 2: Use Azure CLI / Managed Identity (limited functionality):")
            print("  az login")
            print("  python m365_collect.py --use-default-credential")
            print("")
            print("Note: App Registration is required for Reports.Read.All API access")
            print("which enables complete mailbox collection and usage metrics.")
            sys.exit(1)

    # Create output directory
    os.makedirs(args.output, exist_ok=True)

    # Initialize Graph client
    try:
        if use_default_credential:
            logger.info("Initializing Microsoft Graph client with DefaultAzureCredential...")
            print("Auth: Using DefaultAzureCredential (Azure CLI / Managed Identity)")
            print("")
            print("⚠️  WARNING: DefaultAzureCredential uses Delegated permissions which cannot")
            print("   access the Reports.Read.All API. Collection will fall back to slower")
            print("   per-user iteration and some data will be unavailable:")
            print("   - Only user mailboxes collected (not shared/room/group mailboxes)")
            print("   - No storage metrics for Exchange mailboxes")
            print("   - Slower collection (hours for large tenants)")
            print("")
            print("   For complete data collection, use App Registration with Application permissions:")
            print('     export MS365_TENANT_ID="your-tenant-id"')
            print('     export MS365_CLIENT_ID="your-client-id"')
            print('     export MS365_CLIENT_SECRET="your-secret"')
            print("     python m365_collect.py")
            print("")
            graph_client = get_graph_client_default_credential()
            # For DefaultAzureCredential, we need to discover tenant ID
            tenant_id = args.tenant_id or "default"
        else:
            logger.info("Initializing Microsoft Graph client with client credentials...")
            print(f"Tenant: {args.tenant_id[:8]}...{args.tenant_id[-4:]}")
            assert client_secret is not None  # Validated above
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
            print("  For complete data collection, use App Registration instead (RECOMMENDED):")
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
    onedrive_usage: Dict[str, Dict[str, Any]] = {}
    teams_activity: Dict[str, Any] = {}
    exchange_summary: Dict[str, Any] = {}
    sharepoint_summary: Dict[str, Any] = {}
    licensing_info: Dict[str, Any] = {}
    tenant_info: Dict[str, Any] = {}
    user_license_assignments: List[Dict[str, Any]] = []

    # Storage history for change rate fallback
    sharepoint_history: List[Dict[str, Any]] = []
    onedrive_history: List[Dict[str, Any]] = []
    mailbox_history: List[Dict[str, Any]] = []

    with ProgressTracker("M365", total_accounts=num_tasks) as tracker:
        # First: Collect usage reports (needed for accurate mailbox sizes)
        tracker.update_task("Collecting usage reports...")
        try:
            # Get total user count for the tenant
            total_user_count = get_total_user_count(graph_client)

            # Get tenant organization info (name, domains)
            tenant_info = get_tenant_info(graph_client)

            # Get licensing information
            licensing_info = get_tenant_licensing(graph_client)

            # Build SKU ID to name mapping for license assignment lookup
            sku_mapping: Dict[str, str] = {}
            if licensing_info and licensing_info.get('skus'):
                for sku in licensing_info['skus']:
                    if sku.get('sku_id') and sku.get('sku_name'):
                        sku_mapping[sku['sku_id']] = sku['sku_name']

            # Get per-user license assignments
            user_license_assignments = get_user_license_assignments(graph_client, sku_mapping)

            # Collect usage reports for each service
            mailbox_usage = collect_mailbox_usage_report(graph_client)
            sharepoint_usage = collect_sharepoint_usage_report(graph_client) if not args.skip_sharepoint else {}
            onedrive_usage = collect_onedrive_usage_report(graph_client) if not args.skip_onedrive else {}

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
            resources = collect_sharepoint_sites(graph_client, tenant_id, sharepoint_usage)
            all_resources.extend(resources)
            tracker.add_resources(len(resources), sum(r.size_gb for r in resources))
            tracker.complete_account()

        if not args.skip_onedrive:
            tracker.update_task("Collecting OneDrive accounts...")
            resources = collect_onedrive_accounts(graph_client, tenant_id, onedrive_usage)
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
            # Collect Teams usage report first (for storage sizes)
            tracker.update_task("Collecting Teams usage report...")
            teams_usage = collect_teams_usage_report(graph_client)
            
            tracker.update_task("Collecting Teams...")
            resources = collect_teams(graph_client, tenant_id, teams_usage)
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
            'SharePoint': ['m365:sharepoint:site', 'm365:sharepoint:teamsite'],
            'OneDrive': ['m365:onedrive:account'],
            'Exchange': ['m365:exchange:mailbox']
        }
        for service_name, resource_types in service_map.items():
            if service_name in change_rate_data:
                service_resources = [r for r in all_resources if r.resource_type in resource_types]
                change_rate_data[service_name]['resource_count'] = len(service_resources)
                change_rate_data[service_name]['total_size_gb'] = round(sum(r.size_gb for r in service_resources), 2)

        # Fallback: If we have SharePoint storage history but no resources,
        # estimate total size from the most recent storage history data point
        if 'SharePoint' in change_rate_data and change_rate_data['SharePoint'].get('resource_count', 0) == 0:
            if sharepoint_history:
                # Use the most recent storage value from history
                latest_storage_bytes = sharepoint_history[-1].get('storage_bytes', 0)
                estimated_size_gb = round(latest_storage_bytes / (1024**3), 2)
                if estimated_size_gb > 0:
                    change_rate_data['SharePoint']['total_size_gb'] = estimated_size_gb
                    change_rate_data['SharePoint']['size_estimated'] = True
                    logger.info(f"SharePoint total size estimated from storage history: {estimated_size_gb:.2f} GB")
                    print(f"  Note: SharePoint size ({estimated_size_gb:.2f} GB) estimated from storage history - "
                          "site-level detail unavailable (check tenant report concealment settings)")

    # Print comprehensive sizing report
    print("\n")
    print("=" * 120)
    print("M365 COMPREHENSIVE SIZING REPORT")
    print("=" * 120)

    # Print tenant info
    if tenant_info.get('tenant_name'):
        print(f"Tenant: {tenant_info['tenant_name']}")
    if tenant_info.get('primary_domain'):
        print(f"Domain: {tenant_info['primary_domain']}")
    print(f"Tenant ID: {tenant_id}")
    print(f"Licensed Users: {total_user_count:,}")

    # Print licensing info if available
    if licensing_info and licensing_info.get('skus'):
        print(f"Total Licenses: {licensing_info.get('total_licenses', 0):,} purchased, {licensing_info.get('total_consumed', 0):,} consumed")
        print("-" * 120)
        print(f"{'SKU Name':<45} {'Purchased':>12} {'Consumed':>12} {'Available':>12}")
        print("-" * 120)
        for sku in sorted(licensing_info['skus'], key=lambda x: x['licenses_purchased'], reverse=True)[:10]:
            print(f"{sku['sku_name']:<45} {sku['licenses_purchased']:>12,} {sku['licenses_consumed']:>12,} {sku['licenses_available']:>12,}")
        if len(licensing_info['skus']) > 10:
            print(f"... and {len(licensing_info['skus']) - 10} more SKUs")
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
    sizing['collector_metadata'] = get_collector_metadata(args, 'm365', __version__)
    sizing['tenant_id'] = tenant_id
    sizing['tenant_name'] = tenant_info.get('tenant_name')
    sizing['primary_domain'] = tenant_info.get('primary_domain')
    sizing['collection_timestamp'] = timestamp
    sizing['total_user_count'] = total_user_count

    # Add tenant info
    if tenant_info:
        sizing['tenant_info'] = tenant_info

    # Add licensing info
    if licensing_info and licensing_info.get('skus'):
        sizing['licensing'] = {
            'total_licenses_purchased': licensing_info.get('total_licenses', 0),
            'total_licenses_consumed': licensing_info.get('total_consumed', 0),
            'skus': [
                {
                    'name': sku['sku_name'],
                    'purchased': sku['licenses_purchased'],
                    'consumed': sku['licenses_consumed'],
                }
                for sku in licensing_info['skus']
            ],
        }

    # Add per-user license assignments
    if user_license_assignments:
        sizing['user_license_assignments'] = user_license_assignments

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
        'tenant_name': tenant_info.get('tenant_name'),
        'primary_domain': tenant_info.get('primary_domain'),
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

    # Add licensing info to executive summary
    if licensing_info and licensing_info.get('skus'):
        exec_summary['licensing'] = {
            'total_licenses_purchased': licensing_info.get('total_licenses', 0),
            'total_licenses_consumed': licensing_info.get('total_consumed', 0),
            'skus': [
                {
                    'name': sku['sku_name'],
                    'purchased': sku['licenses_purchased'],
                    'consumed': sku['licenses_consumed'],
                }
                for sku in licensing_info['skus']
            ],
            'services_enabled': licensing_info.get('services', []),
        }

    # Add change rate data to executive summary
    if change_rate_data:
        exec_summary['change_rates'] = change_rate_data

    exec_file = write_json_file(exec_summary, f'executive_summary_{timestamp}.json', args.output)
    print(f"Executive summary saved: {exec_file}")

    print(f"\nOutput files in: {args.output}")


if __name__ == '__main__':
    main()
