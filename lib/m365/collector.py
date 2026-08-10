"""M365 collection orchestration.

Orchestrates Microsoft 365 resource collection via the Graph API.
Called by collect.py after argument parsing.

Usage:
    from lib.m365.collector import run_collection
    run_collection(args)
"""
import argparse
import logging
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from lib.__version__ import __version__
from lib.data_quality import compute_data_quality_summary, format_data_quality_report
from lib.m365 import (
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
    get_graph_client,
    get_usage_report,
    parse_usage_report_csv,
    run_sync,
)
from lib.m365.permissions import format_permission_report, verify_m365_permissions
from lib.models import CloudResource
from lib.utils import (
    ProgressTracker,
    get_collector_metadata,
    log_arguments,
    setup_logging,
)
from lib.utils import (
    write_json as _write_json,
)

logger = logging.getLogger(__name__)


# =============================================================================
# M365-specific Data Models
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
        return {
            'service_family': self.service_family,
            'resource_count': self.resource_count,
            'total_size_gb': round(self.total_size_gb, 2),
            'daily_change_gb': round(self.daily_change_gb, 2),
            'daily_change_percent': round(self.daily_change_percent, 2),
            'annual_growth_rate_percent': round(self.annual_growth_rate_percent, 2),
            'sample_period_days': self.sample_period_days,
            'data_points_collected': self.data_points_collected,
        }


# =============================================================================
# Tenant / Licensing Helpers
# =============================================================================

def get_total_user_count(graph_client, credential: Optional[Any] = None) -> Dict[str, Any]:
    """Get total user count in the tenant.

    Uses Graph's `$count` endpoint (GET /users/$count with
    ConsistencyLevel: eventual), which returns an exact tenant-wide count in
    a single request and has no page-based ceiling. Falls back to paginating
    /users and counting the results if the count endpoint is unavailable
    (e.g. missing ConsistencyLevel support in a sovereign cloud) or fails.

    Args:
        graph_client: Microsoft Graph client
        credential: The Graph credential from get_graph_client(), used for
            the $count request and, in the fallback path, for pagination
            beyond page 1

    Returns:
        Dict with 'count' (total users, 0 on total failure), 'source'
        ('count_endpoint' or 'paginated'), and 'truncated' (True only in
        the paginated fallback if collect_all_pages_sync hit its safety cap)
    """
    import httpx

    logger.info("Getting total user count...")

    if credential is not None:
        try:
            token = credential.get_token("https://graph.microsoft.com/.default")
            headers = {
                'Authorization': f'Bearer {token.token}',
                'ConsistencyLevel': 'eventual',
            }
            with httpx.Client(timeout=60.0) as client:
                response = client.get("https://graph.microsoft.com/v1.0/users/$count", headers=headers)
                response.raise_for_status()
                count = int(response.text)
            logger.info(f"Total users in tenant: {count} (via $count endpoint)")
            return {'count': count, 'source': 'count_endpoint', 'truncated': False}
        except Exception as e:
            logger.warning(f"Failed to get user count via $count endpoint, falling back to pagination: {e}")

    try:
        users_response = run_sync(graph_client.users.get())
        all_users = collect_all_pages_sync(users_response, credential)
        count = len(all_users) if all_users else 0
        truncated = getattr(all_users, 'truncated', False)
        logger.info(f"Total users in tenant: {count} (via pagination{', truncated' if truncated else ''})")
        return {'count': count, 'source': 'paginated', 'truncated': truncated}
    except Exception as e:
        logger.warning(f"Failed to get user count: {e}")
        return {'count': 0, 'source': 'paginated', 'truncated': False}


def get_tenant_licensing(graph_client, credential: Any) -> Dict[str, Any]:
    """Get tenant licensing information from Microsoft Graph.

    Args:
        graph_client: Microsoft Graph client (unused - licensing is fetched by
            credential-authenticated raw HTTP, kept for call-site symmetry)
        credential: The Graph credential from get_graph_client(), used to
            fetch the subscribedSkus endpoint

    Returns:
        Dict with 'skus' (list of per-SKU purchase/consumption details),
        'total_licenses', 'total_consumed', and 'services' (sorted list of
        enabled service plan names). Empty defaults on failure.
    """
    import httpx

    licensing: Dict[str, Any] = {
        'skus': [],
        'total_licenses': 0,
        'total_consumed': 0,
        'services': set(),
    }

    try:
        logger.info("Getting tenant licensing information...")
        if credential is None:
            logger.warning("No credential provided - cannot fetch licensing")
            return licensing

        token = credential.get_token("https://graph.microsoft.com/.default")
        headers = {'Authorization': f'Bearer {token.token}', 'Accept': 'application/json'}

        with httpx.Client(timeout=60.0) as client:
            response = client.get("https://graph.microsoft.com/v1.0/subscribedSkus", headers=headers)
            response.raise_for_status()
            data = response.json()

            for sku in data.get('value', []):
                sku_name = sku.get('skuPartNumber', 'Unknown')
                prepaid = sku.get('prepaidUnits', {})
                enabled = prepaid.get('enabled', 0)
                consumed = sku.get('consumedUnits', 0)
                service_plans = []
                for plan in sku.get('servicePlans', []):
                    plan_name = plan.get('servicePlanName', '')
                    if plan_name:
                        service_plans.append(plan_name)
                        licensing['services'].add(plan_name)
                licensing['skus'].append({
                    'sku_id': sku.get('skuId'),
                    'sku_name': sku_name,
                    'licenses_purchased': enabled,
                    'licenses_consumed': consumed,
                    'licenses_available': enabled - consumed,
                    'applies_to': sku.get('appliesTo', 'User'),
                    'capability_status': sku.get('capabilityStatus', 'Unknown'),
                    'service_plans': service_plans,
                })
                licensing['total_licenses'] += enabled
                licensing['total_consumed'] += consumed

        licensing['services'] = sorted(licensing['services'])
        logger.info(f"Found {len(licensing['skus'])} subscribed SKUs")

    except Exception as e:
        logger.warning(f"Failed to get licensing info: {e}")

    return licensing


def get_user_license_assignments(graph_client, sku_mapping: Dict[str, str], credential: Any) -> List[Dict[str, Any]]:
    """Get license assignments for all users in the tenant.

    Args:
        graph_client: Microsoft Graph client (unused - assignments are fetched
            by credential-authenticated raw HTTP, kept for call-site symmetry)
        sku_mapping: Dict mapping SKU ID to friendly SKU name, used to resolve
            each user's assigned license IDs to readable names
        credential: The Graph credential from get_graph_client(), used to
            fetch and paginate the users endpoint

    Returns:
        List of per-user dicts (user_principal_name, display_name, user_id,
        account_enabled, licenses, license_count), sorted by license_count
        descending then user_principal_name. Empty list on failure.
    """
    import httpx

    license_assignments: List[Dict[str, Any]] = []

    try:
        logger.info("Collecting user license assignments...")
        if credential is None:
            logger.warning("No credential provided - cannot fetch license assignments")
            return license_assignments

        token = credential.get_token("https://graph.microsoft.com/.default")
        headers = {'Authorization': f'Bearer {token.token}', 'Accept': 'application/json'}
        next_url: Optional[str] = (
            "https://graph.microsoft.com/v1.0/users"
            "?$select=id,userPrincipalName,displayName,accountEnabled,assignedLicenses"
            "&$top=999"
        )
        page_count = 0

        with httpx.Client(timeout=60.0) as client:
            while next_url and page_count < 1000:
                response = client.get(next_url, headers=headers)
                response.raise_for_status()
                try:
                    data = response.json()
                except Exception as e:
                    logger.warning(f"Invalid JSON on page {page_count + 1}, stopping pagination: {e}")
                    break
                for user in data.get('value', []):
                    upn = user.get('userPrincipalName', '')
                    if not upn:
                        continue
                    assigned = user.get('assignedLicenses', [])
                    license_names = [
                        sku_mapping.get(lic.get('skuId', ''), lic.get('skuId', ''))
                        for lic in assigned
                        if lic.get('skuId')
                    ]
                    license_assignments.append({
                        'user_principal_name': upn,
                        'display_name': user.get('displayName', ''),
                        'user_id': user.get('id', ''),
                        'account_enabled': user.get('accountEnabled', False),
                        'licenses': sorted(license_names),
                        'license_count': len(license_names),
                    })
                raw_next = data.get('@odata.nextLink')
                if raw_next:
                    from urllib.parse import urlparse
                    if urlparse(raw_next).netloc != 'graph.microsoft.com':
                        logger.warning(f"Unexpected nextLink domain, stopping pagination: {raw_next}")
                        raw_next = None
                next_url = raw_next
                page_count += 1

        license_assignments.sort(key=lambda x: (-x['license_count'], x['user_principal_name']))
        licensed_count = sum(1 for u in license_assignments if u['license_count'] > 0)
        logger.info(f"Collected license assignments for {len(license_assignments)} users ({licensed_count} with licenses)")

    except Exception as e:
        logger.warning(f"Failed to get user license assignments: {e}")

    return license_assignments


def get_tenant_info(graph_client, credential: Any) -> Dict[str, Any]:
    """Get tenant organization information from Microsoft Graph.

    Args:
        graph_client: Microsoft Graph client (unused - tenant info is fetched
            by credential-authenticated raw HTTP, kept for call-site symmetry)
        credential: The Graph credential from get_graph_client(), used to
            fetch the organization endpoint

    Returns:
        Dict with tenant_name, display_name, verified_domains, primary_domain,
        tenant_type, country, state, city. Fields stay None/empty on failure.
    """
    import httpx

    tenant_info: Dict[str, Any] = {
        'tenant_name': None, 'display_name': None, 'verified_domains': [],
        'primary_domain': None, 'tenant_type': None,
        'country': None, 'state': None, 'city': None,
    }

    try:
        logger.info("Getting tenant organization information...")
        if credential is None:
            logger.warning("No credential provided - cannot fetch tenant info")
            return tenant_info

        token = credential.get_token("https://graph.microsoft.com/.default")
        headers = {'Authorization': f'Bearer {token.token}', 'Accept': 'application/json'}

        with httpx.Client(timeout=60.0) as client:
            response = client.get("https://graph.microsoft.com/v1.0/organization", headers=headers)
            response.raise_for_status()
            data = response.json()
            orgs = data.get('value', [])
            if orgs:
                org = orgs[0]
                tenant_info['display_name'] = org.get('displayName')
                tenant_info['tenant_name'] = org.get('displayName')
                tenant_info['tenant_type'] = org.get('tenantType')
                tenant_info['country'] = org.get('countryLetterCode')
                tenant_info['state'] = org.get('state')
                tenant_info['city'] = org.get('city')
                for domain in org.get('verifiedDomains', []):
                    name = domain.get('name')
                    if name:
                        tenant_info['verified_domains'].append(name)
                        if domain.get('isDefault'):
                            tenant_info['primary_domain'] = name

        if tenant_info['display_name']:
            logger.info(f"Tenant: {tenant_info['display_name']} ({tenant_info['primary_domain']})")

    except Exception as e:
        logger.warning(f"Failed to get tenant info: {e}")

    return tenant_info


# =============================================================================
# Change Rate Helpers
# =============================================================================

def collect_storage_history_report(graph_client, service: str, credential: Optional[Any] = None) -> List[Dict[str, Any]]:
    """Collect storage history to calculate change rate and growth.

    Args:
        graph_client: Microsoft Graph client (unused - the report is fetched
            by credential-authenticated raw HTTP, kept for call-site symmetry)
        service: Which storage history report to collect - one of
            'sharepoint', 'onedrive', 'mailbox'
        credential: The Graph credential from get_graph_client()

    Returns:
        List of {'date': 'YYYY-MM-DD', 'storage_bytes': int} dicts sorted
        ascending by date. Empty list for an unknown service or on failure.
    """
    report_map = {
        'sharepoint': 'getSharePointSiteUsageStorage',
        'onedrive': 'getOneDriveUsageStorage',
        'mailbox': 'getMailboxUsageStorage',
    }
    report_name = report_map.get(service)
    if not report_name:
        return []

    logger.info(f"Collecting {service} storage history...")
    csv_content = get_usage_report(report_name, credential)
    if not csv_content:
        return []

    rows = parse_usage_report_csv(csv_content)
    history = []
    for row in rows:
        date_str = row.get('Report Date', '')
        if not date_str:
            continue
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
            history.append({'date': date_str, 'storage_bytes': storage_bytes})
        except ValueError:
            continue

    history.sort(key=lambda x: x['date'])
    logger.info(f"Collected {len(history)} days of {service} storage history")
    return history


def calculate_change_rate_and_growth(history: List[Dict[str, Any]]) -> Dict[str, float]:
    """Calculate daily change rate and annual growth from storage history.

    Args:
        history: List of {'date': str, 'storage_bytes': int} dicts sorted
            ascending by date, as returned by collect_storage_history_report()

    Returns:
        Dict with 'daily_change_gb' (average absolute daily change),
        'daily_change_percent', and 'annual_growth_percent' (extrapolated
        from the sampled period). All zero when history has fewer than 7
        days or contains no usable deltas.
    """
    if len(history) < 7:
        return {'daily_change_gb': 0.0, 'daily_change_percent': 0.0, 'annual_growth_percent': 0.0}

    daily_deltas = []
    for i in range(1, len(history)):
        prev = history[i - 1]['storage_bytes']
        curr = history[i]['storage_bytes']
        if prev > 0:
            delta_bytes = curr - prev
            daily_deltas.append({
                'delta_bytes': delta_bytes,
                'delta_percent': (delta_bytes / prev) * 100,
            })

    if not daily_deltas:
        return {'daily_change_gb': 0.0, 'daily_change_percent': 0.0, 'annual_growth_percent': 0.0}

    avg_daily_change_bytes = sum(abs(d['delta_bytes']) for d in daily_deltas) / len(daily_deltas)
    current_storage = history[-1]['storage_bytes']
    avg_daily_change_pct = (avg_daily_change_bytes / current_storage * 100) if current_storage > 0 else 0

    first_storage = history[0]['storage_bytes']
    last_storage = history[-1]['storage_bytes']
    period_days = len(history)
    if first_storage > 0 and period_days > 0:
        period_growth = (last_storage - first_storage) / first_storage
        annual_growth = period_growth * (365 / period_days) * 100
    else:
        annual_growth = 0.0

    return {
        'daily_change_gb': avg_daily_change_bytes / (1024 ** 3),
        'daily_change_percent': avg_daily_change_pct,
        'annual_growth_percent': annual_growth,
    }


# =============================================================================
# Output Helpers
# =============================================================================

def _write_json_file(data: Any, filename: str, output_dir: str) -> str:
    """Write data to JSON file and return filepath."""
    filepath = os.path.join(output_dir, filename)
    _write_json(data, filepath)
    return filepath


def aggregate_m365_sizing(resources: List[CloudResource]) -> Dict[str, Any]:
    """Aggregate sizing information from M365 resources.

    Args:
        resources: List of collected CloudResource objects across all M365
            services

    Returns:
        Dict with 'total_resources', 'total_storage_gb', and per-service
        ('by_service') and per-resource-type ('by_type') breakdowns of
        count and storage_gb, each rounded to 2 decimal places.
    """
    summary: Dict[str, Any] = {
        'total_resources': len(resources),
        'total_storage_gb': 0.0,
        'by_service': {},
        'by_type': {},
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


def print_m365_summary_table(resources: List[CloudResource]) -> None:
    """Print M365-specific summary table to console.

    Args:
        resources: List of collected CloudResource objects across all M365
            services

    Returns:
        None. Writes a formatted per-resource-type summary table to stdout.
    """
    by_type: Dict[str, Dict] = {}
    for r in resources:
        if r.resource_type not in by_type:
            by_type[r.resource_type] = {'count': 0, 'sizing_count': 0, 'size_gb': 0.0}
        by_type[r.resource_type]['count'] += 1
        if r.sizing_relevant:
            by_type[r.resource_type]['sizing_count'] += 1
        by_type[r.resource_type]['size_gb'] += r.size_gb

    print("\n" + "=" * 90)
    print("M365 RESOURCE SUMMARY")
    print("=" * 90)
    print(f"{'Resource Type':<35} {'Total':>10} {'For Sizing':>15} {'Size (GB)':>15}")
    print("-" * 90)
    total_count = 0
    total_sizing_count = 0
    total_size = 0.0
    for rtype, data in sorted(by_type.items()):
        print(f"{rtype:<35} {data['count']:>10} {data['sizing_count']:>15} {data['size_gb']:>15.2f}")
        total_count += data['count']
        total_sizing_count += data['sizing_count']
        total_size += data['size_gb']
    print("-" * 90)
    print(f"{'TOTAL':<35} {total_count:>10} {total_sizing_count:>15} {total_size:>15.2f}")
    print("=" * 90 + "\n")


# =============================================================================
# Argument Parser (for collect.py)
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    """Return the argparse parser for the M365 collector."""
    parser = argparse.ArgumentParser(description='CCA CloudShell - Microsoft 365 Collector')
    parser.add_argument('--tenant-id', default=os.environ.get('MS365_TENANT_ID'),
                        help='Azure AD tenant ID (or set MS365_TENANT_ID env var)')
    parser.add_argument('--client-id', default=os.environ.get('MS365_CLIENT_ID'),
                        help='Azure AD application (client) ID (or set MS365_CLIENT_ID env var)')
    parser.add_argument('--output', '--output-dir', '-o', dest='output',
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
    return parser


# =============================================================================
# Run Collection (called by collect.py)
# =============================================================================

def run_collection(args) -> None:
    """Run full M365 collection based on parsed CLI args.

    Args:
        args: argparse.Namespace with all M365 collection options.
    """
    log_level = 'DEBUG' if getattr(args, 'verbose', False) else args.log_level
    setup_logging(log_level, output_dir=args.output)
    log_arguments(args, "M365 collector")

    client_secret = os.environ.get('MS365_CLIENT_SECRET')

    # Require all three credentials
    if not (args.tenant_id and args.client_id and client_secret):
        missing = []
        if not args.tenant_id:
            missing.append("MS365_TENANT_ID")
        if not args.client_id:
            missing.append("MS365_CLIENT_ID")
        if not client_secret:
            missing.append("MS365_CLIENT_SECRET")
        print("ERROR: Missing required credentials:")
        for var in missing:
            print(f"  - {var}")
        print("\nSet environment variables:")
        print("  export MS365_TENANT_ID='your-tenant-id'")
        print("  export MS365_CLIENT_ID='your-client-id'")
        print("  export MS365_CLIENT_SECRET='your-client-secret'")
        sys.exit(1)

    os.makedirs(args.output, exist_ok=True)

    try:
        logger.info("Initializing Graph client with client credentials...")
        print(f"Tenant: {args.tenant_id[:8]}...{args.tenant_id[-4:]}")
        graph_client, credential = get_graph_client(args.tenant_id, args.client_id, client_secret)
        tenant_id = args.tenant_id
        print(f"Output: {args.output}\n")
    except Exception as e:
        print(f"ERROR: Failed to initialize Graph client: {e}")
        sys.exit(1)

    # Mandatory preflight: verify every Graph permission this run's flags
    # require before collecting anything. A gap found midway through
    # collection today just leaves that section's data missing or (for the
    # usage-report paths) silently empty, with no clear signal anything was
    # wrong. There is no flag to skip this - if the collection needs a
    # permission, it must be verified up front, once, rather than discovered
    # partway through (or after) a run.
    logger.info("Verifying M365 Graph permissions for this run's configuration...")
    print("Verifying M365 permissions before starting collection...")
    permission_result = verify_m365_permissions(graph_client, tenant_id, args, credential)
    if permission_result.missing:
        report = format_permission_report(permission_result)
        logger.error(
            f"Permission check failed for tenant {tenant_id}. Collection was not started.\n{report}"
        )
        print(
            f"\n✗ Permission check failed for tenant {tenant_id} - collection was not started.\n{report}\n\n"
            "Grant the missing Graph permission(s) above (with admin consent), or narrow this run "
            "with --skip-sharepoint/--skip-onedrive/--skip-exchange/--skip-teams as appropriate, "
            "then re-run."
        )
        sys.exit(1)

    if permission_result.warnings:
        logger.warning(format_permission_report(permission_result))
    logger.info("Permission check passed for this tenant")

    num_tasks = (
        1  # usage reports
        + (0 if args.skip_sharepoint else 1)
        + (0 if args.skip_onedrive else 1)
        + (0 if args.skip_exchange else 1)
        + (0 if args.skip_teams else 1)
        + (2 if args.include_entra else 0)
    )

    all_resources: List[CloudResource] = []
    change_rate_data: Dict[str, Any] = {}
    user_count_info: Dict[str, Any] = {'count': 0, 'source': 'paginated', 'truncated': False}
    mailbox_usage: Dict = {}
    sharepoint_usage: Dict = {}
    onedrive_usage: Dict = {}
    teams_activity: Dict = {}
    exchange_summary: Dict = {}
    sharepoint_summary: Dict = {}
    licensing_info: Dict = {}
    tenant_info: Dict = {}
    user_license_assignments: List = []
    sharepoint_history: List = []
    onedrive_history: List = []
    mailbox_history: List = []

    with ProgressTracker("M365", total_accounts=num_tasks) as tracker:
        tracker.update_task("Collecting usage reports...")
        try:
            user_count_info = get_total_user_count(graph_client, credential)
            tenant_info = get_tenant_info(graph_client, credential)
            licensing_info = get_tenant_licensing(graph_client, credential)

            sku_mapping: Dict[str, str] = {}
            if licensing_info.get('skus'):
                for sku in licensing_info['skus']:
                    if sku.get('sku_id') and sku.get('sku_name'):
                        sku_mapping[sku['sku_id']] = sku['sku_name']

            user_license_assignments = get_user_license_assignments(graph_client, sku_mapping, credential)
            mailbox_usage = collect_mailbox_usage_report(graph_client, credential)
            if not args.skip_sharepoint:
                sharepoint_usage = collect_sharepoint_usage_report(graph_client, credential)
            if not args.skip_onedrive:
                onedrive_usage = collect_onedrive_usage_report(graph_client, credential)
            if not args.skip_teams:
                teams_activity = collect_teams_activity_report(graph_client, credential)

            if mailbox_usage:
                exchange_summary = generate_exchange_summary(mailbox_usage)
            if sharepoint_usage:
                sharepoint_summary = generate_sharepoint_summary(sharepoint_usage)

            if not args.skip_sharepoint:
                sharepoint_history = collect_storage_history_report(graph_client, 'sharepoint', credential)
            if not args.skip_onedrive:
                onedrive_history = collect_storage_history_report(graph_client, 'onedrive', credential)
            if not args.skip_exchange:
                mailbox_history = collect_storage_history_report(graph_client, 'mailbox', credential)

            for service_key, history in [
                ('SharePoint', sharepoint_history),
                ('OneDrive', onedrive_history),
                ('Exchange', mailbox_history),
            ]:
                if history:
                    metrics = calculate_change_rate_and_growth(history)
                    change_rate_data[service_key] = {
                        'daily_change_gb': metrics['daily_change_gb'],
                        'daily_change_percent': metrics['daily_change_percent'],
                        'annual_growth_percent': metrics['annual_growth_percent'],
                        'sample_period_days': len(history),
                    }

        except Exception as e:
            logger.warning(f"Failed to collect usage reports: {e}")
        tracker.complete_account()

        if not args.skip_sharepoint:
            tracker.update_task("Collecting SharePoint sites...")
            resources = collect_sharepoint_sites(graph_client, tenant_id, sharepoint_usage, credential)
            all_resources.extend(resources)
            tracker.add_resources(len(resources), sum(r.size_gb for r in resources))
            tracker.complete_account()

        if not args.skip_onedrive:
            tracker.update_task("Collecting OneDrive accounts...")
            resources = collect_onedrive_accounts(graph_client, tenant_id, onedrive_usage, credential)
            all_resources.extend(resources)
            tracker.add_resources(len(resources), sum(r.size_gb for r in resources))
            tracker.complete_account()

        if not args.skip_exchange:
            tracker.update_task("Collecting Exchange mailboxes...")
            resources = collect_exchange_mailboxes(graph_client, tenant_id, mailbox_usage, credential)
            all_resources.extend(resources)
            tracker.add_resources(len(resources), sum(r.size_gb for r in resources))
            tracker.complete_account()

        if not args.skip_teams:
            tracker.update_task("Collecting Teams...")
            teams_usage = collect_teams_usage_report(graph_client, credential)
            resources = collect_teams(graph_client, tenant_id, teams_usage, credential)
            all_resources.extend(resources)
            tracker.add_resources(len(resources), sum(r.size_gb for r in resources))
            tracker.complete_account()

        if args.include_entra:
            tracker.update_task("Collecting Entra ID users...")
            resources = collect_entra_users(graph_client, tenant_id, credential)
            all_resources.extend(resources)
            tracker.add_resources(len(resources), sum(r.size_gb for r in resources))
            tracker.complete_account()

            tracker.update_task("Collecting Entra ID groups...")
            resources = collect_entra_groups(graph_client, tenant_id, credential)
            all_resources.extend(resources)
            tracker.add_resources(len(resources), sum(r.size_gb for r in resources))
            tracker.complete_account()

    print_m365_summary_table(all_resources)

    # Data quality: how many resources have no measured actual usage (reported
    # as 0.0, never a quota/allocated estimate) vs. how many were confirmed.
    # Computed over the final resource list, same shape as Azure/AWS/GCP.
    data_quality = compute_data_quality_summary(all_resources)
    if data_quality and data_quality['resource_types_with_gaps']:
        report = format_data_quality_report(data_quality)
        logger.warning(report)
        print(f"\n⚠ {report}\n")

    # Enrich change_rate_data with resource counts
    if change_rate_data:
        service_map = {
            'SharePoint': ['m365:sharepoint:site', 'm365:sharepoint:teamsite'],
            'OneDrive': ['m365:onedrive:account'],
            'Exchange': ['m365:exchange:mailbox'],
        }
        for service_name, resource_types in service_map.items():
            if service_name in change_rate_data:
                service_resources = [r for r in all_resources if r.resource_type in resource_types]
                change_rate_data[service_name]['resource_count'] = len(service_resources)
                change_rate_data[service_name]['total_size_gb'] = round(sum(r.size_gb for r in service_resources), 2)

        if 'SharePoint' in change_rate_data and change_rate_data['SharePoint'].get('resource_count', 0) == 0:
            if sharepoint_history:
                latest_storage_bytes = sharepoint_history[-1].get('storage_bytes', 0)
                estimated_size_gb = round(latest_storage_bytes / (1024 ** 3), 2)
                if estimated_size_gb > 0:
                    change_rate_data['SharePoint']['total_size_gb'] = estimated_size_gb
                    change_rate_data['SharePoint']['size_estimated'] = True
                    logger.info(f"SharePoint total size estimated from storage history: {estimated_size_gb:.2f} GB")

    if not all_resources:
        print("No resources collected. Check permissions and tenant configuration.")
        return

    file_ts = datetime.now(timezone.utc).strftime('%H%M%S')
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    inventory = [asdict(r) for r in all_resources]
    inventory_file = _write_json_file(inventory, f'cca_m365_inv_{file_ts}.json', args.output)
    print(f"Inventory saved: {inventory_file}")

    sizing = aggregate_m365_sizing(all_resources)
    sizing['collector_metadata'] = get_collector_metadata(args, 'm365', __version__)
    sizing['tenant_id'] = tenant_id
    sizing['tenant_name'] = tenant_info.get('tenant_name')
    sizing['primary_domain'] = tenant_info.get('primary_domain')
    sizing['collection_timestamp'] = timestamp
    sizing['total_user_count'] = user_count_info['count']
    sizing['total_user_count_source'] = user_count_info['source']
    if user_count_info['truncated']:
        sizing['total_user_count_truncated'] = True
    if tenant_info:
        sizing['tenant_info'] = tenant_info
    if licensing_info and licensing_info.get('skus'):
        sizing['licensing'] = {
            'total_licenses_purchased': licensing_info.get('total_licenses', 0),
            'total_licenses_consumed': licensing_info.get('total_consumed', 0),
            'skus': [
                {'name': s['sku_name'], 'purchased': s['licenses_purchased'], 'consumed': s['licenses_consumed']}
                for s in licensing_info['skus']
            ],
        }
    if user_license_assignments:
        sizing['user_license_assignments'] = user_license_assignments
    if change_rate_data:
        sizing['change_rates'] = change_rate_data
    if exchange_summary:
        sizing['exchange_detailed'] = exchange_summary
    if sharepoint_summary:
        sizing['sharepoint_detailed'] = sharepoint_summary
    if teams_activity:
        sizing['teams_activity'] = teams_activity
    if data_quality:
        sizing['data_quality'] = data_quality

    sizing_file = _write_json_file(sizing, f'cca_m365_sum_{file_ts}.json', args.output)
    print(f"Sizing summary saved: {sizing_file}")

    exec_summary: Dict[str, Any] = {
        'collection_timestamp': timestamp,
        'tenant_id': tenant_id,
        'tenant_name': tenant_info.get('tenant_name'),
        'primary_domain': tenant_info.get('primary_domain'),
        'total_user_count': user_count_info['count'],
        'total_user_count_source': user_count_info['source'],
        **({'total_user_count_truncated': True} if user_count_info['truncated'] else {}),
        'total_resources': len(all_resources),
        'total_storage_gb': sizing['total_storage_gb'],
        'resource_breakdown': {
            'sharepoint_sites': len([r for r in all_resources if r.resource_type == 'm365:sharepoint:site']),
            'onedrive_accounts': len([r for r in all_resources if r.resource_type == 'm365:onedrive:account']),
            'exchange_mailboxes': len([r for r in all_resources if r.resource_type == 'm365:exchange:mailbox']),
            'teams': len([r for r in all_resources if r.resource_type == 'm365:teams:team']),
            'entra_users': len([r for r in all_resources if r.resource_type == 'entraid:user']),
            'entra_groups': len([r for r in all_resources if r.resource_type == 'entraid:group']),
        },
    }
    if licensing_info and licensing_info.get('skus'):
        exec_summary['licensing'] = {
            'total_licenses_purchased': licensing_info.get('total_licenses', 0),
            'total_licenses_consumed': licensing_info.get('total_consumed', 0),
            'skus': [
                {'name': s['sku_name'], 'purchased': s['licenses_purchased'], 'consumed': s['licenses_consumed']}
                for s in licensing_info['skus']
            ],
            'services_enabled': licensing_info.get('services', []),
        }
    if change_rate_data:
        exec_summary['change_rates'] = change_rate_data

    exec_file = _write_json_file(exec_summary, f'executive_summary_{timestamp}.json', args.output)
    print(f"Executive summary saved: {exec_file}")
    print(f"\nOutput files in: {args.output}")
