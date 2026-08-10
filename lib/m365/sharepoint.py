"""
M365 Collection Module - SharePoint

SharePoint site collection and usage reporting.
"""

import logging
from typing import Any, Dict, List, Optional

from msgraph.graph_service_client import GraphServiceClient

from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error

from .helpers import (
    collect_all_pages_sync,
    get_csv_field,
    get_usage_report,
    parse_usage_report_csv,
    run_sync,
    safe_int,
)

logger = logging.getLogger(__name__)


def collect_sharepoint_sites(
    graph_client: GraphServiceClient,
    tenant_id: str,
    sharepoint_usage: Optional[Dict[str, Dict[str, Any]]] = None,
    credential: Optional[Any] = None,
) -> List[CloudResource]:
    """Collect SharePoint sites.

    Args:
        graph_client: Microsoft Graph client
        tenant_id: Azure AD tenant ID
        sharepoint_usage: Dict from collect_sharepoint_usage_report() - if provided, creates
                          resources from usage report (recommended for complete data)
        credential: The Graph credential from get_graph_client(), needed only
            for the Graph API fallback path (pagination beyond page 1)

    Returns:
        List of CloudResource objects, one per SharePoint site
        (sizing_relevant=True)

    Example:
        graph_client, credential = get_graph_client(tenant_id, client_id, secret)
        sharepoint_usage = collect_sharepoint_usage_report(graph_client, credential)
        sites = collect_sharepoint_sites(graph_client, tenant_id, sharepoint_usage, credential)
    """
    resources = []

    try:
        # If usage report provided, use it (much more complete than API)
        if sharepoint_usage:
            logger.info("Creating SharePoint resources from usage report...")
            for site_url, site_data in sharepoint_usage.items():
                # Skip deleted sites and OneDrive personal sites
                if site_data.get('is_deleted'):
                    continue
                if 'personal' in site_data.get('site_type', '').lower():
                    continue  # OneDrive sites, handled separately

                storage_gb = site_data.get('storage_gb', 0.0)
                site_id = site_data.get('site_id', site_url)

                # Determine resource type based on site type
                is_team_site = site_data.get('is_team_site', False)
                resource_type = "m365:sharepoint:teamsite" if is_team_site else "m365:sharepoint:site"

                resource = CloudResource(
                    provider="microsoft365",
                    subscription_id=tenant_id,
                    region="global",
                    resource_type=resource_type,
                    service_family="SharePoint",
                    resource_id=site_id,
                    name=site_data.get('owner_display_name') or site_url.split('/')[-1] or "SharePoint Site",
                    tags={},
                    size_gb=storage_gb,
                    sizing_relevant=True,
                    metadata={
                        'web_url': site_url,
                        'site_type': site_data.get('site_type', ''),
                        'root_web_template': site_data.get('root_web_template', ''),
                        'is_team_site': is_team_site,
                        'storage_used_gb': round(storage_gb, 2),
                        'file_count': site_data.get('file_count', 0),
                        'active_file_count': site_data.get('active_file_count', 0),
                        'page_view_count': site_data.get('page_view_count', 0),
                        'last_activity_date': site_data.get('last_activity_date', ''),
                        'owner_display_name': site_data.get('owner_display_name', ''),

                        # storage_gb comes from getSharePointSiteUsageDetail's "Storage
                        # Used (Byte)" column - real measured usage, distinct from that
                        # report's separate "Storage Allocated (Byte)" quota column.
                        'size_source': 'usage',
                    }
                )
                resources.append(resource)

            logger.info(f"Collected {len(resources)} SharePoint sites from usage report")
            return resources

        # Fallback: Use Graph API (may be incomplete)
        logger.warning(
            "SharePoint usage report not available - falling back to Graph API. "
            "This may miss some sites. To fix: Add 'Reports.Read.All' permission to your app registration."
        )
        logger.info("Collecting SharePoint sites via Graph API...")
        sites_response = run_sync(graph_client.sites.get())

        # Collect all sites across all pages
        all_sites = collect_all_pages_sync(sites_response, credential)

        failed_count = 0
        if all_sites:
            for site in all_sites:
                try:
                    storage_used = 0.0
                    storage_quota = 0.0
                    has_quota = False

                    if hasattr(site, 'quota') and site.quota:
                        # quota.used is the drive's real measured usage in bytes
                        # (Microsoft Graph `quota` resource type), not an allocation.
                        storage_used = float(site.quota.used or 0) / (1024**3)
                        storage_quota = float(site.quota.total or 0) / (1024**3)
                        has_quota = True

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
                        sizing_relevant=True,
                        metadata={
                            'web_url': site.web_url,
                            'created_datetime': str(site.created_date_time) if hasattr(site, 'created_date_time') and site.created_date_time else None,
                            'last_modified': str(site.last_modified_date_time) if hasattr(site, 'last_modified_date_time') and site.last_modified_date_time else None,
                            'storage_quota_gb': round(storage_quota, 2),
                            'storage_used_gb': round(storage_used, 2),
                            'storage_used_percentage': round((storage_used / storage_quota * 100) if storage_quota > 0 else 0, 2),
                            'size_source': 'usage' if has_quota else 'unavailable',
                        }
                    )
                    resources.append(resource)
                except Exception as e:
                    failed_count += 1
                    check_and_raise_auth_error(e, "process SharePoint site", "m365")
                    logger.warning(f"Failed to process SharePoint site: {e}")
                    continue

        if failed_count > 0:
            logger.warning(f"Failed to process {failed_count} SharePoint sites")
        logger.info(f"Collected {len(resources)} SharePoint sites via API")

    except Exception as e:
        check_and_raise_auth_error(e, "collect SharePoint sites", "m365")
        logger.error(f"Failed to collect SharePoint sites: {e}")

    return resources


def collect_sharepoint_usage_report(
    graph_client: GraphServiceClient,
    credential: Optional[Any] = None,
) -> Dict[str, Dict[str, Any]]:
    """Collect SharePoint site usage report with historical storage data.

    Returns dict keyed by site URL with storage and site type.

    Args:
        graph_client: Microsoft Graph client (kept for API symmetry - the
            report is fetched by credential-authenticated raw HTTP)
        credential: The Graph credential from get_graph_client()

    Returns:
        Dict keyed by site URL, each value holding storage_bytes,
        storage_gb, site_type, is_team_site, is_deleted, and activity
        details as described above. Empty dict if the report is unavailable.
    """
    logger.info("Collecting SharePoint usage report...")

    csv_content = get_usage_report('getSharePointSiteUsageDetail', credential)
    if not csv_content:
        return {}

    rows = parse_usage_report_csv(csv_content)

    # Debug: log column names from first row to diagnose parsing issues
    if rows:
        logger.debug(f"SharePoint usage report columns: {list(rows[0].keys())}")
    else:
        logger.debug("SharePoint usage report returned no rows")

    # Build lookup by site URL
    # Report includes: Site URL, Site Type, Root Web Template, Storage Used (Byte), etc.
    # Note: Microsoft may use different column names or concealed data
    sites = {}
    skipped_no_url = 0
    for row in rows:
        site_url = get_csv_field(row, 'Site URL', 'Site Url', 'siteUrl', 'Site Id', 'siteId')
        if not site_url:
            skipped_no_url += 1
            continue

        # Get storage
        storage_bytes = safe_int(get_csv_field(
            row, 'Storage Used (Byte)', 'Storage Used (Bytes)', 'storageUsedInBytes'
        ))

        # 'Site Type' is not actually a column getSharePointSiteUsageDetail returns
        # (confirmed against the documented v1.0 schema - only 'Root Web Template' is
        # present), so this lookup always misses and site_type is always ''. Kept as a
        # no-op fallback in case Microsoft adds the column later; detection today relies
        # entirely on root_web_template below.
        site_type = get_csv_field(row, 'Site Type', 'siteType') or ''
        root_web_template = get_csv_field(row, 'Root Web Template', 'rootWebTemplate') or ''

        # Determine if it's a Team Site (Teams-connected) or SharePoint Site
        is_team_site = (
            'group' in site_type.lower() or
            'team' in site_type.lower() or
            root_web_template in ('GROUP', 'Group#0', 'TEAMCHANNEL')
        )

        # Is deleted
        is_deleted_raw = get_csv_field(row, 'Is Deleted', 'isDeleted')
        is_deleted = str(is_deleted_raw).lower() in ('yes', 'true', '1') if is_deleted_raw else False

        sites[site_url] = {
            'storage_bytes': storage_bytes,
            'storage_gb': storage_bytes / (1024**3),
            'last_activity_date': get_csv_field(row, 'Last Activity Date', 'lastActivityDate') or '',
            'file_count': safe_int(get_csv_field(row, 'File Count', 'fileCount')),
            'active_file_count': safe_int(get_csv_field(row, 'Active File Count', 'activeFileCount')),
            'page_view_count': safe_int(get_csv_field(row, 'Page View Count', 'pageViewCount')),
            'site_id': get_csv_field(row, 'Site Id', 'siteId') or '',
            'site_type': site_type,
            'root_web_template': root_web_template,
            'is_team_site': is_team_site,
            'is_deleted': is_deleted,
            'owner_display_name': get_csv_field(row, 'Owner Display Name', 'ownerDisplayName') or '',
        }

    # Log summary with diagnostic info
    if skipped_no_url > 0 and len(sites) == 0:
        logger.warning(
            f"SharePoint usage report had {len(rows)} rows but {skipped_no_url} were skipped "
            f"(no Site URL found). This may indicate concealed report data - check tenant "
            "settings for 'Conceal user, group, and site names in all reports'."
        )
    elif skipped_no_url > 0:
        logger.debug(f"Skipped {skipped_no_url} rows without Site URL")

    team_sites = sum(1 for s in sites.values() if s['is_team_site'])
    sp_sites = len(sites) - team_sites
    logger.info(f"Collected usage data for {len(sites)} SharePoint sites ({team_sites} Team Sites, {sp_sites} SharePoint Sites)")
    return sites


def generate_sharepoint_summary(site_usage: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Generate SharePoint Online summary with site type breakdown.

    Categories:
    - SharePoint Sites (Communication sites, Publishing sites)
    - Team Sites (Teams-connected sites)

    Args:
        site_usage: Dict from collect_sharepoint_usage_report(), keyed by
            site URL

    Returns:
        Dict with per-category stats (count, storage_gib) for
        sharepoint_sites, team_sites, deleted_sites, and a 'total' summing
        sharepoint_sites and team_sites (excluding deleted).
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
