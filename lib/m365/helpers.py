"""
M365 Collection Module - Helpers

Common utilities for Microsoft Graph API operations.
"""

import asyncio
import inspect
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Module-level credential storage (set by auth.py, used for pagination)
_graph_credential = None


def set_graph_credential(credential) -> None:
    """Store the Graph credential for use in pagination helpers."""
    global _graph_credential
    _graph_credential = credential


def get_graph_credential():
    """Get the stored Graph credential."""
    return _graph_credential


def run_sync(coro_or_result):
    """Run an async coroutine synchronously if needed.

    msgraph-sdk 1.55+ returns coroutines from .get() methods.
    This helper ensures compatibility with both sync and async responses.

    Handles event loop state issues that can occur after httpx usage
    or multiple asyncio.run() calls by proactively checking loop state
    and creating fresh event loops as needed.
    """
    if not inspect.iscoroutine(coro_or_result):
        return coro_or_result

    # Check if there's an existing event loop and its state
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        # No event loop exists, create one
        loop = None

    if loop is None or loop.is_closed():
        # Event loop is closed or doesn't exist, create a fresh one
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro_or_result)
        finally:
            loop.close()
    elif loop.is_running():
        # Loop is already running (e.g., in Jupyter) - this is rare
        # Fall back to asyncio.run() which creates its own loop
        return asyncio.run(coro_or_result)
    else:
        # Normal case - use asyncio.run()
        return asyncio.run(coro_or_result)


class AttrDict:
    """Wrapper for dicts that allows attribute-style access (e.g., obj.key instead of obj['key']).

    This allows raw JSON responses from Graph API pagination to be accessed
    the same way as msgraph-sdk objects.
    """
    def __init__(self, data: dict):
        self._data = data or {}

    def __getattr__(self, name):
        # Convert camelCase to snake_case for common Graph API fields
        snake_name = ''.join(['_' + c.lower() if c.isupper() else c for c in name]).lstrip('_')
        camel_name = name

        # Try both snake_case (Python style) and camelCase (API style)
        if snake_name in self._data:
            val = self._data[snake_name]
        elif camel_name in self._data:
            val = self._data[camel_name]
        # Also try the original name as-is for exact match
        elif name in self._data:
            val = self._data[name]
        # Check for common Graph API field name mappings
        else:
            # Map Python-style names to Graph API JSON names
            mappings = {
                'id': 'id',
                'display_name': 'displayName',
                'user_principal_name': 'userPrincipalName',
                'mail': 'mail',
                'created_date_time': 'createdDateTime',
                'account_enabled': 'accountEnabled',
                'visibility': 'visibility',
                'resource_provisioning_options': 'resourceProvisioningOptions',
                'group_types': 'groupTypes',
                'description': 'description',
                'web_url': 'webUrl',
                'root': 'root',
                'drive_type': 'driveType',
                'quota': 'quota',
                'owner': 'owner',
                'site_collection': 'siteCollection',
            }
            json_name = mappings.get(name, name)
            val = self._data.get(json_name)

        # Recursively wrap dicts
        if isinstance(val, dict):
            return AttrDict(val)
        return val

    def get(self, key, default=None):
        return self._data.get(key, default)

    def __repr__(self):
        return f"AttrDict({self._data})"


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


def collect_all_pages_sync(initial_response, max_pages: int = 1000) -> List[Any]:
    """Synchronous helper to collect all items from paginated Graph API response.

    Microsoft Graph API returns max 100 items per page. This follows odata_next_link
    to collect ALL items across all pages using raw HTTP requests.

    Args:
        initial_response: Response from a Graph API call
        max_pages: Maximum pages to fetch (safety limit, default 1000 = 100,000 items)

    Returns:
        List of all items from all pages
    """
    import httpx

    items = []
    page_count = 0

    # Get items from first page
    if initial_response and hasattr(initial_response, 'value') and initial_response.value:
        items.extend(initial_response.value)
        page_count = 1

    # Check if there are more pages
    next_link = getattr(initial_response, 'odata_next_link', None) if initial_response else None

    if next_link:
        logger.debug("Response has more pages, fetching all...")

        # Get token for subsequent requests
        credential = get_graph_credential()
        if credential is None:
            logger.warning("Graph credential not initialized - cannot fetch additional pages")
            return items

        try:
            token = credential.get_token("https://graph.microsoft.com/.default")
            headers = {
                'Authorization': f'Bearer {token.token}',
                'Accept': 'application/json'
            }

            with httpx.Client(timeout=60.0) as client:
                while next_link and page_count < max_pages:
                    try:
                        response = client.get(next_link, headers=headers)
                        response.raise_for_status()
                        data = response.json()

                        # Extract items from this page (wrap in AttrDict for attribute access)
                        page_items = data.get('value', [])
                        if page_items:
                            items.extend(AttrDict(item) for item in page_items)
                        page_count += 1

                        # Log progress for large collections
                        if page_count % 100 == 0:
                            logger.info(f"Pagination progress: {len(items):,} items from {page_count} pages...")

                        # Get next link
                        next_link = data.get('@odata.nextLink')

                    except Exception as e:
                        logger.warning(f"Failed to fetch page {page_count + 1}: {e}. "
                                     f"Returning partial results ({len(items):,} items from {page_count} pages).")
                        break

            if page_count >= max_pages:
                logger.warning(f"Hit max page limit ({max_pages:,} pages = {max_pages * 100:,} items). "
                             f"Data may be incomplete for very large tenants.")

        except Exception as e:
            logger.warning(f"Failed to get token for pagination: {e}")

    if page_count > 1:
        logger.info(f"Collected {len(items):,} items from {page_count} pages")
    return items


# =============================================================================
# Report Helper Functions
# =============================================================================

# Constants for usage report collection
USAGE_REPORT_PERIOD = 'D180'  # 180 days of historical data
USAGE_REPORT_PERIOD_DAYS = 180


def safe_int(value: Any, default: int = 0) -> int:
    """Safely convert value to int."""
    if value is None or value == '':
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert value to float."""
    if value is None or value == '':
        return default
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def get_csv_field(row: Dict[str, Any], *keys: str) -> Any:
    """Get field value trying multiple possible key names."""
    for key in keys:
        if key in row and row[key] is not None and row[key] != '':
            return row[key]
    return None


def parse_usage_report_csv(csv_content: str) -> List[Dict[str, Any]]:
    """Parse CSV content from Microsoft Graph usage reports.

    Microsoft Graph reports API returns CSV with a BOM marker and
    the first line contains report metadata that we skip.
    """
    import csv
    import io

    # Remove BOM if present
    if csv_content.startswith('\ufeff'):
        csv_content = csv_content[1:]

    # Parse CSV
    reader = csv.DictReader(io.StringIO(csv_content))
    return list(reader)


def get_usage_report(report_name: str) -> Optional[str]:
    """Fetch a usage report from Microsoft Graph.

    Args:
        report_name: Report name like 'getSharePointSiteUsageDetail'

    Returns:
        CSV content as string, or None on failure
    """
    try:
        import httpx

        credential = get_graph_credential()
        if credential is None:
            raise RuntimeError("Graph credential not initialized. Call get_graph_client first.")
        token = credential.get_token("https://graph.microsoft.com/.default")

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
        error_msg = str(e)
        if '403' in error_msg or 'Forbidden' in error_msg or 'Authorization' in error_msg:
            logger.warning(
                f"Failed to fetch usage report {report_name}: Permission denied. "
                "Ensure 'Reports.Read.All' (Application) permission is granted and admin consent provided."
            )
        else:
            logger.warning(f"Failed to fetch usage report {report_name}: {e}")
        return None
