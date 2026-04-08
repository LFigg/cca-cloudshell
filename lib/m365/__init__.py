"""
M365 Collection Module

Microsoft 365 data collection via Microsoft Graph API.
Collects inventory from Exchange, SharePoint, OneDrive, Teams, and Entra ID.

Usage:
    from lib.m365 import get_graph_client, get_graph_client_default_credential
    from lib.m365.helpers import run_sync, collect_all_pages_sync

For detailed documentation, see .instructions.md in this directory.
"""

# Authentication
from .auth import (
    get_graph_client,
    get_graph_client_default_credential,
    get_tenant_id_from_client,
)

# Helpers
from .helpers import (
    AttrDict,
    USAGE_REPORT_PERIOD,
    USAGE_REPORT_PERIOD_DAYS,
    collect_all_pages,
    collect_all_pages_sync,
    get_csv_field,
    get_graph_credential,
    get_usage_report,
    parse_usage_report_csv,
    run_sync,
    safe_float,
    safe_int,
    set_graph_credential,
)

# SharePoint Collector
from .sharepoint import (
    collect_sharepoint_sites,
    collect_sharepoint_usage_report,
    generate_sharepoint_summary,
)

# OneDrive Collector
from .onedrive import (
    collect_onedrive_accounts,
    collect_onedrive_usage_report,
)

# Exchange Collector
from .exchange import (
    collect_exchange_mailboxes,
    collect_mailbox_usage_report,
    generate_exchange_summary,
)

# Teams Collector
from .teams import (
    collect_teams,
    collect_teams_activity_report,
    collect_teams_usage_report,
)

# Entra ID Collector
from .entra import (
    collect_entra_groups,
    collect_entra_users,
)

__all__ = [
    # Auth
    'get_graph_client',
    'get_graph_client_default_credential',
    'get_tenant_id_from_client',
    # Helpers
    'run_sync',
    'collect_all_pages',
    'collect_all_pages_sync',
    'AttrDict',
    'get_graph_credential',
    'set_graph_credential',
    'USAGE_REPORT_PERIOD',
    'USAGE_REPORT_PERIOD_DAYS',
    'safe_int',
    'safe_float',
    'get_csv_field',
    'parse_usage_report_csv',
    'get_usage_report',
    # SharePoint
    'collect_sharepoint_sites',
    'collect_sharepoint_usage_report',
    'generate_sharepoint_summary',
    # OneDrive
    'collect_onedrive_accounts',
    'collect_onedrive_usage_report',
    # Exchange
    'collect_exchange_mailboxes',
    'collect_mailbox_usage_report',
    'generate_exchange_summary',
    # Teams
    'collect_teams',
    'collect_teams_activity_report',
    'collect_teams_usage_report',
    # Entra ID
    'collect_entra_users',
    'collect_entra_groups',
]
