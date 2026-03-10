"""
Tests for Microsoft 365 resource collector using unittest.mock.

Covers:
- SharePoint site collection
- OneDrive account collection
- Exchange mailbox collection
- Microsoft Teams collection
- Entra ID users and groups collection
"""
import os
import sys
from unittest.mock import Mock, patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from m365_collect import (
    calculate_change_rate_and_growth,
    collect_entra_groups,
    collect_entra_users,
    collect_exchange_mailboxes,
    collect_mailbox_usage_report,
    collect_onedrive_accounts,
    collect_sharepoint_sites,
    collect_teams,
    generate_exchange_summary,
    generate_sharepoint_summary,
    get_graph_client,
    get_total_user_count,
    _parse_usage_report_csv,
    _safe_int,
    _safe_float,
    _get_csv_field,
)

# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def tenant_id():
    """Test tenant ID."""
    return "12345678-1234-1234-1234-123456789012"


@pytest.fixture
def mock_graph_client():
    """Create a mock Microsoft Graph client."""
    return Mock()


# =============================================================================
# Helper Functions
# =============================================================================

def create_mock_sharepoint_site(
    site_id: str,
    display_name: str,
    web_url: str = None,
    storage_used: int = 1073741824,  # 1 GB in bytes
    storage_total: int = 27487790694400,  # 25 TB in bytes
):
    """Create a mock SharePoint site object."""
    site = Mock()
    site.id = site_id
    site.display_name = display_name
    site.name = display_name.lower().replace(" ", "-")
    site.web_url = web_url or f"https://contoso.sharepoint.com/sites/{site.name}"
    site.created_date_time = "2024-01-01T00:00:00Z"
    site.last_modified_date_time = "2024-01-15T12:00:00Z"

    site.quota = Mock()
    site.quota.used = storage_used
    site.quota.total = storage_total

    return site


def create_mock_user(
    user_id: str,
    display_name: str,
    user_principal_name: str = None,
    mail: str = None,
    account_enabled: bool = True,
):
    """Create a mock Entra ID user object."""
    user = Mock()
    user.id = user_id
    user.display_name = display_name
    user.user_principal_name = user_principal_name or f"{display_name.lower().replace(' ', '.')}@contoso.com"
    user.mail = mail or user.user_principal_name
    user.account_enabled = account_enabled
    user.created_date_time = "2024-01-01T00:00:00Z"

    return user


def create_mock_drive(
    drive_id: str,
    storage_used: int = 5368709120,  # 5 GB in bytes
    storage_total: int = 1099511627776,  # 1 TB in bytes
    drive_type: str = "business",
):
    """Create a mock OneDrive object."""
    drive = Mock()
    drive.id = drive_id
    drive.drive_type = drive_type
    drive.web_url = f"https://contoso-my.sharepoint.com/personal/{drive_id}"

    drive.quota = Mock()
    drive.quota.used = storage_used
    drive.quota.total = storage_total

    return drive


def create_mock_group(
    group_id: str,
    display_name: str,
    description: str = None,
    visibility: str = "Private",
    is_team: bool = False,
    mail: str = None,
):
    """Create a mock Entra ID group object."""
    group = Mock()
    group.id = group_id
    group.display_name = display_name
    group.description = description
    group.visibility = visibility
    group.mail = mail or f"{display_name.lower().replace(' ', '-')}@contoso.com"
    group.created_date_time = "2024-01-01T00:00:00Z"
    group.group_types = ["Unified"] if is_team else []
    group.resource_provisioning_options = ["Team"] if is_team else []

    return group


def create_mock_team(
    team_id: str,
    display_name: str,
    description: str = None,
    visibility: str = "Private",
    is_archived: bool = False,
):
    """Create a mock Microsoft Team object."""
    team = Mock()
    team.id = team_id
    team.display_name = display_name
    team.description = description
    team.visibility = visibility
    team.is_archived = is_archived
    team.web_url = f"https://teams.microsoft.com/l/team/{team_id}"

    return team


# =============================================================================
# SharePoint Tests
# =============================================================================

class TestSharePointCollection:
    """Tests for SharePoint site collection."""

    def test_collect_sites_basic(self, mock_graph_client, tenant_id):
        """Test collecting SharePoint sites."""
        mock_sites = [
            create_mock_sharepoint_site("site-001", "Marketing Site"),
            create_mock_sharepoint_site("site-002", "Engineering Site"),
        ]

        mock_response = Mock()
        mock_response.value = mock_sites
        mock_graph_client.sites.get.return_value = mock_response

        resources = collect_sharepoint_sites(mock_graph_client, tenant_id)

        assert len(resources) == 2
        assert resources[0].name == "Marketing Site"
        assert resources[1].name == "Engineering Site"

    def test_collect_sites_with_storage(self, mock_graph_client, tenant_id):
        """Test collecting SharePoint sites with storage info."""
        mock_sites = [
            create_mock_sharepoint_site(
                "site-001",
                "Data Site",
                storage_used=10737418240,  # 10 GB
                storage_total=53687091200,  # 50 GB
            ),
        ]

        mock_response = Mock()
        mock_response.value = mock_sites
        mock_graph_client.sites.get.return_value = mock_response

        resources = collect_sharepoint_sites(mock_graph_client, tenant_id)

        assert len(resources) == 1
        assert resources[0].size_gb == pytest.approx(10.0, rel=0.1)
        assert resources[0].metadata['storage_quota_gb'] == pytest.approx(50.0, rel=0.1)

    def test_collect_sites_empty(self, mock_graph_client, tenant_id):
        """Test collecting SharePoint sites when none exist."""
        mock_response = Mock()
        mock_response.value = []
        mock_graph_client.sites.get.return_value = mock_response

        resources = collect_sharepoint_sites(mock_graph_client, tenant_id)

        assert len(resources) == 0

    def test_collect_sites_null_response(self, mock_graph_client, tenant_id):
        """Test collecting SharePoint sites with null response."""
        mock_graph_client.sites.get.return_value = None

        resources = collect_sharepoint_sites(mock_graph_client, tenant_id)

        assert len(resources) == 0

    def test_collect_sites_error_handling(self, mock_graph_client, tenant_id):
        """Test SharePoint collection handles errors gracefully."""
        mock_graph_client.sites.get.side_effect = Exception("API Error")

        resources = collect_sharepoint_sites(mock_graph_client, tenant_id)

        assert len(resources) == 0


# =============================================================================
# OneDrive Tests
# =============================================================================

class TestOneDriveCollection:
    """Tests for OneDrive account collection."""

    def test_collect_onedrive_basic(self, mock_graph_client, tenant_id):
        """Test collecting OneDrive accounts."""
        mock_users = [
            create_mock_user("user-001", "John Doe"),
            create_mock_user("user-002", "Jane Smith"),
        ]

        mock_drives = {
            "user-001": create_mock_drive("drive-001", storage_used=5368709120),
            "user-002": create_mock_drive("drive-002", storage_used=10737418240),
        }

        mock_users_response = Mock()
        mock_users_response.value = mock_users
        mock_graph_client.users.get.return_value = mock_users_response

        def get_drive(user_id):
            mock_obj = Mock()
            mock_obj.drive.get.return_value = mock_drives.get(user_id)
            return mock_obj

        mock_graph_client.users.by_user_id.side_effect = lambda uid: get_drive(uid)

        resources = collect_onedrive_accounts(mock_graph_client, tenant_id)

        assert len(resources) == 2

    def test_collect_onedrive_empty(self, mock_graph_client, tenant_id):
        """Test collecting OneDrive accounts when none exist."""
        mock_users_response = Mock()
        mock_users_response.value = []
        mock_graph_client.users.get.return_value = mock_users_response

        resources = collect_onedrive_accounts(mock_graph_client, tenant_id)

        assert len(resources) == 0

    def test_collect_onedrive_error_handling(self, mock_graph_client, tenant_id):
        """Test OneDrive collection handles errors gracefully."""
        mock_graph_client.users.get.side_effect = Exception("API Error")

        resources = collect_onedrive_accounts(mock_graph_client, tenant_id)

        assert len(resources) == 0


# =============================================================================
# Exchange Tests
# =============================================================================

class TestExchangeCollection:
    """Tests for Exchange mailbox collection."""

    def test_collect_mailboxes_basic(self, mock_graph_client, tenant_id):
        """Test collecting Exchange mailboxes."""
        mock_users = [
            create_mock_user("user-001", "John Doe", mail="john.doe@contoso.com"),
            create_mock_user("user-002", "Jane Smith", mail="jane.smith@contoso.com"),
        ]

        mock_users_response = Mock()
        mock_users_response.value = mock_users
        mock_graph_client.users.get.return_value = mock_users_response

        resources = collect_exchange_mailboxes(mock_graph_client, tenant_id)

        assert len(resources) == 2
        assert resources[0].metadata['mail'] == "john.doe@contoso.com"
        assert resources[1].metadata['mail'] == "jane.smith@contoso.com"

    def test_collect_mailboxes_skip_no_mail(self, mock_graph_client, tenant_id):
        """Test that users without mail are skipped."""
        mock_users = [
            create_mock_user("user-001", "John Doe", mail="john.doe@contoso.com"),
            create_mock_user("user-002", "Service Account", mail=None),
        ]
        # Remove mail from second user
        mock_users[1].mail = None

        mock_users_response = Mock()
        mock_users_response.value = mock_users
        mock_graph_client.users.get.return_value = mock_users_response

        resources = collect_exchange_mailboxes(mock_graph_client, tenant_id)

        assert len(resources) == 1
        assert resources[0].metadata['mail'] == "john.doe@contoso.com"

    def test_collect_mailboxes_empty(self, mock_graph_client, tenant_id):
        """Test collecting mailboxes when none exist."""
        mock_users_response = Mock()
        mock_users_response.value = []
        mock_graph_client.users.get.return_value = mock_users_response

        resources = collect_exchange_mailboxes(mock_graph_client, tenant_id)

        assert len(resources) == 0

    def test_collect_mailboxes_error_handling(self, mock_graph_client, tenant_id):
        """Test Exchange collection handles errors gracefully."""
        mock_graph_client.users.get.side_effect = Exception("API Error")

        resources = collect_exchange_mailboxes(mock_graph_client, tenant_id)

        assert len(resources) == 0

    def test_collect_mailboxes_with_usage_data(self, mock_graph_client, tenant_id):
        """Test collecting Exchange mailboxes from usage report data."""
        # Provide comprehensive mailbox usage data (primary source)
        mailbox_usage = {
            "john.doe@contoso.com": {
                "user_principal_name": "john.doe@contoso.com",
                "display_name": "John Doe",
                "storage_bytes": 5368709120,  # 5 GB
                "storage_gb": 5.0,
                "item_count": 2500,
                "recipient_type": "UserMailbox",
                "mailbox_type": "User",
                "has_archive": True,
                "is_deleted": False,
                "deleted_item_count": 50,
                "deleted_item_size_gb": 0.1,
                "prohibit_send_receive_quota_gb": 50.0,
                "quota_usage_percent": 10.0,
                "last_activity_date": "2026-03-08",
                "created_date": "2024-01-15",
            },
            "jane.smith@contoso.com": {
                "user_principal_name": "jane.smith@contoso.com",
                "display_name": "Jane Smith",
                "storage_bytes": 10737418240,  # 10 GB
                "storage_gb": 10.0,
                "item_count": 5000,
                "recipient_type": "UserMailbox",
                "mailbox_type": "User",
                "has_archive": False,
                "is_deleted": False,
                "deleted_item_count": 100,
                "deleted_item_size_gb": 0.2,
                "prohibit_send_receive_quota_gb": 50.0,
                "quota_usage_percent": 20.0,
                "last_activity_date": "2026-03-07",
                "created_date": "2023-06-20",
            }
        }

        resources = collect_exchange_mailboxes(mock_graph_client, tenant_id, mailbox_usage)

        assert len(resources) == 2
        # Check that resources are created from usage data
        john = next((r for r in resources if 'john.doe' in r.resource_id), None)
        assert john is not None
        assert john.size_gb == pytest.approx(5.0, rel=0.1)
        assert john.metadata['item_count'] == 2500
        assert john.metadata['mailbox_type'] == "User"
        assert john.metadata['has_archive'] is True
        
        jane = next((r for r in resources if 'jane.smith' in r.resource_id), None)
        assert jane is not None
        assert jane.size_gb == pytest.approx(10.0, rel=0.1)
        assert jane.metadata['has_archive'] is False

    def test_collect_mailboxes_different_types(self, mock_graph_client, tenant_id):
        """Test collecting different mailbox types: User, Shared, Room, Group."""
        mailbox_usage = {
            "user@contoso.com": {
                "user_principal_name": "user@contoso.com",
                "display_name": "Regular User",
                "storage_gb": 5.0,
                "item_count": 1000,
                "recipient_type": "UserMailbox",
                "mailbox_type": "User",
                "has_archive": False,
                "is_deleted": False,
            },
            "shared@contoso.com": {
                "user_principal_name": "shared@contoso.com",
                "display_name": "HR Shared Mailbox",
                "storage_gb": 20.0,
                "item_count": 10000,
                "recipient_type": "SharedMailbox",
                "mailbox_type": "Shared",
                "has_archive": True,
                "is_deleted": False,
            },
            "room@contoso.com": {
                "user_principal_name": "room@contoso.com",
                "display_name": "Conference Room A",
                "storage_gb": 0.5,
                "item_count": 500,
                "recipient_type": "RoomMailbox",
                "mailbox_type": "Room",
                "has_archive": False,
                "is_deleted": False,
            },
            "group@contoso.com": {
                "user_principal_name": "group@contoso.com",
                "display_name": "Project Alpha",
                "storage_gb": 15.0,
                "item_count": 8000,
                "recipient_type": "GroupMailbox",
                "mailbox_type": "Group",
                "has_archive": False,
                "is_deleted": False,
            },
        }

        resources = collect_exchange_mailboxes(mock_graph_client, tenant_id, mailbox_usage)

        assert len(resources) == 4
        
        # Verify different types
        types = {r.metadata['mailbox_type'] for r in resources}
        assert types == {"User", "Shared", "Room", "Group"}
        
        # Check shared mailbox
        shared = next((r for r in resources if r.metadata['mailbox_type'] == 'Shared'), None)
        assert shared is not None
        assert shared.metadata['has_archive'] is True
        assert shared.size_gb == 20.0

    def test_collect_mailboxes_skips_deleted(self, mock_graph_client, tenant_id):
        """Test that deleted mailboxes are skipped."""
        mailbox_usage = {
            "active@contoso.com": {
                "user_principal_name": "active@contoso.com",
                "display_name": "Active User",
                "storage_gb": 5.0,
                "item_count": 1000,
                "recipient_type": "UserMailbox",
                "mailbox_type": "User",
                "has_archive": False,
                "is_deleted": False,
            },
            "deleted@contoso.com": {
                "user_principal_name": "deleted@contoso.com",
                "display_name": "Deleted User",
                "storage_gb": 2.0,
                "item_count": 500,
                "recipient_type": "UserMailbox",
                "mailbox_type": "User",
                "has_archive": False,
                "is_deleted": True,
            },
        }

        resources = collect_exchange_mailboxes(mock_graph_client, tenant_id, mailbox_usage)

        assert len(resources) == 1
        assert resources[0].metadata['display_name'] == "Active User"


# =============================================================================
# Usage Reports & Change Rate Tests
# =============================================================================

class TestUsageReports:
    """Tests for usage report parsing and change rate calculation."""

    def test_parse_usage_report_csv_basic(self):
        """Test parsing CSV from usage reports."""
        csv_content = """Report Refresh Date,Site URL,Storage Used (Byte)
2026-03-01,https://contoso.sharepoint.com/sites/hr,5368709120
2026-03-01,https://contoso.sharepoint.com/sites/eng,10737418240"""

        rows = _parse_usage_report_csv(csv_content)

        assert len(rows) == 2
        assert rows[0]['Site URL'] == "https://contoso.sharepoint.com/sites/hr"
        assert rows[0]['Storage Used (Byte)'] == "5368709120"

    def test_parse_usage_report_csv_with_bom(self):
        """Test parsing CSV with BOM marker."""
        csv_content = """\ufeffReport Refresh Date,Site URL,Storage Used (Byte)
2026-03-01,https://contoso.sharepoint.com/sites/hr,5368709120"""

        rows = _parse_usage_report_csv(csv_content)

        assert len(rows) == 1
        assert 'Report Refresh Date' in rows[0]

    def test_calculate_change_rate_basic(self):
        """Test change rate calculation with increasing storage."""
        history = [
            {'date': '2026-01-01', 'storage_bytes': 1000000000},
            {'date': '2026-01-02', 'storage_bytes': 1010000000},
            {'date': '2026-01-03', 'storage_bytes': 1020000000},
            {'date': '2026-01-04', 'storage_bytes': 1030000000},
            {'date': '2026-01-05', 'storage_bytes': 1040000000},
            {'date': '2026-01-06', 'storage_bytes': 1050000000},
            {'date': '2026-01-07', 'storage_bytes': 1060000000},
        ]

        result = calculate_change_rate_and_growth(history)

        assert result['daily_change_gb'] > 0
        assert result['daily_change_percent'] > 0
        assert result['annual_growth_percent'] > 0

    def test_calculate_change_rate_stable(self):
        """Test change rate calculation with stable storage."""
        history = [
            {'date': '2026-01-01', 'storage_bytes': 1000000000},
            {'date': '2026-01-02', 'storage_bytes': 1000000000},
            {'date': '2026-01-03', 'storage_bytes': 1000000000},
            {'date': '2026-01-04', 'storage_bytes': 1000000000},
            {'date': '2026-01-05', 'storage_bytes': 1000000000},
            {'date': '2026-01-06', 'storage_bytes': 1000000000},
            {'date': '2026-01-07', 'storage_bytes': 1000000000},
        ]

        result = calculate_change_rate_and_growth(history)

        assert result['daily_change_gb'] == 0.0
        assert result['daily_change_percent'] == 0.0
        assert result['annual_growth_percent'] == 0.0

    def test_calculate_change_rate_insufficient_data(self):
        """Test change rate calculation with insufficient data."""
        history = [
            {'date': '2026-01-01', 'storage_bytes': 1000000000},
            {'date': '2026-01-02', 'storage_bytes': 1010000000},
        ]

        result = calculate_change_rate_and_growth(history)

        # Should return zeros for insufficient data (< 7 days)
        assert result['daily_change_gb'] == 0.0
        assert result['daily_change_percent'] == 0.0
        assert result['annual_growth_percent'] == 0.0

    def test_calculate_change_rate_empty_history(self):
        """Test change rate calculation with empty history."""
        result = calculate_change_rate_and_growth([])

        assert result['daily_change_gb'] == 0.0
        assert result['daily_change_percent'] == 0.0
        assert result['annual_growth_percent'] == 0.0


class TestHelperFunctions:
    """Tests for helper functions used in data parsing."""

    def test_safe_int_valid(self):
        """Test _safe_int with valid inputs."""
        assert _safe_int("123") == 123
        assert _safe_int(456) == 456
        assert _safe_int("0") == 0

    def test_safe_int_invalid(self):
        """Test _safe_int with invalid inputs."""
        assert _safe_int(None) == 0
        assert _safe_int("") == 0
        assert _safe_int("abc") == 0
        assert _safe_int(None, default=99) == 99

    def test_safe_float_valid(self):
        """Test _safe_float with valid inputs."""
        assert _safe_float("12.5") == 12.5
        assert _safe_float(45.6) == 45.6
        assert _safe_float("0") == 0.0

    def test_safe_float_invalid(self):
        """Test _safe_float with invalid inputs."""
        assert _safe_float(None) == 0.0
        assert _safe_float("") == 0.0
        assert _safe_float("abc") == 0.0
        assert _safe_float(None, default=1.5) == 1.5

    def test_get_csv_field_single_key(self):
        """Test _get_csv_field with single key match."""
        row = {"Field A": "value1", "Field B": "value2"}
        assert _get_csv_field(row, "Field A") == "value1"
        assert _get_csv_field(row, "Field B") == "value2"

    def test_get_csv_field_multiple_keys(self):
        """Test _get_csv_field with multiple possible keys."""
        row = {"Storage Used (Byte)": "5000"}
        # Try multiple key variants
        result = _get_csv_field(row, "storageUsedInBytes", "Storage Used (Byte)", "Storage Used (Bytes)")
        assert result == "5000"

    def test_get_csv_field_missing(self):
        """Test _get_csv_field with missing keys."""
        row = {"Field A": "value1"}
        assert _get_csv_field(row, "Missing") is None
        assert _get_csv_field(row, "Also Missing", "Nope") is None

    def test_get_csv_field_empty_value(self):
        """Test _get_csv_field skips empty values."""
        row = {"Field A": "", "Field B": "value2"}
        assert _get_csv_field(row, "Field A", "Field B") == "value2"


class TestMailboxUsageReportParsing:
    """Tests for comprehensive mailbox usage report parsing."""

    def test_parse_mailbox_report_with_all_fields(self):
        """Test parsing mailbox usage report with all available fields."""
        csv_content = """Report Refresh Date,User Principal Name,Display Name,Is Deleted,Deleted Date,Created Date,Last Activity Date,Item Count,Storage Used (Byte),Issue Warning Quota (Byte),Prohibit Send Quota (Byte),Prohibit Send/Receive Quota (Byte),Deleted Item Count,Deleted Item Size (Byte),Deleted Item Quota (Byte),Has Archive,Recipient Type,Report Period
2026-03-09,john@contoso.com,John Doe,No,,2024-01-15,2026-03-08,2500,5368709120,49392123904,50331648000,53687091200,50,104857600,31457280000,Yes,UserMailbox,180
2026-03-09,shared@contoso.com,HR Shared,No,,2023-06-20,2026-03-07,10000,21474836480,49392123904,50331648000,53687091200,100,209715200,31457280000,No,SharedMailbox,180
2026-03-09,room@contoso.com,Conf Room A,No,,2022-08-01,2026-03-06,500,536870912,49392123904,50331648000,53687091200,10,10485760,31457280000,No,RoomMailbox,180"""

        rows = _parse_usage_report_csv(csv_content)

        assert len(rows) == 3
        
        # Check John's mailbox
        john = rows[0]
        assert john['User Principal Name'] == "john@contoso.com"
        assert john['Display Name'] == "John Doe"
        assert john['Has Archive'] == "Yes"
        assert john['Recipient Type'] == "UserMailbox"
        assert john['Storage Used (Byte)'] == "5368709120"
        
        # Check shared mailbox
        shared = rows[1]
        assert shared['Recipient Type'] == "SharedMailbox"
        assert shared['Has Archive'] == "No"
        
        # Check room mailbox
        room = rows[2]
        assert room['Recipient Type'] == "RoomMailbox"

    def test_parse_mailbox_report_recipient_types(self):
        """Test that different recipient types are preserved."""
        csv_content = """User Principal Name,Recipient Type,Storage Used (Byte)
user@contoso.com,UserMailbox,1000
shared@contoso.com,SharedMailbox,2000
room@contoso.com,RoomMailbox,500
equipment@contoso.com,EquipmentMailbox,300
group@contoso.com,GroupMailbox,5000"""

        rows = _parse_usage_report_csv(csv_content)

        types = [row['Recipient Type'] for row in rows]
        assert types == ["UserMailbox", "SharedMailbox", "RoomMailbox", "EquipmentMailbox", "GroupMailbox"]


# =============================================================================
# Summary Generation Tests
# =============================================================================

class TestExchangeSummaryGeneration:
    """Tests for Exchange summary generation."""

    def test_generate_exchange_summary_user_mailboxes(self):
        """Test Exchange summary with user mailboxes."""
        mailbox_usage = {
            "user1@contoso.com": {
                "recipient_type": "UserMailbox",
                "mailbox_type": "User",
                "is_deleted": False,
                "has_archive": True,
                "item_count": 1000,
                "storage_gb": 5.0,
                "deleted_item_count": 50,
                "deleted_item_size_gb": 0.1,
            },
            "user2@contoso.com": {
                "recipient_type": "UserMailbox",
                "mailbox_type": "User",
                "is_deleted": False,
                "has_archive": False,
                "item_count": 2000,
                "storage_gb": 10.0,
                "deleted_item_count": 100,
                "deleted_item_size_gb": 0.2,
            },
        }

        summary = generate_exchange_summary(mailbox_usage)

        assert summary['user_active']['count'] == 2
        assert summary['user_active']['item_count'] == 3000
        assert summary['user_active']['item_size_gib'] == 15.0
        assert summary['user_archive_enabled']['count'] == 1

    def test_generate_exchange_summary_mixed_types(self):
        """Test Exchange summary with mixed mailbox types."""
        mailbox_usage = {
            "user@contoso.com": {
                "recipient_type": "UserMailbox",
                "is_deleted": False,
                "has_archive": False,
                "item_count": 1000,
                "storage_gb": 5.0,
                "deleted_item_count": 0,
                "deleted_item_size_gb": 0.0,
            },
            "shared@contoso.com": {
                "recipient_type": "SharedMailbox",
                "is_deleted": False,
                "has_archive": False,
                "item_count": 500,
                "storage_gb": 2.0,
                "deleted_item_count": 0,
                "deleted_item_size_gb": 0.0,
            },
            "group@contoso.com": {
                "recipient_type": "GroupMailbox",
                "is_deleted": False,
                "has_archive": False,
                "item_count": 200,
                "storage_gb": 1.0,
                "deleted_item_count": 0,
                "deleted_item_size_gb": 0.0,
            },
            "room@contoso.com": {
                "recipient_type": "RoomMailbox",
                "is_deleted": False,
                "has_archive": False,
                "item_count": 100,
                "storage_gb": 0.5,
                "deleted_item_count": 0,
                "deleted_item_size_gb": 0.0,
            },
        }

        summary = generate_exchange_summary(mailbox_usage)

        assert summary['user_active']['count'] == 1
        assert summary['shared_active']['count'] == 1
        assert summary['group_active']['count'] == 1
        assert summary['room_equipment_active']['count'] == 1
        assert summary['totals_all']['count'] == 4

    def test_generate_exchange_summary_soft_deleted(self):
        """Test Exchange summary categorizes soft-deleted mailboxes."""
        mailbox_usage = {
            "active@contoso.com": {
                "recipient_type": "UserMailbox",
                "is_deleted": False,
                "has_archive": False,
                "item_count": 1000,
                "storage_gb": 5.0,
                "deleted_item_count": 0,
                "deleted_item_size_gb": 0.0,
            },
            "deleted@contoso.com": {
                "recipient_type": "UserMailbox",
                "is_deleted": True,
                "has_archive": False,
                "item_count": 500,
                "storage_gb": 2.0,
                "deleted_item_count": 0,
                "deleted_item_size_gb": 0.0,
            },
        }

        summary = generate_exchange_summary(mailbox_usage)

        assert summary['user_active']['count'] == 1
        assert summary['softdeleted_active']['count'] == 1


class TestSharePointSummaryGeneration:
    """Tests for SharePoint summary generation."""

    def test_generate_sharepoint_summary_basic(self):
        """Test SharePoint summary with mixed site types."""
        site_usage = {
            "https://contoso.sharepoint.com/sites/hr": {
                "storage_gb": 100.0,
                "is_team_site": False,
                "is_deleted": False,
            },
            "https://contoso.sharepoint.com/sites/engineering": {
                "storage_gb": 200.0,
                "is_team_site": True,
                "is_deleted": False,
            },
            "https://contoso.sharepoint.com/teams/marketing": {
                "storage_gb": 150.0,
                "is_team_site": True,
                "is_deleted": False,
            },
        }

        summary = generate_sharepoint_summary(site_usage)

        assert summary['sharepoint_sites']['count'] == 1
        assert summary['sharepoint_sites']['storage_gib'] == 100.0
        assert summary['team_sites']['count'] == 2
        assert summary['team_sites']['storage_gib'] == 350.0
        assert summary['total']['count'] == 3

    def test_generate_sharepoint_summary_with_deleted(self):
        """Test SharePoint summary excludes deleted sites from total."""
        site_usage = {
            "https://contoso.sharepoint.com/sites/active": {
                "storage_gb": 100.0,
                "is_team_site": False,
                "is_deleted": False,
            },
            "https://contoso.sharepoint.com/sites/deleted": {
                "storage_gb": 50.0,
                "is_team_site": False,
                "is_deleted": True,
            },
        }

        summary = generate_sharepoint_summary(site_usage)

        assert summary['total']['count'] == 1  # Excludes deleted
        assert summary['deleted_sites']['count'] == 1
        assert summary['deleted_sites']['storage_gib'] == 50.0


# =============================================================================
# Teams Tests
# =============================================================================

class TestTeamsCollection:
    """Tests for Microsoft Teams collection."""

    def test_collect_teams_basic(self, mock_graph_client, tenant_id):
        """Test collecting Microsoft Teams."""
        mock_groups = [
            create_mock_group("group-001", "Engineering Team", is_team=True),
            create_mock_group("group-002", "Marketing Team", is_team=True),
            create_mock_group("group-003", "Security Group", is_team=False),  # Not a team
        ]

        mock_teams = {
            "group-001": create_mock_team("group-001", "Engineering Team"),
            "group-002": create_mock_team("group-002", "Marketing Team"),
        }

        mock_groups_response = Mock()
        mock_groups_response.value = mock_groups
        mock_graph_client.groups.get.return_value = mock_groups_response

        def get_team(team_id):
            mock_obj = Mock()
            mock_obj.get.return_value = mock_teams.get(team_id)
            return mock_obj

        mock_graph_client.teams.by_team_id.side_effect = lambda tid: get_team(tid)

        resources = collect_teams(mock_graph_client, tenant_id)

        # Should only collect groups that are Teams (have "Team" in resource_provisioning_options)
        assert len(resources) == 2

    def test_collect_teams_archived(self, mock_graph_client, tenant_id):
        """Test collecting archived Teams."""
        mock_groups = [
            create_mock_group("group-001", "Archived Team", is_team=True),
        ]

        mock_team = create_mock_team("group-001", "Archived Team", is_archived=True)

        mock_groups_response = Mock()
        mock_groups_response.value = mock_groups
        mock_graph_client.groups.get.return_value = mock_groups_response

        mock_graph_client.teams.by_team_id.return_value.get.return_value = mock_team

        resources = collect_teams(mock_graph_client, tenant_id)

        assert len(resources) == 1
        assert resources[0].metadata['is_archived'] is True

    def test_collect_teams_empty(self, mock_graph_client, tenant_id):
        """Test collecting Teams when none exist."""
        mock_groups_response = Mock()
        mock_groups_response.value = []
        mock_graph_client.groups.get.return_value = mock_groups_response

        resources = collect_teams(mock_graph_client, tenant_id)

        assert len(resources) == 0

    def test_collect_teams_error_handling(self, mock_graph_client, tenant_id):
        """Test Teams collection handles errors gracefully."""
        mock_graph_client.groups.get.side_effect = Exception("API Error")

        resources = collect_teams(mock_graph_client, tenant_id)

        assert len(resources) == 0


# =============================================================================
# Entra ID User Tests
# =============================================================================

class TestEntraUserCollection:
    """Tests for Entra ID user collection."""

    def test_collect_users_basic(self, mock_graph_client, tenant_id):
        """Test collecting Entra ID users."""
        mock_users = [
            create_mock_user("user-001", "John Doe", account_enabled=True),
            create_mock_user("user-002", "Jane Smith", account_enabled=True),
            create_mock_user("user-003", "Disabled User", account_enabled=False),
        ]

        mock_users_response = Mock()
        mock_users_response.value = mock_users
        mock_graph_client.users.get.return_value = mock_users_response

        resources = collect_entra_users(mock_graph_client, tenant_id)

        assert len(resources) == 3
        # Check that account_enabled status is captured
        enabled_resources = [r for r in resources if r.metadata.get('account_enabled')]
        assert len(enabled_resources) == 2

    def test_collect_users_empty(self, mock_graph_client, tenant_id):
        """Test collecting users when none exist."""
        mock_users_response = Mock()
        mock_users_response.value = []
        mock_graph_client.users.get.return_value = mock_users_response

        resources = collect_entra_users(mock_graph_client, tenant_id)

        assert len(resources) == 0

    def test_collect_users_error_handling(self, mock_graph_client, tenant_id):
        """Test user collection handles errors gracefully."""
        mock_graph_client.users.get.side_effect = Exception("API Error")

        resources = collect_entra_users(mock_graph_client, tenant_id)

        assert len(resources) == 0


# =============================================================================
# Entra ID Group Tests
# =============================================================================

class TestEntraGroupCollection:
    """Tests for Entra ID group collection."""

    def test_collect_groups_basic(self, mock_graph_client, tenant_id):
        """Test collecting Entra ID groups."""
        mock_groups = [
            create_mock_group("group-001", "Engineering", is_team=True),
            create_mock_group("group-002", "Finance", is_team=False),
            create_mock_group("group-003", "All Employees", is_team=False),
        ]

        mock_groups_response = Mock()
        mock_groups_response.value = mock_groups
        mock_graph_client.groups.get.return_value = mock_groups_response

        resources = collect_entra_groups(mock_graph_client, tenant_id)

        assert len(resources) == 3

    def test_collect_groups_empty(self, mock_graph_client, tenant_id):
        """Test collecting groups when none exist."""
        mock_groups_response = Mock()
        mock_groups_response.value = []
        mock_graph_client.groups.get.return_value = mock_groups_response

        resources = collect_entra_groups(mock_graph_client, tenant_id)

        assert len(resources) == 0

    def test_collect_groups_error_handling(self, mock_graph_client, tenant_id):
        """Test group collection handles errors gracefully."""
        mock_graph_client.groups.get.side_effect = Exception("API Error")

        resources = collect_entra_groups(mock_graph_client, tenant_id)

        assert len(resources) == 0


# =============================================================================
# Graph Client Tests
# =============================================================================

class TestGraphClient:
    """Tests for Microsoft Graph client creation."""

    def test_get_graph_client(self):
        """Test creating Graph client with credentials."""
        with patch('m365_collect.ClientSecretCredential') as mock_cred:
            with patch('m365_collect.GraphServiceClient') as mock_client:
                mock_cred.return_value = Mock()
                mock_client.return_value = Mock()

                client = get_graph_client(
                    tenant_id="tenant-123",
                    client_id="client-123",
                    client_secret="secret-123"
                )

                mock_cred.assert_called_once_with(
                    tenant_id="tenant-123",
                    client_id="client-123",
                    client_secret="secret-123"
                )
                assert client is not None


# =============================================================================
# Data Model Tests
# =============================================================================

class TestDataModels:
    """Tests for M365 data model helpers."""

    def test_mock_site_creation(self):
        """Test mock SharePoint site creation."""
        site = create_mock_sharepoint_site("site-001", "Test Site")
        assert site.id == "site-001"
        assert site.display_name == "Test Site"
        assert site.quota.used > 0

    def test_mock_user_creation(self):
        """Test mock user creation."""
        user = create_mock_user("user-001", "Test User")
        assert user.id == "user-001"
        assert user.display_name == "Test User"
        assert "@contoso.com" in user.user_principal_name

    def test_mock_group_creation(self):
        """Test mock group creation."""
        group = create_mock_group("group-001", "Test Group", is_team=True)
        assert group.id == "group-001"
        assert group.display_name == "Test Group"
        assert "Team" in group.resource_provisioning_options

    def test_mock_team_creation(self):
        """Test mock team creation."""
        team = create_mock_team("team-001", "Test Team", is_archived=False)
        assert team.id == "team-001"
        assert team.display_name == "Test Team"
        assert team.is_archived is False


# =============================================================================
# Integration-style Tests
# =============================================================================

class TestResourceTypeValidation:
    """Tests to validate resource types are correctly assigned."""

    def test_sharepoint_resource_type(self, mock_graph_client, tenant_id):
        """Test SharePoint resource type."""
        mock_sites = [create_mock_sharepoint_site("site-001", "Test Site")]
        mock_response = Mock()
        mock_response.value = mock_sites
        mock_graph_client.sites.get.return_value = mock_response

        resources = collect_sharepoint_sites(mock_graph_client, tenant_id)

        assert resources[0].resource_type == "m365:sharepoint:site"
        assert resources[0].provider == "microsoft365"

    def test_onedrive_resource_type(self, mock_graph_client, tenant_id):
        """Test OneDrive resource type."""
        mock_users = [create_mock_user("user-001", "Test User")]
        mock_users_response = Mock()
        mock_users_response.value = mock_users
        mock_graph_client.users.get.return_value = mock_users_response

        mock_drive = create_mock_drive("drive-001")
        mock_graph_client.users.by_user_id.return_value.drive.get.return_value = mock_drive

        resources = collect_onedrive_accounts(mock_graph_client, tenant_id)

        assert resources[0].resource_type == "m365:onedrive:account"
        assert resources[0].provider == "microsoft365"

    def test_exchange_resource_type(self, mock_graph_client, tenant_id):
        """Test Exchange resource type."""
        mock_users = [create_mock_user("user-001", "Test User", mail="test@contoso.com")]
        mock_users_response = Mock()
        mock_users_response.value = mock_users
        mock_graph_client.users.get.return_value = mock_users_response

        resources = collect_exchange_mailboxes(mock_graph_client, tenant_id)

        assert resources[0].resource_type == "m365:exchange:mailbox"
        assert resources[0].provider == "microsoft365"
