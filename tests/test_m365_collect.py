"""
Tests for Microsoft 365 resource collector using unittest.mock.

Covers:
- SharePoint site collection
- OneDrive account collection
- Exchange mailbox collection
- Microsoft Teams collection
- Entra ID users and groups collection
"""
import pytest
from unittest.mock import Mock, MagicMock, patch, AsyncMock
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from m365_collect import (
    get_graph_client,
    collect_sharepoint_sites,
    collect_onedrive_accounts,
    collect_exchange_mailboxes,
    collect_teams,
    collect_entra_users,
    collect_entra_groups,
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
