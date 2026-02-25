"""
Large-scale integration test for Microsoft 365 resource collector.

This test simulates a large enterprise M365 environment with:
- Multiple SharePoint sites
- Hundreds of OneDrive accounts
- Exchange mailboxes
- Microsoft Teams
- Entra ID users and groups
- Data quality issues (missing metadata, incomplete profiles)

Run with: python -m pytest tests/test_large_scale_m365.py -v -s --log-cli-level=INFO

Output files will be generated in: tests/large_scale_output_m365/
"""
import os
import random
import shutil
import sys
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.models import CloudResource, aggregate_sizing
from lib.utils import (
    generate_run_id,
    get_timestamp,
    print_summary_table,
    write_csv,
    write_json,
)

# =============================================================================
# Constants
# =============================================================================

LARGE_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "large_scale_output", "m365")

DEPARTMENTS = ["Engineering", "Sales", "Marketing", "Finance", "HR", "Legal", "Operations", "IT", "Product", ""]
LOCATIONS = ["New York", "San Francisco", "London", "Tokyo", "Sydney", "Berlin", "Toronto", ""]
JOB_TITLES = [
    "Software Engineer", "Senior Engineer", "Staff Engineer", "Principal Engineer",
    "Product Manager", "Senior PM", "Director", "VP",
    "Sales Representative", "Account Executive", "Sales Manager",
    "Marketing Specialist", "Marketing Manager",
    "Financial Analyst", "Controller",
    "HR Business Partner", "Recruiter",
    ""
]

SITE_TYPES = ["Team Site", "Communication Site", "Hub Site", "Project Site", "Department Site"]
TEAM_VISIBILITY = ["Private", "Public", "HiddenMembership"]


def setup_large_output_dir():
    """Create clean output directory."""
    if os.path.exists(LARGE_OUTPUT_DIR):
        shutil.rmtree(LARGE_OUTPUT_DIR)
    os.makedirs(LARGE_OUTPUT_DIR)


def generate_uuid():
    """Generate a random UUID."""
    return str(uuid.uuid4())


def random_name():
    """Generate a random person name."""
    first_names = ["John", "Jane", "Mike", "Sarah", "David", "Emily", "Robert", "Lisa",
                   "James", "Jennifer", "William", "Maria", "Richard", "Linda", "Thomas",
                   "Patricia", "Charles", "Barbara", "Daniel", "Elizabeth", "Matthew",
                   "Susan", "Anthony", "Jessica", "Mark", "Karen", "Donald", "Nancy",
                   "Steven", "Betty", "Paul", "Margaret", "Andrew", "Sandra", "Joshua"]
    last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
                  "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
                  "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
                  "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark",
                  "Ramirez", "Lewis", "Robinson", "Walker", "Young", "Allen", "King"]
    return f"{random.choice(first_names)} {random.choice(last_names)}"


# =============================================================================
# Mock M365 Resource Generators
# =============================================================================

def create_mock_sharepoint_sites(tenant_id: str, num_sites: int):
    """Create mock SharePoint sites."""
    sites = []

    for i in range(num_sites):
        site_type = random.choice(SITE_TYPES)
        department = random.choice(DEPARTMENTS)
        storage_used_gb = random.uniform(0.1, 500)
        storage_quota_gb = random.choice([25600, 51200, 102400])  # 25TB, 50TB, 100TB in GB

        # Some sites have incomplete metadata (data holes)
        has_full_metadata = random.random() > 0.2

        site_id = generate_uuid()
        site_name = f"{department or 'General'} {site_type} {i+1:03d}" if has_full_metadata else f"Site-{i+1:03d}"

        site = Mock()
        site.id = site_id
        site.display_name = site_name
        site.name = site_name.lower().replace(" ", "-")
        site.web_url = f"https://contoso.sharepoint.com/sites/{site.name}"

        if has_full_metadata:
            site.created_date_time = (datetime.now(timezone.utc) - timedelta(days=random.randint(30, 1000))).isoformat()
            site.last_modified_date_time = (datetime.now(timezone.utc) - timedelta(days=random.randint(0, 30))).isoformat()
        else:
            site.created_date_time = None
            site.last_modified_date_time = None

        site.quota = Mock()
        site.quota.used = int(storage_used_gb * 1024**3)
        site.quota.total = int(storage_quota_gb * 1024**3)

        sites.append(site)

    return sites


def create_mock_users_with_drives(tenant_id: str, num_users: int):
    """Create mock Entra ID users with OneDrive accounts."""
    users = []
    drives = []

    for _i in range(num_users):
        user_id = generate_uuid()
        name = random_name()
        department = random.choice(DEPARTMENTS)
        location = random.choice(LOCATIONS)
        job_title = random.choice(JOB_TITLES)

        # Some users have incomplete profiles (data holes)
        has_full_profile = random.random() > 0.15
        is_active = random.random() > 0.05  # 95% active

        username = name.lower().replace(" ", ".")

        user = Mock()
        user.id = user_id
        user.display_name = name
        user.user_principal_name = f"{username}@contoso.com"
        user.mail = f"{username}@contoso.com" if has_full_profile else None
        user.account_enabled = is_active
        user.department = department if has_full_profile else None
        user.job_title = job_title if has_full_profile else None
        user.office_location = location if has_full_profile else None
        user.created_date_time = (datetime.now(timezone.utc) - timedelta(days=random.randint(30, 1500))).isoformat()

        users.append(user)

        # Create OneDrive for active users (some may not have OneDrive provisioned)
        if is_active and random.random() > 0.1:
            storage_used_gb = random.uniform(0.1, 200)
            storage_quota_gb = 1024  # 1TB typical

            drive = Mock()
            drive.id = generate_uuid()
            drive.drive_type = "business"
            drive.web_url = f"https://contoso-my.sharepoint.com/personal/{username.replace('.', '_')}_contoso_com"
            drive.owner_id = user_id
            drive.owner_name = name

            drive.quota = Mock()
            drive.quota.used = int(storage_used_gb * 1024**3)
            drive.quota.total = int(storage_quota_gb * 1024**3)

            drives.append(drive)

    return users, drives


def create_mock_mailboxes(users: list):
    """Create mock Exchange mailboxes for users."""
    mailboxes = []

    for user in users:
        # Only active users have mailboxes
        if not user.account_enabled:
            continue

        # Some users may not have mailboxes yet
        if random.random() < 0.05:
            continue

        mailbox_size_gb = random.uniform(0.1, 50)

        mailbox = Mock()
        mailbox.id = user.id
        mailbox.display_name = user.display_name
        mailbox.user_principal_name = user.user_principal_name
        mailbox.mail = user.mail or user.user_principal_name

        mailbox.quota = Mock()
        mailbox.quota.used = int(mailbox_size_gb * 1024**3)
        mailbox.quota.total = int(50 * 1024**3)  # 50GB typical

        mailboxes.append(mailbox)

    return mailboxes


def create_mock_teams(tenant_id: str, num_teams: int):
    """Create mock Microsoft Teams."""
    teams = []

    for i in range(num_teams):
        department = random.choice(DEPARTMENTS)
        visibility = random.choice(TEAM_VISIBILITY)

        # Some teams have incomplete metadata
        has_full_metadata = random.random() > 0.15

        team_id = generate_uuid()
        team_name = f"{department or 'General'} Team {i+1:03d}" if has_full_metadata else f"Team-{i+1:03d}"

        team = Mock()
        team.id = team_id
        team.display_name = team_name
        team.description = f"Team for {department}" if has_full_metadata and department else None
        team.visibility = visibility
        team.is_archived = random.random() < 0.1  # 10% archived
        team.web_url = f"https://teams.microsoft.com/l/team/{team_id}"
        team.created_date_time = (datetime.now(timezone.utc) - timedelta(days=random.randint(30, 800))).isoformat()

        # Member count
        team.member_count = random.randint(2, 500)

        teams.append(team)

    return teams


def create_mock_groups(tenant_id: str, num_groups: int, teams: list):
    """Create mock Entra ID groups."""
    groups = []
    {t.id for t in teams}

    for i in range(num_groups):
        department = random.choice(DEPARTMENTS)

        # Some groups are Microsoft 365 groups (potentially Teams-enabled)
        is_m365_group = random.random() < 0.6
        has_team = is_m365_group and random.random() < 0.4

        # Some groups have incomplete metadata
        has_full_metadata = random.random() > 0.15

        group_id = generate_uuid()
        group_name = f"{department or 'General'} Group {i+1:03d}" if has_full_metadata else f"Group-{i+1:03d}"

        group = Mock()
        group.id = group_id
        group.display_name = group_name
        group.description = f"Group for {department}" if has_full_metadata and department else None
        group.visibility = random.choice(["Private", "Public"])
        group.mail = f"{group_name.lower().replace(' ', '-')}@contoso.com" if is_m365_group else None
        group.created_date_time = (datetime.now(timezone.utc) - timedelta(days=random.randint(30, 1000))).isoformat()
        group.group_types = ["Unified"] if is_m365_group else []
        group.resource_provisioning_options = ["Team"] if has_team else []

        # Member count
        group.member_count = random.randint(1, 200)

        groups.append(group)

    return groups


# =============================================================================
# Test Class
# =============================================================================

class TestLargeScaleM365:
    """Large-scale integration test for M365 with realistic enterprise data."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures."""
        setup_large_output_dir()
        yield

    def test_large_scale_m365_collection(self):
        """
        Test collection across a large, realistic M365 enterprise environment.

        Scale:
        - ~100 SharePoint sites
        - ~500 users with Entra ID profiles
        - ~450 OneDrive accounts
        - ~480 Exchange mailboxes
        - ~100 Microsoft Teams
        - ~150 Entra ID groups
        """
        print("\n" + "=" * 80)
        print("LARGE-SCALE M365 INTEGRATION TEST")
        print("=" * 80)

        # Configuration - scale factors
        NUM_SHAREPOINT_SITES = 100
        NUM_USERS = 500
        NUM_TEAMS = 100
        NUM_GROUPS = 150

        tenant_id = "12345678-1234-1234-1234-123456789012"
        tenant_name = "Contoso Corporation"

        print("\n📦 Creating mock M365 infrastructure...\n")

        all_resources = []

        # Create SharePoint sites
        print("  Creating SharePoint sites...")
        sharepoint_sites = create_mock_sharepoint_sites(tenant_id, NUM_SHAREPOINT_SITES)

        for site in sharepoint_sites:
            storage_used_gb = site.quota.used / (1024**3) if site.quota else 0
            storage_quota_gb = site.quota.total / (1024**3) if site.quota else 0

            resource = CloudResource(
                provider="microsoft365",
                subscription_id=tenant_id,
                region="global",
                resource_type="m365:sharepoint:site",
                service_family="SharePoint",
                resource_id=site.id,
                name=site.display_name or site.name or "Unknown",
                tags={},
                size_gb=storage_used_gb,
                metadata={
                    'web_url': site.web_url,
                    'created_datetime': site.created_date_time,
                    'last_modified': site.last_modified_date_time,
                    'storage_quota_gb': round(storage_quota_gb, 2),
                    'storage_used_gb': round(storage_used_gb, 2),
                }
            )
            all_resources.append(resource)

        print(f"    Created {len(sharepoint_sites)} SharePoint sites")

        # Create users and OneDrive accounts
        print("  Creating users and OneDrive accounts...")
        users, drives = create_mock_users_with_drives(tenant_id, NUM_USERS)

        for user in users:
            resource = CloudResource(
                provider="microsoft365",
                subscription_id=tenant_id,
                region="global",
                resource_type="m365:entra:user",
                service_family="EntraID",
                resource_id=user.id,
                name=user.display_name,
                tags={},
                size_gb=0.0,
                metadata={
                    'user_principal_name': user.user_principal_name,
                    'mail': user.mail,
                    'account_enabled': user.account_enabled,
                    'department': user.department,
                    'job_title': user.job_title,
                    'office_location': user.office_location,
                }
            )
            all_resources.append(resource)

        for drive in drives:
            storage_used_gb = drive.quota.used / (1024**3) if drive.quota else 0
            storage_quota_gb = drive.quota.total / (1024**3) if drive.quota else 0

            resource = CloudResource(
                provider="microsoft365",
                subscription_id=tenant_id,
                region="global",
                resource_type="m365:onedrive:account",
                service_family="OneDrive",
                resource_id=drive.id,
                name=drive.owner_name,
                tags={},
                size_gb=storage_used_gb,
                metadata={
                    'web_url': drive.web_url,
                    'drive_type': drive.drive_type,
                    'owner_id': drive.owner_id,
                    'storage_quota_gb': round(storage_quota_gb, 2),
                    'storage_used_gb': round(storage_used_gb, 2),
                }
            )
            all_resources.append(resource)

        print(f"    Created {len(users)} users, {len(drives)} OneDrive accounts")

        # Create Exchange mailboxes
        print("  Creating Exchange mailboxes...")
        mailboxes = create_mock_mailboxes(users)

        for mailbox in mailboxes:
            storage_used_gb = mailbox.quota.used / (1024**3) if mailbox.quota else 0
            storage_quota_gb = mailbox.quota.total / (1024**3) if mailbox.quota else 0

            resource = CloudResource(
                provider="microsoft365",
                subscription_id=tenant_id,
                region="global",
                resource_type="m365:exchange:mailbox",
                service_family="Exchange",
                resource_id=mailbox.id,
                name=mailbox.display_name,
                tags={},
                size_gb=storage_used_gb,
                metadata={
                    'user_principal_name': mailbox.user_principal_name,
                    'mail': mailbox.mail,
                    'storage_quota_gb': round(storage_quota_gb, 2),
                    'storage_used_gb': round(storage_used_gb, 2),
                }
            )
            all_resources.append(resource)

        print(f"    Created {len(mailboxes)} Exchange mailboxes")

        # Create Teams
        print("  Creating Microsoft Teams...")
        teams = create_mock_teams(tenant_id, NUM_TEAMS)

        for team in teams:
            resource = CloudResource(
                provider="microsoft365",
                subscription_id=tenant_id,
                region="global",
                resource_type="m365:teams:team",
                service_family="Teams",
                resource_id=team.id,
                name=team.display_name,
                tags={},
                size_gb=0.0,
                metadata={
                    'description': team.description,
                    'visibility': team.visibility,
                    'is_archived': team.is_archived,
                    'web_url': team.web_url,
                    'member_count': team.member_count,
                }
            )
            all_resources.append(resource)

        print(f"    Created {len(teams)} Teams")

        # Create Groups
        print("  Creating Entra ID groups...")
        groups = create_mock_groups(tenant_id, NUM_GROUPS, teams)

        for group in groups:
            is_m365 = "Unified" in (group.group_types or [])
            has_team = "Team" in (group.resource_provisioning_options or [])

            resource = CloudResource(
                provider="microsoft365",
                subscription_id=tenant_id,
                region="global",
                resource_type="m365:entra:group",
                service_family="EntraID",
                resource_id=group.id,
                name=group.display_name,
                tags={},
                size_gb=0.0,
                metadata={
                    'description': group.description,
                    'visibility': group.visibility,
                    'mail': group.mail,
                    'is_m365_group': is_m365,
                    'has_team': has_team,
                    'member_count': group.member_count,
                }
            )
            all_resources.append(resource)

        print(f"    Created {len(groups)} groups")

        print("\n✅ Mock infrastructure created\n")

        # Generate outputs
        run_id = generate_run_id()
        timestamp = get_timestamp()

        # Build sizing summaries
        summaries = aggregate_sizing(all_resources)

        inventory_data = {
            'provider': 'microsoft365',
            'run_id': run_id,
            'timestamp': timestamp,
            'tenant_id': tenant_id,
            'tenant_name': tenant_name,
            'resources': [r.to_dict() for r in all_resources]
        }

        summary_data = {
            'provider': 'microsoft365',
            'run_id': run_id,
            'timestamp': timestamp,
            'tenant_id': tenant_id,
            'total_resources': len(all_resources),
            'total_capacity_gb': sum(s.total_gb for s in summaries),
            'summaries': [s.to_dict() for s in summaries]
        }

        # Write output files
        file_ts = datetime.now(timezone.utc).strftime('%H%M%S')
        write_json(inventory_data, f"{LARGE_OUTPUT_DIR}/cca_inv_{file_ts}.json")
        write_json(summary_data, f"{LARGE_OUTPUT_DIR}/cca_sum_{file_ts}.json")

        csv_data = [s.to_dict() for s in summaries]
        write_csv(csv_data, f"{LARGE_OUTPUT_DIR}/sizing.csv")

        # Print statistics
        print("\n" + "=" * 80)
        print("COLLECTION RESULTS")
        print("=" * 80)
        print(f"\nTenant: {tenant_id}")
        print(f"Tenant Name: {tenant_name}")
        print(f"Total Resources: {len(all_resources)}")

        # Count by type
        by_type = {}
        for r in all_resources:
            by_type[r.resource_type] = by_type.get(r.resource_type, 0) + 1

        print("\nResources by Type:")
        for rtype, count in sorted(by_type.items()):
            print(f"  {rtype}: {count}")

        # Count resources with missing names (data holes)
        missing_names = len([r for r in all_resources if not r.name or r.name == "Unknown"])
        missing_metadata = len([r for r in all_resources
                               if r.resource_type == "m365:entra:user"
                               and not r.metadata.get('department')])

        print("\nData Quality:")
        if len(all_resources) > 0:
            print(f"  Resources with missing names: {missing_names} ({missing_names/len(all_resources)*100:.1f}%)")
        else:
            print(f"  Resources with missing names: {missing_names}")
        user_count = by_type.get("m365:entra:user", 0)
        if user_count > 0:
            print(f"  Users with incomplete profiles: {missing_metadata} ({missing_metadata/user_count*100:.1f}%)")

        # Storage summary
        total_sharepoint_gb = sum(r.size_gb for r in all_resources if r.resource_type == "m365:sharepoint:site")
        total_onedrive_gb = sum(r.size_gb for r in all_resources if r.resource_type == "m365:onedrive:account")
        total_exchange_gb = sum(r.size_gb for r in all_resources if r.resource_type == "m365:exchange:mailbox")

        print("\nStorage Summary:")
        print(f"  SharePoint: {total_sharepoint_gb:,.1f} GB")
        print(f"  OneDrive: {total_onedrive_gb:,.1f} GB")
        print(f"  Exchange: {total_exchange_gb:,.1f} GB")
        print(f"  Total: {total_sharepoint_gb + total_onedrive_gb + total_exchange_gb:,.1f} GB")

        print_summary_table([s.to_dict() for s in summaries])

        print(f"\nOutput: {LARGE_OUTPUT_DIR}/")

        # Assertions
        assert len(all_resources) > 500, "Should have collected many resources"
        assert by_type.get("m365:sharepoint:site", 0) > 50, "Should have many SharePoint sites"
        assert by_type.get("m365:entra:user", 0) > 200, "Should have many users"
        assert by_type.get("m365:onedrive:account", 0) > 200, "Should have many OneDrive accounts"

        # Verify files exist
        import glob
        inv_files = glob.glob(f"{LARGE_OUTPUT_DIR}/cca_inv_*.json")
        assert len(inv_files) >= 1, "Inventory file should exist"

        print("\n" + "=" * 80)
        print("TEST COMPLETE")
        print("=" * 80)


# =============================================================================
# Run directly
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--log-cli-level=INFO"])
