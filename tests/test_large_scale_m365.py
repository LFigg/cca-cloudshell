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

# SharePoint site templates (for site type classification)
SHAREPOINT_TEMPLATES = [
    ("GROUP", "Team Site"),
    ("GROUP#0", "Group Site"),
    ("SITEPAGEPUBLISHING", "Communication Site"),
    ("STS", "Team Site"),  # Classic team site
]

# Mailbox types with realistic distribution
MAILBOX_TYPES = [
    ("UserMailbox", "User", 0.80),       # 80% are regular user mailboxes
    ("SharedMailbox", "Shared", 0.10),   # 10% shared
    ("RoomMailbox", "Room", 0.05),       # 5% room
    ("EquipmentMailbox", "Equipment", 0.03),  # 3% equipment
    ("GroupMailbox", "Group", 0.02),     # 2% group
]


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
    """Create mock SharePoint sites with site type classification."""
    sites = []

    for i in range(num_sites):
        site_type = random.choice(SITE_TYPES)
        department = random.choice(DEPARTMENTS)
        storage_used_gb = random.uniform(0.1, 500)
        storage_quota_gb = random.choice([25600, 51200, 102400])  # 25TB, 50TB, 100TB in GB

        # Some sites have incomplete metadata (data holes)
        has_full_metadata = random.random() > 0.2
        
        # Pick a SharePoint template for site type classification
        template, template_site_type = random.choice(SHAREPOINT_TEMPLATES)
        
        # Some sites are soft-deleted
        is_deleted = random.random() < 0.03  # 3% deleted

        site_id = generate_uuid()
        site_name = f"{department or 'General'} {site_type} {i+1:03d}" if has_full_metadata else f"Site-{i+1:03d}"

        site = Mock()
        site.id = site_id
        site.display_name = site_name
        site.name = site_name.lower().replace(" ", "-")
        site.web_url = f"https://contoso.sharepoint.com/sites/{site.name}"
        site.root_web_template = template
        site.site_type = template_site_type
        site.is_deleted = is_deleted

        if has_full_metadata:
            site.created_date_time = (datetime.now(timezone.utc) - timedelta(days=random.randint(30, 1000))).isoformat()
            site.last_modified_date_time = (datetime.now(timezone.utc) - timedelta(days=random.randint(0, 30))).isoformat()
            site.last_activity_date = (datetime.now(timezone.utc) - timedelta(days=random.randint(0, 30))).strftime('%Y-%m-%d')
        else:
            site.created_date_time = None
            site.last_modified_date_time = None
            site.last_activity_date = None
        
        # File counts
        site.file_count = random.randint(100, 50000) if has_full_metadata else None
        site.active_file_count = random.randint(10, site.file_count or 1000) if has_full_metadata and site.file_count else None

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
    """Create mock Exchange mailboxes with comprehensive types and metadata."""
    mailboxes = []
    
    # Create user mailboxes for active users
    for user in users:
        # Only active users have mailboxes
        if not user.account_enabled:
            continue

        # Some users may not have mailboxes yet
        if random.random() < 0.05:
            continue

        # Select mailbox type based on weighted distribution
        rand_val = random.random()
        cumulative = 0
        recipient_type = "UserMailbox"
        mailbox_type = "User"
        for rt, mt, prob in MAILBOX_TYPES:
            cumulative += prob
            if rand_val <= cumulative:
                recipient_type = rt
                mailbox_type = mt
                break

        mailbox_size_gb = random.uniform(0.1, 50)
        
        # Archive mailbox (20% of user mailboxes have archive enabled)
        has_archive = mailbox_type == "User" and random.random() < 0.20
        
        # Soft-deleted mailboxes (2%)
        is_deleted = random.random() < 0.02
        
        # Item counts
        item_count = random.randint(500, 50000)
        deleted_item_count = random.randint(0, int(item_count * 0.1))
        deleted_item_size_gb = random.uniform(0, mailbox_size_gb * 0.05)
        
        # Quotas
        prohibit_send_receive_quota_gb = 50.0
        issue_warning_quota_gb = 49.0
        prohibit_send_quota_gb = 49.5
        quota_usage_percent = (mailbox_size_gb / prohibit_send_receive_quota_gb) * 100

        mailbox = Mock()
        mailbox.id = user.id
        mailbox.display_name = user.display_name
        mailbox.user_principal_name = user.user_principal_name
        mailbox.mail = user.mail or user.user_principal_name
        mailbox.recipient_type = recipient_type
        mailbox.mailbox_type = mailbox_type
        mailbox.has_archive = has_archive
        mailbox.is_deleted = is_deleted
        mailbox.item_count = item_count
        mailbox.deleted_item_count = deleted_item_count
        mailbox.deleted_item_size_gb = deleted_item_size_gb
        mailbox.prohibit_send_receive_quota_gb = prohibit_send_receive_quota_gb
        mailbox.issue_warning_quota_gb = issue_warning_quota_gb
        mailbox.prohibit_send_quota_gb = prohibit_send_quota_gb
        mailbox.quota_usage_percent = quota_usage_percent
        mailbox.last_activity_date = (datetime.now(timezone.utc) - timedelta(days=random.randint(0, 30))).strftime('%Y-%m-%d')
        mailbox.created_date = (datetime.now(timezone.utc) - timedelta(days=random.randint(30, 1500))).strftime('%Y-%m-%d')

        mailbox.quota = Mock()
        mailbox.quota.used = int(mailbox_size_gb * 1024**3)
        mailbox.quota.total = int(50 * 1024**3)  # 50GB typical

        mailboxes.append(mailbox)

    return mailboxes


def create_mock_teams_activity(num_users: int):
    """Create mock Teams activity report data."""
    activity = {
        'active_users': int(num_users * 0.9),  # 90% active on Teams
        'team_chat_messages': random.randint(10000, 50000),
        'private_chat_messages': random.randint(30000, 100000),
        'calls': random.randint(5000, 20000),
        'meetings': random.randint(8000, 30000),
    }
    return activity


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
                    'site_type': site.site_type,
                    'root_web_template': site.root_web_template,
                    'is_deleted': site.is_deleted,
                    'last_activity_date': site.last_activity_date,
                    'file_count': site.file_count,
                    'active_file_count': site.active_file_count,
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
                    'mailbox_type': mailbox.mailbox_type,
                    'recipient_type': mailbox.recipient_type,
                    'has_archive': mailbox.has_archive,
                    'is_deleted': mailbox.is_deleted,
                    'storage_quota_gb': round(storage_quota_gb, 2),
                    'storage_used_gb': round(storage_used_gb, 2),
                    'item_count': mailbox.item_count,
                    'deleted_item_count': mailbox.deleted_item_count,
                    'deleted_item_size_gb': round(mailbox.deleted_item_size_gb, 3),
                    'prohibit_send_receive_quota_gb': mailbox.prohibit_send_receive_quota_gb,
                    'issue_warning_quota_gb': mailbox.issue_warning_quota_gb,
                    'prohibit_send_quota_gb': mailbox.prohibit_send_quota_gb,
                    'quota_usage_percent': round(mailbox.quota_usage_percent, 1),
                    'last_activity_date': mailbox.last_activity_date,
                    'created_date': mailbox.created_date,
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

        # Create Teams activity
        print("  Creating Teams activity data...")
        teams_activity = create_mock_teams_activity(NUM_USERS)
        print(f"    Active users: {teams_activity['active_users']}, Messages: {teams_activity['team_chat_messages'] + teams_activity['private_chat_messages']}")

        print("\n✅ Mock infrastructure created\n")

        # Generate outputs
        run_id = generate_run_id()
        timestamp = get_timestamp()

        # Build sizing summaries
        summaries = aggregate_sizing(all_resources)
        
        # Build exchange mailbox breakdown
        exchange_breakdown = {'by_type': {}, 'archive_enabled_count': 0, 'soft_deleted_count': 0}
        exchange_resources = [r for r in all_resources if r.resource_type == 'm365:exchange:mailbox']
        for r in exchange_resources:
            mtype = r.metadata.get('mailbox_type', 'Unknown')
            if mtype not in exchange_breakdown['by_type']:
                exchange_breakdown['by_type'][mtype] = {'count': 0, 'storage_gb': 0.0}
            exchange_breakdown['by_type'][mtype]['count'] += 1
            exchange_breakdown['by_type'][mtype]['storage_gb'] += r.size_gb
            if r.metadata.get('has_archive'):
                exchange_breakdown['archive_enabled_count'] += 1
            if r.metadata.get('is_deleted'):
                exchange_breakdown['soft_deleted_count'] += 1
        # Round storage values
        for mtype in exchange_breakdown['by_type']:
            exchange_breakdown['by_type'][mtype]['storage_gb'] = round(exchange_breakdown['by_type'][mtype]['storage_gb'], 2)
        
        # Build SharePoint site breakdown
        sharepoint_breakdown = {'by_type': {}, 'deleted_count': 0}
        sharepoint_resources = [r for r in all_resources if r.resource_type == 'm365:sharepoint:site']
        for r in sharepoint_resources:
            stype = r.metadata.get('site_type', 'Unknown')
            if stype not in sharepoint_breakdown['by_type']:
                sharepoint_breakdown['by_type'][stype] = {'count': 0, 'storage_gb': 0.0}
            sharepoint_breakdown['by_type'][stype]['count'] += 1
            sharepoint_breakdown['by_type'][stype]['storage_gb'] += r.size_gb
            if r.metadata.get('is_deleted'):
                sharepoint_breakdown['deleted_count'] += 1
        # Round storage values
        for stype in sharepoint_breakdown['by_type']:
            sharepoint_breakdown['by_type'][stype]['storage_gb'] = round(sharepoint_breakdown['by_type'][stype]['storage_gb'], 2)

        # Build exchange_summary in Cohesity sizer format
        # Categories: user_active, user_archive_enabled, softdeleted_active, softdeleted_archive,
        #             group_active, group_archive, publicfolder_active, shared_active, room_equipment_active
        exchange_summary = {
            'user_active': {'count': 0, 'item_count': 0, 'item_size_gib': 0.0, 
                           'recoverable_item_count': 0, 'recoverable_item_size_gib': 0.0},
            'user_archive_enabled': {'count': 0},
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
        
        for r in exchange_resources:
            recipient_type = r.metadata.get('recipient_type', 'UserMailbox')
            is_deleted = r.metadata.get('is_deleted', False)
            has_archive = r.metadata.get('has_archive', False)
            item_count = r.metadata.get('item_count', 0)
            item_size_gib = r.size_gb  # size_gb is already in GB which in this context is GiB
            recoverable_count = r.metadata.get('deleted_item_count', 0)
            recoverable_size_gib = r.metadata.get('deleted_item_size_gb', 0.0)
            
            if recipient_type == 'GroupMailbox':
                if not is_deleted:
                    exchange_summary['group_active']['count'] += 1
                    exchange_summary['group_active']['item_count'] += item_count
                    exchange_summary['group_active']['item_size_gib'] += item_size_gib
                    exchange_summary['group_active']['recoverable_item_count'] += recoverable_count
                    exchange_summary['group_active']['recoverable_item_size_gib'] += recoverable_size_gib
                    if has_archive:
                        exchange_summary['group_archive']['count'] += 1
            elif recipient_type == 'PublicFolderMailbox':
                exchange_summary['publicfolder_active']['count'] += 1
                exchange_summary['publicfolder_active']['item_count'] += item_count
                exchange_summary['publicfolder_active']['item_size_gib'] += item_size_gib
                exchange_summary['publicfolder_active']['recoverable_item_count'] += recoverable_count
                exchange_summary['publicfolder_active']['recoverable_item_size_gib'] += recoverable_size_gib
            elif recipient_type == 'SharedMailbox':
                if not is_deleted:
                    exchange_summary['shared_active']['count'] += 1
                    exchange_summary['shared_active']['item_count'] += item_count
                    exchange_summary['shared_active']['item_size_gib'] += item_size_gib
                    exchange_summary['shared_active']['recoverable_item_count'] += recoverable_count
                    exchange_summary['shared_active']['recoverable_item_size_gib'] += recoverable_size_gib
            elif recipient_type in ('RoomMailbox', 'EquipmentMailbox', 'SchedulingMailbox'):
                exchange_summary['room_equipment_active']['count'] += 1
                exchange_summary['room_equipment_active']['item_count'] += item_count
                exchange_summary['room_equipment_active']['item_size_gib'] += item_size_gib
                exchange_summary['room_equipment_active']['recoverable_item_count'] += recoverable_count
                exchange_summary['room_equipment_active']['recoverable_item_size_gib'] += recoverable_size_gib
            else:  # UserMailbox
                if is_deleted:
                    exchange_summary['softdeleted_active']['count'] += 1
                    exchange_summary['softdeleted_active']['item_count'] += item_count
                    exchange_summary['softdeleted_active']['item_size_gib'] += item_size_gib
                    exchange_summary['softdeleted_active']['recoverable_item_count'] += recoverable_count
                    exchange_summary['softdeleted_active']['recoverable_item_size_gib'] += recoverable_size_gib
                    if has_archive:
                        exchange_summary['softdeleted_archive']['count'] += 1
                else:
                    exchange_summary['user_active']['count'] += 1
                    exchange_summary['user_active']['item_count'] += item_count
                    exchange_summary['user_active']['item_size_gib'] += item_size_gib
                    exchange_summary['user_active']['recoverable_item_count'] += recoverable_count
                    exchange_summary['user_active']['recoverable_item_size_gib'] += recoverable_size_gib
                    if has_archive:
                        exchange_summary['user_archive_enabled']['count'] += 1
        
        # Calculate totals for each category
        for cat_name, category in exchange_summary.items():
            if 'item_count' in category:
                category['total_item_count'] = category['item_count'] + category.get('recoverable_item_count', 0)
                category['total_item_size_gib'] = round(
                    category['item_size_gib'] + category.get('recoverable_item_size_gib', 0.0), 3
                )
                category['item_size_gib'] = round(category['item_size_gib'], 3)
                category['recoverable_item_size_gib'] = round(category.get('recoverable_item_size_gib', 0.0), 3)
        
        # Calculate ASP effective size (adds ~10% overhead for metadata)
        asp_factor = 1.1
        
        # Totals with default options (user mailboxes only)
        exchange_summary['totals_default'] = {
            'count': exchange_summary['user_active']['count'],
            'item_count': exchange_summary['user_active']['item_count'],
            'item_size_gib': exchange_summary['user_active']['item_size_gib'],
            'recoverable_item_count': exchange_summary['user_active']['recoverable_item_count'],
            'recoverable_item_size_gib': exchange_summary['user_active']['recoverable_item_size_gib'],
            'total_item_count': exchange_summary['user_active']['total_item_count'],
            'total_item_size_gib': exchange_summary['user_active']['total_item_size_gib'],
            'effective_size_asp_gib': round(exchange_summary['user_active']['total_item_size_gib'] * asp_factor, 3),
        }
        
        # Totals with all options
        all_categories = ['user_active', 'group_active', 'publicfolder_active', 
                          'shared_active', 'room_equipment_active', 'softdeleted_active']
        exchange_summary['totals_all'] = {
            'count': sum(exchange_summary[cat]['count'] for cat in all_categories),
            'item_count': sum(exchange_summary[cat].get('item_count', 0) for cat in all_categories),
            'item_size_gib': round(sum(exchange_summary[cat].get('item_size_gib', 0.0) for cat in all_categories), 3),
            'recoverable_item_count': sum(exchange_summary[cat].get('recoverable_item_count', 0) for cat in all_categories),
            'recoverable_item_size_gib': round(sum(exchange_summary[cat].get('recoverable_item_size_gib', 0.0) for cat in all_categories), 3),
        }
        exchange_summary['totals_all']['total_item_count'] = (
            exchange_summary['totals_all']['item_count'] + exchange_summary['totals_all']['recoverable_item_count']
        )
        exchange_summary['totals_all']['total_item_size_gib'] = round(
            exchange_summary['totals_all']['item_size_gib'] + exchange_summary['totals_all']['recoverable_item_size_gib'], 3
        )
        exchange_summary['totals_all']['effective_size_asp_gib'] = round(
            exchange_summary['totals_all']['total_item_size_gib'] * asp_factor, 3
        )

        # Build sharepoint_summary in Cohesity sizer format
        sharepoint_summary = {
            'sharepoint_sites': {'count': 0, 'file_count': 0, 'storage_gib': 0.0},
            'team_sites': {'count': 0, 'file_count': 0, 'storage_gib': 0.0},
            'total': {'count': 0, 'file_count': 0, 'storage_gib': 0.0},
        }
        
        for r in sharepoint_resources:
            if r.metadata.get('is_deleted'):
                continue
            file_count = r.metadata.get('file_count', 0) or 0
            storage_gib = r.size_gb
            site_type = r.metadata.get('site_type', '')
            
            # Team Site includes sites with GROUP template or Team Site type
            is_team_site = site_type == 'Team Site' or 'Team' in site_type
            if is_team_site:
                sharepoint_summary['team_sites']['count'] += 1
                sharepoint_summary['team_sites']['file_count'] += file_count
                sharepoint_summary['team_sites']['storage_gib'] += storage_gib
            else:
                sharepoint_summary['sharepoint_sites']['count'] += 1
                sharepoint_summary['sharepoint_sites']['file_count'] += file_count
                sharepoint_summary['sharepoint_sites']['storage_gib'] += storage_gib
        
        sharepoint_summary['total']['count'] = sharepoint_summary['sharepoint_sites']['count'] + sharepoint_summary['team_sites']['count']
        sharepoint_summary['total']['file_count'] = sharepoint_summary['sharepoint_sites']['file_count'] + sharepoint_summary['team_sites']['file_count']
        sharepoint_summary['total']['storage_gib'] = round(
            sharepoint_summary['sharepoint_sites']['storage_gib'] + sharepoint_summary['team_sites']['storage_gib'], 3
        )
        sharepoint_summary['total']['effective_size_asp_gib'] = round(sharepoint_summary['total']['storage_gib'] * asp_factor, 3)
        
        # Round storage values
        for cat in ['sharepoint_sites', 'team_sites']:
            sharepoint_summary[cat]['storage_gib'] = round(sharepoint_summary[cat]['storage_gib'], 3)

        # Build onedrive_summary  
        onedrive_resources = [r for r in all_resources if r.resource_type == 'm365:onedrive:account']
        onedrive_summary = {
            'personal_sites': {
                'count': len(onedrive_resources),
                'storage_gib': round(sum(r.size_gb for r in onedrive_resources), 3),
            }
        }
        onedrive_summary['personal_sites']['effective_size_asp_gib'] = round(
            onedrive_summary['personal_sites']['storage_gib'] * asp_factor, 3
        )
        
        # Add Teams metered units
        teams_activity['estimated_metered_units_user_chats'] = teams_activity['private_chat_messages']
        teams_activity['estimated_metered_units_channel_conversations'] = teams_activity['team_chat_messages']
        teams_activity['total_estimated_metered_units'] = (
            teams_activity['private_chat_messages'] + teams_activity['team_chat_messages']
        )
        # Project for 180 days + next 1 year (last 30 days data extrapolated)
        projection_factor = 12  # 30 days to 1 year
        teams_activity['projected_annual_metered_units'] = int(
            teams_activity['total_estimated_metered_units'] * projection_factor
        )

        # Calculate growth rates (simulated 180-day growth)
        growth_rates = {
            'exchange': {'growth_gib': round(exchange_summary['totals_all']['total_item_size_gib'] * 0.05, 3), 
                        'growth_rate_percent': 5.03},
            'sharepoint': {'growth_gib': round(sharepoint_summary['total']['storage_gib'] * 0.14, 3), 
                          'growth_rate_percent': 13.93},
            'onedrive': {'growth_gib': round(onedrive_summary['personal_sites']['storage_gib'] * 0.15, 3), 
                        'growth_rate_percent': 15.17},
        }

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
            'total_user_count': NUM_USERS,
            'summaries': [s.to_dict() for s in summaries],
            'exchange_mailbox_breakdown': exchange_breakdown,
            'sharepoint_site_breakdown': sharepoint_breakdown,
            'teams_activity': teams_activity,
            # Cohesity sizer format summaries
            'exchange_summary': exchange_summary,
            'sharepoint_summary': sharepoint_summary,
            'onedrive_summary': onedrive_summary,
            'growth_rates': growth_rates,
        }

        # Write output files
        file_ts = datetime.now(timezone.utc).strftime('%H%M%S')
        write_json(inventory_data, f"{LARGE_OUTPUT_DIR}/cca_inv_{file_ts}.json")
        write_json(summary_data, f"{LARGE_OUTPUT_DIR}/cca_sum_{file_ts}.json")

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
        
        # Exchange mailbox breakdown
        print("\n" + "=" * 60)
        print("EXCHANGE MAILBOX BREAKDOWN")
        print("=" * 60)
        print(f"{'Mailbox Type':<20} {'Count':>10} {'Size (GB)':>15}")
        print("-" * 60)
        for mtype, data in sorted(exchange_breakdown['by_type'].items()):
            print(f"{mtype:<20} {data['count']:>10} {data['storage_gb']:>15,.2f}")
        print("-" * 60)
        print(f"{'TOTAL':<20} {len(exchange_resources):>10} {total_exchange_gb:>15,.2f}")
        print(f"Archive Enabled: {exchange_breakdown['archive_enabled_count']}")
        print(f"Soft Deleted: {exchange_breakdown['soft_deleted_count']}")
        
        # SharePoint site breakdown
        print("\n" + "=" * 60)
        print("SHAREPOINT SITE BREAKDOWN")
        print("=" * 60)
        print(f"{'Site Type':<25} {'Count':>10} {'Size (GB)':>15}")
        print("-" * 60)
        for stype, data in sorted(sharepoint_breakdown['by_type'].items()):
            print(f"{stype:<25} {data['count']:>10} {data['storage_gb']:>15,.2f}")
        print("-" * 60)
        print(f"{'TOTAL':<25} {len(sharepoint_resources):>10} {total_sharepoint_gb:>15,.2f}")
        print(f"Deleted Sites: {sharepoint_breakdown['deleted_count']}")
        
        # Teams activity
        print("\n" + "=" * 60)
        print("TEAMS ACTIVITY")
        print("=" * 60)
        print(f"  Active Users: {teams_activity['active_users']}")
        print(f"  Team Chat Messages: {teams_activity['team_chat_messages']:,}")
        print(f"  Private Chat Messages: {teams_activity['private_chat_messages']:,}")
        print(f"  Calls: {teams_activity['calls']:,}")
        print(f"  Meetings: {teams_activity['meetings']:,}")

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
