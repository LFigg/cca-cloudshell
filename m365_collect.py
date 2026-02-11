#!/usr/bin/env python3
"""
CCA CloudShell - Microsoft 365 Collector
Standalone collector for M365 resources using Microsoft Graph API.

Requirements:
- Azure AD App Registration with following API permissions (Application type):
  - Sites.Read.All (SharePoint)
  - User.Read.All (Users, OneDrive, Exchange)
  - Group.Read.All (Groups, Teams)
  - TeamSettings.Read.All (Teams details)
  
Usage:
    # Set environment variables
    export MS365_TENANT_ID="your-tenant-id"
    export MS365_CLIENT_ID="your-client-id"
    export MS365_CLIENT_SECRET="your-client-secret"
    
    # Run collector
    python m365_collect.py
    
    # Or pass credentials as arguments
    python m365_collect.py --tenant-id xxx --client-id xxx --client-secret xxx
    
    # Include Entra ID collection
    python m365_collect.py --include-entra
"""

import os
import sys
import json
import logging
import argparse
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime

# Check for required packages
try:
    from msgraph.graph_service_client import GraphServiceClient
    from azure.identity import ClientSecretCredential
except ImportError:
    print("Required packages not found. Installing...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", 
                          "msgraph-sdk", "azure-identity"])
    from msgraph.graph_service_client import GraphServiceClient
    from azure.identity import ClientSecretCredential

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class CloudResource:
    """Represents a cloud resource for assessment."""
    provider: str
    subscription_id: str
    region: str
    resource_type: str
    service_family: str
    resource_id: str
    name: str
    tags: Dict[str, str] = field(default_factory=dict)
    size_gb: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Graph Client
# =============================================================================

def get_graph_client(tenant_id: str, client_id: str, client_secret: str) -> GraphServiceClient:
    """Create Microsoft Graph API client."""
    credential = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret
    )
    scopes = ['https://graph.microsoft.com/.default']
    return GraphServiceClient(credentials=credential, scopes=scopes)


# =============================================================================
# SharePoint Collector
# =============================================================================

def collect_sharepoint_sites(graph_client: GraphServiceClient, tenant_id: str) -> List[CloudResource]:
    """Collect SharePoint sites."""
    resources = []
    
    try:
        logger.info("Collecting SharePoint sites...")
        sites_response = graph_client.sites.get()
        
        if sites_response and sites_response.value:
            for site in sites_response.value:
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
        
        if users_response and users_response.value:
            for user in users_response.value:
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
        logger.error(f"Failed to collect OneDrive accounts: {e}")
    
    return resources


# =============================================================================
# Exchange Collector
# =============================================================================

def collect_exchange_mailboxes(graph_client: GraphServiceClient, tenant_id: str) -> List[CloudResource]:
    """Collect Exchange Online mailboxes."""
    resources = []
    
    try:
        logger.info("Collecting Exchange mailboxes...")
        users_response = graph_client.users.get()
        
        if users_response and users_response.value:
            for user in users_response.value:
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
                        size_gb=0.0,  # Requires additional API permissions
                        metadata={
                            'user_id': user.id,
                            'user_principal_name': user.user_principal_name,
                            'display_name': user.display_name,
                            'mail': user.mail,
                            'mailbox_type': 'UserMailbox',
                            'account_enabled': user.account_enabled if hasattr(user, 'account_enabled') else True,
                            'created_datetime': str(user.created_date_time) if hasattr(user, 'created_date_time') and user.created_date_time else None
                        }
                    )
                    resources.append(resource)
                except Exception as e:
                    logger.debug(f"Failed to process mailbox for user {user.id}: {e}")
                    continue
        
        logger.info(f"Collected {len(resources)} Exchange mailboxes")
        
    except Exception as e:
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
        
        if groups_response and groups_response.value:
            for group in groups_response.value:
                try:
                    if not hasattr(group, 'resource_provisioning_options') or \
                       'Team' not in (group.resource_provisioning_options or []):
                        continue
                    
                    # Get team details
                    try:
                        team = graph_client.teams.by_team_id(group.id).get()
                    except:
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
        logger.error(f"Failed to collect Teams: {e}")
    
    return resources


# =============================================================================
# Entra ID Collectors
# =============================================================================

def collect_entra_users(graph_client: GraphServiceClient, tenant_id: str) -> List[CloudResource]:
    """Collect Entra ID (Azure AD) users."""
    resources = []
    
    try:
        logger.info("Collecting Entra ID users...")
        users_response = graph_client.users.get()
        
        if users_response and users_response.value:
            for user in users_response.value:
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
        logger.error(f"Failed to collect Entra ID users: {e}")
    
    return resources


def collect_entra_groups(graph_client: GraphServiceClient, tenant_id: str) -> List[CloudResource]:
    """Collect Entra ID (Azure AD) groups."""
    resources = []
    
    try:
        logger.info("Collecting Entra ID groups...")
        groups_response = graph_client.groups.get()
        
        if groups_response and groups_response.value:
            for group in groups_response.value:
                try:
                    member_count = 0
                    try:
                        members = graph_client.groups.by_group_id(group.id).members.get()
                        member_count = len(members.value) if members and members.value else 0
                    except:
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
        logger.error(f"Failed to collect Entra ID groups: {e}")
    
    return resources


# =============================================================================
# Output Utilities
# =============================================================================

def write_json(data: Any, filename: str, output_dir: str) -> str:
    """Write data to JSON file."""
    filepath = os.path.join(output_dir, filename)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    return filepath


def aggregate_sizing(resources: List[CloudResource]) -> Dict[str, Any]:
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


def print_summary_table(resources: List[CloudResource]):
    """Print summary table to console."""
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
    # Using environment variables
    export MS365_TENANT_ID="your-tenant-id"
    export MS365_CLIENT_ID="your-client-id"
    export MS365_CLIENT_SECRET="your-client-secret"
    python m365_collect.py
    
    # Using command-line arguments
    python m365_collect.py --tenant-id xxx --client-id xxx --client-secret xxx
    
    # Include Entra ID collection
    python m365_collect.py --include-entra
    
Required Azure AD App Permissions (Application type):
    - Sites.Read.All (SharePoint sites)
    - User.Read.All (Users, OneDrive, Exchange)
    - Group.Read.All (Groups, Teams)
    - TeamSettings.Read.All (Teams details)
        """
    )
    
    parser.add_argument('--tenant-id', 
                        default=os.environ.get('MS365_TENANT_ID'),
                        help='Azure AD tenant ID (or set MS365_TENANT_ID env var)')
    parser.add_argument('--client-id',
                        default=os.environ.get('MS365_CLIENT_ID'),
                        help='Azure AD application (client) ID (or set MS365_CLIENT_ID env var)')
    parser.add_argument('--client-secret',
                        default=os.environ.get('MS365_CLIENT_SECRET'),
                        help='Azure AD client secret (or set MS365_CLIENT_SECRET env var)')
    parser.add_argument('--output-dir', '-o',
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
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate credentials
    if not args.tenant_id or not args.client_id or not args.client_secret:
        print("ERROR: Missing credentials. Please provide:")
        print("  --tenant-id or MS365_TENANT_ID environment variable")
        print("  --client-id or MS365_CLIENT_ID environment variable")
        print("  --client-secret or MS365_CLIENT_SECRET environment variable")
        print("\nRun with --help for more information.")
        sys.exit(1)
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    print("="*70)
    print("CCA CloudShell - Microsoft 365 Collector")
    print("="*70)
    print(f"Tenant ID: {args.tenant_id[:8]}...{args.tenant_id[-4:]}")
    print(f"Output Directory: {args.output_dir}")
    print("="*70 + "\n")
    
    # Initialize Graph client
    try:
        logger.info("Initializing Microsoft Graph client...")
        graph_client = get_graph_client(
            args.tenant_id,
            args.client_id,
            args.client_secret
        )
    except Exception as e:
        print(f"ERROR: Failed to initialize Graph client: {e}")
        sys.exit(1)
    
    # Collect resources
    all_resources: List[CloudResource] = []
    
    if not args.skip_sharepoint:
        all_resources.extend(collect_sharepoint_sites(graph_client, args.tenant_id))
    
    if not args.skip_onedrive:
        all_resources.extend(collect_onedrive_accounts(graph_client, args.tenant_id))
    
    if not args.skip_exchange:
        all_resources.extend(collect_exchange_mailboxes(graph_client, args.tenant_id))
    
    if not args.skip_teams:
        all_resources.extend(collect_teams(graph_client, args.tenant_id))
    
    if args.include_entra:
        all_resources.extend(collect_entra_users(graph_client, args.tenant_id))
        all_resources.extend(collect_entra_groups(graph_client, args.tenant_id))
    
    # Print summary
    print_summary_table(all_resources)
    
    if not all_resources:
        print("No resources collected. Check permissions and tenant configuration.")
        return
    
    # Generate outputs
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Raw inventory
    inventory = [asdict(r) for r in all_resources]
    # Use HHMMSS format for timestamp in filenames
    file_ts = datetime.now().strftime('%H%M%S')
    inventory_file = write_json(inventory, f'cca_m365_inv_{file_ts}.json', args.output_dir)
    print(f"Inventory saved: {inventory_file}")
    
    # Sizing summary
    sizing = aggregate_sizing(all_resources)
    sizing['tenant_id'] = args.tenant_id
    sizing['collection_timestamp'] = timestamp
    sizing_file = write_json(sizing, f'cca_m365_sum_{file_ts}.json', args.output_dir)
    print(f"Sizing summary saved: {sizing_file}")
    
    # Executive summary
    exec_summary = {
        'collection_timestamp': timestamp,
        'tenant_id': args.tenant_id,
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
    exec_file = write_json(exec_summary, f'executive_summary_{timestamp}.json', args.output_dir)
    print(f"Executive summary saved: {exec_file}")
    
    print("\n" + "="*70)
    print("Collection complete!")
    print(f"Total resources: {len(all_resources)}")
    print(f"Total storage: {sizing['total_storage_gb']:.2f} GB")
    print(f"Output files in: {args.output_dir}")
    print("="*70)


if __name__ == '__main__':
    main()
