#!/usr/bin/env python3
"""
CCA CloudShell - Unified Cloud Collector

Simple entry point for collecting cloud resources.
Auto-detects available cloud credentials and runs appropriate collectors.

Usage:
    # Auto-detect mode (recommended)
    python collect.py

    # Direct cloud selection
    python collect.py --cloud aws
    python collect.py --cloud azure
    python collect.py --cloud gcp
    python collect.py --cloud m365

    # Interactive setup wizard
    python collect.py --setup

    # Skip permission check (if you know credentials are valid)
    python collect.py --cloud aws --skip-check

    # Pass additional arguments to the collector
    python collect.py --cloud aws -- --org-role CCARole --regions us-east-1
"""
import argparse
import importlib.util
import os
import sys
from typing import Any, Dict, List, Optional, Tuple


# ANSI colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def color(text: str, c: str) -> str:
    """Apply color if terminal supports it."""
    if sys.stdout.isatty():
        return f"{c}{text}{Colors.END}"
    return text


def print_banner():
    """Print welcome banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                   CCA CloudShell Collector                     ║
║           Cloud Resource Assessment & Protection Audit         ║
╚═══════════════════════════════════════════════════════════════╝
"""
    print(color(banner, Colors.CYAN))


def print_cloud_menu():
    """Print cloud selection menu."""
    print(color("\nSelect a cloud platform to collect from:\n", Colors.BOLD))
    print(f"  {color('1', Colors.GREEN)}) AWS       - Amazon Web Services")
    print(f"  {color('2', Colors.GREEN)}) Azure     - Microsoft Azure")
    print(f"  {color('3', Colors.GREEN)}) GCP       - Google Cloud Platform")
    print(f"  {color('4', Colors.GREEN)}) M365      - Microsoft 365 (SharePoint, OneDrive, Teams)")
    print()
    print(color("  Large Organizations:", Colors.BOLD))
    print(f"  {color('5', Colors.GREEN)}) AWS Org   - AWS Organization (parallel + SSO refresh)")
    print()
    print(f"  {color('q', Colors.RED)}) Quit")
    print()


def prompt_aws_org_options() -> Optional[Dict[str, Any]]:
    """Prompt for AWS Organization collection options."""
    print(color("\n=== AWS Organization Collection Setup ===\n", Colors.BOLD))

    # Get org role name
    print("Enter the IAM role name deployed to member accounts.")
    print("(This role should have CCA read permissions and trust the management account)")
    print()
    try:
        org_role = input(color("Role name [CCARole]: ", Colors.CYAN)).strip()
        if not org_role:
            org_role = "CCARole"

        # External ID (security best practice)
        print()
        print("External ID adds security to cross-account role assumption.")
        print("Leave blank if your roles don't require an external ID.")
        print()
        external_id = input(color("External ID (or Enter to skip): ", Colors.CYAN)).strip()

        # Regions filter
        print()
        print("By default, all enabled regions are collected.")
        print("Specify regions to limit scope (e.g., us-east-1,us-west-2).")
        print()
        regions = input(color("Regions to collect (Enter for all): ", Colors.CYAN)).strip()

        # Parallel accounts
        print()
        print("Parallel workers speed up collection by running multiple accounts simultaneously.")
        print("Auto-tunes to 4 for 50+ accounts, 8 for 100+ accounts if not specified.")
        print()
        parallel_input = input(color("Parallel account workers (Enter for auto, or 1-16) [auto]: ", Colors.CYAN)).strip()
        parallel_accounts = None
        if parallel_input:
            try:
                parallel_accounts = int(parallel_input)
                if parallel_accounts < 1 or parallel_accounts > 16:
                    print(color("Invalid value, using auto-tune", Colors.YELLOW))
                    parallel_accounts = None
            except ValueError:
                print(color("Invalid value, using auto-tune", Colors.YELLOW))

        # Parallel regions
        print()
        print("Parallel region collection speeds up each account (4-8 recommended).")
        print()
        parallel_regions_input = input(color("Parallel regions (Enter for default 4, or 1-16): ", Colors.CYAN)).strip()
        parallel_regions = None
        if parallel_regions_input:
            try:
                parallel_regions = int(parallel_regions_input)
                if parallel_regions < 1 or parallel_regions > 16:
                    print(color("Invalid value, using default", Colors.YELLOW))
                    parallel_regions = None
            except ValueError:
                print(color("Invalid value, using default", Colors.YELLOW))

        # SSO refresh
        print()
        print("SSO credentials typically expire after 1 hour.")
        print("Enable auto-refresh to keep credentials valid during long collections.")
        print()
        sso_input = input(color("Enable SSO auto-refresh? [Y/n]: ", Colors.CYAN)).strip().lower()
        sso_refresh = sso_input != 'n'

        # Change rate collection
        print()
        print("Change rate data helps the sizing tool estimate backup requirements.")
        print("Queries CloudWatch metrics (adds ~30s per account).")
        print()
        change_rate_input = input(color("Collect data change rates? [Y/n]: ", Colors.CYAN)).strip().lower()
        include_change_rate = change_rate_input != 'n'

        # Include resource IDs
        print()
        print("Resource IDs/ARNs are redacted by default for privacy.")
        print("Include them for compliance or detailed inventory needs.")
        print()
        resource_ids_input = input(color("Include full resource IDs? [y/N]: ", Colors.CYAN)).strip().lower()
        include_resource_ids = resource_ids_input in ('y', 'yes')

        # Output directory
        print()
        output = input(color("Output directory [./output]: ", Colors.CYAN)).strip()
        if not output:
            output = "./output"

        # Cost collection (default ON — opt out)
        print()
        print("Data protection cost collection is enabled by default.")
        print("It analyzes AWS Backup, EBS snapshot, and Cost Explorer data.")
        print()
        cost_input = input(color("Skip cost collection? [y/N]: ", Colors.CYAN)).strip().lower()
        no_costs = cost_input in ('y', 'yes')

        return {
            'org_role': org_role,
            'external_id': external_id if external_id else None,
            'regions': regions if regions else None,
            'parallel_accounts': parallel_accounts,
            'parallel_regions': parallel_regions,
            'sso_refresh': sso_refresh,
            'include_change_rate': include_change_rate,
            'include_resource_ids': include_resource_ids,
            'output': output,
            'no_costs': no_costs,
        }
    except (KeyboardInterrupt, EOFError):
        print()
        return None


def prompt_aws_options() -> Optional[Dict[str, Any]]:
    """Prompt for AWS collection options."""
    print(color("\n=== AWS Collection Options ===\n", Colors.BOLD))

    try:
        # Regions filter
        print("By default, all enabled regions are collected.")
        print("Specify regions to limit scope (e.g., us-east-1,us-west-2).")
        print()
        regions = input(color("Regions to collect (Enter for all): ", Colors.CYAN)).strip()

        # Change rate collection
        print()
        print("Change rate data helps the sizing tool estimate backup requirements.")
        print("Queries CloudWatch metrics (adds collection time).")
        print()
        change_rate_input = input(color("Collect data change rates? [Y/n]: ", Colors.CYAN)).strip().lower()
        include_change_rate = change_rate_input != 'n'

        # Include resource IDs
        print()
        print("Resource IDs/ARNs are redacted by default for privacy.")
        print("Include them for compliance or detailed inventory needs.")
        print()
        resource_ids_input = input(color("Include full resource IDs? [y/N]: ", Colors.CYAN)).strip().lower()
        include_resource_ids = resource_ids_input in ('y', 'yes')

        # Output directory
        print()
        output = input(color("Output directory [./output]: ", Colors.CYAN)).strip()
        if not output:
            output = "./output"

        # Cost collection (default ON — opt out)
        print()
        print("Data protection cost collection is enabled by default.")
        print()
        cost_input = input(color("Skip cost collection? [y/N]: ", Colors.CYAN)).strip().lower()
        no_costs = cost_input in ('y', 'yes')

        return {
            'regions': regions if regions else None,
            'include_change_rate': include_change_rate,
            'include_resource_ids': include_resource_ids,
            'output': output,
            'no_costs': no_costs,
        }
    except (KeyboardInterrupt, EOFError):
        print()
        return None


def prompt_azure_options() -> Optional[Dict[str, Any]]:
    """Prompt for Azure collection options."""
    print(color("\n=== Azure Collection Options ===\n", Colors.BOLD))

    try:
        # Subscription filter
        print("By default, all accessible subscriptions are collected.")
        print("Specify a subscription ID to limit scope.")
        print()
        subscription_id = input(color("Subscription ID (Enter for all): ", Colors.CYAN)).strip()

        # Regions filter
        print()
        print("By default, all regions are collected.")
        print("Specify regions to limit scope (e.g., eastus,westus2).")
        print()
        regions = input(color("Regions to collect (Enter for all): ", Colors.CYAN)).strip()

        # Change rate collection
        print()
        print("Change rate data helps the sizing tool estimate backup requirements.")
        print("Queries Azure Monitor metrics (adds collection time).")
        print()
        change_rate_input = input(color("Collect data change rates? [Y/n]: ", Colors.CYAN)).strip().lower()
        include_change_rate = change_rate_input != 'n'

        # Include resource IDs
        print()
        print("Resource IDs are redacted by default for privacy.")
        print("Include them for compliance or detailed inventory needs.")
        print()
        resource_ids_input = input(color("Include full resource IDs? [y/N]: ", Colors.CYAN)).strip().lower()
        include_resource_ids = resource_ids_input in ('y', 'yes')

        # Output directory
        print()
        output = input(color("Output directory [./output]: ", Colors.CYAN)).strip()
        if not output:
            output = "./output"

        # Cost collection (default ON — opt out)
        print()
        print("Data protection cost collection is enabled by default.")
        print()
        cost_input = input(color("Skip cost collection? [y/N]: ", Colors.CYAN)).strip().lower()
        no_costs = cost_input in ('y', 'yes')

        return {
            'subscription_id': subscription_id if subscription_id else None,
            'regions': regions if regions else None,
            'include_change_rate': include_change_rate,
            'include_resource_ids': include_resource_ids,
            'output': output,
            'no_costs': no_costs,
        }
    except (KeyboardInterrupt, EOFError):
        print()
        return None


def prompt_gcp_options() -> Optional[Dict[str, Any]]:
    """Prompt for GCP collection options."""
    print(color("\n=== GCP Collection Options ===\n", Colors.BOLD))

    try:
        # Project scope
        print("By default, collects from the current project only.")
        print("Choose 'all' to collect from all accessible projects.")
        print()
        project_input = input(color("Project scope - specific ID, 'all', or Enter for current: ", Colors.CYAN)).strip().lower()
        all_projects = project_input == 'all'
        project = None if (all_projects or not project_input) else project_input

        # Regions filter
        print()
        print("By default, all regions are collected.")
        print("Specify regions to limit scope (e.g., us-central1,us-east1).")
        print()
        regions = input(color("Regions to collect (Enter for all): ", Colors.CYAN)).strip()

        # Change rate collection
        print()
        print("Change rate data helps the sizing tool estimate backup requirements.")
        print("Queries Cloud Monitoring metrics (adds collection time).")
        print()
        change_rate_input = input(color("Collect data change rates? [Y/n]: ", Colors.CYAN)).strip().lower()
        include_change_rate = change_rate_input != 'n'

        # Include resource IDs
        print()
        print("Resource IDs are redacted by default for privacy.")
        print("Include them for compliance or detailed inventory needs.")
        print()
        resource_ids_input = input(color("Include full resource IDs? [y/N]: ", Colors.CYAN)).strip().lower()
        include_resource_ids = resource_ids_input in ('y', 'yes')

        # Output directory
        print()
        output = input(color("Output directory [./output]: ", Colors.CYAN)).strip()
        if not output:
            output = "./output"

        # Cost collection (GCP requires BigQuery billing export table)
        print()
        print("GCP cost collection requires a BigQuery billing export table.")
        print("Leave blank to skip cost collection.")
        print()
        billing_table = input(color("BigQuery billing table (project.dataset.table, or Enter to skip): ", Colors.CYAN)).strip()

        return {
            'project': project,
            'all_projects': all_projects,
            'regions': regions if regions else None,
            'include_change_rate': include_change_rate,
            'include_resource_ids': include_resource_ids,
            'output': output,
            'billing_table': billing_table if billing_table else None,
        }
    except (KeyboardInterrupt, EOFError):
        print()
        return None


def prompt_m365_options() -> Optional[Dict[str, Any]]:
    """Prompt for M365 collection options."""
    print(color("\n=== Microsoft 365 Collection Options ===\n", Colors.BOLD))

    try:
        # Workload selection
        print("Select which M365 workloads to collect:")
        print("(All are collected by default)")
        print()

        sp_input = input(color("Collect SharePoint sites? [Y/n]: ", Colors.CYAN)).strip().lower()
        skip_sharepoint = sp_input == 'n'

        od_input = input(color("Collect OneDrive accounts? [Y/n]: ", Colors.CYAN)).strip().lower()
        skip_onedrive = od_input == 'n'

        ex_input = input(color("Collect Exchange mailboxes? [Y/n]: ", Colors.CYAN)).strip().lower()
        skip_exchange = ex_input == 'n'

        teams_input = input(color("Collect Teams? [Y/n]: ", Colors.CYAN)).strip().lower()
        skip_teams = teams_input == 'n'

        # Entra ID (Azure AD)
        print()
        print("Entra ID (Azure AD) collection includes users and groups.")
        print("Useful for identity protection assessment.")
        print()
        entra_input = input(color("Include Entra ID users and groups? [y/N]: ", Colors.CYAN)).strip().lower()
        include_entra = entra_input in ('y', 'yes')

        # Output directory
        print()
        output = input(color("Output directory [./output]: ", Colors.CYAN)).strip()
        if not output:
            output = "./output"

        return {
            'skip_sharepoint': skip_sharepoint,
            'skip_onedrive': skip_onedrive,
            'skip_exchange': skip_exchange,
            'skip_teams': skip_teams,
            'include_entra': include_entra,
            'output': output,
        }
    except (KeyboardInterrupt, EOFError):
        print()
        return None


def get_cloud_choice() -> Optional[str]:
    """Get cloud choice from user input."""
    choices = {
        '1': 'aws',
        '2': 'azure',
        '3': 'gcp',
        '4': 'm365',
        '5': 'aws-org',
        'aws': 'aws',
        'azure': 'azure',
        'gcp': 'gcp',
        'm365': 'm365',
        'aws-org': 'aws-org',
    }

    while True:
        try:
            choice = input(color("Enter choice (1-5 or cloud name): ", Colors.CYAN)).strip().lower()
            if choice in ('q', 'quit', 'exit'):
                return None
            if choice in choices:
                return choices[choice]
            print(color("Invalid choice. Please enter 1-5 or a cloud name.", Colors.YELLOW))
        except (KeyboardInterrupt, EOFError):
            print()
            return None


# =============================================================================
# Permission Verification
# =============================================================================

def check_aws_permissions() -> Tuple[bool, str, List[str]]:
    """
    Verify AWS credentials and basic permissions.
    Returns: (success, message, details)
    """
    details = []
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
    except ImportError:
        return False, "boto3 not installed", ["Run: pip install boto3"]

    # Check credentials
    try:
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        account_id = identity['Account']
        arn = identity['Arn']
        details.append(f"Account:  {account_id}")
        details.append(f"Identity: {arn}")
    except NoCredentialsError:
        return False, "No AWS credentials found", [
            "Configure credentials via:",
            "  - AWS CloudShell (recommended)",
            "  - aws configure",
            "  - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)",
            "  - IAM role (EC2 instance profile)"
        ]
    except ClientError as e:
        return False, f"Credential error: {e}", []

    # Check basic read permissions
    try:
        ec2 = boto3.client('ec2')  # type: ignore[call-overload]
        regions = ec2.describe_regions()
        details.append(f"Regions:  {len(regions.get('Regions', []))} enabled")
    except ClientError as e:
        code = e.response.get('Error', {}).get('Code', '')
        if code in ('UnauthorizedOperation', 'AccessDenied'):
            return False, "Missing ec2:DescribeRegions permission", [
                "Add ReadOnlyAccess policy or see docs/PERMISSIONS.md"
            ]
        details.append(f"Region check: {e}")

    # Quick check for S3 access
    try:
        s3 = boto3.client('s3')  # type: ignore[call-overload]
        s3.list_buckets()
        details.append("S3:       ✓ ListBuckets")
    except ClientError as e:
        code = e.response.get('Error', {}).get('Code', '')
        if code in ('AccessDenied',):
            details.append("S3:       ✗ No s3:ListAllMyBuckets")

    # Check for Organizations access (optional)
    try:
        org = boto3.client('organizations')  # type: ignore[call-overload]
        org.describe_organization()
        details.append("Org:      ✓ Organizations access (multi-account ready)")
    except ClientError:
        details.append("Org:      – Single account mode (no Organizations access)")
    except Exception:
        pass

    return True, "AWS credentials verified", details


def check_azure_permissions() -> Tuple[bool, str, List[str]]:
    """
    Verify Azure credentials and basic permissions.
    Returns: (success, message, details)
    """
    details = []
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.subscription import SubscriptionClient
    except ImportError:
        return False, "Azure SDK not installed", [
            "Run: pip install azure-identity azure-mgmt-subscription"
        ]

    try:
        credential = DefaultAzureCredential()
        # Get token to verify credentials work
        credential.get_token("https://management.azure.com/.default")
        details.append("Auth:     DefaultAzureCredential")
    except Exception as e:
        return False, f"Azure authentication failed: {e}", [
            "Configure credentials via:",
            "  - Azure Cloud Shell (recommended)",
            "  - az login",
            "  - Service principal environment variables",
            "  - Managed identity"
        ]

    # List subscriptions
    try:
        sub_client = SubscriptionClient(credential)
        subs = list(sub_client.subscriptions.list())
        if subs:
            details.append(f"Subs:     {len(subs)} accessible")
            for sub in subs[:3]:
                sub_id = sub.subscription_id or 'unknown'
                details.append(f"          - {sub.display_name} ({sub_id[:8]}...)")
            if len(subs) > 3:
                details.append(f"          ... and {len(subs) - 3} more")
        else:
            return False, "No subscriptions accessible", [
                "Ensure your account has Reader access to at least one subscription"
            ]
    except Exception as e:
        return False, f"Failed to list subscriptions: {e}", []

    return True, "Azure credentials verified", details


def check_gcp_permissions() -> Tuple[bool, str, List[str]]:
    """
    Verify GCP credentials and basic permissions.
    Returns: (success, message, details)
    """
    details = []
    try:
        import google.auth
        from google.cloud import resourcemanager_v3
    except ImportError:
        return False, "GCP SDK not installed", [
            "Run: pip install google-auth google-cloud-resource-manager"
        ]

    try:
        credentials, project = google.auth.default()
        if project:
            details.append(f"Project:  {project}")
        else:
            details.append("Project:  (not set, will scan all accessible)")
    except Exception as e:
        return False, f"GCP authentication failed: {e}", [
            "Configure credentials via:",
            "  - Google Cloud Shell (recommended)",
            "  - gcloud auth application-default login",
            "  - Service account key file (GOOGLE_APPLICATION_CREDENTIALS)"
        ]

    # Try to list projects
    try:
        client = resourcemanager_v3.ProjectsClient()
        projects = list(client.search_projects(query=""))
        if projects:
            details.append(f"Projects: {len(projects)} accessible")
            for proj in projects[:3]:
                details.append(f"          - {proj.display_name} ({proj.project_id})")
            if len(projects) > 3:
                details.append(f"          ... and {len(projects) - 3} more")
        else:
            details.append("Projects: None found (may need resourcemanager.projects.get)")
    except Exception as e:
        # If resourcemanager_v3 isn't available, try simpler check
        details.append(f"Projects: Could not list ({e})")

    return True, "GCP credentials verified", details


def check_m365_permissions() -> Tuple[bool, str, List[str]]:
    """
    Verify M365 credentials and basic permissions.

    Prefers App Registration credentials if available.
    Falls back to Azure CLI / DefaultAzureCredential.
    Errors if partial App Registration credentials are set.

    Returns: (success, message, details)
    """
    details = []

    # Check for App Registration environment variables
    tenant_id = os.environ.get('MS365_TENANT_ID')
    client_id = os.environ.get('MS365_CLIENT_ID')
    client_secret = os.environ.get('MS365_CLIENT_SECRET')

    ms365_vars = {
        'MS365_TENANT_ID': tenant_id,
        'MS365_CLIENT_ID': client_id,
        'MS365_CLIENT_SECRET': client_secret
    }
    set_vars = [k for k, v in ms365_vars.items() if v]
    missing_vars = [k for k, v in ms365_vars.items() if not v]

    # Error on partial credentials - user started setup but didn't finish
    if set_vars and missing_vars:
        return False, "Partial App Registration credentials detected", [
            f"You have set: {', '.join(set_vars)}",
            f"But missing:  {', '.join(missing_vars)}",
            "",
            "Please set ALL three environment variables:",
            "  export MS365_TENANT_ID='your-tenant-id'",
            "  export MS365_CLIENT_ID='your-client-id'",
            "  export MS365_CLIENT_SECRET='your-client-secret'",
            "",
            "Or unset all of them to use Azure CLI authentication:",
            "  unset MS365_TENANT_ID MS365_CLIENT_ID MS365_CLIENT_SECRET",
            "  az login"
        ]

    # Try to import required libraries
    try:
        from azure.identity import ClientSecretCredential, DefaultAzureCredential
        from msgraph.graph_service_client import GraphServiceClient  # noqa: F401
    except ImportError:
        return False, "msgraph SDK not installed", [
            "Run: pip install msgraph-sdk azure-identity"
        ]

    # Use App Registration if all credentials are set (preferred)
    if all([tenant_id, client_id, client_secret]):
        details.append("Method:   App Registration (preferred)")
        details.append(f"Tenant:   {tenant_id}")
        details.append(f"Client:   {client_id[:8]}...")

        try:
            credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
            # Try to get a token for Graph API
            token = credential.get_token("https://graph.microsoft.com/.default")
            if token:
                details.append("Auth:     ✓ Token acquired")
                return True, "M365 App Registration verified", details
        except Exception as e:
            return False, f"App Registration authentication failed: {e}", [
                "Check that:",
                "  - Tenant ID, Client ID, and Client Secret are correct",
                "  - The App Registration has the required API permissions",
                "  - Admin consent has been granted for the permissions"
            ]

    # Fall back to DefaultAzureCredential (Azure CLI, Managed Identity, etc.)
    details.append("Method:   Azure CLI / DefaultAzureCredential")
    details.append("          (Set MS365_* env vars to use App Registration instead)")

    try:
        # Skip managed identity on non-Azure machines to avoid timeout
        is_azure = os.environ.get('ACC_TERM_ID') or os.path.exists(os.path.expanduser('~/clouddrive'))
        credential = DefaultAzureCredential(
            exclude_managed_identity_credential=not is_azure
        )
        # Try to get a token for Graph API
        token = credential.get_token("https://graph.microsoft.com/.default")
        if token:
            details.append("Auth:     ✓ Token acquired via Azure CLI")
            details.append("")
            details.append("⚠ Note: For production use, App Registration is recommended.")
            details.append("  See docs/collectors/m365.md for setup instructions.")
            return True, "M365 credentials verified (Azure CLI)", details
    except Exception as e:
        return False, f"Azure CLI authentication failed: {e}", [
            "No valid credentials found. Options:",
            "",
            "Option 1: App Registration (recommended for production)",
            "  export MS365_TENANT_ID='your-tenant-id'",
            "  export MS365_CLIENT_ID='your-client-id'",
            "  export MS365_CLIENT_SECRET='your-client-secret'",
            "",
            "Option 2: Azure CLI (for development/testing)",
            "  az login",
            "",
            "See docs/collectors/m365.md for detailed setup instructions."
        ]

    return False, "No M365 credentials found", details


def check_change_rate_requirements(cloud: str) -> Tuple[bool, str]:
    """
    Check if the required monitoring package is installed for change rate collection.
    Returns: (success, error_message)
    """
    if cloud in ('aws', 'aws-org'):
        # AWS uses boto3 CloudWatch which is part of core boto3 - always available
        return True, ""
    elif cloud == 'azure':
        try:
            from azure.mgmt.monitor import MonitorManagementClient  # noqa: F401
            return True, ""
        except ImportError:
            return False, (
                "Change rate collection requires azure-mgmt-monitor.\n"
                "Install it with: pip install azure-mgmt-monitor\n"
                "Or use --skip-change-rate to skip change rate collection."
            )
    elif cloud == 'gcp':
        try:
            from google.cloud import monitoring_v3  # noqa: F401
            return True, ""
        except ImportError:
            return False, (
                "Change rate collection requires google-cloud-monitoring.\n"
                "Install it with: pip install google-cloud-monitoring\n"
                "Or use --skip-change-rate to skip change rate collection."
            )
    # M365 doesn't have change rate collection
    return True, ""


# =============================================================================
# Cloud Auto-Detection
# =============================================================================

def detect_aws() -> bool:
    """Check if AWS credentials are available."""
    # Check environment variables
    if os.environ.get('AWS_ACCESS_KEY_ID') or os.environ.get('AWS_SESSION_TOKEN'):
        return True
    # Check for CloudShell
    if os.environ.get('AWS_EXECUTION_ENV'):
        return True
    # Check for credentials file
    aws_creds = os.path.expanduser('~/.aws/credentials')
    if os.path.exists(aws_creds):
        return True
    # Check for config file with SSO
    aws_config = os.path.expanduser('~/.aws/config')
    if os.path.exists(aws_config):
        return True
    return False


def detect_azure() -> bool:
    """Check if Azure credentials are available."""
    # Check environment variables
    if os.environ.get('AZURE_CLIENT_ID') or os.environ.get('AZURE_SUBSCRIPTION_ID'):
        return True
    # Check for Cloud Shell
    if os.environ.get('ACC_TERM_ID') or os.path.exists(os.path.expanduser('~/clouddrive')):
        return True
    # Check for Azure CLI logged in
    azure_config = os.path.expanduser('~/.azure/azureProfile.json')
    if os.path.exists(azure_config):
        return True
    return False


def detect_gcp() -> bool:
    """Check if GCP credentials are available."""
    # Check environment variables
    if os.environ.get('GOOGLE_APPLICATION_CREDENTIALS'):
        return True
    if os.environ.get('GOOGLE_CLOUD_PROJECT') or os.environ.get('GCLOUD_PROJECT'):
        return True
    # Check for Cloud Shell
    if os.environ.get('CLOUD_SHELL') == 'true' or os.environ.get('DEVSHELL_GCLOUD_CONFIG'):
        return True
    # Check for gcloud config
    gcloud_config = os.path.expanduser('~/.config/gcloud/credentials.db')
    if os.path.exists(gcloud_config):
        return True
    # Check for application default credentials
    adc = os.path.expanduser('~/.config/gcloud/application_default_credentials.json')
    if os.path.exists(adc):
        return True
    return False


def detect_m365() -> bool:
    """Check if M365 credentials are available.

    Detects both App Registration credentials (preferred) and Azure CLI.
    Returns True if either authentication method is available.
    """
    # Check for App Registration credentials (preferred method)
    tenant_id = os.environ.get('MS365_TENANT_ID')
    client_id = os.environ.get('MS365_CLIENT_ID')
    client_secret = os.environ.get('MS365_CLIENT_SECRET')

    if all([tenant_id, client_id, client_secret]):
        return True

    # Check for Azure CLI / DefaultAzureCredential
    # This includes: Azure CLI login, Managed Identity, env vars
    azure_config = os.path.expanduser('~/.azure/azureProfile.json')
    if os.path.exists(azure_config):
        return True

    # Check for Azure Cloud Shell
    if os.environ.get('ACC_TERM_ID') or os.path.exists(os.path.expanduser('~/clouddrive')):
        return True

    # Check for AZURE_ env vars (service principal)
    if os.environ.get('AZURE_CLIENT_ID') and os.environ.get('AZURE_TENANT_ID'):
        return True

    return False


def auto_detect_clouds() -> List[str]:
    """Detect which clouds have credentials configured."""
    detected = []

    detectors = [
        ('aws', detect_aws),
        ('azure', detect_azure),
        ('gcp', detect_gcp),
        ('m365', detect_m365),
    ]

    for cloud, detector in detectors:
        try:
            if detector():
                detected.append(cloud)
        except Exception:
            pass  # Ignore detection errors

    return detected


def verify_permissions(cloud: str) -> bool:
    """Run permission check for specified cloud."""
    print(color(f"\n{'─'*60}", Colors.CYAN))
    print(color(f"  Checking {cloud.upper()} permissions...", Colors.BOLD))
    print(color(f"{'─'*60}\n", Colors.CYAN))

    checkers = {
        'aws': check_aws_permissions,
        'azure': check_azure_permissions,
        'gcp': check_gcp_permissions,
        'm365': check_m365_permissions,
    }

    checker = checkers.get(cloud)
    if not checker:
        print(color(f"Unknown cloud: {cloud}", Colors.RED))
        return False

    try:
        success, message, details = checker()
    except Exception as e:
        print(color(f"  ✗ Permission check failed: {e}", Colors.RED))
        print(color("\n    This could indicate missing credentials or SDK issues.", Colors.YELLOW))
        return False

    if success:
        print(color(f"  ✓ {message}", Colors.GREEN))
    else:
        print(color(f"  ✗ {message}", Colors.RED))

    if details:
        print()
        for line in details:
            if line.startswith("  "):
                print(color(f"    {line}", Colors.CYAN if success else Colors.YELLOW))
            else:
                print(color(f"    {line}", Colors.CYAN if success else Colors.YELLOW))

    print()
    return success


# =============================================================================
# Collection Execution
# =============================================================================

_COLLECTOR_MODULES = {
    'aws': 'lib.aws.collector',
    'azure': 'lib.azure.collector',
    'gcp': 'lib.gcp.collector',
    'm365': 'lib.m365.collector',
}


def run_collector(cloud: str, extra_args: List[str], no_costs: bool = False) -> int:
    """Run the appropriate collector via direct import.

    Returns 0 on success, non-zero on failure.
    """
    module_name = _COLLECTOR_MODULES.get(cloud)
    if not module_name:
        print(color(f"Unknown cloud: {cloud}", Colors.RED))
        return 1

    # Ensure repo root is on sys.path
    repo_root = os.path.dirname(os.path.abspath(__file__))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)

    print(color(f"\n{'─'*60}", Colors.CYAN))
    print(color(f"  Starting {cloud.upper()} collection...", Colors.BOLD))
    print(color(f"{'─'*60}\n", Colors.CYAN))

    if extra_args:
        display = [a for a in extra_args if 'secret' not in a.lower()]
        print(color(f"  Options: {' '.join(display)}\n", Colors.CYAN))

    try:
        mod = importlib.import_module(module_name)
        parser = mod.build_parser()
        args = parser.parse_args(extra_args)
        if no_costs:
            args.no_costs = True
        mod.run_collection(args)
        return 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 1
    except KeyboardInterrupt:
        print(color("\n\nCollection interrupted by user.", Colors.YELLOW))
        return 130
    except Exception as e:
        print(color(f"\n✗ Collection failed: {e}", Colors.RED))
        return 1


def prompt_continue() -> bool:
    """Ask user if they want to continue with collection."""
    try:
        response = input(color("\nProceed with collection? [Y/n]: ", Colors.CYAN)).strip().lower()
        return response in ('', 'y', 'yes')
    except (KeyboardInterrupt, EOFError):
        print()
        return False


def show_collector_help(cloud: str):
    """Show help for the specific collector."""
    module_name = _COLLECTOR_MODULES.get(cloud)
    if not module_name:
        return

    repo_root = os.path.dirname(os.path.abspath(__file__))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)

    try:
        mod = importlib.import_module(module_name)
        mod.build_parser().print_help()
    except Exception as e:
        print(color(f"Could not load help: {e}", Colors.RED))

    print(color(f"\n{'─'*60}", Colors.CYAN))
    print(color("  Tip: Pass options directly after --cloud", Colors.BOLD))
    print(color(f"{'─'*60}\n", Colors.CYAN))
    print(color(f"  python collect.py --cloud {cloud} [options]\n", Colors.CYAN))


# =============================================================================
# Setup Wizard
# =============================================================================

def run_setup_wizard():
    """Interactive setup wizard to configure credentials and test permissions."""
    print(color("\n" + "="*60, Colors.CYAN))
    print(color("  CCA CloudShell - Setup Wizard", Colors.BOLD))
    print(color("="*60 + "\n", Colors.CYAN))

    print("This wizard will help you configure cloud credentials and verify permissions.\n")

    # Detect what's already configured
    detected = auto_detect_clouds()

    if detected:
        print(color(f"✓ Detected credentials for: {', '.join(c.upper() for c in detected)}\n", Colors.GREEN))
    else:
        print(color("No cloud credentials detected.\n", Colors.YELLOW))

    # Ask which clouds to set up
    print(color("Which clouds do you want to collect from?\n", Colors.BOLD))
    print(f"  {color('1', Colors.GREEN)}) AWS       {'✓ credentials found' if 'aws' in detected else ''}")
    print(f"  {color('2', Colors.GREEN)}) Azure     {'✓ credentials found' if 'azure' in detected else ''}")
    print(f"  {color('3', Colors.GREEN)}) GCP       {'✓ credentials found' if 'gcp' in detected else ''}")
    print(f"  {color('4', Colors.GREEN)}) M365      {'✓ credentials found' if 'm365' in detected else ''}")
    print(f"  {color('a', Colors.GREEN)}) All detected ({', '.join(detected) if detected else 'none'})")
    print()

    try:
        choice = input(color("Enter choice(s) (e.g., 1,2 or 'a' for all detected): ", Colors.CYAN)).strip().lower()
    except (KeyboardInterrupt, EOFError):
        print(color("\n\nSetup cancelled.", Colors.YELLOW))
        return

    if choice in ('q', 'quit', 'exit'):
        print(color("\nSetup cancelled.", Colors.YELLOW))
        return

    selected = []
    if choice == 'a':
        selected = detected.copy()
    else:
        choice_map = {'1': 'aws', '2': 'azure', '3': 'gcp', '4': 'm365',
                      'aws': 'aws', 'azure': 'azure', 'gcp': 'gcp', 'm365': 'm365'}
        for c in choice.replace(',', ' ').split():
            if c.strip() in choice_map:
                selected.append(choice_map[c.strip()])

    if not selected:
        print(color("\nNo clouds selected. Exiting setup.", Colors.YELLOW))
        return

    print(color(f"\nSelected: {', '.join(c.upper() for c in selected)}\n", Colors.CYAN))

    # Test each selected cloud
    ready_clouds = []

    for cloud in selected:
        success = verify_permissions(cloud)
        if success:
            ready_clouds.append(cloud)
        else:
            print(color(f"\n  Setup instructions for {cloud.upper()}:\n", Colors.YELLOW))
            _show_setup_instructions(cloud)

    # Summary
    print(color("\n" + "="*60, Colors.CYAN))
    print(color("  Setup Summary", Colors.BOLD))
    print(color("="*60 + "\n", Colors.CYAN))

    if ready_clouds:
        print(color(f"✓ Ready to collect: {', '.join(c.upper() for c in ready_clouds)}", Colors.GREEN))

    failed = [c for c in selected if c not in ready_clouds]
    if failed:
        print(color(f"✗ Need configuration: {', '.join(c.upper() for c in failed)}", Colors.RED))

    if ready_clouds:
        print()
        try:
            response = input(color(f"Run collection for {', '.join(c.upper() for c in ready_clouds)} now? [Y/n]: ", Colors.CYAN)).strip().lower()
            if response in ('', 'y', 'yes'):
                for cloud in ready_clouds:
                    # Check change rate requirements (no --skip-change-rate in quick run)
                    cr_ok, cr_err = check_change_rate_requirements(cloud)
                    if not cr_ok:
                        print(color(f"\n{cr_err}", Colors.RED))
                        continue
                    run_collector(cloud, [])
        except (KeyboardInterrupt, EOFError):
            print(color("\n\nCollection skipped.", Colors.YELLOW))


def _show_setup_instructions(cloud: str):
    """Show setup instructions for a specific cloud."""
    instructions = {
        'aws': [
            "Option 1: Use AWS CloudShell (recommended)",
            "  - Open AWS Console → CloudShell (top-right icon)",
            "  - Clone this repo and run collect.py",
            "",
            "Option 2: Configure AWS CLI",
            "  - Run: aws configure",
            "  - Or set: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY",
            "",
            "For organization access, see: docs/collectors/aws.md"
        ],
        'azure': [
            "Option 1: Use Azure Cloud Shell (recommended)",
            "  - Open Azure Portal → Cloud Shell (top-right icon)",
            "  - Clone this repo and run collect.py",
            "",
            "Option 2: Configure Azure CLI",
            "  - Run: az login",
            "",
            "See: docs/collectors/azure.md"
        ],
        'gcp': [
            "Option 1: Use Google Cloud Shell (recommended)",
            "  - Open Google Cloud Console → Cloud Shell (top-right icon)",
            "  - Clone this repo and run collect.py",
            "",
            "Option 2: Configure gcloud CLI",
            "  - Run: gcloud auth application-default login",
            "",
            "See: docs/collectors/gcp.md"
        ],
        'm365': [
            "M365 requires an Azure AD App Registration with Graph API permissions.",
            "",
            "Set these environment variables:",
            "  export MS365_TENANT_ID='your-tenant-id'",
            "  export MS365_CLIENT_ID='your-client-id'",
            "  export MS365_CLIENT_SECRET='your-secret'",
            "",
            "See: docs/collectors/m365.md"
        ]
    }

    for line in instructions.get(cloud, ["See docs/ for setup instructions."]):
        print(f"    {line}")


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="CCA CloudShell - Unified Cloud Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python collect.py                          # Auto-detect and collect
  python collect.py --cloud aws              # Collect from AWS only
  python collect.py --setup                  # Interactive setup wizard
  python collect.py --cloud azure --skip-check   # Skip permission check
  python collect.py --cloud aws -- --org-role CCARole  # Pass args to collector
"""
    )

    parser.add_argument(
        '--cloud', '-c',
        choices=['aws', 'azure', 'gcp', 'm365'],
        help='Cloud platform to collect from'
    )
    parser.add_argument(
        '--setup',
        action='store_true',
        help='Run interactive setup wizard'
    )
    parser.add_argument(
        '--config',
        metavar='FILE',
        help='Path to YAML config file'
    )
    parser.add_argument(
        '--generate-config',
        action='store_true',
        help='Generate a sample config file and exit'
    )
    parser.add_argument(
        '--skip-check', '-s',
        action='store_true',
        help='Skip permission verification'
    )
    parser.add_argument(
        '--help-collector', '-H',
        action='store_true',
        help='Show help for the specific cloud collector'
    )
    parser.add_argument(
        '--no-costs',
        action='store_true',
        help='Skip data protection cost collection (costs are collected by default)'
    )

    # Parse known args, rest goes to collector
    args, extra_args = parser.parse_known_args()

    # Remove '--' separator if present
    if extra_args and extra_args[0] == '--':
        extra_args = extra_args[1:]

    # Handle --generate-config
    if args.generate_config:
        # Import here to avoid circular imports
        sys.path.insert(0, '.')
        from lib.config import generate_sample_config
        print(generate_sample_config())
        sys.exit(0)

    # Handle --setup
    if args.setup:
        print_banner()
        run_setup_wizard()
        sys.exit(0)

    # Pass --config to collector if specified
    if args.config:
        extra_args = ['--config', args.config] + extra_args

    # Show collector help if requested
    if args.help_collector:
        if not args.cloud:
            print(color("Error: --help-collector requires --cloud", Colors.RED))
            sys.exit(1)
        show_collector_help(args.cloud)
        sys.exit(0)

    print_banner()

    # Auto-detect or use specified cloud
    if args.cloud:
        cloud = args.cloud
    else:
        # Auto-detect available clouds
        print(color("Detecting cloud credentials...\n", Colors.CYAN))
        detected = auto_detect_clouds()

        if not detected:
            print(color("No cloud credentials auto-detected.\n", Colors.YELLOW))
            print("Select an option:\n")
            print_cloud_menu()
            cloud = get_cloud_choice()

            if cloud is None:
                print(color("\nExiting.", Colors.CYAN))
                sys.exit(0)

            # Handle AWS Organization collection
            if cloud == 'aws-org':
                aws_org_opts = prompt_aws_org_options()
                if aws_org_opts is None:
                    print(color("\nExiting.", Colors.CYAN))
                    sys.exit(0)

                # Build extra args for AWS collector with org options
                extra_args = ['--org-role', aws_org_opts['org_role']]
                if aws_org_opts.get('external_id'):
                    extra_args.extend(['--external-id', aws_org_opts['external_id']])
                if aws_org_opts.get('regions'):
                    extra_args.extend(['--regions', aws_org_opts['regions']])
                if aws_org_opts.get('sso_refresh'):
                    extra_args.append('--sso-refresh')
                if aws_org_opts.get('parallel_accounts'):
                    extra_args.extend(['--parallel-accounts', str(aws_org_opts['parallel_accounts'])])
                if aws_org_opts.get('parallel_regions'):
                    extra_args.extend(['--parallel-regions', str(aws_org_opts['parallel_regions'])])
                if not aws_org_opts.get('include_change_rate', True):
                    extra_args.append('--skip-change-rate')
                if aws_org_opts.get('include_resource_ids'):
                    extra_args.append('--include-resource-ids')
                extra_args.extend(['-o', aws_org_opts['output']])

                # Check change rate requirements before starting
                if '--skip-change-rate' not in extra_args:
                    cr_ok, cr_err = check_change_rate_requirements('aws')
                    if not cr_ok:
                        print(color(f"\n{cr_err}", Colors.RED))
                        sys.exit(1)

                no_costs = aws_org_opts.get('no_costs', False) or args.no_costs
                print(color("\nStarting AWS Organization collection...\n", Colors.CYAN))
                exit_code = run_collector('aws', extra_args, no_costs=no_costs)

                if exit_code == 0:
                    print(color("\n✓ AWS Organization collection completed successfully!\n", Colors.GREEN))
                else:
                    print(color(f"\n✗ Collection exited with code {exit_code}\n", Colors.RED))

                sys.exit(exit_code)

            # For single-cloud selection, show setup instructions
            print(color(f"\n{cloud.upper()} selected but credentials not auto-detected.\n", Colors.YELLOW))
            print("Configure credentials first:")
            _show_setup_instructions(cloud)
            print()
            sys.exit(1)

        print(color(f"✓ Found credentials for: {', '.join(c.upper() for c in detected)}\n", Colors.GREEN))

        if len(detected) == 1:
            # Only one cloud detected - use it automatically
            cloud = detected[0]
            print(color(f"Auto-selecting {cloud.upper()}\n", Colors.CYAN))
        else:
            # Multiple clouds detected - let user choose
            print(color("Multiple clouds detected. Select one:\n", Colors.BOLD))
            for i, c in enumerate(detected, 1):
                print(f"  {color(str(i), Colors.GREEN)}) {c.upper()}")
            print(f"  {color('a', Colors.GREEN)}) All (run each sequentially)")
            print()

            try:
                choice = input(color("Enter choice: ", Colors.CYAN)).strip().lower()
            except (KeyboardInterrupt, EOFError):
                print(color("\n\nExiting.", Colors.CYAN))
                sys.exit(0)

            if choice == 'a':
                # Run all detected clouds (costs enabled by default, off via --no-costs)
                all_exit_codes = []
                for c in detected:
                    if not args.skip_check:
                        if not verify_permissions(c):
                            print(color(f"Skipping {c.upper()} due to permission issues.\n", Colors.YELLOW))
                            continue
                    # Check change rate requirements
                    if '--skip-change-rate' not in extra_args:
                        cr_ok, cr_err = check_change_rate_requirements(c)
                        if not cr_ok:
                            print(color(f"\nSkipping {c.upper()}: {cr_err}", Colors.YELLOW))
                            continue
                    exit_code = run_collector(c, extra_args, no_costs=args.no_costs)
                    all_exit_codes.append((c, exit_code))

                # Summary
                print(color("\n" + "="*60, Colors.CYAN))
                print(color("  Collection Summary", Colors.BOLD))
                print(color("="*60 + "\n", Colors.CYAN))
                for c, code in all_exit_codes:
                    status = color("✓", Colors.GREEN) if code == 0 else color("✗", Colors.RED)
                    print(f"  {status} {c.upper()}: exit code {code}")

                sys.exit(0 if all(c == 0 for _, c in all_exit_codes) else 1)

            try:
                idx = int(choice) - 1
                if 0 <= idx < len(detected):
                    cloud = detected[idx]
                else:
                    print(color("Invalid choice.", Colors.RED))
                    sys.exit(1)
            except ValueError:
                if choice in detected:
                    cloud = choice
                else:
                    print(color("Invalid choice.", Colors.RED))
                    sys.exit(1)

    # Interactive prompts for cloud-specific options (only when not using --cloud flag)
    no_costs = args.no_costs

    if not args.cloud and cloud in ('aws', 'azure', 'gcp', 'm365'):
        # Prompt for collection options
        prompt_funcs = {
            'aws': prompt_aws_options,
            'azure': prompt_azure_options,
            'gcp': prompt_gcp_options,
            'm365': prompt_m365_options,
        }

        opts = prompt_funcs[cloud]()
        if opts is None:
            print(color("\nExiting.", Colors.CYAN))
            sys.exit(0)

        # Apply common options
        if opts.get('output'):
            extra_args = ['-o', opts['output']] + extra_args
        if opts.get('regions'):
            extra_args = ['--regions', opts['regions']] + extra_args
        if not opts.get('include_change_rate', True):
            extra_args = ['--skip-change-rate'] + extra_args
        if opts.get('include_resource_ids'):
            extra_args = ['--include-resource-ids'] + extra_args

        # Cloud-specific options
        if cloud == 'azure':
            if opts.get('subscription_id'):
                extra_args = ['--subscription-id', opts['subscription_id']] + extra_args
        elif cloud == 'gcp':
            if opts.get('all_projects'):
                extra_args = ['--all-projects'] + extra_args
            elif opts.get('project'):
                extra_args = ['--project', opts['project']] + extra_args
            if opts.get('billing_table'):
                extra_args = ['--billing-table', opts['billing_table']] + extra_args
        elif cloud == 'm365':
            if opts.get('skip_sharepoint'):
                extra_args = ['--skip-sharepoint'] + extra_args
            if opts.get('skip_onedrive'):
                extra_args = ['--skip-onedrive'] + extra_args
            if opts.get('skip_exchange'):
                extra_args = ['--skip-exchange'] + extra_args
            if opts.get('skip_teams'):
                extra_args = ['--skip-teams'] + extra_args
            if opts.get('include_entra'):
                extra_args = ['--include-entra'] + extra_args

        # no_costs from wizard overrides --no-costs flag
        if opts.get('no_costs'):
            no_costs = True

    # Permission check
    if not args.skip_check:
        if not verify_permissions(cloud):
            print(color("Permission check failed. Fix the issues above and try again.", Colors.RED))
            print(color("Or use --skip-check to bypass (not recommended).\n", Colors.YELLOW))
            sys.exit(1)

    # Check change rate requirements
    if '--skip-change-rate' not in extra_args:
        cr_ok, cr_err = check_change_rate_requirements(cloud)
        if not cr_ok:
            print(color(f"\n{cr_err}", Colors.RED))
            sys.exit(1)

    # Run collection (costs included by default; pass no_costs=True to skip)
    exit_code = run_collector(cloud, extra_args, no_costs=no_costs)

    if exit_code == 0:
        print(color(f"\n✓ {cloud.upper()} collection completed successfully!\n", Colors.GREEN))
    else:
        print(color(f"\n✗ Collection exited with code {exit_code}\n", Colors.RED))

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
