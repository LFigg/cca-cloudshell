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
import os
import sys
import subprocess
from typing import Optional, Tuple, List

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
    print(f"  {color('q', Colors.RED)}) Quit")
    print()


def get_cloud_choice() -> Optional[str]:
    """Get cloud choice from user input."""
    choices = {
        '1': 'aws',
        '2': 'azure',
        '3': 'gcp',
        '4': 'm365',
        'aws': 'aws',
        'azure': 'azure',
        'gcp': 'gcp',
        'm365': 'm365',
    }
    
    while True:
        try:
            choice = input(color("Enter choice (1-4 or cloud name): ", Colors.CYAN)).strip().lower()
            if choice in ('q', 'quit', 'exit'):
                return None
            if choice in choices:
                return choices[choice]
            print(color("Invalid choice. Please enter 1-4 or a cloud name.", Colors.YELLOW))
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
        import boto3  # type: ignore[import-untyped]
        from botocore.exceptions import ClientError, NoCredentialsError
    except ImportError:
        return False, "boto3 not installed", ["Run: pip install boto3"]
    
    # Check credentials
    try:
        sts = boto3.client('sts')  # type: ignore[call-overload]
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
        from azure.identity import DefaultAzureCredential  # type: ignore[import-untyped]
        from azure.mgmt.resource import SubscriptionClient  # type: ignore[import-untyped]
    except ImportError:
        return False, "Azure SDK not installed", [
            "Run: pip install azure-identity azure-mgmt-resource"
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
                details.append(f"          - {sub.display_name} ({sub.subscription_id[:8]}...)")
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
        import google.auth  # type: ignore[import-untyped]
        from google.cloud import resourcemanager_v3  # type: ignore[import-untyped]
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
    Returns: (success, message, details)
    """
    details = []
    
    # Check required environment variables
    tenant_id = os.environ.get('MS365_TENANT_ID')
    client_id = os.environ.get('MS365_CLIENT_ID')
    client_secret = os.environ.get('MS365_CLIENT_SECRET')
    
    if not all([tenant_id, client_id, client_secret]):
        missing = []
        if not tenant_id:
            missing.append("MS365_TENANT_ID")
        if not client_id:
            missing.append("MS365_CLIENT_ID")
        if not client_secret:
            missing.append("MS365_CLIENT_SECRET")
        return False, "Missing required environment variables", [
            f"Set the following env vars: {', '.join(missing)}",
            "",
            "Example:",
            "  export MS365_TENANT_ID='your-tenant-id'",
            "  export MS365_CLIENT_ID='your-client-id'",
            "  export MS365_CLIENT_SECRET='your-client-secret'",
            "",
            "Note: Requires Azure AD App Registration with Graph API permissions.",
            "See docs/collectors/m365.md for setup instructions."
        ]
    
    # Type narrowing - we know these are strings after the check above
    assert tenant_id is not None and client_id is not None and client_secret is not None
    
    details.append(f"Tenant:   {tenant_id}")
    details.append(f"Client:   {client_id[:8]}...")
    
    # Try to get a token
    try:
        from azure.identity import ClientSecretCredential  # type: ignore[import-untyped]
        from msgraph import GraphServiceClient  # type: ignore[import-untyped] # noqa: F401
    except ImportError:
        return False, "msgraph SDK not installed", [
            "Run: pip install msgraph-sdk azure-identity"
        ]
    
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
    except Exception as e:
        return False, f"Authentication failed: {e}", [
            "Check that:",
            "  - Tenant ID, Client ID, and Client Secret are correct",
            "  - The App Registration has the required API permissions",
            "  - Admin consent has been granted for the permissions"
        ]
    
    return True, "M365 credentials verified", details


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
    """Check if M365 credentials are available."""
    return all([
        os.environ.get('MS365_TENANT_ID'),
        os.environ.get('MS365_CLIENT_ID'),
        os.environ.get('MS365_CLIENT_SECRET')
    ])


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
        print(color(f"\n    This could indicate missing credentials or SDK issues.", Colors.YELLOW))
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

def run_collector(cloud: str, extra_args: List[str]) -> int:
    """
    Run the appropriate collector script.
    Returns the exit code from the collector.
    """
    collectors = {
        'aws': 'aws_collect.py',
        'azure': 'azure_collect.py',
        'gcp': 'gcp_collect.py',
        'm365': 'm365_collect.py',
    }
    
    collector = collectors.get(cloud)
    if not collector:
        print(color(f"Unknown cloud: {cloud}", Colors.RED))
        return 1
    
    # Find collector script relative to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    collector_path = os.path.join(script_dir, collector)
    
    if not os.path.exists(collector_path):
        print(color(f"Collector not found: {collector_path}", Colors.RED))
        return 1
    
    # Build command
    cmd = [sys.executable, collector_path] + extra_args
    
    print(color(f"\n{'─'*60}", Colors.CYAN))
    print(color(f"  Starting {cloud.upper()} collection...", Colors.BOLD))
    print(color(f"{'─'*60}\n", Colors.CYAN))
    
    if extra_args:
        print(color(f"  Additional args: {' '.join(extra_args)}\n", Colors.CYAN))
    
    # Run collector
    try:
        result = subprocess.run(cmd, cwd=script_dir)
        return result.returncode
    except KeyboardInterrupt:
        print(color("\n\nCollection interrupted by user.", Colors.YELLOW))
        return 130


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
    collectors = {
        'aws': 'aws_collect.py',
        'azure': 'azure_collect.py',
        'gcp': 'gcp_collect.py',
        'm365': 'm365_collect.py',
    }
    
    collector = collectors.get(cloud)
    if not collector:
        return
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    collector_path = os.path.join(script_dir, collector)
    
    # Run help first
    subprocess.run([sys.executable, collector_path, '--help'])
    
    print(color(f"\n{'─'*60}", Colors.CYAN))
    print(color(f"  Tip: Pass arguments with '--'", Colors.BOLD))
    print(color(f"{'─'*60}\n", Colors.CYAN))
    print(color(f"  python collect.py --cloud {cloud} -- [options]\n", Colors.CYAN))


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
    all_passed = True
    ready_clouds = []
    
    for cloud in selected:
        success = verify_permissions(cloud)
        if success:
            ready_clouds.append(cloud)
        else:
            all_passed = False
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
            print(color("No cloud credentials detected.\n", Colors.YELLOW))
            print("Run the setup wizard to configure credentials:")
            print(color("  python collect.py --setup\n", Colors.GREEN))
            print("Or configure credentials manually:")
            print("  AWS:   aws configure")
            print("  Azure: az login")
            print("  GCP:   gcloud auth application-default login")
            print("  M365:  Set MS365_* environment variables")
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
                # Run all detected clouds
                all_exit_codes = []
                for c in detected:
                    if not args.skip_check:
                        if not verify_permissions(c):
                            print(color(f"Skipping {c.upper()} due to permission issues.\n", Colors.YELLOW))
                            continue
                    exit_code = run_collector(c, extra_args)
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
    
    # Permission check
    if not args.skip_check:
        if not verify_permissions(cloud):
            print(color("Permission check failed. Fix the issues above and try again.", Colors.RED))
            print(color(f"Or use --skip-check to bypass (not recommended).\n", Colors.YELLOW))
            sys.exit(1)
    
    # Run collection
    exit_code = run_collector(cloud, extra_args)
    
    if exit_code == 0:
        print(color(f"\n✓ {cloud.upper()} collection completed successfully!\n", Colors.GREEN))
    else:
        print(color(f"\n✗ Collection exited with code {exit_code}\n", Colors.RED))
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
