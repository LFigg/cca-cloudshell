#!/usr/bin/env python3
"""
Cloud Shell Compatibility Test

Run this script in each cloud shell to verify the collectors will work:
  AWS CloudShell:    python3 tests/test_cloudshell_compat.py
  Azure Cloud Shell: python3 tests/test_cloudshell_compat.py
  Google Cloud Shell: python3 tests/test_cloudshell_compat.py
"""
import sys
import os

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def check_python_version():
    """Check Python version is 3.8+"""
    version = sys.version_info
    if version >= (3, 8):
        print(f"✓ Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"✗ Python {version.major}.{version.minor} (need 3.8+)")
        return False


def check_core_imports():
    """Check that core library imports work."""
    errors = []
    
    # Core lib imports
    try:
        from lib.models import CloudResource, aggregate_sizing
        print("✓ lib.models")
    except ImportError as e:
        print(f"✗ lib.models: {e}")
        errors.append(str(e))
    
    try:
        from lib.utils import (
            generate_run_id, get_timestamp, write_json, write_csv,
            setup_logging, ProgressTracker, retry_with_backoff
        )
        print("✓ lib.utils (core)")
    except ImportError as e:
        print(f"✗ lib.utils: {e}")
        errors.append(str(e))
    
    return len(errors) == 0


def check_progress_tracker():
    """Check ProgressTracker works in both modes."""
    from lib.utils import ProgressTracker, RICH_AVAILABLE
    
    # Test with rich (if available)
    if RICH_AVAILABLE:
        print("✓ rich library available")
        tracker = ProgressTracker("Test", total_regions=1)
        print(f"  Progress mode: rich (TTY={sys.stdout.isatty()})")
    else:
        print("- rich library not installed (fallback mode will be used)")
    
    # Test plain text mode
    tracker = ProgressTracker("Test", total_regions=1, show_progress=False)
    tracker.__enter__()
    tracker.start_region("test-region")
    tracker.update_task("Testing...")
    tracker.add_resources(5, 100.0)
    tracker.complete_region()
    tracker.__exit__(None, None, None)
    
    print("✓ ProgressTracker fallback mode works")
    return True


def check_aws_deps():
    """Check AWS collector dependencies."""
    try:
        import boto3
        print(f"✓ boto3 {boto3.__version__}")
        return True
    except ImportError:
        print("- boto3 not installed (needed for AWS collector)")
        return False


def check_azure_deps():
    """Check Azure collector dependencies."""
    errors = []
    
    try:
        from azure.identity import DefaultAzureCredential
        print("✓ azure-identity")
    except ImportError:
        print("- azure-identity not installed")
        errors.append("azure-identity")
    
    try:
        from azure.mgmt.compute import ComputeManagementClient
        print("✓ azure-mgmt-compute")
    except ImportError:
        print("- azure-mgmt-compute not installed")
        errors.append("azure-mgmt-compute")
    
    return len(errors) == 0


def check_gcp_deps():
    """Check GCP collector dependencies."""
    errors = []
    
    try:
        from google.cloud import compute_v1
        print("✓ google-cloud-compute")
    except ImportError:
        print("- google-cloud-compute not installed")
        errors.append("google-cloud-compute")
    
    try:
        from google.cloud import storage
        print("✓ google-cloud-storage")
    except ImportError:
        print("- google-cloud-storage not installed")
        errors.append("google-cloud-storage")
    
    return len(errors) == 0


def check_m365_deps():
    """Check M365 collector dependencies."""
    try:
        from msgraph.graph_service_client import GraphServiceClient
        from azure.identity import ClientSecretCredential
        print("✓ msgraph-sdk + azure-identity")
        return True
    except ImportError:
        print("- msgraph-sdk not installed (needed for M365 collector)")
        return False


def detect_environment():
    """Detect which cloud shell we're running in."""
    if os.environ.get('AWS_EXECUTION_ENV'):
        return 'aws'
    elif os.environ.get('ACC_TERM_ID') or os.path.exists(f'/home/{os.environ.get("USER", "")}/clouddrive'):
        return 'azure'
    elif os.environ.get('CLOUD_SHELL') == 'true' or os.environ.get('DEVSHELL_GCLOUD_CONFIG'):
        return 'gcp'
    else:
        return 'local'


def main():
    print("=" * 60)
    print("CCA CloudShell - Compatibility Check")
    print("=" * 60)
    
    # Detect environment
    env = detect_environment()
    env_names = {
        'aws': 'AWS CloudShell',
        'azure': 'Azure Cloud Shell', 
        'gcp': 'Google Cloud Shell',
        'local': 'Local/Other'
    }
    print(f"Environment: {env_names.get(env, 'Unknown')}")
    print(f"TTY: {sys.stdout.isatty()}")
    print()
    
    # Run checks
    print("--- Core ---")
    py_ok = check_python_version()
    core_ok = check_core_imports()
    progress_ok = check_progress_tracker()
    
    print()
    print("--- Cloud SDKs ---")
    aws_ok = check_aws_deps()
    azure_ok = check_azure_deps()
    gcp_ok = check_gcp_deps()
    m365_ok = check_m365_deps()
    
    # Summary
    print()
    print("=" * 60)
    print("Summary")
    print("=" * 60)
    
    collectors_ready = []
    if aws_ok:
        collectors_ready.append("AWS")
    if azure_ok:
        collectors_ready.append("Azure")
    if gcp_ok:
        collectors_ready.append("GCP")
    if m365_ok:
        collectors_ready.append("M365")
    
    if py_ok and core_ok:
        print(f"✓ Core libraries ready")
        if collectors_ready:
            print(f"✓ Ready to run: {', '.join(collectors_ready)}")
        else:
            print("- No cloud SDKs installed. Run: pip install -r requirements.txt")
    else:
        print("✗ Core requirements not met")
        return 1
    
    # Suggest what to run based on environment
    print()
    if env == 'aws' and aws_ok:
        print("Suggested: python3 aws_collect.py")
    elif env == 'azure' and azure_ok:
        print("Suggested: python3 azure_collect.py")
    elif env == 'gcp' and gcp_ok:
        print("Suggested: python3 gcp_collect.py")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
