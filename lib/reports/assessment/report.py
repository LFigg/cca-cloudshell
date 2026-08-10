"""Assessment report orchestration: load data, generate every tab, save the workbook."""
import argparse
import glob
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from openpyxl import Workbook

from lib.change_rate import load_change_rate_files

from .analysis import analyze_protection_status
from .loader import load_cost_files, load_inventory_files
from .tabs.account_detail import generate_account_detail
from .tabs.backup_policies import generate_backup_policies
from .tabs.data_quality import generate_data_quality_tab
from .tabs.executive_summary import generate_executive_summary
from .tabs.protection_analysis import generate_protection_analysis
from .tabs.raw_data import generate_raw_data
from .tabs.regional_distribution import generate_regional_distribution
from .tabs.sizing_inputs import generate_sizing_inputs
from .tabs.snapshot_analysis import generate_snapshot_analysis
from .tabs.tco_inputs import generate_tco_inputs
from .tabs.unprotected_resources import generate_unprotected_resources


def generate_report(inventory_files: List[str], cost_files: List[str],
                    output_path: str, change_rate_files: Optional[List[str]] = None) -> None:
    """
    Generate comprehensive assessment report.

    Args:
        inventory_files: List of paths to inventory JSON files
        cost_files: List of paths to cost data JSON files
        output_path: Output Excel file path
        change_rate_files: List of paths to change rate JSON files
    """
    print("Loading inventory files...")
    resources, metadata = load_inventory_files(inventory_files)

    if not resources:
        print("Error: No resources found in inventory files")
        sys.exit(1)

    print(f"  Loaded {len(resources)} resources from {len(inventory_files)} files")

    print("Loading cost data...")
    cost_data = load_cost_files(cost_files) if cost_files else {}

    if cost_data.get('total_cost', 0) > 0:
        print(f"  Found ${cost_data['total_cost']:,.2f} in monthly costs")
    else:
        print("  No cost data found")

    # Load change rate data
    change_rate_data: Dict[str, Any] = {}
    if change_rate_files:
        print("Loading change rate data...")
        change_rate_data = load_change_rate_files(change_rate_files)
        if change_rate_data.get('has_actual_data'):
            print(f"  Found actual change rate data for {len(change_rate_data.get('change_rates', {}))} service families")
        else:
            print("  No change rate data found in files")

    print("Generating report...")

    # Create workbook
    wb = Workbook()

    # Generate each tab
    generate_executive_summary(wb, resources, cost_data, metadata)
    generate_sizing_inputs(wb, resources, change_rate_data)
    generate_regional_distribution(wb, resources)
    generate_protection_analysis(wb, resources)
    generate_snapshot_analysis(wb, resources)
    generate_backup_policies(wb, resources)
    generate_unprotected_resources(wb, resources)
    generate_tco_inputs(wb, resources, cost_data)
    generate_account_detail(wb, resources)
    generate_raw_data(wb, resources)
    generate_data_quality_tab(wb, resources)

    # Save workbook
    wb.save(output_path)
    os.chmod(output_path, 0o600)

    print(f"\nReport generated: {output_path}")
    print("=" * 60)
    print(f"Total Resources: {len(resources)}")
    print(f"Providers: {', '.join(metadata.get('providers', ['Unknown']))}")
    print(f"Orgs/Tenants: {len(metadata.get('orgs', []))}")
    print(f"Accounts/Subscriptions: {len(metadata.get('accounts', []))}")

    # Protection summary
    protection = analyze_protection_status(resources)
    print(f"Protection Coverage: {protection['coverage_percent']:.1f}%")
    print(f"  Protected: {protection['protected_count']}")
    print(f"  Unprotected: {protection['unprotected_count']}")


def find_data_files(directory: str) -> Tuple[List[str], List[str], List[str]]:
    """
    Auto-discover inventory, cost, and change rate files in a directory.

    Returns:
        Tuple of (inventory_files, cost_files, change_rate_files)
    """
    inventory_files = []
    cost_files = []
    change_rate_files = []

    # Find inventory files - support multiple naming patterns
    inv_patterns = [
        '**/cca_inv_*.json',       # Generic pattern
        '**/cca_aws_inv_*.json',   # AWS-specific
        '**/cca_azure_inv_*.json', # Azure-specific
        '**/cca_gcp_inv_*.json',   # GCP-specific
        '**/cca_m365_inv_*.json',  # M365-specific
    ]
    for pattern in inv_patterns:
        inv_pattern = os.path.join(directory, pattern)
        inventory_files.extend(glob.glob(inv_pattern, recursive=True))

    # Remove duplicates while preserving order
    inventory_files = list(dict.fromkeys(inventory_files))

    # Find cost summary files (cca_cost_sum_*.json)
    cost_pattern = os.path.join(directory, '**/cca_cost_sum_*.json')
    cost_files.extend(glob.glob(cost_pattern, recursive=True))

    # Find change rate files (cca_*_change_rates_*.json)
    cr_patterns = [
        '**/cca_change_rates_*.json',
        '**/cca_aws_change_rates_*.json',
        '**/cca_azure_change_rates_*.json',
        '**/cca_gcp_change_rates_*.json',
    ]
    for pattern in cr_patterns:
        cr_pattern = os.path.join(directory, pattern)
        change_rate_files.extend(glob.glob(cr_pattern, recursive=True))

    change_rate_files = list(dict.fromkeys(change_rate_files))

    return inventory_files, cost_files, change_rate_files


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Generate comprehensive assessment report for Cohesity sizing/TCO',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Auto-discover files in current directory
  python generate_assessment_report.py

  # Specify input directory
  python generate_assessment_report.py --directory ./output

  # Specify individual files
  python generate_assessment_report.py --inventory cca_inv_*.json --cost cca_cost_sum_*.json

  # Specify output filename
  python generate_assessment_report.py -o my_assessment.xlsx
'''
    )

    parser.add_argument(
        '--directory', '-d',
        help='Directory to search for inventory and cost files (default: current directory)',
        default='.'
    )

    parser.add_argument(
        '--inventory', '-i',
        nargs='+',
        help='Inventory file(s) to include (cca_inv_*.json)'
    )

    parser.add_argument(
        '--cost', '-c',
        nargs='+',
        help='Cost data file(s) to include (cca_cost_sum_*.json)'
    )

    parser.add_argument(
        '--output', '-o',
        help='Output Excel filename (default: assessment_report_TIMESTAMP.xlsx)'
    )

    args = parser.parse_args()

    # Determine input files
    if args.inventory:
        # Expand globs
        inventory_files = []
        for pattern in args.inventory:
            inventory_files.extend(glob.glob(pattern))
        # Still need to discover cost and change rate files
        _, cost_files_auto, change_rate_files = find_data_files(args.directory)
    else:
        # Auto-discover all files
        inventory_files, cost_files_auto, change_rate_files = find_data_files(args.directory)

    if args.cost:
        cost_files = []
        for pattern in args.cost:
            cost_files.extend(glob.glob(pattern))
    else:
        cost_files = cost_files_auto

    if not inventory_files:
        print("Error: No inventory files found")
        print(f"Looking in: {os.path.abspath(args.directory)}")
        print("\nRun collectors first:")
        print("  python collect.py --auto")
        print("  python aws_collect.py -p my-profile")
        print("  python azure_collect.py")
        sys.exit(1)

    print(f"Found {len(inventory_files)} inventory file(s)")
    for f in inventory_files:
        print(f"  - {f}")

    if cost_files:
        print(f"Found {len(cost_files)} cost file(s)")
        for f in cost_files:
            print(f"  - {f}")

    if change_rate_files:
        print(f"Found {len(change_rate_files)} change rate file(s)")
        for f in change_rate_files:
            print(f"  - {f}")

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        output_path = f"assessment_report_{timestamp}.xlsx"

    # Generate report
    generate_report(inventory_files, cost_files, output_path, change_rate_files)

