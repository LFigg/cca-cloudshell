"""
Comprehensive Assessment Report Generator

Generates a multi-tab Excel report for Cohesity sizing and TCO analysis.
Combines inventory data from AWS, Azure, GCP, and M365 collectors with
cost data to provide complete environment visibility.

Tabs:
1. Executive Summary - Environment overview, sizing summary, protection status
2. Sizing Inputs - Workload inventory by type for Cohesity sizing calculator
3. Regional Distribution - Resources by region for cluster placement planning
4. Protection Analysis - Coverage percentages and snapshot analysis
5. Snapshot Analysis - Automated backup pattern breakdown (DLM, scripts, AWS Backup)
6. Backup Policies - AWS Backup plans, DLM policies, Azure policies (included/excluded scope)
7. Unprotected Resources - Prioritized list for protection planning
8. TCO Inputs - Current backup costs and Cohesity TCO calculator inputs
9. Account Detail - Multi-account/subscription breakdown
10. Raw Data - Full resource inventory for reference
11. Data Quality - Resources whose actual usage couldn't be measured (reported as
    0 GB, not an allocated/quota estimate) - see lib/data_quality.py

Note: For M365 data, use the dedicated M365 report generator (generate_m365_report.py)

Package layout (one file per concern, per this repo's Module Design
Guidelines - see docs/v2-refactor-plan.md):
- loader.py: data loading and validation
- analysis.py: resource categorization and analysis (no Excel dependency)
- excel_helpers.py / styles.py: generic openpyxl cell/formatting helpers
- tabs/: one module per report tab
- report.py: orchestration (generate_report, find_data_files, main)
"""

from .analysis import (
    analyze_accounts,
    analyze_protection_status,
    analyze_regions,
    analyze_snapshot_patterns,
    analyze_snapshots,
    categorize_resources,
    get_provider,
    get_snapshots,
    get_workload_category,
)
from .loader import (
    load_cost_files,
    load_inventory_files,
    load_json_file,
    load_summary_files,
)
from .report import find_data_files, generate_report, main
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

__all__ = [
    # Loader
    'load_json_file',
    'load_inventory_files',
    'load_summary_files',
    'load_cost_files',
    # Analysis
    'get_provider',
    'get_workload_category',
    'categorize_resources',
    'analyze_protection_status',
    'analyze_regions',
    'analyze_accounts',
    'get_snapshots',
    'analyze_snapshots',
    'analyze_snapshot_patterns',
    # Tabs
    'generate_executive_summary',
    'generate_sizing_inputs',
    'generate_regional_distribution',
    'generate_protection_analysis',
    'generate_snapshot_analysis',
    'generate_backup_policies',
    'generate_unprotected_resources',
    'generate_tco_inputs',
    'generate_account_detail',
    'generate_raw_data',
    'generate_data_quality_tab',
    # Orchestration
    'generate_report',
    'find_data_files',
    'main',
]
