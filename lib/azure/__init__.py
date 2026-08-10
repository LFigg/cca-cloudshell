"""
Azure resource collection modules for CCA CloudShell.

This package contains functions for collecting various Azure service resources:
- auth: Credential management, subscription discovery
- helpers: Utility functions for Azure-specific operations
- compute: VMs, managed disks
- storage: Storage accounts, file shares, NetApp Files
- databases: SQL, Managed Instances, CosmosDB, PostgreSQL/MySQL/MariaDB, Synapse, Redis
- container: AKS clusters, node pools
- backup: Recovery Services vaults, policies, protected items, recovery points
- monitoring: Azure Monitor change rate and real-usage collection
- cost: Azure Cost Management collection
- permissions: Mandatory read-only permission preflight

Usage:
    from lib.azure import run_collection, build_parser, verify_azure_permissions
"""

# Collector entry points
from .collector import (
    build_parser,
    collect_subscription,
    run_collection,
)

# Cost collection
from .cost import (
    categorize_azure_cost,
    collect_azure_costs,
)

# Permission preflight
from .permissions import (
    check_subscription_permissions,
    format_permission_report,
    verify_azure_permissions,
)

__all__ = [
    # Collector
    'run_collection',
    'build_parser',
    'collect_subscription',
    # Cost
    'collect_azure_costs',
    'categorize_azure_cost',
    # Permissions
    'verify_azure_permissions',
    'check_subscription_permissions',
    'format_permission_report',
]
