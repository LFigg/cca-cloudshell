"""
Modular collectors for Google Cloud Platform (GCP) resources.

This package provides the following modules:
- auth: Authentication and project discovery
- helpers: Utility functions for GCP resource parsing
- compute: Compute Engine instances, disks, snapshots
- storage: Cloud Storage buckets, Filestore instances
- databases: Cloud SQL, Memorystore, BigQuery, Spanner, Bigtable, AlloyDB
- container: GKE clusters, Cloud Functions
- backup: Backup & DR plans, vaults, data sources, backups
- monitoring: Change rate metrics collection
- cost: BigQuery billing-export cost collection
- permissions: Mandatory read-only permission preflight

Usage:
    from lib.gcp import run_collection, build_parser, verify_gcp_permissions
"""

# Collector entry points
from .collector import (
    build_parser,
    collect_project,
    run_collection,
)

# Cost collection
from .cost import (
    categorize_gcp_cost,
    collect_gcp_costs,
)

# Permission preflight
from .permissions import (
    check_project_permissions,
    format_permission_report,
    verify_gcp_permissions,
)

__all__ = [
    # Collector
    'run_collection',
    'build_parser',
    'collect_project',
    # Cost
    'collect_gcp_costs',
    'categorize_gcp_cost',
    # Permissions
    'verify_gcp_permissions',
    'check_project_permissions',
    'format_permission_report',
]
