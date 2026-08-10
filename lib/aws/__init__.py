"""
AWS resource collection modules for CCA CloudShell.

This package contains functions for collecting various AWS service resources:
- auth: Session management, role assumption, organization discovery
- helpers: Utility functions for AWS-specific operations
- compute: EC2 instances, EBS volumes, Lambda functions
- storage: S3 buckets, EFS, FSx filesystems
- databases: RDS, DynamoDB, ElastiCache, Redshift, DocumentDB, Neptune, OpenSearch, MemoryDB, Timestream
- container: EKS clusters, node groups
- backup: AWS Backup vaults, plans, recovery points, selections
- monitoring: CloudWatch change rate collection
- parallel: Multi-account parallel collection, checkpointing
- cost: AWS Cost Explorer collection
- permissions: Mandatory read-only permission preflight

Usage:
    from lib.aws import run_collection, build_parser, verify_aws_permissions
"""

# Collector entry points
from .collector import (
    build_parser,
    collect_account,
    collect_region,
    run_collection,
)

# Cost collection
from .cost import (
    categorize_aws_usage,
    collect_aws_costs,
)

# Permission preflight
from .permissions import (
    check_single_account,
    format_permission_report,
    verify_aws_permissions,
)

__all__ = [
    # Collector
    'run_collection',
    'build_parser',
    'collect_account',
    'collect_region',
    # Cost
    'collect_aws_costs',
    'categorize_aws_usage',
    # Permissions
    'verify_aws_permissions',
    'check_single_account',
    'format_permission_report',
]
