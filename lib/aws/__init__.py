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
"""
