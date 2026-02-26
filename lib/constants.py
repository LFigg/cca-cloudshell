"""
Constants for CCA CloudShell collectors.

This module defines all magic strings and numbers used across the codebase
to prevent typos, ensure consistency, and make maintenance easier.
"""

# =============================================================================
# Byte/Size Conversion Constants
# =============================================================================

BYTES_PER_KB = 1024
BYTES_PER_MB = 1024 ** 2
BYTES_PER_GB = 1024 ** 3
BYTES_PER_TB = 1024 ** 4

# SI units (base 1000)
BYTES_PER_KB_SI = 1000
BYTES_PER_MB_SI = 1000 ** 2
BYTES_PER_GB_SI = 1000 ** 3
BYTES_PER_TB_SI = 1000 ** 4

# =============================================================================
# Time Constants
# =============================================================================

SECONDS_PER_MINUTE = 60
SECONDS_PER_HOUR = 3600
SECONDS_PER_DAY = 86400

# =============================================================================
# Default Configuration Values
# =============================================================================

DEFAULT_SAMPLE_DAYS = 7
DEFAULT_RETRY_ATTEMPTS = 3
DEFAULT_PARALLEL_WORKERS = 4
DEFAULT_DYNAMODB_WORKERS = 10  # For parallelized DynamoDB describe_table calls
DEFAULT_RECOVERY_POINT_WORKERS = 4  # For parallelized Azure RP collection

# =============================================================================
# Cloud Providers
# =============================================================================

PROVIDER_AWS = "aws"
PROVIDER_AZURE = "azure"
PROVIDER_GCP = "gcp"
PROVIDER_M365 = "m365"

# =============================================================================
# AWS Resource Types
# =============================================================================

# EC2
AWS_EC2_INSTANCE = "aws:ec2:instance"
AWS_EC2_VOLUME = "aws:ec2:volume"
AWS_EC2_SNAPSHOT = "aws:ec2:snapshot"

# RDS
AWS_RDS_INSTANCE = "aws:rds:instance"
AWS_RDS_CLUSTER = "aws:rds:cluster"
AWS_RDS_SNAPSHOT = "aws:rds:snapshot"
AWS_RDS_CLUSTER_SNAPSHOT = "aws:rds:cluster-snapshot"

# S3
AWS_S3_BUCKET = "aws:s3:bucket"

# EFS
AWS_EFS_FILESYSTEM = "aws:efs:filesystem"

# EKS
AWS_EKS_CLUSTER = "aws:eks:cluster"
AWS_EKS_NODEGROUP = "aws:eks:nodegroup"
AWS_EKS_PVC = "aws:eks:pvc"

# Lambda
AWS_LAMBDA_FUNCTION = "aws:lambda:function"

# DynamoDB
AWS_DYNAMODB_TABLE = "aws:dynamodb:table"

# FSx
AWS_FSX_FILESYSTEM = "aws:fsx:filesystem"

# ElastiCache
AWS_ELASTICACHE_CLUSTER = "aws:elasticache:cluster"

# Backup
AWS_BACKUP_VAULT = "aws:backup:vault"
AWS_BACKUP_RECOVERY_POINT = "aws:backup:recovery-point"
AWS_BACKUP_PLAN = "aws:backup:plan"
AWS_BACKUP_SELECTION = "aws:backup:selection"
AWS_BACKUP_PROTECTED_RESOURCE = "aws:backup:protected-resource"
AWS_BACKUP_REGION_SETTINGS = "aws:backup:region-settings"

# Redshift
AWS_REDSHIFT_CLUSTER = "aws:redshift:cluster"

# DocumentDB
AWS_DOCUMENTDB_CLUSTER = "aws:documentdb:cluster"

# Neptune
AWS_NEPTUNE_CLUSTER = "aws:neptune:cluster"

# OpenSearch
AWS_OPENSEARCH_DOMAIN = "aws:opensearch:domain"

# MemoryDB
AWS_MEMORYDB_CLUSTER = "aws:memorydb:cluster"

# Timestream
AWS_TIMESTREAM_DATABASE = "aws:timestream:database"

# =============================================================================
# Azure Resource Types
# =============================================================================

AZURE_VM = "azure:vm"
AZURE_DISK = "azure:disk"
AZURE_SNAPSHOT = "azure:snapshot"
AZURE_STORAGE_ACCOUNT = "azure:storage:account"
AZURE_FILE_SHARE = "azure:storage:fileshare"
AZURE_SQL_SERVER = "azure:sql:server"
AZURE_SQL_DATABASE = "azure:sql:database"
AZURE_SQL_MANAGED_INSTANCE = "azure:sql:managedinstance"
AZURE_SQL_BACKUP = "azure:sql:backup"
AZURE_COSMOSDB_ACCOUNT = "azure:cosmosdb:account"
AZURE_AKS_CLUSTER = "azure:aks:cluster"
AZURE_AKS_PVC = "azure:aks:pvc"
AZURE_FUNCTION_APP = "azure:functions:app"
AZURE_RECOVERY_VAULT = "azure:backup:vault"
AZURE_BACKUP_POLICY = "azure:backup:policy"
AZURE_BACKUP_PROTECTED_ITEM = "azure:backup:protecteditem"
AZURE_BACKUP_RECOVERY_POINT = "azure:backup:recoverypoint"
AZURE_REDIS_CACHE = "azure:redis:cache"
AZURE_POSTGRESQL_SERVER = "azure:postgresql:server"
AZURE_MYSQL_SERVER = "azure:mysql:server"
AZURE_MARIADB_SERVER = "azure:mariadb:server"
AZURE_SYNAPSE_WORKSPACE = "azure:synapse:workspace"
AZURE_SYNAPSE_POOL = "azure:synapse:pool"
AZURE_NETAPP_VOLUME = "azure:netapp:volume"

# =============================================================================
# GCP Resource Types
# =============================================================================

GCP_COMPUTE_INSTANCE = "gcp:compute:instance"
GCP_COMPUTE_DISK = "gcp:compute:disk"
GCP_COMPUTE_SNAPSHOT = "gcp:compute:snapshot"
GCP_STORAGE_BUCKET = "gcp:storage:bucket"
GCP_SQL_INSTANCE = "gcp:sql:instance"
GCP_CONTAINER_CLUSTER = "gcp:container:cluster"
GCP_GKE_PVC = "gcp:gke:pvc"
GCP_FUNCTIONS_FUNCTION = "gcp:functions:function"
GCP_FILESTORE_INSTANCE = "gcp:filestore:instance"
GCP_REDIS_INSTANCE = "gcp:redis:instance"
GCP_BACKUPDR_PLAN = "gcp:backupdr:plan"
GCP_BACKUPDR_VAULT = "gcp:backupdr:vault"
GCP_BACKUPDR_DATASOURCE = "gcp:backupdr:datasource"
GCP_BACKUPDR_BACKUP = "gcp:backupdr:backup"
GCP_BIGQUERY_DATASET = "gcp:bigquery:dataset"
GCP_SPANNER_INSTANCE = "gcp:spanner:instance"
GCP_BIGTABLE_INSTANCE = "gcp:bigtable:instance"
GCP_ALLOYDB_CLUSTER = "gcp:alloydb:cluster"
GCP_ALLOYDB_INSTANCE = "gcp:alloydb:instance"

# =============================================================================
# M365 Resource Types
# =============================================================================

M365_SHAREPOINT_SITE = "m365:sharepoint:site"
M365_ONEDRIVE_DRIVE = "m365:onedrive:drive"
M365_EXCHANGE_MAILBOX = "m365:exchange:mailbox"
M365_TEAMS_TEAM = "m365:teams:team"
ENTRAID_USER = "entraid:user"
ENTRAID_GROUP = "entraid:group"

# =============================================================================
# AWS Service Families
# =============================================================================

SERVICE_EC2 = "EC2"
SERVICE_RDS = "RDS"
SERVICE_S3 = "S3"
SERVICE_EFS = "EFS"
SERVICE_EKS = "EKS"
SERVICE_LAMBDA = "Lambda"
SERVICE_DYNAMODB = "DynamoDB"
SERVICE_FSX = "FSx"
SERVICE_ELASTICACHE = "ElastiCache"
SERVICE_BACKUP = "Backup"
SERVICE_REDSHIFT = "Redshift"
SERVICE_DOCUMENTDB = "DocumentDB"
SERVICE_NEPTUNE = "Neptune"
SERVICE_OPENSEARCH = "OpenSearch"
SERVICE_MEMORYDB = "MemoryDB"
SERVICE_TIMESTREAM = "Timestream"

# =============================================================================
# Azure Service Families
# =============================================================================

SERVICE_AZURE_VM = "AzureVM"
SERVICE_AZURE_STORAGE = "AzureStorage"
SERVICE_AZURE_SQL = "AzureSQL"
SERVICE_COSMOSDB = "CosmosDB"
SERVICE_AKS = "AKS"
SERVICE_AZURE_FUNCTIONS = "AzureFunctions"
SERVICE_AZURE_BACKUP = "AzureBackup"
SERVICE_REDIS = "Redis"
SERVICE_POSTGRESQL = "PostgreSQL"
SERVICE_MYSQL = "MySQL"
SERVICE_MARIADB = "MariaDB"
SERVICE_SYNAPSE = "Synapse"
SERVICE_NETAPP_FILES = "NetAppFiles"
SERVICE_AZURE_FILES = "AzureFiles"
SERVICE_SQL_DATABASE = "SQLDatabase"

# =============================================================================
# GCP Service Families
# =============================================================================

SERVICE_GCP_COMPUTE = "Compute"
SERVICE_GCP_STORAGE = "Storage"
SERVICE_GCP_SQL = "SQL"
SERVICE_GKE = "GKE"
SERVICE_GCP_FUNCTIONS = "Functions"
SERVICE_FILESTORE = "Filestore"
SERVICE_BIGQUERY = "BigQuery"
SERVICE_SPANNER = "Spanner"
SERVICE_BIGTABLE = "Bigtable"
SERVICE_ALLOYDB = "AlloyDB"

# =============================================================================
# M365 Service Families
# =============================================================================

SERVICE_SHAREPOINT = "SharePoint"
SERVICE_ONEDRIVE = "OneDrive"
SERVICE_EXCHANGE = "Exchange"
SERVICE_TEAMS = "Teams"
SERVICE_ENTRA_ID = "EntraID"


# =============================================================================
# Cost Collection Filters (for cost_collect.py)
# =============================================================================

# AWS Backup and snapshot related usage types
# Reference: https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/ce-default-reports.html
AWS_BACKUP_FILTERS = {
    'services': [
        'AWS Backup',
        'EC2 - Other',  # Contains EBS snapshot costs
        'Amazon Elastic Block Store',
        'Amazon RDS',
        'Amazon S3',  # S3 backup storage
        'Amazon EFS',  # EFS backup
        'Amazon FSx',  # FSx backup
        'Amazon DynamoDB',  # DynamoDB backup
    ],
    'usage_types': [
        # EBS Snapshots
        'SnapshotUsage',
        'TimedStorage-Snapshot',
        # AWS Backup vault storage (warm)
        'WarmStorage',
        'BackupStorage',
        'Storage-ByteHrs',
        # AWS Backup vault storage (cold)
        'ColdStorage',
        # AWS Backup general
        'Backup',
        'ChargedBackupUsage',
        'BackupUsage',
        'VaultStorage',
        # RDS automated backups
        'BackupStorage',
        'ChargedBackup',
        # EFS backup via AWS Backup
        'EFS-Backup',
        'EFS-ByteHrs-Backup',
        # FSx backup via AWS Backup
        'FSx-Backup',
        'FSxBackup',
        # Catches region-prefixed usage types like "USE1-BackupStorage"
    ]
}

# Azure backup-related service and meter filters
AZURE_BACKUP_FILTERS = {
    'service_names': [
        'Azure Backup',
        'Storage',
        'Azure Site Recovery',
        'Azure NetApp Files',  # NetApp Files backup/snapshot costs
    ],
    'meter_categories': [
        'Backup',
        'Storage',
        'Site Recovery',
        'Azure NetApp Files',  # NetApp snapshot/replication costs
    ]
}

# GCP backup-related service and SKU filters
GCP_BACKUP_FILTERS = {
    'services': [
        'Compute Engine',
        'Cloud Storage',
        'Cloud SQL',
        'Backup and DR Service',
    ],
    'sku_keywords': [
        'snapshot',
        'backup',
        'nearline',
        'coldline',
        'archive',
    ]
}


# =============================================================================
# Helper Functions
# =============================================================================

def bytes_to_gb(bytes_value: float) -> float:
    """Convert bytes to gigabytes."""
    return bytes_value / BYTES_PER_GB


def bytes_to_tb(bytes_value: float) -> float:
    """Convert bytes to terabytes."""
    return bytes_value / BYTES_PER_TB


def gb_to_bytes(gb_value: float) -> float:
    """Convert gigabytes to bytes."""
    return gb_value * BYTES_PER_GB
