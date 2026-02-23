# CCA CloudShell - Required Permissions

This document details the minimum permissions required to run each cloud collector.

## Table of Contents
- [AWS Permissions](#aws-permissions)
- [Azure Permissions](#azure-permissions)
- [GCP Permissions](#gcp-permissions)
- [Microsoft 365 Permissions](#microsoft-365-permissions)

---

## AWS Permissions

### Quick Setup: CloudFormation Template

The easiest way to set up AWS permissions is using our CloudFormation template:

```bash
aws cloudformation create-stack \
  --stack-name cca-collector \
  --template-body file://setup/aws-iam-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM
```

See [setup/](../setup/) for multi-account deployment options and Azure/GCP setup scripts.

### Alternative: Use AWS Managed Policy

The simplest manual approach is to use the AWS managed policy:
```
arn:aws:iam::aws:policy/ReadOnlyAccess
```

### Minimum Required Permissions (IAM Policy)

If you need a least-privilege policy, use the following:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "CCACloudShellReadOnly",
            "Effect": "Allow",
            "Action": [
                "sts:GetCallerIdentity",
                "sts:AssumeRole",
                
                "ec2:DescribeRegions",
                "ec2:DescribeInstances",
                "ec2:DescribeVolumes",
                "ec2:DescribeSnapshots",
                
                "rds:DescribeDBInstances",
                "rds:DescribeDBClusters",
                "rds:DescribeDBSnapshots",
                "rds:DescribeDBClusterSnapshots",
                
                "cloudwatch:GetMetricStatistics",
                
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "s3:GetBucketTagging",
                
                "elasticfilesystem:DescribeFileSystems",
                
                "fsx:DescribeFileSystems",
                
                "eks:ListClusters",
                "eks:DescribeCluster",
                "eks:ListNodegroups",
                "eks:DescribeNodegroup",
                
                "lambda:ListFunctions",
                
                "dynamodb:ListTables",
                "dynamodb:DescribeTable",
                
                "elasticache:DescribeCacheClusters",
                
                "redshift:DescribeClusters",
                
                "rds:DescribeDBClusters",
                
                "es:ListDomainNames",
                "es:DescribeDomains",
                
                "memorydb:DescribeClusters",
                
                "timestream:ListDatabases",
                "timestream:ListTables",
                "timestream:DescribeTable",
                
                "backup:ListBackupVaults",
                "backup:ListRecoveryPointsByBackupVault",
                "backup:ListBackupPlans",
                "backup:GetBackupPlan",
                "backup:ListBackupSelections",
                "backup:GetBackupSelection",
                "backup:ListProtectedResources"
            ],
            "Resource": "*"
        }
    ]
}
```

### Multi-Account Permissions

For multi-account collection, additional permissions are needed:

#### Role Assumption (--role-arn, --role-arns)

The source identity needs permission to assume roles in target accounts:

```json
{
    "Sid": "AssumeRoleInTargetAccounts",
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Resource": [
        "arn:aws:iam::111111111111:role/CCARole",
        "arn:aws:iam::222222222222:role/CCARole"
    ]
}
```

Each target account needs a role with:
1. Trust policy allowing the source account/role to assume it
2. The read-only permissions listed above

**Trust Policy for Target Account Role:**
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::SOURCE_ACCOUNT_ID:root"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "sts:ExternalId": "YOUR_EXTERNAL_ID"
                }
            }
        }
    ]
}
```

#### Organizations Discovery (--org-role)

For automatic account discovery via AWS Organizations:

```json
{
    "Sid": "OrganizationsDiscovery",
    "Effect": "Allow",
    "Action": [
        "organizations:ListAccounts",
        "organizations:DescribeOrganization"
    ],
    "Resource": "*"
}
```

This permission is only needed in the management account (or delegated admin).

### Permissions by Service

| Service | Permissions | Purpose |
|---------|-------------|---------|
| **STS** | `sts:GetCallerIdentity` | Get account ID |
| | `sts:AssumeRole` | Assume roles in other accounts (multi-account) |
| **Organizations** | `organizations:ListAccounts` | Discover accounts (--org-role) |
| **EC2** | `ec2:DescribeRegions` | List enabled regions |
| | `ec2:DescribeInstances` | List EC2 instances |
| | `ec2:DescribeVolumes` | List EBS volumes |
| | `ec2:DescribeSnapshots` | List EBS snapshots |
| **RDS** | `rds:DescribeDBInstances` | List RDS instances |
| | `rds:DescribeDBClusters` | List Aurora clusters |
| | `rds:DescribeDBSnapshots` | List RDS snapshots |
| | `rds:DescribeDBClusterSnapshots` | List Aurora snapshots |
| **CloudWatch** | `cloudwatch:GetMetricStatistics` | Get Aurora storage metrics |
| **S3** | `s3:ListAllMyBuckets` | List S3 buckets |
| | `s3:GetBucketLocation` | Get bucket region |
| | `s3:GetBucketTagging` | Get bucket tags |
| **EFS** | `elasticfilesystem:DescribeFileSystems` | List EFS file systems |
| **FSx** | `fsx:DescribeFileSystems` | List FSx file systems |
| **EKS** | `eks:ListClusters` | List EKS clusters |
| | `eks:DescribeCluster` | Get cluster details |
| | `eks:ListNodegroups` | List node groups |
| | `eks:DescribeNodegroup` | Get node group details |
| **Lambda** | `lambda:ListFunctions` | List Lambda functions |
| **DynamoDB** | `dynamodb:ListTables` | List DynamoDB tables |
| | `dynamodb:DescribeTable` | Get table details |
| **ElastiCache** | `elasticache:DescribeCacheClusters` | List ElastiCache clusters |
| **Redshift** | `redshift:DescribeClusters` | List Redshift clusters |
| **DocumentDB** | `rds:DescribeDBClusters` | List DocumentDB clusters (filter by engine) |
| **Neptune** | `rds:DescribeDBClusters` | List Neptune clusters (filter by engine) |
| **OpenSearch** | `es:ListDomainNames` | List OpenSearch domains |
| | `es:DescribeDomains` | Get domain details |
| **MemoryDB** | `memorydb:DescribeClusters` | List MemoryDB clusters |
| **Timestream** | `timestream:ListDatabases` | List Timestream databases |
| | `timestream:ListTables` | List tables |
| | `timestream:DescribeTable` | Get table details |
| **AWS Backup** | `backup:ListBackupVaults` | List backup vaults |
| | `backup:ListRecoveryPointsByBackupVault` | List recovery points |
| | `backup:ListBackupPlans` | List backup plans |
| | `backup:GetBackupPlan` | Get plan details |
| | `backup:ListBackupSelections` | List backup selections |
| | `backup:GetBackupSelection` | Get selection details |
| | `backup:ListProtectedResources` | List protected resources |

---

## Azure Permissions

### Recommended: Use Built-in Role

The simplest approach is to assign the built-in **Reader** role at the subscription level:
```
Reader (acdd72a7-3385-48ef-bd42-f606fba81ae7)
```

### Required Role Assignments

For least-privilege access, assign these built-in roles at the subscription level:

| Role | Scope | Purpose |
|------|-------|---------|
| **Reader** | Subscription | Read all resources |

Or use a custom role with these permissions:

### Minimum Required Permissions (Custom Role)

```json
{
    "Name": "CCA CloudShell Reader",
    "Description": "Read-only access for CCA cloud assessment",
    "Actions": [
        "Microsoft.Resources/subscriptions/read",
        
        "Microsoft.Compute/virtualMachines/read",
        "Microsoft.Compute/disks/read",
        "Microsoft.Compute/snapshots/read",
        
        "Microsoft.Storage/storageAccounts/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/read",
        "Microsoft.Storage/storageAccounts/fileServices/shares/read",
        
        "Microsoft.Sql/servers/read",
        "Microsoft.Sql/servers/databases/read",
        "Microsoft.Sql/managedInstances/read",
        
        "Microsoft.DocumentDB/databaseAccounts/read",
        
        "Microsoft.ContainerService/managedClusters/read",
        
        "Microsoft.Web/sites/read",
        
        "Microsoft.RecoveryServices/vaults/read",
        "Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/read",
        "Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems/read",
        "Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems/recoveryPoints/read",
        "Microsoft.RecoveryServices/vaults/backupPolicies/read",
        
        "Microsoft.Cache/redis/read",
        
        "Microsoft.DBforPostgreSQL/flexibleServers/read",
        
        "Microsoft.DBforMySQL/flexibleServers/read",
        
        "Microsoft.DBforMariaDB/servers/read",
        
        "Microsoft.Synapse/workspaces/read",
        "Microsoft.Synapse/workspaces/sqlPools/read",
        
        "Microsoft.NetApp/netAppAccounts/read",
        "Microsoft.NetApp/netAppAccounts/capacityPools/read",
        "Microsoft.NetApp/netAppAccounts/capacityPools/volumes/read"
    ],
    "NotActions": [],
    "AssignableScopes": [
        "/subscriptions/{subscription-id}"
    ]
}
```

### Permissions by Service

| Service | Permission | Purpose |
|---------|------------|---------|
| **Subscriptions** | `Microsoft.Resources/subscriptions/read` | List subscriptions |
| **Virtual Machines** | `Microsoft.Compute/virtualMachines/read` | List VMs |
| **Managed Disks** | `Microsoft.Compute/disks/read` | List disks |
| **Snapshots** | `Microsoft.Compute/snapshots/read` | List snapshots |
| **Storage Accounts** | `Microsoft.Storage/storageAccounts/read` | List storage accounts |
| | `Microsoft.Storage/storageAccounts/blobServices/containers/read` | List blob containers |
| | `Microsoft.Storage/storageAccounts/fileServices/shares/read` | List file shares (Azure Files) |
| **Azure SQL** | `Microsoft.Sql/servers/read` | List SQL servers |
| | `Microsoft.Sql/servers/databases/read` | List databases |
| **SQL Managed Instance** | `Microsoft.Sql/managedInstances/read` | List managed instances |
| **Cosmos DB** | `Microsoft.DocumentDB/databaseAccounts/read` | List Cosmos accounts |
| **AKS** | `Microsoft.ContainerService/managedClusters/read` | List AKS clusters |
| **App Service** | `Microsoft.Web/sites/read` | List web apps/functions |
| **Recovery Services** | `Microsoft.RecoveryServices/vaults/read` | List recovery vaults |
| | `Microsoft.RecoveryServices/vaults/backupFabrics/*/read` | List protected items & recovery points |
| | `Microsoft.RecoveryServices/vaults/backupPolicies/read` | List backup policies |
| **Redis Cache** | `Microsoft.Cache/redis/read` | List Redis instances |
| **PostgreSQL** | `Microsoft.DBforPostgreSQL/flexibleServers/read` | List PostgreSQL Flexible Servers |
| **MySQL** | `Microsoft.DBforMySQL/flexibleServers/read` | List MySQL Flexible Servers |
| **MariaDB** | `Microsoft.DBforMariaDB/servers/read` | List MariaDB servers |
| **Synapse** | `Microsoft.Synapse/workspaces/read` | List Synapse workspaces |
| | `Microsoft.Synapse/workspaces/sqlPools/read` | List dedicated SQL pools |
| **NetApp Files** | `Microsoft.NetApp/netAppAccounts/read` | List NetApp accounts |
| | `Microsoft.NetApp/netAppAccounts/capacityPools/read` | List capacity pools |
| | `Microsoft.NetApp/netAppAccounts/capacityPools/volumes/read` | List volumes |

---

## GCP Permissions

### Recommended: Use Predefined Role

The simplest approach is to grant the **Viewer** predefined role:
```
roles/viewer
```

### Minimum Required Permissions (Custom Role)

For least-privilege access, create a custom role with these permissions:

```yaml
title: CCA CloudShell Reader
description: Read-only access for CCA
includedPermissions:
  # Resource Manager
  - resourcemanager.projects.get
  - resourcemanager.projects.list
  
  # Compute Engine
  - compute.regions.list
  - compute.zones.list
  - compute.instances.list
  - compute.disks.list
  - compute.snapshots.list
  
  # Cloud Storage
  - storage.buckets.list
  - storage.buckets.get
  
  # Cloud SQL
  - cloudsql.instances.list
  - cloudsql.instances.get
  
  # GKE
  - container.clusters.list
  - container.clusters.get
  
  # Cloud Functions
  - cloudfunctions.functions.list
  - cloudfunctions.functions.get
  
  # Filestore
  - file.instances.list
  - file.instances.get
  
  # Memorystore (Redis)
  - redis.instances.list
  - redis.instances.get
  
  # BigQuery
  - bigquery.datasets.get
  - bigquery.datasets.list
  - bigquery.tables.get
  - bigquery.tables.list
  
  # Cloud Spanner
  - spanner.instances.list
  - spanner.instances.get
  - spanner.databases.list
  
  # Bigtable
  - bigtable.instances.list
  - bigtable.instances.get
  - bigtable.clusters.list
  
  # AlloyDB
  - alloydb.clusters.list
  - alloydb.clusters.get
  - alloydb.instances.list
  - alloydb.instances.get
  
  # Backup and DR
  - backupdr.backupVaults.list
  - backupdr.backupVaults.get
  - backupdr.backupPlans.list
  - backupdr.backupPlans.get
  - backupdr.dataSources.list
  - backupdr.dataSources.get
  - backupdr.backups.list
  - backupdr.backups.get
```

### Permissions by Service

| Service | Permission | Purpose |
|---------|------------|---------|
| **Resource Manager** | `resourcemanager.projects.get` | Get project details |
| | `resourcemanager.projects.list` | List accessible projects |
| **Compute Engine** | `compute.regions.list` | List regions |
| | `compute.zones.list` | List zones |
| | `compute.instances.list` | List VM instances |
| | `compute.disks.list` | List persistent disks |
| | `compute.snapshots.list` | List snapshots |
| **Cloud Storage** | `storage.buckets.list` | List buckets |
| | `storage.buckets.get` | Get bucket metadata |
| **Cloud SQL** | `cloudsql.instances.list` | List SQL instances |
| | `cloudsql.instances.get` | Get instance details |
| **GKE** | `container.clusters.list` | List GKE clusters |
| | `container.clusters.get` | Get cluster details |
| **Cloud Functions** | `cloudfunctions.functions.list` | List functions |
| | `cloudfunctions.functions.get` | Get function details |
| **Filestore** | `file.instances.list` | List Filestore instances |
| | `file.instances.get` | Get instance details |
| **Memorystore** | `redis.instances.list` | List Redis instances |
| | `redis.instances.get` | Get instance details |
| **BigQuery** | `bigquery.datasets.list` | List datasets |
| | `bigquery.datasets.get` | Get dataset details |
| | `bigquery.tables.list` | List tables |
| | `bigquery.tables.get` | Get table details (size) |
| **Cloud Spanner** | `spanner.instances.list` | List Spanner instances |
| | `spanner.instances.get` | Get instance details |
| | `spanner.databases.list` | List databases |
| **Bigtable** | `bigtable.instances.list` | List Bigtable instances |
| | `bigtable.instances.get` | Get instance details |
| | `bigtable.clusters.list` | List clusters |
| **AlloyDB** | `alloydb.clusters.list` | List AlloyDB clusters |
| | `alloydb.clusters.get` | Get cluster details |
| | `alloydb.instances.list` | List AlloyDB instances |
| | `alloydb.instances.get` | Get instance details |
| **Backup and DR** | `backupdr.backupVaults.list` | List backup vaults |
| | `backupdr.backupVaults.get` | Get vault details |
| | `backupdr.backupPlans.list` | List backup plans |
| | `backupdr.backupPlans.get` | Get plan details |
| | `backupdr.dataSources.list` | List data sources |
| | `backupdr.dataSources.get` | Get data source details |
| | `backupdr.backups.list` | List backups |
| | `backupdr.backups.get` | Get backup details |

---

## Change Rate Collection Permissions (Optional)

When using the `--include-change-rate` flag, the collectors query cloud monitoring APIs to estimate daily data change rates. These permissions are **optional** - the collector will work without them, but you won't get change rate metrics.

### AWS CloudWatch Permissions

Add these permissions to your IAM policy for change rate collection:

```json
{
    "Sid": "CloudWatchChangeRateMetrics",
    "Effect": "Allow",
    "Action": [
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:GetMetricData"
    ],
    "Resource": "*"
}
```

| Permission | Purpose |
|------------|---------|
| `cloudwatch:GetMetricStatistics` | Query EBS VolumeWriteBytes, RDS WriteIOPS, etc. |
| `cloudwatch:GetMetricData` | Batch query for multiple metrics |

**Metrics collected:**
- EBS: `VolumeWriteBytes` - estimates daily write throughput
- RDS: `WriteIOPS`, `BinLogDiskUsage`, `TransactionLogsDiskUsage` - estimates data and transaction log changes
- S3: `NumberOfObjects` - estimates object churn rate

### Azure Monitor Permissions

Add these permissions to your custom role for change rate collection:

```json
{
    "Actions": [
        "Microsoft.Insights/metrics/read",
        "Microsoft.Insights/metricDefinitions/read"
    ]
}
```

| Permission | Purpose |
|------------|---------|
| `Microsoft.Insights/metrics/read` | Query disk write metrics, SQL log metrics |
| `Microsoft.Insights/metricDefinitions/read` | List available metrics |

**Metrics collected:**
- Managed Disks: `Composite Disk Write Bytes/sec` - estimates daily write throughput
- Azure SQL: `log_write_percent` - estimates transaction log activity

### GCP Cloud Monitoring Permissions

Add these permissions to your custom role for change rate collection:

```yaml
includedPermissions:
  - monitoring.timeSeries.list
  - monitoring.metricDescriptors.list
```

| Permission | Purpose |
|------------|---------|
| `monitoring.timeSeries.list` | Query disk write metrics |
| `monitoring.metricDescriptors.list` | List available metrics |

**Metrics collected:**
- Persistent Disks: `compute.googleapis.com/instance/disk/write_bytes_count` - estimates daily write throughput
- Cloud SQL: `cloudsql.googleapis.com/database/disk/write_ops_count` - estimates database write activity

### Change Rate Output Format

When `--include-change-rate` is specified, collectors output a separate JSON file (`cca_*_change_rates_*.json`) with this structure:

```json
{
  "change_rates": {
    "aws:EBS": {
      "provider": "aws",
      "service_family": "EBS",
      "resource_count": 150,
      "total_size_gb": 5000.0,
      "data_change": {
        "daily_change_gb": 125.5,
        "daily_change_percent": 2.51,
        "sample_days": 7,
        "data_points": 1050
      }
    },
    "aws:RDS": {
      "provider": "aws",
      "service_family": "RDS",
      "resource_count": 10,
      "total_size_gb": 500.0,
      "data_change": {
        "daily_change_gb": 25.0,
        "daily_change_percent": 5.0,
        "sample_days": 7,
        "data_points": 70
      },
      "transaction_logs": {
        "daily_generation_gb": 10.5,
        "capture_rate_percent": 100.0,
        "sample_days": 7,
        "data_points": 70
      }
    }
  },
  "collection_metadata": {
    "collected_at": "2026-02-23T10:30:00Z",
    "sample_period_days": 7,
    "notes": [
      "Data change rates are estimates based on write throughput metrics",
      "Transaction log rates apply to database services (always 100% capture)",
      "Use these values to override default DCR assumptions in sizing tools"
    ]
  }
}
```

---

## Microsoft 365 Permissions

The M365 collector requires an Azure AD App Registration with Microsoft Graph API permissions.

### Setup Requirements

1. **Azure AD App Registration** with:
   - Application (client) ID
   - Client secret or certificate
   - Tenant ID

2. **Microsoft Graph API Permissions** (Application permissions):

### Required Graph API Permissions

| Permission | Type | Purpose |
|------------|------|---------|
| `Sites.Read.All` | Application | Read SharePoint sites |
| `Files.Read.All` | Application | Read OneDrive files/storage |
| `User.Read.All` | Application | Read user profiles & mailbox info |
| `Mail.Read` | Application | Read mailbox metadata |
| `Team.ReadBasic.All` | Application | Read Teams information |
| `Group.Read.All` | Application | Read group membership |
| `Directory.Read.All` | Application | Read Entra ID users/groups |

### App Registration Setup

1. Go to **Azure Portal** → **Azure Active Directory** → **App registrations**
2. Click **New registration**
3. Name: `CCA CloudShell M365 Collector`
4. Supported account types: **Single tenant**
5. Click **Register**
6. Note the **Application (client) ID** and **Directory (tenant) ID**
7. Go to **Certificates & secrets** → **New client secret**
8. Note the secret value (shown only once)
9. Go to **API permissions** → **Add a permission** → **Microsoft Graph** → **Application permissions**
10. Add the permissions listed above
11. Click **Grant admin consent** (requires admin privileges)

### Environment Variables

```bash
export MS365_TENANT_ID="your-tenant-id"
export MS365_CLIENT_ID="your-client-id"
export MS365_CLIENT_SECRET="your-client-secret"
```

### Permission Scopes by Feature

| Feature | Required Permissions |
|---------|---------------------|
| SharePoint Sites | `Sites.Read.All` |
| OneDrive | `Files.Read.All`, `User.Read.All` |
| Exchange Mailboxes | `User.Read.All`, `Mail.Read` |
| Microsoft Teams | `Team.ReadBasic.All`, `Group.Read.All` |
| Entra ID (optional) | `Directory.Read.All`, `User.Read.All`, `Group.Read.All` |

---

## Cost Collector Permissions

The cost collector (`cost_collect.py`) requires additional billing/cost permissions.

> **Important:** Cost collection is separate from inventory collection. The inventory collector
> (`aws_collect.py`) gathers resource data and can run from any account, while the cost collector
> requires access to billing APIs which have different permission models.

### AWS Cost Explorer

> **Critical:** AWS Cost Explorer API is only accessible from the **management account**
> (or a delegated administrator account) in AWS Organizations. Running from a member account
> will return empty or incomplete results.

**Requirements:**
1. Must run from the **management account** (the payer account)
2. Cost Explorer must be enabled (it's enabled by default, but verify in AWS Console → Billing)
3. For multi-account breakdown, use `--org-costs` flag

Add to your IAM policy:

```json
{
    "Sid": "CostExplorerAccess",
    "Effect": "Allow",
    "Action": [
        "ce:GetCostAndUsage",
        "ce:GetCostForecast",
        "ce:GetDimensionValues"
    ],
    "Resource": "*"
}
```

| Permission | Purpose |
|------------|---------|
| `ce:GetCostAndUsage` | Query cost and usage data |
| `ce:GetCostForecast` | Get cost forecasts (optional) |
| `ce:GetDimensionValues` | List available filter values |

#### AWS Organizations Considerations

**Single Organization:** Run cost_collect once from the management account:
```bash
python3 cost_collect.py --aws --org-costs
```

**Multiple Separate Organizations:** If you have multiple independent AWS Organizations
(e.g., from acquisitions), you must run cost_collect separately from each management account:
```bash
# From org1 management account
python3 cost_collect.py --aws --org-costs --profile org1-mgmt -o ./org1/

# From org2 management account  
python3 cost_collect.py --aws --org-costs --profile org2-mgmt -o ./org2/
```

Then merge results using `scripts/merge_batch_outputs.py` if needed.

### Azure Cost Management

Assign the built-in **Cost Management Reader** role, or add to custom role:

```json
{
    "Actions": [
        "Microsoft.CostManagement/query/read",
        "Microsoft.CostManagement/exports/read",
        "Microsoft.Consumption/usageDetails/read"
    ]
}
```

| Permission | Purpose |
|------------|---------|
| `Microsoft.CostManagement/query/read` | Query cost data |
| `Microsoft.Consumption/usageDetails/read` | Read usage details |

### GCP BigQuery Billing

GCP requires billing export to BigQuery. Grant these permissions:

```yaml
includedPermissions:
  - bigquery.jobs.create
  - bigquery.tables.getData
```

| Permission | Scope | Purpose |
|------------|-------|---------|
| `bigquery.jobs.create` | Project | Run queries |
| `bigquery.tables.getData` | Billing table | Read billing data |

**Note:** Before using the GCP cost collector:
1. Enable BigQuery billing export in Cloud Console → Billing → Billing export
2. Wait 24-48 hours for data to populate
3. Grant `BigQuery Data Viewer` role on the billing dataset

---

## Security Best Practices

1. **Use read-only permissions** - The collectors only need read access
2. **Use least-privilege** - Grant only the permissions listed above
3. **Use short-lived credentials** - Rotate secrets regularly
4. **Scope appropriately** - Don't grant permissions broader than needed
5. **Audit access** - Review who has access to the collector credentials
6. **Use managed identities** - When running in cloud environments (CloudShell, VMs)

## Troubleshooting

### AWS
- **AccessDenied**: Missing permission - check the IAM policy
- **UnauthorizedAccess**: Session expired - re-authenticate

### Azure
- **AuthorizationFailed**: Missing role assignment - assign Reader role
- **SubscriptionNotFound**: No access to subscription

### GCP
- **PermissionDenied**: Missing IAM role - grant Viewer role
- **ProjectNotFound**: No access to project

### M365
- **Unauthorized**: Invalid credentials or missing admin consent
- **Forbidden**: Missing Graph API permission
