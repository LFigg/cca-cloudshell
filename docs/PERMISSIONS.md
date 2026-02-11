# CCA CloudShell - Required Permissions

This document details the minimum permissions required to run each cloud collector.

## Table of Contents
- [AWS Permissions](#aws-permissions)
- [Azure Permissions](#azure-permissions)
- [GCP Permissions](#gcp-permissions)
- [Microsoft 365 Permissions](#microsoft-365-permissions)

---

## AWS Permissions

### Recommended: Use AWS Managed Policy

The simplest approach is to use the AWS managed policy:
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
                
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                
                "elasticfilesystem:DescribeFileSystems",
                
                "fsx:DescribeFileSystems",
                
                "eks:ListClusters",
                "eks:DescribeCluster",
                "eks:ListNodegroups",
                "eks:DescribeNodegroup",
                
                "lambda:ListFunctions",
                "lambda:GetFunction",
                
                "dynamodb:ListTables",
                "dynamodb:DescribeTable",
                
                "elasticache:DescribeCacheClusters",
                
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
| **S3** | `s3:ListAllMyBuckets` | List S3 buckets |
| | `s3:GetBucketLocation` | Get bucket region |
| **EFS** | `elasticfilesystem:DescribeFileSystems` | List EFS file systems |
| **FSx** | `fsx:DescribeFileSystems` | List FSx file systems |
| **EKS** | `eks:ListClusters` | List EKS clusters |
| | `eks:DescribeCluster` | Get cluster details |
| | `eks:ListNodegroups` | List node groups |
| | `eks:DescribeNodegroup` | Get node group details |
| **Lambda** | `lambda:ListFunctions` | List Lambda functions |
| | `lambda:GetFunction` | Get function details |
| **DynamoDB** | `dynamodb:ListTables` | List DynamoDB tables |
| | `dynamodb:DescribeTable` | Get table details |
| **ElastiCache** | `elasticache:DescribeCacheClusters` | List ElastiCache clusters |
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
        
        "Microsoft.Cache/redis/read"
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
| **Backup and DR** | `backupdr.backupVaults.list` | List backup vaults |
| | `backupdr.backupVaults.get` | Get vault details |
| | `backupdr.backupPlans.list` | List backup plans |
| | `backupdr.backupPlans.get` | Get plan details |
| | `backupdr.dataSources.list` | List data sources |
| | `backupdr.dataSources.get` | Get data source details |
| | `backupdr.backups.list` | List backups |
| | `backupdr.backups.get` | Get backup details |

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
