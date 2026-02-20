# AWS CloudFormation Templates

This directory contains CloudFormation templates for setting up AWS permissions for the CCA collector.

## Templates

| Template | Purpose |
|----------|---------|
| [aws-iam-role.yaml](aws-iam-role.yaml) | IAM role with read-only permissions for collection |

---

## Quick Start

### Single Account Collection

Deploy the stack in your AWS account:

```bash
aws cloudformation create-stack \
  --stack-name cca-collector \
  --template-body file://setup/aws-iam-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM
```

Then run the collector:

```bash
python3 aws_collect.py
```

### Multi-Account Collection

#### Step 1: Deploy to Management Account

Deploy with Organizations access enabled:

```bash
aws cloudformation create-stack \
  --stack-name cca-collector \
  --template-body file://setup/aws-iam-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters \
    ParameterKey=EnableOrganizationsAccess,ParameterValue=true
```

#### Step 2: Deploy to Member Accounts

Deploy to each member account with cross-account trust:

```bash
# Get your management account ID
MGMT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)

# Deploy to member account (using profile or assumed role)
aws cloudformation create-stack \
  --stack-name cca-collector \
  --template-body file://setup/aws-iam-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters \
    ParameterKey=TrustedAccountId,ParameterValue=$MGMT_ACCOUNT \
    ParameterKey=ExternalId,ParameterValue=your-secret-external-id
```

#### Step 3: Run Multi-Account Collection

```bash
# Auto-discover accounts via Organizations
python3 aws_collect.py --org-role CCACollectorRole --external-id your-secret-external-id

# Or specify explicit role ARNs
python3 aws_collect.py --role-arns \
  arn:aws:iam::111111111111:role/CCACollectorRole,\
  arn:aws:iam::222222222222:role/CCACollectorRole
```

---

## Template Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `RoleName` | `CCACollectorRole` | Name for the IAM role |
| `ExternalId` | *(empty)* | External ID for cross-account security |
| `TrustedAccountId` | *(empty)* | AWS account ID allowed to assume this role |
| `TrustedRoleArn` | *(empty)* | Specific role ARN allowed to assume (more restrictive) |
| `EnableOrganizationsAccess` | `false` | Enable Organizations API access |
| `EnableCostExplorerAccess` | `false` | Enable Cost Explorer API for cost_collect.py |

---

## StackSets for Organization-Wide Deployment

For organizations with many accounts, use CloudFormation StackSets:

```bash
# Create StackSet (from management account)
aws cloudformation create-stack-set \
  --stack-set-name cca-collector-roles \
  --template-body file://setup/aws-iam-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --parameters \
    ParameterKey=TrustedAccountId,ParameterValue=$(aws sts get-caller-identity --query Account --output text) \
    ParameterKey=ExternalId,ParameterValue=your-secret-external-id

# Deploy to all accounts in organization
aws cloudformation create-stack-instances \
  --stack-set-name cca-collector-roles \
  --deployment-targets OrganizationalUnitIds=r-xxxx \
  --regions us-east-1
```

---

## Cleanup

To remove the stack:

```bash
aws cloudformation delete-stack --stack-name cca-collector
```

---

## Permissions Included

The template grants these read-only permissions:

| Service | Permissions |
|---------|-------------|
| **EC2** | DescribeRegions, DescribeInstances, DescribeVolumes, DescribeSnapshots |
| **RDS** | DescribeDBInstances, DescribeDBClusters, DescribeDBSnapshots, DescribeDBClusterSnapshots |
| **S3** | ListAllMyBuckets, GetBucketLocation, GetBucketTagging |
| **EFS** | DescribeFileSystems |
| **FSx** | DescribeFileSystems |
| **EKS** | ListClusters, DescribeCluster, ListNodegroups, DescribeNodegroup |
| **Lambda** | ListFunctions |
| **DynamoDB** | ListTables, DescribeTable |
| **ElastiCache** | DescribeCacheClusters |
| **AWS Backup** | ListBackupVaults, ListRecoveryPointsByBackupVault, ListBackupPlans, GetBackupPlan, ListBackupSelections, GetBackupSelection, ListProtectedResources |
| **Organizations** | ListAccounts, DescribeOrganization, DescribeAccount *(optional)* |
| **Cost Explorer** | GetCostAndUsage, GetCostForecast *(optional)* |

For the complete policy, see [PERMISSIONS.md](../docs/PERMISSIONS.md).
