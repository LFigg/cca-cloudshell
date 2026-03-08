# AWS CloudFormation Templates

CloudFormation templates for setting up AWS permissions for the CCA collector.

## Templates

| Template | Purpose |
|----------|--------|
| [aws-iam-role.yaml](../setup/aws-iam-role.yaml) | IAM role for single account or management account |
| [aws-stackset-member-role.yaml](../setup/aws-stackset-member-role.yaml) | **StackSet template** for organization-wide deployment (100+ accounts) |

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
| `EnableCostExplorerAccess` | `true` | Enable Cost Explorer API for cost_collect.py |

---

## StackSets for Organization-Wide Deployment (100+ Accounts)

For organizations with many accounts, use our dedicated StackSet template for simplified deployment.

### Templates

| Template | Purpose |
|----------|---------|
| [aws-stackset-member-role.yaml](../setup/aws-stackset-member-role.yaml) | **StackSet deployment** - Optimized for member accounts |
| [aws-iam-role.yaml](../setup/aws-iam-role.yaml) | Single account or management account with Organizations access |

### Step 1: Deploy Management Account Role

Deploy to your management account with Organizations access enabled:

```bash
aws cloudformation create-stack \
  --stack-name cca-collector \
  --template-body file://setup/aws-iam-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters \
    ParameterKey=EnableOrganizationsAccess,ParameterValue=true
```

### Step 2: Create StackSet for Member Accounts

```bash
# Get your management account ID
MGMT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)

# Generate a unique external ID (or use your own)
EXTERNAL_ID="cca-$(date +%Y%m%d)-$(openssl rand -hex 4)"
echo "External ID: $EXTERNAL_ID"  # Save this!

# Create the StackSet
aws cloudformation create-stack-set \
  --stack-set-name cca-collector-roles \
  --template-body file://setup/aws-stackset-member-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --parameters \
    ParameterKey=TrustedAccountId,ParameterValue=$MGMT_ACCOUNT \
    ParameterKey=ExternalId,ParameterValue=$EXTERNAL_ID
```

### Step 3: Deploy to All Member Accounts

```bash
# Get your organization root ID
ORG_ROOT=$(aws organizations list-roots --query 'Roots[0].Id' --output text)

# Deploy to all accounts in the organization
aws cloudformation create-stack-instances \
  --stack-set-name cca-collector-roles \
  --deployment-targets OrganizationalUnitIds=$ORG_ROOT \
  --regions us-east-1

# Monitor deployment progress
aws cloudformation list-stack-instances \
  --stack-set-name cca-collector-roles \
  --query 'Summaries[].{Account:Account,Status:Status,Reason:StatusReason}'
```

### Step 4: Run the Collection

```bash
# Using the unified collector (recommended)
python3 collect.py --cloud aws -- \
  --org-role CCACollectorRole \
  --external-id $EXTERNAL_ID \
  --include-change-rate

# Or directly with aws_collect.py  
python3 aws_collect.py \
  --org-role CCACollectorRole \
  --external-id $EXTERNAL_ID \
  --include-change-rate
```

### StackSet Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `TrustedAccountId` | **Yes** | Your management account ID (12 digits) |
| `ExternalId` | **Yes** | Unique external ID for secure cross-account access |
| `RoleName` | No | IAM role name (default: `CCACollectorRole`) |
| `EnableCostExplorerAccess` | No | Enable Cost Explorer API (default: `true`) |

### Monitoring Large Deployments

For 1000+ accounts, deployment may take 15-30 minutes:

```bash
# Check overall status
aws cloudformation describe-stack-set \
  --stack-set-name cca-collector-roles \
  --query 'StackSet.Status'

# Count by status
aws cloudformation list-stack-instances \
  --stack-set-name cca-collector-roles \
  --query 'Summaries[].Status' | sort | uniq -c

# View failed deployments
aws cloudformation list-stack-instances \
  --stack-set-name cca-collector-roles \
  --filters Name=STATUS,Values=FAILED \
  --query 'Summaries[].{Account:Account,Reason:StatusReason}'
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

For the complete policy, see [PERMISSIONS.md](PERMISSIONS.md).
