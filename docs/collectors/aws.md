# AWS Collector

The AWS collector gathers resource inventory from AWS accounts including EC2, RDS, S3, EKS, Lambda, and AWS Backup configurations. It also collects data protection cost data from Cost Explorer by default.

## Basic Usage

```bash
# Collect from current credentials (all enabled regions)
python3 collect.py --cloud aws

# Specific regions
python3 collect.py --cloud aws --regions us-east-1,us-west-2

# Custom output directory
python3 collect.py --cloud aws -o ./my_output/

# Output to S3
python3 collect.py --cloud aws --output s3://my-bucket/assessments/

# Include full resource IDs/ARNs (default: redact for privacy)
python3 collect.py --cloud aws --include-resource-ids

# Skip cost collection (costs collected by default)
python3 collect.py --cloud aws --no-costs
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `--profile PROFILE` | AWS CLI profile name |
| `--regions REGIONS` | Comma-separated regions (default: all enabled) |
| `-o, --output PATH` | Output directory or S3 path |
| `--role-arn ARN` | Single role ARN to assume |
| `--role-arns ARNS` | Multiple role ARNs (comma-separated) |
| `--org-role NAME` | Role name for Organizations discovery |
| `--external-id ID` | External ID for role assumption |
| `--skip-accounts IDS` | Account IDs to skip (comma-separated) |
| `--include-resource-ids` | Include full resource IDs/ARNs (default: redact) |
| `--skip-change-rate` | Skip change rate metrics collection |
| `--skip-storage-sizes` | Skip storage size metrics collection |
| `--change-rate-days N` | Days to sample for change rate (default: 7) |
| `--skip-pvc` | Skip PVC collection from EKS clusters |
| `--no-costs` | Skip data protection cost collection (costs are ON by default) |
| `--parallel-accounts N` | Parallel workers for multi-account (default: auto) |
| `--parallel-regions N` | Parallel workers for regions (default: 4) |
| `--log-level LEVEL` | Logging level (default: INFO) |

## Multi-Account Collection

### Single Role Assumption

Assume a role in a target account:

```bash
python3 collect.py --cloud aws --role-arn arn:aws:iam::123456789012:role/CCARole
```

### Multiple Explicit Accounts

```bash
python3 collect.py --cloud aws --role-arns \
  arn:aws:iam::111111111111:role/CCARole,\
  arn:aws:iam::222222222222:role/CCARole,\
  arn:aws:iam::333333333333:role/CCARole
```

### AWS Organizations Discovery

Auto-discover all accounts and assume a consistently-named role:

```bash
# Discovers accounts via Organizations API
python3 collect.py --cloud aws --org-role CCARole

# Skip specific accounts (e.g., sandbox, suspended)
python3 collect.py --cloud aws --org-role CCARole --skip-accounts 999999999999

# With external ID for additional security
python3 collect.py --cloud aws --org-role CCARole --external-id MySecretExternalId
```

### Multi-Account Setup Requirements

**In the source/management account:**
1. Permission to call `organizations:ListAccounts` (for `--org-role`)
2. Permission to call `organizations:DescribeOrganization` (org metadata in output)
3. Permission to call `organizations:ListParents`, `organizations:DescribeOrganizationalUnit`, and `organizations:ListRoots` (OU metadata enrichment)
4. Permission to call `sts:AssumeRole` on target roles

**In each target account:**
1. Create a role (e.g., `CCARole`) with:
   - Read-only permissions (see [PERMISSIONS.md](../PERMISSIONS.md))
   - Trust policy allowing the source account

### Large-Scale Deployment (100+ Accounts)

For organizations with many accounts, use CloudFormation StackSets for automated IAM role deployment:

```bash
# Deploy to all member accounts via StackSet
aws cloudformation create-stack-set \
  --stack-set-name cca-collector-roles \
  --template-body file://setup/aws-stackset-member-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --parameters \
    ParameterKey=TrustedAccountId,ParameterValue=<MGMT_ACCOUNT_ID> \
    ParameterKey=ExternalId,ParameterValue=<YOUR_EXTERNAL_ID>
```

See [AWS CloudFormation & StackSets](../aws-cloudformation.md) for complete deployment instructions.

**Example Trust Policy:**
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

## Collected Resources

| Resource Type | Service Family | Size Data | Description |
|---------------|----------------|-----------|-------------|
| `aws:ec2:instance` | EC2 | n/a (sized via volumes) | Virtual machines |
| `aws:ec2:volume` | EC2 | Provisioned (this is the volume's actual size) | Block storage volumes |
| `aws:ec2:snapshot` | EC2 | ⚠️ Unavailable | Volume snapshots |
| `aws:rds:instance` | RDS | ✅ Actual usage (CloudWatch `FreeStorageSpace`), when available | Database instances |
| `aws:rds:cluster` | RDS | ✅ Actual usage for Aurora (CloudWatch `VolumeBytesUsed`); ⚠️ Unavailable for non-Aurora (e.g. Multi-AZ DB Cluster) | Aurora / Multi-AZ DB clusters |
| `aws:rds:snapshot` | RDS | ⚠️ Unavailable | DB snapshots |
| `aws:rds:cluster-snapshot` | RDS | ⚠️ Unavailable | Cluster snapshots |
| `aws:s3:bucket` | S3 | ✅ Actual usage (CloudWatch), only with `--include-storage-sizes`; ⚠️ Unavailable otherwise | Object storage buckets |
| `aws:efs:filesystem` | EFS | ✅ Actual usage | Elastic file systems |
| `aws:fsx:filesystem` | FSx | ⚠️ Unavailable | Managed file systems |
| `aws:eks:cluster` | EKS | n/a | Kubernetes clusters |
| `aws:eks:nodegroup` | EKS | n/a | EKS node groups |
| `aws:lambda:function` | Lambda | ✅ Actual usage (deployed code size) | Serverless functions |
| `aws:dynamodb:table` | DynamoDB | ✅ Actual usage | NoSQL tables |
| `aws:elasticache:cluster` | ElastiCache | ⚠️ Unavailable | Cache clusters |
| `aws:redshift:cluster` | Redshift | ✅ Actual usage (CloudWatch `PercentageDiskSpaceUsed`), when available; ⚠️ Unavailable otherwise | Data warehouse clusters |
| `aws:docdb:cluster` | DocumentDB | ⚠️ Unavailable | MongoDB-compatible database |
| `aws:neptune:cluster` | Neptune | ⚠️ Unavailable | Graph database |
| `aws:opensearch:domain` | OpenSearch | ⚠️ Unavailable | Search/analytics engine |
| `aws:memorydb:cluster` | MemoryDB | ⚠️ Unavailable | Persistent Redis |
| `aws:timestream:table` | Timestream | ⚠️ Unavailable | Time-series database |
| `aws:backup:vault` | Backup | n/a | Backup vaults |
| `aws:backup:recovery-point` | Backup | ✅ Actual usage | Recovery points |
| `aws:backup:plan` | Backup | n/a | Backup plans |
| `aws:backup:selection` | Backup | n/a | Backup selections |
| `aws:backup:protected-resource` | Backup | n/a | Protected resources |
| `aws:backup:region-settings` | Backup | n/a | Backup service opt-in preferences (one per region) |
| `aws:dlm:lifecycle-policy` | Backup | n/a | Data Lifecycle Manager snapshot policy definitions |

**Size Data** reflects whether `size_gb` is a real, measured value or currently unavailable (reported as
`0.0`, never a provisioned/allocated estimate) — see each resource's `metadata.size_source` in the output
JSON (`'usage'`, `'unavailable'`, or `'not_applicable'`), and `data_quality` in the summary JSON for a
collection-wide rollup. "Unavailable" resource types are candidates for future real-usage collection work,
tracked in `docs/v2-refactor-plan.md` (internal, not shipped) — not a bug, just not wired up yet.

## Cost Collection

AWS cost collection queries the Cost Explorer API for data protection spending (AWS Backup, EBS snapshots, RDS backup storage, S3 backup storage). It runs automatically at the end of each collection and writes `cca_aws_costs_<time>.json`.

> **Important:** Cost Explorer is only accessible from the **management/payer account** in AWS Organizations. Running from a member account will return empty results.

```bash
# Costs on by default — no flag needed
python3 collect.py --cloud aws

# Skip costs
python3 collect.py --cloud aws --no-costs
```

Required IAM permissions for cost collection:
```json
{
    "Action": ["ce:GetCostAndUsage"],
    "Resource": "*"
}
```

CloudWatch metric permissions for inventory/change-rate collection should include both:
- `cloudwatch:GetMetricStatistics`
- `cloudwatch:GetMetricData`

## Example Output

**Summary JSON:**
```json
{
    "run_id": "20260211-143052-abc123",
    "timestamp": "2026-02-11T14:30:52.123456Z",
    "provider": "aws",
    "account_id": "123456789012",
    "total_resources": 250,
    "total_capacity_gb": 15000.5,
    "summaries": [
        {
            "provider": "aws",
            "service_family": "EC2",
            "resource_type": "aws:ec2:instance",
            "resource_count": 50,
            "total_gb": 0
        },
        {
            "provider": "aws",
            "service_family": "EC2",
            "resource_type": "aws:ec2:volume",
            "resource_count": 80,
            "total_gb": 8000
        }
    ]
}
```

**Multi-Account Summary:**
```json
{
    "account_id": ["111111111111", "222222222222", "333333333333"],
    "accounts": [
        {"account_id": "111111111111", "account_name": "Production", "resource_count": 150},
        {"account_id": "222222222222", "account_name": "Development", "resource_count": 75},
        {"account_id": "333333333333", "account_name": "Staging", "resource_count": 25}
    ],
    "total_resources": 250
}
```

## Required Permissions

See [AWS Permissions](../PERMISSIONS.md#aws-permissions) for the complete IAM policy.

Minimum permissions include:
- `ec2:Describe*` - EC2, EBS, snapshots
- `rds:Describe*` - RDS instances, clusters, snapshots
- `s3:ListAllMyBuckets`, `s3:GetBucketLocation` - S3
- `backup:List*`, `backup:Get*` - AWS Backup
- `sts:AssumeRole` - Multi-account (if using)
- `organizations:ListAccounts` - Organizations discovery (if using)
