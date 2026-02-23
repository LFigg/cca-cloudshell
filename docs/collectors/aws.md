# AWS Collector

The AWS collector (`aws_collect.py`) gathers resource inventory from AWS accounts including EC2, RDS, S3, EKS, Lambda, and AWS Backup configurations.

## Basic Usage

```bash
# Collect from current credentials (all enabled regions)
python3 aws_collect.py

# Specific regions
python3 aws_collect.py --regions us-east-1,us-west-2

# Custom output directory
python3 aws_collect.py -o ./my_output/

# Output to S3
python3 aws_collect.py --output s3://my-bucket/assessments/
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
| `--log-level LEVEL` | Logging level (default: INFO) |

## Multi-Account Collection

### Single Role Assumption

Assume a role in a target account:

```bash
python3 aws_collect.py --role-arn arn:aws:iam::123456789012:role/CCARole
```

### Multiple Explicit Accounts

```bash
python3 aws_collect.py --role-arns \
  arn:aws:iam::111111111111:role/CCARole,\
  arn:aws:iam::222222222222:role/CCARole,\
  arn:aws:iam::333333333333:role/CCARole
```

### AWS Organizations Discovery

Auto-discover all accounts and assume a consistently-named role:

```bash
# Discovers accounts via Organizations API
python3 aws_collect.py --org-role CCARole

# Skip specific accounts (e.g., sandbox, suspended)
python3 aws_collect.py --org-role CCARole --skip-accounts 999999999999

# With external ID for additional security
python3 aws_collect.py --org-role CCARole --external-id MySecretExternalId
```

### Multi-Account Setup Requirements

**In the source/management account:**
1. Permission to call `organizations:ListAccounts` (for `--org-role`)
2. Permission to call `sts:AssumeRole` on target roles

**In each target account:**
1. Create a role (e.g., `CCARole`) with:
   - Read-only permissions (see [PERMISSIONS.md](../PERMISSIONS.md))
   - Trust policy allowing the source account

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

| Resource Type | Service Family | Description |
|---------------|----------------|-------------|
| `aws:ec2:instance` | EC2 | Virtual machines |
| `aws:ec2:volume` | EBS | Block storage volumes |
| `aws:ec2:snapshot` | EBSSnapshot | Volume snapshots |
| `aws:rds:instance` | RDS | Database instances |
| `aws:rds:cluster` | RDS | Aurora clusters |
| `aws:rds:snapshot` | RDSSnapshot | DB snapshots |
| `aws:rds:cluster-snapshot` | RDSSnapshot | Cluster snapshots |
| `aws:s3:bucket` | S3 | Object storage buckets |
| `aws:efs:filesystem` | EFS | Elastic file systems |
| `aws:fsx:filesystem` | FSx | Managed file systems |
| `aws:eks:cluster` | EKS | Kubernetes clusters |
| `aws:eks:nodegroup` | EKS | EKS node groups |
| `aws:lambda:function` | Lambda | Serverless functions |
| `aws:dynamodb:table` | DynamoDB | NoSQL tables |
| `aws:elasticache:cluster` | ElastiCache | Cache clusters |
| `aws:redshift:cluster` | Redshift | Data warehouse clusters |
| `aws:docdb:cluster` | DocumentDB | MongoDB-compatible database |
| `aws:neptune:cluster` | Neptune | Graph database |
| `aws:opensearch:domain` | OpenSearch | Search/analytics engine |
| `aws:memorydb:cluster` | MemoryDB | Persistent Redis |
| `aws:timestream:table` | Timestream | Time-series database |
| `aws:backup:vault` | Backup | Backup vaults |
| `aws:backup:recovery-point` | Backup | Recovery points |
| `aws:backup:plan` | Backup | Backup plans |
| `aws:backup:selection` | Backup | Backup selections |
| `aws:backup:protected-resource` | Backup | Protected resources |

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
            "service_family": "EBS",
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
