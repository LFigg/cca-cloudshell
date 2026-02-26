# Running CCA Collectors from an Admin Machine

This guide covers running the CCA collectors from a local workstation or admin machine rather than from within cloud shell environments.

## Prerequisites

- Python 3.9 or higher
- Git (optional, for cloning)
- Network access to cloud provider APIs

```bash
# Check Python version
python3 --version
```

---

## Installation

### Option 1: Clone Repository

```bash
git clone https://github.com/LFigg/cca-cloudshell.git
cd cca-cloudshell
pip3 install -r requirements.txt
```

### Option 2: Download and Extract

```bash
curl -sL https://github.com/LFigg/cca-cloudshell/archive/refs/heads/main.tar.gz | tar xz
cd cca-cloudshell-main
pip3 install -r requirements.txt
```

### Option 3: Install Only Required Dependencies

```bash
# AWS only
pip3 install boto3 rich tenacity

# Azure only
pip3 install azure-identity azure-mgmt-compute azure-mgmt-storage \
    azure-mgmt-sql azure-mgmt-cosmosdb azure-mgmt-containerservice \
    azure-mgmt-web azure-mgmt-resource azure-mgmt-recoveryservices \
    azure-mgmt-recoveryservicesbackup rich tenacity

# GCP only
pip3 install google-cloud-compute google-cloud-storage google-cloud-sql \
    google-cloud-container google-cloud-functions google-cloud-resource-manager \
    rich tenacity

# M365 only
pip3 install msgraph-sdk azure-identity rich tenacity
```

---

## AWS Collection

### Authentication Options

#### Option A: AWS CLI Profile (Recommended)

```bash
# Configure AWS CLI with your credentials
aws configure

# Or use a named profile
aws configure --profile myprofile
python3 aws_collect.py --profile myprofile
```

#### Option B: Environment Variables

```bash
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_DEFAULT_REGION="us-east-1"

python3 aws_collect.py
```

#### Option C: IAM Role (EC2/ECS)

If running on an EC2 instance or ECS task with an IAM role attached, credentials are automatic.

### Running the Collector

```bash
# Basic collection (all regions)
python3 aws_collect.py

# Specific regions only
python3 aws_collect.py --regions us-east-1,us-west-2,eu-west-1

# Using a specific profile
python3 aws_collect.py --profile production

# Output to custom directory
python3 aws_collect.py -o ./output/

# Output directly to S3
python3 aws_collect.py --output s3://my-bucket/cca-assessments/

# Include full resource IDs/ARNs (default: redact for privacy)
python3 aws_collect.py --include-resource-ids
```

### Multi-Account Collection

```bash
# Single target account via role assumption
python3 aws_collect.py --role-arn arn:aws:iam::123456789012:role/CCACollectorRole

# Multiple accounts explicitly
python3 aws_collect.py --role-arns \
    arn:aws:iam::111111111111:role/CCACollectorRole,\
    arn:aws:iam::222222222222:role/CCACollectorRole

# Auto-discover via AWS Organizations (requires management account access)
python3 aws_collect.py --org-role CCACollectorRole

# With external ID for added security
python3 aws_collect.py --org-role CCACollectorRole --external-id MySecretId

# Skip specific accounts
python3 aws_collect.py --org-role CCACollectorRole --skip-accounts 999999999999
```

### IAM Setup via CloudFormation

```bash
# Deploy IAM role to target account
aws cloudformation create-stack \
    --stack-name cca-collector \
    --template-body file://setup/aws-iam-role.yaml \
    --capabilities CAPABILITY_NAMED_IAM

# For cross-account access from management account
aws cloudformation create-stack \
    --stack-name cca-collector \
    --template-body file://setup/aws-iam-role.yaml \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameters \
        ParameterKey=TrustedAccountId,ParameterValue=<MGMT_ACCOUNT_ID> \
        ParameterKey=ExternalId,ParameterValue=<YOUR_EXTERNAL_ID>
```

---

## Azure Collection

### Authentication Options

#### Option A: Azure CLI (Recommended)

```bash
# Login interactively
az login

# For specific tenant
az login --tenant <tenant-id>

# Verify login
az account show

python3 azure_collect.py
```

#### Option B: Service Principal

```bash
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"

python3 azure_collect.py
```

#### Option C: Managed Identity (Azure VM)

If running on an Azure VM with a managed identity, credentials are automatic.

### Running the Collector

```bash
# All accessible subscriptions
python3 azure_collect.py

# Specific subscription
python3 azure_collect.py --subscription-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Custom output directory
python3 azure_collect.py -o ./output/

# Include full resource IDs (default: redact for privacy)
python3 azure_collect.py --include-resource-ids

# Include individual recovery points (can be slow for large backup environments)
python3 azure_collect.py --include-recovery-points
```

### Required Permissions

Assign **Reader** role at subscription or management group level:

```bash
# Get current user's object ID
USER_ID=$(az ad signed-in-user show --query id -o tsv)

# Assign Reader role at subscription level
az role assignment create \
    --assignee $USER_ID \
    --role "Reader" \
    --scope /subscriptions/<subscription-id>
```

---

## GCP Collection

### Authentication Options

#### Option A: gcloud CLI (Recommended)

```bash
# Login and set application default credentials
gcloud auth application-default login

# Set default project (optional)
gcloud config set project my-project-id

python3 gcp_collect.py
```

#### Option B: Service Account Key

```bash
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account-key.json"

python3 gcp_collect.py
```

### Running the Collector

```bash
# Default project only
python3 gcp_collect.py

# Specific project
python3 gcp_collect.py --project my-project-id

# All accessible projects
python3 gcp_collect.py --all-projects

# Custom output directory
python3 gcp_collect.py --output ./output/

# Output to GCS
python3 gcp_collect.py --output gs://my-bucket/assessments/

# Include full resource IDs (default: redact for privacy)
python3 gcp_collect.py --include-resource-ids
```

### Required Permissions

Create a custom role or use predefined Viewer role:

```bash
# Assign Viewer role at project level
gcloud projects add-iam-policy-binding PROJECT_ID \
    --member="user:you@example.com" \
    --role="roles/viewer"
```

---

## Microsoft 365 Collection

### Prerequisites

1. **Azure AD App Registration** with the following API permissions (Application type):
   - `Sites.Read.All` (SharePoint)
   - `User.Read.All` (Users, OneDrive, Exchange)
   - `Group.Read.All` (Groups, Teams)
   - `TeamSettings.Read.All` (Teams details)

2. **Admin consent** granted for the permissions

### Authentication

M365 collector requires service principal credentials:

```bash
export MS365_TENANT_ID="your-tenant-id"
export MS365_CLIENT_ID="your-app-client-id"
export MS365_CLIENT_SECRET="your-client-secret"

python3 m365_collect.py
```

### Running the Collector

```bash
# Basic collection
python3 m365_collect.py

# Override tenant/client IDs (secret must be env var)
python3 m365_collect.py --tenant-id xxx --client-id xxx

# Include Entra ID (Azure AD) collection
python3 m365_collect.py --include-entra

# Custom output directory
python3 m365_collect.py -o ./output/
```

---

## Cost Analysis

### AWS Costs

```bash
# Analyze backup/snapshot costs (last 30 days)
python3 cost_collect.py --aws

# Custom date range
python3 cost_collect.py --aws --start-date 2026-01-01 --end-date 2026-01-31

# Using a profile
python3 cost_collect.py --aws --profile production
```

Requires `ce:GetCostAndUsage` permission. Enable with CloudFormation:

```bash
aws cloudformation create-stack \
    --stack-name cca-collector \
    --template-body file://setup/aws-iam-role.yaml \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameters ParameterKey=EnableCostExplorerAccess,ParameterValue=true
```

---

## Output Files

Each collector generates three files:

| File | Description |
|------|-------------|
| `cca_<cloud>_inv_<HHMMSS>.json` | Full resource inventory |
| `cca_<cloud>_sum_<HHMMSS>.json` | Aggregated summary |

### Generate Reports

```bash
# Generate protection status report from inventory
python3 scripts/generate_protection_report.py \
    ./output/cca_aws_inv_143052.json \
    ./output/protection_report.xlsx

# Generate comprehensive assessment report (multi-tab Excel)
python3 scripts/generate_assessment_report.py \
    ./output/cca_aws_inv_*.json \
    -o ./output/assessment_report.xlsx

# Include cost data in assessment report
python3 scripts/generate_assessment_report.py \
    ./output/cca_aws_inv_*.json \
    --cost ./output/cca_cost_*.json \
    -o ./output/assessment_report.xlsx
```

---

## Large Environments & Batched Collection

For environments with many accounts (100+), you may need to batch collection to avoid credential timeout issues (AWS SSO tokens expire after 1 hour).

### Automatic Batching (Recommended)

The collector supports automatic batching with checkpoint/resume capability:

```bash
# Auto-batch 100+ accounts into groups of 25
python3 aws_collect.py --org-role CCARole --batch-size 25 -o ./collection/

# Output structure:
# ./collection/
#   ├── batch01/
#   │   ├── cca_aws_inv_143052.json
#   │   └── cca_aws_sum_143052.json
#   ├── batch02/
#   │   └── ...
#   └── checkpoint.json
```

#### Resume After Failure/Timeout

If collection is interrupted (credential expiry, network issue, etc.), resume from where you left off:

```bash
# Re-authenticate if needed
aws sso login --profile my-org

# Resume using the checkpoint file
python3 aws_collect.py --org-role CCARole --resume ./collection/checkpoint.json
```

The checkpoint tracks:
- Completed accounts (skipped on resume)
- Failed accounts (with suggested retry command)
- In-progress account (automatically retried)

#### Retry Failed Accounts Only

```bash
# The checkpoint output shows which accounts failed
# Re-run just those accounts:
python3 aws_collect.py --org-role CCARole \
    --accounts 111111111111,222222222222,333333333333 \
    -o ./collection/retry/
```

#### Pause Between Batches (for SSO)

For AWS SSO environments, pause between batches to allow manual credential refresh:

```bash
# Pause 60 seconds between batches
python3 aws_collect.py --org-role CCARole \
    --batch-size 20 \
    --pause-between-batches 60 \
    -o ./collection/
```

### Account List from File

For complex environments, maintain an account list file:

```bash
# accounts.txt - one account ID per line, supports comments
# Production accounts
111111111111
222222222222

# Development accounts
333333333333
444444444444

# Run collection
python3 aws_collect.py --org-role CCARole --account-file accounts.txt -o ./output/
```

### Manual Batching (Alternative)

For more control, manually specify account groups:

```bash
# Batch 1: First 50 accounts
python3 aws_collect.py --role-arns \
    arn:aws:iam::111111111111:role/CCARole,\
    arn:aws:iam::222222222222:role/CCARole \
    -o ./org1/batch1/

# Batch 2: Next 50 accounts  
python3 aws_collect.py --role-arns \
    arn:aws:iam::333333333333:role/CCARole,\
    arn:aws:iam::444444444444:role/CCARole \
    -o ./org1/batch2/
```

### Strategy: Batch by Region

For very large accounts, split by region instead of account:

```bash
# US regions
python3 aws_collect.py --org-role CCARole --regions us-east-1,us-west-2 -o ./batch-us/

# EU regions
python3 aws_collect.py --org-role CCARole --regions eu-west-1,eu-central-1 -o ./batch-eu/
```

### Merging Batched Outputs

After running batched collections, use the merge script to consolidate:

```bash
# Merge all batches in an org folder (looks in subfolders)
python3 scripts/merge_batch_outputs.py ./collection/

# Merge specific batch folders
python3 scripts/merge_batch_outputs.py ./batch1/ ./batch2/ ./batch3/ -o ./merged/

# Process multiple orgs, one merged output per org
python3 scripts/merge_batch_outputs.py ./org1/ ./org2/ ./org3/ --per-folder

# Dry run to preview what would be merged
python3 scripts/merge_batch_outputs.py ./collection/ --dry-run
```

The merge script:
- Deduplicates resources by `account_id:resource_id`
- Re-aggregates summary totals correctly
- Merges cost data if present

### Recommended Workflow for 100+ Accounts

1. **Initial run with auto-batching:**
   ```bash
   python3 aws_collect.py --org-role CCARole --batch-size 25 -o ./myorg/
   ```

2. **If interrupted, resume:**
   ```bash
   aws sso login --profile my-org  # Refresh credentials
   python3 aws_collect.py --org-role CCARole --resume ./myorg/checkpoint.json
   ```

3. **Retry any failed accounts:**
   ```bash
   python3 aws_collect.py --org-role CCARole --accounts <failed-ids> -o ./myorg/retry/
   ```

4. **Merge all batches:**
   ```bash
   python3 scripts/merge_batch_outputs.py ./myorg/
   ```

5. **Generate reports:**
   ```bash
   python3 scripts/generate_protection_report.py ./myorg/*_merged.json ./myorg/report.xlsx
   ```

### Recommended Folder Structure for Multi-Org

```
assessments/
├── org1-production/
│   ├── batch1/
│   │   ├── cca_aws_inv_143052.json
│   │   └── cca_aws_sum_143052.json
│   ├── batch2/
│   │   └── ...
│   └── cost_collect_output.json
├── org2-development/
│   └── ...
└── merged/
    ├── org1-production/
    │   └── cca_aws_inv_150000_merged.json
    └── org2-development/
        └── ...
```

---

## Troubleshooting

### Verify Dependencies

```bash
python3 tests/test_cloudshell_compat.py
```

### Common Issues

**AWS: "Unable to locate credentials"**
```bash
aws configure list  # Check credential source
aws sts get-caller-identity  # Test credentials
```

**Azure: "DefaultAzureCredential failed"**
```bash
az account show  # Verify login
az account list  # List accessible subscriptions
```

**GCP: "Could not automatically determine credentials"**
```bash
gcloud auth application-default print-access-token  # Test ADC
gcloud config get-value project  # Check default project
```

**M365: "AADSTS7000215: Invalid client secret"**
- Verify `MS365_CLIENT_SECRET` environment variable
- Check if secret has expired in Azure AD app registration

### Debug Mode

```bash
python3 aws_collect.py --log-level DEBUG
python3 azure_collect.py --log-level DEBUG
python3 gcp_collect.py --log-level DEBUG
```

---

## Security Best Practices

1. **Use least-privilege permissions** - Deploy the CloudFormation template for AWS
2. **Use short-lived credentials** - Prefer `aws sso login` or `az login` over static keys
3. **Don't commit secrets** - Use environment variables for M365 client secret
4. **Audit access** - Collection actions appear in cloud audit logs (CloudTrail, Azure Activity Log, etc.)
5. **Secure output files** - Inventory files contain resource metadata; store securely
