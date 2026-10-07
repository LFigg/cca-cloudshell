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
    azure-mgmt-web azure-mgmt-resource azure-mgmt-subscription \
    azure-mgmt-recoveryservices azure-mgmt-recoveryservicesbackup \
    azure-mgmt-redis azure-mgmt-costmanagement azure-mgmt-rdbms \
    azure-mgmt-synapse azure-mgmt-netapp azure-storage-blob \
    rich tenacity

# GCP only
pip3 install google-cloud-compute google-cloud-storage google-api-python-client \
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
python3 collect.py --cloud aws --profile myprofile
```

#### Option B: Environment Variables

```bash
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_DEFAULT_REGION="us-east-1"

python3 collect.py --cloud aws
```

#### Option C: IAM Role (EC2/ECS)

If running on an EC2 instance or ECS task with an IAM role attached, credentials are automatic.

### Running the Collector

```bash
# Basic collection (all regions)
python3 collect.py --cloud aws

# Specific regions only
python3 collect.py --cloud aws --regions us-east-1,us-west-2,eu-west-1

# Using a specific profile
python3 collect.py --cloud aws --profile production

# Output to custom directory
python3 collect.py --cloud aws -o ./output/

# Output directly to S3
python3 collect.py --cloud aws --output s3://my-bucket/cca-assessments/

# Include full resource IDs/ARNs (default: redact for privacy)
python3 collect.py --cloud aws --include-resource-ids
```

### Multi-Account Collection

```bash
# Single target account via role assumption
python3 collect.py --cloud aws --role-arn arn:aws:iam::123456789012:role/CCACollectorRole

# Multiple accounts explicitly
python3 collect.py --cloud aws --role-arns \
    arn:aws:iam::111111111111:role/CCACollectorRole,\
    arn:aws:iam::222222222222:role/CCACollectorRole

# Auto-discover via AWS Organizations (requires management account access)
python3 collect.py --cloud aws --org-role CCACollectorRole

# With external ID for added security
python3 collect.py --cloud aws --org-role CCACollectorRole --external-id MySecretId

# Skip specific accounts
python3 collect.py --cloud aws --org-role CCACollectorRole --skip-accounts 999999999999
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

python3 collect.py --cloud azure
```

#### Option B: Service Principal

```bash
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"

python3 collect.py --cloud azure
```

#### Option C: Managed Identity (Azure VM)

If running on an Azure VM with a managed identity, credentials are automatic.

### Running the Collector

```bash
# All accessible subscriptions
python3 collect.py --cloud azure

# Specific subscription
python3 collect.py --cloud azure --subscription-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Custom output directory
python3 collect.py --cloud azure -o ./output/

# Include full resource IDs (default: redact for privacy)
python3 collect.py --cloud azure --include-resource-ids

# Include individual recovery points (can be slow for large backup environments)
python3 collect.py --cloud azure --include-recovery-points
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

python3 collect.py --cloud gcp
```

#### Option B: Service Account Key

```bash
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account-key.json"

python3 collect.py --cloud gcp
```

### Running the Collector

```bash
# Default project only
python3 collect.py --cloud gcp

# Specific project
python3 collect.py --cloud gcp --project my-project-id

# All accessible projects
python3 collect.py --cloud gcp --all-projects

# Custom output directory
python3 collect.py --cloud gcp --output ./output/

# Output to GCS
python3 collect.py --cloud gcp --output gs://my-bucket/assessments/

# Include full resource IDs (default: redact for privacy)
python3 collect.py --cloud gcp --include-resource-ids
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
   - `Files.Read.All` (OneDrive)
   - `User.Read.All` (Users, Exchange)
   - `Mail.Read` (Mailbox metadata)
   - `Group.Read.All` (Groups)
   - `Team.ReadBasic.All` (Teams)
   - `Reports.Read.All` (**Critical** — enables fast bulk collection via usage reports API)
   - `Organization.Read.All` (Tenant licensing info)
   - `Directory.Read.All` (Entra ID — optional, for `--include-entra`)

2. **Admin consent** granted for all permissions (requires Global Administrator)

### Authentication

M365 collector requires service principal credentials:

```bash
export MS365_TENANT_ID="your-tenant-id"
export MS365_CLIENT_ID="your-app-client-id"
export MS365_CLIENT_SECRET="your-client-secret"

python3 collect.py --cloud m365
```

### Running the Collector

```bash
# Basic collection
python3 collect.py --cloud m365

# Override tenant/client IDs (secret must be env var)
python3 collect.py --cloud m365 --tenant-id xxx --client-id xxx

# Include Entra ID (Azure AD) collection
python3 collect.py --cloud m365 --include-entra

# Custom output directory
python3 collect.py --cloud m365 -o ./output/
```

---

## Cost Analysis

Cost collection is **integrated** into each cloud collector and runs by default. A `cca_<cloud>_costs_<time>.json` file is written alongside the inventory.

### AWS Costs

```bash
# Costs are collected automatically (requires management account for org-level data)
python3 collect.py --cloud aws

# Skip costs if not needed
python3 collect.py --cloud aws --no-costs

# With a specific profile
python3 collect.py --cloud aws --profile production
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
| `cca_log_<HHMMSS>.log` | Collection log for troubleshooting |

### Generate Reports

```bash
# Generate comprehensive assessment report (multi-tab Excel)
python3 scripts/generate_assessment_report.py \
    --inventory ./output/cca_aws_inv_*.json \
    -o ./output/assessment_report.xlsx

# Include cost data in assessment report (point --cost at the collector's actual
# cca_<cloud>_costs_*.json file - see docs/reports/assessment.md)
python3 scripts/generate_assessment_report.py \
    --inventory ./output/cca_aws_inv_*.json \
    --cost ./output/cca_aws_costs_*.json \
    -o ./output/assessment_report.xlsx
```

---

## Large Environments & Batched Collection

For environments with many accounts (100+), the AWS collector has built-in batching, checkpointing, and parallel collection. These options are passed after `--` to the underlying AWS collector:

```bash
python3 collect.py --cloud aws -- --org-role CCARole --batch-size 25
```

### Automatic Parallel Collection

For large account sets, the collector auto-enables parallel workers (outside CloudShell):

| Account Count | Auto Workers |
|---------------|-------------|
| 100+ | 8 |
| 50–99 | 4 |
| < 50 | 1 (sequential) |

Override with `--parallel-accounts N` or disable with `--no-auto-parallel`.

### Batching with Checkpoints

Use `--batch-size` to split collection into checkpoint-aware batches:

```bash
# Collect 100 accounts in batches of 25 (4 batches)
python3 collect.py --cloud aws -- --org-role CCARole --batch-size 25 -o ./collection/

# Output structure:
# ./collection/
#   ├── batch01/  (accounts 1-25)
#   ├── batch02/  (accounts 26-50)
#   ├── batch03/  (accounts 51-75)
#   ├── batch04/  (accounts 76-100)
#   └── checkpoint.json
```

#### Auto-Merge Behavior

When multiple batches are used, the collector can auto-merge at the end based on collection success rate:

- Default: auto-merge runs when at least **90%** of target accounts succeed.
- Tune with `--auto-merge-threshold <percent>`.
- Failed account IDs are printed in console output and included in summary JSON under `collection_progress.failed_account_ids`.

```bash
# Merge only if 95%+ of accounts succeed
python3 collect.py --cloud aws -- --org-role CCARole --batch-size 25 --auto-merge-threshold 95
```

#### Resume After Interruption

If collection is interrupted (credential expiry, network issue, etc.):

```bash
# Re-authenticate if needed
aws sso login --profile my-org

# Resume from checkpoint — already-completed accounts are skipped
python3 collect.py --cloud aws -- --org-role CCARole --resume ./collection/checkpoint.json
```

### SSO Credential Refresh

For AWS SSO environments where tokens expire during long runs:

```bash
# Auto-refresh SSO between batches
python3 collect.py --cloud aws -- --org-role CCARole --batch-size 20 --sso-refresh -o ./collection/

# Pause N seconds between batches (manual refresh window)
python3 collect.py --cloud aws -- --org-role CCARole --batch-size 20 --pause-between-batches 60 -o ./collection/

# Prompt interactively between batches
python3 collect.py --cloud aws -- --org-role CCARole --batch-size 20 --interactive -o ./collection/
```

### Account Filtering

```bash
# Collect only specific accounts
python3 collect.py --cloud aws -- --org-role CCARole --accounts 111111111111,222222222222

# Load account list from file (one ID per line, # comments supported)
python3 collect.py --cloud aws -- --org-role CCARole --account-file accounts.txt -o ./output/

# Skip specific accounts
python3 collect.py --cloud aws -- --org-role CCARole --skip-accounts 999999999999
```

### Batch by Region (Alternative)

For very large single accounts, split by region and run in parallel:

```bash
# US regions
python3 collect.py --cloud aws --org-role CCARole -- --regions us-east-1,us-west-2 -o ./batch-us/

# EU regions
python3 collect.py --cloud aws --org-role CCARole -- --regions eu-west-1,eu-central-1 -o ./batch-eu/
```

### Merging Batched Outputs

After batched collections, use the merge script to consolidate:

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
4. **Merge all batches:**
   ```bash
   python3 scripts/merge_batch_outputs.py ./myorg/
   ```

5. **Generate reports:**
   ```bash
   python3 scripts/generate_assessment_report.py --inventory ./myorg/*_merged.json -o ./myorg/report.xlsx
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
python3 collect.py --cloud aws --log-level DEBUG
python3 collect.py --cloud azure --log-level DEBUG
python3 collect.py --cloud gcp --log-level DEBUG
```

---

## Security Best Practices

1. **Use least-privilege permissions** - Deploy the CloudFormation template for AWS
2. **Use short-lived credentials** - Prefer `aws sso login` or `az login` over static keys
3. **Don't commit secrets** - Use environment variables for M365 client secret
4. **Audit access** - Collection actions appear in cloud audit logs (CloudTrail, Azure Activity Log, etc.)
5. **Secure output files** - Inventory files contain resource metadata; store securely
