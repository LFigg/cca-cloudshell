# Getting Started

This guide covers installation and running your first collection.

## Prerequisites

- Python 3.9+
- Access to cloud environment (AWS, Azure, GCP, or M365)
- Appropriate permissions (see [Required Permissions](PERMISSIONS.md))

## Installation

### Option 1: Download and Extract

```bash
curl -sL https://github.com/LFigg/cca-cloudshell/archive/refs/heads/main.tar.gz | tar xz
cd cca-cloudshell-main
./setup.sh
```

### Option 2: Git Clone

```bash
git clone https://github.com/LFigg/cca-cloudshell.git
cd cca-cloudshell
./setup.sh
```

### Option 3: Manual Setup

```bash
# Install Python dependencies
pip install -r requirements.txt

# For specific clouds only:
pip install boto3                    # AWS
pip install azure-identity azure-mgmt-compute azure-mgmt-storage  # Azure (partial)
pip install google-cloud-compute google-cloud-storage  # GCP (partial)
pip install msgraph-sdk azure-identity  # M365
```

## Quick Start

The easiest way to run collection is using the unified entry point:

```bash
# Auto-detect credentials and run
python3 collect.py

# Setup wizard for first-time users
python3 collect.py --setup

# Specify cloud directly
python3 collect.py --cloud aws
python3 collect.py --cloud azure
python3 collect.py --cloud gcp
python3 collect.py --cloud m365
```

The unified collector will:
1. Auto-detect which cloud credentials are configured
2. Verify your credentials and permissions
3. Prompt for optional cost collection (backup spending analysis)
4. Run the appropriate collector(s) automatically

### Interactive Cost Collection

When using the interactive menu, you'll be prompted to include data protection cost collection after selecting a cloud platform:

```
Data protection cost collection analyzes AWS Backup, EBS snapshot,
and other backup-related costs from AWS Cost Explorer.

Also collect data protection costs? [y/N]:
```

This enables collecting both inventory and backup costs in a single workflow.

## Quick Start by Cloud

You can also run collectors directly:

### AWS

```bash
# In AWS CloudShell (credentials automatic)
python3 aws_collect.py

# Local with AWS CLI configured
aws configure  # if not already done
python3 aws_collect.py
```

### Azure

```bash
# In Azure Cloud Shell (credentials automatic)
python3 azure_collect.py

# Local with Azure CLI
az login
python3 azure_collect.py
```

### GCP

```bash
# In Google Cloud Shell (credentials automatic)
python3 gcp_collect.py

# Local with gcloud CLI
gcloud auth application-default login
python3 gcp_collect.py --project my-project-id
```

### Microsoft 365

```bash
# Set credentials (see M365 Collector docs for app registration)
export MS365_TENANT_ID="your-tenant-id"
export MS365_CLIENT_ID="your-client-id"
export MS365_CLIENT_SECRET="your-client-secret"

python3 m365_collect.py
```

## Using Config Files

For repeated runs or complex configurations, use a YAML config file:

```bash
# Generate a sample config
python3 collect.py --generate-config aws > cca-config.yaml

# Edit cca-config.yaml, then run with it
python3 collect.py --config cca-config.yaml
```

See [config-examples/](../config-examples/) for sample configurations.

Config files support environment variable substitution:
```yaml
aws:
  role_arn: ${CCA_ROLE_ARN}              # Required
  external_id: ${CCA_EXTERNAL_ID:-}      # Optional with default
```

## Setting Up Permissions

Use the setup scripts in `setup/` to configure permissions:

```bash
# AWS - Deploy IAM role via CloudFormation
./setup/setup-aws-permissions.sh

# Azure - Assign Reader role to subscriptions
./setup/setup-azure-permissions.sh

# GCP - Grant Viewer role to projects
./setup/setup-gcp-permissions.sh
```

See [Required Permissions](PERMISSIONS.md) for details on what access is needed.

## Output

Each collector generates:

| File | Description |
|------|-------------|
| `cca_<cloud>_inv_<time>.json` | Full resource inventory |
| `cca_<cloud>_sum_<time>.json` | Aggregated summary |
| `cca_log_<time>.log` | Collection log for troubleshooting |

## Progress Display

Collectors show real-time progress with:
- Spinner animation during collection
- Progress bar showing region/subscription progress
- Resource counts as they're discovered
- Summary table at completion

When output is piped (non-TTY), plain text progress messages are shown instead.

## Next Steps

- [Config Examples](../config-examples/README.md) - Sample YAML configurations
- [AWS Collector](collectors/aws.md) - Multi-account, regions, all options
- [Azure Collector](collectors/azure.md) - Subscriptions, resource types
- [GCP Collector](collectors/gcp.md) - Projects, regions, resources
- [M365 Collector](collectors/m365.md) - App registration, permissions
- [Cost Collector](collectors/cost.md) - Backup/snapshot spending
- [Output Formats](output-formats.md) - JSON schema, CSV fields
- [Required Permissions](PERMISSIONS.md) - IAM policies for each cloud
- [Setup Scripts](../setup/README.md) - Automated permission configuration

## Report Generation

After collection, generate reports for analysis:

```bash
# Protection status report
python scripts/generate_protection_report.py cca_aws_inv_*.json protection_report.xlsx

# Comprehensive assessment report (multi-tab Excel)
python scripts/generate_assessment_report.py cca_*_inv_*.json assessment.xlsx

# Include cost data in assessment
python scripts/generate_assessment_report.py cca_aws_inv_*.json --cost cca_cost_*.json -o assessment.xlsx
```

## Privacy and Security

By default, resource IDs are redacted in output files for privacy. Use these flags to control what's included:

```bash
# Include full resource IDs/ARNs in output
python3 aws_collect.py --include-resource-ids
python3 azure_collect.py --include-resource-ids
python3 gcp_collect.py --include-resource-ids

# Azure - include individual recovery points (verbose, can be slow)
python3 azure_collect.py --include-recovery-points
```
