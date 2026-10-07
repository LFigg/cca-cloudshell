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

# Or for one cloud only, install everything that cloud's collector can use
# (see ./setup.sh's per-cloud options, or the Azure/GCP/AWS/M365 sections of
# requirements.in for the full package list).
```

Azure and GCP each split services across many separate packages
(`azure-mgmt-*`, `google-cloud-*`). Installing only a couple of them (e.g.
just `azure-mgmt-compute`) is **not supported** — the collector runs a
mandatory preflight before any collection starts and refuses to proceed if
any package it can use is missing, specifically because a partial install
used to fail silently instead: entire resource types (Synapse, Redis,
NetApp, PostgreSQL/MySQL) or real-usage lookups (blob capacity, file share
usage, change rates) would just be skipped with an easy-to-miss log warning,
producing a collection that looked complete but wasn't. Use `./setup.sh` or
`pip install -r requirements.txt` so nothing is missing.

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
3. Run inventory **and** cost collection together (change rate metrics also enabled by default)
4. Prompt only for optional configuration

### Cost Collection

Cost collection is **on by default** — no extra steps needed for AWS and Azure. Each run writes a `cca_<cloud>_costs_<time>.json` file alongside the inventory. To skip:

```bash
python3 collect.py --cloud aws --no-costs
```

When using the interactive wizard, you'll see:
```
Data protection cost collection is enabled by default.

Skip cost collection? [y/N]:
```

Press Enter (or type `n`) to collect costs, or type `y` to skip.

**GCP cost collection** requires a BigQuery billing export table:
```bash
python3 collect.py --cloud gcp --billing-table my-project.billing.gcp_billing_export_v1_XXXXXX
```
Leave `--billing-table` unset to skip GCP cost collection.

## Quick Start by Cloud

All clouds are accessed through `collect.py`:

### AWS

```bash
# In AWS CloudShell (credentials automatic)
python3 collect.py --cloud aws

# Local with AWS CLI configured
aws configure  # if not already done
python3 collect.py --cloud aws

# Multi-account via Organizations
python3 collect.py --cloud aws --org-role CCARole
```

### Azure

```bash
# In Azure Cloud Shell (credentials automatic)
python3 collect.py --cloud azure

# Local with Azure CLI
az login
python3 collect.py --cloud azure
```

### GCP

```bash
# In Google Cloud Shell (credentials automatic)
python3 collect.py --cloud gcp

# Local with gcloud CLI
gcloud auth application-default login
python3 collect.py --cloud gcp --project my-project-id
```

### Microsoft 365

```bash
# Set credentials (see M365 Collector docs for app registration)
export MS365_TENANT_ID="your-tenant-id"
export MS365_CLIENT_ID="your-client-id"
export MS365_CLIENT_SECRET="your-client-secret"

python3 collect.py --cloud m365
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
- [Cost Collection](collectors/cost.md) - Backup/snapshot spending (integrated by default)
- [Output Formats](output-formats.md) - JSON schema, CSV fields
- [Required Permissions](PERMISSIONS.md) - IAM policies for each cloud
- [Setup Scripts](../setup/README.md) - Automated permission configuration

## Report Generation

After collection, generate reports for analysis:

```bash
# Comprehensive assessment report (multi-tab Excel)
python scripts/generate_assessment_report.py --inventory cca_*_inv_*.json -o assessment.xlsx

# Include cost data in assessment (point --cost at the collector's actual
# cca_<cloud>_costs_*.json file - see docs/reports/assessment.md)
python scripts/generate_assessment_report.py --inventory cca_aws_inv_*.json --cost cca_aws_costs_*.json -o assessment.xlsx
```

## Privacy and Security

By default, resource IDs are redacted in output files for privacy. Use these flags to control what's included:

```bash
# Include full resource IDs/ARNs in output
python3 collect.py --cloud aws --include-resource-ids
python3 collect.py --cloud azure --include-resource-ids
python3 collect.py --cloud gcp --include-resource-ids

# Azure - include individual recovery points (verbose, can be slow)
python3 collect.py --cloud azure --include-recovery-points
```
