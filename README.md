# CCA CloudShell

Cloud resource assessment collectors for AWS, Azure, GCP, and Microsoft 365.

## What It Does

Collects cloud resource inventory including:
- Compute (VMs, containers, serverless)
- Storage (block, object, file)
- Databases (managed SQL, NoSQL)
- Snapshots and backups
- Protection status analysis
- Backup/snapshot cost analysis
- Data change rate metrics (optional)

## Quick Start

```bash
# Download and setup
curl -sL https://github.com/LFigg/cca-cloudshell/archive/refs/heads/main.tar.gz | tar xz
cd cca-cloudshell-main && ./setup.sh

# Run the unified collector (recommended)
python3 collect.py              # Auto-detects cloud credentials and runs
python3 collect.py --setup      # Interactive setup wizard for first-time users
python3 collect.py --cloud aws  # Specify cloud explicitly
```

## Unified Collector

`collect.py` is the single entry point for all cloud collection. It:
- **Auto-detects** configured cloud credentials
- **Verifies permissions** before collection
- **Collects costs by default** — data protection cost data (AWS Backup, Azure Backup, GCP snapshot costs) is collected alongside inventory with no extra steps
- **Interactive wizard** for first-time users (`--setup`)

```bash
# Auto-detect and run (single cloud detected = runs automatically)
python3 collect.py

# Setup wizard - configure credentials and test permissions
python3 collect.py --setup

# Specify cloud and options directly
python3 collect.py --cloud aws
python3 collect.py --cloud aws --org-role CCARole --regions us-east-1
python3 collect.py --cloud azure --subscription-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
python3 collect.py --cloud gcp --all-projects --billing-table proj.dataset.table
python3 collect.py --cloud m365

# Skip permission verification
python3 collect.py --cloud aws --skip-check

# Skip cost collection (costs are ON by default)
python3 collect.py --cloud aws --no-costs

# Show cloud-specific options
python3 collect.py --cloud aws --help-collector
```

## Output

Each collector generates:
- `cca_<cloud>_inv_<time>.json` - Full resource inventory
- `cca_<cloud>_sum_<time>.json` - Aggregated summary
- `cca_log_<time>.log` - Collection log for troubleshooting

## Features

- **Progress Tracking**: Rich terminal UI with spinners, progress bars, and resource counts (falls back to plain text when piping output)
- **Retry Logic**: Automatic retry with exponential backoff for transient API failures
- **Multi-Account/Project**: Collect across all accessible accounts, subscriptions, or projects
- **Cloud Shell Ready**: Works out of the box in AWS, Azure, and Google Cloud Shell environments

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](docs/getting-started.md) | Installation and first run |
| [Admin Machine Setup](docs/admin-machine-setup.md) | Running from local workstation |
| [AWS Collector](docs/collectors/aws.md) | Multi-account, regions, options |
| [Azure Collector](docs/collectors/azure.md) | Subscriptions, resources |
| [GCP Collector](docs/collectors/gcp.md) | Projects, regions, resources |
| [M365 Collector](docs/collectors/m365.md) | App registration, Graph API |
| [Cost Collection](docs/collectors/cost.md) | Integrated backup/snapshot cost collection |
| [Required Permissions](docs/PERMISSIONS.md) | IAM policies for each cloud |
| [AWS CloudFormation & StackSets](docs/aws-cloudformation.md) | IAM role deployment for 100+ accounts |
| [Permission Setup Scripts](setup/README.md) | Setup scripts for Azure/GCP |
| [Config Examples](config-examples/README.md) | YAML config file examples |
| [Output Formats](docs/output-formats.md) | JSON schema, CSV fields |
| [Troubleshooting](docs/troubleshooting.md) | Common errors and solutions |

## Common Options

```bash
# AWS - multi-account via Organizations
python3 collect.py --cloud aws --org-role CCARole

# AWS - specific regions
python3 collect.py --cloud aws --regions us-east-1,us-west-2

# Azure - specific subscription
python3 collect.py --cloud azure --subscription-id xxx

# GCP - all projects
python3 collect.py --cloud gcp --all-projects

# GCP - with cost collection (requires BigQuery billing export)
python3 collect.py --cloud gcp --billing-table my-project.billing.gcp_billing_export_v1_XXXXXX

# Custom output directory
python3 collect.py --cloud aws -o ./my_output/

# Include full resource IDs/ARNs in output (default: redact for privacy)
python3 collect.py --cloud aws --include-resource-ids

# Azure - include individual recovery points (slow for large environments)
python3 collect.py --cloud azure --include-recovery-points

# Skip change rate metrics (faster collection)
python3 collect.py --cloud aws --skip-change-rate

# Skip cost collection (costs are collected by default for AWS and Azure)
python3 collect.py --cloud aws --no-costs
```

### Cost Collection

Cost collection (backup/snapshot spending) is **enabled by default** for AWS and Azure — no extra steps needed. Each collection run produces a `cca_<cloud>_costs_<time>.json` file alongside the inventory.

- **AWS**: queries Cost Explorer (requires management account for org-level breakdowns)
- **Azure**: queries Cost Management API
- **GCP**: requires `--billing-table` pointing to a BigQuery billing export

To skip cost collection, use `--no-costs`. When using the interactive wizard, you'll be asked "Skip cost collection? [y/N]".

### Change Rate Collection

Change rate metrics are collected by default from CloudWatch/Monitor. Use `--skip-change-rate` or `--change-rate-days` to customize:

```bash
python3 collect.py --cloud aws --change-rate-days 14     # Use 14-day sample instead of 7
python3 collect.py --cloud azure --skip-change-rate       # Skip for faster collection
python3 collect.py --cloud gcp --skip-change-rate
```

This outputs a separate `cca_*_change_rates_*.json` file with estimated daily change rates by service family. Use these values to override default DCR assumptions in sizing tools.

**Note:** Requires additional monitoring permissions (CloudWatch for AWS, Azure Monitor for Azure, Cloud Monitoring for GCP). See [PERMISSIONS.md](docs/PERMISSIONS.md) for details.

### Kubernetes PVC Collection

PersistentVolumeClaims (PVCs) are automatically collected when managed Kubernetes clusters are discovered. Use `--skip-pvc` to disable this:

```bash
python3 collect.py --cloud aws --skip-pvc      # Skip PVC collection from EKS clusters
python3 collect.py --cloud azure --skip-pvc    # Skip PVC collection from AKS clusters
python3 collect.py --cloud gcp --skip-pvc      # Skip PVC collection from GKE clusters
```

This collects:
- PVC name, namespace, and storage class
- Requested and actual storage sizes
- Access modes (ReadWriteOnce, ReadWriteMany, etc.)
- Bound PersistentVolume information
- Pods using each PVC

**Requirements:**
- `kubernetes` Python package: `pip install kubernetes`
- K8s RBAC permissions to list PVCs, PVs, and Pods in the cluster
- Network connectivity to cluster API endpoints

## Config Files

Use YAML config files for repeated runs or complex configurations:

```bash
# Generate a sample config
python3 collect.py --generate-config aws > cca-config.yaml

# Edit the config, then run with it
python3 collect.py --config cca-config.yaml

# Config is auto-discovered if named cca-config.yaml in current directory
```

Config files support environment variable substitution (`${VAR}` or `${VAR:-default}`).
See [config-examples/](config-examples/) for samples.

## Protection Report

Generate an Excel report with protection status analysis:

```bash
python scripts/generate_protection_report.py inventory.json report.xlsx
```

## Assessment Report

Generate a comprehensive multi-tab Excel report combining inventory and cost data:

```bash
# Single inventory file
python scripts/generate_assessment_report.py cca_aws_inv_*.json assessment.xlsx

# Multiple inventory files (multi-cloud)
python scripts/generate_assessment_report.py cca_*_inv_*.json --cost cca_cost_*.json -o assessment.xlsx
```

The assessment report includes:
- Executive summary with sizing overview
- Regional distribution for cluster placement
- Protection analysis and unprotected resources
- TCO inputs for Cohesity sizing calculator
- Multi-account breakdown

## Compatibility Check

Verify your environment has the required dependencies:

```bash
python3 tests/test_cloudshell_compat.py
```

## AWS IAM Setup (CloudFormation)

Deploy the IAM role with required permissions:

```bash
aws cloudformation create-stack \
  --stack-name cca-collector \
  --template-body file://setup/aws-iam-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM
```

For organizations with 100+ accounts, use CloudFormation StackSets for automated deployment. See [AWS CloudFormation & StackSets](docs/aws-cloudformation.md) for detailed instructions.

See [setup/](setup/) for Azure/GCP permission setup scripts.

## Project Structure

```
cca-cloudshell/
├── collect.py              # Unified entry point — all clouds, all options
├── pyproject.toml          # Project config (mypy, pytest, ruff)
├── setup/                  # IAM/permission setup scripts
├── config-examples/        # YAML config file examples
├── lib/                    # All collection and reporting logic
│   ├── models.py           # Resource data models (CloudResource, CostRecord, etc.)
│   ├── utils.py            # Common utilities
│   ├── constants.py        # Centralized constants
│   ├── change_rate.py      # Change rate metric helpers
│   ├── aws/                # AWS collection modules
│   │   ├── collector.py    # Orchestration: run_collection(), build_parser()
│   │   ├── cost.py         # Cost Explorer integration
│   │   ├── auth.py         # Session, role assumption, Organizations
│   │   ├── compute.py      # EC2, EBS, Lambda
│   │   ├── storage.py      # S3, EFS, FSx
│   │   ├── databases.py    # RDS, DynamoDB, ElastiCache, etc.
│   │   ├── container.py    # EKS
│   │   ├── backup.py       # AWS Backup
│   │   ├── monitoring.py   # CloudWatch change rates
│   │   ├── helpers.py      # Account validation, chunking
│   │   └── parallel.py     # Multi-account parallel collection
│   ├── azure/              # Azure collection modules
│   │   ├── collector.py    # Orchestration: run_collection(), build_parser()
│   │   ├── cost.py         # Cost Management integration
│   │   ├── auth.py         # Credential handling
│   │   ├── compute.py      # VMs, disks, snapshots, functions
│   │   ├── storage.py      # Storage accounts
│   │   ├── databases.py    # SQL, CosmosDB, Redis
│   │   ├── container.py    # AKS
│   │   ├── backup.py       # Recovery Services vaults
│   │   └── monitoring.py   # Azure Monitor change rates
│   ├── gcp/                # GCP collection modules
│   │   ├── collector.py    # Orchestration: run_collection(), build_parser()
│   │   ├── cost.py         # BigQuery billing export integration
│   │   ├── auth.py         # Credential handling
│   │   ├── compute.py      # Compute Engine, snapshots
│   │   ├── storage.py      # Cloud Storage
│   │   ├── databases.py    # Cloud SQL, Spanner, Bigtable, etc.
│   │   ├── container.py    # GKE
│   │   ├── backup.py       # Cloud Backup
│   │   └── monitoring.py   # Cloud Monitoring change rates
│   ├── m365/               # M365 collection modules
│   │   ├── collector.py    # Orchestration: run_collection(), build_parser()
│   │   ├── __init__.py     # Graph client, all collection functions
│   │   ├── exchange.py     # Exchange Online
│   │   ├── sharepoint.py   # SharePoint
│   │   ├── onedrive.py     # OneDrive
│   │   └── teams.py        # Teams
│   └── reports/            # Report generation
│       ├── assessment.py   # Multi-tab Excel assessment report
│       ├── protection.py   # Protection status report
│       ├── m365.py         # M365-specific Excel report
│       └── cost.py         # Cost analysis report
├── scripts/                # Thin CLI wrappers for report generators
│   ├── generate_assessment_report.py
│   ├── generate_protection_report.py
│   ├── generate_m365_report.py
│   ├── generate_cost_report.py
│   └── merge_batch_outputs.py
├── docs/                   # Documentation
```


