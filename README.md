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

## Quick Start

```bash
# Download and setup
curl -sL https://github.com/LFigg/cca-cloudshell/archive/refs/heads/main.tar.gz | tar xz
cd cca-cloudshell-main && ./setup.sh

# Run the unified collector (recommended)
python3 collect.py              # Interactive mode - guides you through cloud selection
python3 collect.py --cloud aws  # Direct mode - specify cloud upfront

# Or run individual collectors directly
python3 aws_collect.py      # AWS
python3 azure_collect.py    # Azure
python3 gcp_collect.py      # GCP
python3 m365_collect.py     # Microsoft 365
python3 cost_collect.py --aws  # Backup/snapshot costs (run from management account)
```

## Unified Collector

The `collect.py` entry point provides:
- **Cloud Selection**: Choose AWS, Azure, GCP, or M365
- **Permission Verification**: Validates credentials before collection
- **Guided Experience**: Interactive prompts for first-time users

```bash
# Interactive mode
python3 collect.py

# Direct mode (for scripts/CI)
python3 collect.py --cloud aws
python3 collect.py --cloud azure --skip-check  # Skip permission verification

# Pass arguments to underlying collector
python3 collect.py --cloud aws -- --org-role CCARole --regions us-east-1

# Show collector-specific help
python3 collect.py --cloud aws --help-collector
```

## Output

Each collector generates:
- `cca_<cloud>_inv_<time>.json` - Full resource inventory
- `cca_<cloud>_sum_<time>.json` - Aggregated summary
- `cca_<cloud>_sizing.csv` - Spreadsheet-ready sizing

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
| [Cost Collector](docs/collectors/cost.md) | Backup/snapshot spending |
| [Required Permissions](docs/PERMISSIONS.md) | IAM policies for each cloud |
| [Permission Setup Scripts](setup/README.md) | Setup scripts for Azure/GCP |
| [Config Examples](config-examples/README.md) | YAML config file examples |
| [Output Formats](docs/output-formats.md) | JSON schema, CSV fields |
| [Troubleshooting](docs/troubleshooting.md) | Common errors and solutions |

## Common Options

```bash
# AWS - multi-account via Organizations
python3 aws_collect.py --org-role CCARole

# AWS - specific regions
python3 aws_collect.py --regions us-east-1,us-west-2

# Azure - specific subscription
python3 azure_collect.py --subscription-id xxx

# GCP - all projects
python3 gcp_collect.py --all-projects

# Custom output directory
python3 aws_collect.py -o ./my_output/

# Analyze backup/snapshot costs (requires management account for AWS Organizations)
python3 cost_collect.py --aws --org-costs  # Break down by linked account
python3 cost_collect.py --aws --start-date 2026-01-01
```

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

See [setup/](setup/) for multi-account StackSet deployment and Azure/GCP setup scripts.

## Project Structure

```
cca-cloudshell/
├── collect.py              # Unified collector entry point
├── aws_collect.py          # AWS collector
├── azure_collect.py        # Azure collector
├── cost_collect.py         # Cost analyzer
├── gcp_collect.py          # GCP collector
├── m365_collect.py         # M365 collector
├── setup/                  # IAM/permission setup scripts
├── config-examples/        # YAML config file examples
├── lib/                    # Shared models and utilities
├── scripts/                # Report generators
├── docs/                   # Documentation
└── tests/                  # Test suite
```

## License

MIT License
