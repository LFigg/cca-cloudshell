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

# Run in your cloud shell (credentials automatic)
python3 aws_collect.py      # AWS
python3 azure_collect.py    # Azure
python3 gcp_collect.py      # GCP
python3 m365_collect.py     # Microsoft 365
python3 cost_collect.py --aws  # Backup/snapshot costs
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
| [AWS Collector](docs/collectors/aws.md) | Multi-account, regions, options |
| [Azure Collector](docs/collectors/azure.md) | Subscriptions, resources |
| [GCP Collector](docs/collectors/gcp.md) | Projects, regions, resources |
| [M365 Collector](docs/collectors/m365.md) | App registration, Graph API |
| [Cost Collector](docs/collectors/cost.md) | Backup/snapshot spending |
| [Required Permissions](docs/PERMISSIONS.md) | IAM policies for each cloud |
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

# Analyze backup/snapshot costs
python3 cost_collect.py --aws --start-date 2026-01-01
```

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

## Project Structure

```
cca-cloudshell/
├── aws_collect.py          # AWS collector
├── azure_collect.py        # Azure collector
├── cost_collect.py         # Cost analyzer
├── gcp_collect.py          # GCP collector
├── m365_collect.py         # M365 collector
├── lib/                    # Shared models and utilities
├── scripts/                # Report generators
├── docs/                   # Documentation
└── tests/                  # Test suite
```

## License

MIT License
