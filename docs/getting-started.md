# Getting Started

This guide covers installation and running your first collection.

## Prerequisites

- Python 3.8+
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

## Quick Start by Cloud

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

## Output

Each collector generates:

| File | Description |
|------|-------------|
| `cca_<cloud>_inv_<time>.json` | Full resource inventory |
| `cca_<cloud>_sum_<time>.json` | Aggregated summary |
| `cca_<cloud>_sizing.csv` | Spreadsheet-ready sizing data |

## Next Steps

- [AWS Collector](collectors/aws.md) - Multi-account, regions, all options
- [Azure Collector](collectors/azure.md) - Subscriptions, resource types
- [GCP Collector](collectors/gcp.md) - Projects, regions, resources
- [M365 Collector](collectors/m365.md) - App registration, permissions
- [Output Formats](output-formats.md) - JSON schema, CSV fields
- [Required Permissions](PERMISSIONS.md) - IAM policies for each cloud
