# CCA CloudShell

Lightweight cloud resource assessment collectors designed for cloud shell environments (AWS CloudShell, Azure Cloud Shell).

## Overview

These standalone Python scripts collect cloud resource inventory including primary resources, snapshots, and backup configurations. They're optimized for:
- **AWS CloudShell** - Pre-authenticated, no setup required
- **Azure Cloud Shell** - Uses DefaultAzureCredential  
- **Microsoft 365** - Uses Azure AD app registration
- **Local execution** - With configured credentials

## Features

- Single-file collectors (no complex dependencies)
- Comprehensive snapshot inventory (EBS, RDS, Azure Disk)
- AWS Backup and Azure Recovery Services collection
- Protection status reporting with Excel output
- JSON inventory output
- Size summaries with protected vs unprotected breakdown

## Quick Start

### Setup

```bash
# Clone the repository
git clone https://github.com/LFigg/cca-cloudshell.git
cd cca-cloudshell

# Run setup (installs dependencies)
./setup.sh
```

### AWS CloudShell

```bash
# Open AWS CloudShell from AWS Console
# Your credentials are already configured

python3 aws_collect.py

# Options
python3 aws_collect.py --regions us-east-1,us-west-2   # Specific regions
python3 aws_collect.py --all-regions                    # All regions
python3 aws_collect.py --csv                            # Include CSV output
python3 aws_collect.py -o ./my_output                   # Custom output dir
```

### Azure Cloud Shell

```bash
# Open Azure Cloud Shell from Azure Portal
# Your credentials are already configured via DefaultAzureCredential

# Install dependencies (if not using setup.sh)
pip install azure-identity azure-mgmt-compute azure-mgmt-storage \
    azure-mgmt-sql azure-mgmt-cosmosdb azure-mgmt-containerservice \
    azure-mgmt-web azure-mgmt-resource

python3 azure_collect.py

# Options
python3 azure_collect.py --subscription-id xxx          # Specific subscription
python3 azure_collect.py --csv                          # Include CSV output
python3 azure_collect.py -o ./my_output                 # Custom output dir
```

### Microsoft 365

```bash
# Requires Azure AD App Registration with Graph API permissions
# See M365 Setup section below

export MS365_TENANT_ID="your-tenant-id"
export MS365_CLIENT_ID="your-client-id"
export MS365_CLIENT_SECRET="your-client-secret"

pip install msgraph-sdk azure-identity

python3 m365_collect.py

# Options
python3 m365_collect.py --include-entra    # Include Entra ID users/groups
python3 m365_collect.py --skip-sharepoint  # Skip specific services
python3 m365_collect.py -o ./my_output     # Custom output dir
```

### Run All Collectors

```bash
# Run all configured collectors at once
./run_all.sh ./combined_output
```

## M365 Setup

To collect Microsoft 365 resources, you need an Azure AD App Registration:

1. Go to Azure Portal > Azure Active Directory > App registrations
2. Click "New registration"
3. Name: `CCA-M365-Collector` (or any name)
4. Supported account types: "Accounts in this organizational directory only"
5. Click "Register"

**Add API Permissions:**
1. Go to "API permissions" > "Add a permission"
2. Select "Microsoft Graph" > "Application permissions"
3. Add these permissions:
   - `Sites.Read.All` (SharePoint)
   - `User.Read.All` (Users, OneDrive, Exchange)
   - `Group.Read.All` (Groups, Teams)
   - `TeamSettings.Read.All` (Teams details)
4. Click "Grant admin consent"

**Create Client Secret:**
1. Go to "Certificates & secrets"
2. Click "New client secret"
3. Copy the secret value (shown only once)

**Get IDs:**
- Tenant ID: Azure AD > Properties > Tenant ID
- Client ID: App registration > Overview > Application (client) ID

## Project Structure

```
cca-cloudshell/
├── README.md
├── requirements.txt        # Python dependencies
├── setup.sh                # Setup script
├── run_all.sh              # Run all collectors
├── aws_collect.py          # AWS resource collector
├── azure_collect.py        # Azure resource collector
├── m365_collect.py         # Microsoft 365 collector
├── lib/
│   ├── __init__.py
│   ├── models.py           # Shared data models (CloudResource)
│   └── utils.py            # Shared utilities
└── scripts/
    └── generate_protection_report.py  # Excel protection report generator
```

## Output Files

Each collector generates:
- `inventory_<timestamp>.json` - Raw resource inventory with all resources, snapshots, and backup configs

### Protection Report

Generate an Excel report with protection status analysis:

```bash
python scripts/generate_protection_report.py inventory.json protection_report.xlsx
```

The Excel report includes:
- **Summary tab**: Resource counts, sizes, protection status percentages
- **Protection Report tab**: Instance → Volume → Snapshot hierarchy with color-coded status
- **Backup Plans tab**: All backup plans with rule details (schedule, retention, vault)
- **Backup Selections tab**: Resources assigned to backup plans (if any)

## Collected Resources

### AWS
| Resource Type | Description |
|--------------|-------------|
| EC2 Instances | Virtual machines with instance type, state, storage |
| EBS Volumes | Block storage volumes with size, type, IOPS |
| EBS Snapshots | Volume snapshots with size, creation time |
| RDS Databases | Managed databases (MySQL, PostgreSQL, etc.) |
| RDS Snapshots | Database snapshots (manual and automated) |
| RDS Cluster Snapshots | Aurora cluster snapshots |
| S3 Buckets | Object storage (bucket count, does not enumerate objects) |
| EFS File Systems | Elastic file systems with size metering |
| EKS Clusters | Kubernetes clusters with node groups |
| Lambda Functions | Serverless functions with memory, runtime |
| DynamoDB Tables | NoSQL tables with billing mode, indexes |
| FSx File Systems | Managed file systems (Windows, Lustre, NetApp) |
| ElastiCache | In-memory cache clusters (Redis, Memcached) |
| **Backup Vaults** | AWS Backup vaults with recovery point count |
| **Backup Recovery Points** | Actual backup data with sizes |
| **Backup Plans** | Backup policies with schedules and retention rules |
| **Backup Selections** | Resources assigned to backup plans |
| **Protected Resources** | Resources with at least one recovery point |

### Azure
| Resource Type | Description |
|--------------|-------------|
| Virtual Machines | VMs with size, OS, disks |
| Managed Disks | Block storage with size, SKU, encryption |
| Disk Snapshots | Disk snapshots with size, creation time |
| Storage Accounts | Blob, file, queue, table storage |
| Azure Files | File shares with quota and usage |
| SQL Databases | Azure SQL and SQL MI databases |
| SQL Database Backups | Restore points and LTR backups |
| SQL Managed Instances | Fully managed SQL Server instances |
| Cosmos DB | Multi-model NoSQL databases |
| AKS Clusters | Managed Kubernetes with node pools |
| Function Apps | Serverless compute functions |
| Azure Cache for Redis | In-memory cache instances |
| **Recovery Services Vaults** | Azure Backup vaults |
| **Backup Policies** | Backup policies with schedules |
| **Backup Protected Items** | Resources protected by Azure Backup |
| **Backup Recovery Points** | Actual backup data with sizes |

### Microsoft 365
| Resource Type | Description |
|--------------|-------------|
| SharePoint Sites | Team sites, communication sites with storage |
| OneDrive Accounts | User OneDrive storage with quota |
| Exchange Mailboxes | User mailboxes |
| Microsoft Teams | Teams with membership |
| Entra ID Users | Directory users (optional) |
| Entra ID Groups | Security and M365 groups (optional) |

## Protection Status

The protection report categorizes resources by status:

| Status | Description | Color |
|--------|-------------|-------|
| Protected | Has snapshots/recovery points | Green |
| In Backup Plan | Assigned to backup plan but no snapshots yet | Yellow |
| Unprotected | No snapshots or backup coverage | Red |
| No Storage | Resource has no associated storage | Gray |

### Protection Report Columns

- **Instance/Resource info**: Name, ID, region, tags
- **Volume info**: Name, ID, size in GB
- **Snapshot info**: Name, ID, size, creation time, description
- **Backup Plan**: Associated backup plan (definitive or inferred)
- **Protection Source**: How backup plan was determined (`backup_selection`, `recovery_point`, `inferred`)
- **Protection Status**: Current protection state

## Troubleshooting

### AWS CloudShell
- CloudShell has pre-configured credentials from your console session
- Default region is the region where CloudShell is running
- Use `--regions` to specify other regions

### Azure Cloud Shell
- DefaultAzureCredential automatically uses your Cloud Shell identity
- Lists all subscriptions you have access to
- Use `--subscription-id` to target a specific subscription

### M365 Collector
- Ensure admin consent is granted for API permissions
- Client secret expires - check expiration date
- Test with: `python3 m365_collect.py --skip-onedrive --skip-exchange --skip-teams`

## License

MIT License
