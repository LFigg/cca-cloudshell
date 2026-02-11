# Output Formats

Each collector generates three output files:
- **Inventory JSON** - Complete resource details
- **Summary JSON** - Aggregated sizing data
- **Sizing CSV** - Spreadsheet-ready format

## File Naming Convention

| Cloud | Inventory | Summary | Sizing CSV |
|-------|-----------|---------|------------|
| AWS | `cca_aws_inv_<HHMMSS>.json` | `cca_aws_sum_<HHMMSS>.json` | `cca_aws_sizing.csv` |
| Azure | `cca_azure_inv_<HHMMSS>.json` | `cca_azure_sum_<HHMMSS>.json` | `cca_azure_sizing.csv` |
| GCP | `cca_gcp_inv_<HHMMSS>.json` | `cca_gcp_sum_<HHMMSS>.json` | `cca_gcp_sizing.csv` |
| M365 | `cca_m365_inv_<HHMMSS>.json` | `cca_m365_sum_<HHMMSS>.json` | - |

The `<HHMMSS>` timestamp ensures unique filenames for multiple runs.

---

## Inventory JSON Schema

The inventory file contains the complete resource data:

```json
{
    "run_id": "20260211-143052-abc123",
    "timestamp": "2026-02-11T14:30:52.123456Z",
    "provider": "aws",
    "account_id": "123456789012",
    "regions": ["us-east-1", "us-west-2"],
    "resource_count": 250,
    "resources": [
        {
            "provider": "aws",
            "account_id": "123456789012",
            "region": "us-east-1",
            "resource_type": "aws:ec2:instance",
            "service_family": "EC2",
            "resource_id": "i-0123456789abcdef0",
            "name": "web-server-01",
            "tags": {
                "Environment": "production",
                "Owner": "devops"
            },
            "size_gb": 0.0,
            "parent_resource_id": null,
            "metadata": {
                "instance_type": "t3.large",
                "state": "running",
                "platform": "linux",
                "vpc_id": "vpc-12345",
                "attached_volumes": ["vol-abc123", "vol-def456"]
            }
        }
    ]
}
```

### Resource Object Fields

| Field | Type | Description |
|-------|------|-------------|
| `provider` | string | Cloud provider (aws, azure, gcp, m365) |
| `account_id` | string | Account/subscription/project ID |
| `region` | string | Region/location |
| `resource_type` | string | Full resource type identifier |
| `service_family` | string | Logical grouping for sizing |
| `resource_id` | string | Cloud-specific resource ID |
| `name` | string | Resource name (from tags or ID) |
| `tags` | object | Key-value tags/labels |
| `size_gb` | number | Size in GB (0 if not applicable) |
| `parent_resource_id` | string | Parent resource (e.g., volume → instance) |
| `metadata` | object | Resource-specific attributes |

### Multi-Account Inventory

When collecting from multiple accounts, the structure includes:

```json
{
    "account_id": ["111111111111", "222222222222"],
    "accounts": [
        {"account_id": "111111111111", "account_name": "Production", "resource_count": 150},
        {"account_id": "222222222222", "account_name": "Development", "resource_count": 100}
    ],
    "resources": [...]
}
```

---

## Summary JSON Schema

The summary file contains aggregated statistics:

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
            "total_gb": 0.0
        },
        {
            "provider": "aws",
            "service_family": "EBS",
            "resource_type": "aws:ec2:volume",
            "resource_count": 80,
            "total_gb": 8000.0
        },
        {
            "provider": "aws",
            "service_family": "EBSSnapshot",
            "resource_type": "aws:ec2:snapshot",
            "resource_count": 120,
            "total_gb": 7000.5
        }
    ]
}
```

### Summary Object Fields

| Field | Type | Description |
|-------|------|-------------|
| `provider` | string | Cloud provider |
| `service_family` | string | Logical grouping |
| `resource_type` | string | Full resource type |
| `resource_count` | integer | Number of resources |
| `total_gb` | number | Total size in GB |

---

## Sizing CSV Format

The CSV file is optimized for spreadsheet analysis:

```csv
provider,service_family,resource_type,resource_count,total_gb
aws,EC2,aws:ec2:instance,50,0.0
aws,EBS,aws:ec2:volume,80,8000.0
aws,EBSSnapshot,aws:ec2:snapshot,120,7000.5
aws,RDS,aws:rds:instance,15,2000.0
aws,S3,aws:s3:bucket,40,0.0
```

### CSV Columns

| Column | Description |
|--------|-------------|
| `provider` | Cloud provider |
| `service_family` | Logical grouping for sizing |
| `resource_type` | Full resource type identifier |
| `resource_count` | Number of resources of this type |
| `total_gb` | Total size in gigabytes |

---

## Protection Report (Excel)

Generate an Excel protection report from the inventory:

```bash
python scripts/generate_protection_report.py cca_aws_inv_143052.json protection_report.xlsx
```

### Report Tabs

| Tab | Description |
|-----|-------------|
| **Summary** | Resource counts, sizes, protection percentages |
| **Protection Report** | Instance → Volume → Snapshot hierarchy |
| **Backup Plans** | Backup plans with schedules and retention |
| **Backup Selections** | Resources assigned to backup plans |

### Protection Status Colors

| Status | Color | Description |
|--------|-------|-------------|
| Protected | Green | Has snapshots or recovery points |
| In Backup Plan | Yellow | Assigned to backup plan, no snapshots yet |
| Unprotected | Red | No snapshots or backup coverage |
| No Storage | Gray | Resource has no associated storage |

---

## Working with Output Files

### Load in Python

```python
import json

# Load inventory
with open('cca_aws_inv_143052.json') as f:
    inventory = json.load(f)

# Access resources
for resource in inventory['resources']:
    print(f"{resource['name']}: {resource['size_gb']} GB")
```

### Query with jq

```bash
# Count resources by type
jq '.summaries[] | "\(.resource_type): \(.resource_count)"' cca_aws_sum_143052.json

# Find unattached volumes
jq '.resources[] | select(.resource_type == "aws:ec2:volume" and .metadata.state == "available")' cca_aws_inv_143052.json

# Total capacity
jq '.total_capacity_gb' cca_aws_sum_143052.json
```

### Load in Pandas

```python
import pandas as pd
import json

# Load summary as DataFrame
with open('cca_aws_sum_143052.json') as f:
    data = json.load(f)
df = pd.DataFrame(data['summaries'])

# Or load CSV directly
df = pd.read_csv('cca_aws_sizing.csv')
```
