# Cost Collector

The cost collector (`cost_collect.py`) gathers backup and snapshot spending data from cloud billing APIs.

## Basic Usage

```bash
# AWS costs (last 30 days)
python3 cost_collect.py --aws

# Azure costs
python3 cost_collect.py --azure --subscription-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# GCP costs (requires BigQuery billing export)
python3 cost_collect.py --gcp --project my-project --billing-table project.dataset.table

# All clouds
python3 cost_collect.py --all --subscription-id xxx --billing-table xxx
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `--aws` | Collect AWS costs |
| `--azure` | Collect Azure costs |
| `--gcp` | Collect GCP costs |
| `--all` | Collect from all configured clouds |
| `--start-date DATE` | Start date YYYY-MM-DD (default: 30 days ago) |
| `--end-date DATE` | End date YYYY-MM-DD (default: today) |
| `--profile PROFILE` | AWS CLI profile name |
| `--role-arn ARN` | AWS role ARN to assume |
| `--subscription-id ID` | Azure subscription ID |
| `--project PROJECT` | GCP project ID |
| `--billing-table TABLE` | GCP BigQuery billing table |
| `-o, --output PATH` | Output directory |

## What It Collects

The collector filters for backup and snapshot related costs:

### AWS
- AWS Backup service costs
- EBS snapshot storage
- RDS backup storage
- S3 backup storage (Vault)

### Azure
- Azure Backup service
- Azure Site Recovery
- Storage (snapshot-related)

### GCP
- Compute Engine snapshots
- Cloud Storage (backup tiers)
- Cloud SQL backups
- Backup and DR Service

## Cost Categories

Records are categorized into:

| Category | Description |
|----------|-------------|
| `backup` | Managed backup service costs (AWS Backup, Azure Backup, GCP Backup & DR) |
| `snapshot` | Snapshot storage costs (EBS, Disk, Compute) |
| `storage` | Related storage costs (backup tiers, vault storage) |

## Output Files

| File | Description |
|------|-------------|
| `cca_cost_inv_<time>.json` | Detailed cost records |
| `cca_cost_sum_<time>.json` | Aggregated summaries |
| `cca_cost_sizing.csv` | Spreadsheet-ready summary |

## Example Output

**Summary JSON:**
```json
{
    "run_id": "20260211-143052-abc123",
    "timestamp": "2026-02-11T14:30:52.123456Z",
    "providers": ["aws", "azure"],
    "period": {
        "start": "2026-01-01",
        "end": "2026-02-01"
    },
    "total_cost": 1250.50,
    "summaries": [
        {
            "provider": "aws",
            "category": "backup",
            "total_cost": 450.00,
            "currency": "USD",
            "service_breakdown": {
                "AWS Backup": 350.00,
                "Amazon S3": 100.00
            }
        },
        {
            "provider": "aws",
            "category": "snapshot",
            "total_cost": 320.50,
            "currency": "USD",
            "service_breakdown": {
                "Amazon Elastic Block Store": 320.50
            }
        }
    ]
}
```

**Console Output:**
```
============================================================
Backup & Snapshot Cost Analysis
============================================================
Period:    2026-01-01 to 2026-02-01
Providers: aws, azure
Records:   45

Category        Provider        Cost
--------------- ---------- ------------
backup          aws        $    450.00
snapshot        aws        $    320.50
backup          azure      $    280.00
snapshot        azure      $    200.00
--------------- ---------- ------------
TOTAL                      $  1,250.50

Output: ./
```

## Required Permissions

### AWS

Add to your IAM policy:
```json
{
    "Sid": "CostExplorerAccess",
    "Effect": "Allow",
    "Action": [
        "ce:GetCostAndUsage",
        "ce:GetCostForecast"
    ],
    "Resource": "*"
}
```

### Azure

Assign role or add to custom role:
```json
{
    "Actions": [
        "Microsoft.CostManagement/query/read",
        "Microsoft.CostManagement/exports/read"
    ]
}
```

Or assign the built-in **Cost Management Reader** role.

### GCP

1. **Enable BigQuery billing export** in your billing account:
   - Go to Billing → Billing export → BigQuery export
   - Enable detailed usage cost export
   - Note the dataset and table name

2. **Grant BigQuery permissions:**
   - `bigquery.jobs.create` on the project
   - `bigquery.tables.getData` on the billing table

## GCP BigQuery Setup

GCP requires billing data to be exported to BigQuery (not available via direct API):

1. Go to **Cloud Console** → **Billing** → **Billing export**
2. Select **BigQuery export** → **Edit settings**
3. Choose a project and create/select a dataset
4. Enable **Detailed usage cost** export
5. Note the full table path: `project_id.dataset_name.gcp_billing_export_v1_XXXXXX`

Use this table path with `--billing-table`:
```bash
python3 cost_collect.py --gcp --project my-project \
    --billing-table my-project.billing_dataset.gcp_billing_export_v1_012345
```

**Note:** It can take 24-48 hours for billing data to appear in BigQuery after enabling export.

## Combining with Resource Collection

For a complete picture, run both collectors:

```bash
# Collect resources
python3 aws_collect.py -o ./assessment/

# Collect costs
python3 cost_collect.py --aws --start-date 2026-01-01 -o ./assessment/
```

This gives you both the inventory (what you have) and the costs (what you're spending).
