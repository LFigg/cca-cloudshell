# Cost Collection

Data protection cost collection is **integrated into each cloud collector** — it runs automatically alongside inventory collection with no extra steps.

> **v2 change:** The standalone `cost_collect.py` script has been removed. Cost collection now happens inside `collect.py --cloud <cloud>` and can be skipped with `--no-costs`.

## How It Works

Each cloud collector queries its billing API at the end of the collection run and writes a separate cost output file:

| Cloud | Billing Source | Output File |
|-------|---------------|-------------|
| AWS | Cost Explorer API | `cca_aws_costs_<time>.json` |
| Azure | Cost Management API | `cca_azure_costs_<time>.json` |
| GCP | BigQuery billing export | `cca_gcp_costs_<time>.json` |
| M365 | Not supported | — |

## Opting Out

Cost collection is on by default for AWS and Azure. To skip:

```bash
python3 collect.py --cloud aws --no-costs
python3 collect.py --cloud azure --no-costs
```

When using the interactive wizard, you'll be prompted:
```
Data protection cost collection is enabled by default.

Skip cost collection? [y/N]:
```

## GCP Cost Collection

GCP requires a BigQuery billing export table — cost collection is skipped if `--billing-table` is not provided:

```bash
# With cost collection
python3 collect.py --cloud gcp \
    --billing-table my-project.billing.gcp_billing_export_v1_XXXXXX

# Without (no --billing-table = costs skipped)
python3 collect.py --cloud gcp
```

See the [GCP Collector](gcp.md#cost-collection) doc for BigQuery setup instructions.

## What Is Collected

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

## Output File Format

**`cca_<cloud>_costs_<time>.json`:**
```json
{
    "run_id": "20260211-143052-abc123",
    "timestamp": "2026-02-11T14:30:52.123456Z",
    "provider": "aws",
    "account_id": "123456789012",
    "period": {
        "start": "2026-01-01",
        "end": "2026-02-01"
    },
    "total_cost": 770.50,
    "records": [...],
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

## Required Permissions

### AWS

> **Critical:** AWS Cost Explorer API is only accessible from the **management account** (payer account) in AWS Organizations. Running from a member account will return empty results.

Add to your IAM policy:
```json
{
    "Sid": "CostExplorerAccess",
    "Effect": "Allow",
    "Action": ["ce:GetCostAndUsage"],
    "Resource": "*"
}
```

**Multiple AWS Organizations:** If you have multiple independent orgs, run collection from each management account separately:
```bash
python3 collect.py --cloud aws --profile org1-mgmt -o ./org1/
python3 collect.py --cloud aws --profile org2-mgmt -o ./org2/
```

### Azure

Assign the built-in **Cost Management Reader** role, or add:
```json
{
    "Actions": [
        "Microsoft.CostManagement/query/read",
        "Microsoft.CostManagement/exports/read"
    ]
}
```

### GCP

- `bigquery.jobs.create` on the project running the query
- `bigquery.tables.getData` on the billing export table

## Using Cost Data in Reports

After collection, include cost data in the assessment report:

```bash
# Generate comprehensive assessment report with cost data
python scripts/generate_assessment_report.py --inventory cca_aws_inv_*.json \
    --cost cca_aws_costs_*.json -o assessment.xlsx

# Generate cost-only report
# Note: --summary is required by argparse but its content is unused - pass the
# same cost file to both flags. See docs/reports/cost.md
python scripts/generate_cost_report.py \
    -i cca_aws_costs_*.json -s cca_aws_costs_*.json -o cost_report.xlsx
```
