# Output Formats

Each collector generates two output files:
- **Inventory JSON** - Complete resource details
- **Summary JSON** - Aggregated sizing data

## File Naming Convention

| Cloud | Inventory | Summary |
|-------|-----------|----------|
| AWS | `cca_aws_inv_<HHMMSS>.json` | `cca_aws_sum_<HHMMSS>.json` |
| Azure | `cca_azure_inv_<HHMMSS>.json` | `cca_azure_sum_<HHMMSS>.json` |
| GCP | `cca_gcp_inv_<HHMMSS>.json` | `cca_gcp_sum_<HHMMSS>.json` |
| M365 | `cca_m365_inv_<HHMMSS>.json` | `cca_m365_sum_<HHMMSS>.json` |

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
            "resource_id": "[REDACTED]",
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
                "vpc_id": "[REDACTED]",
                "attached_volumes": ["[REDACTED]", "[REDACTED]"]
            }
        }
    ]
}
```

> **Note on Privacy:** By default, resource IDs and ARNs are redacted in output for privacy. Use `--include-resource-ids` flag to include full identifiers when needed for detailed analysis.

> **Timestamps:** All timestamps use UTC (ISO 8601 format with `Z` suffix) for consistency across time zones.

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
| `sizing_relevant` | boolean | Whether this resource is counted in sizing calculations. `false` for resources reported for auditing only (e.g., shared/room mailboxes, Entra users) |
| `parent_resource_id` | string | Parent resource (e.g., volume → instance) |
| `metadata` | object | Resource-specific attributes |

### Multi-Account Inventory

When collecting from multiple accounts, the structure includes:

```json
{
    "organization": {
        "name": "my-org",
        "id": "o-abc123xyz",
        "management_account_id": "999999999999"
    },
    "run_scope": {
        "mode": "org-role",
        "filters": {"regions": "all"}
    },
    "account_id": ["111111111111", "222222222222"],
    "accounts": [
        {
            "account_id": "111111111111",
            "account_name": "Production",
            "account_status": "ACTIVE",
            "ou_id": "ou-abcd-12345678",
            "ou_name": "Production",
            "ou_path": "/Workloads/Production",
            "collection_status": "completed",
            "failure_reason": null
        },
        {
            "account_id": "222222222222",
            "account_name": "Development",
            "account_status": "ACTIVE",
            "ou_id": "ou-abcd-87654321",
            "ou_name": "Development",
            "ou_path": "/Workloads/Development",
            "collection_status": "failed",
            "failure_reason": "assume-role-failed"
        }
    ],
    "resources": [...]
}
```

`accounts` entries may include `resource_count` in some outputs and always include collection status when multi-account metadata is available.

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

### Collection Progress Fields

Summary outputs may include a `collection_progress` object for multi-account runs:

| Field | Type | Description |
|-------|------|-------------|
| `target_accounts` | integer | Total accounts targeted for the run |
| `completed_accounts` | integer | Accounts collected successfully |
| `failed_accounts` | integer | Accounts that failed collection |
| `failed_account_ids` | array | List of failed account IDs |
| `failed_account_reasons` | object | Map of account ID to failure reason |

### Collection Completeness Fields

AWS, Azure, and GCP summary outputs include a `collection_completeness`
object whenever the run attempted more than one account/subscription/project
(GCP: project, Azure: subscription). It scores how much of the run is
estimated to be missing due to whole units failing outright, weighted by the
average resource count of units that succeeded, rather than just a raw
failed-unit count:

| Field | Type | Description |
|-------|------|-------------|
| `unit_label` | string | What a "unit" is for this provider (`account`, `subscription`, `project`) |
| `total_units` | integer | Units attempted |
| `successful_units` | integer | Units that collected without error |
| `failed_units` | integer | Units that failed outright |
| `unit_success_rate_pct` | number | `successful_units / total_units * 100` |
| `estimated_resource_completeness_pct` | number \| null | Estimated % of resources present, weighting failed units by the average size of successful ones. `null` if every unit failed (no basis for an estimate) |
| `estimated_resources_missing` | integer \| null | Estimated resource count lost to failed units |
| `failed_unit_details` | array | Per-failed-unit `{id, name, error}` |
| `likely_systemic_issue` | object \| null | Present when 2+ failed units share the *exact same* error - `{shared_error, affected_units, of_failed_units}` - a signal that this is probably one root cause (e.g. an expired credential) rather than N unrelated failures |

This is informational only - it never aborts or gates a run; a failed unit
mid-collection means work already done is worth keeping, not discarding.

### Data Quality Fields

Every collector's summary output includes a `data_quality` object scoring
how much of the collected data is *real measured usage* versus a
provisioned/quota/allocated placeholder (`size_source` on each resource is
`usage`, `quota`, `estimate`, `not_applicable`, or `unavailable` - see each
collector's module docstrings for exactly which sources apply to which
resource type):

| Field | Type | Description |
|-------|------|-------------|
| `resource_types_with_gaps` | array | Resource types where `size_gb` isn't backed by real usage for at least one resource |
| (per-type entries) | object | Count/capacity confirmed via real usage vs. not, per affected resource type |

### M365-Specific Summary Fields

| Field | Type | Description |
|-------|------|-------------|
| `total_user_count` | integer | Total tenant users |
| `total_user_count_source` | string | `count_endpoint` (exact, via Graph's `/users/$count`) or `paginated` (fallback) |
| `total_user_count_truncated` | boolean | Present and `true` only if the paginated fallback hit its safety cap - `total_user_count` is a lower bound, not exact, when this is set |

---

## Assessment Report (Excel)

Generate a comprehensive multi-tab report for sizing and TCO analysis:

```bash
python scripts/generate_assessment_report.py --inventory cca_aws_inv_*.json -o assessment.xlsx

# Include cost data (point --cost at the collector's actual cca_<cloud>_costs_*.json
# file - see docs/reports/assessment.md for why auto-discovery alone isn't enough)
python scripts/generate_assessment_report.py --inventory cca_*_inv_*.json --cost cca_aws_costs_*.json -o assessment.xlsx
```

### Assessment Report Tabs

| Tab | Description |
|-----|-------------|
| **Executive Summary** | Environment overview, sizing summary, protection status |
| **Sizing Inputs** | Workload inventory by type for Cohesity sizing calculator |
| **Regional Distribution** | Resources by region for cluster placement planning |
| **Protection Analysis** | Coverage percentages and snapshot analysis |
| **Unprotected Resources** | Prioritized list for protection planning |
| **TCO Inputs** | Current backup costs and Cohesity TCO calculator inputs |
| **M365 Summary** | Microsoft 365 workload summary (if M365 data included) |
| **Account Detail** | Multi-account/subscription breakdown |
| **Raw Data** | Full resource inventory for reference |

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
```
