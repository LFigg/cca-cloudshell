# GCP Collector

The GCP collector gathers resource inventory from Google Cloud projects including Compute Engine, Cloud SQL, GKE, Cloud Storage, and Backup & DR. Cost collection is supported via BigQuery billing export.

## Basic Usage

```bash
# Collect from default project
python3 collect.py --cloud gcp

# Specific project
python3 collect.py --cloud gcp --project my-project-id

# All accessible projects
python3 collect.py --cloud gcp --all-projects

# Custom output directory
python3 collect.py --cloud gcp --output ./my_output/

# Include full resource IDs (default: redact for privacy)
python3 collect.py --cloud gcp --include-resource-ids

# With cost collection (requires BigQuery billing export)
python3 collect.py --cloud gcp --billing-table my-project.billing.gcp_billing_export_v1_XXXXXX
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `--project PROJECT_ID` | Specific project to collect from |
| `--all-projects` | Collect from all accessible projects |
| `--output PATH` | Output directory |
| `--regions REGIONS` | Filter to specific regions (comma-separated) |
| `--include-resource-ids` | Include full resource IDs (default: redact) |
| `--skip-change-rate` | Skip change rate metrics collection |
| `--change-rate-days N` | Days to sample for change rate (default: 7) |
| `--parallel-resources N` | Parallel workers for resources (default: 4) |
| `--skip-pvc` | Skip PVC collection from GKE clusters |
| `--billing-table TABLE` | BigQuery billing export table for cost collection |
| `--no-costs` | Skip cost collection (also skipped if --billing-table not set) |
| `--log-level LEVEL` | Logging level (default: INFO) |

## Authentication

### Google Cloud Shell

Credentials are automatic - just run the collector.

### Local Execution

```bash
# Login via gcloud CLI
gcloud auth application-default login

# Set default project (optional)
gcloud config set project my-project-id
```

The collector uses Application Default Credentials (ADC).

## Collected Resources

| Resource Type | Service Family | Size Data | Description |
|---------------|----------------|-----------|-------------|
| `gcp:compute:instance` | Compute | n/a (sized via disks) | VM instances |
| `gcp:compute:disk` | Compute | Provisioned (this is the disk's actual size) | Persistent disks |
| `gcp:compute:snapshot` | Compute | ✅ Actual usage (`storageBytes`, GCP's own real deduplicated snapshot storage) | Disk snapshots |
| `gcp:storage:bucket` | Storage | ⚠️ Unavailable | Cloud Storage buckets |
| `gcp:sql:instance` | SQL | ⚠️ Unavailable | Cloud SQL instances |
| `gcp:container:cluster` | GKE | n/a | GKE clusters |
| `gcp:functions:function` | Functions | ⚠️ Unavailable | Cloud Functions |
| `gcp:filestore:instance` | Filestore | ⚠️ Unavailable | Filestore instances |
| `gcp:redis:instance` | Redis | ⚠️ Unavailable | Memorystore Redis |
| `gcp:bigquery:dataset` | BigQuery | ✅ Actual usage (`numBytes` per table) | BigQuery datasets |
| `gcp:spanner:instance` | Spanner | ⚠️ Unavailable | Cloud Spanner instances |
| `gcp:bigtable:instance` | Bigtable | ⚠️ Unavailable | Cloud Bigtable instances |
| `gcp:alloydb:cluster` | AlloyDB | ⚠️ Unavailable | AlloyDB clusters |
| `gcp:alloydb:instance` | AlloyDB | ⚠️ Unavailable | AlloyDB instances |
| `gcp:backupdr:vault` | Backup | ✅ Actual usage (`totalStoredBytes`) | Backup & DR vaults |
| `gcp:backupdr:plan` | Backup | n/a | Backup plans |
| `gcp:backupdr:datasource` | Backup | ✅ Actual usage (`totalStoredBytes`) | Data sources |
| `gcp:backupdr:backup` | Backup | ✅ Actual usage (`resourceSizeBytes`), when populated; ⚠️ Unavailable otherwise | Backups |

**Size Data** reflects whether `size_gb` is a real, measured value or currently unavailable (reported as
`0.0`, never a provisioned/allocated estimate) — see each resource's `metadata.size_source` in the output
JSON (`'usage'`, `'unavailable'`, or `'not_applicable'`), and `data_quality` in the summary JSON for a
collection-wide rollup.

> **Note:** Service Family values above are exactly what the collector sets in `metadata['service_family']`
> and `resource.service_family` — verify against `lib/gcp/*.py` before writing code that filters/dispatches
> on these strings. An earlier version of this table listed `PersistentDisk`, `CloudSQL`, `CloudStorage`,
> `CloudFunctions`, `ComputeSnapshot`, and `Memorystore`, none of which the collectors ever actually set —
> that mismatch is suspected to be the root cause of a bug where `lib/gcp/monitoring.py`'s change-rate
> dispatch checked those exact (wrong) values and silently never matched anything, for any GCP resource,
> on any run. Fixed; see `docs/v2-refactor-plan.md` (internal) for details.

## Cost Collection

GCP cost collection requires billing data exported to BigQuery (not available via direct API). Pass `--billing-table` with the full BigQuery table path:

```bash
python3 collect.py --cloud gcp \
    --billing-table my-project.billing_dataset.gcp_billing_export_v1_012345
```

If `--billing-table` is not provided, cost collection is silently skipped. This allows running inventory collection without a billing export set up.

### BigQuery Setup

1. Go to **Cloud Console** → **Billing** → **Billing export**
2. Select **BigQuery export** → **Edit settings**
3. Choose a project and create/select a dataset
4. Enable **Detailed usage cost** export
5. Note the full table path: `project_id.dataset_name.gcp_billing_export_v1_XXXXXX`

> **Note:** It can take 24–48 hours for billing data to appear in BigQuery after enabling export.

Required BigQuery permissions:
- `bigquery.jobs.create` on the project
- `bigquery.tables.getData` on the billing table

## Multi-Project Collection

To collect from multiple projects:

```bash
# All projects you have access to
python3 collect.py --cloud gcp --all-projects

# Specific project only
python3 collect.py --cloud gcp --project my-project-id
```

The collector discovers regions dynamically from each project.

## Example Output

**Summary JSON:**
```json
{
    "run_id": "20260211-143052-abc123",
    "timestamp": "2026-02-11T14:30:52.123456Z",
    "provider": "gcp",
    "project_id": "my-project-12345",
    "total_resources": 150,
    "total_capacity_gb": 25000.0,
    "summaries": [
        {
            "provider": "gcp",
            "service_family": "Compute",
            "resource_type": "gcp:compute:instance",
            "resource_count": 30,
            "total_gb": 0
        },
        {
            "provider": "gcp",
            "service_family": "Compute",
            "resource_type": "gcp:compute:disk",
            "resource_count": 45,
            "total_gb": 15000
        }
    ]
}
```

## Required Permissions

See [GCP Permissions](../PERMISSIONS.md#gcp-permissions) for the complete role definition.

The simplest approach is to grant the predefined **Viewer** role at the project level.

For least-privilege, you need:
- `compute.instances.list`, `compute.disks.list`, `compute.snapshots.list`
- `storage.buckets.list`, `storage.buckets.get`
- `cloudsql.instances.list`
- `container.clusters.list`
- `cloudfunctions.functions.list`
- `file.instances.list`
- `redis.instances.list`
- `backupdr.backupVaults.list`, `backupdr.backups.list`, etc.

## Dependencies

```bash
pip install google-cloud-compute \
    google-cloud-storage \
    google-api-python-client \
    google-cloud-container \
    google-cloud-functions \
    google-cloud-filestore \
    google-cloud-redis \
    google-cloud-backupdr
```

> **Note:** Cloud SQL collection uses the Google Discovery API (`google-api-python-client`) instead of
> a dedicated SDK, as the Cloud SQL Admin SDK is not available on PyPI.
