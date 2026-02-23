# GCP Collector

The GCP collector (`gcp_collect.py`) gathers resource inventory from Google Cloud projects including Compute Engine, Cloud SQL, GKE, Cloud Storage, and Backup & DR.

## Basic Usage

```bash
# Collect from default project
python3 gcp_collect.py

# Specific project
python3 gcp_collect.py --project my-project-id

# All accessible projects
python3 gcp_collect.py --all-projects

# Custom output directory
python3 gcp_collect.py --output ./my_output/
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `--project PROJECT_ID` | Specific project to collect from |
| `--all-projects` | Collect from all accessible projects |
| `--output PATH` | Output directory |
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

| Resource Type | Service Family | Description |
|---------------|----------------|-------------|
| `gcp:compute:instance` | Compute | VM instances |
| `gcp:compute:disk` | PersistentDisk | Persistent disks |
| `gcp:compute:snapshot` | ComputeSnapshot | Disk snapshots |
| `gcp:storage:bucket` | CloudStorage | Cloud Storage buckets |
| `gcp:sql:instance` | CloudSQL | Cloud SQL instances |
| `gcp:container:cluster` | GKE | GKE clusters |
| `gcp:functions:function` | CloudFunctions | Cloud Functions |
| `gcp:filestore:instance` | Filestore | Filestore instances |
| `gcp:redis:instance` | Memorystore | Memorystore Redis |
| `gcp:bigquery:dataset` | BigQuery | BigQuery datasets |
| `gcp:spanner:instance` | Spanner | Cloud Spanner instances |
| `gcp:bigtable:instance` | Bigtable | Cloud Bigtable instances |
| `gcp:alloydb:cluster` | AlloyDB | AlloyDB clusters |
| `gcp:alloydb:instance` | AlloyDB | AlloyDB instances |
| `gcp:backupdr:vault` | Backup | Backup & DR vaults |
| `gcp:backupdr:plan` | Backup | Backup plans |
| `gcp:backupdr:datasource` | Backup | Data sources |
| `gcp:backupdr:backup` | Backup | Backups |

## Multi-Project Collection

To collect from multiple projects:

```bash
# All projects you have access to
python3 gcp_collect.py --all-projects

# Specific project only
python3 gcp_collect.py --project my-project-id
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
            "service_family": "PersistentDisk",
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
    google-cloud-sql \
    google-cloud-container \
    google-cloud-functions \
    google-cloud-filestore \
    google-cloud-redis \
    google-cloud-backupdr
```
