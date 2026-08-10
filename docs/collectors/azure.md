# Azure Collector

The Azure collector gathers resource inventory from Azure subscriptions including Virtual Machines, Managed Disks, Storage, SQL, and Azure Backup (Recovery Services). It also collects data protection cost data from Cost Management by default.

## Basic Usage

```bash
# Collect from all accessible subscriptions
python3 collect.py --cloud azure

# Specific subscription
python3 collect.py --cloud azure --subscription-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Custom output directory
python3 collect.py --cloud azure -o ./my_output/

# Include full resource IDs (default: redact for privacy)
python3 collect.py --cloud azure --include-resource-ids

# Include individual recovery points (can be slow for large environments)
python3 collect.py --cloud azure --include-recovery-points

# Skip cost collection (costs collected by default)
python3 collect.py --cloud azure --no-costs
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `--subscription-id ID` | Specific subscription to collect from |
| `-o, --output PATH` | Output directory |
| `--regions REGIONS` | Filter to specific regions (comma-separated) |
| `--include-resource-ids` | Include full resource IDs (default: redact) |
| `--include-recovery-points` | Include individual recovery points (slow) |
| `--skip-change-rate` | Skip change rate metrics collection |
| `--change-rate-days N` | Days to sample for change rate (default: 7) |
| `--parallel-resources N` | Parallel workers for resources (default: 4) |
| `--skip-pvc` | Skip PVC collection from AKS clusters |
| `--no-costs` | Skip data protection cost collection (costs are ON by default) |
| `--log-level LEVEL` | Logging level (default: INFO) |

## Authentication

### Azure Cloud Shell

Credentials are automatic - just run the collector.

### Local Execution

```bash
# Login via Azure CLI
az login

# Or use a service principal
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
```

The collector uses `DefaultAzureCredential` which tries multiple authentication methods in order.

## Collected Resources

| Resource Type | Service Family | Size Data | Description |
|---------------|----------------|-----------|-------------|
| `azure:vm` | AzureVM | n/a (sized via disks) | Virtual machines |
| `azure:disk` | AzureVM | Provisioned (this is the disk's actual size) | Managed disks |
| `azure:snapshot` | AzureVM | Provisioned (this is the disk's actual size) | Disk snapshots |
| `azure:storage:blob` | AzureStorage | ✅ Actual usage (Azure Monitor), when available; ⚠️ Unavailable otherwise | Storage accounts |
| `azure:storage:fileshare` | AzureFiles | ✅ Actual usage (`file_shares.get(expand='stats')`) | File shares |
| `azure:sql:database` | AzureSQL | ✅ Actual usage (Azure Monitor), when available; ⚠️ Unavailable otherwise | SQL databases |
| `azure:sql:managedinstance` | AzureSQL | ✅ Actual usage (Azure Monitor `storage_space_used_mb`), when available; ⚠️ Unavailable otherwise | SQL Managed Instances |
| `azure:sql:restorepoint` | SQLDatabase | n/a | SQL database restore points |
| `azure:sql:ltrbackup` | SQLDatabase | n/a | SQL long-term retention backups |
| `azure:cosmosdb:account` | CosmosDB | ✅ Actual usage (Azure Monitor `DataUsage`+`IndexUsage`), when available; ⚠️ Unavailable otherwise | Cosmos DB accounts |
| `azure:postgresql:flexibleserver` | PostgreSQL | ✅ Actual usage (Azure Monitor `storage_used`), when available; ⚠️ Unavailable otherwise | PostgreSQL Flexible Servers |
| `azure:mysql:flexibleserver` | MySQL | ✅ Actual usage (Azure Monitor `storage_used`), when available; ⚠️ Unavailable otherwise | MySQL Flexible Servers |
| `azure:mariadb:server` | MariaDB | ⚠️ Unavailable (service retired 2025-09-19) | MariaDB servers |
| `azure:synapse:workspace` | Synapse | n/a | Synapse Analytics workspaces |
| `azure:synapse:sqlpool` | Synapse | ⚠️ Unavailable (no Monitor metric exists for this resource type) | Dedicated SQL pools |
| `azure:aks:cluster` | AKS | n/a | Kubernetes clusters |
| `azure:function:app` | AzureFunctions | n/a | Function apps |
| `azure:redis:cache` | Redis | ✅ Actual usage (Azure Monitor `usedmemory`), non-clustered caches only; ⚠️ Unavailable for clustered caches or when Monitor is unavailable | Redis cache instances |
| `azure:netapp:volume` | NetAppFiles | ✅ Actual usage (Azure Monitor `VolumeLogicalSize`), when available; ⚠️ Unavailable otherwise | NetApp Files volumes |
| `azure:recoveryservices:vault` | AzureBackup | n/a | Recovery Services vaults |
| `azure:backup:policy` | AzureBackup | n/a | Backup policies |
| `azure:backup:protecteditem` | AzureBackup | n/a | Protected items |
| `azure:backup:recoverypoint` | AzureBackup | n/a | Recovery points |

**Size Data** reflects whether `size_gb` is a real, measured value or currently unavailable (reported as
`0.0`, never a provisioned/allocated estimate) — see each resource's `metadata.size_source` in the output
JSON (`'usage'`, `'unavailable'`, or `'not_applicable'`), and `data_quality` in the summary JSON for a
collection-wide rollup.

## Cost Collection

Azure cost collection queries the Cost Management API for data protection spending (Azure Backup service, Azure Site Recovery, snapshot-related storage). It runs automatically and writes `cca_azure_costs_<time>.json`.

```bash
# Costs on by default
python3 collect.py --cloud azure

# Skip costs
python3 collect.py --cloud azure --no-costs
```

Required role for cost collection: **Cost Management Reader** (built-in), or add:
```json
{"Actions": ["Microsoft.CostManagement/query/read"]}
```

## Multi-Subscription

The collector automatically iterates all subscriptions your identity has access to. To limit to a specific subscription:

```bash
python3 collect.py --cloud azure --subscription-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
# Or using the short form:
python3 collect.py --cloud azure --subscription xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

## Example Output

**Summary JSON:**
```json
{
    "run_id": "20260211-143052-abc123",
    "timestamp": "2026-02-11T14:30:52.123456Z",
    "provider": "azure",
    "subscriptions": ["xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"],
    "total_resources": 180,
    "total_capacity_gb": 12500.0,
    "summaries": [
        {
            "provider": "azure",
            "service_family": "AzureVM",
            "resource_type": "azure:vm",
            "resource_count": 25,
            "total_gb": 0
        },
        {
            "provider": "azure",
            "service_family": "AzureVM",
            "resource_type": "azure:disk",
            "resource_count": 40,
            "total_gb": 8000
        }
    ]
}
```

## Required Permissions

See [Azure Permissions](../PERMISSIONS.md#azure-permissions) for the complete role definition.

The simplest approach is to assign the built-in **Reader** role at the subscription level.

For least-privilege, you need read access to:
- `Microsoft.Compute/*` - VMs, Disks, Snapshots
- `Microsoft.Storage/*` - Storage Accounts, File Shares
- `Microsoft.Sql/*` - SQL Databases, Managed Instances
- `Microsoft.DocumentDB/*` - Cosmos DB
- `Microsoft.ContainerService/*` - AKS
- `Microsoft.Web/*` - Function Apps
- `Microsoft.Cache/*` - Redis
- `Microsoft.RecoveryServices/*` - Backup Vaults, Policies, Protected Items

## Dependencies

```bash
pip install azure-identity \
    azure-mgmt-resource \
    azure-mgmt-compute \
    azure-mgmt-storage \
    azure-mgmt-sql \
    azure-mgmt-cosmosdb \
    azure-mgmt-containerservice \
    azure-mgmt-web \
    azure-mgmt-recoveryservices \
    azure-mgmt-recoveryservicesbackup \
    azure-mgmt-redis
```
