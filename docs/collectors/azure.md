# Azure Collector

The Azure collector (`azure_collect.py`) gathers resource inventory from Azure subscriptions including Virtual Machines, Managed Disks, Storage, SQL, and Azure Backup (Recovery Services).

## Basic Usage

```bash
# Collect from all accessible subscriptions
python3 azure_collect.py

# Specific subscription
python3 azure_collect.py --subscription-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Custom output directory
python3 azure_collect.py -o ./my_output/

# Include full resource IDs (default: redact for privacy)
python3 azure_collect.py --include-resource-ids

# Include individual recovery points (can be slow for large environments)
python3 azure_collect.py --include-recovery-points
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `--subscription-id ID` | Specific subscription to collect from |
| `-o, --output PATH` | Output directory |
| `--regions REGIONS` | Filter to specific regions (comma-separated) |
| `--include-resource-ids` | Include full resource IDs (default: redact) |
| `--include-recovery-points` | Include individual recovery points (slow) |
| `--include-change-rate` | Collect change rate metrics from Azure Monitor |
| `--change-rate-days N` | Days to sample for change rate (default: 7) |
| `--parallel-resources N` | Parallel workers for resources (default: 4) |
| `--skip-pvc` | Skip PVC collection from AKS clusters |
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

| Resource Type | Service Family | Description |
|---------------|----------------|-------------|
| `azure:vm` | AzureVM | Virtual machines |
| `azure:disk` | AzureVM | Managed disks |
| `azure:snapshot` | AzureVM | Disk snapshots |
| `azure:storage:blob` | AzureStorage | Storage accounts |
| `azure:storage:fileshare` | AzureFiles | File shares |
| `azure:sql:database` | AzureSQL | SQL databases |
| `azure:sql:managedinstance` | AzureSQL | SQL Managed Instances |
| `azure:cosmosdb:account` | CosmosDB | Cosmos DB accounts |
| `azure:postgresql:flexibleserver` | PostgreSQL | PostgreSQL Flexible Servers |
| `azure:mysql:flexibleserver` | MySQL | MySQL Flexible Servers |
| `azure:mariadb:server` | MariaDB | MariaDB servers |
| `azure:synapse:workspace` | Synapse | Synapse Analytics workspaces |
| `azure:synapse:sqlpool` | Synapse | Dedicated SQL pools |
| `azure:aks:cluster` | AKS | Kubernetes clusters |
| `azure:function:app` | AzureFunctions | Function apps |
| `azure:redis:cache` | Redis | Redis cache instances |
| `azure:recoveryservices:vault` | AzureBackup | Recovery Services vaults |
| `azure:backup:policy` | AzureBackup | Backup policies |
| `azure:backup:protecteditem` | AzureBackup | Protected items |
| `azure:backup:recoverypoint` | AzureBackup | Recovery points |

## Multi-Subscription

The collector automatically iterates all subscriptions your identity has access to. To limit to a specific subscription:

```bash
python3 azure_collect.py --subscription-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
# Or using the short form:
python3 azure_collect.py --subscription xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
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
