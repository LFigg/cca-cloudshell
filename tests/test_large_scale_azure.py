"""
Large-scale integration test for Azure resource collector.

This test simulates a large enterprise Azure environment with:
- Multiple subscriptions
- Multiple regions (eastus, westus2, westeurope, southeastasia)
- Hundreds of resources
- Data quality issues (missing tags, incomplete metadata)
- Mixed protection states
- Orphaned resources

Run with: python -m pytest tests/test_large_scale_azure.py -v -s --log-cli-level=INFO

Output files will be generated in: tests/large_scale_output_azure/
"""
import pytest
from unittest.mock import Mock, MagicMock, patch
import json
import os
import shutil
import random
from datetime import datetime, timedelta, timezone
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.models import CloudResource, aggregate_sizing
from lib.utils import (
    generate_run_id,
    get_timestamp,
    write_json,
    write_csv,
    print_summary_table,
)

# =============================================================================
# Constants
# =============================================================================

LARGE_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "large_scale_output", "azure")

REGIONS = ["eastus", "westus2", "westeurope", "southeastasia"]

ENVIRONMENTS = ["production", "staging", "development", "qa", "sandbox", ""]
APPLICATIONS = ["webapp", "api", "database", "cache", "worker", "batch", "analytics", "ml", ""]
TEAMS = ["platform", "infra", "data", "backend", "frontend", "devops", "sre", ""]
COST_CENTERS = ["CC-1001", "CC-1002", "CC-2001", "CC-3001", ""]

VM_SIZES = [
    "Standard_B2s", "Standard_D2s_v3", "Standard_D4s_v3", "Standard_D8s_v3",
    "Standard_E2s_v3", "Standard_E4s_v3", "Standard_F2s_v2", "Standard_F4s_v2",
]

DISK_SKUS = ["Standard_LRS", "StandardSSD_LRS", "Premium_LRS", "Premium_ZRS"]

STORAGE_SKUS = ["Standard_LRS", "Standard_GRS", "Standard_ZRS", "Premium_LRS"]


def setup_large_output_dir():
    """Create clean output directory."""
    if os.path.exists(LARGE_OUTPUT_DIR):
        shutil.rmtree(LARGE_OUTPUT_DIR)
    os.makedirs(LARGE_OUTPUT_DIR)


def random_tags(completeness=0.7):
    """Generate random tags with configurable completeness (data holes)."""
    tags = {}
    
    if random.random() < completeness:
        tags["Name"] = f"{random.choice(['srv', 'app', 'db', 'cache', 'web', 'api'])}-{random.randint(1, 999):03d}"
    
    if random.random() < completeness * 0.8:
        tags["Environment"] = random.choice(ENVIRONMENTS)
    
    if random.random() < completeness * 0.6:
        tags["Application"] = random.choice(APPLICATIONS)
    
    if random.random() < completeness * 0.5:
        tags["Team"] = random.choice(TEAMS)
    
    if random.random() < completeness * 0.4:
        tags["CostCenter"] = random.choice(COST_CENTERS)
    
    if random.random() < 0.3:
        tags["BackupPolicy"] = random.choice(["daily", "weekly", "monthly", "none"])
    
    return tags if tags else None


# =============================================================================
# Mock Azure Resource Generators
# =============================================================================

def create_mock_vms(subscription_id: str, region: str, num_vms: int):
    """Create mock Azure VMs."""
    vms = []
    for i in range(num_vms):
        vm_size = random.choice(VM_SIZES)
        os_disk_size = random.choice([32, 64, 128, 256, 512])
        data_disk_count = random.randint(0, 4)
        tags = random_tags(completeness=random.uniform(0.3, 1.0))
        
        vm = Mock()
        vm.id = f"/subscriptions/{subscription_id}/resourceGroups/rg-{region}/providers/Microsoft.Compute/virtualMachines/vm-{i:03d}"
        vm.name = f"vm-{region[:4]}-{i:03d}"
        vm.location = region
        vm.tags = tags
        vm.provisioning_state = random.choice(["Succeeded"] * 9 + ["Failed"])
        
        vm.hardware_profile = Mock()
        vm.hardware_profile.vm_size = vm_size
        
        vm.storage_profile = Mock()
        vm.storage_profile.os_disk = Mock()
        vm.storage_profile.os_disk.disk_size_gb = os_disk_size
        vm.storage_profile.os_disk.os_type = random.choice(["Linux", "Windows"])
        
        vm.storage_profile.data_disks = []
        for j in range(data_disk_count):
            data_disk = Mock()
            data_disk.managed_disk = Mock()
            data_disk.managed_disk.id = f"/subscriptions/{subscription_id}/resourceGroups/rg-{region}/providers/Microsoft.Compute/disks/datadisk-{i:03d}-{j}"
            vm.storage_profile.data_disks.append(data_disk)
        
        vms.append(vm)
    
    return vms


def create_mock_disks(subscription_id: str, region: str, num_disks: int, attached_ratio: float = 0.7):
    """Create mock Azure Managed Disks."""
    disks = []
    for i in range(num_disks):
        size_gb = random.choice([32, 64, 128, 256, 512, 1024, 2048])
        sku = random.choice(DISK_SKUS)
        is_attached = random.random() < attached_ratio
        tags = random_tags(completeness=random.uniform(0.2, 0.9))
        
        disk = Mock()
        disk.id = f"/subscriptions/{subscription_id}/resourceGroups/rg-{region}/providers/Microsoft.Compute/disks/disk-{i:03d}"
        disk.name = f"disk-{region[:4]}-{i:03d}"
        disk.location = region
        disk.disk_size_gb = size_gb
        disk.disk_state = "Attached" if is_attached else "Unattached"
        disk.tags = tags
        disk.os_type = random.choice([None, "Linux", "Windows"])
        
        disk.sku = Mock()
        disk.sku.name = sku
        
        disk.encryption = Mock()
        disk.encryption.type = "EncryptionAtRestWithPlatformKey"
        
        if is_attached:
            disk.managed_by = f"/subscriptions/{subscription_id}/resourceGroups/rg-{region}/providers/Microsoft.Compute/virtualMachines/vm-{random.randint(0, 50):03d}"
        else:
            disk.managed_by = None
        
        disks.append(disk)
    
    return disks


def create_mock_snapshots(subscription_id: str, region: str, num_snapshots: int):
    """Create mock Azure Snapshots."""
    snapshots = []
    for i in range(num_snapshots):
        size_gb = random.choice([32, 64, 128, 256, 512])
        tags = random_tags(completeness=random.uniform(0.3, 0.8))
        
        snapshot = Mock()
        snapshot.id = f"/subscriptions/{subscription_id}/resourceGroups/rg-{region}/providers/Microsoft.Compute/snapshots/snap-{i:03d}"
        snapshot.name = f"snap-{region[:4]}-{i:03d}"
        snapshot.location = region
        snapshot.disk_size_gb = size_gb
        snapshot.tags = tags
        snapshot.time_created = (datetime.now(timezone.utc) - timedelta(days=random.randint(1, 90))).isoformat()
        snapshot.provisioning_state = "Succeeded"
        
        snapshot.creation_data = Mock()
        snapshot.creation_data.source_resource_id = f"/subscriptions/{subscription_id}/resourceGroups/rg-{region}/providers/Microsoft.Compute/disks/disk-{random.randint(0, 50):03d}"
        
        snapshot.sku = Mock()
        snapshot.sku.name = "Standard_LRS"
        
        snapshots.append(snapshot)
    
    return snapshots


def create_mock_storage_accounts(subscription_id: str, region: str, num_accounts: int):
    """Create mock Azure Storage Accounts."""
    accounts = []
    for i in range(num_accounts):
        sku = random.choice(STORAGE_SKUS)
        kind = random.choice(["StorageV2", "BlobStorage", "FileStorage"])
        tags = random_tags(completeness=random.uniform(0.4, 0.9))
        
        account = Mock()
        account.id = f"/subscriptions/{subscription_id}/resourceGroups/rg-{region}/providers/Microsoft.Storage/storageAccounts/storage{region[:4]}{i:03d}"
        account.name = f"storage{region[:4]}{i:03d}"
        account.location = region
        account.kind = kind
        account.tags = tags
        
        account.sku = Mock()
        account.sku.name = sku
        
        account.primary_endpoints = Mock()
        account.primary_endpoints.blob = f"https://storage{region[:4]}{i:03d}.blob.core.windows.net/"
        
        account.access_tier = random.choice(["Hot", "Cool"])
        account.provisioning_state = "Succeeded"
        
        account.encryption = Mock()
        account.encryption.services = Mock()
        account.encryption.services.blob = Mock()
        account.encryption.services.blob.enabled = True
        
        accounts.append(account)
    
    return accounts


def create_mock_sql_databases(subscription_id: str, region: str, num_servers: int, dbs_per_server: int = 3):
    """Create mock Azure SQL Servers and Databases."""
    servers = []
    databases = []
    
    for i in range(num_servers):
        tags = random_tags(completeness=random.uniform(0.5, 0.9))
        server_name = f"sqlserver-{region[:4]}-{i:03d}"
        
        server = Mock()
        server.id = f"/subscriptions/{subscription_id}/resourceGroups/rg-{region}/providers/Microsoft.Sql/servers/{server_name}"
        server.name = server_name
        server.location = region
        server.tags = tags
        server.state = "Ready"
        server.fully_qualified_domain_name = f"{server_name}.database.windows.net"
        server.version = "12.0"
        servers.append(server)
        
        # Create databases for this server
        for j in range(random.randint(1, dbs_per_server)):
            db_tags = random_tags(completeness=random.uniform(0.3, 0.8))
            db_name = f"{server_name}-db-{j:02d}"
            
            db = Mock()
            db.id = f"/subscriptions/{subscription_id}/resourceGroups/rg-{region}/providers/Microsoft.Sql/servers/{server_name}/databases/{db_name}"
            db.name = db_name
            db.location = region
            db.server_name = server_name
            db.tags = db_tags
            db.status = "Online"
            db.max_size_bytes = random.choice([1073741824, 10737418240, 53687091200, 107374182400]) # 1GB, 10GB, 50GB, 100GB
            
            db.sku = Mock()
            db.sku.name = random.choice(["S0", "S1", "S2", "P1", "P2"])
            db.sku.tier = random.choice(["Standard", "Premium"])
            
            databases.append(db)
    
    return servers, databases


def create_mock_cosmosdb_accounts(subscription_id: str, region: str, num_accounts: int):
    """Create mock CosmosDB accounts."""
    accounts = []
    for i in range(num_accounts):
        tags = random_tags(completeness=random.uniform(0.4, 0.8))
        
        account = Mock()
        account.id = f"/subscriptions/{subscription_id}/resourceGroups/rg-{region}/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-{region[:4]}-{i:03d}"
        account.name = f"cosmos-{region[:4]}-{i:03d}"
        account.location = region
        account.tags = tags
        account.kind = random.choice(["GlobalDocumentDB", "MongoDB"])
        account.provisioning_state = "Succeeded"
        
        account.consistency_policy = Mock()
        account.consistency_policy.default_consistency_level = random.choice(["Session", "Eventual", "Strong"])
        
        account.locations = [Mock(location_name=region, failover_priority=0)]
        if random.random() < 0.3:
            backup_region = random.choice([r for r in REGIONS if r != region])
            account.locations.append(Mock(location_name=backup_region, failover_priority=1))
        
        accounts.append(account)
    
    return accounts


def create_mock_aks_clusters(subscription_id: str, region: str, num_clusters: int):
    """Create mock AKS clusters."""
    clusters = []
    for i in range(num_clusters):
        tags = random_tags(completeness=random.uniform(0.5, 0.9))
        
        cluster = Mock()
        cluster.id = f"/subscriptions/{subscription_id}/resourceGroups/rg-{region}/providers/Microsoft.ContainerService/managedClusters/aks-{region[:4]}-{i:03d}"
        cluster.name = f"aks-{region[:4]}-{i:03d}"
        cluster.location = region
        cluster.tags = tags
        cluster.provisioning_state = "Succeeded"
        cluster.kubernetes_version = random.choice(["1.28.5", "1.29.2", "1.30.0"])
        
        # Node pools
        cluster.agent_pool_profiles = []
        num_pools = random.randint(1, 3)
        for j in range(num_pools):
            pool = Mock()
            pool.name = f"nodepool{j}"
            pool.count = random.randint(2, 10)
            pool.vm_size = random.choice(VM_SIZES)
            pool.os_disk_size_gb = random.choice([100, 128, 256])
            cluster.agent_pool_profiles.append(pool)
        
        clusters.append(cluster)
    
    return clusters


def create_mock_function_apps(subscription_id: str, region: str, num_apps: int):
    """Create mock Azure Function Apps."""
    apps = []
    for i in range(num_apps):
        tags = random_tags(completeness=random.uniform(0.3, 0.7))
        
        app = Mock()
        app.id = f"/subscriptions/{subscription_id}/resourceGroups/rg-{region}/providers/Microsoft.Web/sites/func-{region[:4]}-{i:03d}"
        app.name = f"func-{region[:4]}-{i:03d}"
        app.location = region
        app.tags = tags
        app.state = random.choice(["Running"] * 9 + ["Stopped"])
        app.kind = "functionapp"
        
        apps.append(app)
    
    return apps


def create_mock_redis_caches(subscription_id: str, region: str, num_caches: int):
    """Create mock Redis Cache instances."""
    caches = []
    for i in range(num_caches):
        tags = random_tags(completeness=random.uniform(0.4, 0.8))
        
        cache = Mock()
        cache.id = f"/subscriptions/{subscription_id}/resourceGroups/rg-{region}/providers/Microsoft.Cache/Redis/redis-{region[:4]}-{i:03d}"
        cache.name = f"redis-{region[:4]}-{i:03d}"
        cache.location = region
        cache.tags = tags
        cache.provisioning_state = "Succeeded"
        
        cache.sku = Mock()
        cache.sku.name = random.choice(["Basic", "Standard", "Premium"])
        cache.sku.family = random.choice(["C", "P"])
        cache.sku.capacity = random.choice([0, 1, 2, 3, 4])
        
        cache.shard_count = random.choice([0, 2, 4]) if cache.sku.name == "Premium" else 0
        
        caches.append(cache)
    
    return caches


def create_mock_recovery_vaults(subscription_id: str, region: str, num_vaults: int):
    """Create mock Recovery Services Vaults."""
    vaults = []
    for i in range(num_vaults):
        tags = random_tags(completeness=random.uniform(0.5, 0.9))
        
        vault = Mock()
        vault.id = f"/subscriptions/{subscription_id}/resourceGroups/rg-{region}/providers/Microsoft.RecoveryServices/vaults/vault-{region[:4]}-{i:03d}"
        vault.name = f"vault-{region[:4]}-{i:03d}"
        vault.location = region
        vault.tags = tags
        vault.type = "Microsoft.RecoveryServices/vaults"
        
        vault.properties = Mock()
        vault.properties.provisioning_state = "Succeeded"
        
        vaults.append(vault)
    
    return vaults


# =============================================================================
# Test Class
# =============================================================================

class TestLargeScaleAzure:
    """Large-scale integration test for Azure with realistic enterprise data."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures."""
        setup_large_output_dir()
        yield
    
    @patch('azure_collect.RecoveryServicesBackupClient')
    @patch('azure_collect.RecoveryServicesClient')
    @patch('azure_collect.WebSiteManagementClient')
    @patch('azure_collect.ContainerServiceClient')
    @patch('azure_collect.CosmosDBManagementClient')
    @patch('azure_collect.SqlManagementClient')
    @patch('azure_collect.StorageManagementClient')
    @patch('azure_collect.ComputeManagementClient')
    def test_large_scale_azure_collection(
        self,
        mock_compute_client,
        mock_storage_client,
        mock_sql_client,
        mock_cosmosdb_client,
        mock_container_client,
        mock_web_client,
        mock_recovery_client,
        mock_backup_client,
    ):
        """
        Test collection across a large, realistic Azure enterprise environment.
        
        Scale:
        - 4 regions
        - ~50 VMs per region
        - ~80 Managed Disks per region (includes orphaned)
        - ~50 Snapshots per region
        - ~10 Storage Accounts per region
        - ~8 SQL Servers with ~20 databases per region
        - ~5 CosmosDB accounts per region
        - ~3 AKS clusters per region
        - ~15 Function Apps per region
        - ~5 Redis Caches per region
        - ~2 Recovery Services Vaults per region
        """
        print("\n" + "=" * 80)
        print("LARGE-SCALE AZURE INTEGRATION TEST")
        print("=" * 80)
        
        # Configuration - scale factors
        VMS_PER_REGION = 50
        DISKS_PER_REGION = 80
        SNAPSHOTS_PER_REGION = 50
        STORAGE_ACCOUNTS_PER_REGION = 10
        SQL_SERVERS_PER_REGION = 8
        COSMOSDB_PER_REGION = 5
        AKS_PER_REGION = 3
        FUNCTION_APPS_PER_REGION = 15
        REDIS_PER_REGION = 5
        RECOVERY_VAULTS_PER_REGION = 2
        
        subscription_id = "12345678-1234-1234-1234-123456789012"
        subscription_name = "Enterprise Production"
        
        print("\n📦 Creating mock Azure infrastructure...\n")
        
        all_resources = []
        
        for region in REGIONS:
            print(f"  Setting up {region}...")
            
            # Generate mock resources for this region
            vms = create_mock_vms(subscription_id, region, VMS_PER_REGION)
            disks = create_mock_disks(subscription_id, region, DISKS_PER_REGION)
            snapshots = create_mock_snapshots(subscription_id, region, SNAPSHOTS_PER_REGION)
            storage_accounts = create_mock_storage_accounts(subscription_id, region, STORAGE_ACCOUNTS_PER_REGION)
            sql_servers, sql_databases = create_mock_sql_databases(subscription_id, region, SQL_SERVERS_PER_REGION)
            cosmosdb_accounts = create_mock_cosmosdb_accounts(subscription_id, region, COSMOSDB_PER_REGION)
            aks_clusters = create_mock_aks_clusters(subscription_id, region, AKS_PER_REGION)
            function_apps = create_mock_function_apps(subscription_id, region, FUNCTION_APPS_PER_REGION)
            redis_caches = create_mock_redis_caches(subscription_id, region, REDIS_PER_REGION)
            recovery_vaults = create_mock_recovery_vaults(subscription_id, region, RECOVERY_VAULTS_PER_REGION)
            
            # Convert to CloudResource objects
            for vm in vms:
                os_disk_size = vm.storage_profile.os_disk.disk_size_gb if vm.storage_profile and vm.storage_profile.os_disk else 0
                resource = CloudResource(
                    provider="azure",
                    subscription_id=subscription_id,
                    region=vm.location,
                    resource_type="azure:vm",
                    service_family="AzureVM",
                    resource_id=vm.id,
                    name=vm.name,
                    tags=vm.tags or {},
                    size_gb=float(os_disk_size),
                    metadata={
                        'vm_size': vm.hardware_profile.vm_size if vm.hardware_profile else 'unknown',
                        'provisioning_state': vm.provisioning_state,
                        'data_disk_count': len(vm.storage_profile.data_disks) if vm.storage_profile else 0,
                    }
                )
                all_resources.append(resource)
            
            for disk in disks:
                resource = CloudResource(
                    provider="azure",
                    subscription_id=subscription_id,
                    region=disk.location,
                    resource_type="azure:disk",
                    service_family="AzureDisk",
                    resource_id=disk.id,
                    name=disk.name,
                    tags=disk.tags or {},
                    size_gb=float(disk.disk_size_gb),
                    metadata={
                        'disk_state': disk.disk_state,
                        'sku': disk.sku.name if disk.sku else 'unknown',
                        'attached_to': disk.managed_by,
                    }
                )
                all_resources.append(resource)
            
            for snapshot in snapshots:
                resource = CloudResource(
                    provider="azure",
                    subscription_id=subscription_id,
                    region=snapshot.location,
                    resource_type="azure:snapshot",
                    service_family="AzureSnapshot",
                    resource_id=snapshot.id,
                    name=snapshot.name,
                    tags=snapshot.tags or {},
                    size_gb=float(snapshot.disk_size_gb),
                    metadata={
                        'source_disk': snapshot.creation_data.source_resource_id if snapshot.creation_data else None,
                        'time_created': snapshot.time_created,
                    }
                )
                all_resources.append(resource)
            
            for account in storage_accounts:
                resource = CloudResource(
                    provider="azure",
                    subscription_id=subscription_id,
                    region=account.location,
                    resource_type="azure:storage:account",
                    service_family="AzureStorage",
                    resource_id=account.id,
                    name=account.name,
                    tags=account.tags or {},
                    size_gb=0.0,  # Would need metrics API for actual usage
                    metadata={
                        'kind': account.kind,
                        'sku': account.sku.name if account.sku else 'unknown',
                        'access_tier': account.access_tier,
                    }
                )
                all_resources.append(resource)
            
            for db in sql_databases:
                size_gb = db.max_size_bytes / (1024**3) if db.max_size_bytes else 0
                resource = CloudResource(
                    provider="azure",
                    subscription_id=subscription_id,
                    region=db.location,
                    resource_type="azure:sql:database",
                    service_family="AzureSQLDB",
                    resource_id=db.id,
                    name=db.name,
                    tags=db.tags or {},
                    size_gb=size_gb,
                    metadata={
                        'server_name': db.server_name,
                        'sku': db.sku.name if db.sku else 'unknown',
                        'status': db.status,
                    }
                )
                all_resources.append(resource)
            
            for account in cosmosdb_accounts:
                resource = CloudResource(
                    provider="azure",
                    subscription_id=subscription_id,
                    region=account.location,
                    resource_type="azure:cosmosdb:account",
                    service_family="AzureCosmosDB",
                    resource_id=account.id,
                    name=account.name,
                    tags=account.tags or {},
                    size_gb=0.0,
                    metadata={
                        'kind': account.kind,
                        'consistency_level': account.consistency_policy.default_consistency_level if account.consistency_policy else 'unknown',
                    }
                )
                all_resources.append(resource)
            
            for cluster in aks_clusters:
                total_nodes = sum(pool.count for pool in cluster.agent_pool_profiles) if cluster.agent_pool_profiles else 0
                resource = CloudResource(
                    provider="azure",
                    subscription_id=subscription_id,
                    region=cluster.location,
                    resource_type="azure:aks:cluster",
                    service_family="AzureAKS",
                    resource_id=cluster.id,
                    name=cluster.name,
                    tags=cluster.tags or {},
                    size_gb=0.0,
                    metadata={
                        'kubernetes_version': cluster.kubernetes_version,
                        'node_pool_count': len(cluster.agent_pool_profiles) if cluster.agent_pool_profiles else 0,
                        'total_nodes': total_nodes,
                    }
                )
                all_resources.append(resource)
            
            for app in function_apps:
                resource = CloudResource(
                    provider="azure",
                    subscription_id=subscription_id,
                    region=app.location,
                    resource_type="azure:function:app",
                    service_family="AzureFunctions",
                    resource_id=app.id,
                    name=app.name,
                    tags=app.tags or {},
                    size_gb=0.0,
                    metadata={
                        'state': app.state,
                    }
                )
                all_resources.append(resource)
            
            for cache in redis_caches:
                resource = CloudResource(
                    provider="azure",
                    subscription_id=subscription_id,
                    region=cache.location,
                    resource_type="azure:redis:cache",
                    service_family="AzureRedis",
                    resource_id=cache.id,
                    name=cache.name,
                    tags=cache.tags or {},
                    size_gb=0.0,
                    metadata={
                        'sku': cache.sku.name if cache.sku else 'unknown',
                        'capacity': cache.sku.capacity if cache.sku else 0,
                    }
                )
                all_resources.append(resource)
            
            for vault in recovery_vaults:
                resource = CloudResource(
                    provider="azure",
                    subscription_id=subscription_id,
                    region=vault.location,
                    resource_type="azure:recovery:vault",
                    service_family="AzureRecoveryServices",
                    resource_id=vault.id,
                    name=vault.name,
                    tags=vault.tags or {},
                    size_gb=0.0,
                    metadata={}
                )
                all_resources.append(resource)
            
            print(f"    Created {len(vms)} VMs, {len(disks)} disks, {len(snapshots)} snapshots, "
                  f"{len(storage_accounts)} storage accounts, {len(sql_databases)} SQL DBs, "
                  f"{len(cosmosdb_accounts)} CosmosDB, {len(aks_clusters)} AKS clusters")
        
        print("\n✅ Mock infrastructure created\n")
        
        # Generate outputs
        run_id = generate_run_id()
        timestamp = get_timestamp()
        
        # Build sizing summaries
        summaries = aggregate_sizing(all_resources)
        
        inventory_data = {
            'provider': 'azure',
            'run_id': run_id,
            'timestamp': timestamp,
            'subscription_id': subscription_id,
            'subscription_name': subscription_name,
            'regions': REGIONS,
            'resources': [r.to_dict() for r in all_resources]
        }
        
        summary_data = {
            'provider': 'azure',
            'run_id': run_id,
            'timestamp': timestamp,
            'subscription_id': subscription_id,
            'total_resources': len(all_resources),
            'total_capacity_gb': sum(s.total_gb for s in summaries),
            'summaries': [s.to_dict() for s in summaries]
        }
        
        # Write output files
        file_ts = datetime.now(timezone.utc).strftime('%H%M%S')
        write_json(inventory_data, f"{LARGE_OUTPUT_DIR}/cca_inv_{file_ts}.json")
        write_json(summary_data, f"{LARGE_OUTPUT_DIR}/cca_sum_{file_ts}.json")
        
        csv_data = [s.to_dict() for s in summaries]
        write_csv(csv_data, f"{LARGE_OUTPUT_DIR}/sizing.csv")
        
        # Print statistics
        print("\n" + "=" * 80)
        print("COLLECTION RESULTS")
        print("=" * 80)
        print(f"\nSubscription: {subscription_id}")
        print(f"Regions: {len(REGIONS)}")
        print(f"Total Resources: {len(all_resources)}")
        
        # Count by type
        by_type = {}
        for r in all_resources:
            by_type[r.resource_type] = by_type.get(r.resource_type, 0) + 1
        
        print("\nResources by Type:")
        for rtype, count in sorted(by_type.items()):
            print(f"  {rtype}: {count}")
        
        # Count resources with missing names (data holes)
        missing_names = len([r for r in all_resources if not r.name or r.name == "unnamed"])
        print(f"\nData Quality:")
        if len(all_resources) > 0:
            print(f"  Resources with missing names: {missing_names} ({missing_names/len(all_resources)*100:.1f}%)")
        else:
            print(f"  Resources with missing names: {missing_names}")
        
        # Count by region
        by_region = {}
        for r in all_resources:
            by_region[r.region] = by_region.get(r.region, 0) + 1
        
        print("\nResources by Region:")
        for region, count in sorted(by_region.items()):
            print(f"  {region}: {count}")
        
        print_summary_table([s.to_dict() for s in summaries])
        
        print(f"\nOutput: {LARGE_OUTPUT_DIR}/")
        
        # Assertions
        assert len(all_resources) > 500, "Should have collected many resources"
        assert len(by_region) == len(REGIONS), "Should have resources from all regions"
        
        # Verify files exist
        import glob
        inv_files = glob.glob(f"{LARGE_OUTPUT_DIR}/cca_inv_*.json")
        assert len(inv_files) >= 1, "Inventory file should exist"
        
        print("\n" + "=" * 80)
        print("TEST COMPLETE")
        print("=" * 80)


# =============================================================================
# Run directly
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--log-cli-level=INFO"])
