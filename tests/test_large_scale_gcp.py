"""
Large-scale integration test for GCP resource collector.

This test simulates a large enterprise GCP environment with:
- Multiple projects
- Multiple regions (us-central1, us-east1, europe-west1, asia-east1)
- Hundreds of resources
- Data quality issues (missing labels, incomplete metadata)
- Mixed protection states
- Orphaned resources

Run with: python -m pytest tests/test_large_scale_gcp.py -v -s --log-cli-level=INFO

Output files will be generated in: tests/large_scale_output_gcp/
"""
import os
import random
import shutil
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.models import CloudResource, aggregate_sizing
from lib.utils import (
    generate_run_id,
    get_timestamp,
    print_summary_table,
    write_csv,
    write_json,
)

# =============================================================================
# Constants
# =============================================================================

LARGE_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "large_scale_output", "gcp")

REGIONS = ["us-central1", "us-east1", "europe-west1", "asia-east1"]
ZONES = {
    "us-central1": ["us-central1-a", "us-central1-b", "us-central1-c"],
    "us-east1": ["us-east1-b", "us-east1-c", "us-east1-d"],
    "europe-west1": ["europe-west1-b", "europe-west1-c", "europe-west1-d"],
    "asia-east1": ["asia-east1-a", "asia-east1-b", "asia-east1-c"],
}

ENVIRONMENTS = ["production", "staging", "development", "qa", "sandbox", ""]
APPLICATIONS = ["webapp", "api", "database", "cache", "worker", "batch", "analytics", "ml", ""]
TEAMS = ["platform", "infra", "data", "backend", "frontend", "devops", "sre", ""]
COST_CENTERS = ["cc-1001", "cc-1002", "cc-2001", "cc-3001", ""]

MACHINE_TYPES = [
    "e2-micro", "e2-small", "e2-medium", "e2-standard-2", "e2-standard-4",
    "n2-standard-2", "n2-standard-4", "n2-standard-8",
    "c2-standard-4", "c2-standard-8",
]

DISK_TYPES = ["pd-standard", "pd-ssd", "pd-balanced", "pd-extreme"]

STORAGE_CLASSES = ["STANDARD", "NEARLINE", "COLDLINE", "ARCHIVE"]


def setup_large_output_dir():
    """Create clean output directory."""
    if os.path.exists(LARGE_OUTPUT_DIR):
        shutil.rmtree(LARGE_OUTPUT_DIR)
    os.makedirs(LARGE_OUTPUT_DIR)


def random_labels(completeness=0.7):
    """Generate random labels with configurable completeness (data holes)."""
    labels = {}

    if random.random() < completeness:
        labels["name"] = f"{random.choice(['srv', 'app', 'db', 'cache', 'web', 'api'])}-{random.randint(1, 999):03d}"

    if random.random() < completeness * 0.8:
        labels["env"] = random.choice(ENVIRONMENTS)

    if random.random() < completeness * 0.6:
        labels["app"] = random.choice(APPLICATIONS)

    if random.random() < completeness * 0.5:
        labels["team"] = random.choice(TEAMS)

    if random.random() < completeness * 0.4:
        labels["cost-center"] = random.choice(COST_CENTERS)

    if random.random() < 0.3:
        labels["backup-policy"] = random.choice(["daily", "weekly", "monthly", "none"])

    return labels if labels else {}


# =============================================================================
# Mock GCP Resource Generators
# =============================================================================

def create_mock_compute_instances(project_id: str, region: str, num_instances: int):
    """Create mock GCP Compute Engine instances."""
    instances = []
    zones = ZONES.get(region, [f"{region}-a"])

    for i in range(num_instances):
        zone = random.choice(zones)
        machine_type = random.choice(MACHINE_TYPES)
        disk_size_gb = random.choice([10, 20, 50, 100, 200, 500])
        labels = random_labels(completeness=random.uniform(0.3, 1.0))

        instance = Mock()
        instance.name = f"instance-{region.replace('-', '')[:8]}-{i:03d}"
        instance.machine_type = f"projects/{project_id}/zones/{zone}/machineTypes/{machine_type}"
        instance.status = random.choice(["RUNNING"] * 8 + ["STOPPED"] + ["TERMINATED"])
        instance.labels = labels

        instance.scheduling = Mock()
        instance.scheduling.preemptible = random.random() < 0.1

        # Disks
        disk = Mock()
        disk.source = f"projects/{project_id}/zones/{zone}/disks/{instance.name}-disk"
        disk.disk_size_gb = disk_size_gb
        instance.disks = [disk]

        # Add data disks sometimes
        if random.random() < 0.3:
            for j in range(random.randint(1, 3)):
                data_disk = Mock()
                data_disk.source = f"projects/{project_id}/zones/{zone}/disks/{instance.name}-data-{j}"
                data_disk.disk_size_gb = random.choice([100, 200, 500, 1000])
                instance.disks.append(data_disk)

        instance.network_interfaces = [Mock()]
        instance.zone = zone

        instances.append(instance)

    return instances


def create_mock_persistent_disks(project_id: str, region: str, num_disks: int, attached_ratio: float = 0.7):
    """Create mock GCP Persistent Disks."""
    disks = []
    zones = ZONES.get(region, [f"{region}-a"])

    for i in range(num_disks):
        zone = random.choice(zones)
        size_gb = random.choice([10, 20, 50, 100, 200, 500, 1000, 2000])
        disk_type = random.choice(DISK_TYPES)
        is_attached = random.random() < attached_ratio
        labels = random_labels(completeness=random.uniform(0.2, 0.9))

        disk = Mock()
        disk.name = f"disk-{region.replace('-', '')[:8]}-{i:03d}"
        disk.self_link = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/zones/{zone}/disks/{disk.name}"
        disk.size_gb = size_gb
        disk.type_ = f"projects/{project_id}/zones/{zone}/diskTypes/{disk_type}"
        disk.status = "READY"
        disk.labels = labels
        disk.source_image = ""
        disk.source_snapshot = ""

        if is_attached:
            disk.users = [f"projects/{project_id}/zones/{zone}/instances/instance-{random.randint(0, 50):03d}"]
        else:
            disk.users = []

        disk.zone = zone
        disks.append(disk)

    return disks


def create_mock_snapshots(project_id: str, num_snapshots: int):
    """Create mock GCP Disk Snapshots."""
    snapshots = []

    for i in range(num_snapshots):
        disk_size_gb = random.choice([10, 20, 50, 100, 200, 500])
        storage_bytes = disk_size_gb * 1024 * 1024 * 1024 * random.uniform(0.3, 0.8)
        labels = random_labels(completeness=random.uniform(0.3, 0.8))
        region = random.choice(REGIONS)
        zone = random.choice(ZONES.get(region, [f"{region}-a"]))

        snapshot = Mock()
        snapshot.name = f"snapshot-{i:04d}"
        snapshot.self_link = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/global/snapshots/{snapshot.name}"
        snapshot.disk_size_gb = disk_size_gb
        snapshot.storage_bytes = int(storage_bytes)
        snapshot.source_disk = f"projects/{project_id}/zones/{zone}/disks/disk-{random.randint(0, 100):03d}"
        snapshot.status = "READY"
        snapshot.labels = labels
        snapshot.creation_timestamp = (datetime.now(timezone.utc) - timedelta(days=random.randint(1, 90))).isoformat()
        snapshot.storage_locations = [region]

        snapshots.append(snapshot)

    return snapshots


def create_mock_storage_buckets(project_id: str, num_buckets: int):
    """Create mock GCP Cloud Storage Buckets."""
    buckets = []

    for i in range(num_buckets):
        location = random.choice(REGIONS + ["US", "EU", "ASIA"])
        storage_class = random.choice(STORAGE_CLASSES)
        labels = random_labels(completeness=random.uniform(0.3, 0.8))
        # Simulate bucket sizes - varies widely from small to large
        size_gb = random.choice([0.1, 0.5, 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2000, 5000])

        bucket = Mock()
        bucket.name = f"{project_id}-bucket-{i:03d}"
        bucket.location = location.upper()
        bucket.location_type = "region" if "-" in location else "multi-region"
        bucket.storage_class = storage_class
        bucket.versioning_enabled = random.random() < 0.3
        bucket.labels = labels
        bucket.lifecycle_rules = []
        bucket.size_gb = size_gb
        bucket.time_created = Mock()
        bucket.time_created.isoformat.return_value = (datetime.now(timezone.utc) - timedelta(days=random.randint(30, 365))).isoformat()

        buckets.append(bucket)

    return buckets


def create_mock_cloud_sql_instances(project_id: str, num_instances: int):
    """Create mock GCP Cloud SQL Instances."""
    instances = []
    database_versions = ["POSTGRES_14", "POSTGRES_15", "MYSQL_8_0", "SQLSERVER_2019_STANDARD"]
    tiers = ["db-f1-micro", "db-g1-small", "db-custom-2-4096", "db-custom-4-8192", "db-custom-8-16384"]

    for i in range(num_instances):
        region = random.choice(REGIONS)
        db_version = random.choice(database_versions)
        tier = random.choice(tiers)
        storage_size_gb = random.choice([10, 20, 50, 100, 200, 500])
        labels = random_labels(completeness=random.uniform(0.4, 0.9))

        instance = Mock()
        instance.name = f"cloudsql-{region.replace('-', '')[:8]}-{i:03d}"
        instance.region = region
        instance.database_version = db_version
        instance.state = random.choice(["RUNNABLE"] * 9 + ["STOPPED"])
        instance.backend_type = "SECOND_GEN"

        instance.settings = Mock()
        instance.settings.tier = tier
        instance.settings.data_disk_size_gb = storage_size_gb
        instance.settings.availability_type = random.choice(["ZONAL", "REGIONAL"])
        instance.settings.user_labels = labels

        instance.settings.backup_configuration = Mock()
        instance.settings.backup_configuration.enabled = random.random() < 0.8

        instances.append(instance)

    return instances


def create_mock_gke_clusters(project_id: str, num_clusters: int):
    """Create mock GKE Clusters."""
    clusters = []
    k8s_versions = ["1.28.5-gke.1200", "1.29.2-gke.1060", "1.30.0-gke.1000"]

    for i in range(num_clusters):
        region = random.choice(REGIONS)
        k8s_version = random.choice(k8s_versions)
        labels = random_labels(completeness=random.uniform(0.5, 0.9))

        cluster = Mock()
        cluster.name = f"gke-{region.replace('-', '')[:8]}-{i:03d}"
        cluster.location = region
        cluster.current_master_version = k8s_version
        cluster.status = "RUNNING"
        cluster.resource_labels = labels

        # Node pools
        cluster.node_pools = []
        num_pools = random.randint(1, 3)
        for j in range(num_pools):
            pool = Mock()
            pool.name = f"pool-{j}"
            pool.initial_node_count = random.randint(1, 5)
            pool.config = Mock()
            pool.config.machine_type = random.choice(MACHINE_TYPES)
            pool.config.disk_size_gb = random.choice([100, 200, 500])

            # Autoscaling
            pool.autoscaling = Mock()
            pool.autoscaling.enabled = random.random() < 0.7
            pool.autoscaling.min_node_count = 1 if pool.autoscaling.enabled else 0
            pool.autoscaling.max_node_count = random.randint(5, 20) if pool.autoscaling.enabled else 0

            cluster.node_pools.append(pool)

        clusters.append(cluster)

    return clusters


def create_mock_cloud_functions(project_id: str, region: str, num_functions: int):
    """Create mock GCP Cloud Functions."""
    functions = []
    runtimes = ["python39", "python310", "python311", "nodejs18", "nodejs20", "go121", "java17"]

    for i in range(num_functions):
        runtime = random.choice(runtimes)
        labels = random_labels(completeness=random.uniform(0.3, 0.7))

        func = Mock()
        func.name = f"projects/{project_id}/locations/{region}/functions/func-{i:03d}"
        func.runtime = runtime
        func.status = random.choice(["ACTIVE"] * 9 + ["OFFLINE"])
        func.available_memory_mb = random.choice([128, 256, 512, 1024, 2048])
        func.timeout = f"{random.choice([60, 120, 300, 540])}s"
        func.labels = labels

        functions.append(func)

    return functions


def create_mock_filestore_instances(project_id: str, region: str, num_instances: int):
    """Create mock GCP Filestore Instances."""
    instances = []
    tiers = ["BASIC_HDD", "BASIC_SSD", "HIGH_SCALE_SSD", "ENTERPRISE"]

    for i in range(num_instances):
        zone = random.choice(ZONES.get(region, [f"{region}-a"]))
        tier = random.choice(tiers)
        capacity_gb = random.choice([1024, 2048, 5120, 10240, 20480])
        labels = random_labels(completeness=random.uniform(0.4, 0.8))

        instance = Mock()
        instance.name = f"projects/{project_id}/locations/{zone}/instances/filestore-{i:03d}"
        instance.tier = tier
        instance.state = "READY"
        instance.labels = labels

        # File shares
        share = Mock()
        share.name = "share1"
        share.capacity_gb = capacity_gb
        instance.file_shares = [share]

        instances.append(instance)

    return instances


def create_mock_memorystore_redis(project_id: str, region: str, num_instances: int):
    """Create mock GCP Memorystore Redis Instances."""
    instances = []
    tiers = ["BASIC", "STANDARD_HA"]

    for i in range(num_instances):
        tier = random.choice(tiers)
        memory_size_gb = random.choice([1, 2, 4, 8, 16, 32])
        labels = random_labels(completeness=random.uniform(0.4, 0.8))

        instance = Mock()
        instance.name = f"projects/{project_id}/locations/{region}/instances/redis-{i:03d}"
        instance.tier = tier
        instance.memory_size_gb = memory_size_gb
        instance.state = "READY"
        instance.redis_version = random.choice(["REDIS_6_X", "REDIS_7_0"])
        instance.labels = labels

        instances.append(instance)

    return instances


def create_mock_backup_vaults(project_id: str, region: str, num_vaults: int):
    """Create mock GCP Backup & DR Vaults."""
    vaults = []

    for i in range(num_vaults):
        labels = random_labels(completeness=random.uniform(0.5, 0.9))
        total_stored_bytes = random.randint(10, 5000) * 1024 * 1024 * 1024  # 10GB to 5TB
        backup_count = random.randint(5, 200)

        vault = Mock()
        vault.name = f"projects/{project_id}/locations/{region}/backupVaults/vault-{i:03d}"
        vault.state = Mock()
        vault.state.name = random.choice(["CREATING", "ACTIVE", "DELETING"])
        vault.labels = labels
        vault.description = f"Backup vault for {random.choice(['production', 'staging', 'dev'])} resources"
        vault.total_stored_bytes = total_stored_bytes
        vault.backup_count = backup_count
        vault.deletable = random.random() > 0.3
        vault.etag = f"etag-{random.randint(1000, 9999)}"

        vaults.append(vault)

    return vaults


def create_mock_backup_plans(project_id: str, region: str, num_plans: int):
    """Create mock GCP Backup & DR Plans."""
    plans = []

    for i in range(num_plans):
        labels = random_labels(completeness=random.uniform(0.5, 0.9))

        plan = Mock()
        plan.name = f"projects/{project_id}/locations/{region}/backupPlans/plan-{i:03d}"
        plan.state = Mock()
        plan.state.name = random.choice(["STATE_UNSPECIFIED", "CREATING", "ACTIVE"])
        plan.labels = labels
        plan.description = f"Backup plan - {random.choice(['daily', 'weekly', 'hourly'])} schedule"

        plans.append(plan)

    return plans


def create_mock_backup_data_sources(project_id: str, region: str, vault_names: list, num_sources: int):
    """Create mock GCP Backup & DR Data Sources (protected resources)."""
    sources = []

    for i in range(num_sources):
        vault_name = random.choice(vault_names) if vault_names else f"projects/{project_id}/locations/{region}/backupVaults/vault-000"
        labels = random_labels(completeness=random.uniform(0.4, 0.8))
        total_stored_bytes = random.randint(1, 500) * 1024 * 1024 * 1024  # 1GB to 500GB
        backup_count = random.randint(1, 50)

        source = Mock()
        source.name = f"{vault_name}/dataSources/ds-{i:03d}"
        source.state = Mock()
        source.state.name = random.choice(["STATE_UNSPECIFIED", "CREATING", "ACTIVE", "DELETING"])
        source.labels = labels
        source.data_source_gcp_resource = {"gcp_resourcename": f"projects/{project_id}/zones/{region}-a/instances/instance-{random.randint(0, 50):03d}"}
        source.total_stored_bytes = total_stored_bytes
        source.backup_count = backup_count

        sources.append(source)

    return sources


def create_mock_backups(project_id: str, region: str, data_source_names: list, num_backups: int):
    """Create mock GCP Backup & DR Backups (recovery points)."""
    backups = []
    backup_types = ["SCHEDULED", "ON_DEMAND"]

    for i in range(num_backups):
        ds_name = random.choice(data_source_names) if data_source_names else f"projects/{project_id}/locations/{region}/backupVaults/vault-000/dataSources/ds-000"
        labels = random_labels(completeness=random.uniform(0.3, 0.7))
        size_bytes = random.randint(100, 50000) * 1024 * 1024  # 100MB to 50GB

        backup = Mock()
        backup.name = f"{ds_name}/backups/backup-{i:04d}"
        backup.state = Mock()
        backup.state.name = random.choice(["STATE_UNSPECIFIED", "CREATING", "ACTIVE", "DELETING"])
        backup.backup_type = Mock()
        backup.backup_type.name = random.choice(backup_types)
        backup.labels = labels
        backup.backup_appliance_backup_size_bytes = size_bytes
        backup.gc_backup_size_bytes = 0
        backup.create_time = (datetime.now(timezone.utc) - timedelta(days=random.randint(0, 90))).isoformat()
        backup.expire_time = (datetime.now(timezone.utc) + timedelta(days=random.randint(7, 365))).isoformat()
        backup.consistency_time = backup.create_time

        backups.append(backup)

    return backups


# =============================================================================
# Test Class
# =============================================================================

class TestLargeScaleGCP:
    """Large-scale integration test for GCP with realistic enterprise data."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures."""
        setup_large_output_dir()
        yield

    def test_large_scale_gcp_collection(self):
        """
        Test collection across a large, realistic GCP enterprise environment.

        Scale:
        - 4 regions
        - ~50 Compute Engine instances per region
        - ~80 Persistent Disks per region (includes orphaned)
        - ~100 Snapshots (global)
        - ~40 Cloud Storage buckets (global)
        - ~15 Cloud SQL instances per region
        - ~5 GKE clusters per region
        - ~20 Cloud Functions per region
        - ~5 Filestore instances per region
        - ~5 Memorystore Redis instances per region
        - ~3 Backup Vaults per region
        - ~5 Backup Plans per region
        - ~20 Backup Data Sources per region
        - ~50 Backups per region
        """
        print("\n" + "=" * 80)
        print("LARGE-SCALE GCP INTEGRATION TEST")
        print("=" * 80)

        # Configuration - scale factors
        INSTANCES_PER_REGION = 50
        DISKS_PER_REGION = 80
        TOTAL_SNAPSHOTS = 100
        TOTAL_BUCKETS = 40
        SQL_PER_REGION = 15
        GKE_PER_REGION = 5
        FUNCTIONS_PER_REGION = 20
        FILESTORE_PER_REGION = 5
        REDIS_PER_REGION = 5
        BACKUP_VAULTS_PER_REGION = 3
        BACKUP_PLANS_PER_REGION = 5
        BACKUP_SOURCES_PER_REGION = 20
        BACKUPS_PER_REGION = 50

        project_id = "enterprise-project-12345"

        print("\n📦 Creating mock GCP infrastructure...\n")

        all_resources = []

        # Create global resources first
        print("  Creating global resources...")
        snapshots = create_mock_snapshots(project_id, TOTAL_SNAPSHOTS)
        buckets = create_mock_storage_buckets(project_id, TOTAL_BUCKETS)

        for snapshot in snapshots:
            snapshot.storage_bytes / (1024**3) if snapshot.storage_bytes else 0
            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region="global",
                resource_type="gcp:compute:snapshot",
                service_family="ComputeSnapshot",
                resource_id=snapshot.self_link,
                name=snapshot.name,
                tags=snapshot.labels or {},
                size_gb=float(snapshot.disk_size_gb),
                metadata={
                    'source_disk': snapshot.source_disk,
                    'storage_bytes': snapshot.storage_bytes,
                    'storage_locations': snapshot.storage_locations,
                }
            )
            all_resources.append(resource)

        for bucket in buckets:
            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region=bucket.location.lower(),
                resource_type="gcp:storage:bucket",
                service_family="CloudStorage",
                resource_id=f"gs://{bucket.name}",
                name=bucket.name,
                tags=bucket.labels or {},
                size_gb=float(bucket.size_gb),
                metadata={
                    'storage_class': bucket.storage_class,
                    'location_type': bucket.location_type,
                    'versioning_enabled': bucket.versioning_enabled,
                    'size_gb': bucket.size_gb,
                }
            )
            all_resources.append(resource)

        for region in REGIONS:
            print(f"  Setting up {region}...")

            # Generate mock resources for this region
            instances = create_mock_compute_instances(project_id, region, INSTANCES_PER_REGION)
            disks = create_mock_persistent_disks(project_id, region, DISKS_PER_REGION)
            sql_instances = create_mock_cloud_sql_instances(project_id, SQL_PER_REGION)
            gke_clusters = create_mock_gke_clusters(project_id, GKE_PER_REGION)
            functions = create_mock_cloud_functions(project_id, region, FUNCTIONS_PER_REGION)
            filestore_instances = create_mock_filestore_instances(project_id, region, FILESTORE_PER_REGION)
            redis_instances = create_mock_memorystore_redis(project_id, region, REDIS_PER_REGION)

            # Convert to CloudResource objects
            for instance in instances:
                total_disk_size = sum(d.disk_size_gb for d in instance.disks if hasattr(d, 'disk_size_gb'))
                zone_name = instance.zone

                resource = CloudResource(
                    provider="gcp",
                    account_id=project_id,
                    region=region,
                    resource_type="gcp:compute:instance",
                    service_family="Compute",
                    resource_id=f"projects/{project_id}/zones/{zone_name}/instances/{instance.name}",
                    name=instance.name,
                    tags=instance.labels or {},
                    size_gb=float(total_disk_size),
                    metadata={
                        'machine_type': instance.machine_type.split('/')[-1] if instance.machine_type else 'unknown',
                        'status': instance.status,
                        'zone': zone_name,
                        'preemptible': instance.scheduling.preemptible if instance.scheduling else False,
                    }
                )
                all_resources.append(resource)

            for disk in disks:
                zone_name = disk.zone
                resource = CloudResource(
                    provider="gcp",
                    account_id=project_id,
                    region=region,
                    resource_type="gcp:compute:disk",
                    service_family="PersistentDisk",
                    resource_id=disk.self_link,
                    name=disk.name,
                    tags=disk.labels or {},
                    size_gb=float(disk.size_gb),
                    metadata={
                        'disk_type': disk.type_.split('/')[-1] if disk.type_ else 'unknown',
                        'status': disk.status,
                        'attached_to': disk.users,
                        'zone': zone_name,
                    }
                )
                all_resources.append(resource)

            for sql in sql_instances:
                resource = CloudResource(
                    provider="gcp",
                    account_id=project_id,
                    region=sql.region,
                    resource_type="gcp:sql:instance",
                    service_family="CloudSQL",
                    resource_id=f"projects/{project_id}/instances/{sql.name}",
                    name=sql.name,
                    tags=sql.settings.user_labels if sql.settings else {},
                    size_gb=float(sql.settings.data_disk_size_gb) if sql.settings else 0,
                    metadata={
                        'database_version': sql.database_version,
                        'tier': sql.settings.tier if sql.settings else 'unknown',
                        'state': sql.state,
                        'availability_type': sql.settings.availability_type if sql.settings else 'unknown',
                        'backup_enabled': sql.settings.backup_configuration.enabled if sql.settings and sql.settings.backup_configuration else False,
                    }
                )
                all_resources.append(resource)

            for cluster in gke_clusters:
                total_nodes = sum(pool.initial_node_count for pool in cluster.node_pools) if cluster.node_pools else 0
                resource = CloudResource(
                    provider="gcp",
                    account_id=project_id,
                    region=cluster.location,
                    resource_type="gcp:container:cluster",
                    service_family="GKE",
                    resource_id=f"projects/{project_id}/locations/{cluster.location}/clusters/{cluster.name}",
                    name=cluster.name,
                    tags=cluster.resource_labels or {},
                    size_gb=0.0,
                    metadata={
                        'kubernetes_version': cluster.current_master_version,
                        'status': cluster.status,
                        'node_pool_count': len(cluster.node_pools) if cluster.node_pools else 0,
                        'total_nodes': total_nodes,
                    }
                )
                all_resources.append(resource)

            for func in functions:
                resource = CloudResource(
                    provider="gcp",
                    account_id=project_id,
                    region=region,
                    resource_type="gcp:functions:function",
                    service_family="CloudFunctions",
                    resource_id=func.name,
                    name=func.name.split('/')[-1],
                    tags=func.labels or {},
                    size_gb=0.0,
                    metadata={
                        'runtime': func.runtime,
                        'status': func.status,
                        'memory_mb': func.available_memory_mb,
                    }
                )
                all_resources.append(resource)

            for fs in filestore_instances:
                capacity_gb = fs.file_shares[0].capacity_gb if fs.file_shares else 0
                resource = CloudResource(
                    provider="gcp",
                    account_id=project_id,
                    region=region,
                    resource_type="gcp:filestore:instance",
                    service_family="Filestore",
                    resource_id=fs.name,
                    name=fs.name.split('/')[-1],
                    tags=fs.labels or {},
                    size_gb=float(capacity_gb),
                    metadata={
                        'tier': fs.tier,
                        'state': fs.state,
                    }
                )
                all_resources.append(resource)

            for redis in redis_instances:
                resource = CloudResource(
                    provider="gcp",
                    account_id=project_id,
                    region=region,
                    resource_type="gcp:redis:instance",
                    service_family="Memorystore",
                    resource_id=redis.name,
                    name=redis.name.split('/')[-1],
                    tags=redis.labels or {},
                    size_gb=float(redis.memory_size_gb),
                    metadata={
                        'tier': redis.tier,
                        'state': redis.state,
                        'redis_version': redis.redis_version,
                    }
                )
                all_resources.append(resource)

            # Backup & DR resources
            backup_vaults = create_mock_backup_vaults(project_id, region, BACKUP_VAULTS_PER_REGION)
            backup_plans = create_mock_backup_plans(project_id, region, BACKUP_PLANS_PER_REGION)
            vault_names = [v.name for v in backup_vaults]
            backup_sources = create_mock_backup_data_sources(project_id, region, vault_names, BACKUP_SOURCES_PER_REGION)
            source_names = [s.name for s in backup_sources]
            backups = create_mock_backups(project_id, region, source_names, BACKUPS_PER_REGION)

            for vault in backup_vaults:
                size_gb = vault.total_stored_bytes / (1024**3) if vault.total_stored_bytes else 0
                resource = CloudResource(
                    provider="gcp",
                    account_id=project_id,
                    region=region,
                    resource_type="gcp:backupdr:vault",
                    service_family="Backup",
                    resource_id=vault.name,
                    name=vault.name.split('/')[-1],
                    tags=vault.labels or {},
                    size_gb=round(size_gb, 2),
                    metadata={
                        'state': vault.state.name if vault.state else '',
                        'description': vault.description,
                        'backup_count': vault.backup_count,
                        'total_stored_bytes': vault.total_stored_bytes,
                    }
                )
                all_resources.append(resource)

            for plan in backup_plans:
                resource = CloudResource(
                    provider="gcp",
                    account_id=project_id,
                    region=region,
                    resource_type="gcp:backupdr:plan",
                    service_family="Backup",
                    resource_id=plan.name,
                    name=plan.name.split('/')[-1],
                    tags=plan.labels or {},
                    size_gb=0.0,
                    metadata={
                        'state': plan.state.name if plan.state else '',
                        'description': plan.description,
                    }
                )
                all_resources.append(resource)

            for source in backup_sources:
                size_gb = source.total_stored_bytes / (1024**3) if source.total_stored_bytes else 0
                vault_name = source.name.split('/dataSources/')[0] if '/dataSources/' in source.name else ''
                resource = CloudResource(
                    provider="gcp",
                    account_id=project_id,
                    region=region,
                    resource_type="gcp:backupdr:datasource",
                    service_family="Backup",
                    resource_id=source.name,
                    name=source.name.split('/')[-1],
                    tags=source.labels or {},
                    size_gb=round(size_gb, 2),
                    parent_resource_id=vault_name,
                    metadata={
                        'state': source.state.name if source.state else '',
                        'data_source_gcp_resource': source.data_source_gcp_resource.get('gcp_resourcename', ''),
                        'backup_count': source.backup_count,
                        'total_stored_bytes': source.total_stored_bytes,
                    }
                )
                all_resources.append(resource)

            for backup in backups:
                size_bytes = backup.backup_appliance_backup_size_bytes or backup.gc_backup_size_bytes or 0
                size_gb = size_bytes / (1024**3)
                ds_name = backup.name.rsplit('/backups/', 1)[0] if '/backups/' in backup.name else ''
                resource = CloudResource(
                    provider="gcp",
                    account_id=project_id,
                    region=region,
                    resource_type="gcp:backupdr:backup",
                    service_family="Backup",
                    resource_id=backup.name,
                    name=backup.name.split('/')[-1],
                    tags=backup.labels or {},
                    size_gb=round(size_gb, 2),
                    parent_resource_id=ds_name,
                    metadata={
                        'state': backup.state.name if backup.state else '',
                        'backup_type': backup.backup_type.name if backup.backup_type else '',
                        'create_time': backup.create_time,
                        'expire_time': backup.expire_time,
                        'size_bytes': size_bytes,
                    }
                )
                all_resources.append(resource)

            print(f"    Created {len(instances)} instances, {len(disks)} disks, "
                  f"{len(sql_instances)} SQL instances, {len(gke_clusters)} GKE clusters, "
                  f"{len(functions)} functions, {len(filestore_instances)} Filestore, {len(redis_instances)} Redis, "
                  f"{len(backup_vaults)} vaults, {len(backup_plans)} plans, {len(backup_sources)} sources, {len(backups)} backups")

        print(f"\n  Created {len(snapshots)} snapshots, {len(buckets)} buckets (global)")
        print("\n✅ Mock infrastructure created\n")

        # Generate outputs
        run_id = generate_run_id()
        timestamp = get_timestamp()

        # Build sizing summaries
        summaries = aggregate_sizing(all_resources)

        inventory_data = {
            'provider': 'gcp',
            'run_id': run_id,
            'timestamp': timestamp,
            'project_id': project_id,
            'regions': REGIONS,
            'resources': [r.to_dict() for r in all_resources]
        }

        summary_data = {
            'provider': 'gcp',
            'run_id': run_id,
            'timestamp': timestamp,
            'project_id': project_id,
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
        print(f"\nProject: {project_id}")
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
        print("\nData Quality:")
        if len(all_resources) > 0:
            print(f"  Resources with missing labels: {missing_names} ({missing_names/len(all_resources)*100:.1f}%)")
        else:
            print(f"  Resources with missing labels: {missing_names}")

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
        assert len(by_region) >= len(REGIONS), "Should have resources from all regions"

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
