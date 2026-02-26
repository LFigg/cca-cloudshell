#!/usr/bin/env python3
"""
CCA CloudShell - Azure Resource Collector

Collects Azure resources for cloud protection assessment.
Optimized for Azure Cloud Shell with minimal dependencies.

Usage:
    python3 azure_collect.py
    python3 azure_collect.py --subscription <subscription-id>
    python3 azure_collect.py --output https://mystorageaccount.blob.core.windows.net/assessments/
"""
import argparse
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

# Azure SDK - pre-installed in Azure Cloud Shell
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.cosmosdb import CosmosDBManagementClient
from azure.mgmt.recoveryservices import RecoveryServicesClient
from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.web import WebSiteManagementClient

# Optional SDKs - may need to be installed
try:
    from azure.mgmt.redis import RedisManagementClient
    HAS_REDIS = True
except ImportError:
    RedisManagementClient = None  # type: ignore[misc,assignment]
    HAS_REDIS = False
    # Will log warning later after logger is set up

# Add lib to path for imports
sys.path.insert(0, '.')
from lib.change_rate import (
    aggregate_change_rates,
    finalize_change_rate_output,
    format_change_rate_output,
    get_azure_disk_change_rate,
    get_azure_monitor_client,
    get_azure_sql_transaction_log_rate,
    merge_change_rates,
)
from lib.k8s import collect_aks_pvcs
from lib.models import CloudResource, aggregate_sizing
from lib.utils import (
    AuthError,
    ProgressTracker,
    check_and_raise_auth_error,
    format_bytes_to_gb,
    generate_run_id,
    get_timestamp,
    parallel_collect,
    print_summary_table,
    redact_sensitive_data,
    retry_with_backoff,
    setup_logging,
    write_csv,
    write_json,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Authentication & Subscriptions
# =============================================================================

def get_credential():
    """Get Azure credential. In Cloud Shell, uses managed identity."""
    return DefaultAzureCredential()


def get_subscriptions(credential) -> List[Dict]:
    """Get all accessible subscriptions."""
    subscription_client = SubscriptionClient(credential)
    subscriptions = []

    for sub in subscription_client.subscriptions.list():
        subscriptions.append({
            'id': sub.subscription_id,
            'name': sub.display_name,
            'state': sub.state
        })

    return subscriptions


def _extract_resource_group(resource_id: str) -> str:
    """Extract resource group from Azure resource ID."""
    try:
        parts = resource_id.split('/')
        rg_index = parts.index('resourceGroups') + 1
        return parts[rg_index]
    except (ValueError, IndexError):
        return 'unknown'


# =============================================================================
# VM Collector
# =============================================================================

@retry_with_backoff(max_attempts=3)
def collect_vms(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Virtual Machines."""
    resources = []
    try:
        compute_client = ComputeManagementClient(credential, subscription_id)

        for vm in compute_client.virtual_machines.list_all():
            if not vm.id:
                continue

            rg = _extract_resource_group(vm.id)

            # Get OS disk size
            os_disk_size = 0.0
            if vm.storage_profile and vm.storage_profile.os_disk:
                os_disk_size = float(vm.storage_profile.os_disk.disk_size_gb or 0)

            # Count data disks
            data_disk_count = 0
            data_disk_ids = []
            if vm.storage_profile and vm.storage_profile.data_disks:
                data_disk_count = len(vm.storage_profile.data_disks)
                for dd in vm.storage_profile.data_disks:
                    if dd.managed_disk and dd.managed_disk.id:
                        data_disk_ids.append(dd.managed_disk.id)

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=vm.location,
                resource_type="azure:vm",
                service_family="AzureVM",
                resource_id=vm.id,
                name=vm.name,
                tags=vm.tags or {},
                size_gb=os_disk_size,
                metadata={
                    'resource_group': rg,
                    'vm_size': vm.hardware_profile.vm_size if vm.hardware_profile else 'unknown',
                    'os_type': vm.storage_profile.os_disk.os_type if vm.storage_profile and vm.storage_profile.os_disk else 'unknown',
                    'data_disk_count': data_disk_count,
                    'attached_disks': data_disk_ids,
                    'provisioning_state': vm.provisioning_state
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure VMs")
    except Exception as e:
        check_and_raise_auth_error(e, "collect VMs", "azure")
        logger.error(f"Failed to collect VMs: {e}")

    return resources


# =============================================================================
# Managed Disk Collector
# =============================================================================

def collect_disks(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Managed Disks."""
    resources = []
    try:
        compute_client = ComputeManagementClient(credential, subscription_id)

        for disk in compute_client.disks.list():
            if not disk.id:
                continue

            rg = _extract_resource_group(disk.id)

            # Get attached VM if any
            attached_vm = None
            if disk.managed_by:
                attached_vm = disk.managed_by.split('/')[-1]

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=disk.location,
                resource_type="azure:disk",
                service_family="AzureVM",
                resource_id=disk.id,
                name=disk.name,
                tags=disk.tags or {},
                size_gb=float(disk.disk_size_gb or 0),
                parent_resource_id=disk.managed_by,
                metadata={
                    'resource_group': rg,
                    'disk_state': disk.disk_state,
                    'sku': disk.sku.name if disk.sku else 'unknown',
                    'os_type': str(disk.os_type) if disk.os_type else None,
                    'attached_vm': attached_vm,
                    'encryption_type': disk.encryption.type if disk.encryption else 'None',
                    'encrypted': True,  # All Azure managed disks are encrypted at rest by default
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure Managed Disks")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Disks", "azure")
        logger.error(f"Failed to collect Disks: {e}")

    return resources


# =============================================================================
# Storage Account Collector
# =============================================================================

def collect_storage_accounts(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Storage Accounts."""
    resources = []
    try:
        storage_client = StorageManagementClient(credential, subscription_id)

        for account in storage_client.storage_accounts.list():
            if not account.id:
                continue

            rg = _extract_resource_group(account.id)

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=account.location,
                resource_type="azure:storage:blob",
                service_family="AzureStorage",
                resource_id=account.id,
                name=account.name,
                tags=account.tags or {},
                size_gb=0.0,  # Requires Monitor API for actual usage
                metadata={
                    'resource_group': rg,
                    'sku_name': account.sku.name if account.sku else 'unknown',
                    'kind': str(account.kind),
                    'https_only': account.enable_https_traffic_only,
                    'provisioning_state': account.provisioning_state,
                    'size_note': 'Use Azure Monitor for actual usage'
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure Storage Accounts")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Storage Accounts", "azure")
        logger.error(f"Failed to collect Storage Accounts: {e}")

    return resources


# =============================================================================
# SQL Database Collectors
# =============================================================================

def collect_sql_servers(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure SQL Servers and Databases."""
    resources = []
    try:
        sql_client = SqlManagementClient(credential, subscription_id)

        for server in sql_client.servers.list():
            server_id = getattr(server, 'id', None)
            server_name = getattr(server, 'name', '')
            if not server_id:
                continue

            rg = _extract_resource_group(server_id)

            # Get databases for this server
            try:
                for db in sql_client.databases.list_by_server(rg, server_name):
                    db_name = getattr(db, 'name', '')
                    if db_name == 'master':
                        continue  # Skip system database

                    # Get size (max_size_bytes is in bytes)
                    size_gb = 0.0
                    max_size_bytes = getattr(db, 'max_size_bytes', None)
                    if max_size_bytes:
                        size_gb = format_bytes_to_gb(max_size_bytes)

                    db_sku = getattr(db, 'sku', None)

                    # Check if this is a replica (secondary database)
                    secondary_type = getattr(db, 'secondary_type', None)
                    is_read_replica = secondary_type is not None and secondary_type != 'None'

                    resource = CloudResource(
                        provider="azure",
                        subscription_id=subscription_id,
                        region=getattr(db, 'location', ''),
                        resource_type="azure:sql:database",
                        service_family="AzureSQL",
                        resource_id=getattr(db, 'id', ''),
                        name=db_name,
                        tags=getattr(db, 'tags', None) or {},
                        size_gb=size_gb,
                        parent_resource_id=server_id,
                        metadata={
                            'resource_group': rg,
                            'server_name': server_name,
                            'sku': getattr(db_sku, 'name', 'unknown') if db_sku else 'unknown',
                            'tier': getattr(db_sku, 'tier', 'unknown') if db_sku else 'unknown',
                            'status': getattr(db, 'status', None),
                            'collation': getattr(db, 'collation', None),
                            'is_read_replica': is_read_replica,
                            'secondary_type': secondary_type,
                            'encrypted': True,  # Azure SQL TDE is enabled by default
                        }
                    )
                    resources.append(resource)
            except Exception as e:
                check_and_raise_auth_error(e, f"list databases for server {server_name}", "azure")
                logger.warning(f"Failed to list databases for server {server_name}: {e}")

        logger.info(f"Found {len(resources)} Azure SQL Databases")
    except Exception as e:
        check_and_raise_auth_error(e, "collect SQL Servers", "azure")
        logger.error(f"Failed to collect SQL Servers: {e}")

    return resources


def collect_sql_managed_instances(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure SQL Managed Instances."""
    resources = []
    try:
        sql_client = SqlManagementClient(credential, subscription_id)

        for mi in sql_client.managed_instances.list():
            mi_id = getattr(mi, 'id', None)
            if not mi_id:
                continue

            rg = _extract_resource_group(mi_id)

            mi_sku = getattr(mi, 'sku', None)
            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=getattr(mi, 'location', ''),
                resource_type="azure:sql:managedinstance",
                service_family="AzureSQL",
                resource_id=mi_id,
                name=getattr(mi, 'name', ''),
                tags=getattr(mi, 'tags', None) or {},
                size_gb=float(getattr(mi, 'storage_size_in_gb', 0) or 0),
                metadata={
                    'resource_group': rg,
                    'sku': getattr(mi_sku, 'name', 'unknown') if mi_sku else 'unknown',
                    'tier': getattr(mi_sku, 'tier', 'unknown') if mi_sku else 'unknown',
                    'vcores': getattr(mi, 'v_cores', None),
                    'state': getattr(mi, 'state', None),
                    'is_read_replica': False,  # Managed instances don't have read replicas concept
                    'encrypted': True,  # Azure SQL MI has TDE enabled by default
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure SQL Managed Instances")
    except Exception as e:
        check_and_raise_auth_error(e, "collect SQL Managed Instances", "azure")
        logger.error(f"Failed to collect SQL Managed Instances: {e}")

    return resources


# =============================================================================
# Cosmos DB Collector
# =============================================================================

def collect_cosmosdb_accounts(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Cosmos DB accounts."""
    resources = []
    try:
        cosmos_client = CosmosDBManagementClient(credential, subscription_id)

        for account in cosmos_client.database_accounts.list():
            if not account.id:
                continue

            rg = _extract_resource_group(account.id)

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=account.location,
                resource_type="azure:cosmosdb:account",
                service_family="CosmosDB",
                resource_id=account.id,
                name=account.name,
                tags=account.tags or {},
                size_gb=0.0,  # Requires metrics API
                metadata={
                    'resource_group': rg,
                    'kind': str(account.kind) if account.kind else 'unknown',
                    'database_account_offer_type': account.database_account_offer_type,
                    'consistency_policy': str(account.consistency_policy.default_consistency_level) if account.consistency_policy else 'unknown',
                    'provisioning_state': account.provisioning_state,
                    'is_read_replica': False,  # Cosmos DB regions are multi-master, not replicas
                    'encrypted': True,  # Cosmos DB data is encrypted at rest by default
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure Cosmos DB accounts")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Cosmos DB accounts", "azure")
        logger.error(f"Failed to collect Cosmos DB accounts: {e}")

    return resources


# =============================================================================
# AKS Collector
# =============================================================================

def collect_aks_clusters(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Kubernetes Service clusters."""
    resources = []
    try:
        aks_client = ContainerServiceClient(credential, subscription_id)

        for cluster in aks_client.managed_clusters.list():
            if not cluster.id:
                continue

            rg = _extract_resource_group(cluster.id)

            # Count nodes
            node_count = 0
            if cluster.agent_pool_profiles:
                node_count = sum(p.count or 0 for p in cluster.agent_pool_profiles)

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=cluster.location,
                resource_type="azure:aks:cluster",
                service_family="AKS",
                resource_id=cluster.id,
                name=cluster.name,
                tags=cluster.tags or {},
                size_gb=0.0,
                metadata={
                    'resource_group': rg,
                    'kubernetes_version': cluster.kubernetes_version,
                    'provisioning_state': cluster.provisioning_state,
                    'node_count': node_count,
                    'dns_prefix': cluster.dns_prefix
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} AKS clusters")
    except Exception as e:
        check_and_raise_auth_error(e, "collect AKS clusters", "azure")
        logger.error(f"Failed to collect AKS clusters: {e}")

    return resources


# =============================================================================
# Azure Functions Collector
# =============================================================================

def collect_function_apps(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Function Apps."""
    resources = []
    try:
        web_client = WebSiteManagementClient(credential, subscription_id)

        for app in web_client.web_apps.list():
            if not app.id or not app.kind or 'functionapp' not in app.kind.lower():
                continue

            rg = _extract_resource_group(app.id)

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
                    'resource_group': rg,
                    'kind': app.kind,
                    'state': app.state,
                    'default_host_name': app.default_host_name
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure Function Apps")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Function Apps", "azure")
        logger.error(f"Failed to collect Function Apps: {e}")

    return resources


# =============================================================================
# Disk Snapshots Collector
# =============================================================================

def collect_disk_snapshots(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Managed Disk Snapshots."""
    resources = []
    try:
        compute_client = ComputeManagementClient(credential, subscription_id)

        for snapshot in compute_client.snapshots.list():
            snapshot_id = getattr(snapshot, 'id', None)
            if not snapshot_id:
                continue

            rg = _extract_resource_group(snapshot_id)

            # Get source disk if available
            source_disk = None
            creation_data = getattr(snapshot, 'creation_data', None)
            if creation_data:
                source_uri = getattr(creation_data, 'source_uri', None) or getattr(creation_data, 'source_resource_id', None)
                if source_uri:
                    source_disk = source_uri.split('/')[-1] if '/' in str(source_uri) else source_uri

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=getattr(snapshot, 'location', ''),
                resource_type="azure:snapshot",
                service_family="AzureVM",
                resource_id=snapshot_id,
                name=getattr(snapshot, 'name', ''),
                tags=getattr(snapshot, 'tags', None) or {},
                size_gb=float(getattr(snapshot, 'disk_size_gb', 0) or 0),
                parent_resource_id=getattr(creation_data, 'source_resource_id', None) if creation_data else None,
                metadata={
                    'resource_group': rg,
                    'source_disk': source_disk,
                    'time_created': str(getattr(snapshot, 'time_created', '')),
                    'sku': getattr(getattr(snapshot, 'sku', None), 'name', 'unknown') if getattr(snapshot, 'sku', None) else 'unknown',
                    'incremental': getattr(snapshot, 'incremental', False),
                    'os_type': str(getattr(snapshot, 'os_type', '')) if getattr(snapshot, 'os_type', None) else None
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure Disk Snapshots")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Disk Snapshots", "azure")
        logger.error(f"Failed to collect Disk Snapshots: {e}")

    return resources


# =============================================================================
# Azure Backup Collectors (Recovery Services)
# =============================================================================

def collect_recovery_services_vaults(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Recovery Services Vaults."""
    resources = []
    try:
        rs_client = RecoveryServicesClient(credential, subscription_id)

        for vault in rs_client.vaults.list_by_subscription_id():
            vault_id = getattr(vault, 'id', None)
            if not vault_id:
                continue

            rg = _extract_resource_group(vault_id)
            vault_sku = getattr(vault, 'sku', None)
            vault_props = getattr(vault, 'properties', None)

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=getattr(vault, 'location', ''),
                resource_type="azure:recoveryservices:vault",
                service_family="AzureBackup",
                resource_id=vault_id,
                name=getattr(vault, 'name', ''),
                tags=getattr(vault, 'tags', None) or {},
                size_gb=0.0,  # Size is in protected items
                metadata={
                    'resource_group': rg,
                    'sku': getattr(vault_sku, 'name', 'unknown') if vault_sku else 'unknown',
                    'provisioning_state': getattr(vault_props, 'provisioning_state', None) if vault_props else None
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Recovery Services Vaults")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Recovery Services Vaults", "azure")
        logger.error(f"Failed to collect Recovery Services Vaults: {e}")

    return resources


def collect_backup_policies(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Backup Policies from all Recovery Services Vaults."""
    resources = []
    try:
        rs_client = RecoveryServicesClient(credential, subscription_id)

        # First get all vaults
        for vault in rs_client.vaults.list_by_subscription_id():
            vault_id = getattr(vault, 'id', None)
            vault_name = getattr(vault, 'name', '')
            if not vault_id or not vault_name:
                continue

            rg = _extract_resource_group(vault_id)

            try:
                backup_client = RecoveryServicesBackupClient(credential, subscription_id)

                # List policies in this vault
                for policy in backup_client.backup_policies.list(vault_name, rg):
                    policy_id = getattr(policy, 'id', None)
                    policy_props = getattr(policy, 'properties', None)

                    # Extract retention and schedule info
                    policy_type = 'unknown'
                    retention_days = None
                    if policy_props:
                        policy_type = getattr(policy_props, 'backup_management_type', 'unknown')
                        # Try to get retention info
                        retention_policy = getattr(policy_props, 'retention_policy', None)
                        if retention_policy:
                            daily_retention = getattr(retention_policy, 'daily_schedule', None)
                            if daily_retention:
                                retention_duration = getattr(daily_retention, 'retention_duration', None)
                                if retention_duration:
                                    retention_days = getattr(retention_duration, 'count', None)

                    resource = CloudResource(
                        provider="azure",
                        subscription_id=subscription_id,
                        region=getattr(vault, 'location', ''),
                        resource_type="azure:backup:policy",
                        service_family="AzureBackup",
                        resource_id=policy_id or '',
                        name=getattr(policy, 'name', ''),
                        tags={},
                        size_gb=0.0,
                        parent_resource_id=vault_id,
                        metadata={
                            'resource_group': rg,
                            'vault_name': vault_name,
                            'policy_type': policy_type,
                            'retention_days': retention_days
                        }
                    )
                    resources.append(resource)
            except Exception as e:
                check_and_raise_auth_error(e, f"list backup policies for vault {vault_name}", "azure")
                logger.warning(f"Failed to list backup policies for vault {vault_name}: {e}")

        logger.info(f"Found {len(resources)} Backup Policies")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Backup Policies", "azure")
        logger.error(f"Failed to collect Backup Policies: {e}")

    return resources


def collect_backup_protected_items(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Backup Protected Items with recovery point counts.

    Recovery point count is included in metadata for each protected item,
    allowing protection status determination without collecting individual RPs.
    """
    resources = []
    try:
        rs_client = RecoveryServicesClient(credential, subscription_id)

        # First get all vaults
        for vault in rs_client.vaults.list_by_subscription_id():
            vault_id = getattr(vault, 'id', None)
            vault_name = getattr(vault, 'name', '')
            if not vault_id or not vault_name:
                continue

            rg = _extract_resource_group(vault_id)
            vault_location = getattr(vault, 'location', '')

            try:
                backup_client = RecoveryServicesBackupClient(credential, subscription_id)

                # List protected items in this vault
                for item in backup_client.backup_protected_items.list(vault_name, rg):
                    item_id = getattr(item, 'id', None)
                    item_props = getattr(item, 'properties', None)

                    # Extract backup details
                    source_resource_id = None
                    workload_type = 'unknown'
                    protection_status = 'unknown'
                    last_backup_time = None
                    backup_size_bytes = 0
                    container_name = ''
                    protected_item_name = getattr(item, 'name', '')

                    if item_props:
                        source_resource_id = getattr(item_props, 'source_resource_id', None)
                        workload_type = getattr(item_props, 'workload_type', 'unknown')
                        protection_status = getattr(item_props, 'protection_status', 'unknown')
                        last_backup_time = getattr(item_props, 'last_backup_time', None)
                        container_name = getattr(item_props, 'container_name', '')
                        friendly_name = getattr(item_props, 'friendly_name', None)
                        if friendly_name:
                            protected_item_name = friendly_name

                        # Try to get backup size from extended info
                        extended_info = getattr(item_props, 'extended_info', None)
                        if extended_info:
                            getattr(extended_info, 'policy_inconsistent', None)

                    # Get recovery point count (lightweight - just count, don't fetch details)
                    recovery_point_count = 0
                    try:
                        rp_list = backup_client.recovery_points.list(
                            vault_name, rg, 'Azure', container_name, protected_item_name
                        )
                        recovery_point_count = sum(1 for _ in rp_list)
                    except Exception as e:
                        logger.debug(f"Could not count recovery points for {protected_item_name}: {e}")

                    # Convert size to GB
                    size_gb = backup_size_bytes / (1024 ** 3) if backup_size_bytes else 0.0

                    resource = CloudResource(
                        provider="azure",
                        subscription_id=subscription_id,
                        region=vault_location,
                        resource_type="azure:backup:protecteditem",
                        service_family="AzureBackup",
                        resource_id=item_id or '',
                        name=getattr(item, 'name', ''),
                        tags={},
                        size_gb=round(size_gb, 2),
                        parent_resource_id=source_resource_id,
                        metadata={
                            'resource_group': rg,
                            'vault_name': vault_name,
                            'workload_type': workload_type,
                            'protection_status': protection_status,
                            'last_backup_time': str(last_backup_time) if last_backup_time else None,
                            'source_resource_id': source_resource_id,
                            'recovery_point_count': recovery_point_count
                        }
                    )
                    resources.append(resource)
            except Exception as e:
                check_and_raise_auth_error(e, f"list protected items for vault {vault_name}", "azure")
                logger.warning(f"Failed to list protected items for vault {vault_name}: {e}")

        logger.info(f"Found {len(resources)} Backup Protected Items")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Backup Protected Items", "azure")
        logger.error(f"Failed to collect Backup Protected Items: {e}")

    return resources


def collect_backup_recovery_points(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Backup Recovery Points (actual backups) with sizes.

    WARNING: This is slow for large backup environments (O(vaults × items × points)).
    Use --include-recovery-points flag to enable. Parallelized across vaults to reduce wall time.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    resources = []
    try:
        rs_client = RecoveryServicesClient(credential, subscription_id)

        # First get all vaults
        vaults = list(rs_client.vaults.list_by_subscription_id())

        if not vaults:
            logger.info("Found 0 Backup Recovery Points (no vaults)")
            return resources

        def process_vault(vault) -> List[CloudResource]:
            """Process a single vault and return its recovery points."""
            vault_resources = []
            vault_id = getattr(vault, 'id', None)
            vault_name = getattr(vault, 'name', '')
            vault_location = getattr(vault, 'location', '')

            if not vault_id or not vault_name:
                return vault_resources

            rg = _extract_resource_group(vault_id)

            try:
                backup_client = RecoveryServicesBackupClient(credential, subscription_id)

                # List protected items to get their recovery points
                for item in backup_client.backup_protected_items.list(vault_name, rg):
                    item_name = getattr(item, 'name', '')
                    item_props = getattr(item, 'properties', None)

                    if not item_name or not item_props:
                        continue

                    container_name = getattr(item_props, 'container_name', '')
                    protected_item_name = getattr(item_props, 'friendly_name', item_name)
                    source_resource_id = getattr(item_props, 'source_resource_id', None)

                    try:
                        for rp in backup_client.recovery_points.list(vault_name, rg, 'Azure', container_name, protected_item_name):
                            rp_id = getattr(rp, 'id', None)
                            rp_name = getattr(rp, 'name', '')
                            rp_props = getattr(rp, 'properties', None)

                            recovery_point_time = None
                            recovery_point_type = 'unknown'
                            recovery_point_size_bytes = 0

                            if rp_props:
                                recovery_point_time = getattr(rp_props, 'recovery_point_time', None)
                                recovery_point_type = getattr(rp_props, 'recovery_point_type', 'unknown')
                                recovery_point_size_bytes = getattr(rp_props, 'recovery_point_size_in_bytes', 0) or 0

                            size_gb = recovery_point_size_bytes / (1024 ** 3) if recovery_point_size_bytes else 0.0

                            resource = CloudResource(
                                provider="azure",
                                subscription_id=subscription_id,
                                region=vault_location,
                                resource_type="azure:backup:recoverypoint",
                                service_family="AzureBackup",
                                resource_id=rp_id or '',
                                name=rp_name,
                                tags={},
                                size_gb=round(size_gb, 2),
                                parent_resource_id=source_resource_id,
                                metadata={
                                    'vault_name': vault_name,
                                    'resource_group': rg,
                                    'recovery_point_time': str(recovery_point_time) if recovery_point_time else None,
                                    'recovery_point_type': recovery_point_type,
                                    'protected_item': protected_item_name,
                                    'container_name': container_name,
                                    'source_resource_id': source_resource_id
                                }
                            )
                            vault_resources.append(resource)
                    except Exception as e:
                        logger.debug(f"Failed to list recovery points for {protected_item_name}: {e}")
            except Exception as e:
                check_and_raise_auth_error(e, f"process vault {vault_name} for recovery points", "azure")
                logger.warning(f"Failed to process vault {vault_name} for recovery points: {e}")

            return vault_resources

        # Parallelize across vaults (max 4 concurrent to avoid throttling)
        max_workers = min(4, len(vaults))
        logger.info(f"Collecting recovery points from {len(vaults)} vaults (parallelized, max {max_workers} concurrent)...")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(process_vault, v): v for v in vaults}
            for future in as_completed(futures):
                try:
                    vault_results = future.result()
                    resources.extend(vault_results)
                except Exception as e:
                    vault = futures[future]
                    logger.warning(f"Failed to process vault {getattr(vault, 'name', 'unknown')}: {e}")

        logger.info(f"Found {len(resources)} Backup Recovery Points")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Backup Recovery Points", "azure")
        logger.error(f"Failed to collect Backup Recovery Points: {e}")

    return resources


# =============================================================================
# Azure Cache for Redis (equivalent to ElastiCache)
# =============================================================================

def collect_redis_caches(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Cache for Redis instances."""
    resources = []

    if not HAS_REDIS:
        logger.warning("azure-mgmt-redis not installed. Skipping Redis cache collection. Install with: pip install azure-mgmt-redis")
        return resources

    try:
        redis_client = RedisManagementClient(credential, subscription_id)  # type: ignore[misc]

        for cache in redis_client.redis.list_by_subscription():
            cache_id = getattr(cache, 'id', None)
            if not cache_id:
                continue

            rg = _extract_resource_group(cache_id)

            # Get cache size based on SKU
            sku = getattr(cache, 'sku', None)
            sku_name = getattr(sku, 'name', 'unknown') if sku else 'unknown'
            sku_family = getattr(sku, 'family', '') if sku else ''
            sku_capacity = getattr(sku, 'capacity', 0) if sku else 0

            # Estimate size based on SKU (Basic/Standard/Premium C0-C6, P1-P5)
            # This is approximate - actual sizes vary
            size_gb = 0.0
            if sku_family == 'C':  # Basic/Standard
                sizes = {0: 0.25, 1: 1, 2: 2.5, 3: 6, 4: 13, 5: 26, 6: 53}
                size_gb = sizes.get(sku_capacity, 0)
            elif sku_family == 'P':  # Premium
                sizes = {1: 6, 2: 13, 3: 26, 4: 53, 5: 120}
                size_gb = sizes.get(sku_capacity, 0)

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=getattr(cache, 'location', ''),
                resource_type="azure:redis:cache",
                service_family="Redis",
                resource_id=cache_id,
                name=getattr(cache, 'name', ''),
                tags=getattr(cache, 'tags', None) or {},
                size_gb=size_gb,
                metadata={
                    'resource_group': rg,
                    'sku_name': sku_name,
                    'sku_family': sku_family,
                    'sku_capacity': sku_capacity,
                    'host_name': getattr(cache, 'host_name', ''),
                    'port': getattr(cache, 'port', 6379),
                    'ssl_port': getattr(cache, 'ssl_port', 6380),
                    'redis_version': getattr(cache, 'redis_version', ''),
                    'provisioning_state': getattr(cache, 'provisioning_state', ''),
                    'enable_non_ssl_port': getattr(cache, 'enable_non_ssl_port', False),
                    'replicas_per_master': getattr(cache, 'replicas_per_master', 0),
                    'shard_count': getattr(cache, 'shard_count', 0),
                    'minimum_tls_version': getattr(cache, 'minimum_tls_version', ''),
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure Cache for Redis instances")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Redis caches", "azure")
        logger.error(f"Failed to collect Redis caches: {e}")

    return resources


# =============================================================================
# Azure Database for PostgreSQL
# =============================================================================

def collect_postgresql_servers(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Database for PostgreSQL servers (Flexible and Single Server)."""
    resources = []
    try:
        from azure.mgmt.rdbms.postgresql_flexibleservers import PostgreSQLManagementClient as PGFlexClient

        # Collect Flexible Servers (recommended)
        flex_client = PGFlexClient(credential, subscription_id)

        for server in flex_client.servers.list():
            server_id = getattr(server, 'id', None)
            if not server_id:
                continue

            rg = _extract_resource_group(server_id)

            # Get storage size
            storage = getattr(server, 'storage', None)
            storage_gb = float(getattr(storage, 'storage_size_gb', 0)) if storage else 0.0

            # SKU info
            sku = getattr(server, 'sku', None)
            sku_name = getattr(sku, 'name', 'unknown') if sku else 'unknown'
            sku_tier = getattr(sku, 'tier', 'unknown') if sku else 'unknown'

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=getattr(server, 'location', ''),
                resource_type="azure:postgresql:flexibleserver",
                service_family="PostgreSQL",
                resource_id=server_id,
                name=getattr(server, 'name', ''),
                tags=getattr(server, 'tags', None) or {},
                size_gb=storage_gb,
                metadata={
                    'resource_group': rg,
                    'sku_name': sku_name,
                    'sku_tier': sku_tier,
                    'version': getattr(server, 'version', ''),
                    'state': str(getattr(server, 'state', '')),
                    'fully_qualified_domain_name': getattr(server, 'fully_qualified_domain_name', ''),
                    'high_availability_mode': str(getattr(getattr(server, 'high_availability', None), 'mode', 'Disabled')) if getattr(server, 'high_availability', None) else 'Disabled',
                    'backup_retention_days': getattr(getattr(server, 'backup', None), 'backup_retention_days', 7) if getattr(server, 'backup', None) else 7,
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure Database for PostgreSQL servers")
    except ImportError:
        logger.warning("azure-mgmt-rdbms not installed. Skipping PostgreSQL collection. Install with: pip install azure-mgmt-rdbms")
    except Exception as e:
        check_and_raise_auth_error(e, "collect PostgreSQL servers", "azure")
        logger.error(f"Failed to collect PostgreSQL servers: {e}")

    return resources


# =============================================================================
# Azure Database for MySQL
# =============================================================================

def collect_mysql_servers(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Database for MySQL servers (Flexible and Single Server)."""
    resources = []
    try:
        from azure.mgmt.rdbms.mysql_flexibleservers import MySQLManagementClient as MySQLFlexClient

        # Collect Flexible Servers (recommended)
        flex_client = MySQLFlexClient(credential, subscription_id)

        for server in flex_client.servers.list():
            server_id = getattr(server, 'id', None)
            if not server_id:
                continue

            rg = _extract_resource_group(server_id)

            # Get storage size
            storage = getattr(server, 'storage', None)
            storage_gb = float(getattr(storage, 'storage_size_gb', 0)) if storage else 0.0

            # SKU info
            sku = getattr(server, 'sku', None)
            sku_name = getattr(sku, 'name', 'unknown') if sku else 'unknown'
            sku_tier = getattr(sku, 'tier', 'unknown') if sku else 'unknown'

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=getattr(server, 'location', ''),
                resource_type="azure:mysql:flexibleserver",
                service_family="MySQL",
                resource_id=server_id,
                name=getattr(server, 'name', ''),
                tags=getattr(server, 'tags', None) or {},
                size_gb=storage_gb,
                metadata={
                    'resource_group': rg,
                    'sku_name': sku_name,
                    'sku_tier': sku_tier,
                    'version': getattr(server, 'version', ''),
                    'state': str(getattr(server, 'state', '')),
                    'fully_qualified_domain_name': getattr(server, 'fully_qualified_domain_name', ''),
                    'high_availability_mode': str(getattr(getattr(server, 'high_availability', None), 'mode', 'Disabled')) if getattr(server, 'high_availability', None) else 'Disabled',
                    'backup_retention_days': getattr(getattr(server, 'backup', None), 'backup_retention_days', 7) if getattr(server, 'backup', None) else 7,
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure Database for MySQL servers")
    except ImportError:
        logger.warning("azure-mgmt-rdbms not installed. Skipping MySQL collection. Install with: pip install azure-mgmt-rdbms")
    except Exception as e:
        check_and_raise_auth_error(e, "collect MySQL servers", "azure")
        logger.error(f"Failed to collect MySQL servers: {e}")

    return resources


# =============================================================================
# Azure Database for MariaDB
# =============================================================================

def collect_mariadb_servers(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Database for MariaDB servers."""
    resources = []
    try:
        from azure.mgmt.rdbms.mariadb import MariaDBManagementClient

        client = MariaDBManagementClient(credential, subscription_id)

        for server in client.servers.list():
            server_id = getattr(server, 'id', None)
            if not server_id:
                continue

            rg = _extract_resource_group(server_id)

            # Get storage size (in MB for MariaDB, convert to GB)
            storage_mb = getattr(server, 'storage_profile', None)
            storage_gb = 0.0
            if storage_mb:
                storage_gb = float(getattr(storage_mb, 'storage_mb', 0)) / 1024.0

            # SKU info
            sku = getattr(server, 'sku', None)
            sku_name = getattr(sku, 'name', 'unknown') if sku else 'unknown'
            sku_tier = getattr(sku, 'tier', 'unknown') if sku else 'unknown'

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=getattr(server, 'location', ''),
                resource_type="azure:mariadb:server",
                service_family="MariaDB",
                resource_id=server_id,
                name=getattr(server, 'name', ''),
                tags=getattr(server, 'tags', None) or {},
                size_gb=storage_gb,
                metadata={
                    'resource_group': rg,
                    'sku_name': sku_name,
                    'sku_tier': sku_tier,
                    'version': getattr(server, 'version', ''),
                    'user_visible_state': str(getattr(server, 'user_visible_state', '')),
                    'fully_qualified_domain_name': getattr(server, 'fully_qualified_domain_name', ''),
                    'ssl_enforcement': str(getattr(server, 'ssl_enforcement', '')),
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure Database for MariaDB servers")
    except ImportError:
        logger.warning("azure-mgmt-rdbms not installed. Skipping MariaDB collection. Install with: pip install azure-mgmt-rdbms")
    except Exception as e:
        check_and_raise_auth_error(e, "collect MariaDB servers", "azure")
        logger.error(f"Failed to collect MariaDB servers: {e}")

    return resources


# =============================================================================
# Azure Synapse Analytics
# =============================================================================

def collect_synapse_workspaces(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Synapse Analytics workspaces and SQL pools."""
    resources = []
    try:
        from azure.mgmt.synapse import SynapseManagementClient

        client = SynapseManagementClient(credential, subscription_id)

        # List workspaces
        for workspace in client.workspaces.list():
            workspace_id = getattr(workspace, 'id', None)
            if not workspace_id:
                continue

            rg = _extract_resource_group(workspace_id)
            workspace_name = getattr(workspace, 'name', '')

            # Collect workspace resource
            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=getattr(workspace, 'location', ''),
                resource_type="azure:synapse:workspace",
                service_family="Synapse",
                resource_id=workspace_id,
                name=workspace_name,
                tags=getattr(workspace, 'tags', None) or {},
                size_gb=0.0,
                metadata={
                    'resource_group': rg,
                    'provisioning_state': getattr(workspace, 'provisioning_state', ''),
                    'managed_resource_group': str(getattr(workspace, 'managed_resource_group_name', '')),
                    'sql_administrator_login': getattr(workspace, 'sql_administrator_login', ''),
                    'connectivity_endpoints': dict(getattr(workspace, 'connectivity_endpoints', {})) if getattr(workspace, 'connectivity_endpoints', None) else {},
                }
            )
            resources.append(resource)

            # List dedicated SQL pools (formerly SQL DW)
            try:
                for pool in client.sql_pools.list_by_workspace(rg, workspace_name):
                    pool_id = getattr(pool, 'id', None)
                    if not pool_id:
                        continue

                    # Get SKU for sizing
                    sku = getattr(pool, 'sku', None)
                    sku_name = getattr(sku, 'name', 'unknown') if sku else 'unknown'

                    # Estimate storage based on DWU (Data Warehouse Units)
                    # Synapse dedicated pools have compute + storage separation
                    # Storage is typically measured in TB and scales with usage
                    max_size_bytes = getattr(pool, 'max_size_bytes', 0)
                    storage_gb = float(max_size_bytes) / (1024 ** 3) if max_size_bytes else 0.0

                    pool_resource = CloudResource(
                        provider="azure",
                        subscription_id=subscription_id,
                        region=getattr(pool, 'location', ''),
                        resource_type="azure:synapse:sqlpool",
                        service_family="Synapse",
                        resource_id=pool_id,
                        name=getattr(pool, 'name', ''),
                        tags=getattr(pool, 'tags', None) or {},
                        size_gb=storage_gb,
                        parent_resource_id=workspace_id,
                        metadata={
                            'resource_group': rg,
                            'workspace_name': workspace_name,
                            'sku_name': sku_name,
                            'status': str(getattr(pool, 'status', '')),
                            'collation': getattr(pool, 'collation', ''),
                            'max_size_bytes': max_size_bytes,
                            'create_mode': str(getattr(pool, 'create_mode', '')),
                        }
                    )
                    resources.append(pool_resource)
            except Exception as e:
                logger.debug(f"Failed to list SQL pools for workspace {workspace_name}: {e}")

        logger.info(f"Found {len(resources)} Synapse workspaces and SQL pools")
    except ImportError:
        logger.warning("azure-mgmt-synapse not installed. Skipping Synapse collection. Install with: pip install azure-mgmt-synapse")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Synapse workspaces", "azure")
        logger.error(f"Failed to collect Synapse workspaces: {e}")

    return resources


# =============================================================================
# Azure NetApp Files (enterprise file storage similar to AWS FSx)
# =============================================================================

def collect_netapp_files(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure NetApp Files volumes."""
    resources = []
    try:
        from azure.mgmt.netapp import NetAppManagementClient

        client = NetAppManagementClient(credential, subscription_id)

        # List all NetApp accounts across subscription
        for account in client.accounts.list_by_subscription():
            account_name = account.name or ''
            rg = account.id.split('/')[4] if account.id else ''
            location = getattr(account, 'location', '')

            # List capacity pools in this account
            try:
                for pool in client.pools.list(rg, account_name):
                    pool_name = (pool.name or '').split('/')[-1] if pool.name and '/' in pool.name else (pool.name or '')
                    getattr(pool, 'size', 0) / (1024 ** 4) if pool.size else 0

                    # List volumes in this pool
                    try:
                        for volume in client.volumes.list(rg, account_name, pool_name):
                            vol_name = (volume.name or '').split('/')[-1] if volume.name and '/' in volume.name else (volume.name or '')
                            vol_id = getattr(volume, 'id', '')

                            # Volume size in bytes, convert to GB
                            usage_bytes = getattr(volume, 'usage_threshold', 0) or 0
                            size_gb = usage_bytes / (1024 ** 3)

                            # Get service level (Standard, Premium, Ultra)
                            service_level = getattr(volume, 'service_level', 'Standard')

                            resource = CloudResource(
                                provider="azure",
                                subscription_id=subscription_id,
                                region=location,
                                resource_type="azure:netapp:volume",
                                service_family="NetAppFiles",
                                resource_id=vol_id,
                                name=vol_name,
                                tags=getattr(volume, 'tags', None) or {},
                                size_gb=round(size_gb, 2),
                                metadata={
                                    'resource_group': rg,
                                    'netapp_account': account_name,
                                    'capacity_pool': pool_name,
                                    'service_level': service_level,
                                    'protocol_types': list(getattr(volume, 'protocol_types', []) or []),
                                    'provisioning_state': getattr(volume, 'provisioning_state', ''),
                                    'subnet_id': getattr(volume, 'subnet_id', ''),
                                    'mount_targets': [
                                        {'ip_address': mt.ip_address}
                                        for mt in (getattr(volume, 'mount_targets', []) or [])
                                        if hasattr(mt, 'ip_address')
                                    ],
                                    'snapshot_policy_id': getattr(volume, 'data_protection', {}).get('snapshot', {}).get('snapshot_policy_id') if hasattr(volume, 'data_protection') else None,
                                    'backup_enabled': bool(getattr(volume, 'data_protection', {}).get('backup')) if hasattr(volume, 'data_protection') else False,
                                }
                            )
                            resources.append(resource)
                    except Exception as e:
                        check_and_raise_auth_error(e, f"list volumes in pool {pool_name}", "azure")
                        logger.warning(f"Failed to list volumes in pool {pool_name}: {e}")
            except Exception as e:
                check_and_raise_auth_error(e, f"list pools in account {account_name}", "azure")
                logger.warning(f"Failed to list pools in account {account_name}: {e}")

        logger.info(f"Found {len(resources)} Azure NetApp Files volumes")
    except ImportError:
        logger.warning("azure-mgmt-netapp not installed. Skipping NetApp collection. Install with: pip install azure-mgmt-netapp")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Azure NetApp Files", "azure")
        logger.error(f"Failed to collect Azure NetApp Files: {e}")

    return resources


# =============================================================================
# Azure Files (file shares in Storage Accounts)
# =============================================================================

def collect_file_shares(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure File Shares from storage accounts."""
    resources = []
    try:
        storage_client = StorageManagementClient(credential, subscription_id)

        for account in storage_client.storage_accounts.list():
            account_id = getattr(account, 'id', None)
            account_name = getattr(account, 'name', '')
            if not account_id or not account_name:
                continue

            rg = _extract_resource_group(account_id)
            account_location = getattr(account, 'location', '')

            try:
                # List file shares in this storage account
                for share in storage_client.file_shares.list(rg, account_name):
                    share_id = getattr(share, 'id', None)
                    share_name = getattr(share, 'name', '')

                    # Get share quota (provisioned size in GB)
                    share_quota = getattr(share, 'share_quota', 0) or 0

                    # Get access tier
                    access_tier = getattr(share, 'access_tier', 'TransactionOptimized')

                    # Get enabled protocols
                    enabled_protocols = getattr(share, 'enabled_protocols', 'SMB')

                    resource = CloudResource(
                        provider="azure",
                        subscription_id=subscription_id,
                        region=account_location,
                        resource_type="azure:storage:fileshare",
                        service_family="AzureFiles",
                        resource_id=share_id or f"{account_id}/fileServices/default/shares/{share_name}",
                        name=share_name,
                        tags={},
                        size_gb=float(share_quota),
                        parent_resource_id=account_id,
                        metadata={
                            'resource_group': rg,
                            'storage_account': account_name,
                            'share_quota_gb': share_quota,
                            'access_tier': str(access_tier) if access_tier else None,
                            'enabled_protocols': str(enabled_protocols) if enabled_protocols else 'SMB',
                            'last_modified_time': str(getattr(share, 'last_modified_time', '')) if getattr(share, 'last_modified_time', None) else None,
                            'share_usage_bytes': getattr(share, 'share_usage_bytes', 0),
                        }
                    )
                    resources.append(resource)
            except Exception as e:
                logger.debug(f"Failed to list file shares for storage account {account_name}: {e}")

        logger.info(f"Found {len(resources)} Azure File Shares")
    except Exception as e:
        check_and_raise_auth_error(e, "collect File Shares", "azure")
        logger.error(f"Failed to collect File Shares: {e}")

    return resources


# =============================================================================
# SQL Database Restore Points/Backups
# =============================================================================

def collect_sql_database_backups(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure SQL Database restore points and long-term retention backups."""
    resources = []
    try:
        sql_client = SqlManagementClient(credential, subscription_id)

        for server in sql_client.servers.list():
            server_id = getattr(server, 'id', None)
            server_name = getattr(server, 'name', '')
            if not server_id or not server_name:
                continue

            rg = _extract_resource_group(server_id)
            server_location = getattr(server, 'location', '')

            # Get databases for this server
            try:
                for db in sql_client.databases.list_by_server(rg, server_name):
                    db_id = getattr(db, 'id', None)
                    db_name = getattr(db, 'name', '')

                    if not db_name or db_name == 'master':
                        continue

                    # Get restore points (point-in-time restore points)
                    try:
                        for rp in sql_client.restore_points.list_by_database(rg, server_name, db_name):
                            rp_id = getattr(rp, 'id', None)
                            rp_name = getattr(rp, 'name', '')

                            restore_point_type = getattr(rp, 'restore_point_type', 'unknown')
                            restore_point_time = getattr(rp, 'restore_point_creation_date', None)
                            earliest_restore_date = getattr(rp, 'earliest_restore_date', None)

                            resource = CloudResource(
                                provider="azure",
                                subscription_id=subscription_id,
                                region=server_location,
                                resource_type="azure:sql:restorepoint",
                                service_family="SQLDatabase",
                                resource_id=rp_id or f"{db_id}/restorePoints/{rp_name}",
                                name=rp_name or f"{db_name}-{restore_point_type}",
                                tags={},
                                size_gb=0.0,  # Restore points don't have explicit size
                                parent_resource_id=db_id,
                                metadata={
                                    'resource_group': rg,
                                    'server_name': server_name,
                                    'database_name': db_name,
                                    'restore_point_type': str(restore_point_type),
                                    'restore_point_time': str(restore_point_time) if restore_point_time else None,
                                    'earliest_restore_date': str(earliest_restore_date) if earliest_restore_date else None,
                                }
                            )
                            resources.append(resource)
                    except Exception as e:
                        logger.debug(f"Failed to list restore points for database {db_name}: {e}")

                    # Get long-term retention backups
                    try:
                        for ltr in sql_client.long_term_retention_backups.list_by_database(
                            rg, server_name, db_name
                        ):
                            ltr_id = getattr(ltr, 'id', None)
                            ltr_name = getattr(ltr, 'name', '')

                            backup_time = getattr(ltr, 'backup_time', None)
                            backup_expiration_time = getattr(ltr, 'backup_expiration_time', None)
                            backup_storage_redundancy = getattr(ltr, 'backup_storage_redundancy', 'unknown')

                            resource = CloudResource(
                                provider="azure",
                                subscription_id=subscription_id,
                                region=server_location,
                                resource_type="azure:sql:ltrbackup",
                                service_family="SQLDatabase",
                                resource_id=ltr_id or '',
                                name=ltr_name or f"{db_name}-ltr",
                                tags={},
                                size_gb=0.0,  # LTR backups don't expose size directly
                                parent_resource_id=db_id,
                                metadata={
                                    'resource_group': rg,
                                    'server_name': server_name,
                                    'database_name': db_name,
                                    'backup_time': str(backup_time) if backup_time else None,
                                    'backup_expiration_time': str(backup_expiration_time) if backup_expiration_time else None,
                                    'backup_storage_redundancy': str(backup_storage_redundancy),
                                }
                            )
                            resources.append(resource)
                    except Exception as e:
                        logger.debug(f"Failed to list LTR backups for database {db_name}: {e}")

            except Exception as e:
                logger.debug(f"Failed to process databases for server {server_name}: {e}")

        logger.info(f"Found {len(resources)} SQL Database Restore Points/LTR Backups")
    except Exception as e:
        check_and_raise_auth_error(e, "collect SQL Database Backups", "azure")
        logger.error(f"Failed to collect SQL Database Backups: {e}")

    return resources


# =============================================================================
# Main Collection Logic
# =============================================================================

def collect_subscription(
    credential,
    subscription_id: str,
    subscription_name: str,
    tracker: Optional[ProgressTracker] = None,
    parallel_resources: int = 1,
    include_recovery_points: bool = False
) -> List[CloudResource]:
    """
    Collect all resources in a subscription.

    Args:
        credential: Azure credential
        subscription_id: Azure subscription ID
        subscription_name: Subscription display name
        tracker: Optional progress tracker
        parallel_resources: Number of resource types to collect in parallel (default: 1)
        include_recovery_points: Include individual recovery points (default: False, slow for large envs)
    """
    logger.info(f"Collecting resources from subscription: {subscription_name} ({subscription_id})")

    # Define all collection tasks as (name, function, args) tuples
    collection_tasks: List[Tuple[str, Callable, tuple]] = [
        # Compute
        ("VMs", collect_vms, (credential, subscription_id)),
        ("Disks", collect_disks, (credential, subscription_id)),
        ("Disk snapshots", collect_disk_snapshots, (credential, subscription_id)),
        # Storage
        ("Storage accounts", collect_storage_accounts, (credential, subscription_id)),
        ("File shares", collect_file_shares, (credential, subscription_id)),
        ("NetApp Files volumes", collect_netapp_files, (credential, subscription_id)),
        # Databases
        ("SQL servers", collect_sql_servers, (credential, subscription_id)),
        ("SQL managed instances", collect_sql_managed_instances, (credential, subscription_id)),
        ("SQL backups", collect_sql_database_backups, (credential, subscription_id)),
        ("CosmosDB accounts", collect_cosmosdb_accounts, (credential, subscription_id)),
        ("PostgreSQL servers", collect_postgresql_servers, (credential, subscription_id)),
        ("MySQL servers", collect_mysql_servers, (credential, subscription_id)),
        ("MariaDB servers", collect_mariadb_servers, (credential, subscription_id)),
        # Analytics
        ("Synapse workspaces", collect_synapse_workspaces, (credential, subscription_id)),
        # Containers & Compute
        ("AKS clusters", collect_aks_clusters, (credential, subscription_id)),
        ("Function apps", collect_function_apps, (credential, subscription_id)),
        # Cache
        ("Redis caches", collect_redis_caches, (credential, subscription_id)),
        # Azure Backup (Recovery Services)
        ("Recovery Services vaults", collect_recovery_services_vaults, (credential, subscription_id)),
        ("Backup policies", collect_backup_policies, (credential, subscription_id)),
        ("Backup protected items", collect_backup_protected_items, (credential, subscription_id)),
    ]

    # Recovery points are SLOW (triple-nested API calls) - only include if explicitly requested
    if include_recovery_points:
        collection_tasks.append(
            ("Backup recovery points", collect_backup_recovery_points, (credential, subscription_id))
        )

    resources = parallel_collect(
        collection_tasks=collection_tasks,
        parallel_workers=parallel_resources,
        tracker=tracker,
        logger=logger
    )

    return resources


# =============================================================================
# Change Rate Collection
# =============================================================================

def collect_azure_change_rates(
    credential,
    subscription_id: str,
    resources: List[CloudResource],
    days: int = 7
) -> Dict[str, Any]:
    """
    Collect change rate metrics from Azure Monitor for the collected resources.

    Args:
        credential: Azure credential
        subscription_id: Azure subscription ID
        resources: List of CloudResource objects collected from the subscription
        days: Number of days to sample for metrics

    Returns:
        Dict with change rate summaries by service family
    """
    change_rates = []

    # Get Monitor client
    monitor_client = get_azure_monitor_client(credential, subscription_id)
    if not monitor_client:
        logger.warning("Azure Monitor client not available, skipping change rate collection")
        return {}

    for resource in resources:
        try:
            rate_entry = _collect_azure_resource_change_rate(
                monitor_client, resource, days
            )
            if rate_entry:
                change_rates.append(rate_entry)
        except Exception as e:
            logger.debug(f"Error collecting change rate for {resource.resource_id}: {e}")
            continue

    # Aggregate change rates by service family
    summaries = aggregate_change_rates(change_rates)
    return format_change_rate_output(summaries)


def _collect_azure_resource_change_rate(
    monitor_client,
    resource: CloudResource,
    days: int
) -> Optional[Dict[str, Any]]:
    """
    Collect change rate for a single Azure resource based on its type.
    """
    service_family = resource.service_family
    resource_id = resource.resource_id

    if service_family == 'ManagedDisk':
        # Azure managed disks
        data_change = get_azure_disk_change_rate(
            monitor_client, resource_id, resource.size_gb, days
        )
        if data_change:
            return {
                'provider': 'azure',
                'service_family': 'ManagedDisk',
                'size_gb': resource.size_gb,
                'data_change': data_change
            }

    elif service_family == 'AzureSQL':
        # Azure SQL databases
        tlog_metrics = get_azure_sql_transaction_log_rate(
            monitor_client, resource_id, days
        )
        if tlog_metrics:
            return {
                'provider': 'azure',
                'service_family': 'AzureSQL',
                'size_gb': resource.size_gb,
                'transaction_logs': tlog_metrics
            }

    return None


def main():
    parser = argparse.ArgumentParser(description='CCA CloudShell - Azure Resource Collector')
    parser.add_argument('--subscription', help='Specific subscription ID (default: all accessible)')
    parser.add_argument('--regions', help='Comma-separated list of regions to filter (e.g., eastus,westus2)')
    parser.add_argument('--output', help='Output directory or blob URL', default='.')
    parser.add_argument('--log-level', help='Logging level', default='INFO')
    parser.add_argument(
        '--include-change-rate',
        action='store_true',
        help='Collect data change rates from Azure Monitor (for sizing tool DCR overrides)'
    )
    parser.add_argument(
        '--skip-pvc',
        action='store_true',
        help='Skip PVC collection from AKS clusters (PVCs are collected by default when clusters are found)'
    )
    parser.add_argument(
        '--change-rate-days',
        type=int,
        default=7,
        help='Number of days to sample for change rate metrics (default: 7)'
    )
    parser.add_argument(
        '--parallel-resources',
        type=int,
        default=4,
        help='Number of resource types to collect in parallel (default: 4, use 1 for serial)'
    )
    parser.add_argument(
        '--include-resource-ids',
        action='store_true',
        help='Include full resource IDs in output (default: redact for privacy)'
    )
    parser.add_argument(
        '--include-recovery-points',
        action='store_true',
        help='Include individual recovery points (slow for large backup environments, default: skip)'
    )

    args = parser.parse_args()

    # Setup logging - write to file if output is local directory
    log_dir = args.output if not args.output.startswith(('s3://', 'gs://', 'https://')) else None
    setup_logging(args.log_level, output_dir=log_dir)

    # Get credential
    try:
        credential = get_credential()
    except Exception as e:
        logger.error(f"Failed to authenticate with Azure: {e}")
        logger.error("Check your Azure credentials are configured correctly.")
        sys.exit(1)

    # Get subscriptions
    try:
        all_subscriptions = get_subscriptions(credential)
    except Exception as e:
        logger.error(f"Failed to list Azure subscriptions: {e}")
        logger.error("Check your credentials have subscription read access.")
        sys.exit(1)

    if not all_subscriptions:
        logger.error("No Azure subscriptions found. Check permissions.")
        sys.exit(1)

    if args.subscription:
        subscriptions = [s for s in all_subscriptions if s['id'] == args.subscription]
        if not subscriptions:
            logger.error(f"Subscription {args.subscription} not found")
            sys.exit(1)
    else:
        subscriptions = [s for s in all_subscriptions if s['state'] == 'Enabled']

    logger.info(f"Found {len(subscriptions)} subscription(s) to scan")

    # Collect resources
    all_resources = []
    subscription_ids = []
    failed_subscriptions = []

    with ProgressTracker("Azure", total_accounts=len(subscriptions)) as tracker:
        for sub in subscriptions:
            try:
                tracker.start_account(sub['id'], sub['name'])
                subscription_ids.append(sub['id'])
                all_resources.extend(collect_subscription(
                    credential, sub['id'], sub['name'], tracker,
                    parallel_resources=args.parallel_resources,
                    include_recovery_points=args.include_recovery_points
                ))
                tracker.complete_account()
            except AuthError as e:
                logger.error(f"Authentication/authorization error for subscription {sub['id']} ({sub['name']}): {e}")
                logger.error("Check that you have correct permissions for this subscription.")
                failed_subscriptions.append({'id': sub['id'], 'name': sub['name'], 'error': str(e)})
                continue
            except Exception as e:
                logger.error(f"Failed to collect from subscription {sub['id']} ({sub['name']}): {e}")
                failed_subscriptions.append({'id': sub['id'], 'name': sub['name'], 'error': str(e)})
                continue

    if failed_subscriptions:
        logger.warning(f"Collection failed for {len(failed_subscriptions)} subscription(s)")

    # Filter by regions if specified
    if args.regions:
        region_filter = {r.strip().lower() for r in args.regions.split(',')}
        original_count = len(all_resources)
        all_resources = [r for r in all_resources if r.region and r.region.lower() in region_filter]
        logger.info(f"Filtered to {len(all_resources)} resources in regions: {', '.join(sorted(region_filter))} (from {original_count} total)")

    # Generate summaries
    summaries = aggregate_sizing(all_resources)

    # Collect change rates if requested
    change_rate_data = None
    if args.include_change_rate:
        logger.info("Collecting change rate metrics from Azure Monitor...")
        print("Collecting change rate metrics from Azure Monitor...")
        all_change_rates = {}
        for sub in subscriptions:
            if sub['id'] not in subscription_ids:
                continue  # Skip failed subscriptions
            try:
                # Filter resources for this subscription
                sub_resources = [r for r in all_resources if r.subscription_id == sub['id']]
                cr_data = collect_azure_change_rates(credential, sub['id'], sub_resources, args.change_rate_days)
                merge_change_rates(all_change_rates, cr_data)
            except Exception as e:
                logger.warning(f"Failed to collect change rates for subscription {sub['id']}: {e}")

        if all_change_rates:
            change_rate_data = finalize_change_rate_output(
                all_change_rates, args.change_rate_days, "Azure Monitor"
            )
            logger.info(f"Collected change rates for {len(all_change_rates)} service families")

    # Collect PVCs from AKS clusters (automatic when clusters are discovered)
    aks_clusters = [r for r in all_resources if r.resource_type == 'azure:aks:cluster']

    if aks_clusters and not args.skip_pvc:
        logger.info("Collecting PVCs from AKS clusters...")
        print("Collecting PVCs from AKS clusters...")

        pvc_count = 0
        k8s_available = True
        for cluster in aks_clusters:
            if not k8s_available:
                break
            try:
                resource_group = cluster.metadata.get('resource_group', '')
                if not resource_group:
                    # Extract from resource ID
                    parts = cluster.resource_id.split('/')
                    rg_idx = parts.index('resourceGroups') if 'resourceGroups' in parts else -1
                    resource_group = parts[rg_idx + 1] if rg_idx >= 0 else ''

                cluster_pvcs = collect_aks_pvcs(
                    credential,
                    cluster.subscription_id,
                    resource_group,
                    cluster.name,
                    cluster.region
                )
                all_resources.extend(cluster_pvcs)
                pvc_count += len(cluster_pvcs)
                if cluster_pvcs:
                    logger.info(f"Found {len(cluster_pvcs)} PVCs in AKS cluster {cluster.name}")
            except ImportError:
                logger.info("kubernetes package not installed - skipping PVC collection (pip install kubernetes)")
                print("Note: Install 'kubernetes' package for PVC collection: pip install kubernetes")
                k8s_available = False
            except Exception as e:
                logger.warning(f"Failed to collect PVCs from AKS cluster {cluster.name}: {e}")

        if pvc_count > 0:
            print(f"Collected {pvc_count} PVCs from {len(aks_clusters)} AKS clusters")
    elif aks_clusters and args.skip_pvc:
        logger.info("Skipping PVC collection (--skip-pvc specified)")

    # Prepare output
    run_id = generate_run_id()
    timestamp = get_timestamp()

    output_data = {
        'run_id': run_id,
        'timestamp': timestamp,
        'provider': 'azure',
        'subscriptions': subscription_ids,
        'resource_count': len(all_resources),
        'resources': [r.to_dict() for r in all_resources]
    }

    summary_data = {
        'run_id': run_id,
        'timestamp': timestamp,
        'provider': 'azure',
        'subscriptions': subscription_ids,
        'total_resources': len(all_resources),
        'total_capacity_gb': sum(s.total_gb for s in summaries),
        'summaries': [s.to_dict() for s in summaries],
        'change_rates': change_rate_data if change_rate_data else None
    }

    # Remove None values
    summary_data = {k: v for k, v in summary_data.items() if v is not None}

    # Redact sensitive IDs unless --include-resource-ids is specified
    if not args.include_resource_ids:
        output_data = redact_sensitive_data(output_data)
        summary_data = redact_sensitive_data(summary_data)

    # Write outputs
    output_base = args.output.rstrip('/')

    if output_base.startswith('https://') and '.blob.core.windows.net' in output_base:
        output_base = f"{output_base}/{run_id}"

    # Short timestamp for filenames (HHMMSS)
    file_ts = datetime.now(timezone.utc).strftime('%H%M%S')
    write_json(output_data, f"{output_base}/cca_azure_inv_{file_ts}.json")
    write_json(summary_data, f"{output_base}/cca_azure_sum_{file_ts}.json")

    # Write change rate data to separate file if collected
    if change_rate_data:
        change_rate_output = {
            'run_id': run_id,
            'timestamp': timestamp,
            'provider': 'azure',
            'subscriptions': subscription_ids,
            **change_rate_data
        }
        if not args.include_resource_ids:
            change_rate_output = redact_sensitive_data(change_rate_output)
        write_json(change_rate_output, f"{output_base}/cca_azure_change_rates_{file_ts}.json")

    # Print detailed results (ProgressTracker already showed collection summary)
    print(f"\nRun ID: {run_id}")
    print_summary_table([s.to_dict() for s in summaries])
    print(f"Output: {output_base}/")


if __name__ == '__main__':
    main()
