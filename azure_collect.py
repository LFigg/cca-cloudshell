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
import json
import logging
import sys
from datetime import datetime
from typing import List, Dict, Any, Optional

# Azure SDK - pre-installed in Azure Cloud Shell
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.cosmosdb import CosmosDBManagementClient
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.recoveryservices import RecoveryServicesClient
from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient

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
from lib.models import CloudResource, aggregate_sizing
from lib.utils import (
    generate_run_id, get_timestamp, format_bytes_to_gb,
    write_json, write_csv, setup_logging, print_summary_table
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
                    'data_disk_ids': data_disk_ids,
                    'provisioning_state': vm.provisioning_state
                }
            )
            resources.append(resource)
        
        logger.info(f"Found {len(resources)} Azure VMs")
    except Exception as e:
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
                    'encryption': disk.encryption.type if disk.encryption else 'None'
                }
            )
            resources.append(resource)
        
        logger.info(f"Found {len(resources)} Azure Managed Disks")
    except Exception as e:
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
                            'collation': getattr(db, 'collation', None)
                        }
                    )
                    resources.append(resource)
            except Exception as e:
                logger.warning(f"Failed to list databases for server {server_name}: {e}")
        
        logger.info(f"Found {len(resources)} Azure SQL Databases")
    except Exception as e:
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
                    'state': getattr(mi, 'state', None)
                }
            )
            resources.append(resource)
        
        logger.info(f"Found {len(resources)} Azure SQL Managed Instances")
    except Exception as e:
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
                    'provisioning_state': account.provisioning_state
                }
            )
            resources.append(resource)
        
        logger.info(f"Found {len(resources)} Azure Cosmos DB accounts")
    except Exception as e:
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
                logger.warning(f"Failed to list backup policies for vault {vault_name}: {e}")
        
        logger.info(f"Found {len(resources)} Backup Policies")
    except Exception as e:
        logger.error(f"Failed to collect Backup Policies: {e}")
    
    return resources


def collect_backup_protected_items(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Backup Protected Items (actual backups) with sizes."""
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
                    
                    if item_props:
                        source_resource_id = getattr(item_props, 'source_resource_id', None)
                        workload_type = getattr(item_props, 'workload_type', 'unknown')
                        protection_status = getattr(item_props, 'protection_status', 'unknown')
                        last_backup_time = getattr(item_props, 'last_backup_time', None)
                        
                        # Try to get backup size from extended info
                        extended_info = getattr(item_props, 'extended_info', None)
                        if extended_info:
                            policy_inconsistent = getattr(extended_info, 'policy_inconsistent', None)
                            # Backup size may be in protected_item_data_disk_storage_info
                    
                    # Convert size to GB
                    size_gb = backup_size_bytes / (1024 ** 3) if backup_size_bytes else 0.0
                    
                    resource = CloudResource(
                        provider="azure",
                        subscription_id=subscription_id,
                        region=getattr(vault, 'location', ''),
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
                            'source_resource_id': source_resource_id
                        }
                    )
                    resources.append(resource)
            except Exception as e:
                logger.warning(f"Failed to list protected items for vault {vault_name}: {e}")
        
        logger.info(f"Found {len(resources)} Backup Protected Items")
    except Exception as e:
        logger.error(f"Failed to collect Backup Protected Items: {e}")
    
    return resources


def collect_backup_recovery_points(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Backup Recovery Points (actual backups) with sizes."""
    resources = []
    try:
        rs_client = RecoveryServicesClient(credential, subscription_id)
        
        # First get all vaults
        for vault in rs_client.vaults.list_by_subscription_id():
            vault_id = getattr(vault, 'id', None)
            vault_name = getattr(vault, 'name', '')
            vault_location = getattr(vault, 'location', '')
            if not vault_id or not vault_name:
                continue
                
            rg = _extract_resource_group(vault_id)
            
            try:
                backup_client = RecoveryServicesBackupClient(credential, subscription_id)
                
                # List protected items to get their recovery points
                for item in backup_client.backup_protected_items.list(vault_name, rg):
                    item_name = getattr(item, 'name', '')
                    item_props = getattr(item, 'properties', None)
                    
                    if not item_name or not item_props:
                        continue
                    
                    # Get container name and protected item name from the item name
                    # Format is usually: container;item
                    container_name = getattr(item_props, 'container_name', '')
                    protected_item_name = getattr(item_props, 'friendly_name', item_name)
                    source_resource_id = getattr(item_props, 'source_resource_id', None)
                    
                    try:
                        # List recovery points for this protected item
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
                                # Size might be in different attributes depending on workload type
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
                            resources.append(resource)
                    except Exception as e:
                        logger.debug(f"Failed to list recovery points for {protected_item_name}: {e}")
            except Exception as e:
                logger.warning(f"Failed to process vault {vault_name} for recovery points: {e}")
        
        logger.info(f"Found {len(resources)} Backup Recovery Points")
    except Exception as e:
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
        logger.error(f"Failed to collect Redis caches: {e}")
    
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
        logger.error(f"Failed to collect SQL Database Backups: {e}")
    
    return resources


# =============================================================================
# Main Collection Logic
# =============================================================================

def collect_subscription(credential, subscription_id: str, subscription_name: str) -> List[CloudResource]:
    """Collect all resources in a subscription."""
    logger.info(f"Collecting resources from subscription: {subscription_name} ({subscription_id})")
    
    resources = []
    
    # Compute
    resources.extend(collect_vms(credential, subscription_id))
    resources.extend(collect_disks(credential, subscription_id))
    resources.extend(collect_disk_snapshots(credential, subscription_id))
    
    # Storage
    resources.extend(collect_storage_accounts(credential, subscription_id))
    resources.extend(collect_file_shares(credential, subscription_id))
    
    # Databases
    resources.extend(collect_sql_servers(credential, subscription_id))
    resources.extend(collect_sql_managed_instances(credential, subscription_id))
    resources.extend(collect_sql_database_backups(credential, subscription_id))
    resources.extend(collect_cosmosdb_accounts(credential, subscription_id))
    
    # Containers & Compute
    resources.extend(collect_aks_clusters(credential, subscription_id))
    resources.extend(collect_function_apps(credential, subscription_id))
    
    # Cache
    resources.extend(collect_redis_caches(credential, subscription_id))
    
    # Azure Backup (Recovery Services)
    resources.extend(collect_recovery_services_vaults(credential, subscription_id))
    resources.extend(collect_backup_policies(credential, subscription_id))
    resources.extend(collect_backup_protected_items(credential, subscription_id))
    resources.extend(collect_backup_recovery_points(credential, subscription_id))
    
    return resources


def main():
    parser = argparse.ArgumentParser(description='CCA CloudShell - Azure Resource Collector')
    parser.add_argument('--subscription', help='Specific subscription ID (default: all accessible)')
    parser.add_argument('--output', help='Output directory or blob URL', default='.')
    parser.add_argument('--log-level', help='Logging level', default='INFO')
    
    args = parser.parse_args()
    
    setup_logging(args.log_level)
    
    # Get credential
    credential = get_credential()
    
    # Get subscriptions
    all_subscriptions = get_subscriptions(credential)
    
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
    
    for sub in subscriptions:
        subscription_ids.append(sub['id'])
        all_resources.extend(collect_subscription(credential, sub['id'], sub['name']))
    
    # Generate summaries
    summaries = aggregate_sizing(all_resources)
    
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
        'summaries': [s.to_dict() for s in summaries]
    }
    
    # Write outputs
    output_base = args.output.rstrip('/')
    
    if output_base.startswith('https://') and '.blob.core.windows.net' in output_base:
        output_base = f"{output_base}/{run_id}"
    
    write_json(output_data, f"{output_base}/inventory.json")
    write_json(summary_data, f"{output_base}/summary.json")
    
    # Write CSV
    csv_data = [s.to_dict() for s in summaries]
    write_csv(csv_data, f"{output_base}/sizing.csv")
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"Azure Cloud Assessment Complete")
    print(f"{'='*60}")
    print(f"Subscriptions: {len(subscriptions)}")
    print(f"Resources:     {len(all_resources)}")
    print(f"Run ID:        {run_id}")
    
    print_summary_table([s.to_dict() for s in summaries])
    
    print(f"Output: {output_base}/")


if __name__ == '__main__':
    main()
