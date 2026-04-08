"""Azure change rate collection from Azure Monitor."""
import logging
from typing import Any, Dict, List, Optional

from lib.change_rate import (
    aggregate_change_rates,
    format_change_rate_output,
    get_azure_disk_change_rate,
    get_azure_monitor_client,
    get_azure_sql_database_capacity,
    get_azure_sql_transaction_log_rate,
    get_azure_storage_account_capacity,
    get_azure_vm_change_rate,
)
from lib.models import CloudResource

logger = logging.getLogger(__name__)


def collect_azure_change_rates(
    credential,
    subscription_id: str,
    resources: List[CloudResource],
    days: int = 7
) -> Dict[str, Any]:
    """
    Collect change rate metrics from Azure Monitor for the collected resources.
    
    Uses VM-level metrics for disk change rate (more reliable than per-disk metrics).

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
        logger.warning("Install azure-mgmt-monitor: pip install azure-mgmt-monitor")
        return {}

    # Build a map of disk ID -> size for calculating total VM disk size
    disk_sizes = {}
    for resource in resources:
        if resource.resource_type == 'azure:disk':
            disk_sizes[resource.resource_id] = resource.size_gb

    for resource in resources:
        try:
            rate_entry = _collect_azure_resource_change_rate(
                monitor_client, resource, days, disk_sizes
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
    days: int,
    disk_sizes: Optional[Dict[str, float]] = None
) -> Optional[Dict[str, Any]]:
    """
    Collect change rate for a single Azure resource based on its type.
    
    For VMs, uses VM-level Disk Write Bytes metric (works for all VMs).
    """
    service_family = resource.service_family
    resource_id = resource.resource_id
    resource_type = resource.resource_type

    # Azure VMs - use VM-level disk write metrics (preferred over per-disk)
    if resource_type == 'azure:vm':
        # Calculate total disk size: OS disk + all attached data disks
        total_disk_gb = resource.size_gb  # OS disk size
        attached_disks = resource.metadata.get('attached_disks', [])
        if disk_sizes:
            for disk_id in attached_disks:
                total_disk_gb += disk_sizes.get(disk_id, 0)
        
        data_change = get_azure_vm_change_rate(
            monitor_client, resource_id, total_disk_gb, days
        )
        if data_change:
            return {
                'provider': 'azure',
                'service_family': 'AzureVM',
                'size_gb': total_disk_gb,
                'data_change': data_change
            }

    elif service_family == 'AzureSQL':
        # Azure SQL databases - get actual used capacity from Monitor
        capacity_gb = get_azure_sql_database_capacity(monitor_client, resource_id)
        if capacity_gb is not None:
            # Update resource size_gb with actual capacity (instead of max_size_bytes)
            resource.size_gb = capacity_gb
            logger.debug(f"SQL database {resource.name}: {capacity_gb:.2f} GB (actual usage)")

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

    elif service_family == 'AzureStorage':
        # Azure Storage Accounts - get actual used capacity from Monitor
        capacity_gb = get_azure_storage_account_capacity(monitor_client, resource_id)
        if capacity_gb is not None:
            # Update resource size_gb with actual capacity
            resource.size_gb = capacity_gb
            logger.debug(f"Storage account {resource.name}: {capacity_gb:.2f} GB")

    # Note: azure:disk resources are skipped - we use VM-level metrics instead
    # This avoids double-counting and works for all disk types

    return None
