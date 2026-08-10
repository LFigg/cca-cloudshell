"""Azure change rate collection from Azure Monitor."""
import logging
from typing import Any, Dict, List, Optional

from lib.change_rate import (
    aggregate_change_rates,
    format_change_rate_output,
    get_azure_blob_service_metrics,
    get_azure_cosmosdb_capacity,
    get_azure_flexible_server_storage_used,
    get_azure_monitor_client,
    get_azure_netapp_volume_usage,
    get_azure_redis_used_memory,
    get_azure_sql_database_capacity,
    get_azure_sql_managed_instance_capacity,
    get_azure_sql_transaction_log_rate,
    get_azure_storage_account_capacity,
    get_azure_vm_change_rate,
)
from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error

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

    Example:
        change_rates = collect_azure_change_rates(credential, subscription_id, resources, days=7)
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

    # Build a map of storage account ID -> total file-share GB already measured
    # for it (via file_shares.get(expand='stats'), see lib/azure/storage.py). The
    # account-level UsedCapacity metric used as a fallback below covers blob +
    # file + queue + table combined, so without this the account's file-share
    # bytes would be counted once here (via UsedCapacity) and again as their own
    # azure:storage:fileshare resources - see _collect_azure_resource_change_rate's
    # AzureStorage branch for where this is subtracted back out.
    file_share_gb_by_account: Dict[str, float] = {}
    for resource in resources:
        if resource.resource_type == 'azure:storage:fileshare' and resource.parent_resource_id:
            file_share_gb_by_account[resource.parent_resource_id] = (
                file_share_gb_by_account.get(resource.parent_resource_id, 0.0) + resource.size_gb
            )

    # Tracks Monitor-backed capacity lookups (attempted, patched, last error) per
    # resource kind so a total failure is surfaced instead of silently leaving
    # every resource on its quota/max-size placeholder. Every individual failure
    # is already logged at WARNING as it happens (see _capacity_call below) - this
    # rollup adds the "how many, out of how many, and what did it look like"
    # summary that's easy to miss when there are thousands of per-resource lines.
    capacity_stats: Dict[str, Dict[str, Any]] = {}

    for resource in resources:
        try:
            rate_entry = _collect_azure_resource_change_rate(
                monitor_client, resource, days, disk_sizes, capacity_stats, file_share_gb_by_account
            )
            if rate_entry:
                change_rates.append(rate_entry)
        except Exception as e:
            check_and_raise_auth_error(e, f"collect change rate for {resource.resource_id}", "azure")
            logger.warning(f"Error collecting change rate for {resource.resource_id}: {e}")
            continue

    for kind, stats in capacity_stats.items():
        attempted, patched = stats['attempted'], stats['patched']
        if attempted and patched < attempted:
            level = logger.error if patched == 0 else logger.warning
            level(
                f"Azure Monitor capacity lookup succeeded for {patched}/{attempted} {kind} "
                f"in subscription {subscription_id}; the rest keep their quota/max-size "
                f"estimate instead of actual usage. Last error seen: {stats['last_error']}"
            )

    # Aggregate change rates by service family
    summaries = aggregate_change_rates(change_rates)
    return format_change_rate_output(summaries)


def _collect_azure_resource_change_rate(
    monitor_client,
    resource: CloudResource,
    days: int,
    disk_sizes: Optional[Dict[str, float]] = None,
    capacity_stats: Optional[Dict[str, Dict[str, Any]]] = None,
    file_share_gb_by_account: Optional[Dict[str, float]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Collect change rate for a single Azure resource based on its type.

    For VMs, uses VM-level Disk Write Bytes metric (works for all VMs).
    """
    service_family = resource.service_family
    resource_id = resource.resource_id
    resource_type = resource.resource_type

    def _record(kind: str, patched: bool, error: Optional[str] = None) -> None:
        if capacity_stats is None:
            return
        stats = capacity_stats.setdefault(kind, {'attempted': 0, 'patched': 0, 'last_error': None})
        stats['attempted'] += 1
        if patched:
            stats['patched'] += 1
        elif error is not None:
            stats['last_error'] = error

    def _capacity_call(kind: str, func, *args):
        """Call a Monitor capacity lookup, always recording the attempt and its error.

        A lookup that raises (e.g. check_and_raise_auth_error reclassifying the
        underlying error as AuthError) must still count as an attempted, failed
        lookup with its real error text - recording only after a normal return
        would silently undercount failures that raise instead of returning None.
        A lookup that returns None *without* raising (the Monitor call itself
        caught its own exception, or the metric had no data points) still needs
        its error text, so func is called with error_sink= to capture it either way.
        """
        errors: List[str] = []
        try:
            result = func(*args, error_sink=errors)
        except BaseException as e:
            _record(kind, False, str(e))
            raise
        _record(kind, result is not None, errors[-1] if errors else None)
        return result

    # Azure VMs - use VM-level disk write metrics (preferred over per-disk)
    if resource_type == 'azure:vm':
        # Calculate total disk size: OS disk + all attached data disks
        total_disk_gb = float(resource.metadata.get('os_disk_size_gb') or 0)
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

    elif service_family == 'AzureSQL' and resource_type == 'azure:sql:managedinstance':
        # storage_space_used_mb is instance-level (no per-database dimension),
        # see lib/change_rate.py:get_azure_sql_managed_instance_capacity.
        capacity_gb = _capacity_call(
            'SQL managed instances', get_azure_sql_managed_instance_capacity, monitor_client, resource_id
        )
        if capacity_gb is not None:
            resource.size_gb = capacity_gb
            resource.metadata['size_source'] = 'usage'
            logger.debug(f"SQL managed instance {resource.name}: {capacity_gb:.2f} GB (actual usage)")

    elif service_family == 'CosmosDB':
        capacity_gb = _capacity_call(
            'CosmosDB accounts', get_azure_cosmosdb_capacity, monitor_client, resource_id
        )
        if capacity_gb is not None:
            resource.size_gb = capacity_gb
            resource.metadata['size_source'] = 'usage'
            logger.debug(f"Cosmos DB account {resource.name}: {capacity_gb:.2f} GB (actual usage)")

    elif service_family in ('PostgreSQL', 'MySQL'):
        capacity_gb = _capacity_call(
            f'{service_family} servers', get_azure_flexible_server_storage_used, monitor_client, resource_id
        )
        if capacity_gb is not None:
            resource.size_gb = capacity_gb
            resource.metadata['size_source'] = 'usage'
            logger.debug(f"{service_family} server {resource.name}: {capacity_gb:.2f} GB (actual usage)")

    elif service_family == 'Redis':
        # 'usedmemory' is only used for non-clustered caches - Azure Monitor's
        # docs don't confirm whether the unfiltered value sums across shards
        # for a clustered cache (see get_azure_redis_used_memory), so clustered
        # caches are deliberately left on their unavailable/estimated-capacity
        # placeholder rather than risk reporting an undercounted "actual" value.
        if not resource.metadata.get('shard_count'):
            capacity_gb = _capacity_call(
                'Redis caches', get_azure_redis_used_memory, monitor_client, resource_id
            )
            if capacity_gb is not None:
                resource.size_gb = capacity_gb
                resource.metadata['size_source'] = 'usage'
                logger.debug(f"Redis cache {resource.name}: {capacity_gb:.2f} GB (actual usage)")

    elif resource_type == 'azure:netapp:volume':
        capacity_gb = _capacity_call(
            'NetApp volumes', get_azure_netapp_volume_usage, monitor_client, resource_id
        )
        if capacity_gb is not None:
            resource.size_gb = capacity_gb
            resource.metadata['size_source'] = 'usage'
            logger.debug(f"NetApp volume {resource.name}: {capacity_gb:.2f} GB (actual usage)")

    elif service_family == 'AzureSQL' and resource_type == 'azure:sql:database':
        # Azure SQL databases - get actual used capacity from Monitor. Restricted
        # to single databases: Managed Instances share service_family='AzureSQL'
        # but the 'storage' metric this call uses is defined on individual
        # databases, not MI resource IDs - it has no real-usage source wired up
        # yet (see docs/v2-refactor-plan.md), so it's deliberately left alone
        # here rather than attempting (and failing) a database-shaped call.
        capacity_gb = _capacity_call('SQL databases', get_azure_sql_database_capacity, monitor_client, resource_id)
        if capacity_gb is not None:
            # Update resource size_gb with actual capacity (instead of max_size_bytes)
            resource.size_gb = capacity_gb
            resource.metadata['size_source'] = 'usage'
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
        # Azure Storage Accounts - get blob-service metrics (capacity + counts).
        # get_azure_blob_service_metrics() always returns a dict (never None,
        # only its 'capacity_gb' key can be), so success is judged on that key
        # rather than on the call's return value like the other capacity calls.
        blob_errors: List[str] = []
        try:
            blob_metrics = get_azure_blob_service_metrics(monitor_client, resource_id, error_sink=blob_errors)
        except BaseException as e:
            _record('storage accounts', False, str(e))
            raise
        _record(
            'storage accounts', blob_metrics['capacity_gb'] is not None,
            blob_errors[-1] if blob_errors else None
        )
        if blob_metrics['capacity_gb'] is not None:
            resource.size_gb = blob_metrics['capacity_gb']
            resource.metadata['size_source'] = 'usage'
            logger.debug(f"Storage account {resource.name}: {blob_metrics['capacity_gb']:.2f} GB")
        else:
            # Fall back to account-level UsedCapacity (covers blob + file + queue + table).
            # This is a separate, independent attempt so it's counted on its own.
            capacity_gb = _capacity_call(
                'storage accounts', get_azure_storage_account_capacity, monitor_client, resource_id
            )
            if capacity_gb is not None:
                # UsedCapacity includes this account's file shares, which are ALSO
                # separately measured as their own azure:storage:fileshare
                # resources (real usage via file_shares.get(expand='stats')) -
                # subtract that out here or the same bytes get counted twice:
                # once under this storage-account resource, once under each share.
                file_share_gb = (file_share_gb_by_account or {}).get(resource_id, 0.0)
                blob_and_other_gb = max(0.0, capacity_gb - file_share_gb)
                resource.size_gb = blob_and_other_gb
                resource.metadata['size_source'] = 'usage'
                if file_share_gb > 0:
                    resource.metadata['account_used_capacity_gb'] = capacity_gb
                    resource.metadata['file_share_gb_excluded'] = file_share_gb
                logger.debug(
                    f"Storage account {resource.name}: {blob_and_other_gb:.2f} GB (account-level "
                    f"{capacity_gb:.2f} GB minus {file_share_gb:.2f} GB already counted as file shares)"
                )

        if blob_metrics['blob_count'] is not None:
            resource.metadata['blob_count'] = blob_metrics['blob_count']
        if blob_metrics['container_count'] is not None:
            resource.metadata['container_count'] = blob_metrics['container_count']

    # Note: azure:storage:fileshare resources are skipped here - their real usage
    # is filled in directly at collection time via file_shares.get(expand='stats')
    # (see lib/azure/storage.py._fill_file_share_usage), an ARM call that needs
    # only the same Storage read permission already used to list the shares, not
    # a separate Microsoft.Insights/metrics grant.

    # Note: azure:disk resources are skipped - we use VM-level metrics instead
    # This avoids double-counting and works for all disk types

    # Note: azure:synapse:sqlpool (Synapse dedicated SQL pool) is deliberately
    # not handled here - Azure Monitor's Microsoft.Synapse/workspaces/sqlPools
    # namespace has no storage/size metric at all (only compute/DWU/cache
    # metrics); real used storage is only exposed via a data-plane SQL query
    # (e.g. sys.dm_pdw_nodes_db_file_space_usage) against the pool's SQL
    # endpoint, a fundamentally different mechanism than every other resource
    # type here, which all use ARM/Monitor management-plane calls. See
    # docs/v2-refactor-plan.md.

    # Note: azure:mariadb:server is deliberately not handled here - Azure
    # Database for MariaDB was fully retired 2025-09-19 (all instances
    # disabled, data deleted); no live workload exists to measure, so this
    # resource type isn't worth wiring a Monitor metric for. See
    # docs/v2-refactor-plan.md.

    return None
