"""Azure preflight permission verification.

Checks, up front, whether the current credential can actually perform every
read operation the parsed CLI args say this run will need - so a missing
role assignment surfaces immediately as a clear, actionable report instead
of partway through a (possibly hours-long) run, or worse, silently as
degraded data with no indication anything was wrong (see: Azure Monitor
capacity lookups silently leaving file shares at their provisioned quota
instead of actual usage).

Each check is a minimal, real, read-only API call - the same call the real
collection step will make - rather than a static RBAC-permission lookup, so
it also catches non-RBAC failure modes (unsupported metric/dimension
combinations, resource providers that aren't registered, etc.) that a pure
"do I have the role" check would miss.
"""
import itertools
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional

from lib.azure.helpers import extract_resource_group
from lib.utils import is_auth_error, isoformat_z

logger = logging.getLogger(__name__)


def _first(iterable) -> Optional[Any]:
    """Pull at most one item from a lazy (paginated) Azure SDK iterator.

    Deliberately does NOT do list(iterable)[:1] - that fully drains every
    page before slicing, which would turn a "just check I have access" probe
    into a full resource enumeration for subscriptions with many resources.
    """
    return next(itertools.islice(iterable, 1), None)


@dataclass
class CheckOutcome:
    label: str
    action: str
    status: str  # 'ok' | 'missing' | 'warning'
    detail: Optional[str] = None


@dataclass
class SubscriptionCheckResult:
    subscription_id: str
    subscription_name: str
    outcomes: List[CheckOutcome] = field(default_factory=list)

    @property
    def missing(self) -> List[CheckOutcome]:
        return [o for o in self.outcomes if o.status == 'missing']

    @property
    def warnings(self) -> List[CheckOutcome]:
        return [o for o in self.outcomes if o.status == 'warning']


class _AzurePermissionProbes:
    """Stateful probe runner for one subscription.

    Some checks depend on a resource discovered by an earlier check in the
    same subscription (e.g. testing AKS cluster-credential access needs an
    actual cluster; testing Monitor metrics needs an actual VM or storage
    account) - state is cached on the instance so those follow-up checks
    don't re-list resources that an earlier check already fetched.
    """

    def __init__(self, credential, subscription_id: str):
        self.credential = credential
        self.subscription_id = subscription_id
        self._vaults: Optional[list] = None
        self._aks_clusters: Optional[list] = None
        self._sample_vm_id: Optional[str] = None
        self._sample_storage_account_id: Optional[str] = None

    # -- Compute --------------------------------------------------------
    def vms(self):
        from azure.mgmt.compute import ComputeManagementClient
        client = ComputeManagementClient(self.credential, self.subscription_id)
        vm = _first(client.virtual_machines.list_all())
        if vm is not None:
            self._sample_vm_id = vm.id

    def disks(self):
        from azure.mgmt.compute import ComputeManagementClient
        client = ComputeManagementClient(self.credential, self.subscription_id)
        _first(client.disks.list())

    def snapshots(self):
        from azure.mgmt.compute import ComputeManagementClient
        client = ComputeManagementClient(self.credential, self.subscription_id)
        _first(client.snapshots.list())

    # -- Storage ----------------------------------------------------------
    def storage_accounts(self):
        from azure.mgmt.storage import StorageManagementClient
        client = StorageManagementClient(self.credential, self.subscription_id)
        account = _first(client.storage_accounts.list())
        if account is not None:
            self._sample_storage_account_id = account.id

    def netapp(self):
        from azure.mgmt.netapp import NetAppManagementClient
        client = NetAppManagementClient(self.credential, self.subscription_id)
        _first(client.accounts.list_by_subscription())

    # -- Databases --------------------------------------------------------
    def sql_servers(self):
        from azure.mgmt.sql import SqlManagementClient
        client = SqlManagementClient(self.credential, self.subscription_id)
        _first(client.servers.list())

    def sql_managed_instances(self):
        from azure.mgmt.sql import SqlManagementClient
        client = SqlManagementClient(self.credential, self.subscription_id)
        _first(client.managed_instances.list())

    def cosmosdb(self):
        from azure.mgmt.cosmosdb import CosmosDBManagementClient
        client = CosmosDBManagementClient(self.credential, self.subscription_id)
        _first(client.database_accounts.list())

    def postgresql(self):
        from azure.mgmt.rdbms.postgresql_flexibleservers import PostgreSQLManagementClient
        client = PostgreSQLManagementClient(self.credential, self.subscription_id)
        _first(client.servers.list())

    def mysql(self):
        from azure.mgmt.rdbms.mysql_flexibleservers import MySQLManagementClient
        client = MySQLManagementClient(self.credential, self.subscription_id)
        _first(client.servers.list())

    def mariadb(self):
        from azure.mgmt.rdbms.mariadb import MariaDBManagementClient
        client = MariaDBManagementClient(self.credential, self.subscription_id)
        _first(client.servers.list())

    def synapse(self):
        from azure.mgmt.synapse import SynapseManagementClient
        client = SynapseManagementClient(self.credential, self.subscription_id)
        _first(client.workspaces.list())

    def redis(self):
        from azure.mgmt.redis import RedisManagementClient
        client = RedisManagementClient(self.credential, self.subscription_id)
        _first(client.redis.list_by_subscription())

    # -- Backup -------------------------------------------------------------
    def recovery_services_vaults(self):
        from azure.mgmt.recoveryservices import RecoveryServicesClient
        client = RecoveryServicesClient(self.credential, self.subscription_id)
        self._vaults = list(itertools.islice(client.vaults.list_by_subscription_id(), 1))

    def backup_policies(self):
        if not self._vaults:
            return  # nothing to collect backups from - not this check's problem to raise
        vault = self._vaults[0]
        rg = extract_resource_group(vault.id)
        from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
        client = RecoveryServicesBackupClient(self.credential, self.subscription_id)
        _first(client.backup_policies.list(vault_name=vault.name, resource_group_name=rg))

    # -- Containers / compute-adjacent --------------------------------------
    def aks_clusters(self):
        from azure.mgmt.containerservice import ContainerServiceClient
        client = ContainerServiceClient(self.credential, self.subscription_id)
        self._aks_clusters = list(itertools.islice(client.managed_clusters.list(), 1))

    def aks_pvc_credentials(self):
        if not self._aks_clusters:
            return  # no clusters to collect PVCs from
        cluster = self._aks_clusters[0]
        rg = extract_resource_group(cluster.id)
        from azure.mgmt.containerservice import ContainerServiceClient
        client = ContainerServiceClient(self.credential, self.subscription_id)
        client.managed_clusters.list_cluster_admin_credentials(
            resource_group_name=rg, resource_name=cluster.name
        )

    def function_apps(self):
        from azure.mgmt.web import WebSiteManagementClient
        client = WebSiteManagementClient(self.credential, self.subscription_id)
        _first(client.web_apps.list())

    # -- Monitor --------------------------------------------------------------
    def monitor_activity_log(self):
        """Baseline Microsoft.Insights read check - needs no specific resource."""
        from azure.mgmt.monitor import MonitorManagementClient
        client = MonitorManagementClient(self.credential, self.subscription_id)
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=1)
        filter_str = f"eventTimestamp ge '{isoformat_z(start)}' and eventTimestamp le '{isoformat_z(end)}'"
        _first(client.activity_logs.list(filter=filter_str))

    def monitor_metrics(self):
        """Best-effort: only meaningful once a real VM or storage account is known.

        This is the check that actually exercises the same
        Microsoft.Insights/metrics/read call path the real collector uses for
        change-rate and capacity data. A subscription with no VMs or storage
        accounts has nothing for the real collector to query either, so
        skipping in that case doesn't miss anything the run would have hit.
        """
        sample = self._sample_vm_id or self._sample_storage_account_id
        if not sample:
            return
        from azure.mgmt.monitor import MonitorManagementClient
        client = MonitorManagementClient(self.credential, self.subscription_id)
        metric_name = 'Percentage CPU' if self._sample_vm_id else 'UsedCapacity'
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=3)
        client.metrics.list(
            resource_uri=sample,
            timespan=f"{isoformat_z(start)}/{isoformat_z(end)}",
            interval='PT1H',
            metricnames=metric_name,
            aggregation='Average',
        )

    # -- Cost Management --------------------------------------------------
    def cost_management(self):
        from azure.mgmt.costmanagement import CostManagementClient
        from azure.mgmt.costmanagement.models import QueryDataset, QueryDefinition, QueryTimePeriod

        # No subscription_id param on CostManagementClient - see the comment
        # in lib/azure/cost.py's collect_azure_costs() for why passing it
        # positionally corrupts the ARM endpoint instead of raising cleanly.
        client = CostManagementClient(self.credential)
        scope = f"/subscriptions/{self.subscription_id}"
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=1)
        query = QueryDefinition(
            type="ActualCost",
            timeframe="Custom",
            time_period=QueryTimePeriod(from_property=start, to=end),
            dataset=QueryDataset(granularity="Daily"),
        )
        client.query.usage(scope=scope, parameters=query)


# Each entry: (label, representative RBAC action, gate(args) -> bool, probe method name).
# Order matters for entries that depend on an earlier check's cached result
# (recovery_services_vaults before backup_policies; aks_clusters before
# aks_pvc_credentials; vms/storage_accounts before monitor_metrics).
_CHECKS: List[tuple] = [
    ('VMs', 'Microsoft.Compute/virtualMachines/read', lambda args: True, 'vms'),
    ('Disks', 'Microsoft.Compute/disks/read', lambda args: True, 'disks'),
    ('Disk snapshots', 'Microsoft.Compute/snapshots/read', lambda args: True, 'snapshots'),
    ('Storage accounts', 'Microsoft.Storage/storageAccounts/read', lambda args: True, 'storage_accounts'),
    ('NetApp Files', 'Microsoft.NetApp/netAppAccounts/read', lambda args: True, 'netapp'),
    ('SQL servers', 'Microsoft.Sql/servers/read', lambda args: True, 'sql_servers'),
    ('SQL managed instances', 'Microsoft.Sql/managedInstances/read', lambda args: True, 'sql_managed_instances'),
    ('CosmosDB accounts', 'Microsoft.DocumentDB/databaseAccounts/read', lambda args: True, 'cosmosdb'),
    ('PostgreSQL flexible servers', 'Microsoft.DBforPostgreSQL/flexibleServers/read', lambda args: True, 'postgresql'),
    ('MySQL flexible servers', 'Microsoft.DBforMySQL/flexibleServers/read', lambda args: True, 'mysql'),
    ('MariaDB servers', 'Microsoft.DBforMariaDB/servers/read', lambda args: True, 'mariadb'),
    ('Synapse workspaces', 'Microsoft.Synapse/workspaces/read', lambda args: True, 'synapse'),
    ('Redis caches', 'Microsoft.Cache/redis/read', lambda args: True, 'redis'),
    ('Recovery Services vaults', 'Microsoft.RecoveryServices/vaults/read', lambda args: True, 'recovery_services_vaults'),
    ('Backup policies', 'Microsoft.RecoveryServices/vaults/backupPolicies/read', lambda args: True, 'backup_policies'),
    ('AKS clusters', 'Microsoft.ContainerService/managedClusters/read', lambda args: True, 'aks_clusters'),
    ('Function apps', 'Microsoft.Web/sites/read', lambda args: True, 'function_apps'),
    ('Azure Monitor (Activity Log)', 'Microsoft.Insights/eventtypes/values/read',
     lambda args: not args.skip_change_rate, 'monitor_activity_log'),
    ('Azure Monitor (metrics)', 'Microsoft.Insights/metrics/read',
     lambda args: not args.skip_change_rate, 'monitor_metrics'),
    ('AKS cluster credentials (for PVC collection)',
     'Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action',
     lambda args: not args.skip_pvc, 'aks_pvc_credentials'),
    ('Cost Management', 'Microsoft.CostManagement/query/action', lambda args: not args.no_costs, 'cost_management'),
]


def check_subscription_permissions(credential, subscription_id: str, subscription_name: str, args) -> SubscriptionCheckResult:
    """Run every permission check that applies to this run's CLI args against one subscription.

    Auth/authorization failures (is_auth_error) are recorded as 'missing' -
    these are the ones that should block the run. Any other exception
    (transient network error, provider-not-registered, an unsupported
    metric/dimension combination, etc.) is recorded as 'warning' - real, and
    worth showing, but not evidence of a permission gap.

    Args:
        credential: Azure credential object
        subscription_id: Azure subscription ID
        subscription_name: Subscription display name
        args: Parsed CLI args (argparse.Namespace) controlling which checks apply

    Returns:
        A SubscriptionCheckResult with one CheckOutcome per applicable check
    """
    result = SubscriptionCheckResult(subscription_id=subscription_id, subscription_name=subscription_name)
    probes = _AzurePermissionProbes(credential, subscription_id)

    for label, action, gate, method_name in _CHECKS:
        if not gate(args):
            continue
        try:
            getattr(probes, method_name)()
            result.outcomes.append(CheckOutcome(label=label, action=action, status='ok'))
        except Exception as e:
            if is_auth_error(e):
                result.outcomes.append(CheckOutcome(label=label, action=action, status='missing', detail=str(e)))
            else:
                result.outcomes.append(CheckOutcome(label=label, action=action, status='warning', detail=str(e)))

    return result


def verify_azure_permissions(
    credential,
    subscriptions: List[dict],
    args,
    parallel_workers: int = 4,
) -> List[SubscriptionCheckResult]:
    """Check every subscription this run will collect from, before collecting anything.

    Runs subscriptions concurrently (same parallelism knob as resource
    collection) since this is N subscriptions x up to ~20 near-instant API
    calls each - sequential would make preflight itself slow for large
    tenants.

    Args:
        credential: Azure credential object
        subscriptions: List of subscription dicts (each with 'id' and 'name')
        args: Parsed CLI args (argparse.Namespace) controlling which checks apply
        parallel_workers: Number of subscriptions to check concurrently

    Returns:
        List of SubscriptionCheckResult, one per subscription checked
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: List[SubscriptionCheckResult] = []
    if not subscriptions:
        return results

    with ThreadPoolExecutor(max_workers=max(1, parallel_workers)) as executor:
        futures = {
            executor.submit(
                check_subscription_permissions, credential, sub['id'], sub['name'], args
            ): sub
            for sub in subscriptions
        }
        for future in as_completed(futures):
            results.append(future.result())

    return results


def format_permission_report(results: List[SubscriptionCheckResult]) -> str:
    """Render a human-readable report of every missing permission and warning found.

    Args:
        results: List of SubscriptionCheckResult from verify_azure_permissions()
            or check_subscription_permissions()

    Returns:
        Multi-line report string, one section for missing permissions and one
        for non-blocking warnings
    """
    lines = []
    subs_with_missing = [r for r in results if r.missing]
    subs_with_warnings = [r for r in results if r.warnings and not r.missing]

    if subs_with_missing:
        lines.append(
            f"MISSING PERMISSIONS - {len(subs_with_missing)}/{len(results)} subscription(s) "
            "cannot complete the collection this run was configured for:"
        )
        for r in subs_with_missing:
            lines.append(f"\n  Subscription: {r.subscription_name} ({r.subscription_id})")
            for o in r.missing:
                lines.append(f"    [MISSING] {o.label} - needs '{o.action}'")
                lines.append(f"              {o.detail}")

    if subs_with_warnings:
        lines.append(
            f"\n{len(subs_with_warnings)} subscription(s) had non-permission errors during "
            "the check (not blocking, but worth reviewing):"
        )
        for r in subs_with_warnings:
            lines.append(f"\n  Subscription: {r.subscription_name} ({r.subscription_id})")
            for o in r.warnings:
                lines.append(f"    [WARNING] {o.label} ({o.action}): {o.detail}")

    return '\n'.join(lines)
