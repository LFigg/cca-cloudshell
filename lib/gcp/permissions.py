"""GCP preflight permission verification.

Checks, up front, whether the current credentials can actually perform every
read operation the parsed CLI args say this run will need - so a missing IAM
permission surfaces immediately as a clear, actionable report instead of
partway through a run, silently dropping that project's results.

Each check is a minimal, real, read-only API call - the same call the real
collection step will make - rather than a static IAM-policy lookup, so it
also catches non-IAM failure modes (an API not enabled on the project, etc.)
that a pure "do I have the role" check would miss.

Mirrors lib/azure/permissions.py's design. Structurally GCP is closer to
Azure than to AWS here: one set of Application Default Credentials is reused
across every project (scoped per-call via a project_id parameter), with no
per-project session/role-assumption step - so there is no AWS-style "assume
role first" check; every probe just takes a project_id.
"""
import itertools
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional

from lib.utils import is_auth_error, validate_bigquery_table

logger = logging.getLogger(__name__)


def _first(iterable) -> Optional[Any]:
    """Pull at most one item from a lazy (paginated) GCP client-library iterator.

    Deliberately does NOT do list(iterable)[:1] - that fully drains every
    page before slicing, which would turn a "just check I have access" probe
    into a full resource enumeration for projects with many resources.
    """
    return next(itertools.islice(iterable, 1), None)


@dataclass
class CheckOutcome:
    label: str
    action: str
    status: str  # 'ok' | 'missing' | 'warning'
    detail: Optional[str] = None


@dataclass
class ProjectCheckResult:
    project_id: str
    project_name: str
    outcomes: List[CheckOutcome] = field(default_factory=list)

    @property
    def missing(self) -> List[CheckOutcome]:
        return [o for o in self.outcomes if o.status == 'missing']

    @property
    def warnings(self) -> List[CheckOutcome]:
        return [o for o in self.outcomes if o.status == 'warning']


class _GCPPermissionProbes:
    """Stateful probe runner for one project.

    Some checks depend on a resource discovered by an earlier check in the
    same project (e.g. testing GKE cluster-credential access needs an actual
    cluster; testing data-source access needs an actual backup vault) - state
    is cached on the instance so those follow-up checks don't re-list
    resources an earlier check already fetched.
    """

    def __init__(self, project_id: str):
        self.project_id = project_id
        self._sample_gke_cluster_name: Optional[str] = None
        self._vault_names: Optional[list] = None

    # -- Compute ------------------------------------------------------------
    def compute_instances(self):
        from google.cloud import compute_v1
        client = compute_v1.InstancesClient()
        request = compute_v1.AggregatedListInstancesRequest(project=self.project_id)
        _first(client.aggregated_list(request=request))

    def persistent_disks(self):
        from google.cloud import compute_v1
        client = compute_v1.DisksClient()
        request = compute_v1.AggregatedListDisksRequest(project=self.project_id)
        _first(client.aggregated_list(request=request))

    def disk_snapshots(self):
        from google.cloud import compute_v1
        client = compute_v1.SnapshotsClient()
        _first(client.list(project=self.project_id))

    # -- Storage --------------------------------------------------------------
    def storage_buckets(self):
        from google.cloud import storage
        client = storage.Client(project=self.project_id)
        _first(client.list_buckets())

    def filestore_instances(self):
        from google.cloud import filestore_v1
        client = filestore_v1.CloudFilestoreManagerClient()
        parent = f"projects/{self.project_id}/locations/-"
        _first(client.list_instances(parent=parent))

    # -- Databases --------------------------------------------------------
    def cloud_sql_instances(self):
        import google.auth
        from googleapiclient.discovery import build as discovery_build
        credentials, _ = google.auth.default()
        service = discovery_build('sqladmin', 'v1beta4', credentials=credentials)
        service.instances().list(project=self.project_id).execute()

    def memorystore_redis(self):
        from google.cloud import redis_v1
        client = redis_v1.CloudRedisClient()
        parent = f"projects/{self.project_id}/locations/-"
        _first(client.list_instances(parent=parent))

    def bigquery_datasets(self):
        from google.cloud import bigquery
        client = bigquery.Client(project=self.project_id)
        _first(client.list_datasets())

    def spanner_instances(self):
        from google.cloud import spanner_v1
        client = spanner_v1.InstanceAdminClient()
        parent = f"projects/{self.project_id}"
        _first(client.list_instances(parent=parent))

    def bigtable_instances(self):
        from google.cloud import bigtable
        client = bigtable.Client(project=self.project_id, admin=True)
        client.list_instances()

    def alloydb_clusters(self):
        from google.cloud import alloydb_v1
        client = alloydb_v1.AlloyDBAdminClient()
        parent = f"projects/{self.project_id}/locations/-"
        _first(client.list_clusters(parent=parent))

    # -- Containers -------------------------------------------------------
    def gke_clusters(self):
        from google.cloud import container_v1
        client = container_v1.ClusterManagerClient()
        parent = f"projects/{self.project_id}/locations/-"
        response = client.list_clusters(parent=parent)
        clusters = response.clusters or []
        if clusters:
            self._sample_gke_cluster_name = clusters[0].name

    def gke_pvc_credentials(self):
        """Best-effort proxy for PVC collection's cluster access.

        Real PVC collection (lib/k8s.py) calls container_v1's get_cluster to
        get the cluster endpoint/credentials, then talks to the Kubernetes
        API directly - that last step depends on in-cluster RBAC, which
        cannot be probed generically the way an IAM action can, same
        limitation Azure's AKS check and AWS's EKS check accept.
        """
        if not self._sample_gke_cluster_name:
            return  # no clusters to collect PVCs from
        from google.cloud import container_v1
        client = container_v1.ClusterManagerClient()
        client.get_cluster(name=self._sample_gke_cluster_name)

    def cloud_functions(self):
        from google.cloud import functions_v2
        client = functions_v2.FunctionServiceClient()
        parent = f"projects/{self.project_id}/locations/-"
        _first(client.list_functions(parent=parent))

    # -- Backup -------------------------------------------------------------
    def backup_plans(self):
        from google.cloud import backupdr_v1
        client = backupdr_v1.BackupDRClient()
        parent = f"projects/{self.project_id}/locations/-"
        _first(client.list_backup_plans(parent=parent))

    def backup_vaults(self):
        from google.cloud import backupdr_v1
        client = backupdr_v1.BackupDRClient()
        parent = f"projects/{self.project_id}/locations/-"
        self._vault_names = [v.name for v in itertools.islice(client.list_backup_vaults(parent=parent), 1)]

    def backup_data_sources(self):
        if not self._vault_names:
            return  # no vaults to collect data sources from
        from google.cloud import backupdr_v1
        client = backupdr_v1.BackupDRClient()
        _first(client.list_data_sources(parent=self._vault_names[0]))

    # -- Monitoring -------------------------------------------------------
    def monitoring_metrics(self):
        """Baseline Cloud Monitoring read check.

        Unlike Azure/AWS (which query by a concrete resource ID), GCP's
        Monitoring API is queried by metric-type filter, so this can run
        unconditionally per project without needing a sample resource first.
        """
        from google.cloud import monitoring_v3
        client = monitoring_v3.MetricServiceClient()
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=1)
        interval = monitoring_v3.TimeInterval(start_time=start_time, end_time=end_time)
        results = client.list_time_series(
            request={
                "name": f"projects/{self.project_id}",
                "filter": 'metric.type="compute.googleapis.com/instance/disk/write_bytes_count"',
                "interval": interval,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            }
        )
        _first(iter(results))

    # -- Cost (BigQuery billing export) --------------------------------------
    def billing_export(self, billing_table: str):
        from google.cloud import bigquery
        validate_bigquery_table(billing_table)
        client = bigquery.Client(project=self.project_id)
        job_config = bigquery.QueryJobConfig(dry_run=True)
        client.query(f"SELECT 1 FROM `{billing_table}` LIMIT 1", job_config=job_config)


# Each entry: (label, representative IAM permission, gate(args) -> bool, probe method name).
# Order matters for entries that depend on an earlier check's cached result
# (gke_clusters before gke_pvc_credentials; backup_vaults before backup_data_sources).
_CHECKS: List[tuple] = [
    ('Compute instances', 'compute.instances.list', lambda args: True, 'compute_instances'),
    ('Persistent disks', 'compute.disks.list', lambda args: True, 'persistent_disks'),
    ('Disk snapshots', 'compute.snapshots.list', lambda args: True, 'disk_snapshots'),
    ('Storage buckets', 'storage.buckets.list', lambda args: True, 'storage_buckets'),
    ('Filestore instances', 'file.instances.list', lambda args: True, 'filestore_instances'),
    ('Cloud SQL instances', 'cloudsql.instances.list', lambda args: True, 'cloud_sql_instances'),
    ('Memorystore Redis instances', 'redis.instances.list', lambda args: True, 'memorystore_redis'),
    ('BigQuery datasets', 'bigquery.datasets.get', lambda args: True, 'bigquery_datasets'),
    ('Spanner instances', 'spanner.instances.list', lambda args: True, 'spanner_instances'),
    ('Bigtable instances', 'bigtable.instances.list', lambda args: True, 'bigtable_instances'),
    ('AlloyDB clusters', 'alloydb.clusters.list', lambda args: True, 'alloydb_clusters'),
    ('GKE clusters', 'container.clusters.list', lambda args: True, 'gke_clusters'),
    ('Cloud Functions', 'cloudfunctions.functions.list', lambda args: True, 'cloud_functions'),
    ('Backup & DR plans', 'backupdr.backupPlans.list', lambda args: True, 'backup_plans'),
    ('Backup & DR vaults', 'backupdr.backupVaults.list', lambda args: True, 'backup_vaults'),
    ('Backup & DR data sources', 'backupdr.dataSources.list', lambda args: True, 'backup_data_sources'),
    ('Cloud Monitoring', 'monitoring.timeSeries.list',
     lambda args: not getattr(args, 'skip_change_rate', False), 'monitoring_metrics'),
    ('GKE cluster access (for PVC collection)', 'container.clusters.get',
     lambda args: not getattr(args, 'skip_pvc', False), 'gke_pvc_credentials'),
]


def check_project_permissions(project_id: str, project_name: str, args) -> ProjectCheckResult:
    """Run every permission check that applies to this run's CLI args against one project.

    Auth/authorization failures (is_auth_error) are recorded as 'missing' -
    these are the ones that should block the run. Any other exception
    (transient network error, API not enabled, etc.) is recorded as
    'warning' - real, and worth showing, but not evidence of a permission gap.

    Args:
        project_id: GCP project ID to probe
        project_name: Display name for the project, used in the report
        args: Parsed CLI args (argparse.Namespace) - gates which checks run
            (e.g. skip_change_rate, skip_pvc, billing_table, no_costs)

    Returns:
        ProjectCheckResult with one CheckOutcome per applicable check.
    """
    result = ProjectCheckResult(project_id=project_id, project_name=project_name)
    probes = _GCPPermissionProbes(project_id)

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

    billing_table = getattr(args, 'billing_table', None)
    if billing_table and not getattr(args, 'no_costs', False):
        try:
            probes.billing_export(billing_table)
            result.outcomes.append(CheckOutcome(
                label='BigQuery billing export', action='bigquery.jobs.create', status='ok'
            ))
        except Exception as e:
            status = 'missing' if is_auth_error(e) else 'warning'
            result.outcomes.append(CheckOutcome(
                label='BigQuery billing export', action='bigquery.jobs.create', status=status, detail=str(e)
            ))

    return result


def verify_gcp_permissions(
    project_ids: List[dict],
    args,
    parallel_workers: int = 4,
) -> List[ProjectCheckResult]:
    """Check every project this run will collect from, before collecting anything.

    Runs projects concurrently (same parallelism knob as resource collection)
    since this is N projects x up to ~18 near-instant API calls each -
    sequential would make preflight itself slow for large organizations.

    Args:
        project_ids: list of {'id': ..., 'name': ...} dicts, matching
            run_collection()'s own `projects` list shape.
        args: Parsed CLI args (argparse.Namespace) - gates which checks run
            (e.g. skip_change_rate, skip_pvc, billing_table, no_costs)
        parallel_workers: Number of projects to check concurrently

    Returns:
        List of ProjectCheckResult, one per project in project_ids.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: List[ProjectCheckResult] = []
    if not project_ids:
        return results

    with ThreadPoolExecutor(max_workers=max(1, parallel_workers)) as executor:
        futures = {
            executor.submit(check_project_permissions, proj['id'], proj.get('name', proj['id']), args): proj
            for proj in project_ids
        }
        for future in as_completed(futures):
            results.append(future.result())

    return results


def format_permission_report(results: List[ProjectCheckResult]) -> str:
    """Render a human-readable report of every missing permission and warning found.

    Args:
        results: List of ProjectCheckResult, as returned by
            verify_gcp_permissions()

    Returns:
        Multi-line string report listing missing permissions (blocking) and
        warnings (non-blocking) grouped by project.
    """
    lines = []
    projects_with_missing = [r for r in results if r.missing]
    projects_with_warnings = [r for r in results if r.warnings and not r.missing]

    if projects_with_missing:
        lines.append(
            f"MISSING PERMISSIONS - {len(projects_with_missing)}/{len(results)} project(s) "
            "cannot complete the collection this run was configured for:"
        )
        for r in projects_with_missing:
            lines.append(f"\n  Project: {r.project_name} ({r.project_id})")
            for o in r.missing:
                lines.append(f"    [MISSING] {o.label} - needs '{o.action}'")
                lines.append(f"              {o.detail}")

    if projects_with_warnings:
        lines.append(
            f"\n{len(projects_with_warnings)} project(s) had non-permission errors during "
            "the check (not blocking, but worth reviewing):"
        )
        for r in projects_with_warnings:
            lines.append(f"\n  Project: {r.project_name} ({r.project_id})")
            for o in r.warnings:
                lines.append(f"    [WARNING] {o.label} ({o.action}): {o.detail}")

    return '\n'.join(lines)
