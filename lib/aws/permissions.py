"""AWS preflight permission verification.

Checks, up front, whether the current credentials can actually perform every
read operation the parsed CLI args say this run will need - so a missing IAM
permission surfaces immediately as a clear, actionable report instead of
partway through a (possibly hours-long, possibly parallel-subprocess) run.

Each check is a minimal, real, read-only API call - the same call the real
collection step will make - rather than a static IAM-policy lookup, so it
also catches non-IAM failure modes (a service not available in a region, an
SCP restriction, etc.) that a pure "do I have the role" check would miss.

Mirrors lib/azure/permissions.py's design. The one structural difference:
Azure re-scopes a single credential to different subscription IDs, while AWS
needs a distinct assumed-role session per account - so this module assumes
each account's role itself (recording that as the first, and if it fails,
only, outcome for that account) before running the rest of the checks
against the resulting session.
"""
import itertools
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from lib.aws.auth import assume_role
from lib.utils import is_auth_error

logger = logging.getLogger(__name__)

# AWS us-east-1 is enabled in every account by default (it cannot be disabled
# the way opt-in regions can), so it's a safe, zero-extra-API-call choice of
# representative region when the run isn't restricted to specific regions via
# --regions. IAM permissions checked here are account-wide, not region-scoped,
# so one representative region is enough to catch a missing permission -
# region-specific SCPs are a warning-worthy edge case, not this check's job.
_DEFAULT_PROBE_REGION = 'us-east-1'


@dataclass
class CheckOutcome:
    label: str
    action: str
    status: str  # 'ok' | 'missing' | 'warning'
    detail: Optional[str] = None


@dataclass
class AccountCheckResult:
    account_id: str
    account_name: str
    outcomes: List[CheckOutcome] = field(default_factory=list)

    @property
    def missing(self) -> List[CheckOutcome]:
        return [o for o in self.outcomes if o.status == 'missing']

    @property
    def warnings(self) -> List[CheckOutcome]:
        return [o for o in self.outcomes if o.status == 'warning']


class _AWSPermissionProbes:
    """Stateful probe runner for one account's session.

    Some checks depend on a resource discovered by an earlier check (e.g.
    testing recovery-point access needs an actual backup vault; testing EKS
    cluster-credential access needs an actual cluster) - state is cached on
    the instance so those follow-up checks don't re-list resources an earlier
    check already fetched.
    """

    def __init__(self, session, region: str):
        self.session = session
        self.region = region
        self._sample_vault_name: Optional[str] = None
        self._sample_eks_cluster_name: Optional[str] = None

    # -- Compute ----------------------------------------------------------
    def ec2_instances(self):
        client = self.session.client('ec2', region_name=self.region)
        client.describe_instances(MaxResults=5)

    def ebs_volumes(self):
        client = self.session.client('ec2', region_name=self.region)
        client.describe_volumes(MaxResults=5)

    def ebs_snapshots(self):
        client = self.session.client('ec2', region_name=self.region)
        client.describe_snapshots(OwnerIds=['self'], MaxResults=5)

    def lambda_functions(self):
        client = self.session.client('lambda', region_name=self.region)
        client.list_functions(MaxItems=5)

    # -- Storage ------------------------------------------------------------
    def s3_buckets(self):
        client = self.session.client('s3')
        client.list_buckets()

    def efs_filesystems(self):
        client = self.session.client('efs', region_name=self.region)
        client.describe_file_systems(MaxItems=5)

    def fsx_filesystems(self):
        client = self.session.client('fsx', region_name=self.region)
        client.describe_file_systems(MaxResults=5)

    # -- Databases ------------------------------------------------------------
    def rds_instances(self):
        client = self.session.client('rds', region_name=self.region)
        client.describe_db_instances(MaxRecords=20)

    def rds_clusters(self):
        client = self.session.client('rds', region_name=self.region)
        client.describe_db_clusters(MaxRecords=20)

    def rds_snapshots(self):
        client = self.session.client('rds', region_name=self.region)
        client.describe_db_snapshots(MaxRecords=20)

    def rds_cluster_snapshots(self):
        client = self.session.client('rds', region_name=self.region)
        client.describe_db_cluster_snapshots(MaxRecords=20)

    def dynamodb_tables(self):
        client = self.session.client('dynamodb', region_name=self.region)
        client.list_tables(Limit=5)

    def elasticache_clusters(self):
        client = self.session.client('elasticache', region_name=self.region)
        client.describe_cache_clusters(MaxRecords=20)

    def redshift_clusters(self):
        client = self.session.client('redshift', region_name=self.region)
        client.describe_clusters(MaxRecords=20)

    def documentdb_clusters(self):
        client = self.session.client('docdb', region_name=self.region)
        client.describe_db_clusters(Filters=[{'Name': 'engine', 'Values': ['docdb']}], MaxRecords=20)

    def neptune_clusters(self):
        client = self.session.client('neptune', region_name=self.region)
        client.describe_db_clusters(Filters=[{'Name': 'engine', 'Values': ['neptune']}], MaxRecords=20)

    def opensearch_domains(self):
        client = self.session.client('opensearch', region_name=self.region)
        client.list_domain_names()

    def memorydb_clusters(self):
        client = self.session.client('memorydb', region_name=self.region)
        client.describe_clusters(MaxResults=5)

    def timestream_databases(self):
        client = self.session.client('timestream-write', region_name=self.region)
        client.list_databases(MaxResults=5)

    # -- Containers -----------------------------------------------------------
    def eks_clusters(self):
        client = self.session.client('eks', region_name=self.region)
        response = client.list_clusters(maxResults=5)
        clusters = response.get('clusters') or []
        if clusters:
            self._sample_eks_cluster_name = clusters[0]

    def eks_pvc_credentials(self):
        """Best-effort proxy for PVC collection's cluster access.

        Real PVC collection (lib/k8s.py) calls eks:DescribeCluster to get the
        cluster endpoint, then generates an STS-signed bearer token (a local
        signing operation, not a distinct IAM-checked call) to talk to the
        Kubernetes API directly. That last step depends on in-cluster RBAC
        (the aws-auth ConfigMap / access entries), which cannot be probed
        generically the way an IAM action can - same limitation Azure's AKS
        check accepts for cluster-admin-credential access.
        """
        if not self._sample_eks_cluster_name:
            return  # no clusters to collect PVCs from
        client = self.session.client('eks', region_name=self.region)
        client.describe_cluster(name=self._sample_eks_cluster_name)

    # -- Backup ---------------------------------------------------------------
    def backup_vaults(self):
        client = self.session.client('backup', region_name=self.region)
        response = client.list_backup_vaults(MaxResults=5)
        vaults = response.get('BackupVaultList') or []
        if vaults:
            self._sample_vault_name = vaults[0]['BackupVaultName']

    def backup_recovery_points(self):
        if not self._sample_vault_name:
            return  # nothing to collect recovery points from
        client = self.session.client('backup', region_name=self.region)
        client.list_recovery_points_by_backup_vault(BackupVaultName=self._sample_vault_name, MaxResults=5)

    def backup_plans(self):
        client = self.session.client('backup', region_name=self.region)
        client.list_backup_plans(MaxResults=5)

    def backup_protected_resources(self):
        client = self.session.client('backup', region_name=self.region)
        client.list_protected_resources(MaxResults=5)

    def backup_region_settings(self):
        client = self.session.client('backup', region_name=self.region)
        client.describe_region_settings()

    def dlm_lifecycle_policies(self):
        client = self.session.client('dlm', region_name=self.region)
        client.get_lifecycle_policies()

    # -- Monitoring -------------------------------------------------------
    def cloudwatch_metrics(self):
        """Baseline CloudWatch read check - needs no specific resource.

        Unlike Azure (which defers its Monitor check until a sample VM/storage
        account is known), CloudWatch's list_metrics is queried by namespace,
        not by a concrete resource ID, so it can run unconditionally.
        """
        client = self.session.client('cloudwatch', region_name=self.region)
        client.list_metrics(Namespace='AWS/EC2')

    # -- Cost Management --------------------------------------------------
    def cost_explorer(self):
        client = self.session.client('ce', region_name='us-east-1')  # Cost Explorer is global
        end = datetime.now(timezone.utc).date()
        start = end - timedelta(days=1)
        client.get_cost_and_usage(
            TimePeriod={'Start': start.isoformat(), 'End': end.isoformat()},
            Granularity='DAILY',
            Metrics=['UnblendedCost'],
        )


# Each entry: (label, representative IAM action, gate(args) -> bool, probe method name).
# Order matters for entries that depend on an earlier check's cached result
# (backup_vaults before backup_recovery_points; eks_clusters before eks_pvc_credentials).
_CHECKS: List[tuple] = [
    ('EC2 instances', 'ec2:DescribeInstances', lambda args: True, 'ec2_instances'),
    ('EBS volumes', 'ec2:DescribeVolumes', lambda args: True, 'ebs_volumes'),
    ('EBS snapshots', 'ec2:DescribeSnapshots', lambda args: True, 'ebs_snapshots'),
    ('Lambda functions', 'lambda:ListFunctions', lambda args: True, 'lambda_functions'),
    ('S3 buckets', 's3:ListAllMyBuckets', lambda args: True, 's3_buckets'),
    ('EFS filesystems', 'elasticfilesystem:DescribeFileSystems', lambda args: True, 'efs_filesystems'),
    ('FSx filesystems', 'fsx:DescribeFileSystems', lambda args: True, 'fsx_filesystems'),
    ('RDS instances', 'rds:DescribeDBInstances', lambda args: True, 'rds_instances'),
    ('RDS clusters', 'rds:DescribeDBClusters', lambda args: True, 'rds_clusters'),
    ('RDS snapshots', 'rds:DescribeDBSnapshots', lambda args: True, 'rds_snapshots'),
    ('RDS cluster snapshots', 'rds:DescribeDBClusterSnapshots', lambda args: True, 'rds_cluster_snapshots'),
    ('DynamoDB tables', 'dynamodb:ListTables', lambda args: True, 'dynamodb_tables'),
    ('ElastiCache clusters', 'elasticache:DescribeCacheClusters', lambda args: True, 'elasticache_clusters'),
    ('Redshift clusters', 'redshift:DescribeClusters', lambda args: True, 'redshift_clusters'),
    ('DocumentDB clusters', 'rds:DescribeDBClusters', lambda args: True, 'documentdb_clusters'),
    ('Neptune clusters', 'rds:DescribeDBClusters', lambda args: True, 'neptune_clusters'),
    ('OpenSearch domains', 'es:ListDomainNames', lambda args: True, 'opensearch_domains'),
    ('MemoryDB clusters', 'memorydb:DescribeClusters', lambda args: True, 'memorydb_clusters'),
    ('Timestream databases', 'timestream:ListDatabases', lambda args: True, 'timestream_databases'),
    ('EKS clusters', 'eks:ListClusters', lambda args: True, 'eks_clusters'),
    ('Backup vaults', 'backup:ListBackupVaults', lambda args: True, 'backup_vaults'),
    ('Backup recovery points', 'backup:ListRecoveryPointsByBackupVault', lambda args: True, 'backup_recovery_points'),
    ('Backup plans', 'backup:ListBackupPlans', lambda args: True, 'backup_plans'),
    ('Backup protected resources', 'backup:ListProtectedResources', lambda args: True, 'backup_protected_resources'),
    ('Backup region settings', 'backup:DescribeRegionSettings', lambda args: True, 'backup_region_settings'),
    ('DLM lifecycle policies', 'dlm:GetLifecyclePolicies', lambda args: True, 'dlm_lifecycle_policies'),
    ('CloudWatch metrics', 'cloudwatch:ListMetrics',
     lambda args: not getattr(args, 'skip_change_rate', False) or not getattr(args, 'skip_storage_sizes', False),
     'cloudwatch_metrics'),
    ('EKS cluster access (for PVC collection)', 'eks:DescribeCluster',
     lambda args: not getattr(args, 'skip_pvc', False), 'eks_pvc_credentials'),
    ('Cost Explorer', 'ce:GetCostAndUsage', lambda args: not getattr(args, 'no_costs', False), 'cost_explorer'),
]


def check_account_permissions(session, account_id: str, account_name: str, region: str, args) -> AccountCheckResult:
    """Run every permission check that applies to this run's CLI args against one account.

    Auth/authorization failures (is_auth_error) are recorded as 'missing' -
    these are the ones that should block the run. Any other exception
    (transient network error, service not available in this region, etc.) is
    recorded as 'warning' - real, and worth showing, but not evidence of a
    permission gap.

    Args:
        session: boto3 Session (or assumed-role session) for the target account
        account_id: AWS account ID being checked
        account_name: Human-readable account name (may be empty)
        region: Representative AWS region to run region-scoped checks against
        args: Parsed CLI args (argparse.Namespace) used to gate which checks run

    Returns:
        AccountCheckResult with the outcome of every applicable check
    """
    result = AccountCheckResult(account_id=account_id, account_name=account_name)
    probes = _AWSPermissionProbes(session, region)

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


def _resolve_account_session(base_session, account: Dict[str, Any], external_id: Optional[str]):
    """Build the session this account's checks should run under.

    Mirrors run_collection()'s own account_sessions construction exactly -
    the base session for the "is_base" (no assumed role) account, otherwise
    an assumed-role session. Returns (session, error) - error is None on
    success, or the exception that assume_role raised.
    """
    if account.get('is_base') or not account.get('role_arn'):
        return base_session, None
    try:
        return assume_role(base_session, account['role_arn'], external_id), None
    except Exception as e:
        return None, e


def check_single_account(base_session, account: Dict[str, Any], args, external_id: Optional[str], region: str) -> AccountCheckResult:
    """Resolve one account's session (assuming its role if needed) and run its checks.

    An assume-role failure is recorded as a single 'missing' outcome (no
    per-service session exists to probe with) rather than skipping the
    account silently - a bad role ARN/external ID/trust policy is exactly
    the kind of gap this preflight exists to surface before collection.

    Args:
        base_session: boto3 Session used to assume the account's role, if any
        account: Account dict (id, name, optional role_arn/is_base)
        args: Parsed CLI args (argparse.Namespace) used to gate which checks run
        external_id: Optional external ID for role assumption
        region: Representative AWS region to run region-scoped checks against

    Returns:
        AccountCheckResult for the account (a single 'missing'/'warning'
        outcome if role assumption itself failed)
    """
    account_id = account.get('id') or '(unknown)'
    account_name = account.get('name', '')
    session, assume_error = _resolve_account_session(base_session, account, external_id)

    if assume_error is not None:
        result = AccountCheckResult(account_id=account_id, account_name=account_name)
        result.outcomes.append(CheckOutcome(
            label='Assume Role', action='sts:AssumeRole',
            status='missing' if is_auth_error(assume_error) else 'warning',
            detail=str(assume_error),
        ))
        return result

    return check_account_permissions(session, account_id, account_name, region, args)


def verify_aws_permissions(
    base_session,
    accounts_to_collect: List[Dict[str, Any]],
    args,
    external_id: Optional[str] = None,
    regions: Optional[List[str]] = None,
    parallel_workers: int = 4,
) -> List[AccountCheckResult]:
    """Check every account this run will collect from, before collecting anything.

    Runs accounts concurrently (same parallelism knob as resource collection)
    since this is N accounts x up to ~25 near-instant API calls each -
    sequential would make preflight itself slow for large organizations.

    One representative region is used per account for region-scoped checks
    (the first of --regions if given, else us-east-1, which every account has
    enabled by default) - IAM permissions checked here are account-wide, not
    region-scoped, so this is sufficient without an extra describe_regions
    call per account just to pick one.

    Args:
        base_session: boto3 Session used to assume each account's role
        accounts_to_collect: List of account dicts this run will collect from
        args: Parsed CLI args (argparse.Namespace) used to gate which checks run
        external_id: Optional external ID for role assumption
        regions: Regions this run is restricted to (None = use the default probe region)
        parallel_workers: Number of accounts to check concurrently

    Returns:
        List of AccountCheckResult, one per account
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: List[AccountCheckResult] = []
    if not accounts_to_collect:
        return results

    region = regions[0] if regions else _DEFAULT_PROBE_REGION

    with ThreadPoolExecutor(max_workers=max(1, parallel_workers)) as executor:
        futures = {
            executor.submit(check_single_account, base_session, account, args, external_id, region): account
            for account in accounts_to_collect
        }
        for future in as_completed(futures):
            results.append(future.result())

    return results


def format_permission_report(results: List[AccountCheckResult]) -> str:
    """Render a human-readable report of every missing permission and warning found.

    Args:
        results: List of AccountCheckResult objects to report on

    Returns:
        Multi-line human-readable report string (empty string if no missing
        permissions or warnings were found)
    """
    lines = []
    accounts_with_missing = [r for r in results if r.missing]
    accounts_with_warnings = [r for r in results if r.warnings and not r.missing]

    if accounts_with_missing:
        lines.append(
            f"MISSING PERMISSIONS - {len(accounts_with_missing)}/{len(results)} account(s) "
            "cannot complete the collection this run was configured for:"
        )
        for r in accounts_with_missing:
            lines.append(f"\n  Account: {r.account_name} ({r.account_id})" if r.account_name else f"\n  Account: {r.account_id}")
            for o in r.missing:
                lines.append(f"    [MISSING] {o.label} - needs '{o.action}'")
                lines.append(f"              {o.detail}")

    if accounts_with_warnings:
        lines.append(
            f"\n{len(accounts_with_warnings)} account(s) had non-permission errors during "
            "the check (not blocking, but worth reviewing):"
        )
        for r in accounts_with_warnings:
            lines.append(f"\n  Account: {r.account_name} ({r.account_id})" if r.account_name else f"\n  Account: {r.account_id}")
            for o in r.warnings:
                lines.append(f"    [WARNING] {o.label} ({o.action}): {o.detail}")

    return '\n'.join(lines)
