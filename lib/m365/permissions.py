"""M365 preflight permission verification.

Checks, up front, whether the current app registration can actually perform
every read operation the parsed CLI args say this run will need - so a
missing Graph API permission surfaces immediately as a clear, actionable
report instead of partway through a run.

Each check is a minimal, real, read-only API call - the same call the real
collection step will make - rather than a static app-permission lookup, so
it also catches non-permission failure modes that a pure "do I have the
scope" check would miss.

Mirrors lib/azure/permissions.py's design, with one structural
simplification: M365 collection is always single-tenant (one Graph client,
one tenant_id per run - no multi-account/multi-subscription/multi-project
loop), so there is nothing to parallelize and no per-account credential
resolution step.

Usage report checks (Exchange/SharePoint/OneDrive/Teams) call the Graph
reports endpoint directly via httpx, deliberately NOT through
lib.m365.helpers.get_usage_report() - that helper swallows every exception
and returns None on failure (by design, for graceful degradation during real
collection), which would make an auth failure indistinguishable from "no
data yet" for this preflight's purposes. Probing the same URL directly, with
the error left to propagate, is what lets is_auth_error() classify it.
"""
import logging
from dataclasses import dataclass, field
from typing import Any, List, Optional

from lib.m365.helpers import (
    USAGE_REPORT_PERIOD,
    run_sync,
)
from lib.utils import is_auth_error

logger = logging.getLogger(__name__)


@dataclass
class CheckOutcome:
    label: str
    action: str
    status: str  # 'ok' | 'missing' | 'warning'
    detail: Optional[str] = None


@dataclass
class TenantCheckResult:
    tenant_id: str
    outcomes: List[CheckOutcome] = field(default_factory=list)

    @property
    def missing(self) -> List[CheckOutcome]:
        return [o for o in self.outcomes if o.status == 'missing']

    @property
    def warnings(self) -> List[CheckOutcome]:
        return [o for o in self.outcomes if o.status == 'warning']


class _M365PermissionProbes:
    """Stateful probe runner for one tenant's Graph client.

    The Team-details check depends on a sample group discovered by the
    Groups check - state is cached on the instance so the follow-up check
    doesn't re-list groups an earlier check already fetched.
    """

    def __init__(self, graph_client, credential: Optional[Any] = None):
        self.graph_client = graph_client
        self.credential = credential
        self._sample_team_group_id: Optional[str] = None

    # -- Graph SDK calls ----------------------------------------------------
    def users(self):
        run_sync(self.graph_client.users.get())

    def groups(self):
        response = run_sync(self.graph_client.groups.get())
        groups = getattr(response, 'value', None) or []
        for group in groups:
            options = getattr(group, 'resource_provisioning_options', None) or []
            if 'Team' in options:
                self._sample_team_group_id = group.id
                break

    def sites(self):
        run_sync(self.graph_client.sites.get())

    def team_details(self):
        if not self._sample_team_group_id:
            return  # no Teams-backed groups to check team details for
        run_sync(self.graph_client.teams.by_team_id(self._sample_team_group_id).get())

    # -- Raw REST calls (no msgraph-sdk surface for these) -------------------
    def organization(self):
        self._rest_get("https://graph.microsoft.com/v1.0/organization")

    def subscribed_skus(self):
        self._rest_get("https://graph.microsoft.com/v1.0/subscribedSkus")

    def mailbox_usage_report(self):
        self._usage_report_get('getMailboxUsageDetail')

    def sharepoint_usage_report(self):
        self._usage_report_get('getSharePointSiteUsageDetail')

    def onedrive_usage_report(self):
        self._usage_report_get('getOneDriveUsageAccountDetail')

    def teams_usage_report(self):
        self._usage_report_get('getTeamsTeamActivityDetail')

    def teams_activity_report(self):
        self._usage_report_get('getTeamsUserActivityUserDetail')

    def _rest_get(self, url: str):
        import httpx
        if self.credential is None:
            raise RuntimeError("No credential provided")
        token = self.credential.get_token("https://graph.microsoft.com/.default")
        headers = {'Authorization': f'Bearer {token.token}', 'Accept': 'application/json'}
        with httpx.Client(timeout=30.0) as client:
            response = client.get(url, headers=headers)
            response.raise_for_status()

    def _usage_report_get(self, report_name: str):
        url = f"https://graph.microsoft.com/v1.0/reports/{report_name}(period='{USAGE_REPORT_PERIOD}')"
        import httpx
        if self.credential is None:
            raise RuntimeError("No credential provided")
        token = self.credential.get_token("https://graph.microsoft.com/.default")
        headers = {'Authorization': f'Bearer {token.token}', 'Accept': 'application/json'}
        with httpx.Client(follow_redirects=True, timeout=30.0) as client:
            response = client.get(url, headers=headers)
            response.raise_for_status()


# Each entry: (label, representative Graph permission, gate(args) -> bool, probe method name).
# Order matters: groups before team_details (dependent on its cached sample group).
_CHECKS: List[tuple] = [
    ('Users', 'User.Read.All', lambda args: True, 'users'),
    ('Groups', 'Group.Read.All',
     lambda args: not getattr(args, 'skip_teams', False) or getattr(args, 'include_entra', False), 'groups'),
    ('SharePoint sites', 'Sites.Read.All', lambda args: not getattr(args, 'skip_sharepoint', False), 'sites'),
    ('Team details', 'Team.ReadBasic.All', lambda args: not getattr(args, 'skip_teams', False), 'team_details'),
    ('Organization info', 'Organization.Read.All', lambda args: True, 'organization'),
    ('Subscribed SKUs (licensing)', 'Organization.Read.All', lambda args: True, 'subscribed_skus'),
    ('Mailbox usage report', 'Reports.Read.All', lambda args: True, 'mailbox_usage_report'),
    ('SharePoint usage report', 'Reports.Read.All',
     lambda args: not getattr(args, 'skip_sharepoint', False), 'sharepoint_usage_report'),
    ('OneDrive usage report', 'Reports.Read.All',
     lambda args: not getattr(args, 'skip_onedrive', False), 'onedrive_usage_report'),
    ('Teams usage report', 'Reports.Read.All',
     lambda args: not getattr(args, 'skip_teams', False), 'teams_usage_report'),
    ('Teams activity report', 'Reports.Read.All',
     lambda args: not getattr(args, 'skip_teams', False), 'teams_activity_report'),
]


def check_tenant_permissions(graph_client, tenant_id: str, args, credential: Optional[Any] = None) -> TenantCheckResult:
    """Run every permission check that applies to this run's CLI args against the tenant.

    Auth/authorization failures (is_auth_error) are recorded as 'missing' -
    these are the ones that should block the run. Any other exception
    (transient network error, throttling, etc.) is recorded as 'warning' -
    real, and worth showing, but not evidence of a permission gap.

    Args:
        graph_client: Microsoft Graph client
        tenant_id: Azure AD tenant ID being checked
        args: argparse.Namespace with the run's CLI options (used to gate
            which checks apply, e.g. --skip-teams)
        credential: The Graph credential from get_graph_client(), needed for
            the raw-HTTP probes (organization, licensing, usage reports)

    Returns:
        TenantCheckResult with one CheckOutcome per applicable check
    """
    result = TenantCheckResult(tenant_id=tenant_id)
    probes = _M365PermissionProbes(graph_client, credential)

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


def verify_m365_permissions(graph_client, tenant_id: str, args, credential: Optional[Any] = None) -> TenantCheckResult:
    """Check the tenant this run will collect from, before collecting anything.

    Unlike the other three clouds, M365 collection is always single-tenant,
    so there is nothing to parallelize here - this is a thin, symmetrical
    entry point kept for naming consistency with verify_azure_permissions() /
    verify_aws_permissions() / verify_gcp_permissions().

    Args:
        graph_client: Microsoft Graph client
        tenant_id: Azure AD tenant ID being checked
        args: argparse.Namespace with the run's CLI options
        credential: The Graph credential from get_graph_client()

    Returns:
        TenantCheckResult with one CheckOutcome per applicable check
    """
    return check_tenant_permissions(graph_client, tenant_id, args, credential)


def format_permission_report(result: TenantCheckResult) -> str:
    """Render a human-readable report of every missing permission and warning found.

    Args:
        result: TenantCheckResult from check_tenant_permissions()/verify_m365_permissions()

    Returns:
        Multi-line human-readable report string. Empty string if result has
        no missing checks and no warnings.
    """
    lines = []

    if result.missing:
        lines.append(
            f"MISSING PERMISSIONS - tenant {result.tenant_id} cannot complete the "
            "collection this run was configured for:"
        )
        for o in result.missing:
            lines.append(f"  [MISSING] {o.label} - needs '{o.action}'")
            lines.append(f"            {o.detail}")

    if result.warnings:
        lines.append(
            f"\n{len(result.warnings)} check(s) had non-permission errors during "
            "the check (not blocking, but worth reviewing):"
        )
        for o in result.warnings:
            lines.append(f"  [WARNING] {o.label} ({o.action}): {o.detail}")

    return '\n'.join(lines)
