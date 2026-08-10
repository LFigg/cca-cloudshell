"""Collection completeness scoring.

Every collector already tracks which subscriptions/accounts/projects failed
outright (see lib/azure/collector.py's failed_subscriptions, lib/gcp/collector.py's
failed_projects, lib/aws/collector.py's checkpoint['failed_accounts']) - but only
ever reports it as a raw count ("Collection failed for 4 subscription(s)"). A
raw count is a blunt instrument: 4 failed subscriptions out of 5 is a very
different situation from 4 out of 500, and a raw count treats a subscription
with 3 resources the same as one with 4,000.

This module turns that raw list into a materiality-weighted completeness
score - what fraction of this run's resources are estimated to be missing,
not just what fraction of units failed - plus a check for whether the
failures look like one systemic problem (e.g. a single expired credential
hitting every unit) rather than N unrelated ones, so an operator sees the
right signal instead of an undifferentiated failure count.

Deliberately does not gate or abort the run: unit failures happen
mid-collection, when work already done is worth keeping. This computes a
score for the report/console to surface, not a pass/fail the collector
enforces (unlike the dependency/permission preflights, which run before any
work is done and can cheaply refuse to start).
"""
from collections import Counter
from typing import Any, Dict, List, Optional, Sequence


def compute_collection_completeness(
    total_units: int,
    failed_units: List[Dict[str, Any]],
    resources: Sequence[Any],
    unit_id_field: str,
    unit_label: str = "unit",
) -> Optional[Dict[str, Any]]:
    """Score how complete a collection run is, weighted by estimated materiality.

    Args:
        total_units: Number of subscriptions/accounts/projects this run attempted.
        failed_units: One dict per unit that failed outright, each with at
            least 'id' (or 'account_id'/'project_id'/'subscription_id'),
            'name' (optional), and 'error' (the exception message).
        resources: The resources actually collected (from successful units
            only - a failed unit contributes none), used to estimate how
            much was likely missed via the average resource count of units
            that did succeed.
        unit_id_field: Attribute name on each resource holding its unit ID
            (e.g. 'subscription_id', 'account_id'), used to count resources
            per successful unit for the materiality estimate.
        unit_label: Human-readable name for one unit (e.g. "subscription",
            "account", "project"), used only in the formatted report text.

    Returns:
        None if total_units is 0 (nothing to score) or there were no
        failures at all with total_units > 0 still returns a summary showing
        100% completeness - a clean run is worth confirming, not just silence.
    """
    if total_units <= 0:
        return None

    successful_units = total_units - len(failed_units)
    unit_success_rate_pct = round(successful_units / total_units * 100, 1)

    resource_counts_per_successful_unit: List[int] = []
    if successful_units > 0:
        counts: Dict[str, int] = {}
        for r in resources:
            unit_id = getattr(r, unit_id_field, None)
            if unit_id is not None:
                counts[unit_id] = counts.get(unit_id, 0) + 1
        resource_counts_per_successful_unit = list(counts.values())

    estimated_completeness_pct = 100.0
    estimated_resources_missing: Optional[int] = None
    if failed_units and resource_counts_per_successful_unit:
        avg_resources_per_unit = sum(resource_counts_per_successful_unit) / len(resource_counts_per_successful_unit)
        estimated_resources_missing = round(avg_resources_per_unit * len(failed_units))
        known_resources = sum(resource_counts_per_successful_unit)
        estimated_completeness_pct = round(
            known_resources / (known_resources + estimated_resources_missing) * 100, 1
        )
    elif failed_units:
        # No successful units to average from (every unit failed) - there's
        # no basis for an estimate, so don't fabricate one.
        estimated_completeness_pct = 0.0 if successful_units == 0 else None

    # Systemic-issue detection: if most failures share the exact same error
    # message, this is very likely one root cause (an expired credential, a
    # revoked role assignment) rather than N independent failures, and
    # deserves a much louder signal than "N units failed" implies on its own.
    likely_systemic_issue = None
    if len(failed_units) >= 2:
        reason_counts = Counter(u.get('error', '') for u in failed_units)
        top_reason, top_count = reason_counts.most_common(1)[0]
        # top_count >= 2 requires the reason to actually be *shared* by more
        # than one unit - a fraction-only check (e.g. top_count / total >= 0.5)
        # would flag two failed units with two entirely different errors,
        # since 1/2 already clears 0.5 with nothing in common between them.
        if top_reason and top_count >= 2 and top_count / len(failed_units) >= 0.5:
            likely_systemic_issue = {
                'shared_error': top_reason,
                'affected_units': top_count,
                'of_failed_units': len(failed_units),
            }

    return {
        'unit_label': unit_label,
        'total_units': total_units,
        'successful_units': successful_units,
        'failed_units': len(failed_units),
        'unit_success_rate_pct': unit_success_rate_pct,
        'estimated_resource_completeness_pct': estimated_completeness_pct,
        'estimated_resources_missing': estimated_resources_missing,
        'failed_unit_details': [
            {'id': u.get('id') or u.get('account_id') or u.get('project_id') or u.get('subscription_id'),
             'name': u.get('name'), 'error': u.get('error')}
            for u in failed_units
        ],
        'likely_systemic_issue': likely_systemic_issue,
    }


def format_completeness_report(summary: Dict[str, Any]) -> str:
    """Format a completeness summary into a short, always-shown console banner."""
    label = summary['unit_label']
    total = summary['total_units']
    successful = summary['successful_units']
    failed = summary['failed_units']

    if failed == 0:
        return f"✓ Collection completeness: 100% ({successful}/{total} {label}s succeeded)"

    lines = []
    pct = summary['estimated_resource_completeness_pct']
    pct_str = f"~{pct}%" if pct is not None else "unknown"

    if summary['likely_systemic_issue']:
        issue = summary['likely_systemic_issue']
        symbol = "✗"
        headline = (
            f"{symbol} Collection completeness: {pct_str} estimated - LIKELY A SINGLE ROOT CAUSE, not {failed} "
            f"unrelated failures: {issue['affected_units']}/{issue['of_failed_units']} failed {label}s share the "
            f"same error"
        )
    else:
        symbol = "⚠" if (pct is None or pct >= 80) else "✗"
        headline = f"{symbol} Collection completeness: {pct_str} estimated ({successful}/{total} {label}s succeeded)"

    lines.append(headline)
    if summary['likely_systemic_issue']:
        lines.append(f"  Shared error: {summary['likely_systemic_issue']['shared_error']}")
        lines.append("  Fix that one thing and re-run rather than treating this as scattered failures.")
    for detail in summary['failed_unit_details']:
        name = f" ({detail['name']})" if detail.get('name') else ""
        lines.append(f"  - {detail['id']}{name}: {detail['error']}")

    return "\n".join(lines)
