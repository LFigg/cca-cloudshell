"""Data quality / collection-gap tracking, shared across cloud collectors.

Policy: a resource whose actual size couldn't be measured must never report
an allocated/provisioned/quota/estimated value as if it were real usage
(size_gb=0.0 instead, with the allocated value - if any - kept in metadata
purely for context, under a *_gb key that is NOT 'size_gb'). Every collector
opting into this policy marks each resource's CloudResource.metadata with a
'size_source' key:

  - 'usage'          - real, measured actual usage (size_gb is trustworthy)
  - 'unavailable'    - actual usage could not be measured (size_gb is 0.0)
  - 'not_applicable' - this resource type has no size concept at all (e.g. a
                        management container, a restore point) - not a gap

Resources with no 'size_source' key at all are outside this policy entirely
(e.g. a VM or a managed disk, whose size_gb *is* its provisioned size - there
is no "actual usage" to distinguish it from) and are excluded from this
summary rather than counted as a gap.

See docs/v2-refactor-plan.md for the full audit of which resource types
currently participate and which are still pending real-usage collection.
"""
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from lib.models import CloudResource

# Known "context only" size fields collectors attach next to size_source='unavailable'
# (the allocated/provisioned/estimated value that is deliberately NOT reported as
# size_gb). Checked in order; first match wins. Add new key names here as new
# resource types adopt the convention - no other change needed for this module
# to pick them up.
_CONTEXT_SIZE_KEYS = (
    'share_quota_gb',
    'max_size_gb',
    'provisioned_storage_gb',
    'provisioned_capacity_gb',
    'estimated_capacity_gb',
    'source_volume_size_gb',
    'total_storage_capacity_gb',
)


def context_size_gb(metadata: Dict[str, Any]) -> float:
    for key in _CONTEXT_SIZE_KEYS:
        value = metadata.get(key)
        if value is not None:
            try:
                return float(value)
            except (TypeError, ValueError):
                return 0.0
    return 0.0


@dataclass
class DataQualityBucket:
    resource_type: str
    total: int = 0
    measured: int = 0
    unavailable: int = 0
    not_applicable: int = 0
    unmeasured_context_gb: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'resource_type': self.resource_type,
            'total': self.total,
            'measured': self.measured,
            'unavailable': self.unavailable,
            'not_applicable': self.not_applicable,
            'unmeasured_context_gb': round(self.unmeasured_context_gb, 2),
        }


def compute_data_quality_summary_from_dicts(resources: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Same as compute_data_quality_summary(), for raw resource dicts (the shape
    every report generator actually works with, loaded straight from a
    cca_*_inv_*.json file - CloudResource.to_dict()'s output, not a CloudResource
    instance). lib/reports/assessment.py reads resources this way and, before
    this function existed, had no visibility into size_source at all - an
    'unavailable' (0 GB, real usage couldn't be measured) resource was
    indistinguishable from a genuinely empty one, silently understating total
    capacity with no caveat in the customer-facing deliverable.
    """
    buckets: Dict[str, DataQualityBucket] = {}

    for resource in resources:
        metadata = resource.get('metadata') or {}
        source = metadata.get('size_source')
        if source is None:
            continue  # this resource type isn't part of the actual-vs-estimate policy

        resource_type = resource.get('resource_type', 'unknown')
        bucket = buckets.setdefault(resource_type, DataQualityBucket(resource_type))
        bucket.total += 1
        if source == 'usage':
            bucket.measured += 1
        elif source == 'unavailable':
            bucket.unavailable += 1
            bucket.unmeasured_context_gb += context_size_gb(metadata)
        elif source == 'not_applicable':
            bucket.not_applicable += 1

    if not buckets:
        return None

    all_buckets = sorted(buckets.values(), key=lambda b: b.resource_type)
    gaps = sorted(
        (b for b in all_buckets if b.unavailable > 0),
        key=lambda b: b.unavailable,
        reverse=True,
    )

    return {
        'resource_types_with_gaps': [b.to_dict() for b in gaps],
        'all_tracked_resource_types': [b.to_dict() for b in all_buckets],
        'total_resources_unavailable': sum(b.unavailable for b in all_buckets),
        'total_unmeasured_context_gb': round(sum(b.unmeasured_context_gb for b in all_buckets), 2),
    }


def compute_data_quality_summary(resources: List[CloudResource]) -> Optional[Dict[str, Any]]:
    """Aggregate size_source across resources into a per-resource-type rollup.

    Returns None if no resource in this collection participates in the
    size_source convention at all (nothing to report). Otherwise returns a
    dict with:
      - 'resource_types_with_gaps': buckets that have at least one 'unavailable'
        resource, sorted worst-first - this is the "how many, and how much" the
        report needs to surface.
      - 'all_tracked_resource_types': every bucket that participates in the
        convention, including fully-measured ones, for completeness.
      - 'total_resources_unavailable' / 'total_unmeasured_context_gb': grand
        totals across all resource types, for a one-line summary.
    """
    buckets: Dict[str, DataQualityBucket] = {}

    for resource in resources:
        source = resource.metadata.get('size_source')
        if source is None:
            continue  # this resource type isn't part of the actual-vs-estimate policy

        bucket = buckets.setdefault(resource.resource_type, DataQualityBucket(resource.resource_type))
        bucket.total += 1
        if source == 'usage':
            bucket.measured += 1
        elif source == 'unavailable':
            bucket.unavailable += 1
            bucket.unmeasured_context_gb += context_size_gb(resource.metadata)
        elif source == 'not_applicable':
            bucket.not_applicable += 1

    if not buckets:
        return None

    all_buckets = sorted(buckets.values(), key=lambda b: b.resource_type)
    gaps = sorted(
        (b for b in all_buckets if b.unavailable > 0),
        key=lambda b: b.unavailable,
        reverse=True,
    )

    return {
        'resource_types_with_gaps': [b.to_dict() for b in gaps],
        'all_tracked_resource_types': [b.to_dict() for b in all_buckets],
        'total_resources_unavailable': sum(b.unavailable for b in all_buckets),
        'total_unmeasured_context_gb': round(sum(b.unmeasured_context_gb for b in all_buckets), 2),
    }


def format_data_quality_report(summary: Optional[Dict[str, Any]]) -> str:
    """Render a human-readable summary of collection gaps for console/log output."""
    if not summary or not summary['resource_types_with_gaps']:
        return ""

    lines = [
        f"Data quality: {summary['total_resources_unavailable']} resource(s) across "
        f"{len(summary['resource_types_with_gaps'])} type(s) have no measured actual "
        "usage (reported as 0 GB, not an allocated/quota estimate):"
    ]
    for bucket in summary['resource_types_with_gaps']:
        context = (
            f" (~{bucket['unmeasured_context_gb']:,.1f} GB allocated/estimated capacity, unmeasured)"
            if bucket['unmeasured_context_gb'] > 0 else ""
        )
        lines.append(
            f"  {bucket['resource_type']}: {bucket['unavailable']}/{bucket['total']} unmeasured{context}"
        )
    return '\n'.join(lines)
