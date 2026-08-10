# GCP Monitoring and Change Rate collectors
"""Change rate collection using Cloud Monitoring."""

import logging
from typing import Any, Dict, List, Optional

from lib.change_rate import (
    aggregate_change_rates,
    compute_dcr_from_snapshot_deltas,
    format_change_rate_output,
    get_cloudsql_change_rate,
    get_gcp_disk_change_rate,
    get_gcp_monitoring_client,
)
from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error

logger = logging.getLogger(__name__)


def collect_gcp_change_rates(
    project_id: str,
    resources: List[CloudResource],
    days: int = 7
) -> Dict[str, Any]:
    """
    Collect change rate metrics from Cloud Monitoring for the collected resources.

    Args:
        project_id: GCP project ID
        resources: List of CloudResource objects collected from the project
        days: Number of days to sample for metrics

    Returns:
        Dict with change rate summaries by service family

    Example:
        change_rates = collect_gcp_change_rates("my-gcp-project", resources, days=7)
    """
    change_rates = []

    # Get Monitoring client
    monitoring_client = get_gcp_monitoring_client(project_id)
    if not monitoring_client:
        logger.warning("Cloud Monitoring client not available, skipping change rate collection")
        logger.warning("Install google-cloud-monitoring: pip install google-cloud-monitoring")
        return {}

    # Build a map of source disk name -> (creation_timestamp, size_gb) for every
    # disk snapshot, for the snapshot-delta DCR cross-check below. GCP disk
    # snapshots' storage_bytes is genuinely incremental/dedup-aware (see
    # lib/gcp/compute.py's collect_disk_snapshots()) - a real measured proxy for
    # daily change, distinct from (and less prone to overcounting rewrites than)
    # the live write_bytes_count metric used elsewhere in this file.
    snapshots_by_disk: Dict[str, List[Any]] = {}
    for resource in resources:
        if resource.resource_type == 'gcp:compute:snapshot':
            source_disk = resource.metadata.get('source_disk')
            creation_timestamp = resource.metadata.get('creation_timestamp')
            if source_disk and creation_timestamp:
                snapshots_by_disk.setdefault(source_disk, []).append((creation_timestamp, resource.size_gb))

    for resource in resources:
        try:
            rate_entry = _collect_gcp_resource_change_rate(
                monitoring_client, project_id, resource, days, snapshots_by_disk
            )
            if rate_entry:
                change_rates.append(rate_entry)
        except Exception as e:
            check_and_raise_auth_error(e, f"collect change rate for {resource.resource_id}", "gcp")
            logger.warning(f"Error collecting change rate for {resource.resource_id}: {e}")
            continue

    # Aggregate change rates by service family
    summaries = aggregate_change_rates(change_rates)
    return format_change_rate_output(summaries)


def _collect_gcp_resource_change_rate(
    monitoring_client,
    project_id: str,
    resource: CloudResource,
    days: int,
    snapshots_by_disk: Optional[Dict[str, List[Any]]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Collect change rate for a single GCP resource based on its type.

    Args:
        monitoring_client: Cloud Monitoring client
        project_id: GCP project ID
        resource: CloudResource to collect change rate for
        days: Number of days to sample
        snapshots_by_disk: disk name -> [(creation_timestamp, size_gb), ...] for
            that disk's snapshot chain, for the snapshot-delta DCR cross-check
            (see compute_dcr_from_snapshot_deltas())

    Returns:
        Dict with change rate data or None if not applicable
    """
    service_family = resource.service_family
    resource_type = resource.resource_type

    # NOTE: these branches previously checked service_family == 'PersistentDisk'
    # and == 'CloudSQL', but no collector ever sets those values - disks use
    # service_family="Compute" (lib/gcp/compute.py) and Cloud SQL instances use
    # service_family="SQL" (lib/gcp/databases.py). Both branches were
    # unreachable dead code, so collect_gcp_change_rates() silently returned
    # {} for every GCP run. Fixed to match the actual values collectors set.
    if service_family == 'Compute' and resource_type == 'gcp:compute:disk':
        # Prefer a snapshot-delta-based DCR when this disk has at least 2
        # snapshots: it's a real, dedup-aware measurement of unique-byte change
        # (see compute_dcr_from_snapshot_deltas()'s docstring), a genuinely
        # different and generally more trustworthy signal than the live
        # write_bytes_count metric below, which has no dedup concept and
        # overcounts any workload rewriting the same blocks repeatedly.
        disk_snapshots = (snapshots_by_disk or {}).get(resource.name, [])
        if len(disk_snapshots) >= 2:
            snapshot_data_change = compute_dcr_from_snapshot_deltas(disk_snapshots, resource.size_gb)
            if snapshot_data_change:
                return {
                    'provider': 'gcp',
                    'service_family': 'Compute',
                    'size_gb': resource.size_gb,
                    'data_change': snapshot_data_change,
                    'dcr_method': 'snapshot_delta',
                }

        # GCP persistent disks. The Compute Engine metric's zone resource
        # label needs the actual zone (e.g. "us-central1-a"), not
        # resource.region, which collect_persistent_disks() already
        # truncates to the region (e.g. "us-central1") - the real zone is
        # only preserved in metadata['zone'].
        disk_name = resource.metadata.get('disk_name', resource.name)
        zone = resource.metadata.get('zone')

        if disk_name and zone:
            data_change = get_gcp_disk_change_rate(
                monitoring_client, project_id, disk_name, zone, resource.size_gb, days
            )
            if data_change:
                return {
                    'provider': 'gcp',
                    'service_family': 'Compute',
                    'size_gb': resource.size_gb,
                    'data_change': data_change,
                    'dcr_method': 'live_write_bytes_metric',
                }

    elif service_family == 'SQL':
        # Cloud SQL instances
        instance_id = resource.metadata.get('instance_name', resource.name)

        if instance_id:
            data_change = get_cloudsql_change_rate(
                monitoring_client, project_id, instance_id, resource.size_gb, days
            )
            if data_change:
                return {
                    'provider': 'gcp',
                    'service_family': 'SQL',
                    'size_gb': resource.size_gb,
                    'data_change': data_change
                }

    return None
