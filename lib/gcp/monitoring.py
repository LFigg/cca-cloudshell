# GCP Monitoring and Change Rate collectors
"""Change rate collection using Cloud Monitoring."""

import logging
from typing import Any, Dict, List, Optional

from lib.change_rate import (
    aggregate_change_rates,
    format_change_rate_output,
    get_cloudsql_change_rate,
    get_gcp_disk_change_rate,
    get_gcp_monitoring_client,
)
from lib.models import CloudResource

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
    """
    change_rates = []

    # Get Monitoring client
    monitoring_client = get_gcp_monitoring_client(project_id)
    if not monitoring_client:
        logger.warning("Cloud Monitoring client not available, skipping change rate collection")
        logger.warning("Install google-cloud-monitoring: pip install google-cloud-monitoring")
        return {}

    for resource in resources:
        try:
            rate_entry = _collect_gcp_resource_change_rate(
                monitoring_client, project_id, resource, days
            )
            if rate_entry:
                change_rates.append(rate_entry)
        except Exception as e:
            logger.debug(f"Error collecting change rate for {resource.resource_id}: {e}")
            continue

    # Aggregate change rates by service family
    summaries = aggregate_change_rates(change_rates)
    return format_change_rate_output(summaries)


def _collect_gcp_resource_change_rate(
    monitoring_client,
    project_id: str,
    resource: CloudResource,
    days: int
) -> Optional[Dict[str, Any]]:
    """
    Collect change rate for a single GCP resource based on its type.

    Args:
        monitoring_client: Cloud Monitoring client
        project_id: GCP project ID
        resource: CloudResource to collect change rate for
        days: Number of days to sample

    Returns:
        Dict with change rate data or None if not applicable
    """
    service_family = resource.service_family

    if service_family == 'PersistentDisk':
        # GCP persistent disks
        disk_name = resource.metadata.get('disk_name', resource.name)
        zone = resource.region  # For zonal disks, this would be the zone

        if disk_name and zone:
            data_change = get_gcp_disk_change_rate(
                monitoring_client, project_id, disk_name, zone, resource.size_gb, days
            )
            if data_change:
                return {
                    'provider': 'gcp',
                    'service_family': 'PersistentDisk',
                    'size_gb': resource.size_gb,
                    'data_change': data_change
                }

    elif service_family == 'CloudSQL':
        # Cloud SQL instances
        instance_id = resource.metadata.get('instance_name', resource.name)

        if instance_id:
            data_change = get_cloudsql_change_rate(
                monitoring_client, project_id, instance_id, resource.size_gb, days
            )
            if data_change:
                return {
                    'provider': 'gcp',
                    'service_family': 'CloudSQL',
                    'size_gb': resource.size_gb,
                    'data_change': data_change
                }

    return None
