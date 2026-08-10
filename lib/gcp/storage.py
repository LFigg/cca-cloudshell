# GCP Storage collectors
"""Collectors for Cloud Storage buckets and Filestore instances."""

import logging
from typing import List

from lib.gcp.utils import extract_location_from_name
from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error

logger = logging.getLogger(__name__)


def collect_storage_buckets(project_id: str) -> List[CloudResource]:
    """
    Collect Cloud Storage buckets.

    Args:
        project_id: GCP project ID

    Returns:
        List of CloudResource objects for storage buckets

    Example:
        buckets = collect_storage_buckets("my-gcp-project")
    """
    from google.cloud import storage

    resources = []
    try:
        client = storage.Client(project=project_id)

        for bucket in client.list_buckets():
            labels = dict(bucket.labels) if bucket.labels else {}

            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region=bucket.location.lower() if bucket.location else 'unknown',
                resource_type="gcp:storage:bucket",
                service_family="Storage",
                resource_id=f"projects/{project_id}/buckets/{bucket.name}",
                name=bucket.name,
                tags=labels,
                # Listing all objects to sum sizes would be prohibitively
                # slow/expensive at scale (mirrors why AWS S3 gates this
                # behind --include-storage-sizes). Cloud Monitoring likely has
                # a real-usage metric (storage.googleapis.com/storage/total_bytes),
                # but it hasn't been verified against docs/SDK yet, so size_gb
                # stays 0.0/unavailable. See docs/v2-refactor-plan.md.
                size_gb=0.0,
                metadata={
                    'location': bucket.location,
                    'location_type': bucket.location_type,
                    'storage_class': bucket.storage_class,
                    'versioning_enabled': bucket.versioning_enabled,
                    'lifecycle_rules': len(bucket.lifecycle_rules) if bucket.lifecycle_rules else 0,
                    'created': bucket.time_created.isoformat() if bucket.time_created else '',
                    'size_source': 'unavailable',
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Cloud Storage buckets")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Cloud Storage buckets", "gcp")
        logger.error(f"Failed to collect Cloud Storage buckets: {e}")

    return resources


def collect_filestore_instances(project_id: str) -> List[CloudResource]:
    """
    Collect Filestore instances.

    Args:
        project_id: GCP project ID

    Returns:
        List of CloudResource objects for Filestore instances
    """
    resources = []
    try:
        from google.cloud import filestore_v1

        client = filestore_v1.CloudFilestoreManagerClient()

        # List instances in all locations
        parent = f"projects/{project_id}/locations/-"

        for instance in client.list_instances(parent=parent):
            labels = dict(instance.labels) if instance.labels else {}

            # capacity_gb per file share is the provisioned/configured share
            # size, not actual data used. Cloud Monitoring likely has a
            # real-usage metric (e.g. file.googleapis.com/nfs/server/used_bytes),
            # but it hasn't been verified against docs/SDK yet, so size_gb
            # stays 0.0/unavailable. See docs/v2-refactor-plan.md.
            total_capacity_gb = 0
            if instance.file_shares:
                for share in instance.file_shares:
                    total_capacity_gb += share.capacity_gb or 0

            # Extract location
            location = extract_location_from_name(instance.name)

            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region=location,
                resource_type="gcp:filestore:instance",
                service_family="Filestore",
                resource_id=instance.name,
                name=instance.name.split('/')[-1],
                tags=labels,
                size_gb=0.0,
                metadata={
                    'state': instance.state.name if instance.state else '',
                    'tier': instance.tier.name if instance.tier else '',
                    'file_shares': [{'name': s.name, 'capacity_gb': s.capacity_gb} for s in instance.file_shares] if instance.file_shares else [],
                    'networks': [n.network for n in instance.networks] if instance.networks else [],
                    'provisioned_storage_gb': float(total_capacity_gb),
                    'size_source': 'unavailable',
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Filestore instances")
    except ImportError:
        logger.warning("Filestore client not available")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Filestore instances", "gcp")
        logger.error(f"Failed to collect Filestore instances: {e}")

    return resources
