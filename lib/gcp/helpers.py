# GCP helper utilities
"""Utility functions for GCP resource parsing and extraction."""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def extract_region_from_zone(zone: str) -> str:
    """
    Extract region from a GCP zone name.

    Args:
        zone: Zone name (e.g., 'us-central1-a' or 'zones/us-central1-a')

    Returns:
        Region name (e.g., 'us-central1')
    """
    # Handle full path format
    if '/' in zone:
        zone = zone.split('/')[-1]

    # Region is everything except the last part (zone letter)
    parts = zone.split('-')
    if len(parts) >= 3:
        return '-'.join(parts[:-1])
    return zone


def extract_location_from_name(resource_name: str, index: int = 3) -> str:
    """
    Extract location from a GCP resource name path.

    Args:
        resource_name: Full resource path (e.g., 'projects/my-project/locations/us-central1/...')
        index: Index of the location component (default: 3 for projects/X/locations/Y pattern)

    Returns:
        Location string or 'unknown'
    """
    if '/' in resource_name:
        parts = resource_name.split('/')
        if len(parts) > index:
            return parts[index]
    return 'unknown'


def extract_name_from_path(resource_path: str) -> str:
    """
    Extract the final name component from a GCP resource path.

    Args:
        resource_path: Full resource path (e.g., 'projects/my-project/zones/us-central1-a/instances/my-vm')

    Returns:
        Final name component (e.g., 'my-vm')
    """
    if '/' in resource_path:
        return resource_path.split('/')[-1]
    return resource_path


def extract_machine_type(machine_type_url: Optional[str]) -> str:
    """
    Extract machine type name from a GCP machine type URL.

    Args:
        machine_type_url: Full machine type URL or path

    Returns:
        Machine type name (e.g., 'n1-standard-1')
    """
    if not machine_type_url:
        return ''
    return machine_type_url.split('/')[-1]


def extract_disk_type(disk_type_url: Optional[str]) -> str:
    """
    Extract disk type name from a GCP disk type URL.

    Args:
        disk_type_url: Full disk type URL or path

    Returns:
        Disk type name (e.g., 'pd-standard', 'pd-ssd')
    """
    if not disk_type_url:
        return ''
    return disk_type_url.split('/')[-1]


def bytes_to_gb(bytes_value: Optional[int]) -> float:
    """
    Convert bytes to gigabytes.

    Args:
        bytes_value: Size in bytes

    Returns:
        Size in GB (rounded to 2 decimal places)
    """
    if not bytes_value:
        return 0.0
    return round(bytes_value / (1024 ** 3), 2)
