"""Azure helper functions."""
from typing import Optional


def extract_resource_group(resource_id: str) -> str:
    """Extract resource group from Azure resource ID.

    Args:
        resource_id: Full Azure resource ID (e.g. "/subscriptions/.../resourceGroups/rg1/...")

    Returns:
        Resource group name, or 'unknown' if it could not be parsed
    """
    try:
        parts = resource_id.split('/')
        # Azure APIs may return 'resourceGroups' or 'resourcegroups' - check case-insensitively
        lower_parts = [p.lower() for p in parts]
        rg_index = lower_parts.index('resourcegroups') + 1
        return parts[rg_index]
    except (ValueError, IndexError):
        return 'unknown'


def normalize_region(location: Optional[str]) -> str:
    """Normalize an Azure location to its canonical short ID.

    Azure SDK calls return location either as canonical ID ("eastus") or as
    display name ("East US"). Treat them as the same region.

    Args:
        location: Azure location value, canonical ID or display name

    Returns:
        Lowercased, whitespace-stripped region string, or '' if location is falsy
    """
    if not location:
        return ''
    return ''.join(str(location).lower().split())
