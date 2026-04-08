"""Azure helper functions."""


def extract_resource_group(resource_id: str) -> str:
    """Extract resource group from Azure resource ID."""
    try:
        parts = resource_id.split('/')
        # Azure APIs may return 'resourceGroups' or 'resourcegroups' - check case-insensitively
        lower_parts = [p.lower() for p in parts]
        rg_index = lower_parts.index('resourcegroups') + 1
        return parts[rg_index]
    except (ValueError, IndexError):
        return 'unknown'
