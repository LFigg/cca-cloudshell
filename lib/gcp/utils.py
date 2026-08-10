"""Shared GCP utility helpers."""


def extract_location_from_name(name: str, fallback: str = "unknown") -> str:
    """Extract the GCP location from a fully-qualified resource name.

    GCP resource names follow the pattern:
        projects/{project}/locations/{location}/...

    Args:
        name: Fully-qualified GCP resource name
        fallback: Value to return if the name doesn't have enough segments

    Returns:
        The location segment of the name, or fallback if it's missing.
    """
    parts = name.split('/')
    if len(parts) > 3:
        return parts[3]
    return fallback
