# GCP authentication and project discovery
"""Authentication and project/region discovery for GCP collectors."""

import logging
from typing import Any, List, Optional, Tuple

logger = logging.getLogger(__name__)


def get_credentials() -> Tuple[Any, Optional[str]]:
    """
    Get GCP credentials and default project.

    Returns:
        Tuple of (credentials, project_id)
    """
    import google.auth
    
    """
    Get GCP credentials and default project.

    Returns:
        Tuple of (credentials, project_id)
    """
    credentials, project = google.auth.default()
    if project:
        logger.info(f"Using default project: {project}")
    else:
        logger.warning("No default project found - specify with --project or set GOOGLE_CLOUD_PROJECT")
    return credentials, project


def get_projects(credentials: Any) -> List[dict]:
    """
    Get list of accessible GCP projects.

    Args:
        credentials: GCP credentials

    Returns:
        List of dicts with 'id' and 'name' keys
    """
    from google.cloud import resourcemanager_v3
    
    projects = []
    try:
        client = resourcemanager_v3.ProjectsClient(credentials=credentials)

        request = resourcemanager_v3.SearchProjectsRequest()

        for project in client.search_projects(request=request):
            if project.state == resourcemanager_v3.Project.State.ACTIVE:
                projects.append({
                    'id': project.project_id,
                    'name': project.display_name or project.project_id
                })

        logger.info(f"Found {len(projects)} accessible projects")
    except Exception as e:
        logger.error(f"Failed to list projects: {e}")
        logger.info("Using default project only")

    return projects


def get_regions(project_id: str) -> List[str]:
    """
    Get list of available GCP regions for a project.

    Args:
        project_id: GCP project ID

    Returns:
        List of region names
    """
    from google.cloud import compute_v1

    regions = []
    try:
        client = compute_v1.RegionsClient()
        for region in client.list(project=project_id):
            regions.append(region.name)
        logger.info(f"Found {len(regions)} regions")
    except Exception as e:
        logger.error(f"Failed to list regions: {e}")
    return regions


def get_zones(project_id: str) -> List[str]:
    """
    Get list of available GCP zones for a project.

    Args:
        project_id: GCP project ID

    Returns:
        List of zone names
    """
    from google.cloud import compute_v1

    zones = []
    try:
        client = compute_v1.ZonesClient()
        for zone in client.list(project=project_id):
            zones.append(zone.name)
        logger.info(f"Found {len(zones)} zones")
    except Exception as e:
        logger.error(f"Failed to list zones: {e}")
    return zones
