# GCP Container and Serverless collectors
"""Collectors for GKE clusters and Cloud Functions."""

import logging
from typing import List

from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error

logger = logging.getLogger(__name__)


def collect_gke_clusters(project_id: str) -> List[CloudResource]:
    """
    Collect GKE clusters.

    Args:
        project_id: GCP project ID

    Returns:
        List of CloudResource objects for GKE clusters
    """
    resources = []
    try:
        from google.cloud import container_v1

        client = container_v1.ClusterManagerClient()

        # List clusters in all locations
        parent = f"projects/{project_id}/locations/-"

        response = client.list_clusters(parent=parent)

        for cluster in response.clusters:
            labels = dict(cluster.resource_labels) if cluster.resource_labels else {}

            # Count total nodes
            total_nodes = 0
            node_pools = []
            if cluster.node_pools:
                for pool in cluster.node_pools:
                    node_pools.append(pool.name)
                    total_nodes += pool.initial_node_count or 0

            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region=cluster.location,
                resource_type="gcp:container:cluster",
                service_family="GKE",
                resource_id=f"projects/{project_id}/locations/{cluster.location}/clusters/{cluster.name}",
                name=cluster.name,
                tags=labels,
                size_gb=0.0,
                metadata={
                    'status': cluster.status.name if cluster.status else '',
                    'current_master_version': cluster.current_master_version,
                    'current_node_version': cluster.current_node_version,
                    'node_pools': node_pools,
                    'total_nodes': total_nodes,
                    'network': cluster.network,
                    'subnetwork': cluster.subnetwork,
                    'endpoint': cluster.endpoint,
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} GKE clusters")
    except ImportError:
        logger.warning("GKE client not available")
    except Exception as e:
        check_and_raise_auth_error(e, "collect GKE clusters", "gcp")
        logger.error(f"Failed to collect GKE clusters: {e}")

    return resources


def collect_cloud_functions(project_id: str) -> List[CloudResource]:
    """
    Collect Cloud Functions.

    Args:
        project_id: GCP project ID

    Returns:
        List of CloudResource objects for Cloud Functions
    """
    resources = []
    try:
        from google.cloud import functions_v2

        client = functions_v2.FunctionServiceClient()

        # List functions in all locations
        parent = f"projects/{project_id}/locations/-"

        for function in client.list_functions(parent=parent):
            labels = dict(function.labels) if function.labels else {}

            # Extract location from name
            location = function.name.split('/')[3] if '/' in function.name else 'unknown'

            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region=location,
                resource_type="gcp:functions:function",
                service_family="Functions",
                resource_id=function.name,
                name=function.name.split('/')[-1],
                tags=labels,
                size_gb=0.0,
                metadata={
                    'state': function.state.name if function.state else '',
                    'runtime': function.build_config.runtime if function.build_config else '',
                    'entry_point': function.build_config.entry_point if function.build_config else '',
                    'available_memory': function.service_config.available_memory if function.service_config else '',
                    'timeout_seconds': function.service_config.timeout_seconds if function.service_config else 0,
                    'environment': function.environment.name if function.environment else '',
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Cloud Functions")
    except ImportError:
        logger.warning("Cloud Functions client not available")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Cloud Functions", "gcp")
        logger.error(f"Failed to collect Cloud Functions: {e}")

    return resources
