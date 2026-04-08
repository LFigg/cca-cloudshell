"""Azure container resource collection (AKS, Function Apps)."""
import logging
from typing import List

from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error
from lib.azure.helpers import extract_resource_group

logger = logging.getLogger(__name__)


def collect_aks_clusters(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Kubernetes Service clusters."""
    from azure.mgmt.containerservice import ContainerServiceClient
    
    resources = []
    try:
        aks_client = ContainerServiceClient(credential, subscription_id)

        for cluster in aks_client.managed_clusters.list():
            if not cluster.id:
                continue

            rg = extract_resource_group(cluster.id)

            # Count nodes
            node_count = 0
            if cluster.agent_pool_profiles:
                node_count = sum(p.count or 0 for p in cluster.agent_pool_profiles)

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=cluster.location,
                resource_type="azure:aks:cluster",
                service_family="AKS",
                resource_id=cluster.id,
                name=cluster.name,
                tags=cluster.tags or {},
                size_gb=0.0,
                metadata={
                    'resource_group': rg,
                    'kubernetes_version': cluster.kubernetes_version,
                    'provisioning_state': cluster.provisioning_state,
                    'node_count': node_count,
                    'dns_prefix': cluster.dns_prefix
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} AKS clusters")
    except Exception as e:
        check_and_raise_auth_error(e, "collect AKS clusters", "azure")
        logger.error(f"Failed to collect AKS clusters: {e}")

    return resources


def collect_function_apps(credential, subscription_id: str) -> List[CloudResource]:
    """Collect Azure Function Apps."""
    from azure.mgmt.web import WebSiteManagementClient
    
    resources = []
    try:
        web_client = WebSiteManagementClient(credential, subscription_id)

        for app in web_client.web_apps.list():
            if not app.id or not app.kind or 'functionapp' not in app.kind.lower():
                continue

            rg = extract_resource_group(app.id)

            resource = CloudResource(
                provider="azure",
                subscription_id=subscription_id,
                region=app.location,
                resource_type="azure:function:app",
                service_family="AzureFunctions",
                resource_id=app.id,
                name=app.name,
                tags=app.tags or {},
                size_gb=0.0,
                metadata={
                    'resource_group': rg,
                    'kind': app.kind,
                    'state': app.state,
                    'default_host_name': app.default_host_name
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Azure Function Apps")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Function Apps", "azure")
        logger.error(f"Failed to collect Function Apps: {e}")

    return resources
