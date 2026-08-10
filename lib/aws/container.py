"""
AWS container resource collection.

Collects EKS clusters and node groups.
"""
import logging
from typing import List

import boto3

from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error

logger = logging.getLogger(__name__)


def collect_eks_clusters(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect EKS clusters.

    Args:
        session: boto3 Session with credentials for the target account
        region: AWS region to collect from
        account_id: AWS account ID being collected

    Returns:
        List of CloudResource objects, one per EKS cluster

    Example:
        clusters = collect_eks_clusters(session, "us-east-1", "123456789012")
    """
    resources = []
    try:
        eks = session.client('eks', region_name=region)

        paginator = eks.get_paginator('list_clusters')
        clusters = []
        for page in paginator.paginate():
            clusters.extend(page.get('clusters', []))

        for cluster_name in clusters:
            try:
                cluster = eks.describe_cluster(name=cluster_name)['cluster']

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:eks:cluster",
                    service_family="EKS",
                    resource_id=cluster.get('arn', ''),
                    name=cluster_name,
                    tags=cluster.get('tags', {}),
                    size_gb=0.0,
                    metadata={
                        'status': cluster.get('status'),
                        'version': cluster.get('version'),
                        'endpoint': cluster.get('endpoint'),
                        'size_source': 'not_applicable',
                    }
                )
                resources.append(resource)
            except Exception as e:
                check_and_raise_auth_error(e, f"describe EKS cluster {cluster_name}", "aws")
                logger.warning(f"[{region}] Failed to describe EKS cluster {cluster_name}: {e}")

        logger.info(f"[{region}] Found {len(resources)} EKS clusters")
    except Exception as e:
        check_and_raise_auth_error(e, "collect EKS clusters", "aws")
        logger.error(f"[{region}] Failed to collect EKS clusters: {e}")

    return resources


def collect_eks_nodegroups(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect EKS node groups with instance mapping.

    Args:
        session: boto3 Session with credentials for the target account
        region: AWS region to collect from
        account_id: AWS account ID being collected

    Returns:
        List of CloudResource objects, one per EKS node group
    """
    resources = []
    try:
        eks = session.client('eks', region_name=region)

        cluster_paginator = eks.get_paginator('list_clusters')
        clusters = []
        for page in cluster_paginator.paginate():
            clusters.extend(page.get('clusters', []))

        for cluster_name in clusters:
            try:
                ng_paginator = eks.get_paginator('list_nodegroups')
                nodegroups = []
                for page in ng_paginator.paginate(clusterName=cluster_name):
                    nodegroups.extend(page.get('nodegroups', []))

                for ng_name in nodegroups:
                    try:
                        ng = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)['nodegroup']

                        # Get Auto Scaling group info if available
                        asg_name = ''
                        if ng.get('resources', {}).get('autoScalingGroups'):
                            asg_name = ng['resources']['autoScalingGroups'][0].get('name', '')

                        resource = CloudResource(
                            provider="aws",
                            account_id=account_id,
                            region=region,
                            resource_type="aws:eks:nodegroup",
                            service_family="EKS",
                            resource_id=ng.get('nodegroupArn', ''),
                            name=ng_name,
                            tags=ng.get('tags', {}),
                            size_gb=0.0,
                            parent_resource_id=cluster_name,
                            metadata={
                                'cluster_name': cluster_name,
                                'status': ng.get('status'),
                                'capacity_type': ng.get('capacityType'),
                                'instance_types': ng.get('instanceTypes', []),
                                'scaling_config': ng.get('scalingConfig', {}),
                                'asg_name': asg_name,
                                'size_source': 'not_applicable',
                            }
                        )
                        resources.append(resource)
                    except Exception as e:
                        check_and_raise_auth_error(e, f"describe nodegroup {ng_name}", "aws")
                        logger.warning(f"[{region}] Failed to describe nodegroup {ng_name}: {e}")
            except Exception as e:
                check_and_raise_auth_error(e, f"list nodegroups for cluster {cluster_name}", "aws")
                logger.warning(f"[{region}] Failed to list nodegroups for cluster {cluster_name}: {e}")

        logger.info(f"[{region}] Found {len(resources)} EKS node groups")
    except Exception as e:
        check_and_raise_auth_error(e, "collect EKS node groups", "aws")
        logger.error(f"[{region}] Failed to collect EKS node groups: {e}")

    return resources
