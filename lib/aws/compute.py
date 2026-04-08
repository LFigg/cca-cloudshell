"""
AWS compute resource collection.

Collects EC2 instances, EBS volumes, EBS snapshots, and Lambda functions.
"""
import logging
from typing import List

import boto3

from lib.constants import BYTES_PER_GB
from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error, get_name_from_tags, tags_to_dict

logger = logging.getLogger(__name__)


def collect_ec2_instances(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect EC2 instances."""
    resources = []
    try:
        ec2 = session.client('ec2', region_name=region)
        paginator = ec2.get_paginator('describe_instances')

        for page in paginator.paginate():
            for reservation in page.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    tags = tags_to_dict(instance.get('Tags', []))

                    # Get attached volumes
                    attached_volumes = [
                        d.get('Ebs', {}).get('VolumeId', '')
                        for d in instance.get('BlockDeviceMappings', [])
                        if d.get('Ebs', {}).get('VolumeId')
                    ]

                    instance_id = instance.get('InstanceId', '')
                    resource = CloudResource(
                        provider="aws",
                        account_id=account_id,
                        region=region,
                        resource_type="aws:ec2:instance",
                        service_family="EC2",
                        resource_id=instance_id,
                        name=get_name_from_tags(tags, instance_id),
                        tags=tags,
                        size_gb=0.0,
                        metadata={
                            'instance_type': instance.get('InstanceType'),
                            'state': instance.get('State', {}).get('Name'),
                            'platform': instance.get('Platform', 'linux'),
                            'vpc_id': instance.get('VpcId'),
                            'attached_volumes': attached_volumes
                        }
                    )
                    resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} EC2 instances")
    except Exception as e:
        check_and_raise_auth_error(e, "collect EC2 instances", "aws")
        logger.error(f"[{region}] Failed to collect EC2 instances: {e}")

    return resources


def collect_ebs_volumes(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect EBS volumes."""
    resources = []
    try:
        ec2 = session.client('ec2', region_name=region)
        paginator = ec2.get_paginator('describe_volumes')

        for page in paginator.paginate():
            for volume in page['Volumes']:
                tags = tags_to_dict(volume.get('Tags', []))

                attachments = volume.get('Attachments', [])
                attached_instance = attachments[0].get('InstanceId') if attachments else None

                volume_id = volume.get('VolumeId', '')
                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:ec2:volume",
                    service_family="EC2",
                    resource_id=volume_id,
                    name=get_name_from_tags(tags, volume_id),
                    tags=tags,
                    size_gb=float(volume.get('Size', 0)),
                    parent_resource_id=attached_instance,
                    metadata={
                        'volume_type': volume.get('VolumeType'),
                        'state': volume.get('State'),
                        'encrypted': volume.get('Encrypted', False),
                        'attached_instance': attached_instance
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} EBS volumes")
    except Exception as e:
        check_and_raise_auth_error(e, "collect EBS volumes", "aws")
        logger.error(f"[{region}] Failed to collect EBS volumes: {e}")

    return resources


def collect_ebs_snapshots(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect EBS snapshots owned by this account."""
    resources = []
    try:
        ec2 = session.client('ec2', region_name=region)
        paginator = ec2.get_paginator('describe_snapshots')

        # Only get snapshots owned by this account ('self' works for both real AWS and moto)
        for page in paginator.paginate(OwnerIds=['self']):
            for snapshot in page.get('Snapshots', []):
                tags = tags_to_dict(snapshot.get('Tags', []))
                snapshot_id = snapshot.get('SnapshotId', '')

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:ec2:snapshot",
                    service_family="EC2",
                    resource_id=snapshot_id,
                    name=get_name_from_tags(tags, snapshot_id),
                    tags=tags,
                    size_gb=float(snapshot.get('VolumeSize', 0)),
                    parent_resource_id=snapshot.get('VolumeId'),
                    metadata={
                        'volume_id': snapshot.get('VolumeId'),
                        'state': snapshot.get('State'),
                        'encrypted': snapshot.get('Encrypted', False),
                        'start_time': str(snapshot.get('StartTime', '')),
                        'description': snapshot.get('Description', '')
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} EBS snapshots")
    except Exception as e:
        check_and_raise_auth_error(e, "collect EBS snapshots", "aws")
        logger.error(f"[{region}] Failed to collect EBS snapshots: {e}")

    return resources


def collect_lambda_functions(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect Lambda functions."""
    resources = []
    try:
        lambda_client = session.client('lambda', region_name=region)
        paginator = lambda_client.get_paginator('list_functions')

        for page in paginator.paginate():
            for func in page['Functions']:
                code_size_bytes = func.get('CodeSize', 0)
                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:lambda:function",
                    service_family="Lambda",
                    resource_id=func.get('FunctionArn', ''),
                    name=func.get('FunctionName', ''),
                    tags={},
                    size_gb=code_size_bytes / BYTES_PER_GB,  # For jump bag sizing
                    metadata={
                        'runtime': func.get('Runtime'),
                        'memory': func.get('MemorySize'),
                        'timeout': func.get('Timeout'),
                        'code_size': code_size_bytes
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} Lambda functions")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Lambda functions", "aws")
        logger.error(f"[{region}] Failed to collect Lambda functions: {e}")

    return resources
