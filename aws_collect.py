#!/usr/bin/env python3
"""
CCA CloudShell - AWS Resource Collector

Collects AWS resources for cloud protection assessment.
Optimized for AWS CloudShell with minimal dependencies.
Supports single-account and multi-account collection.

Usage:
    # Single account (current credentials)
    python3 aws_collect.py
    python3 aws_collect.py --regions us-east-1,us-west-2
    python3 aws_collect.py --output s3://my-bucket/assessments/
    
    # Multi-account via role assumption
    python3 aws_collect.py --role-arn arn:aws:iam::123456789012:role/CCARole
    python3 aws_collect.py --role-arns arn:aws:iam::111:role/CCA,arn:aws:iam::222:role/CCA
    
    # Multi-account via AWS Organizations discovery
    python3 aws_collect.py --org-role CCARole
    python3 aws_collect.py --org-role CCARole --external-id MySecretId
"""
import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

# boto3 is pre-installed in AWS CloudShell
import boto3
from botocore.exceptions import ClientError

# Add lib to path for imports
sys.path.insert(0, '.')
from lib.models import CloudResource, aggregate_sizing
from lib.utils import (
    generate_run_id, get_timestamp, format_bytes_to_gb, tags_to_dict,
    get_name_from_tags, write_json, write_csv, setup_logging, print_summary_table
)

logger = logging.getLogger(__name__)


# =============================================================================
# Session Management
# =============================================================================

def get_session(profile: Optional[str] = None, region: Optional[str] = None) -> boto3.Session:
    """Create boto3 session. In CloudShell, credentials are automatic."""
    return boto3.Session(profile_name=profile, region_name=region)


def get_account_id(session: boto3.Session) -> str:
    """Get AWS account ID."""
    sts = session.client('sts')
    return sts.get_caller_identity()['Account']


def get_enabled_regions(session: boto3.Session) -> List[str]:
    """Get list of enabled regions."""
    ec2 = session.client('ec2', region_name='us-east-1')
    response = ec2.describe_regions(AllRegions=False)
    return sorted([r.get('RegionName', '') for r in response.get('Regions', []) if r.get('RegionName')])


def assume_role(
    session: boto3.Session,
    role_arn: str,
    external_id: Optional[str] = None,
    session_name: str = "CCACloudShell"
) -> boto3.Session:
    """
    Assume an IAM role and return a new session with temporary credentials.
    
    Args:
        session: Source boto3 session for making the AssumeRole call
        role_arn: ARN of the role to assume (e.g., arn:aws:iam::123456789012:role/CCARole)
        external_id: Optional external ID for additional security
        session_name: Session name for CloudTrail auditing
    
    Returns:
        New boto3 Session with assumed role credentials
    """
    sts = session.client('sts')
    
    assume_params = {
        'RoleArn': role_arn,
        'RoleSessionName': session_name,
        'DurationSeconds': 3600  # 1 hour
    }
    
    if external_id:
        assume_params['ExternalId'] = external_id
    
    try:
        response = sts.assume_role(**assume_params)
        credentials = response['Credentials']
        
        return boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
    except ClientError as e:
        logger.error(f"Failed to assume role {role_arn}: {e}")
        raise


def discover_org_accounts(session: boto3.Session, include_suspended: bool = False) -> List[Dict[str, str]]:
    """
    Discover all accounts in the AWS Organization.
    
    Requires organizations:ListAccounts permission.
    
    Args:
        session: boto3 session (must have Organizations access)
        include_suspended: Whether to include suspended accounts
    
    Returns:
        List of dicts with 'id', 'name', 'email', 'status' for each account
    """
    accounts = []
    try:
        org = session.client('organizations')
        paginator = org.get_paginator('list_accounts')
        
        for page in paginator.paginate():
            for account in page.get('Accounts', []):
                status = account.get('Status', 'UNKNOWN')
                if status == 'ACTIVE' or (include_suspended and status == 'SUSPENDED'):
                    accounts.append({
                        'id': account.get('Id', ''),
                        'name': account.get('Name', ''),
                        'email': account.get('Email', ''),
                        'status': status
                    })
        
        logger.info(f"Discovered {len(accounts)} accounts in organization")
        return accounts
    
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code == 'AWSOrganizationsNotInUseException':
            logger.warning("AWS Organizations is not enabled for this account")
        elif error_code == 'AccessDeniedException':
            logger.error("Access denied to Organizations API. Need organizations:ListAccounts permission.")
        else:
            logger.error(f"Failed to list organization accounts: {e}")
        return []


def collect_account(
    session: boto3.Session,
    account_id: str,
    regions: Optional[List[str]] = None
) -> List[CloudResource]:
    """
    Collect all resources from a single AWS account.
    
    Args:
        session: boto3 session with credentials for this account
        account_id: AWS account ID
        regions: List of regions to collect from (None = all enabled)
    
    Returns:
        List of CloudResource objects
    """
    resources = []
    
    # Get regions if not specified
    if regions is None:
        regions = get_enabled_regions(session)
    
    logger.info(f"Collecting from account {account_id} across {len(regions)} regions")
    
    # S3 is global
    resources.extend(collect_s3_buckets(session, account_id))
    
    # Regional resources
    for region in regions:
        resources.extend(collect_region(session, region, account_id))
    
    logger.info(f"Collected {len(resources)} resources from account {account_id}")
    return resources


# =============================================================================
# EC2 Collectors
# =============================================================================

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
        logger.error(f"[{region}] Failed to collect EBS snapshots: {e}")
    
    return resources


# =============================================================================
# RDS Collectors
# =============================================================================

def collect_rds_instances(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect RDS database instances."""
    resources = []
    try:
        rds = session.client('rds', region_name=region)
        paginator = rds.get_paginator('describe_db_instances')
        
        for page in paginator.paginate():
            for db in page['DBInstances']:
                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:rds:instance",
                    service_family="RDS",
                    resource_id=db.get('DBInstanceArn', ''),
                    name=db.get('DBInstanceIdentifier', ''),
                    tags={},
                    size_gb=float(db.get('AllocatedStorage', 0)),
                    metadata={
                        'engine': db.get('Engine'),
                        'engine_version': db.get('EngineVersion'),
                        'instance_class': db.get('DBInstanceClass'),
                        'status': db.get('DBInstanceStatus'),
                        'multi_az': db.get('MultiAZ', False),
                        'encrypted': db.get('StorageEncrypted', False)
                    }
                )
                resources.append(resource)
        
        logger.info(f"[{region}] Found {len(resources)} RDS instances")
    except Exception as e:
        logger.error(f"[{region}] Failed to collect RDS instances: {e}")
    
    return resources


def collect_rds_clusters(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect RDS Aurora clusters."""
    resources = []
    try:
        rds = session.client('rds', region_name=region)
        paginator = rds.get_paginator('describe_db_clusters')
        
        for page in paginator.paginate():
            for cluster in page['DBClusters']:
                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:rds:cluster",
                    service_family="RDS",
                    resource_id=cluster.get('DBClusterArn', ''),
                    name=cluster.get('DBClusterIdentifier', ''),
                    tags={},
                    size_gb=float(cluster.get('AllocatedStorage', 0)),
                    metadata={
                        'engine': cluster.get('Engine'),
                        'engine_version': cluster.get('EngineVersion'),
                        'status': cluster.get('Status'),
                        'multi_az': cluster.get('MultiAZ', False),
                        'encrypted': cluster.get('StorageEncrypted', False)
                    }
                )
                resources.append(resource)
        
        logger.info(f"[{region}] Found {len(resources)} RDS clusters")
    except Exception as e:
        logger.error(f"[{region}] Failed to collect RDS clusters: {e}")
    
    return resources


def collect_rds_snapshots(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect RDS DB snapshots."""
    resources = []
    try:
        rds = session.client('rds', region_name=region)
        paginator = rds.get_paginator('describe_db_snapshots')
        
        for page in paginator.paginate():
            for snapshot in page.get('DBSnapshots', []):
                snapshot_id = snapshot.get('DBSnapshotIdentifier', '')
                
                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:rds:snapshot",
                    service_family="RDS",
                    resource_id=snapshot.get('DBSnapshotArn', ''),
                    name=snapshot_id,
                    tags={},
                    size_gb=float(snapshot.get('AllocatedStorage', 0)),
                    parent_resource_id=snapshot.get('DBInstanceIdentifier'),
                    metadata={
                        'db_instance_id': snapshot.get('DBInstanceIdentifier'),
                        'engine': snapshot.get('Engine'),
                        'status': snapshot.get('Status'),
                        'snapshot_type': snapshot.get('SnapshotType'),
                        'encrypted': snapshot.get('Encrypted', False),
                        'snapshot_create_time': str(snapshot.get('SnapshotCreateTime', ''))
                    }
                )
                resources.append(resource)
        
        logger.info(f"[{region}] Found {len(resources)} RDS snapshots")
    except Exception as e:
        logger.error(f"[{region}] Failed to collect RDS snapshots: {e}")
    
    return resources


def collect_rds_cluster_snapshots(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect RDS Aurora cluster snapshots."""
    resources = []
    try:
        rds = session.client('rds', region_name=region)
        paginator = rds.get_paginator('describe_db_cluster_snapshots')
        
        for page in paginator.paginate():
            for snapshot in page.get('DBClusterSnapshots', []):
                snapshot_id = snapshot.get('DBClusterSnapshotIdentifier', '')
                
                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:rds:cluster-snapshot",
                    service_family="RDS",
                    resource_id=snapshot.get('DBClusterSnapshotArn', ''),
                    name=snapshot_id,
                    tags={},
                    size_gb=float(snapshot.get('AllocatedStorage', 0)),
                    parent_resource_id=snapshot.get('DBClusterIdentifier'),
                    metadata={
                        'db_cluster_id': snapshot.get('DBClusterIdentifier'),
                        'engine': snapshot.get('Engine'),
                        'status': snapshot.get('Status'),
                        'snapshot_type': snapshot.get('SnapshotType'),
                        'encrypted': snapshot.get('StorageEncrypted', False),
                        'snapshot_create_time': str(snapshot.get('SnapshotCreateTime', ''))
                    }
                )
                resources.append(resource)
        
        logger.info(f"[{region}] Found {len(resources)} RDS cluster snapshots")
    except Exception as e:
        logger.error(f"[{region}] Failed to collect RDS cluster snapshots: {e}")
    
    return resources


# =============================================================================
# S3 Collector
# =============================================================================

def collect_s3_buckets(session: boto3.Session, account_id: str) -> List[CloudResource]:
    """Collect S3 buckets (global service)."""
    resources = []
    try:
        s3 = session.client('s3')
        response = s3.list_buckets()
        
        for bucket in response.get('Buckets', []):
            bucket_name = bucket.get('Name', '')
            if not bucket_name:
                continue
            
            # Get bucket region
            try:
                location = s3.get_bucket_location(Bucket=bucket_name)
                region = location.get('LocationConstraint') or 'us-east-1'
            except ClientError:
                region = 'unknown'
            
            # Get bucket tags
            tags = {}
            try:
                tag_response = s3.get_bucket_tagging(Bucket=bucket_name)
                for tag in tag_response.get('TagSet', []):
                    tags[tag['Key']] = tag['Value']
            except ClientError:
                pass
            
            resource = CloudResource(
                provider="aws",
                account_id=account_id,
                region=region,
                resource_type="aws:s3:bucket",
                service_family="S3",
                resource_id=f"arn:aws:s3:::{bucket_name}",
                name=bucket_name,
                tags=tags,
                size_gb=0.0,  # S3 size requires CloudWatch metrics
                metadata={
                    'creation_date': str(bucket.get('CreationDate', '')),
                    'size_note': 'Use CloudWatch metrics for accurate size'
                }
            )
            resources.append(resource)
        
        logger.info(f"Found {len(resources)} S3 buckets")
    except Exception as e:
        logger.error(f"Failed to collect S3 buckets: {e}")
    
    return resources


# =============================================================================
# EFS Collector
# =============================================================================

def collect_efs_filesystems(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect EFS file systems."""
    resources = []
    try:
        efs = session.client('efs', region_name=region)
        paginator = efs.get_paginator('describe_file_systems')
        
        for page in paginator.paginate():
            for fs in page['FileSystems']:
                tags = {t['Key']: t['Value'] for t in fs.get('Tags', [])}
                
                # Size is in bytes
                size_bytes = fs.get('SizeInBytes', {}).get('Value', 0)
                
                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:efs:filesystem",
                    service_family="EFS",
                    resource_id=fs['FileSystemId'],
                    name=tags.get('Name', fs['FileSystemId']),
                    tags=tags,
                    size_gb=format_bytes_to_gb(size_bytes),
                    metadata={
                        'lifecycle_state': fs.get('LifeCycleState'),
                        'performance_mode': fs.get('PerformanceMode'),
                        'encrypted': fs.get('Encrypted', False)
                    }
                )
                resources.append(resource)
        
        logger.info(f"[{region}] Found {len(resources)} EFS file systems")
    except Exception as e:
        logger.error(f"[{region}] Failed to collect EFS: {e}")
    
    return resources


# =============================================================================
# EKS Collector
# =============================================================================

def collect_eks_clusters(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect EKS clusters."""
    resources = []
    try:
        eks = session.client('eks', region_name=region)
        
        clusters = eks.list_clusters().get('clusters', [])
        
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
                        'endpoint': cluster.get('endpoint')
                    }
                )
                resources.append(resource)
            except Exception as e:
                logger.warning(f"[{region}] Failed to describe EKS cluster {cluster_name}: {e}")
        
        logger.info(f"[{region}] Found {len(resources)} EKS clusters")
    except Exception as e:
        logger.error(f"[{region}] Failed to collect EKS clusters: {e}")
    
    return resources


def collect_eks_nodegroups(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect EKS node groups with instance mapping."""
    resources = []
    try:
        eks = session.client('eks', region_name=region)
        
        clusters = eks.list_clusters().get('clusters', [])
        
        for cluster_name in clusters:
            try:
                nodegroups = eks.list_nodegroups(clusterName=cluster_name).get('nodegroups', [])
                
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
                            }
                        )
                        resources.append(resource)
                    except Exception as e:
                        logger.warning(f"[{region}] Failed to describe nodegroup {ng_name}: {e}")
            except Exception as e:
                logger.warning(f"[{region}] Failed to list nodegroups for cluster {cluster_name}: {e}")
        
        logger.info(f"[{region}] Found {len(resources)} EKS node groups")
    except Exception as e:
        logger.error(f"[{region}] Failed to collect EKS node groups: {e}")
    
    return resources


# =============================================================================
# Lambda Collector
# =============================================================================

def collect_lambda_functions(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect Lambda functions."""
    resources = []
    try:
        lambda_client = session.client('lambda', region_name=region)
        paginator = lambda_client.get_paginator('list_functions')
        
        for page in paginator.paginate():
            for func in page['Functions']:
                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:lambda:function",
                    service_family="Lambda",
                    resource_id=func.get('FunctionArn', ''),
                    name=func.get('FunctionName', ''),
                    tags={},
                    size_gb=0.0,
                    metadata={
                        'runtime': func.get('Runtime'),
                        'memory': func.get('MemorySize'),
                        'timeout': func.get('Timeout'),
                        'code_size': func.get('CodeSize', 0)
                    }
                )
                resources.append(resource)
        
        logger.info(f"[{region}] Found {len(resources)} Lambda functions")
    except Exception as e:
        logger.error(f"[{region}] Failed to collect Lambda functions: {e}")
    
    return resources


# =============================================================================
# DynamoDB Collector
# =============================================================================

def collect_dynamodb_tables(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect DynamoDB tables."""
    resources = []
    try:
        dynamodb = session.client('dynamodb', region_name=region)
        paginator = dynamodb.get_paginator('list_tables')
        
        for page in paginator.paginate():
            for table_name in page['TableNames']:
                try:
                    table = dynamodb.describe_table(TableName=table_name)['Table']
                    
                    # Size in bytes
                    size_bytes = table.get('TableSizeBytes', 0)
                    
                    resource = CloudResource(
                        provider="aws",
                        account_id=account_id,
                        region=region,
                        resource_type="aws:dynamodb:table",
                        service_family="DynamoDB",
                        resource_id=table.get('TableArn', ''),
                        name=table_name,
                        tags={},
                        size_gb=format_bytes_to_gb(size_bytes),
                        metadata={
                            'status': table.get('TableStatus'),
                            'item_count': table.get('ItemCount', 0),
                            'billing_mode': table.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED')
                        }
                    )
                    resources.append(resource)
                except Exception as e:
                    logger.warning(f"[{region}] Failed to describe DynamoDB table {table_name}: {e}")
        
        logger.info(f"[{region}] Found {len(resources)} DynamoDB tables")
    except Exception as e:
        logger.error(f"[{region}] Failed to collect DynamoDB tables: {e}")
    
    return resources


# =============================================================================
# FSx Collector
# =============================================================================

def collect_fsx_filesystems(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect FSx file systems."""
    resources = []
    try:
        fsx = session.client('fsx', region_name=region)
        paginator = fsx.get_paginator('describe_file_systems')
        
        for page in paginator.paginate():
            for fs in page['FileSystems']:
                tags = {t['Key']: t['Value'] for t in fs.get('Tags', [])}
                
                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:fsx:filesystem",
                    service_family="FSx",
                    resource_id=fs['FileSystemId'],
                    name=tags.get('Name', fs['FileSystemId']),
                    tags=tags,
                    size_gb=float(fs.get('StorageCapacity', 0)),
                    metadata={
                        'filesystem_type': fs.get('FileSystemType'),
                        'lifecycle': fs.get('Lifecycle'),
                        'storage_type': fs.get('StorageType')
                    }
                )
                resources.append(resource)
        
        logger.info(f"[{region}] Found {len(resources)} FSx file systems")
    except Exception as e:
        logger.error(f"[{region}] Failed to collect FSx: {e}")
    
    return resources


# =============================================================================
# ElastiCache Collector
# =============================================================================

def collect_elasticache_clusters(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect ElastiCache clusters."""
    resources = []
    try:
        elasticache = session.client('elasticache', region_name=region)
        paginator = elasticache.get_paginator('describe_cache_clusters')
        
        for page in paginator.paginate(ShowCacheNodeInfo=True):
            for cluster in page['CacheClusters']:
                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:elasticache:cluster",
                    service_family="ElastiCache",
                    resource_id=cluster.get('ARN', cluster['CacheClusterId']),
                    name=cluster['CacheClusterId'],
                    tags={},
                    size_gb=0.0,
                    metadata={
                        'engine': cluster.get('Engine'),
                        'engine_version': cluster.get('EngineVersion'),
                        'node_type': cluster.get('CacheNodeType'),
                        'num_nodes': cluster.get('NumCacheNodes', 0),
                        'status': cluster.get('CacheClusterStatus')
                    }
                )
                resources.append(resource)
        
        logger.info(f"[{region}] Found {len(resources)} ElastiCache clusters")
    except Exception as e:
        logger.error(f"[{region}] Failed to collect ElastiCache: {e}")
    
    return resources


# =============================================================================
# AWS Backup Collectors
# =============================================================================

def collect_backup_vaults(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect AWS Backup vaults."""
    resources = []
    try:
        backup = session.client('backup', region_name=region)
        paginator = backup.get_paginator('list_backup_vaults')
        
        for page in paginator.paginate():
            for vault in page.get('BackupVaultList', []):
                vault_name = vault.get('BackupVaultName', '')
                
                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:backup:vault",
                    service_family="Backup",
                    resource_id=vault.get('BackupVaultArn', ''),
                    name=vault_name,
                    tags={},
                    size_gb=0.0,  # Size is in recovery points
                    metadata={
                        'number_of_recovery_points': vault.get('NumberOfRecoveryPoints', 0),
                        'encryption_key_arn': vault.get('EncryptionKeyArn'),
                        'creation_date': str(vault.get('CreationDate', '')),
                        'locked': vault.get('Locked', False)
                    }
                )
                resources.append(resource)
        
        logger.info(f"[{region}] Found {len(resources)} Backup vaults")
    except Exception as e:
        logger.error(f"[{region}] Failed to collect Backup vaults: {e}")
    
    return resources


def collect_backup_recovery_points(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect AWS Backup recovery points (actual backups) with sizes."""
    resources = []
    try:
        backup = session.client('backup', region_name=region)
        
        # First, get all vaults
        vaults_paginator = backup.get_paginator('list_backup_vaults')
        vault_names = []
        for page in vaults_paginator.paginate():
            for vault in page.get('BackupVaultList', []):
                vault_names.append(vault.get('BackupVaultName', ''))
        
        # Then get recovery points from each vault
        for vault_name in vault_names:
            try:
                rp_paginator = backup.get_paginator('list_recovery_points_by_backup_vault')
                for page in rp_paginator.paginate(BackupVaultName=vault_name):
                    for rp in page.get('RecoveryPoints', []):
                        # Size in bytes, convert to GB
                        size_bytes = rp.get('BackupSizeInBytes', 0) or 0
                        size_gb = size_bytes / (1024 ** 3)
                        
                        resource = CloudResource(
                            provider="aws",
                            account_id=account_id,
                            region=region,
                            resource_type="aws:backup:recovery-point",
                            service_family="Backup",
                            resource_id=rp.get('RecoveryPointArn', ''),
                            name=rp.get('RecoveryPointArn', '').split(':')[-1] if rp.get('RecoveryPointArn') else '',
                            tags={},
                            size_gb=round(size_gb, 2),
                            parent_resource_id=rp.get('ResourceArn'),  # The backed-up resource
                            metadata={
                                'resource_type': rp.get('ResourceType'),  # EC2, EBS, RDS, etc.
                                'resource_arn': rp.get('ResourceArn'),
                                'backup_vault_name': vault_name,
                                'status': rp.get('Status'),
                                'creation_date': str(rp.get('CreationDate', '')),
                                'completion_date': str(rp.get('CompletionDate', '')),
                                'lifecycle_delete_after_days': rp.get('Lifecycle', {}).get('DeleteAfterDays'),
                                'lifecycle_move_to_cold_after_days': rp.get('Lifecycle', {}).get('MoveToColdStorageAfterDays'),
                                'is_encrypted': rp.get('IsEncrypted', False),
                                'backup_size_bytes': size_bytes
                            }
                        )
                        resources.append(resource)
            except Exception as e:
                logger.warning(f"[{region}] Failed to collect recovery points from vault {vault_name}: {e}")
        
        logger.info(f"[{region}] Found {len(resources)} Backup recovery points")
    except Exception as e:
        logger.error(f"[{region}] Failed to collect Backup recovery points: {e}")
    
    return resources


def collect_backup_plans(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect AWS Backup plans."""
    resources = []
    try:
        backup = session.client('backup', region_name=region)
        paginator = backup.get_paginator('list_backup_plans')
        
        for page in paginator.paginate():
            for plan in page.get('BackupPlansList', []):
                plan_id = plan.get('BackupPlanId', '')
                
                # Get plan details for rules
                try:
                    plan_details = backup.get_backup_plan(BackupPlanId=plan_id)
                    backup_plan = plan_details.get('BackupPlan', {})
                    rules = backup_plan.get('Rules', [])
                    rule_names = [r.get('RuleName', '') for r in rules]
                    
                    # Extract rule details
                    rule_details = []
                    for rule in rules:
                        lifecycle = rule.get('Lifecycle', {})
                        rule_details.append({
                            'rule_name': rule.get('RuleName'),
                            'target_vault': rule.get('TargetBackupVaultName'),
                            'schedule': rule.get('ScheduleExpression'),
                            'start_window_minutes': rule.get('StartWindowMinutes'),
                            'completion_window_minutes': rule.get('CompletionWindowMinutes'),
                            'delete_after_days': lifecycle.get('DeleteAfterDays'),
                            'move_to_cold_after_days': lifecycle.get('MoveToColdStorageAfterDays')
                        })
                except Exception:
                    rules = []
                    rule_names = []
                    rule_details = []
                
                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:backup:plan",
                    service_family="Backup",
                    resource_id=plan.get('BackupPlanArn', ''),
                    name=plan.get('BackupPlanName', ''),
                    tags={},
                    size_gb=0.0,
                    metadata={
                        'backup_plan_id': plan_id,
                        'version_id': plan.get('VersionId'),
                        'creation_date': str(plan.get('CreationDate', '')),
                        'last_execution_date': str(plan.get('LastExecutionDate', '')) if plan.get('LastExecutionDate') else None,
                        'number_of_rules': len(rules),
                        'rule_names': rule_names,
                        'rules': rule_details
                    }
                )
                resources.append(resource)
        
        logger.info(f"[{region}] Found {len(resources)} Backup plans")
    except Exception as e:
        logger.error(f"[{region}] Failed to collect Backup plans: {e}")
    
    return resources


def collect_backup_selections(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect AWS Backup selections (resources assigned to backup plans)."""
    resources = []
    try:
        backup = session.client('backup', region_name=region)
        
        # First get all backup plans
        plans_paginator = backup.get_paginator('list_backup_plans')
        
        for plans_page in plans_paginator.paginate():
            for plan in plans_page.get('BackupPlansList', []):
                plan_id = plan.get('BackupPlanId', '')
                plan_name = plan.get('BackupPlanName', '')
                plan_arn = plan.get('BackupPlanArn', '')
                
                # Get selections for this plan
                try:
                    selections_paginator = backup.get_paginator('list_backup_selections')
                    for sel_page in selections_paginator.paginate(BackupPlanId=plan_id):
                        for selection in sel_page.get('BackupSelectionsList', []):
                            selection_id = selection.get('SelectionId', '')
                            
                            # Get full selection details
                            try:
                                sel_details = backup.get_backup_selection(
                                    BackupPlanId=plan_id,
                                    SelectionId=selection_id
                                )
                                sel_data = sel_details.get('BackupSelection', {})
                                
                                # Extract resource ARNs and conditions
                                resource_arns = sel_data.get('Resources', [])
                                conditions = sel_data.get('Conditions', {})
                                list_of_tags = sel_data.get('ListOfTags', [])
                                not_resources = sel_data.get('NotResources', [])
                                
                                resource = CloudResource(
                                    provider="aws",
                                    account_id=account_id,
                                    region=region,
                                    resource_type="aws:backup:selection",
                                    service_family="Backup",
                                    resource_id=selection.get('SelectionId', ''),
                                    name=sel_data.get('SelectionName', ''),
                                    tags={},
                                    size_gb=0.0,
                                    parent_resource_id=plan_arn,  # Links to backup plan
                                    metadata={
                                        'backup_plan_id': plan_id,
                                        'backup_plan_name': plan_name,
                                        'selection_id': selection_id,
                                        'iam_role_arn': sel_data.get('IamRoleArn'),
                                        'resources': resource_arns,  # ARNs or wildcards like arn:aws:ec2:*:*:volume/*
                                        'not_resources': not_resources,
                                        'list_of_tags': list_of_tags,  # Tag-based selection
                                        'conditions': conditions,
                                        'creation_date': str(selection.get('CreationDate', ''))
                                    }
                                )
                                resources.append(resource)
                            except Exception as e:
                                logger.warning(f"[{region}] Failed to get selection {selection_id} details: {e}")
                except Exception as e:
                    logger.warning(f"[{region}] Failed to list selections for plan {plan_name}: {e}")
        
        logger.info(f"[{region}] Found {len(resources)} Backup selections")
    except Exception as e:
        logger.error(f"[{region}] Failed to collect Backup selections: {e}")
    
    return resources


def collect_backup_protected_resources(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect AWS Backup protected resources (resources with at least one recovery point)."""
    resources = []
    try:
        backup = session.client('backup', region_name=region)
        paginator = backup.get_paginator('list_protected_resources')
        
        for page in paginator.paginate():
            for protected in page.get('Results', []):
                resource_arn = protected.get('ResourceArn', '')
                resource_type = protected.get('ResourceType', '')  # e.g., EC2, EBS, RDS, etc.
                
                # Extract resource name from ARN
                resource_name = resource_arn.split('/')[-1] if '/' in resource_arn else resource_arn.split(':')[-1]
                
                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:backup:protected-resource",
                    service_family="Backup",
                    resource_id=resource_arn,
                    name=resource_name,
                    tags={},
                    size_gb=0.0,
                    parent_resource_id=resource_arn,  # The actual protected resource
                    metadata={
                        'resource_type': resource_type,  # EC2, EBS, RDS, DynamoDB, EFS, etc.
                        'resource_arn': resource_arn,
                        'last_backup_time': str(protected.get('LastBackupTime', '')) if protected.get('LastBackupTime') else None
                    }
                )
                resources.append(resource)
        
        logger.info(f"[{region}] Found {len(resources)} Backup protected resources")
    except Exception as e:
        logger.error(f"[{region}] Failed to collect Backup protected resources: {e}")
    
    return resources


# =============================================================================
# Main Collection Logic
# =============================================================================

def collect_region(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect all resources in a region."""
    resources = []
    
    logger.info(f"Collecting resources in {region}...")
    
    # EC2
    resources.extend(collect_ec2_instances(session, region, account_id))
    resources.extend(collect_ebs_volumes(session, region, account_id))
    resources.extend(collect_ebs_snapshots(session, region, account_id))
    
    # RDS
    resources.extend(collect_rds_instances(session, region, account_id))
    resources.extend(collect_rds_clusters(session, region, account_id))
    resources.extend(collect_rds_snapshots(session, region, account_id))
    resources.extend(collect_rds_cluster_snapshots(session, region, account_id))
    
    # Storage
    resources.extend(collect_efs_filesystems(session, region, account_id))
    resources.extend(collect_fsx_filesystems(session, region, account_id))
    
    # Containers & Compute
    resources.extend(collect_eks_clusters(session, region, account_id))
    resources.extend(collect_eks_nodegroups(session, region, account_id))
    resources.extend(collect_lambda_functions(session, region, account_id))
    
    # Databases
    resources.extend(collect_dynamodb_tables(session, region, account_id))
    resources.extend(collect_elasticache_clusters(session, region, account_id))
    
    # AWS Backup
    resources.extend(collect_backup_vaults(session, region, account_id))
    resources.extend(collect_backup_recovery_points(session, region, account_id))
    resources.extend(collect_backup_plans(session, region, account_id))
    resources.extend(collect_backup_selections(session, region, account_id))
    resources.extend(collect_backup_protected_resources(session, region, account_id))
    
    return resources


def main():
    parser = argparse.ArgumentParser(
        description='CCA CloudShell - AWS Resource Collector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single account (current credentials)
  python3 aws_collect.py

  # Specific regions
  python3 aws_collect.py --regions us-east-1,us-west-2

  # Assume role in another account
  python3 aws_collect.py --role-arn arn:aws:iam::123456789012:role/CCARole

  # Multiple accounts via role assumption
  python3 aws_collect.py --role-arns arn:aws:iam::111:role/CCA,arn:aws:iam::222:role/CCA

  # Auto-discover all accounts in AWS Organization
  python3 aws_collect.py --org-role CCARole

  # Organization discovery with external ID
  python3 aws_collect.py --org-role CCARole --external-id MySecretId
"""
    )
    
    # Basic options
    parser.add_argument('--profile', help='AWS profile name (optional in CloudShell)')
    parser.add_argument('--regions', help='Comma-separated list of regions (default: all enabled)')
    parser.add_argument('--output', '-o', help='Output directory or S3 path', default='.')
    parser.add_argument('--log-level', help='Logging level', default='INFO')
    
    # Multi-account options
    parser.add_argument(
        '--role-arn',
        help='Single role ARN to assume for collection (e.g., arn:aws:iam::123456789012:role/CCARole)'
    )
    parser.add_argument(
        '--role-arns',
        help='Comma-separated list of role ARNs to assume for multi-account collection'
    )
    parser.add_argument(
        '--org-role',
        help='Role name to assume in each Organization account (e.g., CCARole). '
             'Discovers all accounts via Organizations API and assumes arn:aws:iam::<account>:role/<org-role>'
    )
    parser.add_argument(
        '--external-id',
        help='External ID for role assumption (applies to all role assumptions)'
    )
    parser.add_argument(
        '--skip-accounts',
        help='Comma-separated list of account IDs to skip (useful with --org-role)'
    )
    
    args = parser.parse_args()
    setup_logging(args.log_level)
    
    # Create base session
    base_session = get_session(args.profile)
    base_account_id = get_account_id(base_session)
    
    # Parse regions
    regions = None
    if args.regions:
        regions = [r.strip() for r in args.regions.split(',')]
    
    # Parse skip accounts
    skip_accounts = set()
    if args.skip_accounts:
        skip_accounts = {a.strip() for a in args.skip_accounts.split(',')}
    
    # Determine collection mode and build list of (session, account_id) tuples
    account_sessions: List[tuple] = []
    
    if args.org_role:
        # Organizations discovery mode
        logger.info("Discovering accounts via AWS Organizations...")
        org_accounts = discover_org_accounts(base_session)
        
        if not org_accounts:
            logger.error("No accounts discovered. Check Organizations permissions or use --role-arns instead.")
            sys.exit(1)
        
        for account in org_accounts:
            acc_id = account['id']
            acc_name = account['name']
            
            if acc_id in skip_accounts:
                logger.info(f"Skipping account {acc_id} ({acc_name})")
                continue
            
            # Check if this is the management account (where we're running from)
            if acc_id == base_account_id:
                logger.info(f"Using current credentials for management account {acc_id} ({acc_name})")
                account_sessions.append((base_session, acc_id, acc_name))
            else:
                # Assume role in member account
                role_arn = f"arn:aws:iam::{acc_id}:role/{args.org_role}"
                try:
                    assumed_session = assume_role(base_session, role_arn, args.external_id)
                    logger.info(f"Assumed role in account {acc_id} ({acc_name})")
                    account_sessions.append((assumed_session, acc_id, acc_name))
                except Exception as e:
                    logger.warning(f"Failed to assume role in account {acc_id} ({acc_name}): {e}")
                    continue
    
    elif args.role_arns:
        # Explicit multi-account role assumption
        role_arns = [r.strip() for r in args.role_arns.split(',')]
        
        for role_arn in role_arns:
            try:
                assumed_session = assume_role(base_session, role_arn, args.external_id)
                acc_id = get_account_id(assumed_session)
                logger.info(f"Assumed role {role_arn} (account {acc_id})")
                account_sessions.append((assumed_session, acc_id, None))
            except Exception as e:
                logger.warning(f"Failed to assume role {role_arn}: {e}")
                continue
    
    elif args.role_arn:
        # Single role assumption
        try:
            assumed_session = assume_role(base_session, args.role_arn, args.external_id)
            acc_id = get_account_id(assumed_session)
            logger.info(f"Assumed role {args.role_arn} (account {acc_id})")
            account_sessions.append((assumed_session, acc_id, None))
        except Exception as e:
            logger.error(f"Failed to assume role {args.role_arn}: {e}")
            sys.exit(1)
    
    else:
        # Single account mode (current credentials)
        account_sessions.append((base_session, base_account_id, None))
    
    if not account_sessions:
        logger.error("No accounts to collect from")
        sys.exit(1)
    
    # Collect from all accounts
    all_resources: List[CloudResource] = []
    collected_accounts: List[Dict[str, Any]] = []
    
    for session, account_id, account_name in account_sessions:
        try:
            print(f"\n{'='*60}")
            print(f"Collecting from account: {account_id}" + (f" ({account_name})" if account_name else ""))
            print(f"{'='*60}")
            
            account_resources = collect_account(session, account_id, regions)
            all_resources.extend(account_resources)
            
            collected_accounts.append({
                'account_id': account_id,
                'account_name': account_name,
                'resource_count': len(account_resources)
            })
            
        except Exception as e:
            logger.error(f"Failed to collect from account {account_id}: {e}")
            continue
    
    # Generate summaries
    summaries = aggregate_sizing(all_resources)
    
    # Prepare output
    run_id = generate_run_id()
    timestamp = get_timestamp()
    
    # Determine if multi-account
    is_multi_account = len(collected_accounts) > 1
    account_ids = [a['account_id'] for a in collected_accounts]
    
    output_data = {
        'run_id': run_id,
        'timestamp': timestamp,
        'provider': 'aws',
        'account_id': account_ids[0] if len(account_ids) == 1 else account_ids,
        'accounts': collected_accounts if is_multi_account else None,
        'regions': regions if regions else 'all',
        'resource_count': len(all_resources),
        'resources': [r.to_dict() for r in all_resources]
    }
    
    summary_data = {
        'run_id': run_id,
        'timestamp': timestamp,
        'provider': 'aws',
        'account_id': account_ids[0] if len(account_ids) == 1 else account_ids,
        'accounts': collected_accounts if is_multi_account else None,
        'total_resources': len(all_resources),
        'total_capacity_gb': sum(s.total_gb for s in summaries),
        'summaries': [s.to_dict() for s in summaries]
    }
    
    # Remove None values
    output_data = {k: v for k, v in output_data.items() if v is not None}
    summary_data = {k: v for k, v in summary_data.items() if v is not None}
    
    # Write outputs
    output_base = args.output.rstrip('/')
    
    if output_base.startswith('s3://'):
        output_base = f"{output_base}/{run_id}"
    
    # Short timestamp for filenames (HHMMSS) - keeps filename < 20 chars
    file_ts = datetime.now(timezone.utc).strftime('%H%M%S')
    write_json(output_data, f"{output_base}/cca_aws_inv_{file_ts}.json")
    write_json(summary_data, f"{output_base}/cca_aws_sum_{file_ts}.json")
    
    # Write CSV for spreadsheet use
    csv_data = [s.to_dict() for s in summaries]
    write_csv(csv_data, f"{output_base}/cca_aws_sizing.csv")
    
    # Print summary to console
    print(f"\n{'='*60}")
    print(f"AWS Cloud Assessment Complete")
    print(f"{'='*60}")
    
    if is_multi_account:
        print(f"Accounts:  {len(collected_accounts)}")
        for acc in collected_accounts:
            name_str = f" ({acc['account_name']})" if acc.get('account_name') else ""
            print(f"  - {acc['account_id']}{name_str}: {acc['resource_count']} resources")
    else:
        print(f"Account:   {account_ids[0]}")
    
    print(f"Resources: {len(all_resources)}")
    print(f"Run ID:    {run_id}")
    
    print_summary_table([s.to_dict() for s in summaries])
    
    print(f"Output: {output_base}/")


if __name__ == '__main__':
    main()
