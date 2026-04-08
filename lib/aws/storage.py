"""
AWS storage resource collection.

Collects S3 buckets, EFS filesystems, and FSx filesystems.
"""
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError

from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error, format_bytes_to_gb, retry_with_backoff

logger = logging.getLogger(__name__)


def get_s3_bucket_size_from_cloudwatch(session: boto3.Session, bucket_name: str, region: str) -> float:
    """Get S3 bucket size from CloudWatch metrics.

    Returns size in GB, or 0.0 if metrics unavailable.
    """
    try:
        # CloudWatch metrics for S3 are stored in the bucket's region
        cw_region = region if region != 'unknown' else 'us-east-1'
        cloudwatch = session.client('cloudwatch', region_name=cw_region)

        # Query BucketSizeBytes metric (updated daily by S3)
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=3)  # Look back 3 days for latest metric

        response = cloudwatch.get_metric_statistics(
            Namespace='AWS/S3',
            MetricName='BucketSizeBytes',
            Dimensions=[
                {'Name': 'BucketName', 'Value': bucket_name},
                {'Name': 'StorageType', 'Value': 'StandardStorage'}
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,  # Daily
            Statistics=['Average']
        )

        datapoints = response.get('Datapoints', [])
        if datapoints:
            # Get the most recent datapoint
            latest = max(datapoints, key=lambda x: x['Timestamp'])
            size_bytes = latest.get('Average', 0)
            return size_bytes / (1024 ** 3)  # Convert to GB

        return 0.0
    except Exception as e:
        logger.debug(f"Could not get CloudWatch size for bucket {bucket_name}: {e}")
        return 0.0


def _get_bucket_location_and_tags(s3_client, bucket_name: str) -> Dict[str, Any]:
    """Get bucket location and tags in parallel-friendly way.

    Returns dict with bucket_name, region, and tags.
    """
    result = {'name': bucket_name, 'region': 'unknown', 'tags': {}}

    # Get bucket region
    try:
        location = s3_client.get_bucket_location(Bucket=bucket_name)
        result['region'] = location.get('LocationConstraint') or 'us-east-1'
    except ClientError as e:
        logger.debug(f"Could not get location for bucket {bucket_name}: {e}")

    # Get bucket tags
    try:
        tag_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
        for tag in tag_response.get('TagSet', []):
            result['tags'][tag['Key']] = tag['Value']
    except ClientError:
        # NoSuchTagSet is common - bucket has no tags
        pass

    return result


@retry_with_backoff(max_attempts=3, exceptions=(ClientError,))
def collect_s3_buckets(session: boto3.Session, account_id: str, include_sizes: bool = False) -> List[CloudResource]:
    """Collect S3 buckets (global service).

    Args:
        session: boto3 session
        account_id: AWS account ID
        include_sizes: If True, query CloudWatch for bucket sizes (slower but accurate)
    """
    resources = []
    try:
        s3 = session.client('s3')
        response = s3.list_buckets()

        # Get bucket names and creation dates
        buckets = []
        for bucket in response.get('Buckets', []):
            bucket_name = bucket.get('Name', '')
            if bucket_name:
                buckets.append({
                    'name': bucket_name,
                    'creation_date': str(bucket.get('CreationDate', ''))
                })

        if not buckets:
            logger.info("Found 0 S3 buckets")
            return resources

        # Parallel fetch of bucket locations and tags (CR-021 optimization)
        logger.debug(f"Fetching locations and tags for {len(buckets)} buckets in parallel...")
        bucket_info = []
        max_workers = min(10, len(buckets))  # Cap at 10 to avoid S3 throttling

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_get_bucket_location_and_tags, s3, b['name']): b
                for b in buckets
            }
            for future in as_completed(futures):
                bucket_data = futures[future]
                try:
                    info = future.result()
                    info['creation_date'] = bucket_data['creation_date']
                    bucket_info.append(info)
                except Exception as e:
                    logger.debug(f"Failed to get info for bucket {bucket_data['name']}: {e}")
                    # Still include bucket with defaults
                    bucket_info.append({
                        'name': bucket_data['name'],
                        'region': 'unknown',
                        'tags': {},
                        'creation_date': bucket_data['creation_date']
                    })

        # Second pass: get sizes from CloudWatch if requested
        total_size_gb = 0.0

        if include_sizes:
            logger.info(f"Fetching S3 bucket sizes from CloudWatch ({len(bucket_info)} buckets)...")
            buckets_by_region: Dict[str, List[Dict]] = {}
            for info in bucket_info:
                region = info['region']
                if region not in buckets_by_region:
                    buckets_by_region[region] = []
                buckets_by_region[region].append(info)

            for region, region_buckets in buckets_by_region.items():
                for info in region_buckets:
                    size_gb = get_s3_bucket_size_from_cloudwatch(session, info['name'], region)
                    info['size_gb'] = size_gb
                    total_size_gb += size_gb
        else:
            for info in bucket_info:
                info['size_gb'] = 0.0

        # Create resources
        for info in bucket_info:
            resource = CloudResource(
                provider="aws",
                account_id=account_id,
                region=info['region'],
                resource_type="aws:s3:bucket",
                service_family="S3",
                resource_id=f"arn:aws:s3:::{info['name']}",
                name=info['name'],
                tags=info['tags'],
                size_gb=info['size_gb'],
                metadata={
                    'creation_date': info['creation_date'],
                    'size_note': 'Use --include-storage-sizes for accurate sizing' if not include_sizes else None
                }
            )
            resources.append(resource)

        size_note = f" ({total_size_gb:.1f} GB)" if include_sizes else " (sizes not collected)"
        logger.info(f"Found {len(resources)} S3 buckets{size_note}")
    except Exception as e:
        check_and_raise_auth_error(e, "collect S3 buckets", "aws")
        logger.error(f"Failed to collect S3 buckets: {e}")

    return resources


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
        check_and_raise_auth_error(e, "collect EFS", "aws")
        logger.error(f"[{region}] Failed to collect EFS: {e}")

    return resources


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
        check_and_raise_auth_error(e, "collect FSx", "aws")
        logger.error(f"[{region}] Failed to collect FSx: {e}")

    return resources
