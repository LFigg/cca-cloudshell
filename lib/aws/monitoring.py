"""
AWS change rate monitoring using CloudWatch.

Collects change rate metrics for various AWS resources.
"""
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

import boto3

from lib.change_rate import (
    aggregate_change_rates,
    format_change_rate_output,
    get_aws_cloudwatch_client,
    get_ebs_volume_change_rate,
    get_efs_change_rate,
    get_fsx_change_rate,
    get_rds_transaction_log_rate,
    get_rds_write_iops_change_rate,
    get_s3_change_rate,
)
from lib.models import CloudResource

logger = logging.getLogger(__name__)


def collect_resource_change_rates(
    session: boto3.Session,
    resources: List[CloudResource],
    days: int = 7,
    parallel_regions: int = 1
) -> Dict[str, Any]:
    """
    Collect change rate metrics from CloudWatch for the collected resources.

    Args:
        session: boto3 session
        resources: List of CloudResource objects collected from the account
        days: Number of days to sample for metrics
        parallel_regions: Number of regions to process in parallel

    Returns:
        Dict with change rate summaries by service family
    """
    change_rates: List[Dict[str, Any]] = []

    # Group resources by region for efficient CloudWatch access
    resources_by_region: Dict[str, List[CloudResource]] = {}
    for r in resources:
        if r.region and r.region != 'global':
            resources_by_region.setdefault(r.region, []).append(r)

    def collect_region_change_rates(region: str, region_resources: List[CloudResource]) -> List[Dict[str, Any]]:
        """Collect change rates for all resources in a region."""
        region_rates = []
        try:
            cloudwatch = get_aws_cloudwatch_client(session, region)
        except Exception as e:
            logger.warning(f"Could not create CloudWatch client for {region}: {e}")
            return region_rates

        for resource in region_resources:
            try:
                rate_entry = _collect_single_resource_change_rate(
                    cloudwatch, resource, days
                )
                if rate_entry:
                    region_rates.append(rate_entry)
            except Exception as e:
                logger.debug(f"Error collecting change rate for {resource.resource_id}: {e}")
                continue

        logger.info(f"[{region}] Collected change rates for {len(region_rates)} resources")
        return region_rates

    # Process regions (parallel or serial)
    if parallel_regions > 1 and len(resources_by_region) > 1:
        logger.info(f"Collecting change rates from {len(resources_by_region)} regions in parallel (workers={parallel_regions})")
        with ThreadPoolExecutor(max_workers=parallel_regions) as executor:
            futures = {
                executor.submit(collect_region_change_rates, region, region_resources): region
                for region, region_resources in resources_by_region.items()
            }
            for future in as_completed(futures):
                region = futures[future]
                try:
                    region_rates = future.result()
                    change_rates.extend(region_rates)
                except Exception as e:
                    logger.error(f"[{region}] Failed to collect change rates: {e}")
    else:
        for region, region_resources in resources_by_region.items():
            region_rates = collect_region_change_rates(region, region_resources)
            change_rates.extend(region_rates)

    # Also collect for global resources like S3
    try:
        # Use us-east-1 for S3 CloudWatch metrics
        s3_cloudwatch = get_aws_cloudwatch_client(session, 'us-east-1')
        for resource in resources:
            if resource.service_family == 'S3' and resource.size_gb > 0:
                try:
                    bucket_name = resource.metadata.get('bucket_name', resource.name)
                    if bucket_name:
                        data_change = get_s3_change_rate(
                            s3_cloudwatch, bucket_name, resource.size_gb, days
                        )
                        if data_change:
                            change_rates.append({
                                'provider': 'aws',
                                'service_family': 'S3',
                                'size_gb': resource.size_gb,
                                'data_change': data_change
                            })
                except Exception as e:
                    logger.debug(f"Error collecting S3 change rate for {resource.name}: {e}")
    except Exception as e:
        logger.debug(f"Error creating S3 CloudWatch client: {e}")

    # Aggregate change rates by service family
    summaries = aggregate_change_rates(change_rates)
    return format_change_rate_output(summaries)


def _collect_single_resource_change_rate(
    cloudwatch,
    resource: CloudResource,
    days: int
) -> Optional[Dict[str, Any]]:
    """
    Collect change rate for a single resource based on its type.
    """
    service_family = resource.service_family

    if service_family == 'EBS':
        # EBS volumes
        volume_id = resource.metadata.get('volume_id') or resource.resource_id.split('/')[-1]
        if volume_id.startswith('vol-'):
            data_change = get_ebs_volume_change_rate(
                cloudwatch, volume_id, resource.size_gb, days
            )
            if data_change:
                return {
                    'provider': 'aws',
                    'service_family': 'EBS',
                    'size_gb': resource.size_gb,
                    'data_change': data_change
                }

    elif service_family in ('RDS', 'Aurora'):
        # RDS instances and Aurora
        db_id = resource.metadata.get('db_instance_id') or resource.metadata.get('db_cluster_id')
        engine = resource.metadata.get('engine', '').lower()

        if db_id:
            data_change = get_rds_write_iops_change_rate(
                cloudwatch, db_id, resource.size_gb, days
            )
            tlog_metrics = get_rds_transaction_log_rate(
                cloudwatch, db_id, engine, days
            )

            if data_change or tlog_metrics:
                return {
                    'provider': 'aws',
                    'service_family': service_family,
                    'size_gb': resource.size_gb,
                    'data_change': data_change,
                    'transaction_logs': tlog_metrics
                }

    elif service_family in ('DocumentDB', 'Neptune', 'OpenSearch', 'Redshift'):
        # Other database services - use WriteIOPS equivalent metrics
        # For these services, we use size and estimate based on typical patterns
        # (CloudWatch metrics vary by service)
        pass

    elif service_family == 'EFS':
        # EFS filesystems
        fs_id = resource.metadata.get('filesystem_id') or resource.resource_id.split('/')[-1]
        if fs_id.startswith('fs-'):
            data_change = get_efs_change_rate(
                cloudwatch, fs_id, resource.size_gb, days
            )
            if data_change:
                return {
                    'provider': 'aws',
                    'service_family': 'EFS',
                    'size_gb': resource.size_gb,
                    'data_change': data_change
                }

    elif service_family == 'FSx':
        # FSx filesystems (Lustre, Windows, ONTAP, OpenZFS)
        fs_id = resource.metadata.get('filesystem_id') or resource.resource_id.split('/')[-1]
        if fs_id.startswith('fs-'):
            data_change = get_fsx_change_rate(
                cloudwatch, fs_id, resource.size_gb, days
            )
            if data_change:
                return {
                    'provider': 'aws',
                    'service_family': 'FSx',
                    'size_gb': resource.size_gb,
                    'data_change': data_change
                }

    return None
