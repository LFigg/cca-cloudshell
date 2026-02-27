"""
Change rate metrics collection for CCA CloudShell.

Collects data change rates and transaction log generation rates from cloud monitoring APIs.
This data can be used to override default daily change rate (DCR) assumptions in sizing tools.

Dual-metric approach:
- Data change rate: Percentage/GB of data that changes daily (for incremental backups)
- Transaction log rate: GB of logs generated daily (always 100% capture rate)
"""
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .constants import DEFAULT_SAMPLE_DAYS, bytes_to_gb

logger = logging.getLogger(__name__)


@dataclass
class DataChangeMetrics:
    """Metrics for data change rate."""
    daily_change_gb: float = 0.0
    daily_change_percent: Optional[float] = None  # Percentage of total data changed
    sample_days: int = DEFAULT_SAMPLE_DAYS  # Number of days sampled
    data_points: int = 0  # Number of data points collected


@dataclass
class TransactionLogMetrics:
    """Metrics for transaction log generation (databases only)."""
    daily_generation_gb: float = 0.0
    capture_rate_percent: float = 100.0  # Always 100% for transaction logs
    sample_days: int = DEFAULT_SAMPLE_DAYS
    data_points: int = 0


@dataclass
class ChangeRateSummary:
    """
    Combined change rate summary for a service type.
    """
    provider: str
    service_family: str
    resource_count: int = 0
    total_size_gb: float = 0.0

    # Data change metrics (aggregated across resources)
    data_change: DataChangeMetrics = field(default_factory=DataChangeMetrics)

    # Transaction log metrics (databases only)
    transaction_logs: Optional[TransactionLogMetrics] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        result = {
            "provider": self.provider,
            "service_family": self.service_family,
            "resource_count": self.resource_count,
            "total_size_gb": self.total_size_gb,
            "data_change": asdict(self.data_change)
        }
        if self.transaction_logs:
            result["transaction_logs"] = asdict(self.transaction_logs)
        return result


# ============================================================================
# AWS CloudWatch Change Rate Collection
# ============================================================================

def get_aws_cloudwatch_client(session, region: str):
    """Get CloudWatch client for a region."""
    return session.client('cloudwatch', region_name=region)


def get_cloudwatch_metric_average(
    cloudwatch_client,
    namespace: str,
    metric_name: str,
    dimensions: List[Dict[str, str]],
    days: int = 7,
    stat: str = 'Sum'
) -> Optional[float]:
    """
    Get average daily value of a CloudWatch metric over the specified period.

    Args:
        cloudwatch_client: boto3 CloudWatch client
        namespace: CloudWatch namespace (e.g., 'AWS/EBS')
        metric_name: Metric name (e.g., 'VolumeWriteBytes')
        dimensions: List of dimension dicts with Name and Value
        days: Number of days to look back
        stat: Statistic to retrieve (Sum, Average, etc.)

    Returns:
        Average daily value, or None if no data
    """
    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)

        response = cloudwatch_client.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,  # 1 day in seconds
            Statistics=[stat]
        )

        datapoints = response.get('Datapoints', [])
        if not datapoints:
            return None

        # Calculate average daily value
        total = sum(dp.get(stat, 0) for dp in datapoints)
        return total / len(datapoints)

    except Exception as e:
        logger.debug(f"Error getting CloudWatch metric {namespace}/{metric_name}: {e}")
        return None


def get_ebs_volume_change_rate(cloudwatch_client, volume_id: str, volume_size_gb: float, days: int = DEFAULT_SAMPLE_DAYS) -> Optional[DataChangeMetrics]:
    """
    Get change rate for an EBS volume using VolumeWriteBytes metric.
    """
    daily_write_bytes = get_cloudwatch_metric_average(
        cloudwatch_client,
        namespace='AWS/EBS',
        metric_name='VolumeWriteBytes',
        dimensions=[{'Name': 'VolumeId', 'Value': volume_id}],
        days=days
    )

    if daily_write_bytes is None:
        return None

    daily_write_gb = bytes_to_gb(daily_write_bytes)
    change_percent = (daily_write_gb / volume_size_gb * 100) if volume_size_gb > 0 else None

    return DataChangeMetrics(
        daily_change_gb=daily_write_gb,
        daily_change_percent=change_percent,
        sample_days=days,
        data_points=days
    )


def get_efs_change_rate(cloudwatch_client, filesystem_id: str, filesystem_size_gb: float, days: int = DEFAULT_SAMPLE_DAYS) -> Optional[DataChangeMetrics]:
    """
    Get change rate for an EFS filesystem using DataWriteIOBytes metric.
    """
    daily_write_bytes = get_cloudwatch_metric_average(
        cloudwatch_client,
        namespace='AWS/EFS',
        metric_name='DataWriteIOBytes',
        dimensions=[{'Name': 'FileSystemId', 'Value': filesystem_id}],
        days=days
    )

    if daily_write_bytes is None:
        return None

    daily_write_gb = bytes_to_gb(daily_write_bytes)
    change_percent = (daily_write_gb / filesystem_size_gb * 100) if filesystem_size_gb > 0 else None

    return DataChangeMetrics(
        daily_change_gb=daily_write_gb,
        daily_change_percent=change_percent,
        sample_days=days,
        data_points=days
    )


def get_fsx_change_rate(cloudwatch_client, filesystem_id: str, filesystem_size_gb: float, days: int = 7) -> Optional[DataChangeMetrics]:
    """
    Get change rate for an FSx filesystem using DataWriteBytes metric.
    Note: Works for FSx for Lustre, Windows, ONTAP, and OpenZFS.
    """
    daily_write_bytes = get_cloudwatch_metric_average(
        cloudwatch_client,
        namespace='AWS/FSx',
        metric_name='DataWriteBytes',
        dimensions=[{'Name': 'FileSystemId', 'Value': filesystem_id}],
        days=days
    )

    if daily_write_bytes is None:
        return None

    daily_write_gb = daily_write_bytes / (1024 ** 3)
    change_percent = (daily_write_gb / filesystem_size_gb * 100) if filesystem_size_gb > 0 else None

    return DataChangeMetrics(
        daily_change_gb=daily_write_gb,
        daily_change_percent=change_percent,
        sample_days=days,
        data_points=days
    )


def get_rds_transaction_log_rate(cloudwatch_client, db_instance_id: str, engine: str, days: int = 7) -> Optional[TransactionLogMetrics]:
    """
    Get transaction log generation rate for an RDS instance.

    Uses BinLogDiskUsage for MySQL/MariaDB or TransactionLogsDiskUsage for PostgreSQL.
    """
    # Choose metric based on engine
    if engine.lower() in ('mysql', 'mariadb', 'aurora-mysql'):
        metric_name = 'BinLogDiskUsage'
    elif engine.lower() in ('postgres', 'aurora-postgresql'):
        metric_name = 'TransactionLogsDiskUsage'
    else:
        # SQL Server and Oracle have different metrics
        metric_name = 'TransactionLogsDiskUsage'

    # Get the change in transaction log disk usage (approximates generation rate)
    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)

        cloudwatch_client_response = cloudwatch_client.get_metric_statistics(
            Namespace='AWS/RDS',
            MetricName=metric_name,
            Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_instance_id}],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,
            Statistics=['Average']
        )

        datapoints = cloudwatch_client_response.get('Datapoints', [])
        if not datapoints:
            return None

        # Average transaction log size (this is a rough approximation)
        avg_log_bytes = sum(dp.get('Average', 0) for dp in datapoints) / len(datapoints)
        daily_log_gb = avg_log_bytes / (1024 ** 3)

        return TransactionLogMetrics(
            daily_generation_gb=daily_log_gb,
            capture_rate_percent=100.0,  # Always capture 100% of transaction logs
            sample_days=days,
            data_points=len(datapoints)
        )

    except Exception as e:
        logger.debug(f"Error getting RDS transaction log metrics for {db_instance_id}: {e}")
        return None


def get_rds_write_iops_change_rate(cloudwatch_client, db_instance_id: str, allocated_storage_gb: float, days: int = 7) -> Optional[DataChangeMetrics]:
    """
    Estimate data change rate for RDS using WriteIOPS.

    Note: This is an approximation. WriteIOPS * average block size gives write throughput.
    We assume 16KB average block size for database workloads.
    """
    daily_write_iops = get_cloudwatch_metric_average(
        cloudwatch_client,
        namespace='AWS/RDS',
        metric_name='WriteIOPS',
        dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_instance_id}],
        days=days,
        stat='Average'
    )

    if daily_write_iops is None:
        return None

    # Estimate: WriteIOPS * 16KB block size * seconds per day
    avg_block_size_bytes = 16 * 1024  # 16KB typical for databases
    seconds_per_day = 86400
    daily_write_bytes = daily_write_iops * avg_block_size_bytes * seconds_per_day
    daily_write_gb = daily_write_bytes / (1024 ** 3)

    change_percent = (daily_write_gb / allocated_storage_gb * 100) if allocated_storage_gb > 0 else None

    return DataChangeMetrics(
        daily_change_gb=daily_write_gb,
        daily_change_percent=change_percent,
        sample_days=days,
        data_points=days
    )


def get_s3_change_rate(cloudwatch_client, bucket_name: str, bucket_size_gb: float, days: int = 7) -> Optional[DataChangeMetrics]:
    """
    Estimate S3 bucket change rate using NumberOfObjects delta.

    Note: S3 doesn't have direct write throughput metrics. This uses object count changes
    as a rough proxy for change rate.
    """
    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)

        response = cloudwatch_client.get_metric_statistics(
            Namespace='AWS/S3',
            MetricName='NumberOfObjects',
            Dimensions=[
                {'Name': 'BucketName', 'Value': bucket_name},
                {'Name': 'StorageType', 'Value': 'AllStorageTypes'}
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,
            Statistics=['Average']
        )

        datapoints = response.get('Datapoints', [])
        if len(datapoints) < 2:
            return None

        # Sort by timestamp
        sorted_points = sorted(datapoints, key=lambda x: x['Timestamp'])

        # Calculate average daily object change rate
        object_changes = []
        for i in range(1, len(sorted_points)):
            delta = abs(sorted_points[i].get('Average', 0) - sorted_points[i-1].get('Average', 0))
            object_changes.append(delta)

        if not object_changes:
            return None

        avg_daily_object_change = sum(object_changes) / len(object_changes)
        total_objects = sorted_points[-1].get('Average', 1)

        # Estimate change percentage based on object churn
        change_percent = (avg_daily_object_change / total_objects * 100) if total_objects > 0 else None

        # Estimate GB changed (rough approximation based on percentage)
        daily_change_gb = (bucket_size_gb * change_percent / 100) if change_percent else 0

        return DataChangeMetrics(
            daily_change_gb=daily_change_gb,
            daily_change_percent=change_percent,
            sample_days=days,
            data_points=len(datapoints)
        )

    except Exception as e:
        logger.debug(f"Error getting S3 change rate for {bucket_name}: {e}")
        return None


# ============================================================================
# Azure Monitor Change Rate Collection
# ============================================================================

def get_azure_monitor_client(credential, subscription_id: str):
    """Get Azure Monitor client."""
    try:
        from azure.mgmt.monitor import MonitorManagementClient
        return MonitorManagementClient(credential, subscription_id)
    except ImportError:
        logger.warning("azure-mgmt-monitor not installed, change rate collection unavailable")
        return None


def get_azure_metric_average(
    monitor_client,
    resource_id: str,
    metric_name: str,
    days: int = 7,
    aggregation: str = 'Total'
) -> Optional[float]:
    """
    Get average daily value of an Azure Monitor metric.
    """
    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)
        timespan = f"{start_time.isoformat()}/{end_time.isoformat()}"

        response = monitor_client.metrics.list(
            resource_uri=resource_id,
            timespan=timespan,
            interval='P1D',  # 1 day granularity
            metricnames=metric_name,
            aggregation=aggregation
        )

        total_value = 0
        data_points = 0

        for metric in response.value:
            for timeseries in metric.timeseries:
                for data in timeseries.data:
                    value = getattr(data, aggregation.lower(), None)
                    if value is not None:
                        total_value += value
                        data_points += 1

        if data_points == 0:
            return None

        return total_value / data_points

    except Exception as e:
        logger.debug(f"Error getting Azure metric {metric_name}: {e}")
        return None


def get_azure_disk_change_rate(monitor_client, disk_resource_id: str, disk_size_gb: float, days: int = 7) -> Optional[DataChangeMetrics]:
    """
    Get change rate for an Azure managed disk using Disk Write Bytes metric.
    """
    # Note: Managed disks use 'Composite Disk Write Bytes/sec' or need VM-level metrics
    daily_write_bytes = get_azure_metric_average(
        monitor_client,
        resource_id=disk_resource_id,
        metric_name='Composite Disk Write Bytes/sec',
        days=days,
        aggregation='Average'
    )

    if daily_write_bytes is None:
        return None

    # Convert from bytes/sec average to daily GB
    daily_write_gb = (daily_write_bytes * 86400) / (1024 ** 3)
    change_percent = (daily_write_gb / disk_size_gb * 100) if disk_size_gb > 0 else None

    return DataChangeMetrics(
        daily_change_gb=daily_write_gb,
        daily_change_percent=change_percent,
        sample_days=days,
        data_points=days
    )


def get_azure_sql_transaction_log_rate(monitor_client, resource_id: str, days: int = 7) -> Optional[TransactionLogMetrics]:
    """
    Estimate data change rate for Azure SQL Database using storage metric delta.

    Note: Azure SQL doesn't expose transaction log metrics like AWS RDS does.
    This uses the 'storage' metric to calculate data growth rate over time,
    which approximates the net data change (but not raw transaction log volume
    which would include all write operations that may not change net size).

    For backup sizing, data growth rate is typically more relevant than raw
    transaction log volume.

    Returns:
        TransactionLogMetrics with daily_generation_gb representing data growth rate,
        or None if metrics unavailable.
    """
    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)
        timespan = f"{start_time.isoformat()}/{end_time.isoformat()}"

        response = monitor_client.metrics.list(
            resource_uri=resource_id,
            timespan=timespan,
            interval='P1D',  # 1 day granularity
            metricnames='storage',
            aggregation='Average'
        )

        # Collect daily storage values
        daily_values = []
        for metric in response.value:
            for timeseries in metric.timeseries:
                for data in timeseries.data:
                    value = getattr(data, 'average', None)
                    if value is not None:
                        daily_values.append(value)

        if len(daily_values) < 2:
            # Need at least 2 data points to calculate delta
            return None

        # Sort chronologically and calculate daily deltas
        daily_values.sort()  # Assuming chronological order in query
        deltas = []
        for i in range(1, len(daily_values)):
            delta = max(0, daily_values[i] - daily_values[i-1])  # Only count growth
            deltas.append(delta)

        if not deltas:
            return None

        # Average daily growth in bytes, convert to GB
        avg_daily_growth_bytes = sum(deltas) / len(deltas)
        daily_growth_gb = avg_daily_growth_bytes / (1024 ** 3)

        return TransactionLogMetrics(
            daily_generation_gb=daily_growth_gb,
            capture_rate_percent=100.0,
            sample_days=days,
            data_points=len(daily_values)
        )

    except Exception as e:
        logger.debug(f"Error getting Azure SQL storage metrics for {resource_id}: {e}")
        return None


# ============================================================================
# GCP Cloud Monitoring Change Rate Collection
# ============================================================================

def get_gcp_monitoring_client(project_id: str):
    """Get GCP Cloud Monitoring client."""
    try:
        from google.cloud import monitoring_v3
        return monitoring_v3.MetricServiceClient()
    except ImportError:
        logger.warning("google-cloud-monitoring not installed, change rate collection unavailable")
        return None


def get_gcp_metric_average(
    monitoring_client,
    project_id: str,
    metric_type: str,
    resource_labels: Dict[str, str],
    days: int = 7
) -> Optional[float]:
    """
    Get average daily value of a GCP Cloud Monitoring metric.
    """
    try:
        from google.cloud import monitoring_v3

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)

        # Build filter string
        filter_parts = [f'metric.type="{metric_type}"']
        for key, value in resource_labels.items():
            filter_parts.append(f'resource.labels.{key}="{value}"')
        filter_str = ' AND '.join(filter_parts)

        interval = monitoring_v3.TimeInterval()
        interval.end_time.FromDatetime(end_time)
        interval.start_time.FromDatetime(start_time)

        results = monitoring_client.list_time_series(
            request={
                "name": f"projects/{project_id}",
                "filter": filter_str,
                "interval": interval,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL
            }
        )

        total_value = 0
        data_points = 0

        for time_series in results:
            for point in time_series.points:
                value = point.value.double_value or point.value.int64_value
                if value:
                    total_value += value
                    data_points += 1

        if data_points == 0:
            return None

        return total_value / data_points

    except Exception as e:
        logger.debug(f"Error getting GCP metric {metric_type}: {e}")
        return None


def get_gcp_disk_change_rate(monitoring_client, project_id: str, disk_name: str, zone: str, disk_size_gb: float, days: int = 7) -> Optional[DataChangeMetrics]:
    """
    Get change rate for a GCP persistent disk using write_bytes_count metric.
    """
    daily_write_bytes = get_gcp_metric_average(
        monitoring_client,
        project_id=project_id,
        metric_type='compute.googleapis.com/instance/disk/write_bytes_count',
        resource_labels={'zone': zone, 'device_name': disk_name},
        days=days
    )

    if daily_write_bytes is None:
        return None

    daily_write_gb = daily_write_bytes / (1024 ** 3)
    change_percent = (daily_write_gb / disk_size_gb * 100) if disk_size_gb > 0 else None

    return DataChangeMetrics(
        daily_change_gb=daily_write_gb,
        daily_change_percent=change_percent,
        sample_days=days,
        data_points=days
    )


def get_cloudsql_change_rate(monitoring_client, project_id: str, instance_id: str, disk_size_gb: float, days: int = 7) -> Optional[DataChangeMetrics]:
    """
    Get change rate for a Cloud SQL instance using disk write metrics.
    """
    daily_write_ops = get_gcp_metric_average(
        monitoring_client,
        project_id=project_id,
        metric_type='cloudsql.googleapis.com/database/disk/write_ops_count',
        resource_labels={'database_id': f"{project_id}:{instance_id}"},
        days=days
    )

    if daily_write_ops is None:
        return None

    # Estimate bytes: write_ops * 16KB average block size
    avg_block_size_bytes = 16 * 1024
    daily_write_gb = (daily_write_ops * avg_block_size_bytes) / (1024 ** 3)
    change_percent = (daily_write_gb / disk_size_gb * 100) if disk_size_gb > 0 else None

    return DataChangeMetrics(
        daily_change_gb=daily_write_gb,
        daily_change_percent=change_percent,
        sample_days=days,
        data_points=days
    )


# ============================================================================
# Aggregation Functions
# ============================================================================

def aggregate_change_rates(
    change_rates: List[Dict[str, Any]]
) -> Dict[str, ChangeRateSummary]:
    """
    Aggregate individual resource change rates into per-service summaries.

    Args:
        change_rates: List of dicts with keys:
            - provider: str
            - service_family: str
            - size_gb: float
            - data_change: DataChangeMetrics (optional)
            - transaction_logs: TransactionLogMetrics (optional)

    Returns:
        Dict mapping service_family to ChangeRateSummary
    """
    summaries: Dict[str, ChangeRateSummary] = {}

    for rate in change_rates:
        provider = rate.get('provider', 'unknown')
        service_family = rate.get('service_family', 'unknown')
        key = f"{provider}:{service_family}"

        if key not in summaries:
            summaries[key] = ChangeRateSummary(
                provider=provider,
                service_family=service_family
            )

        summary = summaries[key]
        summary.resource_count += 1
        summary.total_size_gb += rate.get('size_gb', 0)

        # Aggregate data change metrics
        data_change = rate.get('data_change')
        if data_change:
            summary.data_change.daily_change_gb += data_change.daily_change_gb
            summary.data_change.data_points += data_change.data_points

        # Aggregate transaction log metrics (databases only)
        tlog = rate.get('transaction_logs')
        if tlog:
            if summary.transaction_logs is None:
                summary.transaction_logs = TransactionLogMetrics()
            summary.transaction_logs.daily_generation_gb += tlog.daily_generation_gb
            summary.transaction_logs.data_points += tlog.data_points

    # Calculate percentages after aggregation
    for summary in summaries.values():
        if summary.total_size_gb > 0 and summary.data_change.daily_change_gb > 0:
            summary.data_change.daily_change_percent = (
                summary.data_change.daily_change_gb / summary.total_size_gb * 100
            )

    return summaries


def format_change_rate_output(summaries: Dict[str, ChangeRateSummary]) -> Dict[str, Any]:
    """
    Format change rate summaries for JSON output.
    """
    return {
        "change_rates": {
            key: summary.to_dict()
            for key, summary in summaries.items()
        },
        "collection_metadata": {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "sample_period_days": 7,
            "notes": [
                "Data change rates are estimates based on write throughput metrics",
                "Transaction log rates apply to database services (always 100% capture)",
                "Use these values to override default DCR assumptions in sizing tools"
            ]
        }
    }


def merge_change_rates(
    accumulated: Dict[str, Any],
    new_cr_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Merge new change rate data into accumulated totals.

    This consolidates the duplicated merge logic from all collectors.
    Call this in a loop when aggregating change rates across multiple
    accounts/subscriptions/projects.

    Args:
        accumulated: Dict of accumulated change rates (modified in place)
        new_cr_data: New change rate data to merge (from collect_*_change_rates)

    Returns:
        The accumulated dict (same object, for chaining)

    Example:
        all_change_rates = {}
        for account in accounts:
            cr_data = collect_resource_change_rates(...)
            merge_change_rates(all_change_rates, cr_data)
        final_data = finalize_change_rate_output(all_change_rates, ...)
    """
    for key, summary in new_cr_data.get('change_rates', {}).items():
        if key not in accumulated:
            accumulated[key] = summary
        else:
            # Aggregate across accounts/subscriptions/projects
            existing = accumulated[key]
            existing['resource_count'] += summary['resource_count']
            existing['total_size_gb'] += summary['total_size_gb']
            existing['data_change']['daily_change_gb'] += summary['data_change']['daily_change_gb']
            existing['data_change']['data_points'] += summary['data_change']['data_points']
            if summary.get('transaction_logs'):
                if existing.get('transaction_logs'):
                    existing['transaction_logs']['daily_generation_gb'] += summary['transaction_logs']['daily_generation_gb']
                else:
                    existing['transaction_logs'] = summary['transaction_logs']

    return accumulated


def finalize_change_rate_output(
    all_change_rates: Dict[str, Any],
    sample_days: int = 7,
    provider_note: str = "cloud monitoring"
) -> Dict[str, Any]:
    """
    Finalize merged change rates: recalculate percentages and add metadata.

    Call this after all merge_change_rates() calls are complete.

    Args:
        all_change_rates: Accumulated change rates from merge_change_rates()
        sample_days: Number of days sampled
        provider_note: Provider-specific note (e.g., "CloudWatch", "Azure Monitor")

    Returns:
        Complete change rate data dict ready for JSON output
    """
    # Recalculate percentages after aggregation
    for _key, summary in all_change_rates.items():
        if summary['total_size_gb'] > 0 and summary['data_change']['daily_change_gb'] > 0:
            summary['data_change']['daily_change_percent'] = (
                summary['data_change']['daily_change_gb'] / summary['total_size_gb'] * 100
            )

    return {
        'change_rates': all_change_rates,
        'collection_metadata': {
            'collected_at': datetime.now(timezone.utc).isoformat(),
            'sample_period_days': sample_days,
            'notes': [
                f'Data change rates are estimates based on {provider_note} write throughput metrics',
                'Transaction log rates apply to database services (always 100% capture)',
                'Use these values to override default DCR assumptions in sizing tools'
            ]
        }
    }


def load_change_rate_files(paths: List[str]) -> Dict[str, Any]:
    """
    Load and merge change rate data from JSON files.

    This is the standard way to load previously collected change rate data
    for use in assessment reports and sizer input generation.

    Args:
        paths: List of paths to change rate JSON files (cca_*_change_rates_*.json)

    Returns:
        Dict with structure:
        {
            'change_rates': {
                'aws:rds-mysql': {
                    'provider': 'aws',
                    'service_family': 'rds-mysql',
                    'resource_count': 10,
                    'total_size_gb': 500,
                    'data_change': {'daily_change_gb': 5.0, 'daily_change_percent': 1.0, ...},
                    'transaction_logs': {'daily_generation_gb': 25, ...}  # optional
                },
                ...
            },
            'has_actual_data': True/False
        }
    """
    import json

    merged: Dict[str, Any] = {
        'change_rates': {},
        'has_actual_data': False,
    }

    for path in paths:
        try:
            with open(path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load change rates from {path}: {e}")
            continue

        # Handle both formats: direct change_rates dict or wrapped
        change_rates = data.get('change_rates', data)
        if not change_rates or not isinstance(change_rates, dict):
            continue

        merged['has_actual_data'] = True

        for key, summary in change_rates.items():
            # Normalize key to provider:service format
            provider = summary.get('provider', 'unknown')
            service = summary.get('service_family', key.split(':')[-1] if ':' in key else key)
            norm_key = f"{provider}:{service}"

            if norm_key not in merged['change_rates']:
                merged['change_rates'][norm_key] = summary
            else:
                # Merge: accumulate counts and sizes
                existing = merged['change_rates'][norm_key]
                existing['resource_count'] = existing.get('resource_count', 0) + summary.get('resource_count', 0)
                existing['total_size_gb'] = existing.get('total_size_gb', 0) + summary.get('total_size_gb', 0)

                # Merge data_change
                if 'data_change' in summary:
                    if 'data_change' not in existing:
                        existing['data_change'] = summary['data_change'].copy()
                    else:
                        existing['data_change']['daily_change_gb'] = (
                            existing['data_change'].get('daily_change_gb', 0) +
                            summary['data_change'].get('daily_change_gb', 0)
                        )
                        existing['data_change']['data_points'] = (
                            existing['data_change'].get('data_points', 0) +
                            summary['data_change'].get('data_points', 0)
                        )

                # Merge transaction_logs
                if 'transaction_logs' in summary and summary['transaction_logs']:
                    if 'transaction_logs' not in existing or not existing['transaction_logs']:
                        existing['transaction_logs'] = summary['transaction_logs'].copy()
                    else:
                        existing['transaction_logs']['daily_generation_gb'] = (
                            existing['transaction_logs'].get('daily_generation_gb', 0) +
                            summary['transaction_logs'].get('daily_generation_gb', 0)
                        )

        logger.debug(f"Loaded change rates from {path}: {len(change_rates)} service families")

    # Recalculate percentages after merging
    for key, summary in merged['change_rates'].items():
        if 'data_change' in summary and summary.get('total_size_gb', 0) > 0:
            daily_gb = summary['data_change'].get('daily_change_gb', 0)
            total_gb = summary['total_size_gb']
            summary['data_change']['daily_change_percent'] = (daily_gb / total_gb) * 100

    if merged['has_actual_data']:
        logger.info(f"Loaded change rates for {len(merged['change_rates'])} service families from {len(paths)} file(s)")

    return merged
