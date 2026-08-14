"""
Change rate metrics collection for CCA CloudShell.

Collects data change rates and transaction log generation rates from cloud monitoring APIs.
This data can be used to override default daily change rate (DCR) assumptions in sizing tools.

Dual-metric approach:
- Data change rate: Percentage/GB of data that changes daily (for incremental backups)
- Transaction log rate: GB of logs generated daily (always 100% capture rate)
"""
from __future__ import annotations

import logging
import statistics
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple, Union

if TYPE_CHECKING:
    import boto3

from .constants import DEFAULT_SAMPLE_DAYS, bytes_to_gb
from .utils import check_and_raise_auth_error

logger = logging.getLogger(__name__)


def _steady_state_average(daily_values: List[float]) -> float:
    """Aggregate a series of daily metric values into a single "steady-state
    daily" figure, resistant to a single spike day (a batch job, a reindex,
    a one-off full backup) skewing what gets reported as the Sizer
    Encyclopedia's DCR - the amount of data that changes in a *typical* 24
    hours, not the peak. A plain mean lets one outlier day dominate a short
    (e.g. 7-day) sample; the median doesn't move unless the majority of
    sampled days shift.
    """
    return statistics.median(daily_values)


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


def _isoformat_z(dt: datetime) -> str:
    """Format a UTC datetime with a 'Z' suffix instead of '+00:00'.

    Azure Monitor's timespan query parameter is sent unencoded by the SDK, and
    a raw '+' in a query string gets decoded by the server as a literal space -
    turning "...192769+00:00" into "...192769 00:00", which Azure Monitor then
    rejects as an invalid ISO 8601 interval. 'Z' means the same UTC offset
    without the ambiguous character.
    """
    return dt.isoformat().replace("+00:00", "Z")


# ============================================================================
# AWS CloudWatch Change Rate Collection
# ============================================================================

def get_aws_cloudwatch_client(session: boto3.Session, region: str) -> Any:
    """Get CloudWatch client for a region."""
    return session.client('cloudwatch', region_name=region)


def get_cloudwatch_metric_average(
    cloudwatch_client: Any,
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

        daily_values = [dp.get(stat, 0) for dp in datapoints]
        return _steady_state_average(daily_values)

    except Exception as e:
        check_and_raise_auth_error(e, f"get CloudWatch metric {namespace}/{metric_name}", "aws")
        logger.warning(f"Error getting CloudWatch metric {namespace}/{metric_name}: {e}")
        return None


def get_ebs_volume_change_rate(cloudwatch_client: Any, volume_id: str, volume_size_gb: float, days: int = DEFAULT_SAMPLE_DAYS) -> Optional[DataChangeMetrics]:
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


def get_efs_change_rate(cloudwatch_client: Any, filesystem_id: str, filesystem_size_gb: float, days: int = DEFAULT_SAMPLE_DAYS) -> Optional[DataChangeMetrics]:
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


def get_fsx_change_rate(cloudwatch_client: Any, filesystem_id: str, filesystem_size_gb: float, days: int = 7) -> Optional[DataChangeMetrics]:
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


def get_rds_transaction_log_rate(cloudwatch_client: Any, db_instance_id: str, engine: str, days: int = 7) -> Optional[TransactionLogMetrics]:
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

        # BinLogDiskUsage/TransactionLogsDiskUsage is a GAUGE of currently-retained
        # log bytes on disk, not a cumulative counter - averaging its raw value (the
        # previous implementation) conflated "how much log is retained right now"
        # with "how much log is generated per day," and was wildly sensitive to
        # whatever retention window happens to be configured (a short rotation
        # window underreports true generation; a long one overreports it - the
        # average of the gauge isn't a rate at all). Sort chronologically and sum
        # the positive day-over-day deltas instead - a genuine (if imperfect - it
        # undercounts whenever old logs are purged the same day new ones are
        # written) proxy for actual daily generation, the same delta-based
        # methodology used for AGR/growth elsewhere in this module.
        datapoints = sorted(datapoints, key=lambda dp: dp['Timestamp'])
        values = [dp.get('Average', 0) for dp in datapoints]
        if len(values) < 2:
            # A single datapoint has no day-over-day delta to compute at all.
            return None

        daily_deltas_bytes = [max(0.0, values[i] - values[i - 1]) for i in range(1, len(values))]
        avg_daily_log_bytes = _steady_state_average(daily_deltas_bytes)
        daily_log_gb = avg_daily_log_bytes / (1024 ** 3)

        return TransactionLogMetrics(
            daily_generation_gb=daily_log_gb,
            capture_rate_percent=100.0,  # Always capture 100% of transaction logs
            sample_days=days,
            data_points=len(datapoints)
        )

    except Exception as e:
        check_and_raise_auth_error(e, f"get RDS transaction log metrics for {db_instance_id}", "aws")
        logger.warning(f"Error getting RDS transaction log metrics for {db_instance_id}: {e}")
        return None


def get_rds_write_iops_change_rate(cloudwatch_client: Any, db_instance_id: str, allocated_storage_gb: float, days: int = 7) -> Optional[DataChangeMetrics]:
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


def get_s3_change_rate(cloudwatch_client: Any, bucket_name: str, bucket_size_gb: float, days: int = 7) -> Optional[DataChangeMetrics]:
    """
    Estimate S3 bucket change rate using NumberOfObjects delta.

    S3's only always-available CloudWatch metrics (BucketSizeBytes,
    NumberOfObjects) are daily snapshots, not write-throughput deltas - unlike
    every other change-rate function in this module, there is no direct
    "bytes written" signal to fall back on here. This is a genuinely weaker
    proxy: it is blind to any write that doesn't change the object COUNT (an
    in-place overwrite of an existing key looks identical to zero activity).
    A better metric (BytesUploaded) exists in AWS/S3's "request metrics," but
    those are an opt-in, paid feature keyed by a customer-assigned FilterId
    this tool has no way to discover without an additional API call and a new
    permission - not implemented; see format_change_rate_output()'s S3 note,
    which surfaces this limitation in the collected JSON output itself.

    Treat the result as a lower bound on real change, not a point estimate.
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

        avg_daily_object_change = _steady_state_average(object_changes)
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
        check_and_raise_auth_error(e, f"get S3 change rate for {bucket_name}", "aws")
        logger.warning(f"Error getting S3 change rate for {bucket_name}: {e}")
        return None


# ============================================================================
# Azure Monitor Change Rate Collection
# ============================================================================

def get_azure_monitor_client(credential: Any, subscription_id: str) -> Optional[Any]:
    """Get Azure Monitor client."""
    try:
        from azure.mgmt.monitor import MonitorManagementClient
        return MonitorManagementClient(credential, subscription_id)
    except ImportError:
        logger.warning("azure-mgmt-monitor not installed, change rate collection unavailable")
        return None


def get_azure_metric_average(
    monitor_client: Any,
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
        timespan = f"{_isoformat_z(start_time)}/{_isoformat_z(end_time)}"

        response = monitor_client.metrics.list(
            resource_uri=resource_id,
            timespan=timespan,
            interval='P1D',  # 1 day granularity
            metricnames=metric_name,
            aggregation=aggregation
        )

        daily_values = []

        for metric in response.value:
            for timeseries in metric.timeseries:
                for data in timeseries.data:
                    value = getattr(data, aggregation.lower(), None)
                    if value is not None:
                        daily_values.append(value)

        if not daily_values:
            return None

        return _steady_state_average(daily_values)

    except Exception as e:
        check_and_raise_auth_error(e, f"get Azure metric {metric_name}", "azure")
        logger.warning(f"Error getting Azure metric {metric_name}: {e}")
        return None


def get_azure_vm_change_rate(monitor_client: Any, vm_resource_id: str, total_disk_size_gb: float, days: int = 7) -> Optional[DataChangeMetrics]:
    """
    Get change rate for an Azure VM using VM-level Disk Write Bytes metric.

    This is the preferred method as it:
    - Works for ALL Azure VMs regardless of disk type
    - Aggregates writes across all attached disks (OS + data disks)
    - Is more reliable than per-disk metrics which only work for Premium SSD v2/Ultra

    Args:
        monitor_client: Azure Monitor client
        vm_resource_id: Full Azure resource ID of the VM
        total_disk_size_gb: Total size of all disks attached to VM (OS + data)
        days: Number of days to sample

    Returns:
        DataChangeMetrics with daily change calculated from VM-level disk writes
    """
    # VM-level metric gives total bytes written across all disks
    daily_write_bytes = get_azure_metric_average(
        monitor_client,
        resource_id=vm_resource_id,
        metric_name='Disk Write Bytes',  # VM-level metric (total, not per-second)
        days=days,
        aggregation='Total'  # Total bytes written per day
    )

    if daily_write_bytes is None:
        return None

    # Convert from bytes to daily GB (already a daily total with Total aggregation)
    daily_write_gb = daily_write_bytes / (1024 ** 3)
    change_percent = (daily_write_gb / total_disk_size_gb * 100) if total_disk_size_gb > 0 else None

    return DataChangeMetrics(
        daily_change_gb=daily_write_gb,
        daily_change_percent=change_percent,
        sample_days=days,
        data_points=days
    )


def get_azure_disk_change_rate(monitor_client: Any, disk_resource_id: str, disk_size_gb: float, days: int = 7) -> Optional[DataChangeMetrics]:
    """
    Get change rate for an Azure managed disk using Disk Write Bytes metric.

    Note: This is a fallback - prefer get_azure_vm_change_rate() which works for all VMs.

    Metric availability varies by disk type:
    - Premium SSD v2/Ultra: Composite Disk Write Bytes/sec
    - Standard/Premium SSD v1: Limited metrics, often need VM-level metrics instead
    """
    # Try different metric names in order of preference
    metric_names = [
        'Composite Disk Write Bytes/sec',  # Premium SSD v2, Ultra Disk
        'Disk Write Bytes/sec',            # Some disk types
        'DiskWriteBytes',                  # Alternative naming
    ]

    daily_write_bytes = None
    for metric_name in metric_names:
        daily_write_bytes = get_azure_metric_average(
            monitor_client,
            resource_id=disk_resource_id,
            metric_name=metric_name,
            days=days,
            aggregation='Average'
        )
        if daily_write_bytes is not None:
            logger.debug(f"Got disk write metric using {metric_name}")
            break

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


def get_azure_sql_transaction_log_rate(monitor_client: Any, resource_id: str, days: int = 7) -> Optional[TransactionLogMetrics]:
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
        timespan = f"{_isoformat_z(start_time)}/{_isoformat_z(end_time)}"

        response = monitor_client.metrics.list(
            resource_uri=resource_id,
            timespan=timespan,
            interval='P1D',  # 1 day granularity
            metricnames='storage',
            aggregation='Average'
        )

        # Collect (timestamp, value) pairs - MetricValue's real field is
        # `time_stamp` (confirmed against the installed azure-mgmt-monitor SDK's
        # MetricValue._attribute_map: {'time_stamp': {'key': 'timeStamp', ...}}).
        daily_points = []
        for metric in response.value:
            for timeseries in metric.timeseries:
                for data in timeseries.data:
                    value = getattr(data, 'average', None)
                    timestamp = getattr(data, 'time_stamp', None)
                    if value is not None and timestamp is not None:
                        daily_points.append((timestamp, value))

        if len(daily_points) < 2:
            # Need at least 2 data points to calculate delta
            return None

        # Sort chronologically by the real timestamp - NOT by value, which is a
        # different bug (previously `daily_values.sort()` sorted the bare values
        # themselves, silently corrupting the delta for any non-monotonic sample:
        # e.g. readings [100, 150, 80, 130] sort to [80, 100, 130, 150], giving
        # deltas [20, 30, 20] (avg 23.3) instead of the true day-order deltas
        # [50, 0, 50] (avg 33.3) - a ~30% error with no error raised anywhere).
        daily_points.sort(key=lambda point: point[0])
        daily_values = [value for _timestamp, value in daily_points]
        deltas = []
        for i in range(1, len(daily_values)):
            delta = max(0, daily_values[i] - daily_values[i-1])  # Only count growth
            deltas.append(delta)

        if not deltas:
            return None

        # Average daily growth in bytes, convert to GB
        avg_daily_growth_bytes = _steady_state_average(deltas)
        daily_growth_gb = avg_daily_growth_bytes / (1024 ** 3)

        return TransactionLogMetrics(
            daily_generation_gb=daily_growth_gb,
            capture_rate_percent=100.0,
            sample_days=days,
            data_points=len(daily_values)
        )

    except Exception as e:
        check_and_raise_auth_error(e, f"get Azure SQL storage metrics for {resource_id}", "azure")
        logger.warning(f"Error getting Azure SQL storage metrics for {resource_id}: {e}")
        return None


def _azure_metric_latest_value(
    monitor_client: Any,
    resource_uri: str,
    metric_name: str,
    days: int = 3,
    aggregation: str = 'Average',
    interval: str = 'PT1H',
    error_sink: Optional[List[str]] = None,
    metric_filter: Optional[str] = None,
) -> Optional[float]:
    """Return the most recent non-null value for an Azure Monitor metric, or None.

    error_sink, if given, gets the exact failure text appended on error - this
    always logs at WARNING regardless, but callers that aggregate many of these
    calls (e.g. one per file share) can use error_sink to surface a concrete
    example alongside a rollup count instead of relying on the caller having to
    scroll back through potentially thousands of per-resource WARNING lines.

    metric_filter is an OData filter string (e.g. "FileShare eq 'myshare'") used
    to scope the metric to one dimension value.
    """
    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)
        timespan = f"{_isoformat_z(start_time)}/{_isoformat_z(end_time)}"

        response = monitor_client.metrics.list(
            resource_uri=resource_uri,
            timespan=timespan,
            interval=interval,
            metricnames=metric_name,
            aggregation=aggregation,
            filter=metric_filter,
        )

        attr = aggregation.lower()
        for metric in response.value:
            for timeseries in metric.timeseries:
                for data in reversed(timeseries.data):
                    value = getattr(data, attr, None)
                    if value is not None:
                        return value
        if error_sink is not None:
            error_sink.append(f"{metric_name}: metric returned no data points in the last {days}d")
        return None
    except Exception as e:
        check_and_raise_auth_error(e, f"get Azure metric {metric_name} for {resource_uri}", "azure")
        logger.warning(f"Error getting Azure metric {metric_name} for {resource_uri}: {e}")
        if error_sink is not None:
            error_sink.append(f"{metric_name}: {e}")
        return None


def get_azure_storage_account_capacity(
    monitor_client: Any, storage_account_id: str, error_sink: Optional[List[str]] = None
) -> Optional[float]:
    """Get used capacity for an Azure Storage Account from Azure Monitor.

    UsedCapacity is emitted once per day with up to ~24h lag, so we sample a
    3-day window at hourly granularity and take the latest non-null value.

    Returns:
        Used capacity in GB, or None if metric unavailable.
    """
    value = _azure_metric_latest_value(
        monitor_client, storage_account_id, 'UsedCapacity', days=3, aggregation='Average',
        error_sink=error_sink,
    )
    if value is None:
        return None
    return value / (1024 ** 3)


def get_azure_blob_service_metrics(
    monitor_client: Any, storage_account_id: str, error_sink: Optional[List[str]] = None
) -> Dict[str, Optional[float]]:
    """Get blob-service-level metrics (capacity, blob count, container count).

    These are emitted on the /blobServices/default child of the storage account
    and are reported daily. Returns a dict with keys: capacity_gb, blob_count,
    container_count. Values are None when the metric is unavailable.
    """
    blob_uri = f"{storage_account_id}/blobServices/default"
    capacity_bytes = _azure_metric_latest_value(
        monitor_client, blob_uri, 'BlobCapacity', days=3, aggregation='Average', error_sink=error_sink
    )
    blob_count = _azure_metric_latest_value(
        monitor_client, blob_uri, 'BlobCount', days=3, aggregation='Average', error_sink=error_sink
    )
    container_count = _azure_metric_latest_value(
        monitor_client, blob_uri, 'ContainerCount', days=3, aggregation='Average', error_sink=error_sink
    )
    return {
        'capacity_gb': capacity_bytes / (1024 ** 3) if capacity_bytes is not None else None,
        'blob_count': int(blob_count) if blob_count is not None else None,
        'container_count': int(container_count) if container_count is not None else None,
    }


def get_azure_sql_database_capacity(
    monitor_client: Any, database_resource_id: str, error_sink: Optional[List[str]] = None
) -> Optional[float]:
    """
    Get actual used storage for an Azure SQL Database from Azure Monitor.

    The 'storage' metric returns the used data space in bytes.

    Args:
        monitor_client: Azure Monitor client
        database_resource_id: Full resource ID of the SQL database
        error_sink: optional list to append the exact failure text to

    Returns:
        Used storage in GB, or None if metric unavailable
    """
    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=1)  # Just need latest value
        timespan = f"{_isoformat_z(start_time)}/{_isoformat_z(end_time)}"

        response = monitor_client.metrics.list(
            resource_uri=database_resource_id,
            timespan=timespan,
            interval='PT1H',  # 1 hour granularity for recent data
            metricnames='storage',
            aggregation='Average'
        )

        # Get the most recent value
        latest_value = None
        for metric in response.value:
            for timeseries in metric.timeseries:
                for data in reversed(timeseries.data):  # Start from most recent
                    value = getattr(data, 'average', None)
                    if value is not None:
                        latest_value = value
                        break
                if latest_value is not None:
                    break
            if latest_value is not None:
                break

        if latest_value is None:
            if error_sink is not None:
                error_sink.append("storage: metric returned no data points in the last 1d")
            return None

        # Convert bytes to GB
        return latest_value / (1024 ** 3)

    except Exception as e:
        check_and_raise_auth_error(e, f"get Azure SQL database capacity for {database_resource_id}", "azure")
        logger.warning(f"Error getting Azure SQL database capacity for {database_resource_id}: {e}")
        if error_sink is not None:
            error_sink.append(f"storage: {e}")
        return None


def get_azure_sql_managed_instance_capacity(
    monitor_client: Any, mi_resource_id: str, error_sink: Optional[List[str]] = None
) -> Optional[float]:
    """Get actual used storage for an Azure SQL Managed Instance from Azure Monitor.

    storage_space_used_mb has no dimensions - it's emitted at the instance
    level, not per-database, so no summing across databases is needed. Its
    values are megabytes despite the metric's documented Unit of "Count".
    Verified against https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-sql-managedinstances-metrics

    Returns:
        Used storage in GB, or None if metric unavailable.
    """
    value = _azure_metric_latest_value(
        monitor_client, mi_resource_id, 'storage_space_used_mb', days=3, aggregation='Average',
        error_sink=error_sink,
    )
    if value is None:
        return None
    return value / 1024.0


def get_azure_cosmosdb_capacity(
    monitor_client: Any, account_resource_id: str, error_sink: Optional[List[str]] = None
) -> Optional[float]:
    """Get actual used storage (data + index) for a Cosmos DB account from Azure Monitor.

    DataUsage and IndexUsage both carry CollectionName/DatabaseName/Region
    dimensions, but querying without a dimension filter returns the
    pre-aggregated account-wide total, so no per-container enumeration is
    needed. Verified against https://learn.microsoft.com/en-us/azure/cosmos-db/monitor-reference
    (DocumentQuota is the provisioning/quota figure and AvailableStorage is
    deprecated - neither represents actual usage, so neither is used here).

    Returns:
        Used storage (data + index) in GB, or None if both metrics are unavailable.
    """
    data_bytes = _azure_metric_latest_value(
        monitor_client, account_resource_id, 'DataUsage', days=3, aggregation='Total',
        error_sink=error_sink,
    )
    index_bytes = _azure_metric_latest_value(
        monitor_client, account_resource_id, 'IndexUsage', days=3, aggregation='Total',
        error_sink=error_sink,
    )
    if data_bytes is None and index_bytes is None:
        return None
    return ((data_bytes or 0) + (index_bytes or 0)) / (1024 ** 3)


def get_azure_flexible_server_storage_used(
    monitor_client: Any, server_resource_id: str, error_sink: Optional[List[str]] = None
) -> Optional[float]:
    """Get actual used storage for a PostgreSQL/MySQL flexible server from Azure Monitor.

    'storage_used' (bytes) is the identical metric name on both
    Microsoft.DBforPostgreSQL/flexibleServers and Microsoft.DBforMySQL/flexibleServers,
    verified against each resource type's "Supported metrics" reference page -
    shared by both callers rather than duplicated.

    Returns:
        Used storage in GB, or None if metric unavailable.
    """
    value = _azure_metric_latest_value(
        monitor_client, server_resource_id, 'storage_used', days=3, aggregation='Average',
        error_sink=error_sink,
    )
    if value is None:
        return None
    return value / (1024 ** 3)


def get_azure_redis_used_memory(
    monitor_client: Any, cache_resource_id: str, error_sink: Optional[List[str]] = None
) -> Optional[float]:
    """Get actual used memory for a non-clustered Azure Cache for Redis instance.

    Callers must only use this for shard_count == 0 caches: Monitor's docs
    confirm 'usedmemory' has a ShardId dimension but don't state whether the
    unfiltered account-level value sums across shards - the docs' one
    explicit clustered-aggregation caution (Total Keys) says clustered
    metrics return the max shard, not a true total, so assuming sum-across-
    shards here without confirmation would repeat the exact mistake this
    audit exists to catch. Verified against
    https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-cache-redis-metrics

    Returns:
        Used memory in GB, or None if metric unavailable.
    """
    value = _azure_metric_latest_value(
        monitor_client, cache_resource_id, 'usedmemory', days=3, aggregation='Maximum',
        error_sink=error_sink,
    )
    if value is None:
        return None
    return value / (1024 ** 3)


def get_azure_netapp_volume_usage(
    monitor_client: Any, volume_resource_id: str, error_sink: Optional[List[str]] = None
) -> Optional[float]:
    """Get actual logical (used) size for an Azure NetApp Files volume from Azure Monitor.

    VolumeLogicalSize is "used bytes" (includes active file system + snapshots),
    distinct from VolumeAllocatedSize (the provisioned quota - the SDK's
    usage_threshold field). Verified against
    https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-netapp-netappaccounts-capacitypools-volumes-metrics

    Returns:
        Used size in GB, or None if metric unavailable.
    """
    value = _azure_metric_latest_value(
        monitor_client, volume_resource_id, 'VolumeLogicalSize', days=1, aggregation='Average',
        error_sink=error_sink,
    )
    if value is None:
        return None
    return value / (1024 ** 3)


# ============================================================================
# GCP Cloud Monitoring Change Rate Collection
# ============================================================================

def get_gcp_monitoring_client(project_id: str) -> Optional[Any]:
    """Get GCP Cloud Monitoring client."""
    try:
        from google.cloud import monitoring_v3
        return monitoring_v3.MetricServiceClient()
    except ImportError:
        logger.warning("google-cloud-monitoring not installed, change rate collection unavailable")
        return None


def get_gcp_metric_average(
    monitoring_client: Any,
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

        daily_values = []

        for time_series in results:
            for point in time_series.points:
                value = point.value.double_value or point.value.int64_value
                if value:
                    daily_values.append(value)

        if not daily_values:
            return None

        return _steady_state_average(daily_values)

    except Exception as e:
        check_and_raise_auth_error(e, f"get GCP metric {metric_type}", "gcp")
        logger.warning(f"Error getting GCP metric {metric_type}: {e}")
        return None


def get_gcp_disk_change_rate(monitoring_client: Any, project_id: str, disk_name: str, zone: str, disk_size_gb: float, days: int = 7) -> Optional[DataChangeMetrics]:
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


def compute_dcr_from_snapshot_deltas(
    snapshot_points: List[Tuple[Union[datetime, str], float]],
    base_size_gb: float,
) -> Optional[DataChangeMetrics]:
    """Derive a real, measured Daily Change Rate from a source resource's own
    snapshot history, rather than a live write-throughput metric.

    This is a genuinely different (and, where the underlying snapshot data
    supports it, arguably better) DCR signal than every other function in this
    module: `get_ebs_volume_change_rate`/`get_azure_vm_change_rate`/
    `get_gcp_disk_change_rate` etc. all estimate DCR from raw write bytes/IOPS,
    which has no concept of deduplication and overcounts any workload that
    rewrites the same blocks repeatedly (DB page updates, swap, in-place log
    rotation). A snapshot chain's own incremental storage growth - each
    snapshot's real, already-deduplicated stored footprint since the prior one -
    is a direct measurement of how much *unique* data actually changed, which is
    much closer to what a backup product's incremental capture would see.

    Today this is only meaningfully wireable for GCP disk snapshots
    (`gcp:compute:snapshot`'s `storage_bytes` is genuinely incremental/dedup-aware
    per the installed google-cloud-compute SDK's own field docs - see
    lib/gcp/compute.py's collect_disk_snapshots()). AWS EBS/RDS snapshots and
    Azure disk/SQL snapshots do not yet have a real per-snapshot incremental-size
    field wired up (size_gb is 0.0/'unavailable' for those today - see the
    "Deferred" tables in docs/v2-refactor-plan.md) - feeding zeros through this
    function would just always yield 0% change, so it isn't wired in for those
    clouds yet. Revisit once/if real incremental snapshot sizing lands there.

    Args:
        snapshot_points: (timestamp, incremental_size_gb) pairs, one per
            snapshot in the source resource's chain, in ANY order (sorted
            internally). Timestamps may be datetime objects or ISO-8601 strings
            (GCP's `creation_timestamp` is a string).
        base_size_gb: the source resource's own total size, for the percentage.

    Returns:
        DataChangeMetrics with daily_change_gb/daily_change_percent, or None if
        fewer than 2 snapshots are given (no elapsed period to measure across).
    """
    if len(snapshot_points) < 2:
        return None

    def _as_datetime(value: Union[datetime, str]) -> datetime:
        if isinstance(value, datetime):
            return value
        # GCP's creation_timestamp is RFC3339, e.g. "2026-01-15T08:00:00.123-08:00"
        return datetime.fromisoformat(str(value).replace('Z', '+00:00'))

    points = sorted(
        ((_as_datetime(ts), size_gb) for ts, size_gb in snapshot_points),
        key=lambda p: p[0]
    )

    elapsed = points[-1][0] - points[0][0]
    elapsed_days = max(elapsed.total_seconds() / 86400, 1.0)  # floor at 1 day - avoid divide-by-zero for same-day snapshots

    # Sum every snapshot's own incremental footprint across the whole window
    # (including the first one - it's still real, measured stored bytes
    # attributable to this chain during the sample period, not a baseline to
    # discard) and spread it evenly across the elapsed period.
    total_incremental_gb = sum(size_gb for _ts, size_gb in points)
    daily_change_gb = total_incremental_gb / elapsed_days
    daily_change_percent = (daily_change_gb / base_size_gb * 100) if base_size_gb > 0 else None

    return DataChangeMetrics(
        daily_change_gb=daily_change_gb,
        daily_change_percent=daily_change_percent,
        sample_days=round(elapsed_days, 1),
        data_points=len(points),
    )


def get_cloudsql_change_rate(monitoring_client: Any, project_id: str, instance_id: str, disk_size_gb: float, days: int = 7) -> Optional[DataChangeMetrics]:
    """
    Get change rate for a Cloud SQL instance using disk write metrics.

    NOTE on `daily_change_percent`: this is currently ALWAYS None for Cloud SQL.
    `disk_size_gb` here is `resource.size_gb`, and Cloud SQL instances deliberately
    always report `size_gb=0.0`/`size_source='unavailable'` (no verified real-usage
    Cloud Monitoring metric exists yet for Cloud SQL storage - see the "Deferred"
    table in docs/v2-refactor-plan.md) - so the `disk_size_gb > 0` guard below can
    never pass. This is NOT a bug in this function: `daily_change_gb` (the absolute
    measured write volume) is still real and returned as-is; only the percentage,
    which structurally needs a real total-size denominator this collector doesn't
    have yet, is honestly left unset rather than divided against a value known to
    be zero. Wiring up real Cloud SQL storage usage is separate, already-deferred
    work (would also fix this) - don't "fix" this by substituting an
    allocated/provisioned capacity value here; that would violate the same
    real-usage-only policy that zeroed size_gb in the first place.
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
    notes = [
        "Data change rates are estimates based on write throughput metrics",
        "Transaction log rates apply to database services (always 100% capture)",
        "Use these values to override default DCR assumptions in sizing tools",
    ]
    # S3 has no write-throughput metric at all (confirmed: AWS/S3's only
    # always-available CloudWatch metrics are BucketSizeBytes/NumberOfObjects,
    # both daily snapshots, not deltas). get_s3_change_rate() estimates DCR from
    # NumberOfObjects deltas - a weaker proxy than every other service here,
    # since it's blind to any write that doesn't change the object COUNT (an
    # in-place overwrite of an existing key looks like zero change). A better
    # metric (BytesUploaded) exists but requires the customer to have already
    # opted into paid S3 request metrics AND a metrics-configuration FilterId
    # this tool doesn't have - not wired up; flagged here instead.
    if any(summary.service_family == 'S3' for summary in summaries.values()):
        notes.append(
            "S3 change rate is estimated from NumberOfObjects deltas, not actual bytes written - "
            "it will under-report change for buckets where existing objects are overwritten in "
            "place (object count unchanged, content changed). Treat S3 DCR values as a lower bound"
        )

    return {
        "change_rates": {
            key: summary.to_dict()
            for key, summary in summaries.items()
        },
        "collection_metadata": {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "sample_period_days": 7,
            "notes": notes,
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

    notes = [
        f'Data change rates are estimates based on {provider_note} write throughput metrics',
        'Transaction log rates apply to database services (always 100% capture)',
        'Use these values to override default DCR assumptions in sizing tools',
    ]
    # See get_s3_change_rate()'s docstring - S3 has no write-throughput metric
    # at all, so its DCR is estimated from NumberOfObjects deltas, a weaker
    # proxy than every other service here (blind to same-key overwrites).
    if any(summary.get('service_family') == 'S3' for summary in all_change_rates.values()):
        notes.append(
            "S3 change rate is estimated from NumberOfObjects deltas, not actual bytes written - "
            "it will under-report change for buckets where existing objects are overwritten in "
            "place (object count unchanged, content changed). Treat S3 DCR values as a lower bound"
        )

    return {
        'change_rates': all_change_rates,
        'collection_metadata': {
            'collected_at': datetime.now(timezone.utc).isoformat(),
            'sample_period_days': sample_days,
            'notes': notes,
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
    for _key, summary in merged['change_rates'].items():
        if 'data_change' in summary and summary.get('total_size_gb', 0) > 0:
            daily_gb = summary['data_change'].get('daily_change_gb', 0)
            total_gb = summary['total_size_gb']
            summary['data_change']['daily_change_percent'] = (daily_gb / total_gb) * 100

    if merged['has_actual_data']:
        logger.info(f"Loaded change rates for {len(merged['change_rates'])} service families from {len(paths)} file(s)")

    return merged
