"""
CCA CloudShell shared library.
"""
# Import constants module for easy access
from . import constants
from .change_rate import (
    ChangeRateSummary,
    DataChangeMetrics,
    TransactionLogMetrics,
    aggregate_change_rates,
    finalize_change_rate_output,
    format_change_rate_output,
    get_aws_cloudwatch_client,
    get_azure_disk_change_rate,
    get_azure_monitor_client,
    get_azure_sql_transaction_log_rate,
    get_cloudsql_change_rate,
    get_ebs_volume_change_rate,
    get_gcp_disk_change_rate,
    get_gcp_monitoring_client,
    get_rds_transaction_log_rate,
    get_rds_write_iops_change_rate,
    get_s3_change_rate,
    merge_change_rates,
)
from .constants import (
    # Byte conversion
    BYTES_PER_GB,
    BYTES_PER_KB,
    BYTES_PER_MB,
    BYTES_PER_TB,
    DEFAULT_PARALLEL_WORKERS,
    DEFAULT_RETRY_ATTEMPTS,
    # Default values
    DEFAULT_SAMPLE_DAYS,
    # Providers
    PROVIDER_AWS,
    PROVIDER_AZURE,
    PROVIDER_GCP,
    PROVIDER_M365,
    # Time constants
    SECONDS_PER_DAY,
    SECONDS_PER_HOUR,
    bytes_to_gb,
    bytes_to_tb,
)
from .k8s import (
    PVCInfo,
    collect_aks_pvcs,
    collect_eks_pvcs,
    collect_gke_pvcs,
    collect_pvcs_from_cluster,
    get_k8s_client,
    parse_k8s_storage_size,
)
from .models import CloudResource, SizingSummary
from .utils import (
    format_bytes_to_gb,
    generate_run_id,
    get_timestamp,
    setup_logging,
    tags_to_dict,
    write_csv,
    write_json,
)

__all__ = [
    # Constants
    'constants',
    'BYTES_PER_GB',
    'BYTES_PER_KB',
    'BYTES_PER_MB',
    'BYTES_PER_TB',
    'SECONDS_PER_DAY',
    'SECONDS_PER_HOUR',
    'DEFAULT_SAMPLE_DAYS',
    'DEFAULT_PARALLEL_WORKERS',
    'DEFAULT_RETRY_ATTEMPTS',
    'PROVIDER_AWS',
    'PROVIDER_AZURE',
    'PROVIDER_GCP',
    'PROVIDER_M365',
    'bytes_to_gb',
    'bytes_to_tb',
    # Models
    'CloudResource',
    'SizingSummary',
    # Utils
    'generate_run_id',
    'get_timestamp',
    'format_bytes_to_gb',
    'tags_to_dict',
    'write_json',
    'write_csv',
    'setup_logging',
    # Change rate exports
    'DataChangeMetrics',
    'TransactionLogMetrics',
    'ChangeRateSummary',
    'aggregate_change_rates',
    'format_change_rate_output',
    'merge_change_rates',
    'finalize_change_rate_output',
    'get_aws_cloudwatch_client',
    'get_ebs_volume_change_rate',
    'get_rds_transaction_log_rate',
    'get_rds_write_iops_change_rate',
    'get_s3_change_rate',
    'get_azure_monitor_client',
    'get_azure_disk_change_rate',
    'get_azure_sql_transaction_log_rate',
    'get_gcp_monitoring_client',
    'get_gcp_disk_change_rate',
    'get_cloudsql_change_rate',
    # K8s PVC exports
    'PVCInfo',
    'parse_k8s_storage_size',
    'get_k8s_client',
    'collect_pvcs_from_cluster',
    'collect_eks_pvcs',
    'collect_aks_pvcs',
    'collect_gke_pvcs',
]
