"""
CCA CloudShell shared library.
"""
from .models import CloudResource, SizingSummary
from .utils import (
    generate_run_id,
    get_timestamp,
    format_bytes_to_gb,
    tags_to_dict,
    write_json,
    write_csv,
    setup_logging
)
from .change_rate import (
    DataChangeMetrics,
    TransactionLogMetrics,
    ChangeRateSummary,
    aggregate_change_rates,
    format_change_rate_output,
    get_aws_cloudwatch_client,
    get_ebs_volume_change_rate,
    get_rds_transaction_log_rate,
    get_rds_write_iops_change_rate,
    get_s3_change_rate,
    get_azure_monitor_client,
    get_azure_disk_change_rate,
    get_azure_sql_transaction_log_rate,
    get_gcp_monitoring_client,
    get_gcp_disk_change_rate,
    get_cloudsql_change_rate
)

__all__ = [
    'CloudResource',
    'SizingSummary',
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
]
