#!/usr/bin/env python3
"""
CCA CloudShell - Cost Collector

Collects backup and snapshot costs from cloud billing APIs.
Supports AWS Cost Explorer, Azure Cost Management, and GCP BigQuery billing.

Usage:
    # AWS costs
    python3 cost_collect.py --aws
    python3 cost_collect.py --aws --start-date 2026-01-01 --end-date 2026-02-01
    
    # Azure costs
    python3 cost_collect.py --azure --subscription-id xxx
    
    # GCP costs (requires BigQuery billing export)
    python3 cost_collect.py --gcp --project my-project --billing-table project.dataset.table
    
    # All clouds
    python3 cost_collect.py --all
"""
import argparse
import json
import logging
import sys
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict

# Add lib to path for imports
sys.path.insert(0, '.')
from lib.utils import (
    generate_run_id, get_timestamp, write_json, write_csv, setup_logging
)

logger = logging.getLogger(__name__)


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class CostRecord:
    """Represents a cost record for a service/category."""
    provider: str
    account_id: str
    service: str
    category: str  # backup, snapshot, storage
    cost: float
    currency: str
    period_start: str
    period_end: str
    usage_quantity: Optional[float] = None
    usage_unit: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if d['metadata'] is None:
            del d['metadata']
        if d['usage_quantity'] is None:
            del d['usage_quantity']
        if d['usage_unit'] is None:
            del d['usage_unit']
        return d


@dataclass
class CostSummary:
    """Aggregated cost summary by category."""
    provider: str
    category: str
    total_cost: float
    currency: str
    service_breakdown: Dict[str, float]
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =============================================================================
# Date Helpers
# =============================================================================

def get_last_full_month() -> tuple:
    """
    Return start and end dates for the last complete month.
    
    Returns:
        Tuple of (start_date, end_date) as YYYY-MM-DD strings
        
    Example:
        If today is 2026-02-13, returns ('2026-01-01', '2026-02-01')
        Note: end_date is exclusive (first day of current month)
    """
    today = datetime.now(timezone.utc)
    # First day of current month
    first_of_this_month = today.replace(day=1)
    # Last day of previous month
    last_of_prev_month = first_of_this_month - timedelta(days=1)
    # First day of previous month
    first_of_prev_month = last_of_prev_month.replace(day=1)
    
    return (
        first_of_prev_month.strftime('%Y-%m-%d'),
        first_of_this_month.strftime('%Y-%m-%d')  # exclusive end date
    )


# =============================================================================
# AWS Cost Explorer
# =============================================================================

# Backup and snapshot related usage types
# Reference: https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/ce-default-reports.html
AWS_BACKUP_FILTERS = {
    'services': [
        'AWS Backup',
        'EC2 - Other',  # Contains EBS snapshot costs
        'Amazon Elastic Block Store',
        'Amazon RDS',
        'Amazon S3',  # S3 backup storage
        'Amazon EFS',  # EFS backup
        'Amazon FSx',  # FSx backup
        'Amazon DynamoDB',  # DynamoDB backup
    ],
    'usage_types': [
        # EBS Snapshots
        'SnapshotUsage',
        'TimedStorage-Snapshot',
        # AWS Backup vault storage (warm)
        'WarmStorage',
        'BackupStorage',
        'Storage-ByteHrs',
        # AWS Backup vault storage (cold) 
        'ColdStorage',
        # AWS Backup general
        'Backup',
        'ChargedBackupUsage',
        'BackupUsage',
        'VaultStorage',
        # RDS automated backups
        'BackupStorage',
        'ChargedBackup',
        # EFS backup via AWS Backup
        'EFS-Backup',
        'EFS-ByteHrs-Backup',
        # FSx backup via AWS Backup
        'FSx-Backup',
        'FSxBackup',
        # Catches region-prefixed usage types like "USE1-BackupStorage"
    ]
}


def collect_aws_costs(
    session,
    start_date: str,
    end_date: str,
    account_id: str,
    group_by_account: bool = False
) -> List[CostRecord]:
    """
    Collect backup and snapshot costs from AWS Cost Explorer.
    
    Args:
        session: boto3 session
        start_date: Start date (YYYY-MM-DD)
        end_date: End date (YYYY-MM-DD)
        account_id: AWS account ID (management account for orgs)
        group_by_account: If True, break down costs by LINKED_ACCOUNT (for Organizations)
    
    Returns:
        List of CostRecord objects
    """
    records = []
    
    try:
        ce = session.client('ce', region_name='us-east-1')  # Cost Explorer is global
        
        # AWS Cost Explorer only allows 2 GroupBy dimensions
        # When grouping by account, we use LINKED_ACCOUNT + SERVICE
        # Otherwise, we use SERVICE + USAGE_TYPE for more granular filtering
        if group_by_account:
            group_by = [
                {'Type': 'DIMENSION', 'Key': 'LINKED_ACCOUNT'},
                {'Type': 'DIMENSION', 'Key': 'SERVICE'}
            ]
            logger.info("Grouping costs by linked account (Organizations mode)")
        else:
            group_by = [
                {'Type': 'DIMENSION', 'Key': 'SERVICE'},
                {'Type': 'DIMENSION', 'Key': 'USAGE_TYPE'}
            ]
        
        # Query for backup-related services
        response = ce.get_cost_and_usage(
            TimePeriod={
                'Start': start_date,
                'End': end_date
            },
            Granularity='MONTHLY',
            Filter={
                'Dimensions': {
                    'Key': 'SERVICE',
                    'Values': AWS_BACKUP_FILTERS['services']
                }
            },
            Metrics=['UnblendedCost', 'UsageQuantity'],
            GroupBy=group_by
        )
        
        for result in response.get('ResultsByTime', []):
            period_start = result['TimePeriod']['Start']
            period_end = result['TimePeriod']['End']
            
            for group in result.get('Groups', []):
                keys = group.get('Keys', [])
                
                # Parse keys based on grouping mode
                if group_by_account:
                    if len(keys) < 2:
                        continue
                    linked_account = keys[0]
                    service = keys[1]
                    usage_type = None  # Not available in org mode
                else:
                    if len(keys) < 2:
                        continue
                    linked_account = account_id  # Use caller's account
                    service = keys[0]
                    usage_type = keys[1]
                
                # Filter to backup/snapshot related usage types (only when usage_type is available)
                if usage_type:
                    is_backup_related = any(
                        bt.lower() in usage_type.lower() 
                        for bt in AWS_BACKUP_FILTERS['usage_types']
                    )
                    
                    if not is_backup_related:
                        continue
                
                metrics = group.get('Metrics', {})
                cost = float(metrics.get('UnblendedCost', {}).get('Amount', 0))
                usage_qty = float(metrics.get('UsageQuantity', {}).get('Amount', 0))
                usage_unit = metrics.get('UsageQuantity', {}).get('Unit', '')
                
                if cost == 0:
                    continue
                
                # Categorize
                category = categorize_aws_usage(service, usage_type or '')
                
                record = CostRecord(
                    provider='aws',
                    account_id=linked_account,
                    service=service,
                    category=category,
                    cost=round(cost, 2),
                    currency='USD',
                    period_start=period_start,
                    period_end=period_end,
                    usage_quantity=round(usage_qty, 2) if usage_qty else None,
                    usage_unit=usage_unit if usage_unit else None,
                    metadata={'usage_type': usage_type} if usage_type else None
                )
                records.append(record)
        
        logger.info(f"Collected {len(records)} AWS cost records")
        
    except Exception as e:
        logger.error(f"Failed to collect AWS costs: {e}")
        raise
    
    return records


def categorize_aws_usage(service: str, usage_type: str) -> str:
    """Categorize AWS usage type into backup, snapshot, or storage."""
    usage_lower = usage_type.lower()
    service_lower = service.lower()
    
    if 'snapshot' in usage_lower:
        return 'snapshot'
    elif 'backup' in usage_lower or 'vault' in usage_lower:
        return 'backup'
    elif 'aws backup' in service_lower:
        return 'backup'
    elif 'efs' in service_lower and 'backup' in usage_lower:
        return 'efs_backup'
    elif 'fsx' in service_lower and 'backup' in usage_lower:
        return 'fsx_backup'
    else:
        return 'storage'


# =============================================================================
# Azure Cost Management
# =============================================================================

AZURE_BACKUP_FILTERS = {
    'service_names': [
        'Azure Backup',
        'Storage',
        'Azure Site Recovery',
        'Azure NetApp Files',  # NetApp Files backup/snapshot costs
    ],
    'meter_categories': [
        'Backup',
        'Storage',
        'Site Recovery',
        'Azure NetApp Files',  # NetApp snapshot/replication costs
    ]
}


def collect_azure_costs(
    credential,
    subscription_id: str,
    start_date: str,
    end_date: str
) -> List[CostRecord]:
    """
    Collect backup and snapshot costs from Azure Cost Management.
    
    Args:
        credential: Azure credential
        subscription_id: Azure subscription ID
        start_date: Start date (YYYY-MM-DD)
        end_date: End date (YYYY-MM-DD)
    
    Returns:
        List of CostRecord objects
    """
    records = []
    
    try:
        from azure.mgmt.costmanagement import CostManagementClient
        from azure.mgmt.costmanagement.models import (
            QueryDefinition,
            QueryTimePeriod,
            QueryDataset,
            QueryAggregation,
            QueryGrouping,
            QueryFilter,
            QueryComparisonExpression,
        )
        
        client = CostManagementClient(credential, subscription_id)
        scope = f"/subscriptions/{subscription_id}"
        
        # Parse dates to datetime objects for the SDK
        from_date = datetime.strptime(start_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        to_date = datetime.strptime(end_date, "%Y-%m-%d").replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
        
        # Query for backup-related costs using the proper models
        query = QueryDefinition(
            type="ActualCost",
            timeframe="Custom",
            time_period=QueryTimePeriod(
                from_property=from_date,
                to=to_date
            ),
            dataset=QueryDataset(
                granularity="Monthly",
                aggregation={
                    "totalCost": QueryAggregation(name="Cost", function="Sum"),
                    "totalQuantity": QueryAggregation(name="Quantity", function="Sum")
                },
                grouping=[
                    QueryGrouping(type="Dimension", name="ServiceName"),
                    QueryGrouping(type="Dimension", name="MeterCategory")
                ],
                filter=QueryFilter(
                    or_property=[
                        QueryFilter(
                            dimensions=QueryComparisonExpression(
                                name="ServiceName",
                                operator="In",
                                values=AZURE_BACKUP_FILTERS['service_names']
                            )
                        ),
                        QueryFilter(
                            dimensions=QueryComparisonExpression(
                                name="MeterCategory",
                                operator="In",
                                values=AZURE_BACKUP_FILTERS['meter_categories']
                            )
                        )
                    ]
                )
            )
        )
        
        result = client.query.usage(scope=scope, parameters=query)
        
        # Parse results (with null checks)
        if result is None or result.columns is None or result.rows is None:
            logger.warning("No cost data returned from Azure")
            return records
            
        columns = [col.name for col in result.columns]
        
        for row in result.rows:
            row_dict = dict(zip(columns, row))
            
            cost = float(row_dict.get('Cost', 0))
            if cost == 0:
                continue
            
            service = row_dict.get('ServiceName', 'Unknown')
            meter_category = row_dict.get('MeterCategory', '')
            
            # Categorize
            category = categorize_azure_cost(service, meter_category)
            
            record = CostRecord(
                provider='azure',
                account_id=subscription_id,
                service=service,
                category=category,
                cost=round(cost, 2),
                currency=row_dict.get('Currency', 'USD'),
                period_start=start_date,
                period_end=end_date,
                usage_quantity=float(row_dict.get('Quantity', 0)) if row_dict.get('Quantity') else None,
                metadata={'meter_category': meter_category}
            )
            records.append(record)
        
        logger.info(f"Collected {len(records)} Azure cost records")
        
    except ImportError:
        logger.error("Azure Cost Management SDK not installed. Run: pip install azure-mgmt-costmanagement")
        raise
    except Exception as e:
        logger.error(f"Failed to collect Azure costs: {e}")
        raise
    
    return records


def categorize_azure_cost(service: str, meter_category: str) -> str:
    """Categorize Azure cost into backup, snapshot, or storage."""
    service_lower = service.lower()
    meter_lower = meter_category.lower()
    
    if 'backup' in service_lower or 'backup' in meter_lower:
        return 'backup'
    elif 'snapshot' in meter_lower:
        return 'snapshot'
    elif 'site recovery' in service_lower:
        return 'backup'
    elif 'netapp' in service_lower or 'netapp' in meter_lower:
        # NetApp Files has its own backup/snapshot features
        if 'snapshot' in meter_lower or 'backup' in meter_lower:
            return 'netapp_backup'
        return 'netapp_storage'
    else:
        return 'storage'


# =============================================================================
# GCP BigQuery Billing
# =============================================================================

GCP_BACKUP_FILTERS = {
    'services': [
        'Compute Engine',
        'Cloud Storage',
        'Cloud SQL',
        'Backup and DR Service',
    ],
    'sku_keywords': [
        'snapshot',
        'backup',
        'nearline',
        'coldline',
        'archive',
    ]
}


def collect_gcp_costs(
    project_id: str,
    billing_table: str,
    start_date: str,
    end_date: str
) -> List[CostRecord]:
    """
    Collect backup and snapshot costs from GCP BigQuery billing export.
    
    Args:
        project_id: GCP project ID
        billing_table: Full BigQuery table path (project.dataset.table)
        start_date: Start date (YYYY-MM-DD)
        end_date: End date (YYYY-MM-DD)
    
    Returns:
        List of CostRecord objects
    """
    records = []
    
    try:
        from google.cloud import bigquery
        
        client = bigquery.Client(project=project_id)
        
        # Validate billing_table format to prevent injection
        # Expected format: project.dataset.table or project.dataset.table_*
        import re
        if not re.match(r'^[\w-]+\.[\w-]+\.[\w-]+\*?$', billing_table):
            raise ValueError(
                f"Invalid billing_table format: {billing_table}. "
                "Expected format: project.dataset.table"
            )
        
        # Build service filter using parameterized query
        # Note: BigQuery doesn't support parameterized table names, but we validated above
        # Services and SKU keywords are from our controlled constant
        # Escape special LIKE characters (%, _, \) in keywords for safety
        def escape_like_pattern(s: str) -> str:
            return s.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        
        services_filter = ', '.join([f"'{s}'" for s in GCP_BACKUP_FILTERS['services']])
        sku_conditions = ' OR '.join([
            f"LOWER(sku.description) LIKE '%{escape_like_pattern(kw)}%'" 
            for kw in GCP_BACKUP_FILTERS['sku_keywords']
        ])
        
        # Use parameterized query for user-provided date values
        query = f"""
        SELECT
            project.id as project_id,
            service.description as service,
            sku.description as sku,
            SUM(cost) as cost,
            currency,
            SUM(usage.amount) as usage_amount,
            usage.unit as usage_unit,
            FORMAT_DATE('%Y-%m-%d', DATE(usage_start_time)) as period_start,
            FORMAT_DATE('%Y-%m-%d', DATE(usage_end_time)) as period_end
        FROM `{billing_table}`
        WHERE 
            DATE(usage_start_time) >= @start_date
            AND DATE(usage_end_time) <= @end_date
            AND service.description IN ({services_filter})
            AND ({sku_conditions})
        GROUP BY 
            project.id, 
            service.description, 
            sku.description, 
            currency,
            usage.unit,
            DATE(usage_start_time),
            DATE(usage_end_time)
        HAVING cost > 0
        ORDER BY cost DESC
        """
        
        # Configure query parameters for dates
        job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("start_date", "DATE", start_date),
                bigquery.ScalarQueryParameter("end_date", "DATE", end_date),
            ]
        )
        
        query_job = client.query(query, job_config=job_config)
        results = query_job.result()
        
        for row in results:
            category = categorize_gcp_cost(row.service, row.sku)
            
            record = CostRecord(
                provider='gcp',
                account_id=row.project_id,
                service=row.service,
                category=category,
                cost=round(float(row.cost), 2),
                currency=row.currency,
                period_start=row.period_start,
                period_end=row.period_end,
                usage_quantity=round(float(row.usage_amount), 2) if row.usage_amount else None,
                usage_unit=row.usage_unit,
                metadata={'sku': row.sku}
            )
            records.append(record)
        
        logger.info(f"Collected {len(records)} GCP cost records")
        
    except ImportError:
        logger.error("Google Cloud BigQuery SDK not installed. Run: pip install google-cloud-bigquery")
        raise
    except Exception as e:
        logger.error(f"Failed to collect GCP costs: {e}")
        raise
    
    return records


def categorize_gcp_cost(service: str, sku: str) -> str:
    """Categorize GCP cost into backup, snapshot, or storage."""
    sku_lower = sku.lower()
    
    if 'snapshot' in sku_lower:
        return 'snapshot'
    elif 'backup' in sku_lower or 'Backup and DR' in service:
        return 'backup'
    else:
        return 'storage'


# =============================================================================
# Aggregation
# =============================================================================

def aggregate_costs(records: List[CostRecord]) -> List[CostSummary]:
    """Aggregate cost records into summaries by provider and category."""
    summaries = {}
    
    for record in records:
        key = (record.provider, record.category, record.currency)
        
        if key not in summaries:
            summaries[key] = {
                'provider': record.provider,
                'category': record.category,
                'total_cost': 0,
                'currency': record.currency,
                'service_breakdown': {}
            }
        
        summaries[key]['total_cost'] += record.cost
        
        service = record.service
        if service not in summaries[key]['service_breakdown']:
            summaries[key]['service_breakdown'][service] = 0
        summaries[key]['service_breakdown'][service] += record.cost
    
    # Round totals
    result = []
    for data in summaries.values():
        data['total_cost'] = round(data['total_cost'], 2)
        data['service_breakdown'] = {
            k: round(v, 2) for k, v in data['service_breakdown'].items()
        }
        result.append(CostSummary(**data))
    
    return sorted(result, key=lambda x: (x.provider, x.category))


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='CCA CloudShell - Cost Collector for Backup & Snapshot Spending',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # AWS costs for last full month (default)
  python3 cost_collect.py --aws

  # AWS with custom date range
  python3 cost_collect.py --aws --start-date 2026-01-01 --end-date 2026-02-01

  # AWS Organizations - break down costs by member account
  python3 cost_collect.py --aws --org-costs

  # Azure costs
  python3 cost_collect.py --azure --subscription-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

  # GCP costs (requires BigQuery billing export)
  python3 cost_collect.py --gcp --project my-project --billing-table project.dataset.gcp_billing

  # All clouds
  python3 cost_collect.py --all --subscription-id xxx --billing-table xxx
"""
    )
    
    # Cloud selection
    parser.add_argument('--aws', action='store_true', help='Collect AWS costs')
    parser.add_argument('--azure', action='store_true', help='Collect Azure costs')
    parser.add_argument('--gcp', action='store_true', help='Collect GCP costs')
    parser.add_argument('--all', action='store_true', help='Collect from all configured clouds')
    
    # Date range - default to last full month
    default_start, default_end = get_last_full_month()
    
    parser.add_argument('--start-date', default=default_start,
                        help=f'Start date YYYY-MM-DD (default: {default_start} - last full month)')
    parser.add_argument('--end-date', default=default_end,
                        help=f'End date YYYY-MM-DD (default: {default_end} - exclusive)')
    parser.add_argument('--last-30-days', action='store_true',
                        help='Use last 30 days instead of last full month')
    
    # AWS options
    parser.add_argument('--profile', help='AWS profile name')
    parser.add_argument('--role-arn', help='AWS role ARN to assume')
    parser.add_argument('--org-costs', action='store_true',
                        help='Break down costs by linked account (for AWS Organizations)')
    
    # Azure options
    parser.add_argument('--subscription-id', help='Azure subscription ID')
    
    # GCP options
    parser.add_argument('--project', help='GCP project ID')
    parser.add_argument('--billing-table', help='GCP BigQuery billing table (project.dataset.table)')
    
    # Output options
    parser.add_argument('-o', '--output', default='.', help='Output directory')
    parser.add_argument('--log-level', default='INFO', help='Logging level')
    
    args = parser.parse_args()
    setup_logging(args.log_level)
    
    # Handle --last-30-days override
    if args.last_30_days:
        args.end_date = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        args.start_date = (datetime.now(timezone.utc) - timedelta(days=30)).strftime('%Y-%m-%d')
        logger.info(f"Using last 30 days: {args.start_date} to {args.end_date}")
    
    # Validate at least one cloud selected
    if not (args.aws or args.azure or args.gcp or args.all):
        parser.error("Must specify at least one of: --aws, --azure, --gcp, --all")
    
    all_records: List[CostRecord] = []
    collected_providers = []
    
    # AWS Collection
    if args.aws or args.all:
        try:
            import boto3
            from botocore.exceptions import ClientError
            
            session = boto3.Session(profile_name=args.profile)
            
            # Handle role assumption if specified
            if args.role_arn:
                sts = session.client('sts')
                response = sts.assume_role(
                    RoleArn=args.role_arn,
                    RoleSessionName='CCACloudShellCost'
                )
                creds = response['Credentials']
                session = boto3.Session(
                    aws_access_key_id=creds['AccessKeyId'],
                    aws_secret_access_key=creds['SecretAccessKey'],
                    aws_session_token=creds['SessionToken']
                )
            
            account_id = session.client('sts').get_caller_identity()['Account']
            
            logger.info(f"Collecting AWS costs for account {account_id}")
            logger.info(f"Period: {args.start_date} to {args.end_date}")
            
            records = collect_aws_costs(
                session, 
                args.start_date, 
                args.end_date, 
                account_id,
                group_by_account=args.org_costs
            )
            all_records.extend(records)
            collected_providers.append('aws')
            
        except ImportError:
            logger.warning("boto3 not installed, skipping AWS")
        except Exception as e:
            logger.error(f"AWS collection failed: {e}")
            if not args.all:
                raise
    
    # Azure Collection
    if args.azure or args.all:
        if not args.subscription_id and args.azure:
            parser.error("--subscription-id required for Azure")
        
        if args.subscription_id:
            try:
                from azure.identity import DefaultAzureCredential
                
                credential = DefaultAzureCredential()
                
                logger.info(f"Collecting Azure costs for subscription {args.subscription_id}")
                records = collect_azure_costs(
                    credential, args.subscription_id, 
                    args.start_date, args.end_date
                )
                all_records.extend(records)
                collected_providers.append('azure')
                
            except ImportError:
                logger.warning("Azure SDK not installed, skipping Azure")
            except Exception as e:
                logger.error(f"Azure collection failed: {e}")
                if not args.all:
                    raise
    
    # GCP Collection
    if args.gcp or args.all:
        if args.gcp and (not args.project or not args.billing_table):
            parser.error("--project and --billing-table required for GCP")
        
        if args.project and args.billing_table:
            try:
                logger.info(f"Collecting GCP costs for project {args.project}")
                records = collect_gcp_costs(
                    args.project, args.billing_table,
                    args.start_date, args.end_date
                )
                all_records.extend(records)
                collected_providers.append('gcp')
                
            except ImportError:
                logger.warning("Google Cloud BigQuery SDK not installed, skipping GCP")
            except Exception as e:
                logger.error(f"GCP collection failed: {e}")
                if not args.all:
                    raise
    
    if not all_records:
        logger.warning("No cost records collected")
        print("\nNo backup/snapshot costs found for the specified period.")
        return
    
    # Aggregate
    summaries = aggregate_costs(all_records)
    
    # Prepare output
    run_id = generate_run_id()
    timestamp = get_timestamp()
    
    output_data = {
        'run_id': run_id,
        'timestamp': timestamp,
        'providers': collected_providers,
        'period': {
            'start': args.start_date,
            'end': args.end_date
        },
        'total_records': len(all_records),
        'total_cost': round(sum(r.cost for r in all_records), 2),
        'records': [r.to_dict() for r in all_records]
    }
    
    summary_data = {
        'run_id': run_id,
        'timestamp': timestamp,
        'providers': collected_providers,
        'period': {
            'start': args.start_date,
            'end': args.end_date
        },
        'total_cost': round(sum(r.cost for r in all_records), 2),
        'summaries': [s.to_dict() for s in summaries]
    }
    
    # Write outputs
    output_base = args.output.rstrip('/')
    file_ts = datetime.now(timezone.utc).strftime('%H%M%S')
    
    write_json(output_data, f"{output_base}/cca_cost_inv_{file_ts}.json")
    write_json(summary_data, f"{output_base}/cca_cost_sum_{file_ts}.json")
    
    # Write CSV
    csv_data = []
    for s in summaries:
        csv_data.append({
            'provider': s.provider,
            'category': s.category,
            'total_cost': s.total_cost,
            'currency': s.currency
        })
    write_csv(csv_data, f"{output_base}/cca_cost_sizing.csv")
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"Backup & Snapshot Cost Analysis")
    print(f"{'='*60}")
    print(f"Period:    {args.start_date} to {args.end_date}")
    print(f"Providers: {', '.join(collected_providers)}")
    print(f"Records:   {len(all_records)}")
    print(f"\n{'Category':<15} {'Provider':<10} {'Cost':>12}")
    print(f"{'-'*15} {'-'*10} {'-'*12}")
    
    grand_total = 0
    for s in summaries:
        print(f"{s.category:<15} {s.provider:<10} ${s.total_cost:>10,.2f}")
        grand_total += s.total_cost
    
    print(f"{'-'*15} {'-'*10} {'-'*12}")
    print(f"{'TOTAL':<15} {'':<10} ${grand_total:>10,.2f}")
    
    print(f"\nOutput: {output_base}/")


if __name__ == '__main__':
    main()
