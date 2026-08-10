"""AWS Cost Explorer collection.

Collects backup and snapshot costs from AWS Cost Explorer.

Usage:
    from lib.aws.cost import collect_aws_costs
    records = collect_aws_costs(session, start_date, end_date, account_id)
"""
import logging
from typing import List, Optional

from lib.constants import AWS_BACKUP_FILTERS
from lib.models import CostRecord

logger = logging.getLogger(__name__)


def collect_aws_costs(
    session,
    start_date: str,
    end_date: str,
    account_id: str,
    group_by_account: bool = False
) -> List[CostRecord]:
    """Collect backup and snapshot costs from AWS Cost Explorer.

    Args:
        session: boto3 Session
        start_date: Start date (YYYY-MM-DD)
        end_date: End date (YYYY-MM-DD, exclusive)
        account_id: AWS account ID (management account for orgs)
        group_by_account: If True, break down costs by LINKED_ACCOUNT

    Returns:
        List of CostRecord objects

    Example:
        records = collect_aws_costs(session, "2024-01-01", "2024-02-01", "123456789012")
    """
    records: List[CostRecord] = []

    try:
        ce = session.client('ce', region_name='us-east-1')  # Cost Explorer is global

        if group_by_account:
            group_by = [
                {'Type': 'DIMENSION', 'Key': 'LINKED_ACCOUNT'},
                {'Type': 'DIMENSION', 'Key': 'SERVICE'},
            ]
            logger.info("Grouping costs by linked account (Organizations mode)")
        else:
            group_by = [
                {'Type': 'DIMENSION', 'Key': 'SERVICE'},
                {'Type': 'DIMENSION', 'Key': 'USAGE_TYPE'},
            ]

        response = ce.get_cost_and_usage(
            TimePeriod={'Start': start_date, 'End': end_date},
            Granularity='MONTHLY',
            Filter={
                'Dimensions': {
                    'Key': 'SERVICE',
                    'Values': AWS_BACKUP_FILTERS['services'],
                }
            },
            Metrics=['UnblendedCost', 'UsageQuantity'],
            GroupBy=group_by,
        )

        for result in response.get('ResultsByTime', []):
            period_start = result['TimePeriod']['Start']
            period_end = result['TimePeriod']['End']

            for group in result.get('Groups', []):
                keys = group.get('Keys', [])
                if len(keys) < 2:
                    continue

                if group_by_account:
                    linked_account = keys[0]
                    service = keys[1]
                    usage_type: Optional[str] = None
                else:
                    linked_account = account_id
                    service = keys[0]
                    usage_type = keys[1]

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

                category = categorize_aws_usage(service, usage_type or '')

                records.append(CostRecord(
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
                    metadata={'usage_type': usage_type} if usage_type else None,
                ))

        logger.info(f"Collected {len(records)} AWS cost records")

    except Exception as e:
        logger.error(f"Failed to collect AWS costs: {e}")
        raise

    return records


def categorize_aws_usage(service: str, usage_type: str) -> str:
    """Categorize AWS usage type into backup, snapshot, or storage.

    Args:
        service: AWS service name from Cost Explorer (e.g., "AWS Backup")
        usage_type: Cost Explorer usage type string (e.g., "USE1-Snapshot-Storage")

    Returns:
        Category string: one of 'snapshot', 'backup', 'efs_backup', 'fsx_backup',
        or 'storage'
    """
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
