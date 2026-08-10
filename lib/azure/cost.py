"""Azure Cost Management collection.

Collects backup and snapshot costs from Azure Cost Management API.

Usage:
    from lib.azure.cost import collect_azure_costs
    records = collect_azure_costs(credential, subscription_id, start_date, end_date)
"""
import logging
from datetime import datetime, timezone
from typing import Any, List

from lib.constants import AZURE_BACKUP_FILTERS
from lib.models import CostRecord

logger = logging.getLogger(__name__)


def collect_azure_costs(
    credential,
    subscription_id: str,
    start_date: str,
    end_date: str
) -> List[CostRecord]:
    """Collect backup and snapshot costs from Azure Cost Management.

    Args:
        credential: Azure credential object
        subscription_id: Azure subscription ID
        start_date: Start date (YYYY-MM-DD)
        end_date: End date (YYYY-MM-DD)

    Returns:
        List of CostRecord objects

    Example:
        records = collect_azure_costs(credential, subscription_id, "2026-06-01", "2026-06-30")
    """
    records: List[CostRecord] = []

    try:
        from azure.mgmt.costmanagement import CostManagementClient
        from azure.mgmt.costmanagement.models import (
            QueryAggregation,
            QueryComparisonExpression,
            QueryDataset,
            QueryDefinition,
            QueryFilter,
            QueryGrouping,
            QueryTimePeriod,
        )

        client = CostManagementClient(credential, subscription_id)
        scope = f"/subscriptions/{subscription_id}"

        from_date = datetime.strptime(start_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        to_date = datetime.strptime(end_date, "%Y-%m-%d").replace(
            hour=23, minute=59, second=59, tzinfo=timezone.utc
        )

        query = QueryDefinition(
            type="ActualCost",
            timeframe="Custom",
            time_period=QueryTimePeriod(from_property=from_date, to=to_date),
            dataset=QueryDataset(
                granularity="Monthly",
                aggregation={
                    "totalCost": QueryAggregation(name="Cost", function="Sum"),
                    "totalQuantity": QueryAggregation(name="Quantity", function="Sum"),
                },
                grouping=[
                    QueryGrouping(type="Dimension", name="ServiceName"),
                    QueryGrouping(type="Dimension", name="MeterCategory"),
                ],
                filter=QueryFilter(
                    or_property=[
                        QueryFilter(
                            dimensions=QueryComparisonExpression(
                                name="ServiceName",
                                operator="In",
                                values=AZURE_BACKUP_FILTERS['service_names'],
                            )
                        ),
                        QueryFilter(
                            dimensions=QueryComparisonExpression(
                                name="MeterCategory",
                                operator="In",
                                values=AZURE_BACKUP_FILTERS['meter_categories'],
                            )
                        ),
                    ]
                ),
            ),
        )

        result = client.query.usage(scope=scope, parameters=query)

        all_rows: List[Any] = []
        columns: List[str] = []
        while True:
            if result is None or result.columns is None or result.rows is None:
                if not all_rows:
                    logger.warning("No cost data returned from Azure")
                break
            if not columns:
                columns = [col.name or '' for col in result.columns]
            all_rows.extend(result.rows)
            break  # Azure Cost Management returns all rows in a single response

        for row in all_rows:
            row_dict = dict(zip(columns, row))
            cost = float(row_dict.get('Cost', 0))
            if cost == 0:
                continue

            service = row_dict.get('ServiceName', 'Unknown')
            meter_category = row_dict.get('MeterCategory', '')
            category = categorize_azure_cost(service, meter_category)

            records.append(CostRecord(
                provider='azure',
                account_id=subscription_id,
                service=service,
                category=category,
                cost=round(cost, 2),
                currency=row_dict.get('Currency', 'USD'),
                period_start=start_date,
                period_end=end_date,
                usage_quantity=float(row_dict.get('Quantity', 0)) if row_dict.get('Quantity') else None,
                metadata={'meter_category': meter_category},
            ))

        logger.info(f"Collected {len(records)} Azure cost records")

    except ImportError:
        logger.error("Azure Cost Management SDK not installed. Run: pip install azure-mgmt-costmanagement")
        raise
    except Exception as e:
        logger.error(f"Failed to collect Azure costs: {e}")
        raise

    return records


def categorize_azure_cost(service: str, meter_category: str) -> str:
    """Categorize Azure cost into backup, snapshot, or storage.

    Args:
        service: Azure Cost Management ServiceName dimension value
        meter_category: Azure Cost Management MeterCategory dimension value

    Returns:
        Category string: 'netapp_backup', 'netapp_storage', 'backup',
        'snapshot', or 'storage'
    """
    service_lower = service.lower()
    meter_lower = meter_category.lower()

    if 'netapp' in service_lower or 'netapp' in meter_lower:
        if 'backup' in meter_lower or 'snapshot' in meter_lower:
            return 'netapp_backup'
        return 'netapp_storage'
    elif 'backup' in service_lower or 'backup' in meter_lower:
        return 'backup'
    elif 'snapshot' in meter_lower:
        return 'snapshot'
    elif 'site recovery' in service_lower:
        return 'backup'
    else:
        return 'storage'
