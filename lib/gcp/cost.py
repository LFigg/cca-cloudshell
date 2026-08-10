"""GCP BigQuery billing cost collection.

Collects backup and snapshot costs from GCP BigQuery billing export.

Usage:
    from lib.gcp.cost import collect_gcp_costs
    records = collect_gcp_costs(project_id, billing_table, start_date, end_date)
"""
import logging
from typing import List

from lib.constants import GCP_BACKUP_FILTERS
from lib.models import CostRecord
from lib.utils import validate_bigquery_table

logger = logging.getLogger(__name__)


def collect_gcp_costs(
    project_id: str,
    billing_table: str,
    start_date: str,
    end_date: str
) -> List[CostRecord]:
    """Collect backup and snapshot costs from GCP BigQuery billing export.

    Args:
        project_id: GCP project ID
        billing_table: Full BigQuery table path (project.dataset.table)
        start_date: Start date (YYYY-MM-DD)
        end_date: End date (YYYY-MM-DD)

    Returns:
        List of CostRecord objects

    Example:
        records = collect_gcp_costs(
            "my-gcp-project",
            "my-gcp-project.billing_export.gcp_billing_export_v1",
            "2024-01-01",
            "2024-01-31",
        )
    """
    records: List[CostRecord] = []

    try:
        from google.cloud import bigquery

        client = bigquery.Client(project=project_id)

        # Validate billing_table format to prevent SQL injection —
        # BigQuery doesn't support parameterized table names
        validate_bigquery_table(billing_table)

        def escape_like_pattern(s: str) -> str:
            return s.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')

        services_filter = ', '.join([f"'{s}'" for s in GCP_BACKUP_FILTERS['services']])
        sku_conditions = ' OR '.join([
            f"LOWER(sku.description) LIKE '%{escape_like_pattern(kw)}%'"
            for kw in GCP_BACKUP_FILTERS['sku_keywords']
        ])

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
            records.append(CostRecord(
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
                metadata={'sku': row.sku},
            ))

        logger.info(f"Collected {len(records)} GCP cost records")

    except ImportError:
        logger.error("Google Cloud BigQuery SDK not installed. Run: pip install google-cloud-bigquery")
        raise
    except Exception as e:
        logger.error(f"Failed to collect GCP costs: {e}")
        raise

    return records


def categorize_gcp_cost(service: str, sku: str) -> str:
    """Categorize GCP cost into backup, snapshot, or storage.

    Args:
        service: Billing service description (e.g. "Backup and DR")
        sku: Billing SKU description (e.g. "Backup and DR Storage")

    Returns:
        One of 'snapshot', 'backup', or 'storage'.
    """
    sku_lower = sku.lower()
    if 'snapshot' in sku_lower:
        return 'snapshot'
    elif 'backup' in sku_lower or 'Backup and DR' in service:
        return 'backup'
    else:
        return 'storage'
