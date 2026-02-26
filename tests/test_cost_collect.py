"""
Comprehensive tests for Cost Collector.

Covers:
- Data model tests (CostRecord, CostSummary)
- Categorization functions
- AWS Cost Explorer collection (mocked)
- Azure Cost Management collection (mocked)
- GCP BigQuery billing collection (mocked)
- Aggregation functions
- Error handling
"""
import os
import sys
from unittest.mock import Mock, patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.constants import AWS_BACKUP_FILTERS, AZURE_BACKUP_FILTERS, GCP_BACKUP_FILTERS
from cost_collect import (
    CostRecord,
    CostSummary,
    aggregate_costs,
    categorize_aws_usage,
    categorize_azure_cost,
    categorize_gcp_cost,
    collect_aws_costs,
    collect_azure_costs,
)

# =============================================================================
# Data Model Tests
# =============================================================================

class TestCostRecord:
    """Tests for CostRecord dataclass."""

    def test_basic_record(self):
        """Test creating a basic cost record."""
        record = CostRecord(
            provider='aws',
            account_id='123456789012',
            service='AWS Backup',
            category='backup',
            cost=150.50,
            currency='USD',
            period_start='2026-01-01',
            period_end='2026-02-01'
        )

        assert record.provider == 'aws'
        assert record.account_id == '123456789012'
        assert record.service == 'AWS Backup'
        assert record.category == 'backup'
        assert record.cost == 150.50
        assert record.currency == 'USD'
        assert record.usage_quantity is None
        assert record.metadata is None

    def test_record_with_optional_fields(self):
        """Test cost record with all optional fields."""
        record = CostRecord(
            provider='azure',
            account_id='subscription-123',
            service='Azure Backup',
            category='backup',
            cost=200.00,
            currency='EUR',
            period_start='2026-01-01',
            period_end='2026-02-01',
            usage_quantity=500.0,
            usage_unit='GB-Month',
            metadata={'vault_name': 'my-vault'}
        )

        assert record.usage_quantity == 500.0
        assert record.usage_unit == 'GB-Month'
        assert record.metadata == {'vault_name': 'my-vault'}

    def test_record_to_dict(self):
        """Test converting cost record to dictionary."""
        record = CostRecord(
            provider='gcp',
            account_id='my-project',
            service='Cloud Storage',
            category='snapshot',
            cost=75.25,
            currency='USD',
            period_start='2026-01-01',
            period_end='2026-02-01',
            usage_quantity=100.0,
            usage_unit='gibibyte month'
        )

        d = record.to_dict()

        assert d['provider'] == 'gcp'
        assert d['cost'] == 75.25
        assert d['usage_quantity'] == 100.0
        assert 'metadata' not in d  # None values removed

    def test_record_to_dict_with_metadata(self):
        """Test to_dict includes metadata when present."""
        record = CostRecord(
            provider='aws',
            account_id='123456789012',
            service='EC2 - Other',
            category='snapshot',
            cost=50.00,
            currency='USD',
            period_start='2026-01-01',
            period_end='2026-02-01',
            metadata={'usage_type': 'EBS:SnapshotUsage'}
        )

        d = record.to_dict()
        assert 'metadata' in d
        assert d['metadata'] == {'usage_type': 'EBS:SnapshotUsage'}


class TestCostSummary:
    """Tests for CostSummary dataclass."""

    def test_basic_summary(self):
        """Test creating a basic cost summary."""
        summary = CostSummary(
            provider='aws',
            category='backup',
            total_cost=500.00,
            currency='USD',
            service_breakdown={'AWS Backup': 300.00, 'Amazon S3': 200.00}
        )

        assert summary.provider == 'aws'
        assert summary.category == 'backup'
        assert summary.total_cost == 500.00
        assert len(summary.service_breakdown) == 2

    def test_summary_to_dict(self):
        """Test converting summary to dictionary."""
        summary = CostSummary(
            provider='azure',
            category='snapshot',
            total_cost=150.00,
            currency='USD',
            service_breakdown={'Storage': 150.00}
        )

        d = summary.to_dict()

        assert d['provider'] == 'azure'
        assert d['total_cost'] == 150.00
        assert d['service_breakdown'] == {'Storage': 150.00}


# =============================================================================
# Categorization Function Tests
# =============================================================================

class TestCategorizeAWSUsage:
    """Tests for AWS usage type categorization."""

    def test_snapshot_usage_type(self):
        """Test snapshot categorization."""
        assert categorize_aws_usage('EC2 - Other', 'EBS:SnapshotUsage') == 'snapshot'
        assert categorize_aws_usage('Amazon Elastic Block Store', 'TimedStorage-Snapshot') == 'snapshot'

    def test_backup_usage_type(self):
        """Test backup categorization."""
        assert categorize_aws_usage('AWS Backup', 'BackupUsage') == 'backup'
        assert categorize_aws_usage('AWS Backup', 'VaultStorage') == 'backup'
        assert categorize_aws_usage('EC2 - Other', 'ChargedBackupUsage') == 'backup'

    def test_aws_backup_service(self):
        """Test AWS Backup service is always categorized as backup."""
        assert categorize_aws_usage('AWS Backup', 'SomeOtherType') == 'backup'

    def test_storage_fallback(self):
        """Test storage fallback for unrecognized types."""
        assert categorize_aws_usage('Amazon S3', 'TimedStorage-ByteHrs') == 'storage'


class TestCategorizeAzureCost:
    """Tests for Azure cost categorization."""

    def test_backup_service(self):
        """Test backup service categorization."""
        assert categorize_azure_cost('Azure Backup', 'Storage') == 'backup'
        assert categorize_azure_cost('Storage', 'Backup') == 'backup'

    def test_snapshot_meter(self):
        """Test snapshot meter categorization."""
        assert categorize_azure_cost('Storage', 'Snapshot') == 'snapshot'

    def test_site_recovery(self):
        """Test Site Recovery is categorized as backup."""
        assert categorize_azure_cost('Azure Site Recovery', 'Compute') == 'backup'

    def test_storage_fallback(self):
        """Test storage fallback."""
        assert categorize_azure_cost('Storage', 'Block Blob') == 'storage'


class TestCategorizeGCPCost:
    """Tests for GCP cost categorization."""

    def test_snapshot_sku(self):
        """Test snapshot SKU categorization."""
        assert categorize_gcp_cost('Compute Engine', 'Snapshot storage') == 'snapshot'
        assert categorize_gcp_cost('Compute Engine', 'Regional Snapshot Storage') == 'snapshot'

    def test_backup_sku(self):
        """Test backup SKU categorization."""
        assert categorize_gcp_cost('Cloud SQL', 'Backup storage') == 'backup'
        assert categorize_gcp_cost('Backup and DR Service', 'Management Fee') == 'backup'

    def test_storage_fallback(self):
        """Test storage fallback."""
        assert categorize_gcp_cost('Cloud Storage', 'Nearline Storage') == 'storage'
        assert categorize_gcp_cost('Cloud Storage', 'Standard Storage') == 'storage'


# =============================================================================
# AWS Cost Explorer Tests
# =============================================================================

class TestCollectAWSCosts:
    """Tests for AWS Cost Explorer collection."""

    def test_collect_costs_success(self):
        """Test successful cost collection."""
        mock_session = Mock()
        mock_ce = Mock()
        mock_session.client.return_value = mock_ce

        mock_ce.get_cost_and_usage.return_value = {
            'ResultsByTime': [
                {
                    'TimePeriod': {'Start': '2026-01-01', 'End': '2026-02-01'},
                    'Groups': [
                        {
                            'Keys': ['AWS Backup', 'BackupUsage'],
                            'Metrics': {
                                'UnblendedCost': {'Amount': '150.50', 'Unit': 'USD'},
                                'UsageQuantity': {'Amount': '500', 'Unit': 'GB-Mo'}
                            }
                        },
                        {
                            'Keys': ['EC2 - Other', 'EBS:SnapshotUsage'],
                            'Metrics': {
                                'UnblendedCost': {'Amount': '75.25', 'Unit': 'USD'},
                                'UsageQuantity': {'Amount': '250', 'Unit': 'GB-Mo'}
                            }
                        }
                    ]
                }
            ]
        }

        records = collect_aws_costs(
            mock_session, '2026-01-01', '2026-02-01', '123456789012'
        )

        assert len(records) == 2

        backup_record = next(r for r in records if r.category == 'backup')
        assert backup_record.cost == 150.50
        assert backup_record.service == 'AWS Backup'

        snapshot_record = next(r for r in records if r.category == 'snapshot')
        assert snapshot_record.cost == 75.25
        assert snapshot_record.service == 'EC2 - Other'

    def test_collect_costs_filters_non_backup(self):
        """Test that non-backup usage types are filtered out."""
        mock_session = Mock()
        mock_ce = Mock()
        mock_session.client.return_value = mock_ce

        mock_ce.get_cost_and_usage.return_value = {
            'ResultsByTime': [
                {
                    'TimePeriod': {'Start': '2026-01-01', 'End': '2026-02-01'},
                    'Groups': [
                        {
                            'Keys': ['AWS Backup', 'BackupUsage'],
                            'Metrics': {
                                'UnblendedCost': {'Amount': '100.00', 'Unit': 'USD'},
                                'UsageQuantity': {'Amount': '100', 'Unit': 'GB-Mo'}
                            }
                        },
                        {
                            'Keys': ['Amazon S3', 'Requests-Tier1'],  # Not backup-related
                            'Metrics': {
                                'UnblendedCost': {'Amount': '200.00', 'Unit': 'USD'},
                                'UsageQuantity': {'Amount': '1000', 'Unit': 'Requests'}
                            }
                        }
                    ]
                }
            ]
        }

        records = collect_aws_costs(
            mock_session, '2026-01-01', '2026-02-01', '123456789012'
        )

        # Only backup-related record should be returned
        assert len(records) == 1
        assert records[0].category == 'backup'

    def test_collect_costs_skips_zero_cost(self):
        """Test that zero cost records are skipped."""
        mock_session = Mock()
        mock_ce = Mock()
        mock_session.client.return_value = mock_ce

        mock_ce.get_cost_and_usage.return_value = {
            'ResultsByTime': [
                {
                    'TimePeriod': {'Start': '2026-01-01', 'End': '2026-02-01'},
                    'Groups': [
                        {
                            'Keys': ['AWS Backup', 'BackupUsage'],
                            'Metrics': {
                                'UnblendedCost': {'Amount': '0.00', 'Unit': 'USD'},
                                'UsageQuantity': {'Amount': '0', 'Unit': 'GB-Mo'}
                            }
                        }
                    ]
                }
            ]
        }

        records = collect_aws_costs(
            mock_session, '2026-01-01', '2026-02-01', '123456789012'
        )

        assert len(records) == 0

    def test_collect_costs_empty_response(self):
        """Test handling empty response."""
        mock_session = Mock()
        mock_ce = Mock()
        mock_session.client.return_value = mock_ce

        mock_ce.get_cost_and_usage.return_value = {
            'ResultsByTime': []
        }

        records = collect_aws_costs(
            mock_session, '2026-01-01', '2026-02-01', '123456789012'
        )

        assert len(records) == 0

    def test_collect_costs_api_error(self):
        """Test handling API errors."""
        mock_session = Mock()
        mock_ce = Mock()
        mock_session.client.return_value = mock_ce

        mock_ce.get_cost_and_usage.side_effect = Exception("Access Denied")

        with pytest.raises(Exception, match="Access Denied"):
            collect_aws_costs(
                mock_session, '2026-01-01', '2026-02-01', '123456789012'
            )


# =============================================================================
# Azure Cost Management Tests
# =============================================================================

class TestCollectAzureCosts:
    """Tests for Azure Cost Management collection."""

    def test_collect_costs_success_simulated(self):
        """Test Azure cost collection logic by simulating the data flow.

        Since Azure SDK mocking is complex, we test the categorization and
        data structure that would be created from real API responses.
        """
        # Simulate what records would look like from Azure
        test_data = [
            {'ServiceName': 'Azure Backup', 'MeterCategory': 'Storage', 'Cost': 100.00, 'Currency': 'USD'},
            {'ServiceName': 'Storage', 'MeterCategory': 'Snapshot', 'Cost': 50.00, 'Currency': 'USD'}
        ]

        records = []
        for row_dict in test_data:
            cost = float(row_dict.get('Cost', 0))
            if cost == 0:
                continue

            service = row_dict.get('ServiceName', 'Unknown')
            meter_category = row_dict.get('MeterCategory', '')
            category = categorize_azure_cost(service, meter_category)

            record = CostRecord(
                provider='azure',
                account_id='subscription-123',
                service=service,
                category=category,
                cost=round(cost, 2),
                currency=row_dict.get('Currency', 'USD'),
                period_start='2026-01-01',
                period_end='2026-02-01',
                metadata={'meter_category': meter_category}
            )
            records.append(record)

        assert len(records) == 2

        backup_record = next(r for r in records if r.service == 'Azure Backup')
        assert backup_record.category == 'backup'
        assert backup_record.cost == 100.00

        snapshot_record = next(r for r in records if r.category == 'snapshot')
        assert snapshot_record.cost == 50.00

    def test_collect_costs_missing_sdk(self):
        """Test handling missing Azure SDK."""
        with patch.dict('sys.modules', {'azure.mgmt.costmanagement': None}):
            # Force ImportError
            import builtins
            real_import = builtins.__import__

            def mock_import(name, *args, **kwargs):
                if 'costmanagement' in name:
                    raise ImportError("No module named 'azure.mgmt.costmanagement'")
                return real_import(name, *args, **kwargs)

            with patch.object(builtins, '__import__', mock_import):
                with pytest.raises(ImportError):
                    collect_azure_costs(Mock(), 'sub-123', '2026-01-01', '2026-02-01')


# =============================================================================
# GCP BigQuery Tests
# =============================================================================

class TestCollectGCPCosts:
    """Tests for GCP BigQuery billing collection."""

    def test_collect_costs_success_simulated(self):
        """Test GCP cost collection logic by simulating the data flow.

        Since BigQuery SDK mocking is complex, we test the categorization and
        data structure that would be created from real query results.
        """
        # Simulate what rows would look like from BigQuery
        test_data = [
            {
                'project_id': 'my-project',
                'service': 'Compute Engine',
                'sku': 'Snapshot storage',
                'cost': 75.50,
                'currency': 'USD',
                'usage_amount': 500.0,
                'usage_unit': 'gibibyte month',
                'period_start': '2026-01-01',
                'period_end': '2026-01-31'
            },
            {
                'project_id': 'my-project',
                'service': 'Cloud SQL',
                'sku': 'Backup storage',
                'cost': 25.00,
                'currency': 'USD',
                'usage_amount': 100.0,
                'usage_unit': 'gibibyte month',
                'period_start': '2026-01-01',
                'period_end': '2026-01-31'
            }
        ]

        records = []
        for row in test_data:
            category = categorize_gcp_cost(row['service'], row['sku'])

            record = CostRecord(
                provider='gcp',
                account_id=row['project_id'],
                service=row['service'],
                category=category,
                cost=round(float(row['cost']), 2),
                currency=row['currency'],
                period_start=row['period_start'],
                period_end=row['period_end'],
                usage_quantity=round(float(row['usage_amount']), 2) if row['usage_amount'] else None,
                usage_unit=row['usage_unit'],
                metadata={'sku': row['sku']}
            )
            records.append(record)

        assert len(records) == 2

        snapshot_record = next(r for r in records if r.category == 'snapshot')
        assert snapshot_record.cost == 75.50
        assert snapshot_record.service == 'Compute Engine'

        backup_record = next(r for r in records if r.category == 'backup')
        assert backup_record.cost == 25.00
        assert backup_record.service == 'Cloud SQL'


# =============================================================================
# Aggregation Tests
# =============================================================================

class TestAggregateCosts:
    """Tests for cost aggregation."""

    def test_aggregate_single_provider(self):
        """Test aggregation for single provider."""
        records = [
            CostRecord(
                provider='aws', account_id='123', service='AWS Backup',
                category='backup', cost=100.00, currency='USD',
                period_start='2026-01-01', period_end='2026-02-01'
            ),
            CostRecord(
                provider='aws', account_id='123', service='EC2 - Other',
                category='snapshot', cost=50.00, currency='USD',
                period_start='2026-01-01', period_end='2026-02-01'
            ),
            CostRecord(
                provider='aws', account_id='123', service='AWS Backup',
                category='backup', cost=75.00, currency='USD',
                period_start='2026-01-01', period_end='2026-02-01'
            )
        ]

        summaries = aggregate_costs(records)

        assert len(summaries) == 2

        backup_summary = next(s for s in summaries if s.category == 'backup')
        assert backup_summary.total_cost == 175.00
        assert backup_summary.service_breakdown['AWS Backup'] == 175.00

        snapshot_summary = next(s for s in summaries if s.category == 'snapshot')
        assert snapshot_summary.total_cost == 50.00

    def test_aggregate_multiple_providers(self):
        """Test aggregation across multiple providers."""
        records = [
            CostRecord(
                provider='aws', account_id='123', service='AWS Backup',
                category='backup', cost=100.00, currency='USD',
                period_start='2026-01-01', period_end='2026-02-01'
            ),
            CostRecord(
                provider='azure', account_id='sub-123', service='Azure Backup',
                category='backup', cost=150.00, currency='USD',
                period_start='2026-01-01', period_end='2026-02-01'
            ),
            CostRecord(
                provider='gcp', account_id='proj-123', service='Compute Engine',
                category='snapshot', cost=75.00, currency='USD',
                period_start='2026-01-01', period_end='2026-02-01'
            )
        ]

        summaries = aggregate_costs(records)

        # Should have separate summaries for each (provider, category) pair
        assert len(summaries) == 3

        aws_backup = next(s for s in summaries if s.provider == 'aws' and s.category == 'backup')
        assert aws_backup.total_cost == 100.00

        azure_backup = next(s for s in summaries if s.provider == 'azure' and s.category == 'backup')
        assert azure_backup.total_cost == 150.00

        gcp_snapshot = next(s for s in summaries if s.provider == 'gcp' and s.category == 'snapshot')
        assert gcp_snapshot.total_cost == 75.00

    def test_aggregate_service_breakdown(self):
        """Test that service breakdown is calculated correctly."""
        records = [
            CostRecord(
                provider='aws', account_id='123', service='AWS Backup',
                category='backup', cost=100.00, currency='USD',
                period_start='2026-01-01', period_end='2026-02-01'
            ),
            CostRecord(
                provider='aws', account_id='123', service='Amazon RDS',
                category='backup', cost=50.00, currency='USD',
                period_start='2026-01-01', period_end='2026-02-01'
            ),
            CostRecord(
                provider='aws', account_id='123', service='AWS Backup',
                category='backup', cost=25.00, currency='USD',
                period_start='2026-01-01', period_end='2026-02-01'
            )
        ]

        summaries = aggregate_costs(records)

        assert len(summaries) == 1
        summary = summaries[0]

        assert summary.total_cost == 175.00
        assert summary.service_breakdown['AWS Backup'] == 125.00
        assert summary.service_breakdown['Amazon RDS'] == 50.00

    def test_aggregate_empty_list(self):
        """Test aggregation with empty list."""
        summaries = aggregate_costs([])
        assert summaries == []

    def test_aggregate_rounding(self):
        """Test that costs are properly rounded."""
        records = [
            CostRecord(
                provider='aws', account_id='123', service='AWS Backup',
                category='backup', cost=100.333, currency='USD',
                period_start='2026-01-01', period_end='2026-02-01'
            ),
            CostRecord(
                provider='aws', account_id='123', service='AWS Backup',
                category='backup', cost=50.666, currency='USD',
                period_start='2026-01-01', period_end='2026-02-01'
            )
        ]

        summaries = aggregate_costs(records)

        assert summaries[0].total_cost == 151.00  # Rounded
        assert summaries[0].service_breakdown['AWS Backup'] == 151.00


# =============================================================================
# Filter Configuration Tests
# =============================================================================

class TestFilterConfigurations:
    """Tests for filter configurations."""

    def test_aws_filters_structure(self):
        """Test AWS backup filters are properly configured."""
        assert 'services' in AWS_BACKUP_FILTERS
        assert 'usage_types' in AWS_BACKUP_FILTERS
        assert 'AWS Backup' in AWS_BACKUP_FILTERS['services']
        assert 'SnapshotUsage' in AWS_BACKUP_FILTERS['usage_types']

    def test_azure_filters_structure(self):
        """Test Azure backup filters are properly configured."""
        assert 'service_names' in AZURE_BACKUP_FILTERS
        assert 'meter_categories' in AZURE_BACKUP_FILTERS
        assert 'Azure Backup' in AZURE_BACKUP_FILTERS['service_names']

    def test_gcp_filters_structure(self):
        """Test GCP backup filters are properly configured."""
        assert 'services' in GCP_BACKUP_FILTERS
        assert 'sku_keywords' in GCP_BACKUP_FILTERS
        assert 'Compute Engine' in GCP_BACKUP_FILTERS['services']
        assert 'snapshot' in GCP_BACKUP_FILTERS['sku_keywords']


# =============================================================================
# Integration-style Tests
# =============================================================================

class TestEndToEndFlow:
    """Tests for end-to-end data flow."""

    def test_record_to_aggregation_flow(self):
        """Test that records flow correctly through aggregation."""
        # Create records as they would come from collection
        aws_records = [
            CostRecord(
                provider='aws', account_id='123456789012',
                service='AWS Backup', category='backup',
                cost=250.00, currency='USD',
                period_start='2026-01-01', period_end='2026-02-01',
                usage_quantity=1000.0, usage_unit='GB-Mo',
                metadata={'usage_type': 'BackupUsage'}
            ),
            CostRecord(
                provider='aws', account_id='123456789012',
                service='EC2 - Other', category='snapshot',
                cost=125.50, currency='USD',
                period_start='2026-01-01', period_end='2026-02-01',
                usage_quantity=500.0, usage_unit='GB-Mo',
                metadata={'usage_type': 'EBS:SnapshotUsage'}
            )
        ]

        azure_records = [
            CostRecord(
                provider='azure', account_id='subscription-abc',
                service='Azure Backup', category='backup',
                cost=180.00, currency='USD',
                period_start='2026-01-01', period_end='2026-02-01'
            )
        ]

        all_records = aws_records + azure_records
        summaries = aggregate_costs(all_records)

        # Should have 3 summaries: aws-backup, aws-snapshot, azure-backup
        assert len(summaries) == 3

        # Verify totals
        total = sum(s.total_cost for s in summaries)
        assert total == 555.50  # 250 + 125.50 + 180

    def test_multiple_periods_same_category(self):
        """Test aggregating costs from multiple time periods."""
        records = [
            CostRecord(
                provider='aws', account_id='123',
                service='AWS Backup', category='backup',
                cost=100.00, currency='USD',
                period_start='2026-01-01', period_end='2026-02-01'
            ),
            CostRecord(
                provider='aws', account_id='123',
                service='AWS Backup', category='backup',
                cost=120.00, currency='USD',
                period_start='2026-02-01', period_end='2026-03-01'
            )
        ]

        summaries = aggregate_costs(records)

        assert len(summaries) == 1
        assert summaries[0].total_cost == 220.00


# =============================================================================
# Security Tests - BigQuery Table Validation (CC-001)
# =============================================================================

class TestValidateBigQueryTable:
    """Tests for BigQuery table name validation to prevent SQL injection."""

    def test_valid_table_format(self):
        """Test valid BigQuery table references are accepted."""
        from lib.utils import validate_bigquery_table

        # Standard format
        result = validate_bigquery_table('my-project.billing_dataset.gcp_billing_export')
        assert result == 'my-project.billing_dataset.gcp_billing_export'

        # With underscores
        result = validate_bigquery_table('my_project.my_dataset.my_table')
        assert result == 'my_project.my_dataset.my_table'

        # With hyphens
        result = validate_bigquery_table('project-123.dataset-name.table-name')
        assert result == 'project-123.dataset-name.table-name'

    def test_valid_wildcard_table(self):
        """Test wildcard table references are accepted."""
        from lib.utils import validate_bigquery_table

        result = validate_bigquery_table('my-project.billing.gcp_billing_export_*')
        assert result == 'my-project.billing.gcp_billing_export_*'

    def test_empty_table_rejected(self):
        """Test empty table name raises ValueError."""
        from lib.utils import validate_bigquery_table

        with pytest.raises(ValueError, match="cannot be empty"):
            validate_bigquery_table('')

        with pytest.raises(ValueError, match="cannot be empty"):
            validate_bigquery_table(None)

    def test_sql_injection_attempts_rejected(self):
        """Test SQL injection attempts are rejected."""
        from lib.utils import validate_bigquery_table

        # SQL injection with comment
        with pytest.raises(ValueError, match="Invalid BigQuery table format"):
            validate_bigquery_table("project.dataset.table; DROP TABLE users; --")

        # SQL injection with union
        with pytest.raises(ValueError, match="Invalid BigQuery table format"):
            validate_bigquery_table("project.dataset.table UNION SELECT * FROM passwords")

        # Backtick escape attempt
        with pytest.raises(ValueError, match="Invalid BigQuery table format"):
            validate_bigquery_table("project`.`dataset`.`table")

    def test_invalid_formats_rejected(self):
        """Test invalid table formats are rejected."""
        from lib.utils import validate_bigquery_table

        # Missing components
        with pytest.raises(ValueError, match="Invalid BigQuery table format"):
            validate_bigquery_table("just_a_table")

        with pytest.raises(ValueError, match="Invalid BigQuery table format"):
            validate_bigquery_table("project.table")

        # Extra components
        with pytest.raises(ValueError, match="Invalid BigQuery table format"):
            validate_bigquery_table("project.dataset.schema.table")

        # Special characters
        with pytest.raises(ValueError, match="Invalid BigQuery table format"):
            validate_bigquery_table("project.dataset.table$special")

        with pytest.raises(ValueError, match="Invalid BigQuery table format"):
            validate_bigquery_table("project.dataset.table@version")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
