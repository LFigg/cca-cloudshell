"""
Tests for lib/change_rate.py change rate aggregation utilities.

Covers:
- merge_change_rates aggregation logic
- finalize_change_rate_output percentage calculation and metadata
- aggregate_change_rates basic functionality
"""
import os
import sys
from datetime import datetime

import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.change_rate import (
    DataChangeMetrics,
    aggregate_change_rates,
    finalize_change_rate_output,
    merge_change_rates,
)

# =============================================================================
# merge_change_rates Tests
# =============================================================================

class TestMergeChangeRates:
    """Tests for merge_change_rates function."""

    def test_merge_into_empty(self):
        """Test merging into empty accumulated dict."""
        accumulated = {}
        new_data = {
            'change_rates': {
                'EBS': {
                    'provider': 'aws',
                    'service_family': 'EBS',
                    'resource_count': 10,
                    'total_size_gb': 1000.0,
                    'data_change': {
                        'daily_change_gb': 50.0,
                        'data_points': 70,
                    }
                }
            }
        }

        result = merge_change_rates(accumulated, new_data)

        assert result is accumulated  # Same object returned
        assert 'EBS' in accumulated
        assert accumulated['EBS']['resource_count'] == 10
        assert accumulated['EBS']['total_size_gb'] == 1000.0

    def test_merge_aggregates_values(self):
        """Test merging aggregates resource counts and sizes."""
        accumulated = {
            'EBS': {
                'provider': 'aws',
                'service_family': 'EBS',
                'resource_count': 10,
                'total_size_gb': 1000.0,
                'data_change': {
                    'daily_change_gb': 50.0,
                    'data_points': 70,
                }
            }
        }
        new_data = {
            'change_rates': {
                'EBS': {
                    'provider': 'aws',
                    'service_family': 'EBS',
                    'resource_count': 5,
                    'total_size_gb': 500.0,
                    'data_change': {
                        'daily_change_gb': 25.0,
                        'data_points': 35,
                    }
                }
            }
        }

        merge_change_rates(accumulated, new_data)

        assert accumulated['EBS']['resource_count'] == 15
        assert accumulated['EBS']['total_size_gb'] == 1500.0
        assert accumulated['EBS']['data_change']['daily_change_gb'] == 75.0
        assert accumulated['EBS']['data_change']['data_points'] == 105

    def test_merge_multiple_service_families(self):
        """Test merging multiple service families."""
        accumulated = {}

        data1 = {
            'change_rates': {
                'EBS': {'provider': 'aws', 'service_family': 'EBS', 'resource_count': 10,
                        'total_size_gb': 1000.0, 'data_change': {'daily_change_gb': 50.0, 'data_points': 70}},
            }
        }
        data2 = {
            'change_rates': {
                'RDS': {'provider': 'aws', 'service_family': 'RDS', 'resource_count': 3,
                        'total_size_gb': 200.0, 'data_change': {'daily_change_gb': 10.0, 'data_points': 21}},
            }
        }

        merge_change_rates(accumulated, data1)
        merge_change_rates(accumulated, data2)

        assert 'EBS' in accumulated
        assert 'RDS' in accumulated
        assert accumulated['EBS']['resource_count'] == 10
        assert accumulated['RDS']['resource_count'] == 3

    def test_merge_with_transaction_logs(self):
        """Test merging data with transaction logs."""
        accumulated = {
            'RDS': {
                'provider': 'aws',
                'service_family': 'RDS',
                'resource_count': 2,
                'total_size_gb': 100.0,
                'data_change': {'daily_change_gb': 5.0, 'data_points': 14},
                'transaction_logs': {'daily_generation_gb': 2.0}
            }
        }
        new_data = {
            'change_rates': {
                'RDS': {
                    'provider': 'aws',
                    'service_family': 'RDS',
                    'resource_count': 1,
                    'total_size_gb': 50.0,
                    'data_change': {'daily_change_gb': 2.5, 'data_points': 7},
                    'transaction_logs': {'daily_generation_gb': 1.0}
                }
            }
        }

        merge_change_rates(accumulated, new_data)

        assert accumulated['RDS']['transaction_logs']['daily_generation_gb'] == 3.0

    def test_merge_adds_transaction_logs(self):
        """Test merging adds transaction logs when not in accumulated."""
        accumulated = {
            'RDS': {
                'provider': 'aws',
                'service_family': 'RDS',
                'resource_count': 2,
                'total_size_gb': 100.0,
                'data_change': {'daily_change_gb': 5.0, 'data_points': 14},
            }
        }
        new_data = {
            'change_rates': {
                'RDS': {
                    'provider': 'aws',
                    'service_family': 'RDS',
                    'resource_count': 1,
                    'total_size_gb': 50.0,
                    'data_change': {'daily_change_gb': 2.5, 'data_points': 7},
                    'transaction_logs': {'daily_generation_gb': 1.0}
                }
            }
        }

        merge_change_rates(accumulated, new_data)

        assert 'transaction_logs' in accumulated['RDS']
        assert accumulated['RDS']['transaction_logs']['daily_generation_gb'] == 1.0

    def test_merge_empty_new_data(self):
        """Test merging empty new data doesn't change accumulated."""
        accumulated = {'EBS': {'resource_count': 10, 'total_size_gb': 1000.0,
                               'data_change': {'daily_change_gb': 50.0, 'data_points': 70}}}
        new_data = {'change_rates': {}}

        merge_change_rates(accumulated, new_data)

        assert accumulated['EBS']['resource_count'] == 10

    def test_merge_missing_change_rates_key(self):
        """Test merging data without change_rates key."""
        accumulated = {}
        new_data = {}  # No change_rates key

        merge_change_rates(accumulated, new_data)

        assert accumulated == {}


# =============================================================================
# finalize_change_rate_output Tests
# =============================================================================

class TestFinalizeChangeRateOutput:
    """Tests for finalize_change_rate_output function."""

    def test_recalculates_percentages(self):
        """Test percentage recalculation after aggregation."""
        all_change_rates = {
            'EBS': {
                'provider': 'aws',
                'service_family': 'EBS',
                'resource_count': 10,
                'total_size_gb': 1000.0,
                'data_change': {
                    'daily_change_gb': 50.0,  # 5% of 1000
                    'data_points': 70,
                }
            }
        }

        result = finalize_change_rate_output(all_change_rates)

        assert result['change_rates']['EBS']['data_change']['daily_change_percent'] == 5.0

    def test_includes_metadata(self):
        """Test output includes collection metadata."""
        all_change_rates = {}
        result = finalize_change_rate_output(all_change_rates, sample_days=14)

        assert 'collection_metadata' in result
        assert 'collected_at' in result['collection_metadata']
        assert result['collection_metadata']['sample_period_days'] == 14
        assert isinstance(result['collection_metadata']['notes'], list)

    def test_custom_provider_note(self):
        """Test custom provider note in output."""
        all_change_rates = {}
        result = finalize_change_rate_output(all_change_rates, provider_note="CloudWatch")

        notes = result['collection_metadata']['notes']
        assert any('CloudWatch' in note for note in notes)

    def test_no_percentage_for_zero_size(self):
        """Test no percentage calculated when total_size_gb is 0."""
        all_change_rates = {
            'EBS': {
                'total_size_gb': 0,
                'data_change': {'daily_change_gb': 0, 'data_points': 0}
            }
        }

        result = finalize_change_rate_output(all_change_rates)

        # Should not have daily_change_percent added
        assert 'daily_change_percent' not in result['change_rates']['EBS']['data_change']

    def test_no_percentage_for_zero_change(self):
        """Test no percentage calculated when daily_change_gb is 0."""
        all_change_rates = {
            'EBS': {
                'total_size_gb': 1000.0,
                'data_change': {'daily_change_gb': 0, 'data_points': 70}
            }
        }

        result = finalize_change_rate_output(all_change_rates)

        # Should not have daily_change_percent added
        assert 'daily_change_percent' not in result['change_rates']['EBS']['data_change']

    def test_timestamp_format(self):
        """Test collected_at timestamp is ISO format."""
        all_change_rates = {}
        result = finalize_change_rate_output(all_change_rates)

        collected_at = result['collection_metadata']['collected_at']
        # Should be parseable as ISO format
        datetime.fromisoformat(collected_at.replace('Z', '+00:00'))


# =============================================================================
# aggregate_change_rates Tests (basic sanity checks)
# =============================================================================

class TestAggregateChangeRates:
    """Tests for aggregate_change_rates function."""

    def test_aggregate_empty_list(self):
        """Test aggregating empty list."""
        result = aggregate_change_rates([])
        assert result == {}

    def test_aggregate_single_item(self):
        """Test aggregating single item."""
        items = [{
            'provider': 'aws',
            'service_family': 'EBS',
            'size_gb': 100.0,
            'data_change': DataChangeMetrics(daily_change_gb=5.0, data_points=7)
        }]

        result = aggregate_change_rates(items)

        assert 'aws:EBS' in result
        assert result['aws:EBS'].resource_count == 1
        assert result['aws:EBS'].total_size_gb == 100.0

    def test_aggregate_multiple_same_family(self):
        """Test aggregating multiple items of same family."""
        items = [
            {'provider': 'aws', 'service_family': 'EBS', 'size_gb': 100.0,
             'data_change': DataChangeMetrics(daily_change_gb=5.0, data_points=7)},
            {'provider': 'aws', 'service_family': 'EBS', 'size_gb': 200.0,
             'data_change': DataChangeMetrics(daily_change_gb=10.0, data_points=7)},
        ]

        result = aggregate_change_rates(items)

        assert result['aws:EBS'].resource_count == 2
        assert result['aws:EBS'].total_size_gb == 300.0
        assert result['aws:EBS'].data_change.daily_change_gb == 15.0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
