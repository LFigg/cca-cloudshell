"""
Tests for scripts/generate_protection_report.py helper functions.

Covers:
- load_inventory function
- build_resource_index function
- Resource filtering functions (get_ec2_instances, get_ebs_volumes, etc.)
- build_backup_selection_index function
- build_protected_resources_set function
- get_backup_plan_for_resource function
- format_tags function
- infer_backup_plan function
"""
import pytest
import json
import tempfile
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'scripts'))

from scripts.generate_protection_report import (
    load_inventory,
    build_resource_index,
    get_ec2_instances,
    get_ebs_volumes,
    get_rds_instances,
    get_other_primary_resources,
    get_snapshots,
    get_backup_plans,
    get_backup_selections,
    get_protected_resources,
    build_backup_selection_index,
    build_protected_resources_set,
    get_backup_plan_for_resource,
    format_tags,
    infer_backup_plan,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def sample_resources():
    """Sample resources for testing."""
    return [
        {
            'resource_id': 'arn:aws:ec2:us-east-1:123:instance/i-001',
            'resource_type': 'aws:ec2:instance',
            'name': 'web-server-1',
            'tags': {'Name': 'web-server-1', 'Environment': 'prod'},
            'metadata': {}
        },
        {
            'resource_id': 'arn:aws:ec2:us-east-1:123:volume/vol-001',
            'resource_type': 'aws:ec2:volume',
            'name': 'vol-001',
            'tags': {},
            'metadata': {'attached_to': 'i-001'}
        },
        {
            'resource_id': 'arn:aws:ec2:us-east-1:123:snapshot/snap-001',
            'resource_type': 'aws:ec2:snapshot',
            'name': 'snap-001',
            'tags': {'BackupType': 'daily'},
            'metadata': {'source_volume': 'vol-001'}
        },
        {
            'resource_id': 'arn:aws:rds:us-east-1:123:db/mydb',
            'resource_type': 'aws:rds:instance',
            'name': 'mydb',
            'tags': {},
            'metadata': {}
        },
        {
            'resource_id': 'arn:aws:s3:::my-bucket',
            'resource_type': 'aws:s3:bucket',
            'name': 'my-bucket',
            'tags': {},
            'metadata': {}
        },
        {
            'resource_id': 'arn:aws:backup:us-east-1:123:plan/plan-001',
            'resource_type': 'aws:backup:plan',
            'name': 'daily-backup-plan',
            'tags': {},
            'metadata': {'rule_names': ['DailyRule']}
        },
        {
            'resource_id': 'arn:aws:backup:us-east-1:123:selection/sel-001',
            'resource_type': 'aws:backup:selection',
            'name': 'sel-001',
            'tags': {},
            'metadata': {
                'backup_plan_name': 'daily-backup-plan',
                'resources': ['arn:aws:ec2:us-east-1:123:volume/vol-001']
            }
        },
        {
            'resource_id': 'arn:aws:backup:us-east-1:123:protected/vol-001',
            'resource_type': 'aws:backup:protected-resource',
            'name': 'protected-vol-001',
            'tags': {},
            'metadata': {'resource_arn': 'arn:aws:ec2:us-east-1:123:volume/vol-001'}
        },
    ]


@pytest.fixture
def sample_inventory(sample_resources):
    """Sample inventory structure."""
    return {
        'run_id': 'test-run-001',
        'timestamp': '2026-01-15T10:00:00Z',
        'resources': sample_resources
    }


# =============================================================================
# load_inventory Tests
# =============================================================================

class TestLoadInventory:
    """Tests for load_inventory function."""
    
    def test_load_valid_inventory(self, sample_inventory):
        """Test loading a valid inventory file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(sample_inventory, f)
            filepath = f.name
        
        try:
            result = load_inventory(filepath)
            assert result['run_id'] == 'test-run-001'
            assert len(result['resources']) == 8
        finally:
            os.unlink(filepath)
    
    def test_load_nonexistent_file(self):
        """Test loading a nonexistent file raises error."""
        with pytest.raises(FileNotFoundError):
            load_inventory('/nonexistent/path/inventory.json')


# =============================================================================
# build_resource_index Tests
# =============================================================================

class TestBuildResourceIndex:
    """Tests for build_resource_index function."""
    
    def test_build_index(self, sample_resources):
        """Test building resource index."""
        index = build_resource_index(sample_resources)
        
        assert len(index) == 8
        assert 'arn:aws:ec2:us-east-1:123:instance/i-001' in index
        assert index['arn:aws:ec2:us-east-1:123:instance/i-001']['name'] == 'web-server-1'
    
    def test_empty_resources(self):
        """Test building index from empty list."""
        index = build_resource_index([])
        assert index == {}


# =============================================================================
# Resource Filtering Tests
# =============================================================================

class TestResourceFiltering:
    """Tests for resource filtering functions."""
    
    def test_get_ec2_instances(self, sample_resources):
        """Test filtering EC2 instances."""
        instances = get_ec2_instances(sample_resources)
        assert len(instances) == 1
        assert instances[0]['resource_type'] == 'aws:ec2:instance'
    
    def test_get_ebs_volumes(self, sample_resources):
        """Test filtering EBS volumes."""
        volumes = get_ebs_volumes(sample_resources)
        assert len(volumes) == 1
        assert volumes[0]['resource_type'] == 'aws:ec2:volume'
    
    def test_get_rds_instances(self, sample_resources):
        """Test filtering RDS instances."""
        rds = get_rds_instances(sample_resources)
        assert len(rds) == 1
        assert rds[0]['resource_type'] == 'aws:rds:instance'
    
    def test_get_other_primary_resources(self, sample_resources):
        """Test filtering other primary resources."""
        others = get_other_primary_resources(sample_resources)
        assert len(others) == 1
        assert others[0]['resource_type'] == 'aws:s3:bucket'
    
    def test_get_snapshots(self, sample_resources):
        """Test filtering snapshots."""
        snapshots = get_snapshots(sample_resources)
        assert len(snapshots) == 1
        assert snapshots[0]['resource_type'] == 'aws:ec2:snapshot'
    
    def test_get_backup_plans(self, sample_resources):
        """Test filtering backup plans."""
        plans = get_backup_plans(sample_resources)
        assert len(plans) == 1
        assert plans[0]['resource_type'] == 'aws:backup:plan'
    
    def test_get_backup_selections(self, sample_resources):
        """Test filtering backup selections."""
        selections = get_backup_selections(sample_resources)
        assert len(selections) == 1
        assert selections[0]['resource_type'] == 'aws:backup:selection'
    
    def test_get_protected_resources(self, sample_resources):
        """Test filtering protected resources."""
        protected = get_protected_resources(sample_resources)
        assert len(protected) == 1
        assert protected[0]['resource_type'] == 'aws:backup:protected-resource'


# =============================================================================
# build_backup_selection_index Tests
# =============================================================================

class TestBuildBackupSelectionIndex:
    """Tests for build_backup_selection_index function."""
    
    def test_build_index(self, sample_resources):
        """Test building backup selection index."""
        selections = get_backup_selections(sample_resources)
        index = build_backup_selection_index(selections)
        
        assert 'arn:aws:ec2:us-east-1:123:volume/vol-001' in index
        assert 'daily-backup-plan' in index['arn:aws:ec2:us-east-1:123:volume/vol-001']
    
    def test_empty_selections(self):
        """Test building index from empty selections."""
        index = build_backup_selection_index([])
        assert index == {}


# =============================================================================
# build_protected_resources_set Tests
# =============================================================================

class TestBuildProtectedResourcesSet:
    """Tests for build_protected_resources_set function."""
    
    def test_build_set(self, sample_resources):
        """Test building protected resources set."""
        protected = get_protected_resources(sample_resources)
        protected_set = build_protected_resources_set(protected)
        
        assert 'arn:aws:ec2:us-east-1:123:volume/vol-001' in protected_set
    
    def test_empty_protected(self):
        """Test building set from empty list."""
        protected_set = build_protected_resources_set([])
        assert protected_set == set()  # Empty set for empty input


# =============================================================================
# format_tags Tests
# =============================================================================

class TestFormatTags:
    """Tests for format_tags function."""
    
    def test_format_multiple_tags(self):
        """Test formatting multiple tags."""
        tags = {'Name': 'my-resource', 'Environment': 'prod'}
        result = format_tags(tags)
        
        # Result should contain both tags with semicolon separator
        assert 'Name=my-resource' in result
        assert 'Environment=prod' in result
        assert ';' in result
    
    def test_format_single_tag(self):
        """Test formatting single tag."""
        tags = {'Name': 'my-resource'}
        result = format_tags(tags)
        assert result == 'Name=my-resource'
    
    def test_format_empty_tags(self):
        """Test formatting empty tags."""
        assert format_tags({}) == ''
        assert format_tags(None) == ''  # type: ignore[arg-type]


# =============================================================================
# get_backup_plan_for_resource Tests
# =============================================================================

class TestGetBackupPlanForResource:
    """Tests for get_backup_plan_for_resource function."""
    
    def test_resource_in_selection(self, sample_resources):
        """Test resource found in backup selection."""
        selections = get_backup_selections(sample_resources)
        selection_index = build_backup_selection_index(selections)
        protected = get_protected_resources(sample_resources)
        protected_set = build_protected_resources_set(protected)
        backup_plans = get_backup_plans(sample_resources)
        
        volume = {
            'resource_id': 'arn:aws:ec2:us-east-1:123:volume/vol-001',
            'resource_type': 'aws:ec2:volume'
        }
        
        plan_name, source = get_backup_plan_for_resource(
            volume, selection_index, protected_set, backup_plans
        )
        
        assert plan_name == 'daily-backup-plan'
        assert source == 'backup_selection'
    
    def test_resource_has_recovery_points(self, sample_resources):
        """Test resource with recovery points but not in selection."""
        selection_index = {}  # Empty - no selections
        protected = get_protected_resources(sample_resources)
        protected_set = build_protected_resources_set(protected)
        backup_plans = get_backup_plans(sample_resources)
        
        volume = {
            'resource_id': 'arn:aws:ec2:us-east-1:123:volume/vol-001',
            'resource_type': 'aws:ec2:volume'
        }
        
        plan_name, source = get_backup_plan_for_resource(
            volume, selection_index, protected_set, backup_plans
        )
        
        assert plan_name == '(has recovery points)'
        assert source == 'recovery_point'
    
    def test_resource_not_protected(self):
        """Test resource with no backup plan or recovery points."""
        instance = {
            'resource_id': 'arn:aws:ec2:us-east-1:123:instance/i-999',
            'resource_type': 'aws:ec2:instance'
        }
        
        plan_name, source = get_backup_plan_for_resource(
            instance, {}, set(), []
        )
        
        assert plan_name is None
        assert source is None


# =============================================================================
# infer_backup_plan Tests
# =============================================================================

class TestInferBackupPlan:
    """Tests for infer_backup_plan function."""
    
    def test_infer_from_backup_type_tag(self):
        """Test inferring backup plan from BackupType tag."""
        snapshot = {
            'tags': {'BackupType': 'daily'},
            'metadata': {}
        }
        backup_plans = [
            {'name': 'daily-backup-plan', 'metadata': {'rule_names': ['DailyRule']}},
            {'name': 'weekly-backup-plan', 'metadata': {'rule_names': ['WeeklyRule']}},
        ]
        
        result = infer_backup_plan(snapshot, backup_plans)
        assert result == 'daily-backup-plan'
    
    def test_infer_from_description(self):
        """Test inferring backup plan from description."""
        snapshot = {
            'tags': {},
            'metadata': {'description': 'Daily automated backup'}
        }
        backup_plans = [
            {'name': 'daily-backup', 'metadata': {'rule_names': []}},
        ]
        
        result = infer_backup_plan(snapshot, backup_plans)
        assert result == 'daily-backup'
    
    def test_infer_fallback_daily(self):
        """Test fallback inference for daily backup type."""
        snapshot = {
            'tags': {'BackupType': 'daily'},
            'metadata': {}
        }
        backup_plans = []  # No matching plans
        
        result = infer_backup_plan(snapshot, backup_plans)
        assert result is not None and 'daily' in result.lower()
    
    def test_no_inference_possible(self):
        """Test when no inference is possible."""
        snapshot = {
            'tags': {},
            'metadata': {}
        }
        backup_plans = []
        
        result = infer_backup_plan(snapshot, backup_plans)
        assert result is None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
