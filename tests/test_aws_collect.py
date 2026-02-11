"""
Comprehensive tests for AWS resource collector using moto.

Covers:
- Normal operation with good values
- Empty/null return scenarios
- Non-optimal configurations
- Error handling
"""
import pytest
import boto3
from moto import (
    mock_aws,
)
from datetime import datetime
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aws_collect import (
    get_session,
    get_account_id,
    get_enabled_regions,
    collect_ec2_instances,
    collect_ebs_volumes,
    collect_ebs_snapshots,
    collect_rds_instances,
    collect_rds_clusters,
    collect_rds_snapshots,
    collect_rds_cluster_snapshots,
    collect_s3_buckets,
    collect_efs_filesystems,
    collect_lambda_functions,
    collect_dynamodb_tables,
    collect_eks_clusters,
    collect_elasticache_clusters,
    collect_backup_vaults,
    collect_backup_recovery_points,
    collect_backup_plans,
    collect_backup_selections,
    collect_backup_protected_resources,
    collect_region,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture
def mock_session(aws_credentials):
    """Create a mocked boto3 session."""
    return boto3.Session(region_name="us-east-1")


# =============================================================================
# Session Management Tests
# =============================================================================

class TestSessionManagement:
    """Tests for session and account management functions."""
    
    @mock_aws
    def test_get_account_id(self, mock_session):
        """Test getting AWS account ID."""
        account_id = get_account_id(mock_session)
        assert account_id is not None
        assert len(account_id) == 12
        
    @mock_aws
    def test_get_enabled_regions(self, mock_session):
        """Test getting enabled regions."""
        regions = get_enabled_regions(mock_session)
        assert isinstance(regions, list)
        assert len(regions) > 0
        assert "us-east-1" in regions


# =============================================================================
# EC2 Instance Tests
# =============================================================================

class TestEC2Instances:
    """Tests for EC2 instance collection."""
    
    @mock_aws
    def test_collect_instances_with_volumes_and_tags(self, mock_session):
        """Test collecting EC2 instances with attached volumes and tags."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        
        # Create VPC
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]
        
        # Create subnet
        subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")
        subnet_id = subnet["Subnet"]["SubnetId"]
        
        # Run instance with tags
        instances = ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="t2.micro",
            SubnetId=subnet_id,
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "Name", "Value": "test-instance"},
                        {"Key": "Environment", "Value": "test"},
                    ],
                }
            ],
        )
        instance_id = instances["Instances"][0]["InstanceId"]
        
        # Collect resources
        resources = collect_ec2_instances(mock_session, "us-east-1", "123456789012")
        
        assert len(resources) == 1
        resource = resources[0]
        assert resource.resource_type == "aws:ec2:instance"
        assert resource.name == "test-instance"
        assert resource.tags["Environment"] == "test"
        assert resource.metadata["instance_type"] == "t2.micro"
        assert resource.metadata["vpc_id"] == vpc_id
        
    @mock_aws
    def test_collect_instance_no_tags(self, mock_session):
        """Test collecting EC2 instance without tags - should use instance ID as name."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        
        instances = ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="t3.medium",
        )
        instance_id = instances["Instances"][0]["InstanceId"]
        
        resources = collect_ec2_instances(mock_session, "us-east-1", "123456789012")
        
        assert len(resources) == 1
        resource = resources[0]
        # Name should fall back to instance ID when no tags
        assert resource.name == instance_id
        assert resource.tags == {}
        
    @mock_aws
    def test_collect_instance_no_attached_volumes(self, mock_session):
        """Test collecting EC2 instance with no block device mappings."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        
        # Run a basic instance (moto creates with root volume by default)
        ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="t2.nano",
        )
        
        resources = collect_ec2_instances(mock_session, "us-east-1", "123456789012")
        
        assert len(resources) == 1
        # attached_volumes should be a list (possibly empty or with root volume)
        assert isinstance(resources[0].metadata["attached_volumes"], list)
        
    @mock_aws
    def test_collect_instances_empty_region(self, mock_session):
        """Test collecting EC2 instances from region with no instances."""
        resources = collect_ec2_instances(mock_session, "us-west-2", "123456789012")
        
        assert resources == []
        
    @mock_aws
    def test_collect_instances_multiple_states(self, mock_session):
        """Test collecting instances in various states (running, stopped)."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        
        # Create two instances
        instances = ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=2,
            MaxCount=2,
            InstanceType="t2.micro",
        )
        
        # Stop one instance
        instance_to_stop = instances["Instances"][0]["InstanceId"]
        ec2.stop_instances(InstanceIds=[instance_to_stop])
        
        resources = collect_ec2_instances(mock_session, "us-east-1", "123456789012")
        
        assert len(resources) == 2
        states = {r.metadata["state"] for r in resources}
        assert "running" in states or "stopped" in states


# =============================================================================
# EBS Volume Tests
# =============================================================================

class TestEBSVolumes:
    """Tests for EBS volume collection."""
    
    @mock_aws
    def test_collect_volumes_attached(self, mock_session):
        """Test collecting EBS volumes attached to instances."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        
        # Create an instance (creates root volume automatically)
        instances = ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="t2.micro",
        )
        instance_id = instances["Instances"][0]["InstanceId"]
        
        # Create and attach an additional volume
        volume = ec2.create_volume(
            AvailabilityZone="us-east-1a",
            Size=100,
            VolumeType="gp3",
            Encrypted=True,
            TagSpecifications=[
                {
                    "ResourceType": "volume",
                    "Tags": [{"Key": "Name", "Value": "data-volume"}],
                }
            ],
        )
        volume_id = volume["VolumeId"]
        
        ec2.attach_volume(
            VolumeId=volume_id,
            InstanceId=instance_id,
            Device="/dev/sdf",
        )
        
        resources = collect_ebs_volumes(mock_session, "us-east-1", "123456789012")
        
        # Find the attached volume we created
        attached_volumes = [r for r in resources if r.name == "data-volume"]
        assert len(attached_volumes) == 1
        vol = attached_volumes[0]
        assert vol.size_gb == 100.0
        assert vol.metadata["encrypted"] == True
        assert vol.metadata["volume_type"] == "gp3"
        assert vol.metadata["attached_instance"] == instance_id
        assert vol.parent_resource_id == instance_id
        
    @mock_aws
    def test_collect_volumes_unattached(self, mock_session):
        """Test collecting unattached EBS volumes."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        
        # Create standalone volume, not attached
        ec2.create_volume(
            AvailabilityZone="us-east-1a",
            Size=500,
            VolumeType="gp2",
            Encrypted=False,
            TagSpecifications=[
                {
                    "ResourceType": "volume",
                    "Tags": [{"Key": "Name", "Value": "orphan-volume"}],
                }
            ],
        )
        
        resources = collect_ebs_volumes(mock_session, "us-east-1", "123456789012")
        
        orphan = next((r for r in resources if r.name == "orphan-volume"), None)
        assert orphan is not None
        assert orphan.size_gb == 500.0
        assert orphan.metadata["attached_instance"] is None
        assert orphan.parent_resource_id is None
        assert orphan.metadata["encrypted"] == False
        
    @mock_aws
    def test_collect_volumes_no_tags(self, mock_session):
        """Test collecting volumes without tags - name falls back to volume ID."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        
        volume = ec2.create_volume(
            AvailabilityZone="us-east-1a",
            Size=50,
            VolumeType="standard",
        )
        volume_id = volume["VolumeId"]
        
        resources = collect_ebs_volumes(mock_session, "us-east-1", "123456789012")
        
        vol = next((r for r in resources if r.resource_id == volume_id), None)
        assert vol is not None
        # Name should fall back to volume ID
        assert vol.name == volume_id
        assert vol.tags == {}
        
    @mock_aws
    def test_collect_volumes_empty(self, mock_session):
        """Test collecting volumes from region with no volumes."""
        resources = collect_ebs_volumes(mock_session, "us-west-2", "123456789012")
        assert resources == []
        
    @mock_aws
    def test_collect_volumes_various_types(self, mock_session):
        """Test collecting volumes of different types."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        
        volume_types = ["gp2", "gp3", "io1", "st1", "sc1", "standard"]
        
        for i, vol_type in enumerate(volume_types):
            kwargs = {
                "AvailabilityZone": "us-east-1a",
                "Size": 100 if vol_type not in ["st1", "sc1"] else 500,  # st1/sc1 require min 500GB
                "VolumeType": vol_type,
            }
            if vol_type == "io1":
                kwargs["Iops"] = 100
            ec2.create_volume(**kwargs)
            
        resources = collect_ebs_volumes(mock_session, "us-east-1", "123456789012")
        
        collected_types = {r.metadata["volume_type"] for r in resources}
        assert collected_types == set(volume_types)


# =============================================================================
# RDS Tests
# =============================================================================

class TestRDS:
    """Tests for RDS instance and cluster collection."""
    
    @mock_aws
    def test_collect_rds_instance(self, mock_session):
        """Test collecting RDS instances."""
        rds = boto3.client("rds", region_name="us-east-1")
        
        rds.create_db_instance(
            DBInstanceIdentifier="test-mysql",
            DBInstanceClass="db.t3.micro",
            Engine="mysql",
            MasterUsername="admin",
            MasterUserPassword="password123",
            AllocatedStorage=100,
            StorageEncrypted=True,
        )
        
        resources = collect_rds_instances(mock_session, "us-east-1", "123456789012")
        
        assert len(resources) == 1
        db = resources[0]
        assert db.resource_type == "aws:rds:instance"
        assert db.name == "test-mysql"
        assert db.size_gb == 100.0
        assert db.metadata["engine"] == "mysql"
        assert db.metadata["encrypted"] == True
        
    @mock_aws
    def test_collect_rds_instance_minimal(self, mock_session):
        """Test collecting RDS instance with minimal configuration."""
        rds = boto3.client("rds", region_name="us-east-1")
        
        rds.create_db_instance(
            DBInstanceIdentifier="minimal-db",
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            MasterUsername="admin",
            MasterUserPassword="password123",
            AllocatedStorage=20,
        )
        
        resources = collect_rds_instances(mock_session, "us-east-1", "123456789012")
        
        assert len(resources) == 1
        assert resources[0].metadata["multi_az"] == False
        
    @mock_aws
    def test_collect_rds_instances_empty(self, mock_session):
        """Test collecting RDS instances from empty region."""
        resources = collect_rds_instances(mock_session, "us-west-2", "123456789012")
        assert resources == []
        
    @mock_aws
    def test_collect_rds_cluster_aurora(self, mock_session):
        """Test collecting Aurora RDS clusters."""
        rds = boto3.client("rds", region_name="us-east-1")
        
        rds.create_db_cluster(
            DBClusterIdentifier="test-aurora-cluster",
            Engine="aurora-mysql",
            MasterUsername="admin",
            MasterUserPassword="password123",
            DatabaseName="testdb",
        )
        
        resources = collect_rds_clusters(mock_session, "us-east-1", "123456789012")
        
        assert len(resources) == 1
        cluster = resources[0]
        assert cluster.resource_type == "aws:rds:cluster"
        assert cluster.name == "test-aurora-cluster"
        assert cluster.metadata["engine"] == "aurora-mysql"
        
    @mock_aws
    def test_collect_rds_clusters_empty(self, mock_session):
        """Test collecting RDS clusters from empty region."""
        resources = collect_rds_clusters(mock_session, "us-west-2", "123456789012")
        assert resources == []


# =============================================================================
# EBS Snapshot Tests
# =============================================================================

class TestEBSSnapshots:
    """Tests for EBS snapshot collection."""
    
    @mock_aws
    def test_collect_snapshots_with_tags(self, mock_session):
        """Test collecting EBS snapshots with tags."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        
        # Create a volume first
        volume = ec2.create_volume(
            AvailabilityZone="us-east-1a",
            Size=100,
            VolumeType="gp2",
        )
        volume_id = volume["VolumeId"]
        
        # Create snapshot with tags
        snapshot = ec2.create_snapshot(
            VolumeId=volume_id,
            Description="Test backup snapshot",
            TagSpecifications=[
                {
                    "ResourceType": "snapshot",
                    "Tags": [
                        {"Key": "Name", "Value": "daily-backup"},
                        {"Key": "BackupType", "Value": "daily"},
                    ],
                }
            ],
        )
        snapshot_id = snapshot["SnapshotId"]
        
        resources = collect_ebs_snapshots(mock_session, "us-east-1", "123456789012")
        
        # Filter to our created snapshot (moto includes AMI snapshots)
        our_snapshots = [r for r in resources if r.resource_id == snapshot_id]
        assert len(our_snapshots) == 1
        snap = our_snapshots[0]
        assert snap.resource_type == "aws:ec2:snapshot"
        assert snap.name == "daily-backup"
        assert snap.tags["BackupType"] == "daily"
        assert snap.size_gb == 100.0
        assert snap.parent_resource_id == volume_id
        assert snap.metadata["volume_id"] == volume_id
        assert snap.metadata["description"] == "Test backup snapshot"
        
    @mock_aws
    def test_collect_snapshots_no_tags(self, mock_session):
        """Test collecting EBS snapshots without tags - name falls back to snapshot ID."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        
        volume = ec2.create_volume(
            AvailabilityZone="us-east-1a",
            Size=50,
            VolumeType="gp2",
        )
        
        snapshot = ec2.create_snapshot(
            VolumeId=volume["VolumeId"],
            Description="Untagged snapshot",
        )
        snapshot_id = snapshot["SnapshotId"]
        
        resources = collect_ebs_snapshots(mock_session, "us-east-1", "123456789012")
        
        # Filter to our created snapshot (moto includes AMI snapshots)
        our_snapshots = [r for r in resources if r.resource_id == snapshot_id]
        assert len(our_snapshots) == 1
        # Name should fall back to snapshot ID
        assert our_snapshots[0].name == snapshot_id
        assert our_snapshots[0].tags == {}
        
    @mock_aws
    def test_collect_snapshots_empty(self, mock_session):
        """Test that collector runs without error in region with no user snapshots."""
        # Note: moto includes pre-baked AMI snapshots, so we just verify the collector works
        resources = collect_ebs_snapshots(mock_session, "us-west-2", "123456789012")
        # All snapshots should have proper structure
        for r in resources:
            assert r.resource_type == "aws:ec2:snapshot"
            assert r.service_family == "EC2"
        
    @mock_aws
    def test_collect_snapshots_multiple(self, mock_session):
        """Test collecting multiple snapshots from same volume."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        
        volume = ec2.create_volume(
            AvailabilityZone="us-east-1a",
            Size=100,
            VolumeType="gp2",
        )
        volume_id = volume["VolumeId"]
        
        # Create multiple snapshots
        created_ids = []
        for i in range(3):
            snap = ec2.create_snapshot(
                VolumeId=volume_id,
                Description=f"Snapshot {i+1}",
            )
            created_ids.append(snap["SnapshotId"])
        
        resources = collect_ebs_snapshots(mock_session, "us-east-1", "123456789012")
        
        # Filter to our created snapshots
        our_snapshots = [r for r in resources if r.resource_id in created_ids]
        assert len(our_snapshots) == 3
        # All should reference the same volume
        for snap in our_snapshots:
            assert snap.parent_resource_id == volume_id


# =============================================================================
# RDS Snapshot Tests
# =============================================================================

class TestRDSSnapshots:
    """Tests for RDS snapshot collection."""
    
    @mock_aws
    def test_collect_rds_snapshots(self, mock_session):
        """Test collecting RDS DB snapshots."""
        rds = boto3.client("rds", region_name="us-east-1")
        
        # Create DB instance first
        rds.create_db_instance(
            DBInstanceIdentifier="test-mysql",
            DBInstanceClass="db.t3.micro",
            Engine="mysql",
            MasterUsername="admin",
            MasterUserPassword="password123",
            AllocatedStorage=100,
        )
        
        # Create snapshot
        rds.create_db_snapshot(
            DBSnapshotIdentifier="test-mysql-backup",
            DBInstanceIdentifier="test-mysql",
        )
        
        resources = collect_rds_snapshots(mock_session, "us-east-1", "123456789012")
        
        # Filter to our manual snapshot (moto may create automated snapshots)
        our_snapshots = [r for r in resources if r.name == "test-mysql-backup"]
        assert len(our_snapshots) == 1
        snap = our_snapshots[0]
        assert snap.resource_type == "aws:rds:snapshot"
        assert snap.name == "test-mysql-backup"
        assert snap.parent_resource_id == "test-mysql"
        assert snap.metadata["db_instance_id"] == "test-mysql"
        assert snap.metadata["engine"] == "mysql"
        
    @mock_aws
    def test_collect_rds_snapshots_empty(self, mock_session):
        """Test collecting RDS snapshots from empty region."""
        resources = collect_rds_snapshots(mock_session, "us-west-2", "123456789012")
        assert resources == []
        
    @mock_aws
    def test_collect_rds_cluster_snapshots(self, mock_session):
        """Test collecting Aurora cluster snapshots."""
        rds = boto3.client("rds", region_name="us-east-1")
        
        # Create Aurora cluster
        rds.create_db_cluster(
            DBClusterIdentifier="test-aurora",
            Engine="aurora-mysql",
            MasterUsername="admin",
            MasterUserPassword="password123",
        )
        
        # Create cluster snapshot
        rds.create_db_cluster_snapshot(
            DBClusterSnapshotIdentifier="aurora-backup",
            DBClusterIdentifier="test-aurora",
        )
        
        resources = collect_rds_cluster_snapshots(mock_session, "us-east-1", "123456789012")
        
        # Filter to our manual snapshot (moto may create automated snapshots)
        our_snapshots = [r for r in resources if r.name == "aurora-backup"]
        assert len(our_snapshots) == 1
        snap = our_snapshots[0]
        assert snap.resource_type == "aws:rds:cluster-snapshot"
        assert snap.name == "aurora-backup"
        assert snap.parent_resource_id == "test-aurora"
        assert snap.metadata["db_cluster_id"] == "test-aurora"
        
    @mock_aws
    def test_collect_rds_cluster_snapshots_empty(self, mock_session):
        """Test collecting Aurora cluster snapshots from empty region."""
        resources = collect_rds_cluster_snapshots(mock_session, "us-west-2", "123456789012")
        assert resources == []


# =============================================================================
# AWS Backup Tests
# =============================================================================

class TestBackupVaults:
    """Tests for AWS Backup vault collection."""
    
    @mock_aws
    def test_collect_backup_vaults(self, mock_session):
        """Test collecting backup vaults."""
        backup = boto3.client("backup", region_name="us-east-1")
        
        # Create a backup vault
        backup.create_backup_vault(BackupVaultName="my-vault")
        
        resources = collect_backup_vaults(mock_session, "us-east-1", "123456789012")
        
        # Should have at least our vault (moto may include default vault)
        vault_names = [r.name for r in resources]
        assert "my-vault" in vault_names
        
        our_vault = [r for r in resources if r.name == "my-vault"][0]
        assert our_vault.resource_type == "aws:backup:vault"
        assert our_vault.service_family == "Backup"
        
    @mock_aws
    def test_collect_backup_vaults_empty(self, mock_session):
        """Test collecting backup vaults from region with none."""
        resources = collect_backup_vaults(mock_session, "us-west-2", "123456789012")
        # May have default vault, just verify structure
        for r in resources:
            assert r.resource_type == "aws:backup:vault"


class TestBackupRecoveryPoints:
    """Tests for AWS Backup recovery point collection."""
    
    @mock_aws
    def test_collect_recovery_points(self, mock_session):
        """Test collecting backup recovery points."""
        backup = boto3.client("backup", region_name="us-east-1")
        ec2 = boto3.client("ec2", region_name="us-east-1")
        
        # Create a backup vault
        backup.create_backup_vault(BackupVaultName="test-vault")
        
        # Create an EBS volume to back up
        volume = ec2.create_volume(
            AvailabilityZone="us-east-1a",
            Size=100,
            VolumeType="gp2",
        )
        volume_arn = f"arn:aws:ec2:us-east-1:123456789012:volume/{volume['VolumeId']}"
        
        # Start a backup job (moto will create recovery point)
        try:
            backup.start_backup_job(
                BackupVaultName="test-vault",
                ResourceArn=volume_arn,
                IamRoleArn="arn:aws:iam::123456789012:role/backup-role",
            )
        except Exception:
            # moto may not fully support start_backup_job
            pass
        
        resources = collect_backup_recovery_points(mock_session, "us-east-1", "123456789012")
        
        # Verify structure if any recovery points exist
        for r in resources:
            assert r.resource_type == "aws:backup:recovery-point"
            assert r.service_family == "Backup"
            assert "backup_vault_name" in r.metadata
            
    @mock_aws
    def test_collect_recovery_points_empty(self, mock_session):
        """Test collecting recovery points from empty region."""
        resources = collect_backup_recovery_points(mock_session, "us-west-2", "123456789012")
        # Empty region should return empty list
        assert resources == [] or all(r.resource_type == "aws:backup:recovery-point" for r in resources)


class TestBackupPlans:
    """Tests for AWS Backup plan collection."""
    
    @mock_aws
    def test_collect_backup_plans(self, mock_session):
        """Test collecting backup plans."""
        backup = boto3.client("backup", region_name="us-east-1")
        
        # Create a backup plan
        backup.create_backup_plan(
            BackupPlan={
                "BackupPlanName": "daily-backup-plan",
                "Rules": [
                    {
                        "RuleName": "daily-rule",
                        "TargetBackupVaultName": "Default",
                        "ScheduleExpression": "cron(0 12 * * ? *)",
                        "Lifecycle": {
                            "DeleteAfterDays": 30
                        }
                    }
                ]
            }
        )
        
        resources = collect_backup_plans(mock_session, "us-east-1", "123456789012")
        
        assert len(resources) >= 1
        our_plan = [r for r in resources if r.name == "daily-backup-plan"][0]
        assert our_plan.resource_type == "aws:backup:plan"
        assert our_plan.service_family == "Backup"
        assert our_plan.metadata["number_of_rules"] == 1
        assert "daily-rule" in our_plan.metadata["rule_names"]
        
    @mock_aws
    def test_collect_backup_plans_empty(self, mock_session):
        """Test collecting backup plans from empty region."""
        resources = collect_backup_plans(mock_session, "us-west-2", "123456789012")
        assert resources == []


class TestBackupSelections:
    """Tests for Backup Selection collection."""
    
    @pytest.fixture
    def mock_session(self):
        """Create mock boto3 session."""
        return boto3.Session(region_name="us-east-1")
    
    @mock_aws
    def test_collect_backup_selections(self, mock_session):
        """Test collecting backup selections from a plan."""
        backup_client = mock_session.client("backup", region_name="us-east-1")
        iam_client = mock_session.client("iam")
        
        # Create IAM role for backup
        iam_client.create_role(
            RoleName="BackupRole",
            AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[]}',
        )
        
        # Create backup plan
        plan_response = backup_client.create_backup_plan(
            BackupPlan={
                "BackupPlanName": "test-plan",
                "Rules": [
                    {
                        "RuleName": "daily-rule",
                        "TargetBackupVaultName": "Default",
                        "ScheduleExpression": "cron(0 12 * * ? *)",
                    }
                ]
            }
        )
        plan_id = plan_response["BackupPlanId"]
        
        # Create backup selection - note: moto may not fully support this
        try:
            backup_client.create_backup_selection(
                BackupPlanId=plan_id,
                BackupSelection={
                    "SelectionName": "ec2-selection",
                    "IamRoleArn": f"arn:aws:iam::123456789012:role/BackupRole",
                    "Resources": [
                        "arn:aws:ec2:us-east-1:123456789012:volume/*"
                    ],
                }
            )
        except Exception:
            # moto may not support backup selections yet
            pytest.skip("moto does not support backup selections")
        
        resources = collect_backup_selections(mock_session, "us-east-1", "123456789012")
        
        # Should have at least our selection
        assert len(resources) >= 1
        
    @mock_aws
    def test_collect_backup_selections_empty(self, mock_session):
        """Test collecting backup selections from empty region."""
        resources = collect_backup_selections(mock_session, "us-west-2", "123456789012")
        assert resources == []


class TestBackupProtectedResources:
    """Tests for Backup Protected Resources collection."""
    
    @pytest.fixture
    def mock_session(self):
        """Create mock boto3 session."""
        return boto3.Session(region_name="us-east-1")
    
    @mock_aws
    def test_collect_backup_protected_resources_empty(self, mock_session):
        """Test collecting protected resources from empty region."""
        resources = collect_backup_protected_resources(mock_session, "us-west-2", "123456789012")
        # Should return empty list or may have some based on moto behavior
        assert isinstance(resources, list)
    
    @mock_aws
    def test_collect_backup_protected_resources_with_backup(self, mock_session):
        """Test collecting protected resources."""
        # Create EC2 instance
        ec2_client = mock_session.client("ec2", region_name="us-east-1")
        ec2_client.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="t2.micro",
        )
        
        # Note: moto may not track protected resources without actual backup jobs
        resources = collect_backup_protected_resources(mock_session, "us-east-1", "123456789012")
        
        # Should return a list (may be empty without actual backups)
        assert isinstance(resources, list)


# =============================================================================
# S3 Tests
# =============================================================================

class TestS3:
    """Tests for S3 bucket collection."""
    
    @mock_aws
    def test_collect_s3_buckets_with_tags(self, mock_session):
        """Test collecting S3 buckets with tags."""
        s3 = boto3.client("s3", region_name="us-east-1")
        
        s3.create_bucket(Bucket="test-bucket-with-tags")
        s3.put_bucket_tagging(
            Bucket="test-bucket-with-tags",
            Tagging={
                "TagSet": [
                    {"Key": "Environment", "Value": "production"},
                    {"Key": "Project", "Value": "cca"},
                ]
            },
        )
        
        resources = collect_s3_buckets(mock_session, "123456789012")
        
        assert len(resources) == 1
        bucket = resources[0]
        assert bucket.resource_type == "aws:s3:bucket"
        assert bucket.name == "test-bucket-with-tags"
        assert bucket.tags["Environment"] == "production"
        assert bucket.tags["Project"] == "cca"
        
    @mock_aws
    def test_collect_s3_buckets_no_tags(self, mock_session):
        """Test collecting S3 buckets without tags."""
        s3 = boto3.client("s3", region_name="us-east-1")
        
        s3.create_bucket(Bucket="bucket-no-tags")
        
        resources = collect_s3_buckets(mock_session, "123456789012")
        
        assert len(resources) == 1
        assert resources[0].tags == {}
        
    @mock_aws
    def test_collect_s3_buckets_different_regions(self, mock_session):
        """Test collecting S3 buckets from different regions."""
        s3 = boto3.client("s3", region_name="us-east-1")
        
        # us-east-1 bucket (no LocationConstraint needed)
        s3.create_bucket(Bucket="bucket-us-east-1")
        
        # us-west-2 bucket
        s3.create_bucket(
            Bucket="bucket-us-west-2",
            CreateBucketConfiguration={"LocationConstraint": "us-west-2"},
        )
        
        resources = collect_s3_buckets(mock_session, "123456789012")
        
        assert len(resources) == 2
        regions = {r.region for r in resources}
        assert "us-east-1" in regions
        assert "us-west-2" in regions
        
    @mock_aws
    def test_collect_s3_buckets_empty(self, mock_session):
        """Test collecting S3 buckets when none exist."""
        resources = collect_s3_buckets(mock_session, "123456789012")
        assert resources == []


# =============================================================================
# EFS Tests
# =============================================================================

class TestEFS:
    """Tests for EFS filesystem collection."""
    
    @mock_aws
    def test_collect_efs_with_tags(self, mock_session):
        """Test collecting EFS filesystems with tags."""
        efs = boto3.client("efs", region_name="us-east-1")
        
        fs = efs.create_file_system(
            CreationToken="test-efs-token",
            PerformanceMode="generalPurpose",
            Encrypted=True,
            Tags=[
                {"Key": "Name", "Value": "shared-storage"},
                {"Key": "Team", "Value": "platform"},
            ],
        )
        
        resources = collect_efs_filesystems(mock_session, "us-east-1", "123456789012")
        
        assert len(resources) == 1
        efs_res = resources[0]
        assert efs_res.resource_type == "aws:efs:filesystem"
        assert efs_res.name == "shared-storage"
        assert efs_res.tags["Team"] == "platform"
        assert efs_res.metadata["encrypted"] == True
        assert efs_res.metadata["performance_mode"] == "generalPurpose"
        
    @mock_aws
    def test_collect_efs_no_tags(self, mock_session):
        """Test collecting EFS without tags - name falls back to filesystem ID."""
        efs = boto3.client("efs", region_name="us-east-1")
        
        fs = efs.create_file_system(CreationToken="no-tag-efs")
        fs_id = fs["FileSystemId"]
        
        resources = collect_efs_filesystems(mock_session, "us-east-1", "123456789012")
        
        assert len(resources) == 1
        assert resources[0].name == fs_id
        
    @mock_aws
    def test_collect_efs_empty(self, mock_session):
        """Test collecting EFS from empty region."""
        resources = collect_efs_filesystems(mock_session, "us-west-2", "123456789012")
        assert resources == []


# =============================================================================
# Lambda Tests
# =============================================================================

class TestLambda:
    """Tests for Lambda function collection."""
    
    @mock_aws
    def test_collect_lambda_functions(self, mock_session):
        """Test collecting Lambda functions."""
        lambda_client = boto3.client("lambda", region_name="us-east-1")
        iam = boto3.client("iam", region_name="us-east-1")
        
        # Create IAM role for Lambda
        assume_role_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        
        role = iam.create_role(
            RoleName="lambda-role",
            AssumeRolePolicyDocument=str(assume_role_policy),
        )
        
        lambda_client.create_function(
            FunctionName="test-function",
            Runtime="python3.9",
            Role=role["Role"]["Arn"],
            Handler="handler.lambda_handler",
            Code={"ZipFile": b"fake code"},
            MemorySize=256,
            Timeout=30,
        )
        
        resources = collect_lambda_functions(mock_session, "us-east-1", "123456789012")
        
        assert len(resources) == 1
        func = resources[0]
        assert func.resource_type == "aws:lambda:function"
        assert func.name == "test-function"
        assert func.metadata["runtime"] == "python3.9"
        assert func.metadata["memory"] == 256
        assert func.metadata["timeout"] == 30
        
    @mock_aws
    def test_collect_lambda_empty(self, mock_session):
        """Test collecting Lambda functions from empty region."""
        resources = collect_lambda_functions(mock_session, "us-west-2", "123456789012")
        assert resources == []


# =============================================================================
# DynamoDB Tests
# =============================================================================

class TestDynamoDB:
    """Tests for DynamoDB table collection."""
    
    @mock_aws
    def test_collect_dynamodb_tables(self, mock_session):
        """Test collecting DynamoDB tables."""
        dynamodb = boto3.client("dynamodb", region_name="us-east-1")
        
        dynamodb.create_table(
            TableName="users-table",
            KeySchema=[{"AttributeName": "user_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "user_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        
        resources = collect_dynamodb_tables(mock_session, "us-east-1", "123456789012")
        
        assert len(resources) == 1
        table = resources[0]
        assert table.resource_type == "aws:dynamodb:table"
        assert table.name == "users-table"
        # New tables have 0 items/size
        assert table.metadata["item_count"] == 0
        
    @mock_aws
    def test_collect_dynamodb_empty(self, mock_session):
        """Test collecting DynamoDB tables from empty region."""
        resources = collect_dynamodb_tables(mock_session, "us-west-2", "123456789012")
        assert resources == []


# =============================================================================
# ElastiCache Tests
# =============================================================================

class TestElastiCache:
    """Tests for ElastiCache cluster collection."""
    
    @mock_aws
    def test_collect_elasticache_redis(self, mock_session):
        """Test collecting ElastiCache Redis clusters."""
        elasticache = boto3.client("elasticache", region_name="us-east-1")
        
        elasticache.create_cache_cluster(
            CacheClusterId="redis-cache",
            Engine="redis",
            CacheNodeType="cache.t3.micro",
            NumCacheNodes=1,
        )
        
        resources = collect_elasticache_clusters(mock_session, "us-east-1", "123456789012")
        
        assert len(resources) == 1
        cache = resources[0]
        assert cache.resource_type == "aws:elasticache:cluster"
        assert cache.name == "redis-cache"
        assert cache.metadata["engine"] == "redis"
        assert cache.metadata["node_type"] == "cache.t3.micro"
        
    @mock_aws
    def test_collect_elasticache_empty(self, mock_session):
        """Test collecting ElastiCache from empty region."""
        resources = collect_elasticache_clusters(mock_session, "us-west-2", "123456789012")
        assert resources == []


# =============================================================================
# Integration / collect_region Tests
# =============================================================================

class TestCollectRegion:
    """Integration tests for collecting all resources in a region."""
    
    @mock_aws
    def test_collect_region_mixed_resources(self, mock_session):
        """Test collecting multiple resource types from a single region."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        rds = boto3.client("rds", region_name="us-east-1")
        
        # Create EC2 instance
        ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="t2.micro",
        )
        
        # Create standalone volume
        ec2.create_volume(
            AvailabilityZone="us-east-1a",
            Size=100,
            VolumeType="gp2",
        )
        
        # Create RDS instance
        rds.create_db_instance(
            DBInstanceIdentifier="test-db",
            DBInstanceClass="db.t3.micro",
            Engine="mysql",
            MasterUsername="admin",
            MasterUserPassword="password123",
            AllocatedStorage=50,
        )
        
        resources = collect_region(mock_session, "us-east-1", "123456789012")
        
        resource_types = {r.resource_type for r in resources}
        assert "aws:ec2:instance" in resource_types
        assert "aws:ec2:volume" in resource_types
        assert "aws:rds:instance" in resource_types
        
    @mock_aws
    def test_collect_region_empty(self, mock_session):
        """Test collecting from a region with no user-created resources."""
        resources = collect_region(mock_session, "eu-west-1", "123456789012")
        # Filter out moto's pre-baked AMI snapshots which have "Auto-created snapshot for AMI" description
        user_resources = [
            r for r in resources 
            if not (r.resource_type == "aws:ec2:snapshot" and 
                    "Auto-created snapshot for AMI" in r.metadata.get("description", ""))
        ]
        assert user_resources == []


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error scenarios."""
    
    @mock_aws
    def test_instance_with_empty_string_values(self, mock_session):
        """Test handling instances where some fields might be empty strings."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        
        # Run basic instance
        ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="t2.micro",
        )
        
        resources = collect_ec2_instances(mock_session, "us-east-1", "123456789012")
        
        assert len(resources) == 1
        # Should handle missing/empty values gracefully
        resource = resources[0]
        assert resource.resource_id != ""
        assert resource.provider == "aws"
        
    @mock_aws 
    def test_volume_with_zero_size(self, mock_session):
        """Test that volumes always have a valid numeric size."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        
        # Minimum volume size is 1 GB, but test the handling
        ec2.create_volume(
            AvailabilityZone="us-east-1a",
            Size=1,  # Minimum size
            VolumeType="gp2",
        )
        
        resources = collect_ebs_volumes(mock_session, "us-east-1", "123456789012")
        
        assert len(resources) == 1
        assert resources[0].size_gb == 1.0
        assert isinstance(resources[0].size_gb, float)
        
    @mock_aws
    def test_s3_bucket_with_empty_name_filtered(self, mock_session):
        """Test that buckets must have a valid name."""
        s3 = boto3.client("s3", region_name="us-east-1")
        
        # Create normal bucket - empty bucket names aren't allowed by AWS
        s3.create_bucket(Bucket="valid-bucket")
        
        resources = collect_s3_buckets(mock_session, "123456789012")
        
        assert len(resources) == 1
        assert resources[0].name == "valid-bucket"
        assert "arn:aws:s3:::valid-bucket" == resources[0].resource_id
        
    @mock_aws
    def test_special_characters_in_tags(self, mock_session):
        """Test handling tags with special characters."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        
        ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="t2.micro",
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "Name", "Value": "test-instance/with-slash"},
                        {"Key": "Description", "Value": "Instance with special chars: @#$%"},
                        {"Key": "unicode-tag", "Value": "日本語"},
                    ],
                }
            ],
        )
        
        resources = collect_ec2_instances(mock_session, "us-east-1", "123456789012")
        
        assert len(resources) == 1
        assert resources[0].name == "test-instance/with-slash"
        assert resources[0].tags["unicode-tag"] == "日本語"
        
    @mock_aws
    def test_large_number_of_resources(self, mock_session):
        """Test collecting a larger number of resources (pagination test)."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        
        # Create multiple volumes to test pagination
        for i in range(25):
            ec2.create_volume(
                AvailabilityZone="us-east-1a",
                Size=10,
                VolumeType="gp2",
            )
            
        resources = collect_ebs_volumes(mock_session, "us-east-1", "123456789012")
        
        assert len(resources) == 25


# =============================================================================
# Run Tests
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
