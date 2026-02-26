"""
Integration test that generates sample output files using mock AWS data.

This test simulates a realistic customer environment and generates the actual
output files (inventory.json, summary.json) that would be produced
when running the collector.

Run with: python -m pytest tests/test_aws_integration.py -v -s --log-cli-level=INFO

Output files will be generated in: tests/sample_output/
"""
import json
import os
import shutil
import sys
from datetime import datetime

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aws_collect import (
    collect_region,
    collect_s3_buckets,
    get_account_id,
)
from lib.models import aggregate_sizing
from lib.utils import (
    generate_run_id,
    get_timestamp,
    print_summary_table,
    setup_logging,
    write_csv,
    write_json,
)

# =============================================================================
# Sample Output Directory
# =============================================================================

SAMPLE_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "sample_output")


def setup_sample_output_dir():
    """Create clean sample output directory."""
    if os.path.exists(SAMPLE_OUTPUT_DIR):
        shutil.rmtree(SAMPLE_OUTPUT_DIR)
    os.makedirs(SAMPLE_OUTPUT_DIR)


# =============================================================================
# Mock Customer Environment Setup
# =============================================================================

def create_mock_customer_environment():
    """
    Create a realistic mock AWS environment simulating a mid-size customer.

    Includes:
    - Multiple EC2 instances (various types, states, with/without tags)
    - EBS volumes (attached and orphaned)
    - RDS databases (MySQL, PostgreSQL, Aurora)
    - S3 buckets (different regions, with/without tags)
    - EFS filesystems
    - Lambda functions
    - DynamoDB tables
    - ElastiCache clusters
    """

    # ---------------------------------------------------------------------
    # EC2 Instances
    # ---------------------------------------------------------------------
    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2_west = boto3.client("ec2", region_name="us-west-2")

    # Create VPC for us-east-1
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": "production-vpc"}])

    subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24", AvailabilityZone="us-east-1a")
    subnet_id = subnet["Subnet"]["SubnetId"]

    # Production web servers (3 instances)
    for i in range(3):
        ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="m5.xlarge",
            SubnetId=subnet_id,
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "Name", "Value": f"prod-web-{i+1}"},
                        {"Key": "Environment", "Value": "production"},
                        {"Key": "Application", "Value": "web-frontend"},
                        {"Key": "Team", "Value": "platform"},
                    ],
                }
            ],
        )

    # Database servers (2 instances)
    for i in range(2):
        ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="r5.2xlarge",
            SubnetId=subnet_id,
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "Name", "Value": f"prod-db-{i+1}"},
                        {"Key": "Environment", "Value": "production"},
                        {"Key": "Application", "Value": "database"},
                    ],
                }
            ],
        )

    # Dev/test instances (smaller, some stopped)
    dev_instances = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=2,
        MaxCount=2,
        InstanceType="t3.medium",
        SubnetId=subnet_id,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": "dev-server"},
                    {"Key": "Environment", "Value": "development"},
                ],
            }
        ],
    )
    # Stop one dev instance
    ec2.stop_instances(InstanceIds=[dev_instances["Instances"][0]["InstanceId"]])

    # Instance without tags (legacy/unknown)
    ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        InstanceType="t2.micro",
    )

    # US-West-2 instances (DR site)
    vpc_west = ec2_west.create_vpc(CidrBlock="10.1.0.0/16")
    vpc_west_id = vpc_west["Vpc"]["VpcId"]
    subnet_west = ec2_west.create_subnet(VpcId=vpc_west_id, CidrBlock="10.1.1.0/24", AvailabilityZone="us-west-2a")

    ec2_west.run_instances(
        ImageId="ami-87654321",
        MinCount=2,
        MaxCount=2,
        InstanceType="m5.large",
        SubnetId=subnet_west["Subnet"]["SubnetId"],
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": "dr-replica"},
                    {"Key": "Environment", "Value": "dr"},
                ],
            }
        ],
    )

    # ---------------------------------------------------------------------
    # EBS Volumes
    # ---------------------------------------------------------------------

    # Large data volumes
    for i in range(3):
        ec2.create_volume(
            AvailabilityZone="us-east-1a",
            Size=500,
            VolumeType="gp3",
            Encrypted=True,
            TagSpecifications=[
                {
                    "ResourceType": "volume",
                    "Tags": [
                        {"Key": "Name", "Value": f"data-volume-{i+1}"},
                        {"Key": "Environment", "Value": "production"},
                    ],
                }
            ],
        )

    # Archive volume (cold storage)
    ec2.create_volume(
        AvailabilityZone="us-east-1a",
        Size=2000,
        VolumeType="sc1",
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [
                    {"Key": "Name", "Value": "archive-storage"},
                    {"Key": "Purpose", "Value": "cold-storage"},
                ],
            }
        ],
    )

    # Orphaned volume (detached, no tags - common finding)
    ec2.create_volume(
        AvailabilityZone="us-east-1a",
        Size=100,
        VolumeType="gp2",
    )

    # High-performance IO volume
    ec2.create_volume(
        AvailabilityZone="us-east-1a",
        Size=200,
        VolumeType="io1",
        Iops=3000,
        Encrypted=True,
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [
                    {"Key": "Name", "Value": "high-iops-db"},
                    {"Key": "Application", "Value": "database"},
                ],
            }
        ],
    )

    # ---------------------------------------------------------------------
    # EBS Snapshots
    # ---------------------------------------------------------------------

    # Create snapshots of the data volumes
    volumes = ec2.describe_volumes()["Volumes"]
    for i, vol in enumerate(volumes[:3]):  # Create snapshots for first 3 volumes
        ec2.create_snapshot(
            VolumeId=vol["VolumeId"],
            Description=f"Daily backup snapshot {i+1}",
            TagSpecifications=[
                {
                    "ResourceType": "snapshot",
                    "Tags": [
                        {"Key": "Name", "Value": f"daily-backup-{i+1}"},
                        {"Key": "BackupType", "Value": "daily"},
                    ],
                }
            ],
        )

    # Weekly snapshot (larger retention)
    if volumes:
        ec2.create_snapshot(
            VolumeId=volumes[0]["VolumeId"],
            Description="Weekly backup snapshot",
            TagSpecifications=[
                {
                    "ResourceType": "snapshot",
                    "Tags": [
                        {"Key": "Name", "Value": "weekly-backup"},
                        {"Key": "BackupType", "Value": "weekly"},
                        {"Key": "RetentionDays", "Value": "90"},
                    ],
                }
            ],
        )

    # Orphaned snapshot (no tags - common in customer environments)
    if len(volumes) > 1:
        ec2.create_snapshot(
            VolumeId=volumes[1]["VolumeId"],
            Description="Old snapshot",
        )

    # ---------------------------------------------------------------------
    # RDS Databases
    # ---------------------------------------------------------------------
    rds = boto3.client("rds", region_name="us-east-1")

    # Production MySQL
    rds.create_db_instance(
        DBInstanceIdentifier="prod-mysql-primary",
        DBInstanceClass="db.r5.xlarge",
        Engine="mysql",
        EngineVersion="8.0.32",
        MasterUsername="admin",
        MasterUserPassword="password123",
        AllocatedStorage=500,
        StorageEncrypted=True,
        MultiAZ=True,
    )

    # Production PostgreSQL
    rds.create_db_instance(
        DBInstanceIdentifier="prod-postgres",
        DBInstanceClass="db.r5.large",
        Engine="postgres",
        EngineVersion="14.7",
        MasterUsername="admin",
        MasterUserPassword="password123",
        AllocatedStorage=200,
        StorageEncrypted=True,
    )

    # Dev database (smaller)
    rds.create_db_instance(
        DBInstanceIdentifier="dev-mysql",
        DBInstanceClass="db.t3.medium",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="password123",
        AllocatedStorage=50,
    )

    # Aurora cluster
    rds.create_db_cluster(
        DBClusterIdentifier="prod-aurora-cluster",
        Engine="aurora-mysql",
        EngineVersion="8.0.mysql_aurora.3.03.0",
        MasterUsername="admin",
        MasterUserPassword="password123",
        DatabaseName="appdb",
    )

    # ---------------------------------------------------------------------
    # RDS Snapshots
    # ---------------------------------------------------------------------

    # Manual snapshot of production MySQL
    rds.create_db_snapshot(
        DBSnapshotIdentifier="prod-mysql-manual-backup",
        DBInstanceIdentifier="prod-mysql-primary",
    )

    # Pre-upgrade snapshot
    rds.create_db_snapshot(
        DBSnapshotIdentifier="prod-postgres-pre-upgrade",
        DBInstanceIdentifier="prod-postgres",
    )

    # Aurora cluster snapshot
    rds.create_db_cluster_snapshot(
        DBClusterSnapshotIdentifier="aurora-weekly-backup",
        DBClusterIdentifier="prod-aurora-cluster",
    )

    # ---------------------------------------------------------------------
    # S3 Buckets
    # ---------------------------------------------------------------------
    s3 = boto3.client("s3", region_name="us-east-1")

    # Application data bucket
    s3.create_bucket(Bucket="acme-corp-app-data-prod")
    s3.put_bucket_tagging(
        Bucket="acme-corp-app-data-prod",
        Tagging={
            "TagSet": [
                {"Key": "Environment", "Value": "production"},
                {"Key": "DataClassification", "Value": "confidential"},
            ]
        },
    )

    # Backup bucket
    s3.create_bucket(Bucket="acme-corp-backups")
    s3.put_bucket_tagging(
        Bucket="acme-corp-backups",
        Tagging={
            "TagSet": [
                {"Key": "Purpose", "Value": "backup"},
                {"Key": "RetentionDays", "Value": "90"},
            ]
        },
    )

    # Logs bucket (us-west-2)
    s3.create_bucket(
        Bucket="acme-corp-logs-west",
        CreateBucketConfiguration={"LocationConstraint": "us-west-2"},
    )

    # Static assets (no tags - legacy)
    s3.create_bucket(Bucket="acme-static-assets")

    # Data lake bucket
    s3.create_bucket(Bucket="acme-data-lake")
    s3.put_bucket_tagging(
        Bucket="acme-data-lake",
        Tagging={
            "TagSet": [
                {"Key": "Team", "Value": "data-engineering"},
                {"Key": "Purpose", "Value": "analytics"},
            ]
        },
    )

    # ---------------------------------------------------------------------
    # EFS Filesystems
    # ---------------------------------------------------------------------
    efs = boto3.client("efs", region_name="us-east-1")

    # Shared application storage
    efs.create_file_system(
        CreationToken="shared-app-storage",
        PerformanceMode="generalPurpose",
        Encrypted=True,
        Tags=[
            {"Key": "Name", "Value": "shared-app-storage"},
            {"Key": "Environment", "Value": "production"},
        ],
    )

    # Home directories
    efs.create_file_system(
        CreationToken="user-home-dirs",
        PerformanceMode="generalPurpose",
        Tags=[
            {"Key": "Name", "Value": "user-home-directories"},
        ],
    )

    # ---------------------------------------------------------------------
    # AWS Backup - Vaults, Plans, and Recovery Points
    # ---------------------------------------------------------------------
    backup = boto3.client("backup", region_name="us-east-1")

    # Create backup vaults
    backup.create_backup_vault(BackupVaultName="production-vault")
    backup.create_backup_vault(BackupVaultName="compliance-vault")
    backup.create_backup_vault(BackupVaultName="dr-vault")

    # Create backup plans with different retention policies
    # Daily backup plan - 30 day retention
    backup.create_backup_plan(
        BackupPlan={
            "BackupPlanName": "daily-backup-plan",
            "Rules": [
                {
                    "RuleName": "daily-rule",
                    "TargetBackupVaultName": "production-vault",
                    "ScheduleExpression": "cron(0 5 * * ? *)",
                    "StartWindowMinutes": 60,
                    "CompletionWindowMinutes": 180,
                    "Lifecycle": {
                        "DeleteAfterDays": 30
                    }
                }
            ]
        }
    )

    # Weekly backup plan - 90 day retention with cold storage
    backup.create_backup_plan(
        BackupPlan={
            "BackupPlanName": "weekly-compliance-plan",
            "Rules": [
                {
                    "RuleName": "weekly-rule",
                    "TargetBackupVaultName": "compliance-vault",
                    "ScheduleExpression": "cron(0 3 ? * SUN *)",
                    "StartWindowMinutes": 120,
                    "Lifecycle": {
                        "MoveToColdStorageAfterDays": 30,
                        "DeleteAfterDays": 90
                    }
                }
            ]
        }
    )

    # Monthly DR backup plan - 365 day retention
    backup.create_backup_plan(
        BackupPlan={
            "BackupPlanName": "monthly-dr-plan",
            "Rules": [
                {
                    "RuleName": "monthly-rule",
                    "TargetBackupVaultName": "dr-vault",
                    "ScheduleExpression": "cron(0 2 1 * ? *)",
                    "Lifecycle": {
                        "MoveToColdStorageAfterDays": 7,
                        "DeleteAfterDays": 365
                    }
                }
            ]
        }
    )

    # Create recovery points via backup jobs
    # Note: moto does not yet support start_backup_job, so recovery points
    # won't be created in this mock test. When run against real AWS accounts,
    # recovery points will be collected with their actual sizes (BackupSizeInBytes).
    # Get some volumes to backup
    volumes = ec2.describe_volumes()["Volumes"][:3]

    # Create IAM role for AWS Backup
    backup_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "backup.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    iam = boto3.client("iam", region_name="us-east-1")
    try:
        backup_role = iam.create_role(
            RoleName="aws-backup-service-role",
            AssumeRolePolicyDocument=json.dumps(backup_role_policy),
        )
        backup_role_arn = backup_role["Role"]["Arn"]
    except iam.exceptions.EntityAlreadyExistsException:
        backup_role_arn = "arn:aws:iam::123456789012:role/aws-backup-service-role"

    # Attempt to start backup jobs to create recovery points
    # This currently fails in moto but is left here for when support is added
    recovery_point_count = 0
    for _i, vol in enumerate(volumes):
        try:
            backup.start_backup_job(
                BackupVaultName="production-vault",
                ResourceArn=f"arn:aws:ec2:us-east-1:123456789012:volume/{vol['VolumeId']}",
                IamRoleArn=backup_role_arn,
            )
            recovery_point_count += 1
        except Exception:
            # moto does not yet support start_backup_job
            pass

    print(f"  - 3 Backup vaults, 3 Backup plans ({recovery_point_count} recovery points - moto limitation)")

    # ---------------------------------------------------------------------
    # Lambda Functions
    # ---------------------------------------------------------------------
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
        RoleName="lambda-execution-role",
        AssumeRolePolicyDocument=json.dumps(assume_role_policy),
    )

    # API handler function
    lambda_client.create_function(
        FunctionName="api-handler",
        Runtime="python3.11",
        Role=role["Role"]["Arn"],
        Handler="handler.main",
        Code={"ZipFile": b"fake code"},
        MemorySize=512,
        Timeout=30,
    )

    # Data processor
    lambda_client.create_function(
        FunctionName="data-processor",
        Runtime="python3.11",
        Role=role["Role"]["Arn"],
        Handler="processor.handle",
        Code={"ZipFile": b"fake code"},
        MemorySize=1024,
        Timeout=300,
    )

    # Scheduled task
    lambda_client.create_function(
        FunctionName="nightly-cleanup",
        Runtime="nodejs18.x",
        Role=role["Role"]["Arn"],
        Handler="index.handler",
        Code={"ZipFile": b"fake code"},
        MemorySize=256,
        Timeout=60,
    )

    # ---------------------------------------------------------------------
    # DynamoDB Tables
    # ---------------------------------------------------------------------
    dynamodb = boto3.client("dynamodb", region_name="us-east-1")

    # Session store
    dynamodb.create_table(
        TableName="user-sessions",
        KeySchema=[{"AttributeName": "session_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "session_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    # Application config
    dynamodb.create_table(
        TableName="app-config",
        KeySchema=[{"AttributeName": "config_key", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "config_key", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    # Event log
    dynamodb.create_table(
        TableName="event-log",
        KeySchema=[
            {"AttributeName": "event_type", "KeyType": "HASH"},
            {"AttributeName": "timestamp", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "event_type", "AttributeType": "S"},
            {"AttributeName": "timestamp", "AttributeType": "N"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )

    # ---------------------------------------------------------------------
    # ElastiCache
    # ---------------------------------------------------------------------
    elasticache = boto3.client("elasticache", region_name="us-east-1")

    # Redis session cache
    elasticache.create_cache_cluster(
        CacheClusterId="session-cache",
        Engine="redis",
        EngineVersion="7.0",
        CacheNodeType="cache.r6g.large",
        NumCacheNodes=1,
    )

    # Application cache
    elasticache.create_cache_cluster(
        CacheClusterId="app-cache",
        Engine="redis",
        CacheNodeType="cache.m6g.medium",
        NumCacheNodes=1,
    )

    print("\n" + "="*70)
    print("MOCK CUSTOMER ENVIRONMENT CREATED")
    print("="*70)
    print("Resources created:")
    print("  - 10 EC2 instances (prod, dev, DR across 2 regions)")
    print("  - 6 EBS volumes (various types, some orphaned)")
    print("  - 5 EBS snapshots (daily, weekly, orphaned)")
    print("  - 4 RDS databases (MySQL, PostgreSQL, Aurora)")
    print("  - 3 RDS snapshots (manual, pre-upgrade, cluster)")
    print("  - 5 S3 buckets (various purposes)")
    print("  - 2 EFS filesystems")
    print("  - 3 Lambda functions")
    print("  - 3 DynamoDB tables")
    print("  - 2 ElastiCache clusters")
    print("="*70 + "\n")


# =============================================================================
# Integration Test
# =============================================================================

class TestAWSIntegrationWithOutput:
    """
    Integration test that generates sample output files.
    """

    @mock_aws
    def test_full_collection_generates_output_files(self):
        """
        Run full collection against mock environment and generate output files.

        This simulates what a customer would see when running the collector.
        """
        # Setup
        setup_sample_output_dir()
        setup_logging("INFO")

        # Create mock customer environment
        create_mock_customer_environment()

        # Create session and get account info
        session = boto3.Session(region_name="us-east-1")
        account_id = get_account_id(session)

        # Define regions to collect (simulating customer's enabled regions)
        regions = ["us-east-1", "us-west-2"]

        print(f"\nAWS Account: {account_id}")
        print(f"Collecting from regions: {', '.join(regions)}\n")

        # Collect all resources
        all_resources = []

        # S3 is global
        all_resources.extend(collect_s3_buckets(session, account_id))

        # Regional resources
        for region in regions:
            all_resources.extend(collect_region(session, region, account_id))

        # Generate summaries
        summaries = aggregate_sizing(all_resources)

        # Prepare output data
        run_id = generate_run_id()
        timestamp = get_timestamp()

        inventory_data = {
            "run_id": run_id,
            "timestamp": timestamp,
            "provider": "aws",
            "account_id": account_id,
            "regions": regions,
            "resource_count": len(all_resources),
            "resources": [r.to_dict() for r in all_resources]
        }

        summary_data = {
            "run_id": run_id,
            "timestamp": timestamp,
            "provider": "aws",
            "account_id": account_id,
            "total_resources": len(all_resources),
            "total_capacity_gb": sum(s.total_gb for s in summaries),
            "summaries": [s.to_dict() for s in summaries]
        }

        # Write output files (timestamped to match real collector)
        from datetime import timezone
        file_ts = datetime.now(timezone.utc).strftime('%H%M%S')
        write_json(inventory_data, f"{SAMPLE_OUTPUT_DIR}/cca_inv_{file_ts}.json")
        write_json(summary_data, f"{SAMPLE_OUTPUT_DIR}/cca_sum_{file_ts}.json")

        # Print summary to console (same as real collector)
        print(f"\n{'='*60}")
        print("AWS Cloud Assessment Complete")
        print(f"{'='*60}")
        print(f"Account:   {account_id}")
        print(f"Regions:   {len(regions)}")
        print(f"Resources: {len(all_resources)}")
        print(f"Run ID:    {run_id}")

        print_summary_table([s.to_dict() for s in summaries])

        print(f"Output: {SAMPLE_OUTPUT_DIR}/")

        # Assertions
        assert len(all_resources) > 0

        # Find timestamped output files
        import glob
        inv_files = glob.glob(f"{SAMPLE_OUTPUT_DIR}/cca_inv_*.json")
        sum_files = glob.glob(f"{SAMPLE_OUTPUT_DIR}/cca_sum_*.json")
        assert len(inv_files) >= 1, "No inventory file found"
        assert len(sum_files) >= 1, "No summary file found"

        # Verify inventory structure (use most recent file)
        inv_file = sorted(inv_files)[-1]
        with open(inv_file) as f:
            inventory = json.load(f)
            assert inventory["provider"] == "aws"
            assert inventory["account_id"] == account_id
            assert len(inventory["resources"]) == len(all_resources)

        # Verify summary structure
        sum_file = sorted(sum_files)[-1]
        with open(sum_file) as f:
            summary = json.load(f)
            assert summary["total_resources"] == len(all_resources)
            assert "summaries" in summary

        # Print sample resource for reference
        print("\n" + "="*70)
        print("SAMPLE RESOURCE (first EC2 instance):")
        print("="*70)
        ec2_instance = next((r for r in all_resources if r.resource_type == "aws:ec2:instance"), None)
        if ec2_instance:
            print(json.dumps(ec2_instance.to_dict(), indent=2))

        print("\n" + "="*70)
        print("FILES GENERATED:")
        print("="*70)
        for filename in os.listdir(SAMPLE_OUTPUT_DIR):
            filepath = os.path.join(SAMPLE_OUTPUT_DIR, filename)
            size = os.path.getsize(filepath)
            print(f"  {filename}: {size:,} bytes")
        print("="*70)


# =============================================================================
# Run directly
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--log-cli-level=INFO"])
