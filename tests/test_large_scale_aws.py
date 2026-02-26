"""
Large-scale integration test with multiple regions, data holes, and realistic complexity.

This test simulates a large enterprise environment with:
- Multiple regions (us-east-1, us-west-2, eu-west-1, ap-northeast-1)
- Hundreds of resources
- Data quality issues (missing tags, incomplete metadata)
- Mixed protection states
- Orphaned resources
- Legacy resources

Run with: python -m pytest tests/test_large_scale.py -v -s --log-cli-level=INFO

Output files will be generated in: tests/large_scale_output/
"""
import json
import os
import random
import shutil
import sys
from datetime import datetime, timezone

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aws_collect import collect_region
from lib.models import aggregate_sizing
from lib.utils import (
    generate_run_id,
    get_timestamp,
    print_summary_table,
    write_csv,
    write_json,
)

# =============================================================================
# Constants
# =============================================================================

LARGE_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "large_scale_output", "aws")

REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-northeast-1"]

ENVIRONMENTS = ["production", "staging", "development", "qa", "sandbox", ""]
APPLICATIONS = ["webapp", "api", "database", "cache", "worker", "batch", "analytics", "ml", ""]
TEAMS = ["platform", "infra", "data", "backend", "frontend", "devops", "sre", ""]
COST_CENTERS = ["CC-1001", "CC-1002", "CC-2001", "CC-3001", ""]

INSTANCE_TYPES = [
    "t3.micro", "t3.small", "t3.medium", "t3.large",
    "m5.large", "m5.xlarge", "m5.2xlarge", "m5.4xlarge",
    "c5.large", "c5.xlarge", "c5.2xlarge",
    "r5.large", "r5.xlarge", "r5.2xlarge",
    "i3.large", "i3.xlarge",
]

VOLUME_TYPES = ["gp2", "gp3"]  # Simple types that don't require special params


def setup_large_output_dir():
    """Create clean output directory."""
    if os.path.exists(LARGE_OUTPUT_DIR):
        shutil.rmtree(LARGE_OUTPUT_DIR)
    os.makedirs(LARGE_OUTPUT_DIR)


def random_tags(include_name=True, completeness=0.7):
    """Generate random tags with configurable completeness (data holes)."""
    tags = []

    if include_name and random.random() < completeness:
        name = f"{random.choice(['srv', 'app', 'db', 'cache', 'web', 'api'])}-{random.randint(1, 999):03d}"
        tags.append({"Key": "Name", "Value": name})

    if random.random() < completeness * 0.8:
        tags.append({"Key": "Environment", "Value": random.choice(ENVIRONMENTS)})

    if random.random() < completeness * 0.6:
        tags.append({"Key": "Application", "Value": random.choice(APPLICATIONS)})

    if random.random() < completeness * 0.5:
        tags.append({"Key": "Team", "Value": random.choice(TEAMS)})

    if random.random() < completeness * 0.4:
        tags.append({"Key": "CostCenter", "Value": random.choice(COST_CENTERS)})

    # Sometimes add backup-related tags
    if random.random() < 0.3:
        tags.append({"Key": "BackupPolicy", "Value": random.choice(["daily", "weekly", "monthly", "none"])})

    return tags if tags else None


def create_large_ec2_environment(region: str, num_instances: int, vpc_id: str, subnet_id: str, eks_clusters: list[str] = None):
    """Create EC2 instances with varying configurations and data quality."""
    ec2 = boto3.client("ec2", region_name=region)
    instances_created = []
    eks_clusters = eks_clusters or []

    states = ["running"] * 7 + ["stopped"] * 2 + ["terminated"]  # 70% running, 20% stopped, 10% terminated

    for _i in range(num_instances):
        instance_type = random.choice(INSTANCE_TYPES)

        # Some instances have no tags at all (data hole)
        if random.random() < 0.1:
            tag_spec = None
        else:
            tags = random_tags(completeness=random.uniform(0.3, 1.0)) or []

            # ~15% of instances are EKS nodes (if clusters exist)
            if eks_clusters and random.random() < 0.15:
                cluster_name = random.choice(eks_clusters)
                # Add EKS node tags
                tags.append({"Key": f"kubernetes.io/cluster/{cluster_name}", "Value": "owned"})
                tags.append({"Key": "eks:cluster-name", "Value": cluster_name})

            tag_spec = [{"ResourceType": "instance", "Tags": tags}] if tags else None

        try:
            kwargs = {
                "ImageId": f"ami-{random.randint(10000000, 99999999)}",
                "MinCount": 1,
                "MaxCount": 1,
                "InstanceType": instance_type,
                "SubnetId": subnet_id,
            }
            if tag_spec:
                kwargs["TagSpecifications"] = tag_spec

            resp = ec2.run_instances(**kwargs)
            instance_id = resp["Instances"][0]["InstanceId"]
            instances_created.append(instance_id)

            # Stop some instances
            if random.choice(states) == "stopped":
                try:
                    ec2.stop_instances(InstanceIds=[instance_id])
                except Exception:
                    pass
        except Exception as e:
            print(f"Failed to create instance: {e}")

    return instances_created


def create_large_ebs_environment(region: str, instance_ids: list, num_orphan_volumes: int):
    """Create EBS volumes - attached and orphaned."""
    ec2 = boto3.client("ec2", region_name=region)

    # Get AZ from region
    az = f"{region}a"

    # Create orphan volumes (not attached to anything - data hole)
    for _i in range(num_orphan_volumes):
        size = random.choice([8, 16, 32, 50, 100, 200, 500, 1000, 2000])
        vol_type = random.choice(VOLUME_TYPES)

        kwargs = {
            "AvailabilityZone": az,
            "Size": size,
            "VolumeType": vol_type,
        }

        # Some orphan volumes have no tags (forgotten resources)
        if random.random() > 0.3:
            tags = random_tags(completeness=0.4)
            if tags:
                kwargs["TagSpecifications"] = [{"ResourceType": "volume", "Tags": tags}]

        try:
            vol = ec2.create_volume(**kwargs)

            # Create snapshots for some orphan volumes
            if random.random() < 0.2:
                snap_tags = random_tags(completeness=0.3)
                snap_kwargs = {
                    "VolumeId": vol["VolumeId"],
                    "Description": random.choice([
                        "Backup before migration",
                        "Pre-upgrade snapshot",
                        f"Manual backup {datetime.now().strftime('%Y%m%d')}",
                        "",  # Empty description - data hole
                    ])
                }
                if snap_tags:
                    snap_kwargs["TagSpecifications"] = [{"ResourceType": "snapshot", "Tags": snap_tags}]
                ec2.create_snapshot(**snap_kwargs)
        except Exception as e:
            print(f"Failed to create orphan volume: {e}")


def create_snapshots_for_volumes(region: str, num_snapshots: int):
    """Create snapshots with varying metadata completeness."""
    ec2 = boto3.client("ec2", region_name=region)

    # Get existing volumes
    volumes = ec2.describe_volumes()["Volumes"]
    if not volumes:
        return

    for _i in range(num_snapshots):
        vol = random.choice(volumes)

        # Varying description quality
        descriptions = [
            f"Daily backup - {datetime.now().strftime('%Y-%m-%d')}",
            "Weekly compliance backup",
            f"Pre-deployment snapshot for {random.choice(APPLICATIONS)}",
            "Automated backup",
            "",  # Empty - data hole
            None,  # Missing - data hole
        ]

        desc = random.choice(descriptions)

        try:
            kwargs = {"VolumeId": vol["VolumeId"]}
            if desc:
                kwargs["Description"] = desc

            # Some snapshots have backup-related tags
            if random.random() < 0.5:
                tags = [
                    {"Key": "BackupType", "Value": random.choice(["daily", "weekly", "monthly", "ad-hoc"])},
                ]
                if random.random() < 0.5:
                    tags.append({"Key": "RetentionDays", "Value": str(random.choice([7, 14, 30, 90, 365]))})
                kwargs["TagSpecifications"] = [{"ResourceType": "snapshot", "Tags": tags}]

            ec2.create_snapshot(**kwargs)
        except Exception:
            pass


def create_rds_environment(region: str, num_instances: int, num_clusters: int):
    """Create RDS instances and clusters with varying configurations."""
    rds = boto3.client("rds", region_name=region)

    engines = ["mysql", "postgres", "mariadb"]
    instance_classes = ["db.t3.micro", "db.t3.small", "db.t3.medium", "db.m5.large", "db.r5.large"]

    # Create standalone RDS instances
    for _i in range(num_instances):
        engine = random.choice(engines)
        instance_class = random.choice(instance_classes)
        storage = random.choice([20, 50, 100, 200, 500, 1000])

        identifier = f"{region.replace('-', '')}-{engine}-{random.randint(1, 999):03d}"

        try:
            tags = random_tags(include_name=False, completeness=random.uniform(0.2, 0.8))

            rds.create_db_instance(
                DBInstanceIdentifier=identifier,
                DBInstanceClass=instance_class,
                Engine=engine,
                MasterUsername="admin",
                MasterUserPassword="Password123!",
                AllocatedStorage=storage,
                Tags=tags if tags else [],
            )

            # Create manual snapshots for some instances
            if random.random() < 0.4:
                snap_identifier = f"{identifier}-snap-{random.randint(1, 99):02d}"
                try:
                    rds.create_db_snapshot(
                        DBSnapshotIdentifier=snap_identifier,
                        DBInstanceIdentifier=identifier,
                    )
                except Exception:
                    pass
        except Exception:
            pass

    # Create Aurora clusters
    for _i in range(num_clusters):
        cluster_id = f"{region.replace('-', '')}-aurora-{random.randint(1, 99):02d}"

        try:
            tags = random_tags(include_name=False, completeness=random.uniform(0.3, 0.7))

            rds.create_db_cluster(
                DBClusterIdentifier=cluster_id,
                Engine="aurora-mysql",
                MasterUsername="admin",
                MasterUserPassword="Password123!",
                Tags=tags if tags else [],
            )

            # Create cluster snapshots
            if random.random() < 0.3:
                try:
                    rds.create_db_cluster_snapshot(
                        DBClusterSnapshotIdentifier=f"{cluster_id}-snap",
                        DBClusterIdentifier=cluster_id,
                    )
                except Exception:
                    pass
        except Exception:
            pass


def create_s3_environment(num_buckets: int):
    """Create S3 buckets across regions."""
    s3 = boto3.client("s3", region_name="us-east-1")

    bucket_prefixes = ["data", "logs", "backup", "archive", "assets", "uploads", "temp", "exports"]

    for _i in range(num_buckets):
        prefix = random.choice(bucket_prefixes)
        bucket_name = f"{prefix}-{random.randint(100000, 999999)}"

        try:
            # Random region for bucket
            region = random.choice(REGIONS)

            if region == "us-east-1":
                s3.create_bucket(Bucket=bucket_name)
            else:
                s3.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={"LocationConstraint": region}
                )

            # Some buckets have tags, some don't (data hole)
            if random.random() < 0.6:
                tags = random_tags(include_name=False, completeness=random.uniform(0.3, 0.8))
                if tags:
                    s3.put_bucket_tagging(
                        Bucket=bucket_name,
                        Tagging={"TagSet": tags}
                    )
        except Exception:
            pass


def create_efs_environment(region: str, num_filesystems: int):
    """Create EFS filesystems."""
    efs = boto3.client("efs", region_name=region)

    for i in range(num_filesystems):
        try:
            tags = random_tags(completeness=random.uniform(0.4, 0.9))

            efs.create_file_system(
                CreationToken=f"efs-{region}-{i}-{random.randint(1000, 9999)}",
                PerformanceMode=random.choice(["generalPurpose", "maxIO"]),
                ThroughputMode=random.choice(["bursting", "provisioned"]),
                Tags=tags if tags else [],
            )
        except Exception:
            pass


def create_lambda_environment(region: str, num_functions: int):
    """Create Lambda functions."""
    lambda_client = boto3.client("lambda", region_name=region)
    iam = boto3.client("iam", region_name="us-east-1")

    # Create IAM role
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

    try:
        role = iam.create_role(
            RoleName=f"lambda-role-{region}",
            AssumeRolePolicyDocument=json.dumps(assume_role_policy),
        )
        role_arn = role["Role"]["Arn"]
    except Exception:
        role_arn = f"arn:aws:iam::123456789012:role/lambda-role-{region}"

    runtimes = ["python3.9", "python3.10", "python3.11", "nodejs18.x", "nodejs20.x", "java17", "go1.x"]
    function_prefixes = ["api", "processor", "handler", "worker", "scheduler", "notifier", "validator"]

    for _i in range(num_functions):
        func_name = f"{random.choice(function_prefixes)}-{random.randint(1, 999):03d}"

        try:
            tags = random_tags(include_name=False, completeness=random.uniform(0.2, 0.7))

            lambda_client.create_function(
                FunctionName=func_name,
                Runtime=random.choice(runtimes),
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": b"fake code"},
                MemorySize=random.choice([128, 256, 512, 1024, 2048, 3008]),
                Timeout=random.choice([3, 10, 30, 60, 300, 900]),
                Tags={t["Key"]: t["Value"] for t in tags} if tags else {},
            )
        except Exception:
            pass


def create_dynamodb_environment(region: str, num_tables: int):
    """Create DynamoDB tables."""
    dynamodb = boto3.client("dynamodb", region_name=region)

    table_prefixes = ["sessions", "users", "orders", "products", "events", "logs", "config", "cache"]

    for _i in range(num_tables):
        table_name = f"{random.choice(table_prefixes)}-{random.randint(1, 999):03d}"

        try:
            tags = random_tags(include_name=False, completeness=random.uniform(0.3, 0.6))

            dynamodb.create_table(
                TableName=table_name,
                KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                BillingMode=random.choice(["PAY_PER_REQUEST", "PROVISIONED"]),
                Tags=tags if tags else [],
            )
        except Exception:
            pass


def create_elasticache_environment(region: str, num_clusters: int):
    """Create ElastiCache clusters."""
    elasticache = boto3.client("elasticache", region_name=region)

    for _i in range(num_clusters):
        cluster_id = f"cache-{region.replace('-', '')}-{random.randint(1, 99):02d}"

        try:
            tags = random_tags(include_name=False, completeness=random.uniform(0.3, 0.7))

            elasticache.create_cache_cluster(
                CacheClusterId=cluster_id,
                Engine=random.choice(["redis", "memcached"]),
                CacheNodeType=random.choice(["cache.t3.micro", "cache.t3.small", "cache.m5.large"]),
                NumCacheNodes=random.choice([1, 2, 3]),
                Tags=tags if tags else [],
            )
        except Exception:
            pass


def create_eks_environment(region: str, num_clusters: int, subnet_id: str) -> list[str]:
    """Create EKS clusters. Returns list of cluster names created."""
    eks = boto3.client("eks", region_name=region)
    iam = boto3.client("iam", region_name=region)
    cluster_names = []

    # Create IAM role for EKS (moto requires this)
    try:
        iam.create_role(
            RoleName="eks-cluster-role",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}]
            }),
        )
    except Exception:
        pass  # Role may already exist

    role_arn = "arn:aws:iam::123456789012:role/eks-cluster-role"

    for _i in range(num_clusters):
        cluster_name = f"eks-{region.replace('-', '')}-{random.randint(1, 99):02d}"

        try:
            tags = random_tags(include_name=False, completeness=random.uniform(0.3, 0.7))
            # Convert tags from [{Key, Value}] to {key: value} format for EKS
            eks_tags = {t['Key']: t['Value'] for t in tags} if tags else {}

            eks.create_cluster(
                name=cluster_name,
                version=random.choice(["1.28", "1.29", "1.30"]),
                roleArn=role_arn,
                resourcesVpcConfig={
                    "subnetIds": [subnet_id],
                },
                tags=eks_tags,
            )
            cluster_names.append(cluster_name)
        except Exception:
            pass

    return cluster_names


def create_backup_environment(region: str):
    """Create AWS Backup vaults and plans."""
    backup = boto3.client("backup", region_name=region)

    # Create backup vaults
    vault_names = ["default-vault", "production-vault", "compliance-vault", "archive-vault"]
    for vault_name in vault_names:
        try:
            backup.create_backup_vault(BackupVaultName=f"{vault_name}-{region.replace('-', '')}")
        except Exception:
            pass

    # Create backup plans
    plans = [
        {
            "name": "daily-backup-plan",
            "rules": [
                {
                    "RuleName": "DailyBackup",
                    "TargetBackupVaultName": f"default-vault-{region.replace('-', '')}",
                    "ScheduleExpression": "cron(0 5 ? * * *)",
                    "StartWindowMinutes": 60,
                    "CompletionWindowMinutes": 180,
                    "Lifecycle": {"DeleteAfterDays": 30},
                }
            ]
        },
        {
            "name": "weekly-compliance-plan",
            "rules": [
                {
                    "RuleName": "WeeklyCompliance",
                    "TargetBackupVaultName": f"compliance-vault-{region.replace('-', '')}",
                    "ScheduleExpression": "cron(0 5 ? * 1 *)",
                    "StartWindowMinutes": 60,
                    "CompletionWindowMinutes": 360,
                    "Lifecycle": {"DeleteAfterDays": 365},
                }
            ]
        },
        {
            "name": "monthly-archive-plan",
            "rules": [
                {
                    "RuleName": "MonthlyArchive",
                    "TargetBackupVaultName": f"archive-vault-{region.replace('-', '')}",
                    "ScheduleExpression": "cron(0 5 1 * ? *)",
                    "StartWindowMinutes": 120,
                    "CompletionWindowMinutes": 720,
                    "Lifecycle": {
                        "MoveToColdStorageAfterDays": 90,
                        "DeleteAfterDays": 2555,
                    },
                }
            ]
        },
    ]

    for plan in plans:
        try:
            backup.create_backup_plan(
                BackupPlan={
                    "BackupPlanName": plan["name"],
                    "Rules": plan["rules"],
                }
            )
        except Exception:
            pass


# =============================================================================
# Test Class
# =============================================================================

class TestLargeScaleEnvironment:
    """Large-scale integration test with realistic enterprise data."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures."""
        setup_large_output_dir()
        yield

    @mock_aws
    def test_large_scale_collection(self):
        """
        Test collection across a large, realistic enterprise environment.

        Scale:
        - 4 regions
        - ~50 EC2 instances per region
        - ~30 orphan volumes per region
        - ~100 snapshots per region
        - ~15 RDS instances per region
        - ~5 Aurora clusters per region
        - ~40 S3 buckets (global)
        - ~10 EFS filesystems per region
        - ~20 Lambda functions per region
        - ~15 DynamoDB tables per region
        - ~5 ElastiCache clusters per region
        """
        print("\n" + "=" * 80)
        print("LARGE-SCALE INTEGRATION TEST")
        print("=" * 80)

        # Configuration - scale factors
        EC2_PER_REGION = 50
        ORPHAN_VOLUMES_PER_REGION = 30
        SNAPSHOTS_PER_REGION = 100
        RDS_INSTANCES_PER_REGION = 15
        RDS_CLUSTERS_PER_REGION = 5
        S3_BUCKETS = 40
        EFS_PER_REGION = 10
        LAMBDA_PER_REGION = 20
        DYNAMODB_PER_REGION = 15
        ELASTICACHE_PER_REGION = 5
        EKS_PER_REGION = 3

        # Track VPCs and subnets per region
        region_infra = {}

        print("\n📦 Creating infrastructure...\n")

        # Create infrastructure per region
        for region in REGIONS:
            print(f"  Setting up {region}...")

            ec2 = boto3.client("ec2", region_name=region)

            # Create VPC
            vpc = ec2.create_vpc(CidrBlock=f"10.{REGIONS.index(region)}.0.0/16")
            vpc_id = vpc["Vpc"]["VpcId"]

            # Create subnet
            subnet = ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock=f"10.{REGIONS.index(region)}.1.0/24",
                AvailabilityZone=f"{region}a"
            )
            subnet_id = subnet["Subnet"]["SubnetId"]

            region_infra[region] = {"vpc_id": vpc_id, "subnet_id": subnet_id}

            # Create EKS clusters first so we can tag EC2 instances as nodes
            eks_clusters = create_eks_environment(region, EKS_PER_REGION, subnet_id)

            # Create resources
            create_large_ec2_environment(region, EC2_PER_REGION, vpc_id, subnet_id, eks_clusters)
            create_large_ebs_environment(region, [], ORPHAN_VOLUMES_PER_REGION)
            create_snapshots_for_volumes(region, SNAPSHOTS_PER_REGION)
            create_rds_environment(region, RDS_INSTANCES_PER_REGION, RDS_CLUSTERS_PER_REGION)
            create_efs_environment(region, EFS_PER_REGION)
            create_lambda_environment(region, LAMBDA_PER_REGION)
            create_dynamodb_environment(region, DYNAMODB_PER_REGION)
            create_elasticache_environment(region, ELASTICACHE_PER_REGION)
            create_backup_environment(region)

        # Create S3 buckets (global)
        create_s3_environment(S3_BUCKETS)

        print("\n✅ Infrastructure created\n")

        # Get account info first
        sts = boto3.client("sts", region_name="us-east-1")
        account_id = sts.get_caller_identity()["Account"]

        # Collect resources
        print("📊 Collecting resources...\n")

        all_resources = []

        for region in REGIONS:
            print(f"  Collecting {region}...")
            try:
                session = boto3.Session(region_name=region)
                region_resources = collect_region(session, region, account_id)
                all_resources.extend(region_resources)
                print(f"    Found {len(region_resources)} resources")
            except Exception as e:
                print(f"    Error: {e}")

        # Generate outputs
        run_id = generate_run_id()
        timestamp = get_timestamp()

        # Build sizing summaries
        summaries = aggregate_sizing(all_resources)

        inventory_data = {
            'provider': 'aws',
            'run_id': run_id,
            'timestamp': timestamp,
            'account_id': account_id,
            'regions': REGIONS,
            'resources': [r.to_dict() for r in all_resources]
        }

        summary_data = {
            'provider': 'aws',
            'run_id': run_id,
            'timestamp': timestamp,
            'account_id': account_id,
            'total_resources': len(all_resources),
            'total_capacity_gb': sum(s.total_gb for s in summaries),
            'summaries': [s.to_dict() for s in summaries]
        }

        # Write output files (timestamped)
        file_ts = datetime.now(timezone.utc).strftime('%H%M%S')
        write_json(inventory_data, f"{LARGE_OUTPUT_DIR}/cca_inv_{file_ts}.json")
        write_json(summary_data, f"{LARGE_OUTPUT_DIR}/cca_sum_{file_ts}.json")

        # Print statistics
        print("\n" + "=" * 80)
        print("COLLECTION RESULTS")
        print("=" * 80)
        print(f"\nAccount: {account_id}")
        print(f"Regions: {len(REGIONS)}")
        print(f"Total Resources: {len(all_resources)}")

        # Count by type
        by_type = {}
        for r in all_resources:
            by_type[r.resource_type] = by_type.get(r.resource_type, 0) + 1

        print("\nResources by Type:")
        for rtype, count in sorted(by_type.items()):
            print(f"  {rtype}: {count}")

        # Count resources with missing names (data holes)
        missing_names = len([r for r in all_resources if not r.name or r.name == "unnamed"])
        print("\nData Quality:")
        if len(all_resources) > 0:
            print(f"  Resources with missing names: {missing_names} ({missing_names/len(all_resources)*100:.1f}%)")
        else:
            print(f"  Resources with missing names: {missing_names}")

        # Count by region
        by_region = {}
        for r in all_resources:
            by_region[r.region] = by_region.get(r.region, 0) + 1

        print("\nResources by Region:")
        for region, count in sorted(by_region.items()):
            print(f"  {region}: {count}")

        print_summary_table([s.to_dict() for s in summaries])

        print(f"\nOutput: {LARGE_OUTPUT_DIR}/")

        # Generate protection report
        print("\n📝 Generating protection report...\n")

        try:
            # Import and run the report generator
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            from scripts.generate_protection_report import generate_report

            inv_file = f"{LARGE_OUTPUT_DIR}/cca_inv_{file_ts}.json"
            report_file = f"{LARGE_OUTPUT_DIR}/protection_report.xlsx"

            generate_report(inv_file, report_file)

            print(f"\n✅ Protection report generated: {report_file}")
        except Exception as e:
            print(f"\n⚠️  Could not generate protection report: {e}")

        # Assertions
        assert len(all_resources) > 100, "Should have collected many resources"
        assert len(by_region) == len(REGIONS), "Should have resources from all regions"

        # Verify files exist
        import glob
        inv_files = glob.glob(f"{LARGE_OUTPUT_DIR}/cca_inv_*.json")
        assert len(inv_files) >= 1, "Inventory file should exist"

        print("\n" + "=" * 80)
        print("TEST COMPLETE")
        print("=" * 80)


# =============================================================================
# Run directly
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--log-cli-level=INFO"])
