#!/usr/bin/env python3
"""
CCA CloudShell - AWS Resource Collector

Collects AWS resources for cloud protection assessment.
Optimized for AWS CloudShell with minimal dependencies.
Supports single-account and multi-account collection.

Usage:
    # Single account (current credentials)
    python3 aws_collect.py
    python3 aws_collect.py --regions us-east-1,us-west-2
    python3 aws_collect.py --output s3://my-bucket/assessments/

    # Multi-account via role assumption
    python3 aws_collect.py --role-arn arn:aws:iam::123456789012:role/CCARole
    python3 aws_collect.py --role-arns arn:aws:iam::111:role/CCA,arn:aws:iam::222:role/CCA

    # Multi-account via AWS Organizations discovery
    python3 aws_collect.py --org-role CCARole

    # With external ID (use env var to avoid shell history exposure)
    export CCA_EXTERNAL_ID="your-secret-external-id"
    python3 aws_collect.py --org-role CCARole

    # Large environments: auto-batching with checkpoint
    python3 aws_collect.py --org-role CCARole --batch-size 25 -o ./collection/

    # Resume from checkpoint after failure/timeout
    python3 aws_collect.py --org-role CCARole --resume ./collection/checkpoint.json

    # Collect specific accounts only (retry failed)
    python3 aws_collect.py --org-role CCARole --accounts 111111111111,222222222222

    # Load accounts from file
    python3 aws_collect.py --org-role CCARole --account-file accounts.txt
"""
import argparse
import logging
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# boto3 is pre-installed in AWS CloudShell
import boto3

# Add lib to path for imports
sys.path.insert(0, '.')
from lib.change_rate import finalize_change_rate_output, merge_change_rates
from lib.config import generate_sample_config, load_config
from lib.__version__ import __version__
from lib.k8s import collect_eks_pvcs
from lib.models import CloudResource, aggregate_sizing
from lib.utils import (
    AuthError,
    ProgressTracker,
    generate_run_id,
    get_collector_metadata,
    get_timestamp,
    log_arguments,
    print_summary_table,
    redact_sensitive_data,
    setup_logging,
    write_json,
)

# Import from modular lib.aws modules
from lib.aws.auth import (
    is_running_in_cloudshell,
    get_session,
    get_account_id,
    get_enabled_regions,
    assume_role,
    discover_org_accounts,
    get_sso_token_expiry,
)
from lib.aws.helpers import chunk_list, load_account_list, validate_account_ids
from lib.aws.compute import (
    collect_ec2_instances,
    collect_ebs_volumes,
    collect_ebs_snapshots,
    collect_lambda_functions,
)
from lib.aws.storage import (
    collect_s3_buckets,
    collect_efs_filesystems,
    collect_fsx_filesystems,
)
from lib.aws.databases import (
    collect_rds_instances,
    collect_rds_clusters,
    collect_rds_snapshots,
    collect_rds_cluster_snapshots,
    collect_dynamodb_tables,
    collect_elasticache_clusters,
    collect_redshift_clusters,
    collect_documentdb_clusters,
    collect_neptune_clusters,
    collect_opensearch_domains,
    collect_memorydb_clusters,
    collect_timestream_databases,
)
from lib.aws.container import collect_eks_clusters, collect_eks_nodegroups
from lib.aws.backup import (
    collect_backup_vaults,
    collect_backup_recovery_points,
    collect_backup_plans,
    collect_backup_selections,
    collect_backup_protected_resources,
    collect_backup_region_settings,
)
from lib.aws.monitoring import collect_resource_change_rates
from lib.aws.parallel import (
    load_checkpoint,
    save_checkpoint,
    run_parallel_account_collection,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Account/Region Collection Orchestration
# =============================================================================

def collect_region(
    session: boto3.Session,
    region: str,
    account_id: str,
    tracker: Optional[ProgressTracker] = None
) -> List[CloudResource]:
    """Collect all resources in a region."""
    resources = []

    logger.info(f"Collecting resources in {region}...")

    def collect_and_track(name: str, collect_fn, *args):
        """Helper to collect resources and update tracker."""
        if tracker:
            tracker.update_task(f"Collecting {name}...")
        result = collect_fn(*args)
        if tracker and result:
            tracker.add_resources(len(result), sum(r.size_gb for r in result))
        return result

    # EC2
    resources.extend(collect_and_track("EC2 instances", collect_ec2_instances, session, region, account_id))
    resources.extend(collect_and_track("EBS volumes", collect_ebs_volumes, session, region, account_id))
    resources.extend(collect_and_track("EBS snapshots", collect_ebs_snapshots, session, region, account_id))

    # RDS
    resources.extend(collect_and_track("RDS instances", collect_rds_instances, session, region, account_id))
    resources.extend(collect_and_track("RDS clusters", collect_rds_clusters, session, region, account_id))
    resources.extend(collect_and_track("RDS snapshots", collect_rds_snapshots, session, region, account_id))
    resources.extend(collect_and_track("RDS cluster snapshots", collect_rds_cluster_snapshots, session, region, account_id))

    # Storage
    resources.extend(collect_and_track("EFS filesystems", collect_efs_filesystems, session, region, account_id))
    resources.extend(collect_and_track("FSx filesystems", collect_fsx_filesystems, session, region, account_id))

    # Containers & Compute
    resources.extend(collect_and_track("EKS clusters", collect_eks_clusters, session, region, account_id))
    resources.extend(collect_and_track("EKS node groups", collect_eks_nodegroups, session, region, account_id))
    resources.extend(collect_and_track("Lambda functions", collect_lambda_functions, session, region, account_id))

    # Databases
    resources.extend(collect_and_track("DynamoDB tables", collect_dynamodb_tables, session, region, account_id))
    resources.extend(collect_and_track("ElastiCache clusters", collect_elasticache_clusters, session, region, account_id))
    resources.extend(collect_and_track("Redshift clusters", collect_redshift_clusters, session, region, account_id))
    resources.extend(collect_and_track("DocumentDB clusters", collect_documentdb_clusters, session, region, account_id))
    resources.extend(collect_and_track("Neptune clusters", collect_neptune_clusters, session, region, account_id))
    resources.extend(collect_and_track("OpenSearch domains", collect_opensearch_domains, session, region, account_id))
    resources.extend(collect_and_track("MemoryDB clusters", collect_memorydb_clusters, session, region, account_id))
    resources.extend(collect_and_track("Timestream tables", collect_timestream_databases, session, region, account_id))

    # AWS Backup
    resources.extend(collect_and_track("Backup vaults", collect_backup_vaults, session, region, account_id))
    resources.extend(collect_and_track("Backup recovery points", collect_backup_recovery_points, session, region, account_id))
    resources.extend(collect_and_track("Backup plans", collect_backup_plans, session, region, account_id))
    resources.extend(collect_and_track("Backup selections", collect_backup_selections, session, region, account_id))
    resources.extend(collect_and_track("Backup protected resources", collect_backup_protected_resources, session, region, account_id))
    # Note: Backup region settings collected once per account in collect_account(), not per region

    return resources


def collect_account(
    session: boto3.Session,
    account_id: str,
    regions: Optional[List[str]] = None,
    tracker: Optional[ProgressTracker] = None,
    include_storage_sizes: bool = False,
    parallel_regions: int = 1
) -> List[CloudResource]:
    """
    Collect all resources from a single AWS account.

    Args:
        session: boto3 session with credentials for this account
        account_id: AWS account ID
        regions: List of regions to collect from (None = all enabled)
        tracker: Optional progress tracker for UI feedback
        include_storage_sizes: If True, query CloudWatch for S3 bucket sizes
        parallel_regions: Number of regions to collect in parallel (1 = serial)

    Returns:
        List of CloudResource objects
    """
    resources = []

    # Get regions if not specified
    if regions is None:
        regions = get_enabled_regions(session)

    logger.info(f"Collecting from account {account_id} across {len(regions)} regions (parallel={parallel_regions})")

    # S3 is global
    if tracker:
        tracker.update_task("Collecting S3 buckets...")
    s3_resources = collect_s3_buckets(session, account_id, include_sizes=include_storage_sizes)
    resources.extend(s3_resources)
    if tracker:
        tracker.add_resources(len(s3_resources), sum(r.size_gb for r in s3_resources))

    # Backup region settings are account-level (same across all regions), collect once
    if tracker:
        tracker.update_task("Collecting Backup region settings...")
    # Use first region to make the API call, but treat as account-level resource
    backup_region = regions[0] if regions else 'us-east-1'
    backup_settings = collect_backup_region_settings(session, backup_region, account_id)
    # Change region to 'global' since settings apply account-wide
    for resource in backup_settings:
        resource.region = 'global'
        resource.resource_id = f"arn:aws:backup:{account_id}:region-settings"
    resources.extend(backup_settings)
    if tracker and backup_settings:
        tracker.add_resources(len(backup_settings), 0)

    # Regional resources - can parallelize across regions
    if parallel_regions > 1 and len(regions) > 1:
        # Parallel collection (no tracker updates - runs in background)
        logger.info(f"Collecting {len(regions)} regions in parallel (workers={parallel_regions})")
        with ThreadPoolExecutor(max_workers=parallel_regions) as executor:
            futures = {
                executor.submit(collect_region, session, region, account_id, None): region
                for region in regions
            }
            for future in as_completed(futures):
                region = futures[future]
                try:
                    region_resources = future.result()
                    resources.extend(region_resources)
                    logger.info(f"[{region}] Completed: {len(region_resources)} resources")
                except Exception as e:
                    logger.error(f"[{region}] Failed: {e}")
    else:
        # Serial collection (with tracker updates)
        for region in regions:
            if tracker:
                tracker.start_region(region)
            region_resources = collect_region(session, region, account_id, tracker)
            resources.extend(region_resources)
            if tracker:
                tracker.complete_region()

    logger.info(f"Collected {len(resources)} resources from account {account_id}")
    return resources


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='CCA CloudShell - AWS Resource Collector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single account (current credentials)
  python3 aws_collect.py

  # Specific regions
  python3 aws_collect.py --regions us-east-1,us-west-2

  # Assume role in another account
  python3 aws_collect.py --role-arn arn:aws:iam::123456789012:role/CCARole

  # Multiple accounts via role assumption
  python3 aws_collect.py --role-arns arn:aws:iam::111:role/CCA,arn:aws:iam::222:role/CCA

  # Auto-discover all accounts in AWS Organization
  python3 aws_collect.py --org-role CCARole

  # Organization discovery with external ID
  python3 aws_collect.py --org-role CCARole --external-id MySecretId

Large Environment Examples:
  # Auto-batch 100+ accounts into groups of 25, with checkpoint
  python3 aws_collect.py --org-role CCARole --batch-size 25 -o ./collection/

  # Parallel region collection (4x-8x faster)
  python3 aws_collect.py --org-role CCARole --parallel-regions 8

  # Faster collection without change rates (skip CloudWatch metrics)
  python3 aws_collect.py --org-role CCARole --parallel-regions 8 --skip-change-rate

  # Resume after credential timeout (uses checkpoint.json)
  python3 aws_collect.py --org-role CCARole --resume ./collection/checkpoint.json

  # Retry only failed accounts
  python3 aws_collect.py --org-role CCARole --accounts 111111111111,222222222222

  # Load account list from file
  python3 aws_collect.py --org-role CCARole --account-file accounts.txt -o ./output/

  # Auto-refresh SSO credentials between batches (recommended for SSO users)
  python3 aws_collect.py --org-role CCARole --batch-size 20 --sso-refresh

  # Interactive mode: pause and prompt between batches
  python3 aws_collect.py --org-role CCARole --batch-size 20 --interactive

  # Timed pause between batches (manual refresh)
  python3 aws_collect.py --org-role CCARole --batch-size 20 --pause-between-batches 60
"""
    )

    # Basic options
    parser.add_argument('--config', '-c', help='Path to YAML config file')
    parser.add_argument('--generate-config', action='store_true',
                        help='Generate a sample config file and exit')
    parser.add_argument('--profile', help='AWS profile name (optional in CloudShell)')
    parser.add_argument('--regions', help='Comma-separated list of regions (default: all enabled)')
    parser.add_argument('--output', '-o', help='Output directory or S3 path', default='.')
    parser.add_argument('--log-level', help='Logging level', default='INFO')
    parser.add_argument(
        '--org-name',
        help='Organization name to include in output (used for report filenames)'
    )

    # Data collection options
    parser.add_argument(
        '--skip-storage-sizes',
        action='store_true',
        help='Skip querying CloudWatch for S3 bucket sizes (faster but shows 0 for bucket sizes)'
    )
    parser.add_argument(
        '--skip-change-rate',
        action='store_true',
        help='Skip collecting change rates from CloudWatch'
    )
    parser.add_argument(
        '--skip-pvc',
        action='store_true',
        help='Skip PVC collection from EKS clusters (PVCs are collected by default when clusters are found)'
    )
    parser.add_argument(
        '--change-rate-days',
        type=int,
        default=7,
        help='Number of days to sample for change rate metrics (default: 7)'
    )
    parser.add_argument(
        '--parallel-regions',
        type=int,
        default=None,
        metavar='N',
        help='Number of regions to collect in parallel. Default: 4 (or 1 in CloudShell). '
             'Higher values (4-8) significantly speed up collection but use more memory.'
    )

    # Multi-account options
    parser.add_argument(
        '--role-arn',
        help='Single role ARN to assume for collection (e.g., arn:aws:iam::123456789012:role/CCARole)'
    )
    parser.add_argument(
        '--role-arns',
        help='Comma-separated list of role ARNs to assume for multi-account collection'
    )
    parser.add_argument(
        '--org-role',
        help='Role name to assume in each Organization account (e.g., CCARole). '
             'Discovers all accounts via Organizations API and assumes arn:aws:iam::<account>:role/<org-role>'
    )
    parser.add_argument(
        '--external-id',
        default=os.environ.get('CCA_EXTERNAL_ID'),
        help='External ID for role assumption (applies to all role assumptions). '
             'Can also be set via CCA_EXTERNAL_ID env var to avoid shell history exposure.'
    )
    parser.add_argument(
        '--skip-accounts',
        help='Comma-separated list of account IDs to skip (useful with --org-role)'
    )

    # Batching options (for large environments)
    parser.add_argument(
        '--accounts',
        help='Comma-separated list of account IDs to include (only collect these accounts)'
    )
    parser.add_argument(
        '--account-file',
        help='File containing account IDs to collect (one per line, supports # comments)'
    )
    parser.add_argument(
        '--batch-size',
        type=int,
        help='Auto-batch: collect N accounts per batch, output to numbered subfolders. '
             'Saves checkpoint for resume capability.'
    )
    parser.add_argument(
        '--resume',
        metavar='CHECKPOINT',
        help='Resume collection from checkpoint file (created by --batch-size)'
    )
    parser.add_argument(
        '--checkpoint',
        help='Path for checkpoint file (default: <output>/checkpoint.json)'
    )
    parser.add_argument(
        '--pause-between-batches',
        type=int,
        default=0,
        metavar='SECONDS',
        help='Pause N seconds between batches (allows manual credential refresh)'
    )
    parser.add_argument(
        '--sso-refresh',
        action='store_true',
        help='Run "aws sso login" between batches to refresh SSO credentials'
    )
    parser.add_argument(
        '--interactive',
        action='store_true',
        help='Prompt and wait for user input between batches (for manual credential refresh)'
    )
    parser.add_argument(
        '--parallel-accounts',
        type=int,
        default=None,
        metavar='N',
        help='Number of accounts to collect in parallel using subprocess workers. '
             'Auto-tunes to 4 for 50+ accounts, 8 for 100+ accounts. '
             'Set to 1 to disable auto-parallelization.'
    )
    parser.add_argument(
        '--no-auto-parallel',
        action='store_true',
        help='Disable automatic parallel account collection for large environments'
    )
    parser.add_argument(
        '--include-resource-ids',
        action='store_true',
        help='Include full resource IDs/ARNs in output (default: redact for privacy)'
    )

    args = parser.parse_args()

    # Smart default for parallel_regions based on environment
    if args.parallel_regions is None:
        if is_running_in_cloudshell():
            args.parallel_regions = 1  # CloudShell has memory constraints
        else:
            args.parallel_regions = 4  # Default to parallel on EC2/local

    # Handle --generate-config
    if args.generate_config:
        print(generate_sample_config())
        sys.exit(0)

    # Setup logging - write to file if output is local directory
    log_dir = args.output if not args.output.startswith(('s3://', 'gs://', 'https://')) else None
    setup_logging(args.log_level, output_dir=log_dir)
    log_arguments(args, "AWS collector")

    # Load configuration from file/env/args
    try:
        config = load_config(args)
        if config:
            logger.debug(f"Loaded configuration: {list(config.keys())}")
    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.warning(f"Could not load config file: {e}")

    # Ensure skip_storage_sizes has a default
    if not hasattr(args, 'skip_storage_sizes'):
        args.skip_storage_sizes = False

    # Create base session
    try:
        base_session = get_session(args.profile)
    except Exception as e:
        logger.error(f"Failed to create AWS session: {e}")
        logger.error("Check your AWS credentials are configured correctly.")
        sys.exit(1)

    try:
        base_account_id = get_account_id(base_session)
    except Exception as e:
        logger.error(f"Failed to get AWS account ID: {e}")
        logger.error("Check your credentials have sts:GetCallerIdentity permission.")
        sys.exit(1)

    # Parse regions
    regions = None
    if args.regions:
        regions = [r.strip() for r in args.regions.split(',')]

    # Parse account filters
    skip_accounts = set()
    if args.skip_accounts:
        skip_list = [a.strip() for a in args.skip_accounts.split(',')]
        validate_account_ids(skip_list, "--skip-accounts")
        skip_accounts = set(skip_list)

    include_accounts = None  # None means "all accounts"
    if args.accounts:
        include_list = [a.strip() for a in args.accounts.split(',')]
        validate_account_ids(include_list, "--accounts")
        include_accounts = set(include_list)
    elif args.account_file:
        include_accounts = set(load_account_list(args.account_file))
        logger.info(f"Loaded {len(include_accounts)} accounts from {args.account_file}")

    # Check for resume mode
    checkpoint_file = args.checkpoint or os.path.join(args.output.rstrip('/'), 'checkpoint.json')
    checkpoint: Dict[str, Any] = {'completed_accounts': [], 'failed_accounts': []}
    is_parallel_resume = False

    if args.resume:
        checkpoint_file = args.resume
        checkpoint = load_checkpoint(checkpoint_file)

        # Detect if this is a parallel checkpoint (has 'workers' key)
        if 'workers' in checkpoint:
            is_parallel_resume = True
            # For parallel resume, extract output directory from checkpoint path
            if args.output == '.':
                args.output = os.path.dirname(checkpoint_file)
                logger.info(f"Auto-detected output directory from checkpoint: {args.output}")

        already_done = set(checkpoint.get('completed_accounts', []))
        logger.info(f"Resuming: {len(already_done)} accounts already completed")
        skip_accounts = skip_accounts | already_done

    # Build list of accounts to collect
    accounts_to_collect: List[Dict[str, Any]] = []

    if args.org_role:
        # Organizations discovery mode
        logger.info("Discovering accounts via AWS Organizations...")
        org_accounts = discover_org_accounts(base_session)

        if not org_accounts:
            logger.error("No accounts discovered. Check Organizations permissions or use --role-arns instead.")
            sys.exit(1)

        for account in org_accounts:
            acc_id = account['id']

            # Apply include filter
            if include_accounts is not None and acc_id not in include_accounts:
                continue

            # Apply skip filter
            if acc_id in skip_accounts:
                logger.info(f"Skipping account {acc_id} ({account['name']})")
                continue

            accounts_to_collect.append(account)

    elif args.role_arns:
        # Explicit multi-account role assumption - extract account IDs from ARNs
        role_arns = [r.strip() for r in args.role_arns.split(',')]
        for role_arn in role_arns:
            # Extract account ID from ARN format arn:aws:iam::ACCOUNT_ID:role/...
            try:
                acc_id = role_arn.split(':')[4]
                if include_accounts is not None and acc_id not in include_accounts:
                    continue
                if acc_id in skip_accounts:
                    continue
                accounts_to_collect.append({'id': acc_id, 'name': '', 'role_arn': role_arn})
            except (IndexError, ValueError):
                logger.warning(f"Could not parse account ID from role ARN: {role_arn}")
                accounts_to_collect.append({'id': '', 'name': '', 'role_arn': role_arn})

    elif args.role_arn:
        # Single role assumption
        acc_id = args.role_arn.split(':')[4] if ':' in args.role_arn else ''
        accounts_to_collect.append({'id': acc_id, 'name': '', 'role_arn': args.role_arn})

    else:
        # Single account mode (current credentials)
        accounts_to_collect.append({'id': base_account_id, 'name': '', 'is_base': True})

    if not accounts_to_collect:
        logger.error("No accounts to collect from (all filtered out)")
        sys.exit(1)

    # Auto-tune parallel accounts based on environment size
    num_accounts = len(accounts_to_collect)
    num_regions = len(regions) if regions else 20  # Assume ~20 regions if not specified
    total_region_calls = num_accounts * num_regions

    # Estimated time: ~1.25 min per account with current optimizations
    MINUTES_PER_ACCOUNT = 1.25
    estimated_minutes = num_accounts * MINUTES_PER_ACCOUNT
    estimated_hours = estimated_minutes / 60

    # Auto-tune --parallel-accounts if not explicitly set
    if args.parallel_accounts is None and not args.no_auto_parallel and not is_running_in_cloudshell():
        # If resuming a parallel collection, restore the worker count from checkpoint
        if is_parallel_resume and checkpoint.get('num_workers'):
            args.parallel_accounts = checkpoint['num_workers']
            logger.info(f"Resuming parallel collection with {args.parallel_accounts} workers")
        elif num_accounts >= 100:
            args.parallel_accounts = 8
        elif num_accounts >= 50:
            args.parallel_accounts = 4
        else:
            args.parallel_accounts = 1
    elif args.parallel_accounts is None:
        args.parallel_accounts = 1

    # If parallel accounts > 1 and we have multiple accounts, spawn worker subprocesses
    if args.parallel_accounts > 1 and num_accounts > 1:
        parallel_hours = estimated_hours / args.parallel_accounts
        print("\n" + "=" * 70)
        print(f"PARALLEL COLLECTION: {num_accounts} accounts across {args.parallel_accounts} workers")
        print("=" * 70)
        print(f"  Sequential estimate: {estimated_hours:.1f} hours")
        print(f"  Parallel estimate:   ~{parallel_hours:.1f} hours ({args.parallel_accounts}x speedup)")

        # Suggest --sso-refresh for long-running collections if using SSO
        sso_expiry = get_sso_token_expiry()
        parallel_minutes = estimated_minutes / args.parallel_accounts
        if sso_expiry and parallel_minutes > 45 and not args.sso_refresh:
            now = datetime.now(timezone.utc)
            remaining_minutes = (sso_expiry - now).total_seconds() / 60
            print("")
            print(f"  TIP: SSO token expires in {remaining_minutes:.0f} min, runtime ~{parallel_minutes:.0f} min")
            print("       Consider adding --sso-refresh for automatic credential refresh")

        print("")
        print(f"  Spawning {args.parallel_accounts} parallel worker processes...")
        print("=" * 70 + "\n")

        # Run parallel collection and exit
        exit_code = run_parallel_account_collection(
            accounts_to_collect=accounts_to_collect,
            args=args,
            base_session=base_session,
            regions=regions,
            checkpoint=checkpoint,
            checkpoint_file=checkpoint_file
        )
        sys.exit(exit_code)
    elif num_accounts >= 50:
        # Large environment but running sequentially (CloudShell or --no-auto-parallel)
        print("\n" + "=" * 70)
        print(f"LARGE ENVIRONMENT: {num_accounts} accounts (sequential mode)")
        print("=" * 70)
        print(f"  Estimated runtime: {estimated_hours:.1f} hours ({estimated_minutes:.0f} minutes)")
        if is_running_in_cloudshell():
            print("")
            print("  CloudShell detected - parallel accounts disabled (memory constraints)")
            print("  Consider running from an EC2 instance for faster collection")
        elif args.no_auto_parallel:
            print("")
            print("  Auto-parallel disabled via --no-auto-parallel")
            print(f"  To enable: remove --no-auto-parallel (will use {8 if num_accounts >= 100 else 4} workers)")
        print("")
        print("  Tip: Use --batch-size for checkpointing/resume capability")
        print("=" * 70 + "\n")

    # Recommend maximum parallel collection for very large environments
    if args.parallel_regions < 8 and not is_running_in_cloudshell():
        if num_accounts >= 50 or total_region_calls >= 500:
            print("\n" + "=" * 70)
            print("TIP: Very large environment detected!")
            print(f"     {num_accounts} accounts × {num_regions} regions = {total_region_calls} region collections")
            print("")
            print("     Current: --parallel-regions {}".format(args.parallel_regions))
            print("     Consider increasing for faster collection:")
            print("       python3 aws_collect.py ... --parallel-regions 8")
            print("")
            print("     Estimated speedup: ~{:.0f}x faster".format(min(8 / args.parallel_regions, num_regions)))
            if not args.skip_change_rate:
                print("     (Change rate collection will also be parallelized)")
            print("=" * 70 + "\n")
    elif is_running_in_cloudshell() and (num_accounts >= 50 or total_region_calls >= 500):
        print("\n" + "=" * 70)
        print("WARNING: Very large environment detected in CloudShell!")
        print(f"         {num_accounts} accounts × {num_regions} regions = {total_region_calls} region collections")
        print("")
        print("         CloudShell has limited memory (1GB). For best results:")
        print("         1. Use --batch-size 10 to process fewer accounts at once")
        print("         2. Or run from an EC2 instance with --parallel-regions 8")
        print("=" * 70 + "\n")

    # Warn about CloudShell memory limits with parallel collection
    if is_running_in_cloudshell() and args.parallel_regions > 1:
        print("\n" + "=" * 70)
        print("NOTE: Running parallel collection in CloudShell")
        print(f"      --parallel-regions {args.parallel_regions}")
        print("")
        print("      CloudShell has a 1GB memory limit. If you encounter memory")
        print("      errors, try reducing --parallel-regions or use --batch-size.")
        print("=" * 70 + "\n")

    # Handle batching
    batches = [accounts_to_collect]  # Default: single batch with all accounts

    if args.batch_size and len(accounts_to_collect) > args.batch_size:
        batches = chunk_list(accounts_to_collect, args.batch_size)
        logger.info(f"Split {len(accounts_to_collect)} accounts into {len(batches)} batches of up to {args.batch_size}")

        # Initialize checkpoint for batch tracking
        checkpoint['total_accounts'] = len(accounts_to_collect)
        checkpoint['batch_size'] = args.batch_size
        checkpoint['total_batches'] = len(batches)
        checkpoint['started_at'] = checkpoint.get('started_at') or get_timestamp()

    # Collect from all batches
    all_collected_accounts: List[Dict[str, Any]] = []
    all_summaries = []
    output_base = args.output.rstrip('/')
    run_id = generate_run_id()  # Initialize here, may be overwritten per batch

    for batch_num, batch_accounts in enumerate(batches, 1):
        # Determine output path for this batch
        if len(batches) > 1:
            batch_output = f"{output_base}/batch{batch_num:02d}"
            os.makedirs(batch_output, exist_ok=True)
            print(f"\n{'='*60}")
            print(f"BATCH {batch_num}/{len(batches)}: {len(batch_accounts)} accounts")
            print(f"{'='*60}")
        else:
            batch_output = output_base

        # Build sessions for this batch
        account_sessions: List[tuple] = []

        for account in batch_accounts:
            acc_id = account['id']
            acc_name = account.get('name', '')

            if account.get('is_base'):
                # Use current credentials
                account_sessions.append((base_session, acc_id, acc_name))
            elif account.get('role_arn'):
                # Explicit role ARN provided
                try:
                    assumed_session = assume_role(base_session, account['role_arn'], args.external_id)
                    if not acc_id:
                        acc_id = get_account_id(assumed_session)
                    logger.info(f"Assumed role in account {acc_id}")
                    account_sessions.append((assumed_session, acc_id, acc_name))
                except Exception as e:
                    logger.warning(f"Failed to assume role {account['role_arn']}: {e}")
                    checkpoint['failed_accounts'].append(acc_id)
                    continue
            else:
                # Org discovery mode - construct role ARN
                if acc_id == base_account_id:
                    logger.info(f"Using current credentials for management account {acc_id} ({acc_name})")
                    account_sessions.append((base_session, acc_id, acc_name))
                else:
                    role_arn = f"arn:aws:iam::{acc_id}:role/{args.org_role}"
                    try:
                        assumed_session = assume_role(base_session, role_arn, args.external_id)
                        logger.info(f"Assumed role in account {acc_id} ({acc_name})")
                        account_sessions.append((assumed_session, acc_id, acc_name))
                    except Exception as e:
                        logger.warning(f"Failed to assume role in account {acc_id} ({acc_name}): {e}")
                        checkpoint['failed_accounts'].append(acc_id)
                        continue

        if not account_sessions:
            logger.warning(f"No valid sessions for batch {batch_num}, skipping")
            continue

        # Collect from all accounts in this batch
        batch_resources: List[CloudResource] = []
        batch_collected: List[Dict[str, Any]] = []

        total_regions = len(regions) if regions else len(get_enabled_regions(base_session))

        with ProgressTracker("AWS", total_regions=total_regions * len(account_sessions)) as tracker:
            for session, account_id, account_name in account_sessions:
                try:
                    # Update checkpoint: mark in progress
                    checkpoint['in_progress'] = account_id
                    if args.batch_size:
                        save_checkpoint(checkpoint_file, checkpoint)

                    tracker.start_account(account_id, account_name or "")

                    account_resources = collect_account(
                        session, account_id, regions, tracker,
                        include_storage_sizes=not args.skip_storage_sizes,
                        parallel_regions=args.parallel_regions
                    )
                    batch_resources.extend(account_resources)

                    batch_collected.append({
                        'account_id': account_id,
                        'account_name': account_name,
                        'resource_count': len(account_resources)
                    })

                    # Update checkpoint: mark completed
                    checkpoint['completed_accounts'].append(account_id)
                    checkpoint['in_progress'] = None
                    if args.batch_size:
                        save_checkpoint(checkpoint_file, checkpoint)

                except AuthError as e:
                    logger.error(f"Authentication/authorization error for account {account_id}: {e}")
                    logger.error("Check that the IAM role has required permissions.")
                    checkpoint['failed_accounts'].append(account_id)
                    checkpoint['in_progress'] = None
                    if args.batch_size:
                        save_checkpoint(checkpoint_file, checkpoint)
                    continue
                except Exception as e:
                    logger.error(f"Failed to collect from account {account_id}: {e}")
                    checkpoint['failed_accounts'].append(account_id)
                    checkpoint['in_progress'] = None
                    if args.batch_size:
                        save_checkpoint(checkpoint_file, checkpoint)
                    continue

        # Generate summaries for this batch
        batch_summaries = aggregate_sizing(batch_resources)

        # Collect change rates by default
        change_rate_data = None
        if not args.skip_change_rate:
            logger.info("Collecting change rate metrics from CloudWatch...")
            print("Collecting change rate metrics from CloudWatch...")
            all_change_rates = {}
            for session, account_id, _account_name in account_sessions:
                try:
                    # Filter resources for this account
                    account_resources = [r for r in batch_resources if r.account_id == account_id]
                    cr_data = collect_resource_change_rates(session, account_resources, args.change_rate_days, args.parallel_regions)
                    merge_change_rates(all_change_rates, cr_data)
                except Exception as e:
                    logger.warning(f"Failed to collect change rates for account {account_id}: {e}")

            if all_change_rates:
                change_rate_data = finalize_change_rate_output(
                    all_change_rates, args.change_rate_days, "CloudWatch"
                )
                logger.info(f"Collected change rates for {len(all_change_rates)} service families")

        # Collect PVCs from EKS clusters (automatic when clusters are discovered)
        eks_clusters = [r for r in batch_resources if r.resource_type == 'aws:eks:cluster']

        if eks_clusters and not args.skip_pvc:
            logger.info("Collecting PVCs from EKS clusters...")
            print("Collecting PVCs from EKS clusters...")

            pvc_count = 0
            for session, account_id, _account_name in account_sessions:
                account_clusters = [c for c in eks_clusters if c.account_id == account_id]
                for cluster in account_clusters:
                    if not cluster.name or not cluster.region:
                        continue
                    try:
                        cluster_pvcs = collect_eks_pvcs(
                            session,
                            cluster.name,
                            cluster.region,
                            account_id
                        )
                        batch_resources.extend(cluster_pvcs)
                        pvc_count += len(cluster_pvcs)
                        if cluster_pvcs:
                            logger.info(f"[{cluster.region}] Found {len(cluster_pvcs)} PVCs in cluster {cluster.name}")
                    except ImportError:
                        logger.info("kubernetes package not installed - skipping PVC collection (pip install kubernetes)")
                        print("Note: Install 'kubernetes' package for PVC collection: pip install kubernetes")
                        break
                    except Exception as e:
                        logger.warning(f"Failed to collect PVCs from cluster {cluster.name}: {e}")
                else:
                    continue
                break  # Break outer loop if ImportError occurred

            if pvc_count > 0:
                print(f"Collected {pvc_count} PVCs from {len(eks_clusters)} EKS clusters")
        elif eks_clusters and args.skip_pvc:
            logger.info("Skipping PVC collection (--skip-pvc specified)")

        # Write batch outputs
        run_id = generate_run_id()
        timestamp = get_timestamp()

        is_multi_account = len(batch_collected) > 1
        account_ids = [a['account_id'] for a in batch_collected]

        output_data = {
            'run_id': run_id,
            'timestamp': timestamp,
            'provider': 'aws',
            'org_name': args.org_name if args.org_name else None,
            'account_id': account_ids[0] if len(account_ids) == 1 else account_ids,
            'accounts': batch_collected if is_multi_account else None,
            'regions': regions if regions else 'all',
            'resource_count': len(batch_resources),
            'resources': [r.to_dict() for r in batch_resources]
        }

        summary_data = {
            'run_id': run_id,
            'timestamp': timestamp,
            'collector_metadata': get_collector_metadata(args, 'aws', __version__),
            'provider': 'aws',
            'org_name': args.org_name if args.org_name else None,
            'account_id': account_ids[0] if len(account_ids) == 1 else account_ids,
            'accounts': batch_collected if is_multi_account else None,
            'total_resources': len(batch_resources),
            'total_capacity_gb': sum(s.total_gb for s in batch_summaries),
            'summaries': [s.to_dict() for s in batch_summaries],
            'change_rates': change_rate_data if change_rate_data else None
        }

        # Remove None values
        output_data = {k: v for k, v in output_data.items() if v is not None}
        summary_data = {k: v for k, v in summary_data.items() if v is not None}

        # Redact sensitive IDs unless --include-resource-ids is specified
        if not args.include_resource_ids:
            output_data = redact_sensitive_data(output_data)
            summary_data = redact_sensitive_data(summary_data)

        # Handle S3 output
        if batch_output.startswith('s3://'):
            batch_output = f"{batch_output}/{run_id}"

        # Write outputs
        file_ts = datetime.now(timezone.utc).strftime('%H%M%S')
        write_json(output_data, f"{batch_output}/cca_aws_inv_{file_ts}.json")
        write_json(summary_data, f"{batch_output}/cca_aws_sum_{file_ts}.json")

        # Write change rate data to separate file if collected
        if change_rate_data:
            change_rate_output = {
                'run_id': run_id,
                'timestamp': timestamp,
                'provider': 'aws',
                'account_id': account_ids[0] if len(account_ids) == 1 else account_ids,
                **change_rate_data
            }
            if not args.include_resource_ids:
                change_rate_output = redact_sensitive_data(change_rate_output)
            write_json(change_rate_output, f"{batch_output}/cca_aws_change_rates_{file_ts}.json")

        # Track for final summary
        all_collected_accounts.extend(batch_collected)
        all_summaries.extend(batch_summaries)

        # Print batch results
        if len(batches) > 1:
            print(f"\nBatch {batch_num} complete: {len(batch_collected)} accounts, {len(batch_resources)} resources")
            print(f"Output: {batch_output}/")

        # Handle credential refresh between batches
        if batch_num < len(batches):
            if args.sso_refresh:
                print(f"\n{'='*60}")
                print(f"Refreshing SSO credentials before batch {batch_num + 1}...")
                print(f"{'='*60}")
                sso_cmd = ['aws', 'sso', 'login']
                if args.profile:
                    sso_cmd.extend(['--profile', args.profile])
                try:
                    subprocess.run(sso_cmd, check=True)
                    print("SSO login successful, continuing...")
                    # Recreate base session with refreshed credentials
                    base_session = get_session(args.profile)
                except subprocess.CalledProcessError as e:
                    print(f"SSO login failed (exit code {e.returncode})")
                    print("You can resume later with: --resume " + checkpoint_file)
                    sys.exit(1)
                except FileNotFoundError:
                    print("Error: 'aws' CLI not found. Install AWS CLI or use --interactive instead.")
                    sys.exit(1)

            elif args.interactive:
                print(f"\n{'='*60}")
                print(f"BATCH {batch_num}/{len(batches)} COMPLETE")
                print(f"{'='*60}")
                print("Refresh your credentials now if needed.")
                print("  - AWS SSO: aws sso login" + (f" --profile {args.profile}" if args.profile else ""))
                print("  - IAM User: update ~/.aws/credentials")
                print(f"Progress saved to: {checkpoint_file}")
                input("\nPress ENTER to continue to batch " + str(batch_num + 1) + "...")
                # Recreate base session with potentially refreshed credentials
                base_session = get_session(args.profile)

            elif args.pause_between_batches:
                print(f"\nPausing {args.pause_between_batches} seconds before next batch...")
                print("(Refresh credentials now if using SSO)")
                time.sleep(args.pause_between_batches)

    # Final checkpoint update
    if args.batch_size:
        checkpoint['completed_at'] = get_timestamp()
        save_checkpoint(checkpoint_file, checkpoint)
        print(f"\nCheckpoint saved: {checkpoint_file}")
        if checkpoint['failed_accounts']:
            print(f"Failed accounts ({len(checkpoint['failed_accounts'])}): {', '.join(checkpoint['failed_accounts'])}")
            print(f"Re-run with: --accounts {','.join(checkpoint['failed_accounts'])}")

    # Print final summary
    if len(all_collected_accounts) > 1:
        print(f"\n{'='*60}")
        print("COLLECTION COMPLETE")
        print(f"{'='*60}")
        print(f"Total accounts: {len(all_collected_accounts)}")
        for acc in all_collected_accounts:
            name_str = f" ({acc['account_name']})" if acc.get('account_name') else ""
            print(f"  - {acc['account_id']}{name_str}: {acc['resource_count']} resources")

    print(f"\nRun ID: {run_id}")
    print_summary_table([s.to_dict() for s in all_summaries])
    print(f"Output: {output_base}/")

    if len(batches) > 1:
        print(f"\nTo merge batches: python3 scripts/merge_batch_outputs.py {output_base}/")

    # Exit with error if all accounts failed
    if not all_collected_accounts and checkpoint.get('failed_accounts'):
        print(f"\nERROR: All {len(checkpoint['failed_accounts'])} account(s) failed to collect.")
        sys.exit(1)


if __name__ == '__main__':
    main()
