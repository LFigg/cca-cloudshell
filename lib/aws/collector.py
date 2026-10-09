"""AWS collection orchestration.

Orchestrates multi-account, multi-region AWS resource collection.
Called by collect.py after argument parsing.

Usage:
    from lib.aws.collector import collect_region, collect_account, run_collection
    run_collection(args)
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

import boto3

from lib.__version__ import __version__
from lib.aws.auth import (
    assume_role,
    discover_org_accounts,
    get_account_id,
    get_account_ou_info,
    get_enabled_regions,
    get_organization_info,
    get_session,
    get_sso_token_expiry,
    is_running_in_cloudshell,
)
from lib.aws.backup import (
    collect_backup_plans,
    collect_backup_protected_resources,
    collect_backup_recovery_points,
    collect_backup_region_settings,
    collect_backup_selections,
    collect_backup_vaults,
    collect_dlm_lifecycle_policies,
)
from lib.aws.compute import (
    collect_ebs_snapshots,
    collect_ebs_volumes,
    collect_ec2_instances,
    collect_lambda_functions,
)
from lib.aws.container import collect_eks_clusters, collect_eks_nodegroups
from lib.aws.cost import collect_aws_costs
from lib.aws.databases import (
    collect_documentdb_clusters,
    collect_dynamodb_tables,
    collect_elasticache_clusters,
    collect_memorydb_clusters,
    collect_neptune_clusters,
    collect_opensearch_domains,
    collect_rds_cluster_snapshots,
    collect_rds_clusters,
    collect_rds_instances,
    collect_rds_snapshots,
    collect_redshift_clusters,
    collect_timestream_databases,
)
from lib.aws.helpers import chunk_list, load_account_list, validate_account_ids
from lib.aws.monitoring import collect_resource_change_rates
from lib.aws.parallel import (
    load_checkpoint,
    run_parallel_account_collection,
    save_checkpoint,
)
from lib.aws.permissions import format_permission_report, verify_aws_permissions
from lib.aws.storage import (
    collect_efs_filesystems,
    collect_fsx_filesystems,
    collect_s3_buckets,
)
from lib.change_rate import finalize_change_rate_output, merge_change_rates
from lib.collection_completeness import compute_collection_completeness, format_completeness_report
from lib.config import generate_sample_config, load_config
from lib.data_quality import compute_data_quality_summary, format_data_quality_report
from lib.k8s import collect_eks_pvcs
from lib.models import CloudResource, aggregate_sizing
from lib.utils import (
    AuthError,
    ProgressTracker,
    aggregate_costs,
    generate_run_id,
    get_collector_metadata,
    get_last_full_month,
    get_timestamp,
    log_arguments,
    print_summary_table,
    redact_sensitive_data,
    setup_logging,
    write_json,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Region / Account Collection
# =============================================================================

def collect_region(
    session: boto3.Session,
    region: str,
    account_id: str,
    tracker: Optional[ProgressTracker] = None
) -> List[CloudResource]:
    """Collect all resources in a single AWS region.

    Args:
        session: boto3 Session with credentials for the target account
        region: AWS region name to collect from
        account_id: AWS account ID being collected
        tracker: Optional progress tracker to update as collection proceeds

    Returns:
        List of CloudResource objects found in the region
    """
    resources: List[CloudResource] = []

    logger.info(f"Collecting resources in {region}...")

    def collect_and_track(name: str, collect_fn, *args):
        if tracker:
            tracker.update_task(f"Collecting {name}...")
        try:
            result = collect_fn(*args)
        except Exception as e:
            logger.error(f"[{region}] Failed to collect {name}: {e}")
            return []
        if tracker and result:
            tracker.add_resources(len(result), sum(r.size_gb for r in result))
        return result

    resources.extend(collect_and_track("EC2 instances", collect_ec2_instances, session, region, account_id))
    resources.extend(collect_and_track("EBS volumes", collect_ebs_volumes, session, region, account_id))
    resources.extend(collect_and_track("EBS snapshots", collect_ebs_snapshots, session, region, account_id))
    resources.extend(collect_and_track("RDS instances", collect_rds_instances, session, region, account_id))
    resources.extend(collect_and_track("RDS clusters", collect_rds_clusters, session, region, account_id))
    resources.extend(collect_and_track("RDS snapshots", collect_rds_snapshots, session, region, account_id))
    resources.extend(collect_and_track("RDS cluster snapshots", collect_rds_cluster_snapshots, session, region, account_id))
    resources.extend(collect_and_track("EFS filesystems", collect_efs_filesystems, session, region, account_id))
    resources.extend(collect_and_track("FSx filesystems", collect_fsx_filesystems, session, region, account_id))
    resources.extend(collect_and_track("EKS clusters", collect_eks_clusters, session, region, account_id))
    resources.extend(collect_and_track("EKS node groups", collect_eks_nodegroups, session, region, account_id))
    resources.extend(collect_and_track("Lambda functions", collect_lambda_functions, session, region, account_id))
    resources.extend(collect_and_track("DynamoDB tables", collect_dynamodb_tables, session, region, account_id))
    resources.extend(collect_and_track("ElastiCache clusters", collect_elasticache_clusters, session, region, account_id))
    resources.extend(collect_and_track("Redshift clusters", collect_redshift_clusters, session, region, account_id))
    resources.extend(collect_and_track("DocumentDB clusters", collect_documentdb_clusters, session, region, account_id))
    resources.extend(collect_and_track("Neptune clusters", collect_neptune_clusters, session, region, account_id))
    resources.extend(collect_and_track("OpenSearch domains", collect_opensearch_domains, session, region, account_id))
    resources.extend(collect_and_track("MemoryDB clusters", collect_memorydb_clusters, session, region, account_id))
    resources.extend(collect_and_track("Timestream tables", collect_timestream_databases, session, region, account_id))
    resources.extend(collect_and_track("Backup vaults", collect_backup_vaults, session, region, account_id))
    resources.extend(collect_and_track("Backup recovery points", collect_backup_recovery_points, session, region, account_id))
    resources.extend(collect_and_track("Backup plans", collect_backup_plans, session, region, account_id))
    resources.extend(collect_and_track("Backup selections", collect_backup_selections, session, region, account_id))
    resources.extend(collect_and_track("Backup protected resources", collect_backup_protected_resources, session, region, account_id))
    resources.extend(collect_and_track("DLM lifecycle policies", collect_dlm_lifecycle_policies, session, region, account_id))

    return resources


def collect_account(
    session: boto3.Session,
    account_id: str,
    regions: Optional[List[str]] = None,
    tracker: Optional[ProgressTracker] = None,
    include_storage_sizes: bool = False,
    parallel_regions: int = 1
) -> List[CloudResource]:
    """Collect all resources from a single AWS account.

    Args:
        session: boto3 Session with credentials for this account
        account_id: AWS account ID
        regions: Regions to collect (None = all enabled)
        tracker: Optional progress tracker
        include_storage_sizes: Query CloudWatch for S3 bucket sizes
        parallel_regions: Number of regions to collect in parallel

    Returns:
        List of CloudResource objects
    """
    resources: List[CloudResource] = []

    if regions is None:
        try:
            regions = get_enabled_regions(session)
        except Exception as e:
            logger.error(f"Failed to discover enabled regions for account {account_id}: {e}")
            regions = []

    logger.info(f"Collecting from account {account_id} across {len(regions)} regions (parallel={parallel_regions})")

    if tracker:
        tracker.update_task("Collecting S3 buckets...")
    try:
        s3_resources = collect_s3_buckets(session, account_id, include_sizes=include_storage_sizes)
    except Exception as e:
        logger.error(f"Failed to collect S3 buckets for account {account_id}: {e}")
        s3_resources = []
    resources.extend(s3_resources)
    if tracker:
        tracker.add_resources(len(s3_resources), sum(r.size_gb for r in s3_resources))

    if tracker:
        tracker.update_task("Collecting Backup region settings...")
    # Prefer us-east-1 over regions[0] (the alphabetically-first enabled
    # region, almost never us-east-1 since codes like ap-northeast-1 sort
    # first): this setting is account-wide/global, identical from any
    # region, and us-east-1 is the one region the mandatory preflight check
    # already proved is callable for this exact API action (see
    # lib/aws/permissions.py's _DEFAULT_PROBE_REGION). Some SCPs scope AWS
    # Backup actions to specific regions independently of other services'
    # own region restrictions, so regions[0] can land somewhere this
    # specific call is denied even though us-east-1 would have worked.
    if not regions:
        backup_region = 'us-east-1'
    elif 'us-east-1' in regions:
        backup_region = 'us-east-1'
    else:
        backup_region = regions[0]
    try:
        backup_settings = collect_backup_region_settings(session, backup_region, account_id)
    except Exception as e:
        logger.error(f"Failed to collect Backup region settings for account {account_id}: {e}")
        backup_settings = []
    for resource in backup_settings:
        resource.region = 'global'
        resource.resource_id = f"arn:aws:backup:{account_id}:region-settings"
    resources.extend(backup_settings)
    if tracker and backup_settings:
        tracker.add_resources(len(backup_settings), 0)

    if parallel_regions > 1 and len(regions) > 1:
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
        for region in regions:
            if tracker:
                tracker.start_region(region)
            try:
                region_resources = collect_region(session, region, account_id, tracker)
                resources.extend(region_resources)
            except Exception as e:
                logger.error(f"[{region}] Failed: {e}")
            if tracker:
                tracker.complete_region()

    logger.info(f"Collected {len(resources)} resources from account {account_id}")
    return resources


# =============================================================================
# Argument Parser (for collect.py)
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    """Return the argparse parser for the AWS collector."""
    parser = argparse.ArgumentParser(description='CCA CloudShell - AWS Resource Collector')

    # Basic options
    parser.add_argument('--config', '-c', help='Path to YAML config file')
    parser.add_argument('--generate-config', action='store_true',
                        help='Generate a sample config file and exit')
    parser.add_argument('--profile', help='AWS profile name (optional in CloudShell)')
    parser.add_argument('--regions', help='Comma-separated list of regions (default: all enabled)')
    parser.add_argument('--output', '-o', help='Output directory or S3 path', default='.')
    parser.add_argument('--log-level', help='Logging level', default='INFO')
    parser.add_argument('--org-name',
                        help='Organization name to include in output (used for report filenames)')

    # Data collection options
    parser.add_argument('--skip-storage-sizes', action='store_true',
                        help='Skip querying CloudWatch for S3 bucket sizes (faster but shows 0 for bucket sizes)')
    parser.add_argument('--skip-change-rate', action='store_true',
                        help='Skip collecting change rates from CloudWatch')
    parser.add_argument('--skip-pvc', action='store_true',
                        help='Skip PVC collection from EKS clusters')
    parser.add_argument('--change-rate-days', type=int, default=7,
                        help='Number of days to sample for change rate metrics (default: 7)')
    parser.add_argument('--parallel-regions', type=int, default=None, metavar='N',
                        help='Number of regions to collect in parallel (default: 4, or 1 in CloudShell)')
    parser.add_argument('--no-costs', action='store_true',
                        help='Skip data protection cost collection (costs are collected by default)')

    # Multi-account options
    parser.add_argument('--role-arn',
                        help='Single role ARN to assume for collection')
    parser.add_argument('--role-arns',
                        help='Comma-separated list of role ARNs for multi-account collection')
    parser.add_argument('--org-role',
                        help='Role name to assume in each Organization account (e.g., CCARole)')
    parser.add_argument('--external-id', default=os.environ.get('CCA_EXTERNAL_ID'),
                        help='External ID for role assumption (or set CCA_EXTERNAL_ID env var)')
    parser.add_argument('--skip-accounts',
                        help='Comma-separated list of account IDs to skip')

    # Batching / resume options
    parser.add_argument('--accounts',
                        help='Comma-separated list of account IDs to include')
    parser.add_argument('--account-file',
                        help='File containing account IDs to collect (one per line)')
    parser.add_argument('--batch-size', type=int,
                        help='Auto-batch: collect N accounts per batch')
    parser.add_argument('--resume', metavar='CHECKPOINT',
                        help='Resume collection from checkpoint file')
    parser.add_argument('--checkpoint',
                        help='Path for checkpoint file (default: <output>/checkpoint.json)')
    parser.add_argument('--pause-between-batches', type=int, default=0, metavar='SECONDS',
                        help='Pause N seconds between batches')
    parser.add_argument('--sso-refresh', action='store_true',
                        help='Run "aws sso login" between batches to refresh SSO credentials')
    parser.add_argument('--interactive', action='store_true',
                        help='Prompt and wait for user input between batches')
    parser.add_argument('--parallel-accounts', type=int, default=None, metavar='N',
                        help='Number of accounts to collect in parallel')
    parser.add_argument('--no-auto-parallel', action='store_true',
                        help='Disable automatic parallel account collection for large environments')
    parser.add_argument('--auto-merge-threshold', type=float, default=90.0, metavar='PCT',
                        help='Auto-merge batches when at least this percent of target accounts succeed (default: 90)')
    parser.add_argument('--include-resource-ids', action='store_true',
                        help='Include full resource IDs/ARNs in output (default: redact for privacy)')

    return parser


# =============================================================================
# Run Collection (called by collect.py)
# =============================================================================

def run_collection(args) -> None:
    """Run full AWS collection based on parsed CLI args.

    Args:
        args: argparse.Namespace with all AWS collection options.
              Expected attributes — see collect.py for full list.
    """
    # Smart default for parallel_regions
    if getattr(args, 'parallel_regions', None) is None:
        args.parallel_regions = 1 if is_running_in_cloudshell() else 4

    if getattr(args, 'generate_config', False):
        print(generate_sample_config())
        sys.exit(0)

    log_dir = args.output if not args.output.startswith(('s3://', 'gs://', 'https://')) else None
    setup_logging(args.log_level, output_dir=log_dir)
    log_arguments(args, "AWS collector")

    try:
        config = load_config(args)
        if config:
            logger.debug(f"Loaded configuration: {list(config.keys())}")
    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.warning(f"Could not load config file: {e}")

    if not hasattr(args, 'skip_storage_sizes'):
        args.skip_storage_sizes = False

    try:
        base_session = get_session(args.profile)
    except Exception as e:
        logger.error(f"Failed to create AWS session: {e}")
        sys.exit(1)

    try:
        base_account_id = get_account_id(base_session)
    except Exception as e:
        logger.error(f"Failed to get AWS account ID: {e}")
        sys.exit(1)

    regions = None
    if args.regions:
        regions = [r.strip() for r in args.regions.split(',')]

    skip_accounts: set = set()
    if args.skip_accounts:
        skip_list = [a.strip() for a in args.skip_accounts.split(',')]
        validate_account_ids(skip_list, "--skip-accounts")
        skip_accounts = set(skip_list)

    include_accounts = None
    if args.accounts:
        include_list = [a.strip() for a in args.accounts.split(',')]
        validate_account_ids(include_list, "--accounts")
        include_accounts = set(include_list)
    elif args.account_file:
        include_accounts = set(load_account_list(args.account_file))
        logger.info(f"Loaded {len(include_accounts)} accounts from {args.account_file}")

    checkpoint_file = args.checkpoint or os.path.join(args.output.rstrip('/'), 'checkpoint.json')
    checkpoint: Dict[str, Any] = {'completed_accounts': [], 'failed_accounts': []}
    is_parallel_resume = False

    if args.resume:
        checkpoint_file = os.path.abspath(args.resume)
        checkpoint = load_checkpoint(checkpoint_file)
        checkpoint.setdefault('failed_account_reasons', {})
        if 'workers' in checkpoint:
            is_parallel_resume = True
            if args.output == '.':
                args.output = os.path.dirname(checkpoint_file)
                logger.info(f"Auto-detected output directory from checkpoint: {args.output}")
        already_done = set(checkpoint.get('completed_accounts', []))
        logger.info(f"Resuming: {len(already_done)} accounts already completed")
        skip_accounts = skip_accounts | already_done

    # Build accounts list
    accounts_to_collect: List[Dict[str, Any]] = []

    if args.org_role:
        logger.info("Discovering accounts via AWS Organizations...")
        org_accounts = discover_org_accounts(base_session)
        if not org_accounts:
            logger.error("No accounts discovered. Check Organizations permissions.")
            sys.exit(1)
        for account in org_accounts:
            acc_id = account['id']
            if include_accounts is not None and acc_id not in include_accounts:
                continue
            if acc_id in skip_accounts:
                logger.info(f"Skipping account {acc_id} ({account['name']})")
                continue
            accounts_to_collect.append(account)

    elif args.role_arns:
        role_arns = [r.strip() for r in args.role_arns.split(',')]
        for role_arn in role_arns:
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
        acc_id = args.role_arn.split(':')[4] if ':' in args.role_arn else ''
        accounts_to_collect.append({'id': acc_id, 'name': '', 'role_arn': args.role_arn})

    else:
        accounts_to_collect.append({'id': base_account_id, 'name': '', 'is_base': True})

    # Track account-level status for summary/output context.
    account_status_map: Dict[str, Dict[str, Any]] = {}
    account_ids_for_ou = [a.get('id') for a in accounts_to_collect if a.get('id')]
    ou_info_map = get_account_ou_info(base_session, account_ids_for_ou)

    for account in accounts_to_collect:
        acc_id = account.get('id')
        if not acc_id:
            continue
        ou_info = ou_info_map.get(acc_id, {})
        account_status_map[acc_id] = {
            'account_id': acc_id,
            'account_name': account.get('name', ''),
            'account_status': account.get('status', 'UNKNOWN'),
            'ou_id': ou_info.get('ou_id'),
            'ou_name': ou_info.get('ou_name'),
            'ou_path': ou_info.get('ou_path'),
            'collection_status': 'pending',
            'failure_reason': None,
        }

    checkpoint.setdefault('failed_account_reasons', {})

    org_info = get_organization_info(base_session)

    run_mode = 'single-account'
    if args.org_role:
        run_mode = 'org-role'
    elif args.role_arns:
        run_mode = 'role-arns'
    elif args.role_arn:
        run_mode = 'role-arn'

    run_scope = {
        'mode': run_mode,
        'filters': {
            'include_accounts': sorted(include_accounts) if include_accounts else None,
            'skip_accounts': sorted(skip_accounts) if skip_accounts else None,
            'regions': regions if regions else 'all',
        },
        'batching': {
            'batch_size': args.batch_size,
            'parallel_accounts': args.parallel_accounts,
            'auto_merge_threshold': getattr(args, 'auto_merge_threshold', 90.0),
        },
        'auth': {
            'profile': args.profile,
            'external_id_used': bool(args.external_id),
        },
    }

    if not accounts_to_collect:
        logger.error("No accounts to collect from (all filtered out)")
        sys.exit(1)

    # Mandatory preflight: verify every permission this run's flags require -
    # across every account - before collecting anything. This must run here,
    # before the parallel-accounts subprocess-dispatch branch below, or a
    # parallel-mode run would skip it entirely. A gap found midway through
    # collection today just drops that account's resources into
    # failed_accounts with no chance to fix and re-run cheaply. There is no
    # flag to skip this - if the collection needs a permission, it must be
    # verified up front, once, rather than discovered partway through (or
    # after) a possibly hours-long run.
    logger.info("Verifying AWS permissions for this run's configuration...")
    print("Verifying AWS permissions before starting collection...")
    permission_results = verify_aws_permissions(
        base_session, accounts_to_collect, args,
        external_id=args.external_id, regions=regions,
    )
    accounts_missing_permissions = [r for r in permission_results if r.missing]
    if accounts_missing_permissions:
        report = format_permission_report(permission_results)
        logger.error(
            f"Permission check failed for {len(accounts_missing_permissions)}/{len(accounts_to_collect)} "
            f"account(s). Collection was not started.\n{report}"
        )
        print(
            f"\n✗ Permission check failed for {len(accounts_missing_permissions)}/{len(accounts_to_collect)} "
            f"account(s) - collection was not started.\n{report}\n\n"
            "Grant the missing permission(s) above (or narrow this run with "
            "--accounts/--skip-change-rate/--skip-pvc/--skip-storage-sizes/--no-costs as appropriate), "
            "then re-run."
        )
        sys.exit(1)

    accounts_with_warnings = [r for r in permission_results if r.warnings and not r.missing]
    if accounts_with_warnings:
        logger.warning(format_permission_report(permission_results))
    logger.info("Permission check passed for all accounts being collected")

    num_accounts = len(accounts_to_collect)
    num_regions = len(regions) if regions else 20
    total_region_calls = num_accounts * num_regions
    MINUTES_PER_ACCOUNT = 1.25
    estimated_minutes = num_accounts * MINUTES_PER_ACCOUNT
    estimated_hours = estimated_minutes / 60

    if args.parallel_accounts is None and not args.no_auto_parallel and not is_running_in_cloudshell():
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

    if args.parallel_accounts > 1 and num_accounts > 1:
        parallel_hours = estimated_hours / args.parallel_accounts
        print("\n" + "=" * 70)
        print(f"PARALLEL COLLECTION: {num_accounts} accounts across {args.parallel_accounts} workers")
        print("=" * 70)
        print(f"  Sequential estimate: {estimated_hours:.1f} hours")
        print(f"  Parallel estimate:   ~{parallel_hours:.1f} hours ({args.parallel_accounts}x speedup)")
        sso_expiry = get_sso_token_expiry()
        parallel_minutes = estimated_minutes / args.parallel_accounts
        if sso_expiry and parallel_minutes > 45 and not args.sso_refresh:
            now = datetime.now(timezone.utc)
            remaining_minutes = (sso_expiry - now).total_seconds() / 60
            print(f"\n  TIP: SSO token expires in {remaining_minutes:.0f} min, runtime ~{parallel_minutes:.0f} min")
            print("       Consider adding --sso-refresh for automatic credential refresh")
        print(f"\n  Spawning {args.parallel_accounts} parallel worker processes...")
        print("=" * 70 + "\n")
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
        print("\n" + "=" * 70)
        print(f"LARGE ENVIRONMENT: {num_accounts} accounts (sequential mode)")
        print("=" * 70)
        print(f"  Estimated runtime: {estimated_hours:.1f} hours ({estimated_minutes:.0f} minutes)")
        if is_running_in_cloudshell():
            print("\n  CloudShell detected - parallel accounts disabled (memory constraints)")
        elif args.no_auto_parallel:
            print("\n  Auto-parallel disabled via --no-auto-parallel")
        print("\n  Tip: Use --batch-size for checkpointing/resume capability")
        print("=" * 70 + "\n")

    if args.parallel_regions < 8 and not is_running_in_cloudshell():
        if num_accounts >= 50 or total_region_calls >= 500:
            print("\n" + "=" * 70)
            print("TIP: Very large environment detected!")
            print(f"     {num_accounts} accounts × {num_regions} regions = {total_region_calls} region collections")
            print("     Consider: --parallel-regions 8")
            print("=" * 70 + "\n")
    elif is_running_in_cloudshell() and (num_accounts >= 50 or total_region_calls >= 500):
        print("\n" + "=" * 70)
        print("WARNING: Very large environment detected in CloudShell!")
        print(f"         {num_accounts} accounts × {num_regions} regions = {total_region_calls} region collections")
        print("         Consider --batch-size 10 or running from an EC2 instance")
        print("=" * 70 + "\n")

    if is_running_in_cloudshell() and args.parallel_regions > 1:
        print("\n" + "=" * 70)
        print(f"NOTE: Running parallel collection in CloudShell (--parallel-regions {args.parallel_regions})")
        print("      CloudShell has a 1GB memory limit. Reduce --parallel-regions if needed.")
        print("=" * 70 + "\n")

    # Handle batching
    batches = [accounts_to_collect]
    if args.batch_size and len(accounts_to_collect) > args.batch_size:
        batches = chunk_list(accounts_to_collect, args.batch_size)
        logger.info(f"Split {len(accounts_to_collect)} accounts into {len(batches)} batches of up to {args.batch_size}")
        checkpoint['total_accounts'] = len(accounts_to_collect)
        checkpoint['batch_size'] = args.batch_size
        checkpoint['total_batches'] = len(batches)
        checkpoint['started_at'] = checkpoint.get('started_at') or get_timestamp()

    all_collected_accounts: List[Dict[str, Any]] = []
    all_summaries = []
    output_base = args.output.rstrip('/')
    run_id = generate_run_id()

    for batch_num, batch_accounts in enumerate(batches, 1):
        if len(batches) > 1:
            batch_output = f"{output_base}/batch{batch_num:02d}"
            os.makedirs(batch_output, exist_ok=True)
            print(f"\n{'='*60}\nBATCH {batch_num}/{len(batches)}: {len(batch_accounts)} accounts\n{'='*60}")
        else:
            batch_output = output_base

        account_sessions: List[tuple] = []
        batch_failed_accounts: List[Dict[str, Any]] = []
        for account in batch_accounts:
            acc_id = account['id']
            acc_name = account.get('name', '')
            if account.get('is_base'):
                account_sessions.append((base_session, acc_id, acc_name))
            elif account.get('role_arn'):
                try:
                    assumed_session = assume_role(base_session, account['role_arn'], args.external_id)
                    if not acc_id:
                        acc_id = get_account_id(assumed_session)
                    account_sessions.append((assumed_session, acc_id, acc_name))
                except Exception as e:
                    logger.warning(f"Failed to assume role {account['role_arn']}: {e}")
                    checkpoint['failed_accounts'].append(acc_id)
                    batch_failed_accounts.append({'id': acc_id, 'name': acc_name, 'error': str(e)})
                    if acc_id in account_status_map:
                        account_status_map[acc_id]['collection_status'] = 'failed'
                        account_status_map[acc_id]['failure_reason'] = 'assume-role-failed'
                    checkpoint['failed_account_reasons'][acc_id] = 'assume-role-failed'
                    continue
            else:
                if acc_id == base_account_id:
                    account_sessions.append((base_session, acc_id, acc_name))
                else:
                    role_arn = f"arn:aws:iam::{acc_id}:role/{args.org_role}"
                    try:
                        assumed_session = assume_role(base_session, role_arn, args.external_id)
                        account_sessions.append((assumed_session, acc_id, acc_name))
                    except Exception as e:
                        logger.warning(f"Failed to assume role in account {acc_id}: {e}")
                        checkpoint['failed_accounts'].append(acc_id)
                        batch_failed_accounts.append({'id': acc_id, 'name': acc_name, 'error': str(e)})
                        if acc_id in account_status_map:
                            account_status_map[acc_id]['collection_status'] = 'failed'
                            account_status_map[acc_id]['failure_reason'] = 'assume-role-failed'
                        checkpoint['failed_account_reasons'][acc_id] = 'assume-role-failed'
                        continue

        if not account_sessions:
            logger.warning(f"No valid sessions for batch {batch_num}, skipping")
            continue

        batch_resources: List[CloudResource] = []
        batch_collected: List[Dict[str, Any]] = []
        total_regions = len(regions) if regions else len(get_enabled_regions(base_session))

        with ProgressTracker("AWS", total_regions=total_regions * len(account_sessions)) as tracker:
            for session, account_id, account_name in account_sessions:
                try:
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
                    checkpoint['completed_accounts'].append(account_id)
                    if account_id in account_status_map:
                        account_status_map[account_id]['collection_status'] = 'completed'
                        account_status_map[account_id]['failure_reason'] = None
                    checkpoint['in_progress'] = None
                    if args.batch_size:
                        save_checkpoint(checkpoint_file, checkpoint)
                except AuthError as e:
                    logger.error(f"Auth error for account {account_id}: {e}")
                    checkpoint['failed_accounts'].append(account_id)
                    batch_failed_accounts.append({'id': account_id, 'name': account_name, 'error': str(e)})
                    if account_id in account_status_map:
                        account_status_map[account_id]['collection_status'] = 'failed'
                        account_status_map[account_id]['failure_reason'] = 'auth-error'
                    checkpoint['failed_account_reasons'][account_id] = 'auth-error'
                    checkpoint['in_progress'] = None
                    if args.batch_size:
                        save_checkpoint(checkpoint_file, checkpoint)
                    continue
                except Exception as e:
                    logger.error(f"Failed to collect from account {account_id}: {e}")
                    checkpoint['failed_accounts'].append(account_id)
                    batch_failed_accounts.append({'id': account_id, 'name': account_name, 'error': str(e)})
                    if account_id in account_status_map:
                        account_status_map[account_id]['collection_status'] = 'failed'
                        account_status_map[account_id]['failure_reason'] = 'collection-failed'
                    checkpoint['failed_account_reasons'][account_id] = 'collection-failed'
                    checkpoint['in_progress'] = None
                    if args.batch_size:
                        save_checkpoint(checkpoint_file, checkpoint)
                    continue

        # Change rates
        change_rate_data = None
        if not args.skip_change_rate:
            logger.info("Collecting change rate metrics from CloudWatch...")
            print("Collecting change rate metrics from CloudWatch...")
            all_change_rates: Dict = {}
            for session, account_id, _account_name in account_sessions:
                try:
                    account_resources = [r for r in batch_resources if r.account_id == account_id]
                    cr_data = collect_resource_change_rates(session, account_resources, args.change_rate_days, args.parallel_regions)
                    merge_change_rates(all_change_rates, cr_data)
                except Exception as e:
                    logger.warning(f"Failed to collect change rates for account {account_id}: {e}")
            if all_change_rates:
                change_rate_data = finalize_change_rate_output(
                    all_change_rates, args.change_rate_days, "CloudWatch"
                )

        # PVCs from EKS
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
                        cluster_pvcs = collect_eks_pvcs(session, cluster.name, cluster.region, account_id)
                        batch_resources.extend(cluster_pvcs)
                        pvc_count += len(cluster_pvcs)
                    except ImportError:
                        logger.info("kubernetes package not installed - skipping PVC collection")
                        print("Note: Install 'kubernetes' package for PVC collection: pip install kubernetes")
                        break
                    except Exception as e:
                        logger.warning(f"Failed to collect PVCs from cluster {cluster.name}: {e}")
                else:
                    continue
                break
            if pvc_count > 0:
                print(f"Collected {pvc_count} PVCs from {len(eks_clusters)} EKS clusters")

        # Cost collection (default, opt-out via --no-costs)
        cost_records = []
        if not getattr(args, 'no_costs', False):
            logger.info("Collecting AWS costs from Cost Explorer...")
            print("Collecting AWS costs from Cost Explorer...")
            start_date, end_date = get_last_full_month()
            for session, account_id, _account_name in account_sessions:
                try:
                    records = collect_aws_costs(
                        session, start_date, end_date, account_id,
                        group_by_account=getattr(args, 'org_costs', False)
                    )
                    cost_records.extend(records)
                except Exception as e:
                    logger.warning(f"Failed to collect costs for account {account_id}: {e}")

        # aggregate_sizing() must run over the FINAL batch resource list (after
        # PVCs are appended above), or its capacity totals ('summaries'/
        # 'total_capacity_gb' below) silently exclude PVC capacity while
        # 'resource_count'/'resources'/data_quality (computed from the same
        # batch_resources reference below) include it - an internal
        # inconsistency between the resource count and the capacity total next
        # to it in cca_aws_sum_*.json. This was previously computed too early
        # (before the PVC-collection block above), which caused exactly that.
        batch_summaries = aggregate_sizing(batch_resources)

        # Data quality: how many resources have no measured actual usage
        # (reported as 0.0, never a quota/allocated estimate) vs. how many
        # were confirmed. Computed over the final batch resource list (after
        # PVCs) so it reflects everything actually written below.
        data_quality = compute_data_quality_summary(batch_resources)
        if data_quality and data_quality['resource_types_with_gaps']:
            dq_report = format_data_quality_report(data_quality)
            logger.warning(dq_report)
            print(f"\n⚠ {dq_report}\n")

        # Collection completeness: how much of this batch is estimated missing
        # because a whole account failed outright (assume-role, auth, or any
        # other collection error), weighted by the average resource count of
        # accounts that did succeed - not just a raw failed-account count.
        # Always printed, even on a clean batch, so the operator sees this
        # every time rather than only when something's wrong.
        completeness = compute_collection_completeness(
            total_units=len(batch_accounts), failed_units=batch_failed_accounts,
            resources=batch_resources, unit_id_field='account_id', unit_label='account',
        )
        if completeness:
            completeness_report = format_completeness_report(completeness)
            if completeness['failed_units'] > 0:
                logger.warning(completeness_report)
            print(f"\n{completeness_report}\n")

        # Write outputs
        run_id = generate_run_id()
        timestamp = get_timestamp()
        batch_account_ids = [a.get('id') for a in batch_accounts if a.get('id')]
        batch_account_details = [account_status_map[a] for a in batch_account_ids if a in account_status_map]
        account_ids = [a['account_id'] for a in batch_collected] or batch_account_ids
        account_id_value = None
        if len(account_ids) == 1:
            account_id_value = account_ids[0]
        elif len(account_ids) > 1:
            account_id_value = account_ids

        output_data = {
            'run_id': run_id,
            'timestamp': timestamp,
            'provider': 'aws',
            'org_name': args.org_name if args.org_name else None,
            'organization': {
                'name': args.org_name if args.org_name else None,
                'id': org_info.get('organization_id'),
                'management_account_id': org_info.get('management_account_id'),
            },
            'run_scope': run_scope,
            'account_id': account_id_value,
            'accounts': batch_account_details if batch_account_details else None,
            'regions': regions if regions else 'all',
            'resource_count': len(batch_resources),
            'resources': [r.to_dict() for r in batch_resources],
        }

        summary_data = {
            'run_id': run_id,
            'timestamp': timestamp,
            'collector_metadata': get_collector_metadata(args, 'aws', __version__),
            'provider': 'aws',
            'org_name': args.org_name if args.org_name else None,
            'organization': {
                'name': args.org_name if args.org_name else None,
                'id': org_info.get('organization_id'),
                'management_account_id': org_info.get('management_account_id'),
            },
            'run_scope': run_scope,
            'account_id': account_id_value,
            'accounts': batch_account_details if batch_account_details else None,
            'total_resources': len(batch_resources),
            'total_capacity_gb': sum(s.total_gb for s in batch_summaries),
            'summaries': [s.to_dict() for s in batch_summaries],
            'change_rates': change_rate_data if change_rate_data else None,
            'data_quality': data_quality,
            'collection_completeness': completeness,
            'collection_progress': {
                'target_accounts': checkpoint.get('total_accounts', len(accounts_to_collect)),
                'completed_accounts': len(set(checkpoint.get('completed_accounts', []))),
                'failed_accounts': len(set(checkpoint.get('failed_accounts', []))),
                'failed_account_ids': sorted(set(checkpoint.get('failed_accounts', []))),
                'failed_account_reasons': {
                    account_id: checkpoint.get('failed_account_reasons', {}).get(account_id)
                    for account_id in sorted(set(checkpoint.get('failed_accounts', [])))
                },
            },
        }

        output_data = {k: v for k, v in output_data.items() if v is not None}
        summary_data = {k: v for k, v in summary_data.items() if v is not None}

        if not args.include_resource_ids:
            output_data = redact_sensitive_data(output_data)
            summary_data = redact_sensitive_data(summary_data)

        if batch_output.startswith('s3://'):
            batch_output = f"{batch_output}/{run_id}"

        file_ts = datetime.now(timezone.utc).strftime('%H%M%S')
        write_json(output_data, f"{batch_output}/cca_aws_inv_{file_ts}.json")
        write_json(summary_data, f"{batch_output}/cca_aws_sum_{file_ts}.json")

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

        if cost_records:
            cost_summaries = aggregate_costs(cost_records)
            cost_output = {
                'run_id': run_id,
                'timestamp': timestamp,
                'provider': 'aws',
                'account_id': account_ids[0] if len(account_ids) == 1 else account_ids,
                'period': {'start': start_date, 'end': end_date},
                'total_cost': round(sum(r.cost for r in cost_records), 2),
                'records': [r.to_dict() for r in cost_records],
                'summaries': [s.to_dict() for s in cost_summaries],
            }
            write_json(cost_output, f"{batch_output}/cca_aws_costs_{file_ts}.json")
            logger.info(f"Wrote {len(cost_records)} cost records")

        all_collected_accounts.extend(batch_collected)
        all_summaries.extend(batch_summaries)

        if len(batches) > 1:
            print(f"\nBatch {batch_num} complete: {len(batch_collected)} accounts, {len(batch_resources)} resources")
            print(f"Output: {batch_output}/")

        # Credential refresh between batches
        if batch_num < len(batches):
            if args.sso_refresh:
                print(f"\nRefreshing SSO credentials before batch {batch_num + 1}...")
                sso_cmd = ['aws', 'sso', 'login']
                if args.profile:
                    sso_cmd.extend(['--profile', args.profile])
                try:
                    subprocess.run(sso_cmd, check=True)
                    base_session = get_session(args.profile)
                except subprocess.CalledProcessError as e:
                    print(f"SSO login failed (exit code {e.returncode})")
                    print(f"You can resume with: --resume {checkpoint_file}")
                    sys.exit(1)
                except FileNotFoundError:
                    print("Error: 'aws' CLI not found.")
                    sys.exit(1)
            elif args.interactive:
                print(f"\nBATCH {batch_num}/{len(batches)} COMPLETE — refresh credentials if needed.")
                print(f"Progress saved to: {checkpoint_file}")
                input(f"\nPress ENTER to continue to batch {batch_num + 1}...")
                base_session = get_session(args.profile)
            elif args.pause_between_batches:
                print(f"\nPausing {args.pause_between_batches} seconds before next batch...")
                time.sleep(args.pause_between_batches)

    if args.batch_size:
        checkpoint['completed_at'] = get_timestamp()
        save_checkpoint(checkpoint_file, checkpoint)
        print(f"\nCheckpoint saved: {checkpoint_file}")
        if checkpoint['failed_accounts']:
            print(f"Failed accounts ({len(checkpoint['failed_accounts'])}): {', '.join(checkpoint['failed_accounts'])}")
            print(f"Re-run with: --accounts {','.join(checkpoint['failed_accounts'])}")

    if len(all_collected_accounts) > 1:
        print(f"\n{'='*60}\nCOLLECTION COMPLETE\n{'='*60}")
        print(f"Total accounts: {len(all_collected_accounts)}")
        for acc in all_collected_accounts:
            name_str = f" ({acc['account_name']})" if acc.get('account_name') else ""
            print(f"  - {acc['account_id']}{name_str}: {acc['resource_count']} resources")

    completed_ids = set(checkpoint.get('completed_accounts', []))
    failed_ids = set(checkpoint.get('failed_accounts', [])) - completed_ids
    target_accounts = checkpoint.get('total_accounts')
    if not target_accounts:
        # Fallback when total_accounts wasn't set (e.g., non-batched runs)
        combined = completed_ids | failed_ids
        target_accounts = len(combined) if combined else len(accounts_to_collect)

    success_pct = (len(completed_ids) / target_accounts * 100.0) if target_accounts else 0.0
    print(f"\nAccount collection success: {len(completed_ids)}/{target_accounts} ({success_pct:.1f}%)")
    if failed_ids:
        print(f"Failed accounts ({len(failed_ids)}): {', '.join(sorted(failed_ids))}")

    print(f"\nRun ID: {run_id}")
    print_summary_table([s.to_dict() for s in all_summaries])
    print(f"Output: {output_base}/")

    if len(batches) > 1:
        print(f"\nTo merge batches: python3 scripts/merge_batch_outputs.py {output_base}/")

        threshold = max(0.0, min(100.0, float(getattr(args, 'auto_merge_threshold', 90.0))))
        should_auto_merge = bool(completed_ids) and success_pct >= threshold

        # Auto-merge when success rate meets threshold (default 90%).
        if should_auto_merge:
            print("\nAuto-merging batch outputs...")
            try:
                from pathlib import Path as _Path
                _repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                _scripts_dir = os.path.join(_repo_root, 'scripts')
                if _scripts_dir not in sys.path:
                    sys.path.insert(0, _scripts_dir)
                from merge_batch_outputs import process_folder
                merge_result = process_folder(_Path(output_base), output_dir=_Path(output_base))
                if 'inventory' in merge_result:
                    inv_file = _Path(merge_result['inventory']['file']).name
                    print(f"\nMerged inventory: {output_base}/{inv_file}")
                    if 'summary' in merge_result:
                        sum_file = _Path(merge_result['summary']['file']).name
                        print(f"Merged summary:   {output_base}/{sum_file}")
                    if 'cost' in merge_result:
                        cost_file = _Path(merge_result['cost']['file']).name
                        print(f"Merged costs:     {output_base}/{cost_file}")
            except Exception as e:
                logger.warning(f"Auto-merge failed: {e}")
                print(f"  Auto-merge failed — run manually: python3 scripts/merge_batch_outputs.py {output_base}/")
        else:
            print(
                f"\nAuto-merge skipped: {success_pct:.1f}% below threshold {threshold:.1f}% "
                f"or no successful accounts collected."
            )

    if not all_collected_accounts and checkpoint.get('failed_accounts'):
        print(f"\nERROR: All {len(checkpoint['failed_accounts'])} account(s) failed to collect.")
        sys.exit(1)
