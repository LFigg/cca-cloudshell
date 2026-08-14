"""Azure collection orchestration.

Orchestrates multi-subscription Azure resource collection.
Called by collect.py after argument parsing.

Usage:
    from lib.azure.collector import collect_subscription, run_collection
    run_collection(args)
"""
import argparse
import logging
import sys
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

from lib.__version__ import __version__
from lib.azure.auth import get_credential, get_subscriptions
from lib.azure.backup import (
    collect_backup_policies,
    collect_backup_protected_items,
    collect_backup_recovery_points,
    collect_recovery_services_vaults,
)
from lib.azure.compute import collect_disk_snapshots, collect_disks, collect_vms
from lib.azure.container import collect_aks_clusters, collect_function_apps
from lib.azure.cost import collect_azure_costs
from lib.azure.databases import (
    collect_cosmosdb_accounts,
    collect_mariadb_servers,
    collect_mysql_servers,
    collect_postgresql_servers,
    collect_redis_caches,
    collect_sql_database_backups,
    collect_sql_managed_instances,
    collect_sql_servers,
    collect_synapse_workspaces,
)
from lib.azure.dependencies import check_azure_dependencies, format_dependency_report
from lib.azure.monitoring import collect_azure_change_rates
from lib.azure.permissions import format_permission_report, verify_azure_permissions
from lib.azure.storage import collect_file_shares, collect_netapp_files, collect_storage_accounts
from lib.change_rate import finalize_change_rate_output, merge_change_rates
from lib.collection_completeness import compute_collection_completeness, format_completeness_report
from lib.data_quality import compute_data_quality_summary, format_data_quality_report
from lib.k8s import collect_aks_pvcs
from lib.models import CloudResource, aggregate_sizing
from lib.utils import (
    AuthError,
    ProgressTracker,
    aggregate_costs,
    generate_run_id,
    get_collector_metadata,
    get_last_full_month,
    get_timestamp,
    is_azure_blob_url,
    log_arguments,
    parallel_collect,
    print_summary_table,
    redact_sensitive_data,
    setup_logging,
    write_json,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Subscription Collection
# =============================================================================

def collect_subscription(
    credential,
    subscription_id: str,
    subscription_name: str,
    tracker: Optional[ProgressTracker] = None,
    parallel_resources: int = 1,
    include_recovery_points: bool = False
) -> List[CloudResource]:
    """Collect all resources in a subscription.

    Args:
        credential: Azure credential
        subscription_id: Azure subscription ID
        subscription_name: Subscription display name
        tracker: Optional progress tracker
        parallel_resources: Number of resource types to collect in parallel
        include_recovery_points: Include individual recovery points (slow)

    Returns:
        List of CloudResource objects for every resource type collected
    """
    logger.info(f"Collecting resources from subscription: {subscription_name} ({subscription_id})")

    collection_tasks: List[Tuple[str, Callable, tuple]] = [
        ("VMs", collect_vms, (credential, subscription_id)),
        ("Disks", collect_disks, (credential, subscription_id)),
        ("Disk snapshots", collect_disk_snapshots, (credential, subscription_id)),
        ("Storage accounts", collect_storage_accounts, (credential, subscription_id)),
        ("File shares", collect_file_shares, (credential, subscription_id)),
        ("NetApp Files volumes", collect_netapp_files, (credential, subscription_id)),
        ("SQL servers", collect_sql_servers, (credential, subscription_id)),
        ("SQL managed instances", collect_sql_managed_instances, (credential, subscription_id)),
        ("SQL backups", collect_sql_database_backups, (credential, subscription_id)),
        ("CosmosDB accounts", collect_cosmosdb_accounts, (credential, subscription_id)),
        ("PostgreSQL servers", collect_postgresql_servers, (credential, subscription_id)),
        ("MySQL servers", collect_mysql_servers, (credential, subscription_id)),
        ("MariaDB servers", collect_mariadb_servers, (credential, subscription_id)),
        ("Synapse workspaces", collect_synapse_workspaces, (credential, subscription_id)),
        ("AKS clusters", collect_aks_clusters, (credential, subscription_id)),
        ("Function apps", collect_function_apps, (credential, subscription_id)),
        ("Redis caches", collect_redis_caches, (credential, subscription_id)),
        ("Recovery Services vaults", collect_recovery_services_vaults, (credential, subscription_id)),
        ("Backup policies", collect_backup_policies, (credential, subscription_id)),
        ("Backup protected items", collect_backup_protected_items, (credential, subscription_id)),
    ]

    if include_recovery_points:
        collection_tasks.append(
            ("Backup recovery points", collect_backup_recovery_points, (credential, subscription_id))
        )

    return parallel_collect(
        collection_tasks=collection_tasks,
        parallel_workers=parallel_resources,
        tracker=tracker,
        logger=logger
    )


# =============================================================================
# Argument Parser (for collect.py)
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    """Return the argparse parser for the Azure collector."""
    parser = argparse.ArgumentParser(description='CCA CloudShell - Azure Resource Collector')
    parser.add_argument('--subscription-id', '--subscription', dest='subscription_id',
                        help='Specific subscription ID (default: all accessible)')
    parser.add_argument('--exclude-subscriptions', dest='exclude_subscriptions',
                        help='Comma-separated subscription IDs to skip (default: none)')
    parser.add_argument('--regions',
                        help='Comma-separated list of regions to filter (e.g., eastus,westus2)')
    parser.add_argument('--output', help='Output directory or blob URL', default='.')
    parser.add_argument('--log-level', help='Logging level', default='INFO')
    parser.add_argument('--skip-change-rate', action='store_true',
                        help='Skip collecting change rates from Azure Monitor')
    parser.add_argument('--skip-pvc', action='store_true',
                        help='Skip PVC collection from AKS clusters')
    parser.add_argument('--change-rate-days', type=int, default=7,
                        help='Number of days to sample for change rate metrics (default: 7)')
    parser.add_argument('--parallel-resources', type=int, default=4,
                        help='Number of resource types to collect in parallel (default: 4)')
    parser.add_argument('--include-resource-ids', action='store_true',
                        help='Include full resource IDs in output (default: redact for privacy)')
    parser.add_argument('--include-recovery-points', action='store_true',
                        help='Include individual recovery points (slow for large backup environments)')
    parser.add_argument('--no-costs', action='store_true',
                        help='Skip data protection cost collection (costs are collected by default)')
    return parser


# =============================================================================
# Run Collection (called by collect.py)
# =============================================================================

def run_collection(args) -> None:
    """Run full Azure collection based on parsed CLI args.

    Args:
        args: argparse.Namespace with all Azure collection options.
    """
    log_dir = args.output if not args.output.startswith(('s3://', 'gs://', 'https://')) else None
    setup_logging(args.log_level, output_dir=log_dir)
    log_arguments(args, "Azure collector")

    # Mandatory preflight: verify every package requirements.in says the Azure
    # collector needs is actually importable, before touching credentials or
    # subscriptions. A missing package today doesn't stop the run - each
    # affected collector just logs a "not installed, skipping" warning and
    # keeps going - which means the same silent, partial-data failure mode
    # the permission preflight below exists to prevent (see
    # lib/azure/dependencies.py's docstring for a real example of this
    # happening). There is no flag to skip this - run `pip install -r
    # requirements.txt` (or `./setup.sh`) and re-run.
    missing_packages = check_azure_dependencies()
    if missing_packages:
        report = format_dependency_report(missing_packages)
        logger.error(f"Dependency check failed. Collection was not started.\n{report}")
        print(
            f"\n✗ Dependency check failed - collection was not started.\n{report}\n\n"
            "Install the missing package(s) above (`pip install -r requirements.txt` "
            "or `./setup.sh`), then re-run."
        )
        sys.exit(1)

    try:
        credential = get_credential()
    except Exception as e:
        logger.error(f"Failed to authenticate with Azure: {e}")
        sys.exit(1)

    try:
        all_subscriptions = get_subscriptions(credential)
    except Exception as e:
        logger.error(f"Failed to list Azure subscriptions: {e}")
        sys.exit(1)

    if not all_subscriptions:
        logger.error("No Azure subscriptions found. Check permissions.")
        sys.exit(1)

    if args.subscription_id:
        subscriptions = [s for s in all_subscriptions if s['id'] == args.subscription_id]
        if not subscriptions:
            logger.error(f"Subscription {args.subscription_id} not found")
            sys.exit(1)
    else:
        subscriptions = [s for s in all_subscriptions if s['state'] == 'Enabled']

    if args.exclude_subscriptions:
        excluded_ids = {s.strip() for s in args.exclude_subscriptions.split(',') if s.strip()}
        found_ids = {s['id'] for s in subscriptions}
        unmatched = excluded_ids - found_ids
        if unmatched:
            logger.warning(f"--exclude-subscriptions ID(s) not found among scanned subscriptions: {', '.join(sorted(unmatched))}")
        subscriptions = [s for s in subscriptions if s['id'] not in excluded_ids]
        if not subscriptions:
            logger.error("All subscriptions were excluded via --exclude-subscriptions. Nothing to collect.")
            sys.exit(1)

    logger.info(f"Found {len(subscriptions)} subscription(s) to scan")

    # Mandatory preflight: verify every permission this run's flags require -
    # across every subscription - before collecting anything. A gap found
    # midway through collection today means either an entire subscription's
    # already-collected resources get discarded (see collector.py's AuthError
    # handling below) or, worse, a resource type silently keeps degraded
    # placeholder data with no clear signal anything was wrong (e.g. Azure
    # Monitor capacity lookups leaving file shares at quota instead of usage).
    # There is no flag to skip this - if the collection needs a permission,
    # it must be verified up front so it can be fixed once, rather than
    # discovered partway through (or after) a run.
    logger.info("Verifying Azure permissions for this run's configuration...")
    print("Verifying Azure permissions before starting collection...")
    permission_results = verify_azure_permissions(
        credential, subscriptions, args, parallel_workers=args.parallel_resources
    )
    subs_missing_permissions = [r for r in permission_results if r.missing]
    if subs_missing_permissions:
        report = format_permission_report(permission_results)
        logger.error(
            f"Permission check failed for {len(subs_missing_permissions)}/{len(subscriptions)} "
            f"subscription(s). Collection was not started.\n{report}"
        )
        print(
            f"\n✗ Permission check failed for {len(subs_missing_permissions)}/{len(subscriptions)} "
            f"subscription(s) - collection was not started.\n{report}\n\n"
            "Grant the missing role assignment(s) above (or narrow this run with "
            "--subscription-id/--skip-change-rate/--skip-pvc/--no-costs as appropriate), "
            "then re-run."
        )
        sys.exit(1)

    subs_with_warnings = [r for r in permission_results if r.warnings and not r.missing]
    if subs_with_warnings:
        logger.warning(format_permission_report(permission_results))
    logger.info("Permission check passed for all subscriptions being collected")

    all_resources: List[CloudResource] = []
    subscription_info = []
    failed_subscriptions = []

    with ProgressTracker("Azure", total_accounts=len(subscriptions)) as tracker:
        for sub in subscriptions:
            try:
                tracker.start_account(sub['id'], sub['name'])
                subscription_info.append({
                    'subscription_id': sub['id'],
                    'subscription_name': sub['name']
                })
                all_resources.extend(collect_subscription(
                    credential, sub['id'], sub['name'], tracker,
                    parallel_resources=args.parallel_resources,
                    include_recovery_points=args.include_recovery_points
                ))
                tracker.complete_account()
            except AuthError as e:
                logger.error(f"Auth error for subscription {sub['id']}: {e}")
                failed_subscriptions.append({'id': sub['id'], 'name': sub['name'], 'error': str(e)})
                continue
            except Exception as e:
                logger.error(f"Failed to collect from subscription {sub['id']}: {e}")
                failed_subscriptions.append({'id': sub['id'], 'name': sub['name'], 'error': str(e)})
                continue

    if failed_subscriptions:
        logger.warning(f"Collection failed for {len(failed_subscriptions)} subscription(s)")

    if args.regions:
        from lib.azure.helpers import normalize_region
        region_filter = {normalize_region(r) for r in args.regions.split(',')}
        original_count = len(all_resources)
        all_resources = [r for r in all_resources if r.region and r.region in region_filter]
        logger.info(f"Filtered to {len(all_resources)} resources in regions: {', '.join(sorted(region_filter))} (from {original_count})")

    # Change rates
    change_rate_data = None
    successful_sub_ids = {s['subscription_id'] for s in subscription_info}
    if not args.skip_change_rate:
        logger.info("Collecting change rate metrics from Azure Monitor...")
        print("Collecting change rate metrics and storage capacities from Azure Monitor...")
        all_change_rates: Dict = {}
        for sub in subscriptions:
            if sub['id'] not in successful_sub_ids:
                continue
            try:
                sub_resources = [r for r in all_resources if r.subscription_id == sub['id']]
                cr_data = collect_azure_change_rates(credential, sub['id'], sub_resources, args.change_rate_days)
                merge_change_rates(all_change_rates, cr_data)
            except Exception as e:
                logger.warning(f"Failed to collect change rates for subscription {sub['id']}: {e}")
        if all_change_rates:
            change_rate_data = finalize_change_rate_output(
                all_change_rates, args.change_rate_days, "Azure Monitor"
            )
        else:
            # azure-mgmt-monitor is installed and reachable by this point (a missing
            # package is caught earlier, per-subscription, with its own explicit
            # warning) - an empty result here means Monitor was queried but returned
            # no usable metric data for any resource, e.g. a missing "Monitoring
            # Reader" role grant or metric/dimension errors on every call. Every
            # failed call already logged its real error at WARNING as it happened
            # (see collect_azure_change_rates' per-resource-kind rollup above,
            # logged at WARNING/ERROR - no need to re-run at a higher verbosity).
            logger.warning(
                "No change rate data collected from Azure Monitor for any subscription. "
                "Storage account and SQL database size_gb could not be measured for any "
                "resource this run and report 0.0 (never a quota/max-size estimate - see "
                "the data quality summary below for exactly which resources). See the "
                "'Azure Monitor capacity lookup' warnings/errors above for the actual "
                "per-resource-kind failure reason, or check the collector's Monitor "
                "Reader (or Reader) role assignment."
            )
            print(
                "⚠ No change rate data collected from Azure Monitor. Storage account/SQL "
                "database sizes could not be measured this run (reported as 0 GB, not an "
                "estimate) - see the log for the actual Monitor error."
            )

    summaries = aggregate_sizing(all_resources)

    # PVCs from AKS
    aks_clusters = [r for r in all_resources if r.resource_type == 'azure:aks:cluster']
    if aks_clusters and not args.skip_pvc:
        logger.info("Collecting PVCs from AKS clusters...")
        print("Collecting PVCs from AKS clusters...")
        pvc_count = 0
        k8s_available = True
        for cluster in aks_clusters:
            if not k8s_available:
                break
            try:
                resource_group = cluster.metadata.get('resource_group', '')
                if not resource_group:
                    parts = cluster.resource_id.split('/')
                    rg_idx = parts.index('resourceGroups') if 'resourceGroups' in parts else -1
                    resource_group = parts[rg_idx + 1] if rg_idx >= 0 else ''
                cluster_pvcs = collect_aks_pvcs(
                    credential, cluster.subscription_id, resource_group, cluster.name, cluster.region
                )
                all_resources.extend(cluster_pvcs)
                pvc_count += len(cluster_pvcs)
            except ImportError:
                logger.info("kubernetes package not installed - skipping PVC collection")
                print("Note: Install 'kubernetes' package for PVC collection: pip install kubernetes")
                k8s_available = False
            except Exception as e:
                logger.warning(f"Failed to collect PVCs from AKS cluster {cluster.name}: {e}")
        if pvc_count > 0:
            print(f"Collected {pvc_count} PVCs from {len(aks_clusters)} AKS clusters")

    # Cost collection (default, opt-out via --no-costs)
    cost_records = []
    if not getattr(args, 'no_costs', False):
        logger.info("Collecting Azure costs from Cost Management...")
        print("Collecting Azure costs from Cost Management...")
        start_date, end_date = get_last_full_month()
        for sub in subscription_info:
            try:
                records = collect_azure_costs(
                    credential, sub['subscription_id'], start_date, end_date
                )
                cost_records.extend(records)
            except Exception as e:
                logger.warning(f"Failed to collect costs for subscription {sub['subscription_id']}: {e}")

    # Data quality: how many resources have no measured actual usage (reported
    # as 0.0, never a quota/allocated estimate) vs. how many were confirmed.
    # Computed over the final resource list (after PVCs) so it reflects
    # everything actually written below.
    data_quality = compute_data_quality_summary(all_resources)
    if data_quality and data_quality['resource_types_with_gaps']:
        report = format_data_quality_report(data_quality)
        logger.warning(report)
        print(f"\n⚠ {report}\n")

    # Collection completeness: how much of this run is estimated missing
    # because a whole subscription failed outright, weighted by the average
    # resource count of subscriptions that did succeed - not just a raw
    # failed-subscription count. Always printed, even on a clean run, so the
    # operator sees this every time rather than only when something's wrong.
    completeness = compute_collection_completeness(
        total_units=len(subscriptions), failed_units=failed_subscriptions,
        resources=all_resources, unit_id_field='subscription_id', unit_label='subscription',
    )
    if completeness:
        report = format_completeness_report(completeness)
        if completeness['failed_units'] > 0:
            logger.warning(report)
        print(f"\n{report}\n")

    # Prepare output
    run_id = generate_run_id()
    timestamp = get_timestamp()
    subscription_ids = [s['subscription_id'] for s in subscription_info]

    output_data = {
        'run_id': run_id,
        'timestamp': timestamp,
        'provider': 'azure',
        'subscription_id': subscription_ids,
        'subscriptions': subscription_info,
        'resource_count': len(all_resources),
        'resources': [r.to_dict() for r in all_resources],
    }

    summary_data = {
        'run_id': run_id,
        'timestamp': timestamp,
        'collector_metadata': get_collector_metadata(args, 'azure', __version__),
        'provider': 'azure',
        'subscription_id': subscription_ids,
        'subscriptions': subscription_info,
        'total_resources': len(all_resources),
        'total_capacity_gb': sum(s.total_gb for s in summaries),
        'summaries': [s.to_dict() for s in summaries],
        'change_rates': change_rate_data if change_rate_data else None,
        'data_quality': data_quality,
        'collection_completeness': completeness,
    }
    summary_data = {k: v for k, v in summary_data.items() if v is not None}

    if not args.include_resource_ids:
        output_data = redact_sensitive_data(output_data)
        summary_data = redact_sensitive_data(summary_data)

    output_base = args.output.rstrip('/')
    if is_azure_blob_url(output_base):
        output_base = f"{output_base}/{run_id}"

    file_ts = datetime.now(timezone.utc).strftime('%H%M%S')
    write_json(output_data, f"{output_base}/cca_azure_inv_{file_ts}.json")
    write_json(summary_data, f"{output_base}/cca_azure_sum_{file_ts}.json")

    if change_rate_data:
        change_rate_output = {
            'run_id': run_id,
            'timestamp': timestamp,
            'provider': 'azure',
            'subscription_id': subscription_ids,
            'subscriptions': subscription_info,
            **change_rate_data
        }
        if not args.include_resource_ids:
            change_rate_output = redact_sensitive_data(change_rate_output)
        write_json(change_rate_output, f"{output_base}/cca_azure_change_rates_{file_ts}.json")

    if cost_records:
        cost_summaries = aggregate_costs(cost_records)
        cost_output = {
            'run_id': run_id,
            'timestamp': timestamp,
            'provider': 'azure',
            'subscription_id': subscription_ids,
            'period': {'start': start_date, 'end': end_date},
            'total_cost': round(sum(r.cost for r in cost_records), 2),
            'records': [r.to_dict() for r in cost_records],
            'summaries': [s.to_dict() for s in cost_summaries],
        }
        write_json(cost_output, f"{output_base}/cca_azure_costs_{file_ts}.json")

    print(f"\nRun ID: {run_id}")
    print_summary_table([s.to_dict() for s in summaries])
    print(f"Output: {output_base}/")
