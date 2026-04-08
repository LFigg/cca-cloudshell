#!/usr/bin/env python3
"""
CCA CloudShell - Azure Resource Collector

Collects Azure resources for cloud protection assessment.
Optimized for Azure Cloud Shell with minimal dependencies.

Usage:
    python3 azure_collect.py
    python3 azure_collect.py --subscription-id <subscription-id>
    python3 azure_collect.py --output https://mystorageaccount.blob.core.windows.net/assessments/
"""
import argparse
import logging
import sys
from datetime import datetime, timezone
from typing import Callable, List, Optional, Tuple

# Add lib to path for imports
sys.path.insert(0, '.')

from lib.__version__ import __version__
from lib.change_rate import finalize_change_rate_output, merge_change_rates
from lib.k8s import collect_aks_pvcs
from lib.models import CloudResource, aggregate_sizing
from lib.utils import (
    AuthError,
    ProgressTracker,
    generate_run_id,
    get_collector_metadata,
    get_timestamp,
    log_arguments,
    parallel_collect,
    print_summary_table,
    redact_sensitive_data,
    setup_logging,
    write_json,
)

# Import from lib/azure modules
from lib.azure.auth import get_credential, get_subscriptions
from lib.azure.compute import collect_disks, collect_disk_snapshots, collect_vms
from lib.azure.storage import collect_file_shares, collect_netapp_files, collect_storage_accounts
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
from lib.azure.container import collect_aks_clusters, collect_function_apps
from lib.azure.backup import (
    collect_backup_policies,
    collect_backup_protected_items,
    collect_backup_recovery_points,
    collect_recovery_services_vaults,
)
from lib.azure.monitoring import collect_azure_change_rates

logger = logging.getLogger(__name__)


# =============================================================================
# Main Collection Logic
# =============================================================================

def collect_subscription(
    credential,
    subscription_id: str,
    subscription_name: str,
    tracker: Optional[ProgressTracker] = None,
    parallel_resources: int = 1,
    include_recovery_points: bool = False
) -> List[CloudResource]:
    """
    Collect all resources in a subscription.

    Args:
        credential: Azure credential
        subscription_id: Azure subscription ID
        subscription_name: Subscription display name
        tracker: Optional progress tracker
        parallel_resources: Number of resource types to collect in parallel (default: 1)
        include_recovery_points: Include individual recovery points (default: False, slow for large envs)
    """
    logger.info(f"Collecting resources from subscription: {subscription_name} ({subscription_id})")

    # Define all collection tasks as (name, function, args) tuples
    collection_tasks: List[Tuple[str, Callable, tuple]] = [
        # Compute
        ("VMs", collect_vms, (credential, subscription_id)),
        ("Disks", collect_disks, (credential, subscription_id)),
        ("Disk snapshots", collect_disk_snapshots, (credential, subscription_id)),
        # Storage
        ("Storage accounts", collect_storage_accounts, (credential, subscription_id)),
        ("File shares", collect_file_shares, (credential, subscription_id)),
        ("NetApp Files volumes", collect_netapp_files, (credential, subscription_id)),
        # Databases
        ("SQL servers", collect_sql_servers, (credential, subscription_id)),
        ("SQL managed instances", collect_sql_managed_instances, (credential, subscription_id)),
        ("SQL backups", collect_sql_database_backups, (credential, subscription_id)),
        ("CosmosDB accounts", collect_cosmosdb_accounts, (credential, subscription_id)),
        ("PostgreSQL servers", collect_postgresql_servers, (credential, subscription_id)),
        ("MySQL servers", collect_mysql_servers, (credential, subscription_id)),
        ("MariaDB servers", collect_mariadb_servers, (credential, subscription_id)),
        # Analytics
        ("Synapse workspaces", collect_synapse_workspaces, (credential, subscription_id)),
        # Containers & Compute
        ("AKS clusters", collect_aks_clusters, (credential, subscription_id)),
        ("Function apps", collect_function_apps, (credential, subscription_id)),
        # Cache
        ("Redis caches", collect_redis_caches, (credential, subscription_id)),
        # Azure Backup (Recovery Services)
        ("Recovery Services vaults", collect_recovery_services_vaults, (credential, subscription_id)),
        ("Backup policies", collect_backup_policies, (credential, subscription_id)),
        ("Backup protected items", collect_backup_protected_items, (credential, subscription_id)),
    ]

    # Recovery points are SLOW (triple-nested API calls) - only include if explicitly requested
    if include_recovery_points:
        collection_tasks.append(
            ("Backup recovery points", collect_backup_recovery_points, (credential, subscription_id))
        )

    resources = parallel_collect(
        collection_tasks=collection_tasks,
        parallel_workers=parallel_resources,
        tracker=tracker,
        logger=logger
    )

    return resources


def main():
    parser = argparse.ArgumentParser(description='CCA CloudShell - Azure Resource Collector')
    parser.add_argument('--subscription-id', '--subscription', dest='subscription_id',
                        help='Specific subscription ID (default: all accessible)')
    parser.add_argument('--regions', help='Comma-separated list of regions to filter (e.g., eastus,westus2)')
    parser.add_argument('--output', help='Output directory or blob URL', default='.')
    parser.add_argument('--log-level', help='Logging level', default='INFO')
    parser.add_argument(
        '--skip-change-rate',
        action='store_true',
        help='Skip collecting change rates and storage account capacity from Azure Monitor'
    )
    parser.add_argument(
        '--skip-pvc',
        action='store_true',
        help='Skip PVC collection from AKS clusters (PVCs are collected by default when clusters are found)'
    )
    parser.add_argument(
        '--change-rate-days',
        type=int,
        default=7,
        help='Number of days to sample for change rate metrics (default: 7)'
    )
    parser.add_argument(
        '--parallel-resources',
        type=int,
        default=4,
        help='Number of resource types to collect in parallel (default: 4, use 1 for serial)'
    )
    parser.add_argument(
        '--include-resource-ids',
        action='store_true',
        help='Include full resource IDs in output (default: redact for privacy)'
    )
    parser.add_argument(
        '--include-recovery-points',
        action='store_true',
        help='Include individual recovery points (slow for large backup environments, default: skip)'
    )

    args = parser.parse_args()

    # Setup logging - write to file if output is local directory
    log_dir = args.output if not args.output.startswith(('s3://', 'gs://', 'https://')) else None
    setup_logging(args.log_level, output_dir=log_dir)
    log_arguments(args, "Azure collector")

    # Get credential
    try:
        credential = get_credential()
    except Exception as e:
        logger.error(f"Failed to authenticate with Azure: {e}")
        logger.error("Check your Azure credentials are configured correctly.")
        sys.exit(1)

    # Get subscriptions
    try:
        all_subscriptions = get_subscriptions(credential)
    except Exception as e:
        logger.error(f"Failed to list Azure subscriptions: {e}")
        logger.error("Check your credentials have subscription read access.")
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

    logger.info(f"Found {len(subscriptions)} subscription(s) to scan")

    # Collect resources
    all_resources = []
    subscription_info = []  # List of {subscription_id, subscription_name}
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
                logger.error(f"Authentication/authorization error for subscription {sub['id']} ({sub['name']}): {e}")
                logger.error("Check that you have correct permissions for this subscription.")
                failed_subscriptions.append({'id': sub['id'], 'name': sub['name'], 'error': str(e)})
                continue
            except Exception as e:
                logger.error(f"Failed to collect from subscription {sub['id']} ({sub['name']}): {e}")
                failed_subscriptions.append({'id': sub['id'], 'name': sub['name'], 'error': str(e)})
                continue

    if failed_subscriptions:
        logger.warning(f"Collection failed for {len(failed_subscriptions)} subscription(s)")

    # Filter by regions if specified
    if args.regions:
        region_filter = {r.strip().lower() for r in args.regions.split(',')}
        original_count = len(all_resources)
        all_resources = [r for r in all_resources if r.region and r.region.lower() in region_filter]
        logger.info(f"Filtered to {len(all_resources)} resources in regions: {', '.join(sorted(region_filter))} (from {original_count} total)")

    # Collect change rates by default (do this BEFORE aggregate_sizing so storage capacities are included)
    change_rate_data = None
    successful_sub_ids = {s['subscription_id'] for s in subscription_info}
    if not args.skip_change_rate:
        logger.info("Collecting change rate metrics and storage capacities from Azure Monitor...")
        print("Collecting change rate metrics and storage capacities from Azure Monitor...")
        all_change_rates = {}
        for sub in subscriptions:
            if sub['id'] not in successful_sub_ids:
                continue  # Skip failed subscriptions
            try:
                # Filter resources for this subscription
                sub_resources = [r for r in all_resources if r.subscription_id == sub['id']]
                cr_data = collect_azure_change_rates(credential, sub['id'], sub_resources, args.change_rate_days)
                merge_change_rates(all_change_rates, cr_data)
            except Exception as e:
                logger.warning(f"Failed to collect change rates for subscription {sub['id']}: {e}")

        if all_change_rates:
            change_rate_data = finalize_change_rate_output(
                all_change_rates, args.change_rate_days, "Azure Monitor"
            )
            logger.info(f"Collected change rates for {len(all_change_rates)} service families")
        else:
            logger.warning("No change rate data collected. Check if azure-mgmt-monitor is installed.")
            print("⚠ No change rate data collected. Run: pip install azure-mgmt-monitor")

    # Generate summaries (after change rate collection so storage capacities are included)
    summaries = aggregate_sizing(all_resources)

    # Collect PVCs from AKS clusters (automatic when clusters are discovered)
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
                    # Extract from resource ID
                    parts = cluster.resource_id.split('/')
                    rg_idx = parts.index('resourceGroups') if 'resourceGroups' in parts else -1
                    resource_group = parts[rg_idx + 1] if rg_idx >= 0 else ''

                cluster_pvcs = collect_aks_pvcs(
                    credential,
                    cluster.subscription_id,
                    resource_group,
                    cluster.name,
                    cluster.region
                )
                all_resources.extend(cluster_pvcs)
                pvc_count += len(cluster_pvcs)
                if cluster_pvcs:
                    logger.info(f"Found {len(cluster_pvcs)} PVCs in AKS cluster {cluster.name}")
            except ImportError:
                logger.info("kubernetes package not installed - skipping PVC collection (pip install kubernetes)")
                print("Note: Install 'kubernetes' package for PVC collection: pip install kubernetes")
                k8s_available = False
            except Exception as e:
                logger.warning(f"Failed to collect PVCs from AKS cluster {cluster.name}: {e}")

        if pvc_count > 0:
            print(f"Collected {pvc_count} PVCs from {len(aks_clusters)} AKS clusters")
    elif aks_clusters and args.skip_pvc:
        logger.info("Skipping PVC collection (--skip-pvc specified)")

    # Prepare output
    run_id = generate_run_id()
    timestamp = get_timestamp()
    subscription_ids = [s['subscription_id'] for s in subscription_info]

    output_data = {
        'run_id': run_id,
        'timestamp': timestamp,
        'provider': 'azure',
        'subscription_id': subscription_ids,  # List of IDs for backward compatibility
        'subscriptions': subscription_info,   # List of {subscription_id, subscription_name}
        'resource_count': len(all_resources),
        'resources': [r.to_dict() for r in all_resources]
    }

    summary_data = {
        'run_id': run_id,
        'timestamp': timestamp,
        'collector_metadata': get_collector_metadata(args, 'azure', __version__),
        'provider': 'azure',
        'subscription_id': subscription_ids,  # List of IDs for backward compatibility
        'subscriptions': subscription_info,   # List of {subscription_id, subscription_name}
        'total_resources': len(all_resources),
        'total_capacity_gb': sum(s.total_gb for s in summaries),
        'summaries': [s.to_dict() for s in summaries],
        'change_rates': change_rate_data if change_rate_data else None
    }

    # Remove None values
    summary_data = {k: v for k, v in summary_data.items() if v is not None}

    # Redact sensitive IDs unless --include-resource-ids is specified
    if not args.include_resource_ids:
        output_data = redact_sensitive_data(output_data)
        summary_data = redact_sensitive_data(summary_data)

    # Write outputs
    output_base = args.output.rstrip('/')

    if output_base.startswith('https://') and '.blob.core.windows.net' in output_base:
        output_base = f"{output_base}/{run_id}"

    # Short timestamp for filenames (HHMMSS)
    file_ts = datetime.now(timezone.utc).strftime('%H%M%S')
    write_json(output_data, f"{output_base}/cca_azure_inv_{file_ts}.json")
    write_json(summary_data, f"{output_base}/cca_azure_sum_{file_ts}.json")

    # Write change rate data to separate file if collected
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

    # Print detailed results (ProgressTracker already showed collection summary)
    print(f"\nRun ID: {run_id}")
    print_summary_table([s.to_dict() for s in summaries])
    print(f"Output: {output_base}/")


if __name__ == '__main__':
    main()
