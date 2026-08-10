"""GCP collection orchestration.

Orchestrates multi-project GCP resource collection.
Called by collect.py after argument parsing.

Usage:
    from lib.gcp.collector import collect_project, run_collection
    run_collection(args)
"""
import argparse
import logging
import os
import sys
from typing import Callable, Dict, List, Optional, Tuple

try:
    import google.auth  # noqa: F401
    from google.api_core.exceptions import NotFound, PermissionDenied  # noqa: F401
    from google.cloud import compute_v1, storage  # noqa: F401
    from googleapiclient.discovery import build as discovery_build  # noqa: F401
    HAS_GCP_SDK = True
except ImportError:
    HAS_GCP_SDK = False

from lib.__version__ import __version__
from lib.change_rate import finalize_change_rate_output, merge_change_rates
from lib.collection_completeness import compute_collection_completeness, format_completeness_report
from lib.data_quality import compute_data_quality_summary, format_data_quality_report
from lib.gcp.dependencies import check_gcp_dependencies, format_dependency_report
from lib.k8s import collect_gke_pvcs
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
    parallel_collect,
    print_summary_table,
    redact_sensitive_data,
    setup_logging,
    write_json,
)

if HAS_GCP_SDK:
    from lib.gcp.auth import get_credentials, get_projects
    from lib.gcp.backup import (
        collect_backup_data_sources,
        collect_backup_plans,
        collect_backup_vaults,
        collect_backups,
    )
    from lib.gcp.compute import (
        collect_compute_instances,
        collect_disk_snapshots,
        collect_persistent_disks,
    )
    from lib.gcp.container import collect_cloud_functions, collect_gke_clusters
    from lib.gcp.cost import collect_gcp_costs
    from lib.gcp.databases import (
        collect_alloydb_clusters,
        collect_bigquery_datasets,
        collect_bigtable_instances,
        collect_cloud_sql_instances,
        collect_memorystore_redis,
        collect_spanner_instances,
    )
    from lib.gcp.monitoring import collect_gcp_change_rates
    from lib.gcp.permissions import format_permission_report, verify_gcp_permissions
    from lib.gcp.storage import collect_filestore_instances, collect_storage_buckets

logger = logging.getLogger(__name__)


# =============================================================================
# Project Collection
# =============================================================================

def collect_project(
    project_id: str,
    tracker: Optional[ProgressTracker] = None,
    parallel_resources: int = 1
) -> List[CloudResource]:
    """Collect all resources for a GCP project.

    Args:
        project_id: GCP project ID
        tracker: Optional progress tracker
        parallel_resources: Number of resource types to collect in parallel

    Returns:
        List of CloudResource objects collected across every resource type
        (compute, storage, databases, containers, backup, etc.) for this
        project.
    """
    logger.info(f"Collecting resources for project: {project_id}")

    collection_tasks: List[Tuple[str, Callable, tuple]] = [
        ("Compute instances", collect_compute_instances, (project_id,)),
        ("Persistent disks", collect_persistent_disks, (project_id,)),
        ("Disk snapshots", collect_disk_snapshots, (project_id,)),
        ("Cloud Storage buckets", collect_storage_buckets, (project_id,)),
        ("Filestore instances", collect_filestore_instances, (project_id,)),
        ("Cloud SQL instances", collect_cloud_sql_instances, (project_id,)),
        ("Memorystore Redis", collect_memorystore_redis, (project_id,)),
        ("Cloud Spanner instances", collect_spanner_instances, (project_id,)),
        ("AlloyDB clusters", collect_alloydb_clusters, (project_id,)),
        ("BigQuery datasets", collect_bigquery_datasets, (project_id,)),
        ("Bigtable instances", collect_bigtable_instances, (project_id,)),
        ("GKE clusters", collect_gke_clusters, (project_id,)),
        ("Cloud Functions", collect_cloud_functions, (project_id,)),
        ("Backup plans", collect_backup_plans, (project_id,)),
        ("Backup vaults", collect_backup_vaults, (project_id,)),
        ("Backup data sources", collect_backup_data_sources, (project_id,)),
        ("Backups", collect_backups, (project_id,)),
    ]

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
    """Return the argparse parser for the GCP collector."""
    parser = argparse.ArgumentParser(description='CCA CloudShell - GCP Resource Collector')
    parser.add_argument('--project', help='GCP project ID (default: current project)')
    parser.add_argument('--all-projects', action='store_true',
                        help='Collect from all accessible projects')
    parser.add_argument('--regions',
                        help='Comma-separated list of regions to filter (e.g., us-central1,us-east1)')
    parser.add_argument('--output', help='Output directory or GCS path', default='.')
    parser.add_argument('--log-level', help='Logging level', default='INFO')
    parser.add_argument('--skip-change-rate', action='store_true',
                        help='Skip collecting change rates from Cloud Monitoring')
    parser.add_argument('--skip-pvc', action='store_true',
                        help='Skip PVC collection from GKE clusters')
    parser.add_argument('--change-rate-days', type=int, default=7,
                        help='Number of days to sample for change rate metrics (default: 7)')
    parser.add_argument('--parallel-resources', type=int, default=4,
                        help='Number of resource types to collect in parallel (default: 4)')
    parser.add_argument('--include-resource-ids', action='store_true',
                        help='Include full resource IDs in output (default: redact for privacy)')
    parser.add_argument('--billing-table',
                        help='BigQuery billing export table (e.g., project.dataset.table) for cost collection')
    parser.add_argument('--no-costs', action='store_true',
                        help='Skip data protection cost collection (costs are collected by default)')
    return parser


# =============================================================================
# Run Collection (called by collect.py)
# =============================================================================

def run_collection(args) -> None:
    """Run full GCP collection based on parsed CLI args.

    Args:
        args: argparse.Namespace with all GCP collection options.
    """
    log_dir = args.output if not args.output.startswith(('s3://', 'gs://', 'https://')) else None
    setup_logging(args.log_level, output_dir=log_dir)
    log_arguments(args, "GCP collector")

    if not HAS_GCP_SDK:
        logger.error("Google Cloud SDK not installed. Run: pip install google-cloud-compute google-cloud-storage")
        sys.exit(1)

    # Mandatory preflight: verify every package requirements.in says the GCP
    # collector needs is actually importable, before touching credentials or
    # projects. A missing package today doesn't stop the run - each affected
    # collector (backup.py, container.py, databases.py, storage.py's
    # Filestore support, monitoring.py) just logs a "not installed, skipping"
    # warning and keeps going, the same silent partial-data failure mode the
    # permission preflight below exists to prevent (see
    # lib/gcp/dependencies.py's docstring). There is no flag to skip this -
    # run `pip install -r requirements.txt` and re-run.
    missing_packages = check_gcp_dependencies()
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
        credentials, default_project = get_credentials()

        if args.all_projects:
            projects = get_projects(credentials)
        elif args.project:
            projects = [{'id': args.project, 'name': args.project}]
        elif default_project:
            projects = [{'id': default_project, 'name': default_project}]
        else:
            logger.error("No project specified and no default project found")
            sys.exit(1)

        project_ids = [p['id'] for p in projects]
        logger.info(f"Collecting from {len(project_ids)} project(s)")

        # Mandatory preflight: verify every permission this run's flags require -
        # across every project - before collecting anything. A gap found midway
        # through collection today just drops that project's resources into
        # failed_projects with no chance to fix and re-run cheaply. There is no
        # flag to skip this - if the collection needs a permission, it must be
        # verified up front, once, rather than discovered partway through a run.
        logger.info("Verifying GCP permissions for this run's configuration...")
        print("Verifying GCP permissions before starting collection...")
        permission_results = verify_gcp_permissions(projects, args, parallel_workers=args.parallel_resources)
        projects_missing_permissions = [r for r in permission_results if r.missing]
        if projects_missing_permissions:
            report = format_permission_report(permission_results)
            logger.error(
                f"Permission check failed for {len(projects_missing_permissions)}/{len(project_ids)} "
                f"project(s). Collection was not started.\n{report}"
            )
            print(
                f"\n✗ Permission check failed for {len(projects_missing_permissions)}/{len(project_ids)} "
                f"project(s) - collection was not started.\n{report}\n\n"
                "Grant the missing permission(s) above (or narrow this run with "
                "--project/--skip-change-rate/--skip-pvc/--no-costs as appropriate), then re-run."
            )
            sys.exit(1)

        projects_with_warnings = [r for r in permission_results if r.warnings and not r.missing]
        if projects_with_warnings:
            logger.warning(format_permission_report(permission_results))
        logger.info("Permission check passed for all projects being collected")

        all_resources: List[CloudResource] = []
        failed_projects = []
        successful_projects = []

        with ProgressTracker("GCP", total_accounts=len(project_ids)) as tracker:
            for proj in projects:
                project_id = proj['id']
                project_name = proj.get('name', project_id)
                try:
                    tracker.start_account(project_id, project_name)
                    resources = collect_project(project_id, tracker, parallel_resources=args.parallel_resources)
                    all_resources.extend(resources)
                    successful_projects.append({'project_id': project_id, 'project_name': project_name})
                    tracker.complete_account()
                except AuthError as e:
                    logger.error(f"Auth error for project {project_id}: {e}")
                    failed_projects.append({'project_id': project_id, 'error': str(e)})
                    continue
                except Exception as e:
                    logger.error(f"Failed to collect from project {project_id}: {e}")
                    failed_projects.append({'project_id': project_id, 'error': str(e)})
                    continue

        if failed_projects:
            logger.warning(f"Collection failed for {len(failed_projects)} project(s)")

        if args.regions:
            region_filter = {r.strip().lower() for r in args.regions.split(',')}
            original_count = len(all_resources)
            all_resources = [r for r in all_resources if r.region and r.region.lower() in region_filter]
            logger.info(f"Filtered to {len(all_resources)} resources in regions (from {original_count})")

        run_id = generate_run_id()
        timestamp = get_timestamp()
        sizing = aggregate_sizing(all_resources)

        # Change rates
        change_rate_data = None
        successful_project_ids = [p['project_id'] for p in successful_projects]
        if not args.skip_change_rate:
            logger.info("Collecting change rate metrics from Cloud Monitoring...")
            print("Collecting change rate metrics from Cloud Monitoring...")
            all_change_rates: Dict = {}
            for project_id in successful_project_ids:
                try:
                    proj_resources = [
                        r for r in all_resources
                        if r.metadata.get('project_id') == project_id
                        or r.resource_id.startswith(f"projects/{project_id}")
                    ]
                    cr_data = collect_gcp_change_rates(project_id, proj_resources, args.change_rate_days)
                    merge_change_rates(all_change_rates, cr_data)
                except Exception as e:
                    logger.warning(f"Failed to collect change rates for project {project_id}: {e}")
            if all_change_rates:
                change_rate_data = finalize_change_rate_output(
                    all_change_rates, args.change_rate_days, "Cloud Monitoring"
                )
            else:
                logger.warning("No change rate data collected.")
                print("⚠ No change rate data collected. Run: pip install google-cloud-monitoring")

        # PVCs from GKE
        gke_clusters = [r for r in all_resources if r.resource_type == 'gcp:container:cluster']
        if gke_clusters and not args.skip_pvc:
            logger.info("Collecting PVCs from GKE clusters...")
            print("Collecting PVCs from GKE clusters...")
            pvc_count = 0
            k8s_available = True
            for cluster in gke_clusters:
                if not k8s_available:
                    break
                try:
                    parts = cluster.resource_id.split('/')
                    project_id = parts[1] if len(parts) > 1 else cluster.account_id
                    cluster_pvcs = collect_gke_pvcs(project_id, cluster.region, cluster.name)
                    all_resources.extend(cluster_pvcs)
                    pvc_count += len(cluster_pvcs)
                except ImportError:
                    logger.info("kubernetes package not installed - skipping PVC collection")
                    print("Note: Install 'kubernetes' package for PVC collection: pip install kubernetes")
                    k8s_available = False
                except Exception as e:
                    logger.warning(f"Failed to collect PVCs from GKE cluster {cluster.name}: {e}")
            if pvc_count > 0:
                print(f"Collected {pvc_count} PVCs from {len(gke_clusters)} GKE clusters")

        # Cost collection (default, opt-out via --no-costs)
        cost_records = []
        start_date, end_date = get_last_full_month()
        if not getattr(args, 'no_costs', False) and getattr(args, 'billing_table', None):
            logger.info("Collecting GCP costs from BigQuery billing...")
            print("Collecting GCP costs from BigQuery billing...")
            for project_id in successful_project_ids:
                try:
                    records = collect_gcp_costs(project_id, args.billing_table, start_date, end_date)
                    cost_records.extend(records)
                except Exception as e:
                    logger.warning(f"Failed to collect costs for project {project_id}: {e}")
        elif not getattr(args, 'no_costs', False):
            logger.info("Skipping GCP cost collection: --billing-table not provided")

        # Data quality: how many resources have no measured actual usage
        # (reported as 0.0, never a quota/allocated estimate) vs. how many
        # were confirmed. Computed over the final resource list (after PVCs)
        # so it reflects everything actually written below.
        data_quality = compute_data_quality_summary(all_resources)
        if data_quality and data_quality['resource_types_with_gaps']:
            dq_report = format_data_quality_report(data_quality)
            logger.warning(dq_report)
            print(f"\n⚠ {dq_report}\n")

        # Collection completeness: how much of this run is estimated missing
        # because a whole project failed outright, weighted by the average
        # resource count of projects that did succeed - not just a raw
        # failed-project count. Always printed, even on a clean run, so the
        # operator sees this every time rather than only when something's wrong.
        completeness = compute_collection_completeness(
            total_units=len(project_ids), failed_units=failed_projects,
            resources=all_resources, unit_id_field='account_id', unit_label='project',
        )
        if completeness:
            completeness_report = format_completeness_report(completeness)
            if completeness['failed_units'] > 0:
                logger.warning(completeness_report)
            print(f"\n{completeness_report}\n")

        # Write outputs
        output_dir = args.output.rstrip('/')
        os.makedirs(output_dir, exist_ok=True)

        inventory_data = {
            'run_id': run_id,
            'timestamp': timestamp,
            'provider': 'gcp',
            'project_id': successful_project_ids,
            'projects': successful_projects,
            'resources': [r.to_dict() for r in all_resources],
        }

        summary_data = {
            'run_id': run_id,
            'timestamp': timestamp,
            'collector_metadata': get_collector_metadata(args, 'gcp', __version__),
            'provider': 'gcp',
            'project_id': successful_project_ids,
            'projects': successful_projects,
            'total_resources': len(all_resources),
            'sizing': [s.to_dict() for s in sizing],
            'change_rates': change_rate_data if change_rate_data else None,
            'data_quality': data_quality,
            'collection_completeness': completeness,
        }
        summary_data = {k: v for k, v in summary_data.items() if v is not None}

        if not args.include_resource_ids:
            inventory_data = redact_sensitive_data(inventory_data)
            summary_data = redact_sensitive_data(summary_data)

        file_ts = timestamp[11:19].replace(":", "")
        write_json(inventory_data, f"{output_dir}/cca_gcp_inv_{file_ts}.json")
        write_json(summary_data, f"{output_dir}/cca_gcp_sum_{file_ts}.json")

        if change_rate_data:
            change_rate_output = {
                'run_id': run_id,
                'timestamp': timestamp,
                'provider': 'gcp',
                'project_id': successful_project_ids,
                'projects': successful_projects,
                **change_rate_data
            }
            if not args.include_resource_ids:
                change_rate_output = redact_sensitive_data(change_rate_output)
            write_json(change_rate_output, f"{output_dir}/cca_gcp_change_rates_{file_ts}.json")

        if cost_records:
            cost_summaries = aggregate_costs(cost_records)
            cost_output = {
                'run_id': run_id,
                'timestamp': timestamp,
                'provider': 'gcp',
                'project_id': successful_project_ids,
                'period': {'start': start_date, 'end': end_date},
                'total_cost': round(sum(r.cost for r in cost_records), 2),
                'records': [r.to_dict() for r in cost_records],
                'summaries': [s.to_dict() for s in cost_summaries],
            }
            write_json(cost_output, f"{output_dir}/cca_gcp_costs_{file_ts}.json")

        print("\nOutput files:")
        print(f"  Inventory: {output_dir}/cca_gcp_inv_{file_ts}.json")
        print(f"  Summary:   {output_dir}/cca_gcp_sum_{file_ts}.json")
        print_summary_table([s.to_dict() for s in sizing])

    except Exception as e:
        logger.error(f"Collection failed: {e}", exc_info=True)
        sys.exit(1)
