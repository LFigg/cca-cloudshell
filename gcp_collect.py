#!/usr/bin/env python3
"""
CCA CloudShell - Google Cloud Resource Collector

Collects GCP resources for cloud protection assessment.
Optimized for Google Cloud Shell with minimal dependencies.

Usage:
    python3 gcp_collect.py
    python3 gcp_collect.py --project my-project-id
    python3 gcp_collect.py --output gs://my-bucket/assessments/
"""
import argparse
import logging
import sys
from typing import Callable, List, Optional, Tuple

# Google Cloud SDK - pre-installed in Cloud Shell
try:
    import google.auth  # noqa: F401 - used by submodules
    from google.api_core.exceptions import NotFound, PermissionDenied  # noqa: F401 - used in exception handlers
    from google.cloud import compute_v1, storage  # noqa: F401 - test core SDK
    from googleapiclient.discovery import build as discovery_build  # noqa: F401 - for Cloud SQL
    HAS_GCP_SDK = True
except ImportError:
    HAS_GCP_SDK = False

# Add lib to path for imports
sys.path.insert(0, '.')
from lib.__version__ import __version__
from lib.change_rate import finalize_change_rate_output, merge_change_rates
from lib.k8s import collect_gke_pvcs
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

# GCP module imports - only when SDK is available
if HAS_GCP_SDK:
    from lib.gcp.auth import get_credentials, get_projects
    from lib.gcp.compute import (
        collect_compute_instances,
        collect_disk_snapshots,
        collect_persistent_disks,
    )
    from lib.gcp.storage import collect_filestore_instances, collect_storage_buckets
    from lib.gcp.databases import (
        collect_alloydb_clusters,
        collect_bigquery_datasets,
        collect_bigtable_instances,
        collect_cloud_sql_instances,
        collect_memorystore_redis,
        collect_spanner_instances,
    )
    from lib.gcp.container import collect_cloud_functions, collect_gke_clusters
    from lib.gcp.backup import (
        collect_backup_data_sources,
        collect_backup_plans,
        collect_backup_vaults,
        collect_backups,
    )
    from lib.gcp.monitoring import collect_gcp_change_rates

logger = logging.getLogger(__name__)


# =============================================================================
# Main Collection
# =============================================================================

def collect_project(
    project_id: str,
    tracker: Optional[ProgressTracker] = None,
    parallel_resources: int = 1
) -> List[CloudResource]:
    """
    Collect all resources for a project.

    Args:
        project_id: GCP project ID
        tracker: Optional progress tracker
        parallel_resources: Number of resource types to collect in parallel (default: 1)
    """
    logger.info(f"Collecting resources for project: {project_id}")

    # Define all collection tasks as (name, function, args) tuples
    collection_tasks: List[Tuple[str, Callable, tuple]] = [
        # Compute Engine
        ("Compute instances", collect_compute_instances, (project_id,)),
        ("Persistent disks", collect_persistent_disks, (project_id,)),
        ("Disk snapshots", collect_disk_snapshots, (project_id,)),
        # Storage
        ("Cloud Storage buckets", collect_storage_buckets, (project_id,)),
        ("Filestore instances", collect_filestore_instances, (project_id,)),
        # Databases
        ("Cloud SQL instances", collect_cloud_sql_instances, (project_id,)),
        ("Memorystore Redis", collect_memorystore_redis, (project_id,)),
        ("Cloud Spanner instances", collect_spanner_instances, (project_id,)),
        ("AlloyDB clusters", collect_alloydb_clusters, (project_id,)),
        # Analytics
        ("BigQuery datasets", collect_bigquery_datasets, (project_id,)),
        ("Bigtable instances", collect_bigtable_instances, (project_id,)),
        # Containers & Compute
        ("GKE clusters", collect_gke_clusters, (project_id,)),
        ("Cloud Functions", collect_cloud_functions, (project_id,)),
        # Backup & DR
        ("Backup plans", collect_backup_plans, (project_id,)),
        ("Backup vaults", collect_backup_vaults, (project_id,)),
        ("Backup data sources", collect_backup_data_sources, (project_id,)),
        ("Backups", collect_backups, (project_id,)),
    ]

    all_resources = parallel_collect(
        collection_tasks=collection_tasks,
        parallel_workers=parallel_resources,
        tracker=tracker,
        logger=logger
    )

    return all_resources


def main():
    parser = argparse.ArgumentParser(description='CCA CloudShell - GCP Resource Collector')
    parser.add_argument('--project', help='GCP project ID (default: current project)')
    parser.add_argument('--all-projects', action='store_true', help='Collect from all accessible projects')
    parser.add_argument('--regions', help='Comma-separated list of regions to filter (e.g., us-central1,us-east1)')
    parser.add_argument('--output', help='Output directory or GCS path', default='.')
    parser.add_argument('--log-level', help='Logging level', default='INFO')
    parser.add_argument(
        '--skip-change-rate',
        action='store_true',
        help='Skip collecting change rates from Cloud Monitoring'
    )
    parser.add_argument(
        '--skip-pvc',
        action='store_true',
        help='Skip PVC collection from GKE clusters (PVCs are collected by default when clusters are found)'
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

    args = parser.parse_args()

    # Setup logging - write to file if output is local directory
    log_dir = args.output if not args.output.startswith(('s3://', 'gs://', 'https://')) else None
    setup_logging(args.log_level, output_dir=log_dir)
    log_arguments(args, "GCP collector")

    if not HAS_GCP_SDK:
        logger.error("Google Cloud SDK not installed. Run: pip install google-cloud-compute google-cloud-storage")
        sys.exit(1)

    try:
        credentials, default_project = get_credentials()

        # Determine which projects to collect
        # projects is a list of {id, name} dicts
        if args.all_projects:
            projects = get_projects(credentials)
        elif args.project:
            projects = [{'id': args.project, 'name': args.project}]  # Name unknown, use ID
        elif default_project:
            projects = [{'id': default_project, 'name': default_project}]  # Name unknown, use ID
        else:
            logger.error("No project specified and no default project found")
            sys.exit(1)

        project_ids = [p['id'] for p in projects]
        logger.info(f"Collecting from {len(project_ids)} project(s)")

        all_resources = []
        failed_projects = []
        successful_projects = []  # Track projects with names

        with ProgressTracker("GCP", total_accounts=len(project_ids)) as tracker:
            for proj in projects:
                project_id = proj['id']
                project_name = proj.get('name', project_id)
                try:
                    tracker.start_account(project_id, project_name)
                    resources = collect_project(
                        project_id, tracker,
                        parallel_resources=args.parallel_resources
                    )
                    all_resources.extend(resources)
                    successful_projects.append({
                        'project_id': project_id,
                        'project_name': project_name
                    })
                    tracker.complete_account()
                except AuthError as e:
                    logger.error(f"Authentication/authorization error for project {project_id}: {e}")
                    logger.error("Check that the service account has required permissions.")
                    failed_projects.append({'project_id': project_id, 'error': str(e)})
                    continue
                except Exception as e:
                    logger.error(f"Failed to collect from project {project_id}: {e}")
                    failed_projects.append({'project_id': project_id, 'error': str(e)})
                    continue

        if failed_projects:
            logger.warning(f"Collection failed for {len(failed_projects)} project(s)")

        # Filter by regions if specified
        if args.regions:
            region_filter = {r.strip().lower() for r in args.regions.split(',')}
            original_count = len(all_resources)
            all_resources = [r for r in all_resources if r.region and r.region.lower() in region_filter]
            logger.info(f"Filtered to {len(all_resources)} resources in regions: {', '.join(sorted(region_filter))} (from {original_count} total)")

        # Generate run ID and timestamp
        run_id = generate_run_id()
        timestamp = get_timestamp()

        # Aggregate sizing
        sizing = aggregate_sizing(all_resources)

        # Collect change rates by default
        change_rate_data = None
        successful_project_ids = [p['project_id'] for p in successful_projects]
        if not args.skip_change_rate:
            logger.info("Collecting change rate metrics from Cloud Monitoring...")
            print("Collecting change rate metrics from Cloud Monitoring...")
            all_change_rates = {}
            for project_id in successful_project_ids:
                try:
                    # Filter resources for this project
                    proj_resources = [r for r in all_resources if r.metadata.get('project_id') == project_id or r.resource_id.startswith(f"projects/{project_id}")]
                    cr_data = collect_gcp_change_rates(project_id, proj_resources, args.change_rate_days)
                    merge_change_rates(all_change_rates, cr_data)
                except Exception as e:
                    logger.warning(f"Failed to collect change rates for project {project_id}: {e}")

            if all_change_rates:
                change_rate_data = finalize_change_rate_output(
                    all_change_rates, args.change_rate_days, "Cloud Monitoring"
                )
                logger.info(f"Collected change rates for {len(all_change_rates)} service families")
            else:
                logger.warning("No change rate data collected. Check if google-cloud-monitoring is installed.")
                print("⚠ No change rate data collected. Run: pip install google-cloud-monitoring")

        # Collect PVCs from GKE clusters (automatic when clusters are discovered)
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
                    # Extract project_id from resource_id: projects/{project}/locations/{location}/clusters/{name}
                    parts = cluster.resource_id.split('/')
                    project_id = parts[1] if len(parts) > 1 else cluster.account_id

                    cluster_pvcs = collect_gke_pvcs(
                        project_id,
                        cluster.region,  # This is the location
                        cluster.name
                    )
                    all_resources.extend(cluster_pvcs)
                    pvc_count += len(cluster_pvcs)
                    if cluster_pvcs:
                        logger.info(f"Found {len(cluster_pvcs)} PVCs in GKE cluster {cluster.name}")
                except ImportError:
                    logger.info("kubernetes package not installed - skipping PVC collection (pip install kubernetes)")
                    print("Note: Install 'kubernetes' package for PVC collection: pip install kubernetes")
                    k8s_available = False
                except Exception as e:
                    logger.warning(f"Failed to collect PVCs from GKE cluster {cluster.name}: {e}")

            if pvc_count > 0:
                print(f"Collected {pvc_count} PVCs from {len(gke_clusters)} GKE clusters")
        elif gke_clusters and args.skip_pvc:
            logger.info("Skipping PVC collection (--skip-pvc specified)")

        # Prepare output data
        inventory_data = {
            'run_id': run_id,
            'timestamp': timestamp,
            'provider': 'gcp',
            'project_id': successful_project_ids,  # List of IDs for backward compatibility
            'projects': successful_projects,       # List of {project_id, project_name}
            'resources': [r.to_dict() for r in all_resources]
        }

        summary_data = {
            'run_id': run_id,
            'timestamp': timestamp,
            'collector_metadata': get_collector_metadata(args, 'gcp', __version__),
            'provider': 'gcp',
            'project_id': successful_project_ids,  # List of IDs for backward compatibility
            'projects': successful_projects,       # List of {project_id, project_name}
            'total_resources': len(all_resources),
            'sizing': [s.to_dict() for s in sizing],
            'change_rates': change_rate_data if change_rate_data else None
        }

        # Remove None values
        summary_data = {k: v for k, v in summary_data.items() if v is not None}

        # Redact sensitive IDs unless --include-resource-ids is specified
        if not args.include_resource_ids:
            inventory_data = redact_sensitive_data(inventory_data)
            summary_data = redact_sensitive_data(summary_data)

        # Write outputs
        output_dir = args.output.rstrip('/')

        # Ensure output directory exists
        import os
        os.makedirs(output_dir, exist_ok=True)

        # Short timestamp for filenames (HHMMSS)
        file_ts = timestamp[11:19].replace(":", "")
        inv_file = f"{output_dir}/cca_gcp_inv_{file_ts}.json"
        sum_file = f"{output_dir}/cca_gcp_sum_{file_ts}.json"

        write_json(inventory_data, inv_file)
        write_json(summary_data, sum_file)

        # Write change rate data to separate file if collected
        if change_rate_data:
            change_rate_file = f"{output_dir}/cca_gcp_change_rates_{file_ts}.json"
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
            write_json(change_rate_output, change_rate_file)

        # Print detailed results (ProgressTracker already showed collection summary)
        print("\nOutput files:")
        print(f"  Inventory: {inv_file}")
        print(f"  Summary: {sum_file}")

        # Print sizing table
        print_summary_table([s.to_dict() for s in sizing])

    except Exception as e:
        logger.error(f"Collection failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
