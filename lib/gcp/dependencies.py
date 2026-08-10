"""GCP preflight dependency verification.

GCP splits services across separate google-cloud-* packages, same as Azure's
azure-mgmt-* split (see lib/azure/dependencies.py). Every optional-service
collector here (backup.py, container.py, databases.py, storage.py's Filestore
support, monitoring.py) already catches its own ImportError and logs a "not
installed" warning, but that's the same silent-partial-data failure mode the
Azure fix exists to prevent: a package missing from the collection
environment doesn't stop the run, it just quietly drops that service's data
with a warning easy to miss in a long collection log.

This mirrors lib/azure/dependencies.py and lib/azure/permissions.py's
mandatory preflight: check everything requirements.in says this run needs, up
front, so a missing package is a clear "run `pip install -r
requirements.txt`" failure before collection starts, not a scattered set of
warnings after a possibly hours-long run.
"""
import importlib.util
import logging
from dataclasses import dataclass
from typing import List

logger = logging.getLogger(__name__)


@dataclass
class MissingPackage:
    pip_name: str
    module_name: str
    affects: str


# (pip package name, importable module, what's lost if it's missing) - kept in
# the same order as the GCP section of requirements.in.
_REQUIRED_PACKAGES = [
    ("google-cloud-compute", "google.cloud.compute_v1", "VM instances, persistent disks, disk snapshots"),
    ("google-cloud-storage", "google.cloud.storage", "Cloud Storage buckets"),
    ("google-cloud-container", "google.cloud.container_v1", "GKE clusters"),
    ("google-cloud-functions", "google.cloud.functions_v2", "Cloud Functions"),
    ("google-cloud-filestore", "google.cloud.filestore_v1", "Filestore instances"),
    ("google-cloud-redis", "google.cloud.redis_v1", "Memorystore for Redis instances"),
    ("google-cloud-resource-manager", "google.cloud.resourcemanager_v3", "project discovery (--all-projects)"),
    ("google-cloud-monitoring", "google.cloud.monitoring_v3", "change-rate/growth metrics"),
    ("google-cloud-backupdr", "google.cloud.backupdr_v1", "Backup and DR plans, vaults, data sources, backups"),
    ("google-cloud-bigquery", "google.cloud.bigquery", "BigQuery datasets and cost data (--costs)"),
    ("google-cloud-spanner", "google.cloud.spanner_v1", "Cloud Spanner instances"),
    ("google-cloud-bigtable", "google.cloud.bigtable", "Cloud Bigtable instances"),
    ("google-cloud-alloydb", "google.cloud.alloydb_v1", "AlloyDB clusters"),
    ("google-api-python-client", "googleapiclient.discovery", "Cloud SQL instances (Discovery API fallback)"),
]


def check_gcp_dependencies() -> List[MissingPackage]:
    """Check that every package the GCP collector can use is importable.

    Uses importlib.util.find_spec rather than a real import - cheap, and
    avoids triggering any package-level side effects just to check presence.

    Returns:
        Missing packages, in the same order as requirements.in. Empty if
        everything is installed.
    """
    missing = []
    for pip_name, module_name, affects in _REQUIRED_PACKAGES:
        if importlib.util.find_spec(module_name) is None:
            missing.append(MissingPackage(pip_name, module_name, affects))
    return missing


def format_dependency_report(missing: List[MissingPackage]) -> str:
    """Format missing packages into a human-readable report."""
    lines = [f"Missing {len(missing)} required package(s):"]
    for pkg in missing:
        lines.append(f"  - {pkg.pip_name}: {pkg.affects}")
    return "\n".join(lines)
