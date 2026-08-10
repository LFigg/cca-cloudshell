"""Azure preflight dependency verification.

Every optional-package collector in this codebase (databases.py, storage.py's
NetApp support, monitoring.py) already catches its own ImportError and logs a
"not installed, skipping" warning - but that warning is easy to miss in a long
collection run, and the practical effect is silent, partial data with no clear
signal anything was wrong (see: the BrettH/Acosta and BrettH/Crossmark Azure
collections, both missing blob capacity and change-rate data, and Acosta also
missing Synapse/Redis/PostgreSQL/MySQL/MariaDB/NetApp entirely, because the
collection environment was missing several azure-mgmt-* packages that
requirements.txt lists but nothing had verified were actually installed).

This mirrors lib/azure/permissions.py's mandatory preflight: check everything
requirements.in says this run needs, up front, so a missing package is a
clear "run `pip install -r requirements.txt`" failure before collection
starts, not a scattered set of warnings after a possibly hours-long run.
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
# the same order as the Azure section of requirements.in.
_REQUIRED_PACKAGES = [
    ("azure-identity", "azure.identity", "authentication - nothing can be collected without this"),
    ("azure-mgmt-compute", "azure.mgmt.compute", "VMs, managed disks, disk snapshots"),
    ("azure-mgmt-storage", "azure.mgmt.storage", "storage accounts, blob capacity, file shares"),
    ("azure-mgmt-sql", "azure.mgmt.sql", "SQL databases, managed instances, restore points, LTR backups"),
    ("azure-mgmt-cosmosdb", "azure.mgmt.cosmosdb", "Cosmos DB accounts"),
    ("azure-mgmt-containerservice", "azure.mgmt.containerservice", "AKS clusters"),
    ("azure-mgmt-web", "azure.mgmt.web", "Function Apps"),
    ("azure-mgmt-resource", "azure.mgmt.resource", "subscription/resource enumeration"),
    ("azure-mgmt-subscription", "azure.mgmt.subscription", "subscription discovery"),
    ("azure-mgmt-recoveryservices", "azure.mgmt.recoveryservices", "Recovery Services vaults"),
    ("azure-mgmt-recoveryservicesbackup", "azure.mgmt.recoveryservicesbackup", "backup policies, protected items"),
    ("azure-mgmt-redis", "azure.mgmt.redis", "Redis caches"),
    ("azure-mgmt-costmanagement", "azure.mgmt.costmanagement", "cost data (--costs)"),
    ("azure-mgmt-rdbms", "azure.mgmt.rdbms", "PostgreSQL, MySQL, MariaDB"),
    ("azure-mgmt-synapse", "azure.mgmt.synapse", "Synapse SQL pools"),
    ("azure-mgmt-netapp", "azure.mgmt.netapp", "Azure NetApp Files volumes"),
    ("azure-mgmt-monitor", "azure.mgmt.monitor", "change-rate/growth metrics and every real-usage lookup (blob capacity, file share, SQL, Cosmos DB, PostgreSQL/MySQL, Redis, NetApp) - without it these silently fall back to 0/quota/unavailable"),
    ("azure-storage-blob", "azure.storage.blob", "blob-level operations used by storage account collection"),
]


def check_azure_dependencies() -> List[MissingPackage]:
    """Check that every package the Azure collector can use is importable.

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
