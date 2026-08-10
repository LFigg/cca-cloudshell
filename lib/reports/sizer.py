"""
CCA CloudShell - Generate Sizer Input

Transforms CCA inventory/summary data into Cohesity Reverse Sizer JSON format.
This enables cloud workload data to be imported into the Cohesity sizing tool.
"""
import argparse
import json
import logging
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from lib.change_rate import load_change_rate_files
from lib.constants import (
    DEFAULT_CHANGE_RATES,
    DEFAULT_REDUCTION_RATIOS,
    PEAK_DAY_DB_WL_SUBTYPES,
    SIZER_SKIP_RESOURCE_TYPES,
    SIZER_WORKLOAD_MAPPING,
    TRANSACTION_LOG_DCR_FACTOR,
    TRANSACTION_LOG_RETENTION_DAYS,
)
from lib.data_quality import compute_data_quality_summary_from_dicts, context_size_gb
from lib.utils import setup_logging

# Policy name used for every emitted transaction-log workload - see
# create_default_policies() and the transaction-log emission block in
# create_sizer_workloads().
TRANSACTION_LOG_POLICY_NAME = "TransactionLog-ShortRetention"

logger = logging.getLogger(__name__)

# =============================================================================
# Data Models
# =============================================================================

@dataclass
class SizerWorkload:
    """Represents a workload in reverse sizer format."""
    wl_type: str  # iba, app_dump, etc.
    name: str
    wl_subtype: str  # vm, unstructured, other_db, sql, oracle, etc.
    data_size_tb: float
    daily_change_rate: float
    annual_growth_rate: float = 10.0  # Default 10% growth
    backup_window: List[str] = field(default_factory=lambda: ["00:00", "04:00"])
    replication: List[dict] = field(default_factory=list)
    policy_name: str = "Default-30Day"
    incr_data_reduction_ratio: float = 2.0
    full_data_reduction_ratio: float = 2.5
    cr_per_run: float = 0.02
    cadv2_enabled: bool = False
    cav2_enabled: bool = False
    accurate_annual_growth_rate: bool = False  # False = estimated
    accurate_daily_change_rate: bool = False  # False = estimated default, not measured
    object_count: int = 0
    # Peak Day size (TB) for workloads needing a periodic-full-backup throughput
    # reservation, per the Sizer Encyclopedia's Periodic Full Simulation section.
    # This tool has no way to know a workload's actual backup methodology (e.g.
    # incremental-forever/File-VSS/Adapter, which need no Peak Day, vs. VDI/RMAN/
    # native-dump, which do) from cloud inventory data alone - left None (not
    # guessed) rather than fabricating a number; see generate_sizer_json()'s
    # WARNING note for the manual follow-up this implies.
    peak_day_tb: Optional[float] = None
    # False when at least one resource folded into this workload's
    # data_size_tb has metadata['size_source'] == 'unavailable' (its actual
    # usage couldn't be measured, so it contributed 0 GB instead of an
    # allocated/estimated guess - see lib/data_quality.py). data_size_tb is
    # then a real but *understated* total, not a fabricated one; the SE should
    # add unmeasured_context_gb (the collector's best-effort allocated/quota
    # context for those resources, where available) before keying this into
    # WST, rather than trusting data_size_tb as-is.
    accurate_data_size: bool = True
    unmeasured_context_gb: float = 0.0
    # True for wl_subtype == "vm": VM/disk resources have no size_source key at
    # all (see lib/data_quality.py) because there's no "actual usage" to
    # distinguish from provisioned size for a disk - size_gb IS the
    # provisioned/allocated capacity, not measured in-guest consumption (no
    # cloud API exposes that without an in-guest agent). This is a hard
    # limitation, not a gap accurate_data_size can catch - disclosed
    # separately so a thin-provisioned volume's real usage isn't confused
    # with the accurate_data_size='unavailable' meaning above.
    size_reflects_provisioned_capacity: bool = False
    # Number of database resources (sql/oracle/other_db) folded into this
    # workload that are TDE-enabled/encrypted-at-rest. Disclosure only - see
    # the comment at its point of use in aggregate_by_workload_type() for why
    # this intentionally does NOT adjust incr/full_data_reduction_ratio.
    encrypted_db_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SizerPolicy:
    """Represents a backup policy in reverse sizer format."""
    name: str
    id: str
    backup_frequency_days: int = 1
    retention_days: int = 30
    archival_enabled: bool = False
    archival_retention_days: int = 90

    def to_dict(self) -> Dict[str, Any]:
        """Convert to reverse sizer policy format."""
        policy = {
            "name": self.name,
            "backupPolicy": {
                "regular": {
                    "incremental": {
                        "schedule": {
                            "unit": "Days",
                            "daySchedule": {"frequency": self.backup_frequency_days}
                        }
                    },
                    "retention": {
                        "unit": "Days",
                        "duration": self.retention_days
                    }
                }
            },
            "retryOptions": {
                "retries": 3,
                "retryIntervalMins": 5
            },
            "id": self.id,
            "originalApiVersion": "v1"
        }

        if self.archival_enabled:
            policy["remoteTargetPolicy"] = {
                "archivalTargets": [{
                    "configId": f"archive-{self.id}",
                    "retention": {
                        "unit": "Days",
                        "duration": self.archival_retention_days
                    },
                    "schedule": {"unit": "Runs", "frequency": 1},
                    "targetId": 1,
                    "targetName": "CloudArchive",
                    "targetType": "Cloud"
                }],
                "cloudSpinTargets": [],
                "onpremDeployTargets": [],
                "replicationTargets": [],
                "rpaasTargets": []
            }

        return policy


# =============================================================================
# Conversion Functions
# =============================================================================

def load_cca_data(file_paths: List[str]) -> List[Dict]:
    """Load CCA inventory JSON files.

    Deduplicates resources across (and within) files by (provider,
    resource_type, resource_id) - this tool's own --help epilog advertises
    multi-file invocation (`--input aws_inv.json azure_inv.json ...`) as
    normal usage, and aggregate_by_workload_type() trusts every resource it's
    handed as distinct capacity with no dedup of its own. Without this, the
    same inventory file passed twice, or a re-run's output merged with a
    prior run's, silently sums the same bytes N times.
    """
    all_resources = []
    seen_ids = set()  # (provider, resource_type, resource_id)
    duplicate_count = 0

    for path in file_paths:
        try:
            with open(path, 'r') as f:
                data = json.load(f)

            if 'resources' not in data:
                logger.warning(f"No 'resources' key in {path}")
                continue

            loaded = data['resources']
            deduped = []
            for resource in loaded:
                resource_id = resource.get('resource_id')
                if resource_id:
                    key = (resource.get('provider'), resource.get('resource_type'), resource_id)
                    if key in seen_ids:
                        duplicate_count += 1
                        continue
                    seen_ids.add(key)
                deduped.append(resource)

            all_resources.extend(deduped)
            skipped = len(loaded) - len(deduped)
            logger.info(
                f"Loaded {len(deduped)} resources from {path}"
                + (f" ({skipped} duplicate(s) skipped)" if skipped else "")
            )

        except Exception as e:
            logger.error(f"Failed to load {path}: {e}")

    if duplicate_count:
        logger.warning(
            f"Skipped {duplicate_count} duplicate resource(s) across input files (same "
            "provider+resource_type+resource_id seen more than once) - check for overlapping --input files"
        )

    return all_resources


def aggregate_by_workload_type(
    resources: List[Dict],
    mode: str = "apples",
    change_rates: Optional[Dict[str, Dict]] = None
) -> Dict[str, Dict]:
    """
    Aggregate resources by workload type.

    Args:
        resources: List of CCA resource dictionaries
        mode: "apples" for Cohesity-native only, "all" for everything
        change_rates: Optional dict of collected change rate data

    Returns:
        Dict mapping workload key to aggregated data
    """
    workloads = {}

    for resource in resources:
        resource_type = resource.get('resource_type', '')

        # Skip backup/snapshot resources
        if resource_type in SIZER_SKIP_RESOURCE_TYPES:
            continue

        # Get workload mapping
        mapping = SIZER_WORKLOAD_MAPPING.get(resource_type)
        if not mapping:
            logger.debug(f"Unknown resource type: {resource_type}")
            continue

        wl_type, wl_subtype, is_native = mapping

        # WST has no concept of a read replica (per the Sizer Encyclopedia:
        # "WST does not consider the number of databases" - a replica is not
        # a distinct database for sizing purposes). A replica's size_gb is
        # independently measured (real bytes, not zero), so without this
        # exclusion every replica fully re-sizes the same logical dataset
        # its primary already counted - a 500GB primary + 2 replicas would
        # contribute 1500GB instead of 500GB. Mirrors the same exclusion
        # lib/reports/assessment/analysis.py already applies for reporting.
        if resource_type in ("aws:rds:instance", "azure:sql:database", "gcp:sql:instance"):
            if (resource.get('metadata') or {}).get('is_read_replica'):
                continue

        # AWS RDS lumps every engine (MySQL, PostgreSQL, SQL Server, MariaDB,
        # Aurora-*, Oracle) into the same "sql" wl_subtype. Per the Sizer
        # Encyclopedia, Oracle's transaction-log-to-DCR ratio (3x) differs from
        # MSSQL's (1x) - refine the bucket to "oracle" using the real, collected
        # engine metadata so the transaction-log emission in
        # create_sizer_workloads() applies the right factor. Azure SQL and GCP
        # Cloud SQL have no Oracle offering, so this only ever applies here.
        # Substring match (not startswith) so RDS Custom for Oracle - engine
        # identifiers like "custom-oracle-ee" - is also caught, not just the
        # managed "oracle-ee"/"oracle-se2" identifiers.
        if wl_subtype == "sql" and resource_type in ("aws:rds:instance", "aws:rds:cluster"):
            engine = (resource.get('metadata') or {}).get('engine') or ''
            if 'oracle' in engine.lower():
                wl_subtype = "oracle"

        # In "apples" mode, skip non-native workloads
        if mode == "apples" and not is_native:
            continue

        # Create workload key (provider + subtype for grouping)
        provider = resource.get('provider', 'unknown')
        account = resource.get('account_id') or resource.get('subscription_id') or 'default'
        wl_key = f"{provider}_{wl_subtype}_{account}"

        if wl_key not in workloads:
            workloads[wl_key] = {
                "wl_type": wl_type,
                "wl_subtype": wl_subtype,
                "provider": provider,
                "account": account,
                "total_size_gb": 0.0,
                "resource_count": 0,
                "resource_types": set(),
                "service_families": set(),  # Track for change rate lookup
                "unavailable_count": 0,  # size_source == 'unavailable' (real usage not measured)
                "unmeasured_context_gb": 0.0,  # best-effort allocated/quota context for those
                "encrypted_db_count": 0,  # tde_enabled/encrypted database resources - see below
            }

        workloads[wl_key]["total_size_gb"] += resource.get('size_gb', 0) or 0
        workloads[wl_key]["resource_count"] += 1
        workloads[wl_key]["resource_types"].add(resource_type)

        # Track size_source gaps (see lib/data_quality.py) so create_sizer_workloads()
        # can flag when this workload's total_size_gb is a real but understated
        # measurement, not silently pass it off as complete.
        metadata = resource.get('metadata') or {}
        if metadata.get('size_source') == 'unavailable':
            workloads[wl_key]["unavailable_count"] += 1
            workloads[wl_key]["unmeasured_context_gb"] += context_size_gb(metadata)

        # Disclosure only, not a reduction-ratio adjustment (see PEAK_DAY_DB_WL_SUBTYPES'
        # comment for why "database" is scoped to sql/oracle/other_db here). The Sizer
        # Encyclopedia's CDR=1 guidance is for data encrypted/compressed BEFORE it reaches
        # the backup layer (source-side) - whether transparent, storage-engine-level TDE
        # defeats Cohesity's dedup the same way is NOT verified here, so this intentionally
        # does not touch incr/full_data_reduction_ratio. It only surfaces the fact so an SE
        # can check with the Sizing team rather than silently trusting an unverified ratio.
        if wl_subtype in PEAK_DAY_DB_WL_SUBTYPES and (metadata.get('tde_enabled') or metadata.get('encrypted')):
            workloads[wl_key]["encrypted_db_count"] += 1

        # Track service family for change rate lookup
        service_family = resource.get('service_family') or resource.get('service') or resource_type.split(':')[0]
        workloads[wl_key]["service_families"].add(service_family)

    return workloads


def create_sizer_workloads(
    aggregated: Dict[str, Dict],
    policy_name: str = "Default-30Day",
    change_rates: Optional[Dict[str, Dict]] = None
) -> Tuple[List[SizerWorkload], bool]:
    """
    Convert aggregated data to SizerWorkload objects.

    Returns:
        Tuple of (workloads list, used_actual_rates bool)
    """
    workloads = []
    used_actual_rates = False

    for wl_key, data in aggregated.items():
        wl_subtype = data["wl_subtype"]

        # Try to get actual change rate from collected data.
        #
        # `change_rates` is keyed "<provider>:<service_family>" (see
        # lib/change_rate.py's load_change_rate_files()/merge_change_rates()),
        # e.g. "aws:RDS", "azure:AzureVM" - NOT by bare service_family alone.
        # A bare-string lookup here can never match those keys, which silently
        # defeated this entire "prefer real data over defaults" path for every
        # cloud (the join key shapes never lined up). Build the same
        # provider-qualified key the change-rate collectors actually use.
        change_rate = None
        accurate_change_rate = False
        provider = data.get("provider", "unknown")
        if change_rates:
            for service_family in data.get("service_families", []):
                lookup_key = f"{provider}:{service_family}"
                rate_info = change_rates.get(lookup_key)
                if rate_info is None:
                    continue
                if 'data_change' in rate_info:
                    actual_rate = rate_info['data_change'].get('daily_change_percent')
                    if actual_rate is not None and actual_rate > 0:
                        change_rate = actual_rate
                        accurate_change_rate = True
                        used_actual_rates = True
                        logger.debug(f"Using actual change rate {change_rate:.2f}% for {wl_key} (matched {lookup_key})")
                        break

        # Fall back to defaults if no actual rate found
        if change_rate is None:
            change_rate = DEFAULT_CHANGE_RATES.get(wl_subtype, 2.0)
            logger.debug(f"Using default change rate {change_rate}% for {wl_key}")

        reduction = DEFAULT_REDUCTION_RATIOS.get(wl_subtype, {"incr": 2.0, "full": 2.5})

        # Create friendly name
        provider = data["provider"].upper()
        subtype_display = wl_subtype.replace("_", " ").title()
        name = f"{provider}_{subtype_display}_{data['account'][-8:]}"

        workload = SizerWorkload(
            wl_type=data["wl_type"],
            name=name,
            wl_subtype=wl_subtype,
            data_size_tb=data["total_size_gb"] / 1024,  # Convert GB to TB
            daily_change_rate=change_rate,
            annual_growth_rate=10.0,  # Default to 10%
            policy_name=policy_name,
            incr_data_reduction_ratio=reduction["incr"],
            full_data_reduction_ratio=reduction["full"],
            cr_per_run=change_rate / 100,
            accurate_daily_change_rate=accurate_change_rate,
            object_count=data["resource_count"],
            accurate_data_size=data.get("unavailable_count", 0) == 0,
            unmeasured_context_gb=data.get("unmeasured_context_gb", 0.0),
            size_reflects_provisioned_capacity=(wl_subtype == "vm"),
            encrypted_db_count=data.get("encrypted_db_count", 0),
        )

        workloads.append(workload)

    # Emit a separate Transaction Log workload for each SQL/Oracle workload, per
    # the Sizer Encyclopedia's "Transaction Logs = factor x DCR" methodology:
    #   - the log workload's SIZE is a fraction of the base workload's size
    #     (base_DCR% x factor), NOT the base database's full data size;
    #   - the log workload's own daily change rate is always 100% (virtually
    #     all log data is newly written, never touched again);
    #   - it uses a short-retention policy (TRANSACTION_LOG_RETENTION_DAYS),
    #     not the base workload's typically-30-day policy, per the
    #     Encyclopedia's guidance to control log storage/licensing cost.
    # Skipped entirely when the base workload's data size is 0 (nothing to log).
    log_workloads = []
    for base in list(workloads):
        factor = TRANSACTION_LOG_DCR_FACTOR.get(base.wl_subtype)
        if factor is None or base.data_size_tb <= 0:
            continue

        log_reduction = DEFAULT_REDUCTION_RATIOS["archive_transactionlog"]
        log_workloads.append(SizerWorkload(
            wl_type="iba",
            name=f"{base.name}_TransactionLog",
            wl_subtype="archive_transactionlog",
            data_size_tb=base.data_size_tb * (base.daily_change_rate / 100.0) * factor,
            daily_change_rate=100.0,
            annual_growth_rate=base.annual_growth_rate,
            policy_name=TRANSACTION_LOG_POLICY_NAME,
            incr_data_reduction_ratio=log_reduction["incr"],
            full_data_reduction_ratio=log_reduction["full"],
            cr_per_run=1.0,
            accurate_annual_growth_rate=base.accurate_annual_growth_rate,
            # A log workload's DCR is fixed at 100% by definition (not measured or
            # defaulted the way its base workload's DCR is), so "accuracy" here
            # instead reflects whether the SIZE derived from it rests on a real,
            # measured base DCR rather than an estimated default.
            accurate_daily_change_rate=base.accurate_daily_change_rate,
            # The log size is derived from base.data_size_tb, so an understated
            # base carries the same understatement into its log sibling.
            accurate_data_size=base.accurate_data_size,
            unmeasured_context_gb=0.0,  # context is the base workload's to report, not duplicated here
            # Transaction logs come from the same (possibly encrypted) database;
            # the CDR uncertainty applies equally to the log stream.
            encrypted_db_count=base.encrypted_db_count,
            object_count=0,
        ))
    workloads.extend(log_workloads)

    return workloads, used_actual_rates


def create_default_policies() -> List[SizerPolicy]:
    """Create default backup policies."""
    return [
        SizerPolicy(
            name="Default-30Day",
            id="cca:policy:default-30",
            backup_frequency_days=1,
            retention_days=30,
            archival_enabled=False,
        ),
        SizerPolicy(
            name="Production-90Day-Archive",
            id="cca:policy:prod-90-archive",
            backup_frequency_days=1,
            retention_days=90,
            archival_enabled=True,
            archival_retention_days=365,
        ),
        SizerPolicy(
            name="Compliance-7Year",
            id="cca:policy:compliance-7y",
            backup_frequency_days=1,
            retention_days=30,
            archival_enabled=True,
            archival_retention_days=2555,  # 7 years
        ),
        SizerPolicy(
            # Used for every emitted transaction-log workload (see
            # create_sizer_workloads()). NOTE: the Sizer Encyclopedia recommends
            # transaction logs be captured as frequently as every 15 min-4 hours
            # with short (1-3 day) retention; this generator's policy schema only
            # models whole-day frequencies today (backup_frequency_days), so
            # "1 day" here is a placeholder for frequency, not a real RPO -
            # retention (the part that drives storage/licensing cost, which this
            # policy IS modeling correctly) is set to the Encyclopedia's
            # recommended floor. Tighten the frequency manually in Cohesity's
            # Sizer/WST tool for an RPO-accurate throughput calculation.
            name=TRANSACTION_LOG_POLICY_NAME,
            id="cca:policy:txlog-short-retention",
            backup_frequency_days=1,
            retention_days=TRANSACTION_LOG_RETENTION_DAYS,
            archival_enabled=False,
        ),
    ]


def generate_sizer_json(
    resources: List[Dict],
    mode: str = "apples",
    output_path: Optional[str] = None,
    change_rates: Optional[Dict[str, Dict]] = None
) -> Dict:
    """
    Generate Cohesity Reverse Sizer JSON from CCA data.

    Args:
        resources: List of CCA resource dictionaries
        mode: "apples" for native workloads only, "all" for everything
        output_path: Optional path to write output
        change_rates: Optional dict of collected change rate data

    Returns:
        Sizer JSON dictionary
    """
    # Aggregate resources by workload type
    aggregated = aggregate_by_workload_type(resources, mode, change_rates)

    if not aggregated:
        logger.warning("No workloads to process")
        return {}

    # Create workloads and policies
    workloads, used_actual_rates = create_sizer_workloads(aggregated, "Default-30Day", change_rates)
    policies = create_default_policies()

    # Calculate totals
    total_size_tb = sum(w.data_size_tb for w in workloads)
    total_objects = sum(w.object_count for w in workloads)
    accurate_rate_count = sum(1 for w in workloads if w.accurate_daily_change_rate)
    estimated_rate_count = len(workloads) - accurate_rate_count
    # AGR is never measured today (no code path collects longitudinal growth
    # data), so this is always 0/len(workloads) - computed generically (not
    # hardcoded) so it starts reflecting reality the moment that changes,
    # mirroring accurate_rate_count's per-workload pattern above rather than
    # staying a single blanket warning sentence.
    accurate_growth_count = sum(1 for w in workloads if w.accurate_annual_growth_rate)
    estimated_growth_count = len(workloads) - accurate_growth_count

    change_rate_warnings = []
    if workloads and estimated_rate_count > 0:
        change_rate_warnings.append(
            f"{estimated_rate_count} of {len(workloads)} workload(s) used an estimated default change rate "
            "rather than measured data - per-workload accuracy is in each workload's "
            "'accurate_daily_change_rate' field"
        )

    # size_source data-quality disclosure (see lib/data_quality.py): a resource
    # whose actual usage couldn't be measured contributes 0 GB to its
    # workload's data_size_tb rather than a fabricated allocation/quota guess -
    # correct, but it means data_size_tb can be a real, understated total. The
    # per-resource-type breakdown mirrors what lib/reports/assessment.py and
    # lib/reports/protection.py already surface, so an SE sees the same gap
    # picture whichever CCA deliverable they're reading; the per-workload
    # 'accurate_data_size'/'unmeasured_context_gb' fields above are the
    # actionable version scoped to what's actually in THIS sizer JSON.
    data_quality_summary = compute_data_quality_summary_from_dicts(resources)
    data_quality_warnings = []
    inaccurate_size_workloads = [w for w in workloads if not w.accurate_data_size]
    if inaccurate_size_workloads:
        total_context_gb = sum(w.unmeasured_context_gb for w in inaccurate_size_workloads)
        data_quality_warnings.append(
            f"{len(inaccurate_size_workloads)} of {len(workloads)} workload(s) have unmeasured resources "
            f"folded in at 0 GB (real usage couldn't be collected) - data_size_tb is real but understated; "
            f"see each workload's 'accurate_data_size'/'unmeasured_context_gb' fields "
            f"(~{total_context_gb:,.1f} GB of allocated/estimated capacity is known as context, where "
            "available) and the top-level 'data_quality' section for the resource-type breakdown"
        )

    # Periodic-full / Peak Day disclosure: this tool can tell a database workload
    # apart from a VM/file/object workload, but it has no way to know the
    # customer's actual backup METHODOLOGY (incremental-forever/File-VSS/Adapter
    # need no Peak Day; VDI/RMAN/native-dump/App-Dump do) from cloud inventory
    # data alone. Rather than guess a Peak Day value - which the Sizer
    # Encyclopedia's own Periodic Full Simulation section says depends on the
    # customer's actual full-backup cadence - every workload's peak_day_tb is
    # left unset (None) and this is surfaced explicitly instead of silently
    # undersizing throughput for any workload that turns out to need one.
    db_workload_count = sum(1 for w in workloads if w.wl_subtype in PEAK_DAY_DB_WL_SUBTYPES)
    peak_day_warnings = []
    if db_workload_count > 0:
        peak_day_warnings.append(
            f"{db_workload_count} database workload(s) have no Peak Day / periodic-full sizing - if any of "
            "these uses a periodic-full backup method (VDI, RMAN, native dump, App Dump - see the Sizer "
            "Encyclopedia's Periodic Full Simulation section), throughput will be undersized unless a Peak "
            "Day value is added manually (workload field 'peak_day_tb')"
        )

    # The transaction-log policy's backup_frequency_days is a placeholder (see
    # create_default_policies()'s TRANSACTION_LOG_POLICY_NAME comment) - the
    # Sizer Encyclopedia recommends capturing logs every 15min-4hrs, far tighter
    # than the "1 day" this policy schema can express. Previously that caveat
    # only lived in a Python source comment, invisible to an SE reading the
    # JSON this function actually produces - surface it as a real WARNING.
    tlog_frequency_warnings = []
    if any(w.wl_subtype == "archive_transactionlog" for w in workloads):
        tlog_frequency_warnings.append(
            "Transaction-log workload(s) use a placeholder 1-day backup frequency in the "
            f"'{TRANSACTION_LOG_POLICY_NAME}' policy - the Sizer Encyclopedia recommends capturing "
            "logs every 15 minutes to 4 hours for an RPO-accurate throughput calculation; tighten "
            "the frequency manually in WST before finalizing this sizing"
        )

    # Disclosure only (see aggregate_by_workload_type()'s comment on
    # encrypted_db_count for why this does not adjust reduction ratios itself).
    # Excludes archive_transactionlog siblings, which inherit their base
    # workload's encrypted_db_count for per-workload disclosure - counting
    # both here would double-count the same underlying database.
    encrypted_workloads = [
        w for w in workloads if w.encrypted_db_count > 0 and w.wl_subtype != "archive_transactionlog"
    ]
    encryption_warnings = []
    if encrypted_workloads:
        total_encrypted = sum(w.encrypted_db_count for w in encrypted_workloads)
        encryption_warnings.append(
            f"{total_encrypted} database resource(s) across {len(encrypted_workloads)} workload(s) are "
            "TDE-enabled/encrypted-at-rest ('encrypted_db_count' field) - this tool has NOT verified "
            "whether transparent, storage-engine-level encryption defeats Cohesity's dedup the way the "
            "Sizer Encyclopedia's source-side-encryption CDR=1 guidance assumes, so reduction ratios were "
            "left unchanged; confirm with the Sizing team whether Custom Data Reduction should be adjusted "
            "for these workloads"
        )

    # Hard limitation, not a gap: no cloud API exposes real in-guest disk usage
    # without an in-guest agent, so a "vm" workload's data_size_tb is always the
    # provisioned/allocated disk capacity (a thin-provisioned volume overstates
    # real usage). This is why "vm" resources carry no size_source key at all
    # (see lib/data_quality.py) rather than being flagged 'unavailable'.
    provisioned_capacity_workloads = [w for w in workloads if w.size_reflects_provisioned_capacity]
    provisioned_capacity_warnings = []
    if provisioned_capacity_workloads:
        provisioned_capacity_warnings.append(
            f"{len(provisioned_capacity_workloads)} VM workload(s) report provisioned/allocated disk "
            "capacity as data_size_tb, not measured in-guest usage - no cloud API exposes real consumption "
            "without an in-guest agent ('size_reflects_provisioned_capacity' field); thin-provisioned "
            "volumes will overstate real data size"
        )

    # Build sizer JSON
    timestamp = datetime.now(timezone.utc)
    sizer_json = {
        "reverse_sizer_version": "v0.12",
        "node_set": [
            "GenericChassisModel"  # Generic for cloud workloads
        ],
        "policies": [p.to_dict() for p in policies],
        "clusters": [
            {
                "cluster_info": {
                    "total_jobs_storage_consumed": int(total_size_tb * 1024 * 1024 * 1024 * 1024),  # bytes
                    "run_timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "accurate_annual_growth_rate": False,
                    "no_primary_and_incoming_repl_workloads": False,
                },
                "cluster_id": int(timestamp.timestamp() * 1000),
                "workloads": [w.to_dict() for w in workloads],
                "data_quality": data_quality_summary,
                "notes": {
                    "CRITICAL": [],
                    "INFO": [
                        "Generated from CCA CloudShell data",
                        f"Mode: {mode} ({'Cohesity-native workloads only' if mode == 'apples' else 'All collected resources'})",
                        f"Total protected data size: {total_size_tb:.2f} TB",
                        f"Total objects: {total_objects}",
                        f"Generated at: {timestamp.isoformat()}",
                        *(
                            [f"Data quality: {len(inaccurate_size_workloads)}/{len(workloads)} workload(s) "
                             "have unmeasured resources - see the WARNING section and 'data_quality' key"]
                            if inaccurate_size_workloads else []
                        ),
                        (
                            f"Growth rates: {accurate_growth_count}/{len(workloads)} workload(s) used actual "
                            f"collected data; {estimated_growth_count} used the estimated 10% default"
                            if workloads else "Growth rates: no workloads to report"
                        ),
                        (
                            f"Change rates: {accurate_rate_count}/{len(workloads)} workload(s) used actual "
                            f"collected data; {estimated_rate_count} used estimated defaults"
                            if workloads else "Change rates: no workloads to report"
                        ),
                    ],
                    "ERROR": [],
                    "WARNING": [
                        *change_rate_warnings,
                        *peak_day_warnings,
                        *tlog_frequency_warnings,
                        *data_quality_warnings,
                        *encryption_warnings,
                        *provisioned_capacity_warnings,
                        "Data reduction ratios are industry averages",
                        "Actual values will vary based on workload characteristics",
                    ],
                    "DEBUG": []
                },
                "software_version": "CCA-CloudShell-v1.0",
                "alerts": []
            }
        ]
    }

    # Write to file if path provided
    if output_path:
        with open(output_path, 'w') as f:
            json.dump(sizer_json, f, indent=2)
        logger.info(f"Wrote sizer JSON to {output_path}")

    return sizer_json


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Generate Cohesity Sizer input from CCA inventory data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Apples-to-apples (Cohesity-native workloads only)
  python3 scripts/generate_sizer_input.py --input cca_inv_*.json --mode apples

  # All-in (all collected resources)
  python3 scripts/generate_sizer_input.py --input cca_inv_*.json --mode all

  # Multi-cloud
  python3 scripts/generate_sizer_input.py --input aws_inv.json azure_inv.json gcp_inv.json

  # With actual change rates (from --include-change-rate collection)
  python3 scripts/generate_sizer_input.py --input cca_inv_*.json --change-rates cca_*_change_rates_*.json
        """
    )

    parser.add_argument(
        "--input", "-i",
        nargs="+",
        required=True,
        help="Input CCA inventory JSON file(s)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output sizer JSON file (default: sizer_input_<timestamp>.json)"
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["apples", "all"],
        default="apples",
        help="Mode: 'apples' for Cohesity-native only, 'all' for everything"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--change-rates", "-c",
        nargs="*",
        help="CCA change rate JSON file(s) from --include-change-rate collection"
    )

    args = parser.parse_args()

    # Setup logging
    log_level = "DEBUG" if args.verbose else "INFO"
    setup_logging(level=log_level)

    # Load CCA data
    resources = load_cca_data(args.input)
    if not resources:
        logger.error("No resources loaded")
        sys.exit(1)

    logger.info(f"Loaded {len(resources)} total resources")

    # Load change rates if provided
    change_rates = None
    if args.change_rates:
        cr_data = load_change_rate_files(args.change_rates)
        if cr_data.get('has_actual_data'):
            change_rates = cr_data.get('change_rates', {})
            logger.info(f"Loaded change rates for {len(change_rates)} service families")
        else:
            logger.warning("No change rate data loaded, will use defaults")

    # Generate output path
    output_path = args.output
    if not output_path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"sizer_input_{args.mode}_{timestamp}.json"

    # Generate sizer JSON
    sizer_json = generate_sizer_json(resources, args.mode, output_path, change_rates)

    # Print summary
    if sizer_json and sizer_json.get("clusters"):
        cluster = sizer_json["clusters"][0]
        workloads = cluster.get("workloads", [])
        total_tb = sum(w["data_size_tb"] for w in workloads)

        print(f"\n{'='*60}")
        print(f"Generated Sizer Input ({args.mode} mode)")
        print(f"{'='*60}")
        print(f"  Output file: {output_path}")
        print(f"  Workloads: {len(workloads)}")
        print(f"  Total data: {total_tb:.2f} TB")
        print("\nWorkload breakdown:")
        for w in workloads:
            print(f"  - {w['name']}: {w['data_size_tb']:.2f} TB ({w['object_count']} objects)")
