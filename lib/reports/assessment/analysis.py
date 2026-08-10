"""Resource categorization and analysis for the assessment report.

Pure data-analysis functions (no Excel/openpyxl dependency) - categorize
resources by workload type, analyze protection coverage, regions, accounts,
and snapshot patterns.
"""
import re
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from lib.constants import WORKLOAD_CATEGORIES


def get_provider(resource_type: str) -> str:
    """Extract provider from resource type."""
    if resource_type.startswith('aws:'):
        return 'AWS'
    elif resource_type.startswith('azure:'):
        return 'Azure'
    elif resource_type.startswith('gcp:'):
        return 'GCP'
    elif resource_type.startswith('m365:'):
        return 'M365'
    elif resource_type.startswith('k8s:'):
        return 'Kubernetes'
    return 'Unknown'


def get_workload_category(resource_type: str) -> str:
    """Map resource type to workload category."""
    for _category, config in WORKLOAD_CATEGORIES.items():
        if resource_type in config['types']:
            return config['label']

    # Fallback categorization
    if 'snapshot' in resource_type:
        return 'Snapshots'
    if 'backup' in resource_type:
        return 'Backup Services'

    return 'Other'


def _is_kubernetes_node(resource: Dict) -> bool:
    """
    Check if an EC2/VM instance is a Kubernetes worker node.

    Detects EKS, AKS, GKE nodes via common tag patterns:
    - kubernetes.io/cluster/*
    - eks:cluster-name / aws:eks:cluster-name
    - aks-managed-* tags
    - gke-* labels
    """
    tags = resource.get('tags', {}) or {}

    # Check for Kubernetes-related tags
    k8s_tag_patterns = [
        'kubernetes.io/cluster/',
        'eks:cluster-name',
        'aws:eks:cluster-name',
        'alpha.eksctl.io/cluster-name',
        'eksctl.cluster.k8s.io/',
        'KubernetesCluster',
        'k8s.io/cluster-autoscaler/',
        'aks-managed-',
        'kubernetes.azure.com/',
        'gke-',
        'cloud.google.com/gke-',
    ]

    for tag_key in tags.keys():
        for pattern in k8s_tag_patterns:
            if pattern in tag_key:
                return True

    # Also check instance name patterns
    name = (resource.get('name', '') or '').lower()
    if any(p in name for p in ['eks-node', 'k8s-node', 'kubernetes-node', '-worker', '-node-']):
        # Additional check: must have k8s-related metadata or be near a cluster
        if any('kube' in k.lower() or 'eks' in k.lower() for k in tags.keys()):
            return True

    return False


def categorize_resources(resources: List[Dict]) -> Dict[str, Dict[str, Any]]:
    """
    Categorize resources by workload type.

    Note:
    - EC2 instances that are K8s worker nodes are categorized under 'Kubernetes/Containers'
    - EBS volumes attached to EC2 instances are counted under the VM's category
    - Unattached volumes remain under 'Block Storage (Unattached)'
    """
    categories: Dict[str, Dict[str, Any]] = {}

    # Build lookup of volumes by ID for efficient access
    volume_by_id: Dict[str, Dict] = {}
    for r in resources:
        if r.get('resource_type') == 'aws:ec2:volume':
            volume_by_id[r.get('resource_id', '')] = r

    # Track which volumes are attached to instances (to avoid double-counting)
    attached_volume_ids: set = set()

    # First pass: Process EC2 instances and calculate their storage
    for r in resources:
        rtype = r.get('resource_type', '')

        if rtype == 'aws:ec2:instance':
            # Get attached volumes
            meta = r.get('metadata', {}) or {}
            attached_vols = meta.get('attached_volumes', [])

            # Calculate total storage from attached volumes
            vm_storage_gb = 0
            for vol_id in attached_vols:
                if vol_id in volume_by_id:
                    vm_storage_gb += volume_by_id[vol_id].get('size_gb', 0) or 0
                    attached_volume_ids.add(vol_id)

            # Check if this is a K8s node
            if _is_kubernetes_node(r):
                category = 'Kubernetes/Containers'
            else:
                category = 'Virtual Machines'

            if category not in categories:
                categories[category] = {'count': 0, 'size_gb': 0, 'resources': []}
            categories[category]['count'] += 1
            categories[category]['size_gb'] += vm_storage_gb
            categories[category]['resources'].append(r)

        elif rtype == 'azure:vm':
            # Azure VMs - similar logic for attached disks
            meta = r.get('metadata', {}) or {}
            attached_disks = meta.get('attached_disks', [])
            vm_storage_gb = r.get('size_gb', 0) or 0
            for disk_id in attached_disks:
                if disk_id in volume_by_id:
                    vm_storage_gb += volume_by_id[disk_id].get('size_gb', 0) or 0
                    attached_volume_ids.add(disk_id)

            # Check if this is a K8s node
            if _is_kubernetes_node(r):
                category = 'Kubernetes/Containers'
            else:
                category = 'Virtual Machines'

            if category not in categories:
                categories[category] = {'count': 0, 'size_gb': 0, 'resources': []}
            categories[category]['count'] += 1
            categories[category]['size_gb'] += vm_storage_gb
            categories[category]['resources'].append(r)

        elif rtype == 'gcp:compute:instance':
            # GCP instances
            meta = r.get('metadata', {}) or {}
            attached_disks = meta.get('attached_disks', []) or meta.get('disks', [])
            vm_storage_gb = r.get('size_gb', 0) or 0
            for disk_id in attached_disks:
                if disk_id in volume_by_id:
                    vm_storage_gb += volume_by_id[disk_id].get('size_gb', 0) or 0
                    attached_volume_ids.add(disk_id)

            # Check if this is a K8s node
            if _is_kubernetes_node(r):
                category = 'Kubernetes/Containers'
            else:
                category = 'Virtual Machines'

            if category not in categories:
                categories[category] = {'count': 0, 'size_gb': 0, 'resources': []}
            categories[category]['count'] += 1
            categories[category]['size_gb'] += vm_storage_gb
            categories[category]['resources'].append(r)

    # Second pass: Process remaining resources
    for r in resources:
        rtype = r.get('resource_type', '')

        # Skip EC2/VM instances (already processed)
        if rtype in ['aws:ec2:instance', 'azure:vm', 'gcp:compute:instance']:
            continue

        # Skip database read replicas - they replicate from primary, don't backup separately
        meta = r.get('metadata', {}) or {}
        if rtype in ['aws:rds:instance', 'azure:sql:database', 'gcp:sql:instance']:
            if meta.get('is_read_replica'):
                # Track separately for reporting purposes
                if 'Read Replicas (excluded)' not in categories:
                    categories['Read Replicas (excluded)'] = {'count': 0, 'size_gb': 0, 'resources': []}
                categories['Read Replicas (excluded)']['count'] += 1
                categories['Read Replicas (excluded)']['size_gb'] += r.get('size_gb', 0) or 0
                categories['Read Replicas (excluded)']['resources'].append(r)
                continue

        # For block storage, only count unattached volumes
        if rtype in ['aws:ec2:volume', 'azure:disk', 'gcp:compute:disk']:
            if r.get('resource_id', '') in attached_volume_ids:
                continue  # Already counted under VMs
            category = 'Block Storage (Unattached)'
        else:
            category = get_workload_category(rtype)

        if category not in categories:
            categories[category] = {'count': 0, 'size_gb': 0, 'resources': []}
        categories[category]['count'] += 1
        categories[category]['size_gb'] += r.get('size_gb', 0) or 0
        categories[category]['resources'].append(r)

    return categories


def analyze_protection_status(resources: List[Dict]) -> Dict[str, Any]:
    """
    Analyze protection coverage across resources.

    Protection is determined by:
    - AWS Backup: backup_plan metadata or aws:backup:source-resource tag on snapshots
    - Snapshots: Existence of recent snapshots (within 30 days) for volumes
    - DLM: aws:dlm:lifecycle-policy-id tag on snapshots
    - RDS: Automated backup retention > 0
    - Azure: Protected item resources (azure:backup:protecteditem) with source_resource_id
    """
    # Identify protectable resources (exclude snapshots, backup plans, etc.)
    protectable_types = []
    for config in WORKLOAD_CATEGORIES.values():
        protectable_types.extend(config['types'])

    # Filter protectable resources, excluding read replicas (they replicate from primary)
    def is_protectable(r: Dict) -> bool:
        rtype = r.get('resource_type')
        if rtype not in protectable_types:
            return False
        # Exclude database read replicas across all cloud providers
        if rtype in ['aws:rds:instance', 'azure:sql:database', 'gcp:sql:instance']:
            meta = r.get('metadata', {}) or {}
            if meta.get('is_read_replica'):
                return False
        return True

    protectable = [r for r in resources if is_protectable(r)]

    # Build snapshot lookup: volume_id -> list of snapshots
    # Also track which resources have AWS Backup or DLM protection
    from datetime import datetime, timedelta
    now = datetime.now().astimezone()
    thirty_days_ago = now - timedelta(days=30)

    aws_backup_protected_vols: set = set()
    dlm_protected_vols: set = set()
    recent_snapshot_vols: set = set()  # Volumes with snapshots in last 30 days
    rds_automated_backup_dbs: set = set()  # RDS databases with automated backups
    azure_protected_resources: set = set()  # Azure resources protected by Recovery Services vault
    azure_protected_names: set = set()  # Fallback: extracted resource names from protected items
    azure_protected_sub_name: set = set()  # Fallback: (subscription, resource_name) pairs

    # Build Azure protected resource index from protected items
    for r in resources:
        if r.get('resource_type') == 'azure:backup:protecteditem':
            meta = r.get('metadata', {}) or {}
            source_id = meta.get('source_resource_id', '')
            if source_id:
                # Normalize to lowercase for case-insensitive matching
                azure_protected_resources.add(source_id.lower())
                # Also extract resource name for fallback matching (last path component)
                # e.g., /subscriptions/.../virtualMachines/my-vm -> my-vm
                parts = source_id.lower().split('/')
                if len(parts) > 1:
                    azure_protected_names.add(parts[-1])
                    # Also track subscription+name pair (handles resource group hash inconsistency)
                    if 'subscriptions' in parts:
                        sub_idx = parts.index('subscriptions') + 1
                        if sub_idx < len(parts):
                            azure_protected_sub_name.add((parts[sub_idx], parts[-1]))

    for r in resources:
        rtype = r.get('resource_type', '')
        if rtype == 'aws:ec2:snapshot':
            tags = r.get('tags', {}) or {}
            meta = r.get('metadata', {}) or {}
            vol_id = meta.get('volume_id') or r.get('parent_resource_id')

            if vol_id:
                # Check for AWS Backup
                if tags.get('aws:backup:source-resource'):
                    aws_backup_protected_vols.add(vol_id)

                # Check for DLM
                if tags.get('aws:dlm:lifecycle-policy-id'):
                    dlm_protected_vols.add(vol_id)

                # Check if recent
                start_time = meta.get('start_time', '')
                if start_time:
                    try:
                        dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                        if dt > thirty_days_ago:
                            recent_snapshot_vols.add(vol_id)
                    except Exception:
                        pass

        elif rtype in ['aws:rds:snapshot', 'aws:rds:cluster-snapshot']:
            tags = r.get('tags', {}) or {}
            meta = r.get('metadata', {}) or {}
            db_id = meta.get('db_instance_id') or meta.get('db_cluster_id') or r.get('parent_resource_id')
            if db_id:
                # Check for AWS Backup
                if tags.get('aws:backup:source-resource'):
                    aws_backup_protected_vols.add(db_id)
                # Check for automated RDS snapshots (indicates backup retention is enabled)
                if meta.get('snapshot_type') == 'automated':
                    rds_automated_backup_dbs.add(db_id)

    # Build volume-to-instance mapping for EC2
    instance_volumes: Dict[str, List[str]] = {}  # instance_id -> [vol_ids]
    volume_to_instance: Dict[str, str] = {}  # vol_id -> instance_id

    for r in resources:
        if r.get('resource_type') == 'aws:ec2:instance':
            inst_id = r.get('resource_id')
            meta = r.get('metadata', {}) or {}
            vols = meta.get('attached_volumes', [])
            if inst_id and vols:
                instance_volumes[inst_id] = vols
                for v in vols:
                    volume_to_instance[v] = inst_id

    # Calculate protection status
    protected = []
    unprotected = []

    for r in protectable:
        rtype = r.get('resource_type', '')
        metadata = r.get('metadata', {}) or {}
        tags = r.get('tags', {}) or {}
        rid = r.get('resource_id', '')

        is_protected = False

        # Check direct protection indicators
        if metadata.get('backup_plan'):
            is_protected = True
        elif metadata.get('recovery_vault'):
            is_protected = True
        elif tags.get('aws:backup:source-resource'):
            is_protected = True
        elif metadata.get('protected_by'):
            is_protected = True

        # Check Azure protected items index (cross-reference by resource_id or name)
        elif rtype.startswith('azure:') and rid:
            if rid.lower() in azure_protected_resources:
                is_protected = True
            else:
                # Fallback: match by subscription + resource name (handles resource group hash inconsistency)
                rid_parts = rid.lower().split('/')
                if len(rid_parts) > 1:
                    # Try subscription+name matching first (more precise than name-only)
                    if 'subscriptions' in rid_parts:
                        sub_idx = rid_parts.index('subscriptions') + 1
                        if sub_idx < len(rid_parts):
                            sub_name_key = (rid_parts[sub_idx], rid_parts[-1])
                            if sub_name_key in azure_protected_sub_name:
                                is_protected = True
                    # Last resort: name-only matching
                    if not is_protected and rid_parts[-1] in azure_protected_names:
                        is_protected = True

        # For EC2 volumes, check snapshot coverage
        elif rtype == 'aws:ec2:volume':
            if rid in aws_backup_protected_vols:
                is_protected = True
            elif rid in dlm_protected_vols:
                is_protected = True
            elif rid in recent_snapshot_vols:
                is_protected = True

        # For EC2 instances, check if ALL attached volumes are protected
        elif rtype == 'aws:ec2:instance':
            attached = metadata.get('attached_volumes', [])
            if attached:
                protected_vols = sum(1 for v in attached if
                                    v in aws_backup_protected_vols or
                                    v in dlm_protected_vols or
                                    v in recent_snapshot_vols)
                if protected_vols == len(attached):
                    is_protected = True
                elif protected_vols > 0:
                    # Partially protected - still count as protected but note it
                    is_protected = True
                    f'Partial ({protected_vols}/{len(attached)} volumes)'

        # For RDS, check backup retention or presence of automated snapshots
        elif rtype in ['aws:rds:instance', 'aws:rds:cluster']:
            # Get the DB identifier (could be resource_id or name)
            db_identifier = rid or r.get('name', '')

            retention = metadata.get('backup_retention_period', 0)
            if retention and retention > 0:
                is_protected = True
            elif rid in aws_backup_protected_vols:
                is_protected = True
            elif db_identifier in rds_automated_backup_dbs:
                is_protected = True
            else:
                # Check by name match (snapshot db_instance_id might match name not resource_id)
                name = r.get('name', '')
                if name and name in rds_automated_backup_dbs:
                    is_protected = True

        if is_protected:
            protected.append(r)
        else:
            unprotected.append(r)

    # Calculate totals
    total_protectable_size = sum(r.get('size_gb', 0) or 0 for r in protectable)
    protected_size = sum(r.get('size_gb', 0) or 0 for r in protected)
    unprotected_size = sum(r.get('size_gb', 0) or 0 for r in unprotected)

    return {
        'total_protectable': len(protectable),
        'protected_count': len(protected),
        'unprotected_count': len(unprotected),
        'protected_resources': protected,
        'unprotected_resources': unprotected,
        'total_size_gb': total_protectable_size,
        'protected_size_gb': protected_size,
        'unprotected_size_gb': unprotected_size,
        'coverage_percent': (len(protected) / len(protectable) * 100) if protectable else 0,
    }


def analyze_regions(resources: List[Dict]) -> Dict[str, Dict[str, Any]]:
    """Analyze resource distribution by region."""
    regions: Dict[str, Dict[str, Any]] = {}

    for r in resources:
        region = r.get('region', 'unknown')
        provider = get_provider(r.get('resource_type', ''))

        if region not in regions:
            regions[region] = {
                'count': 0,
                'size_gb': 0,
                'providers': set(),
                'types': {}
            }

        regions[region]['count'] += 1
        regions[region]['size_gb'] += r.get('size_gb', 0) or 0
        regions[region]['providers'].add(provider)

        rtype = r.get('resource_type', 'unknown')
        if rtype not in regions[region]['types']:
            regions[region]['types'][rtype] = 0
        regions[region]['types'][rtype] += 1

    # Convert sets to lists for JSON compatibility
    for region in regions:
        regions[region]['providers'] = list(regions[region]['providers'])

    return regions


def analyze_accounts(resources: List[Dict]) -> Dict[str, Dict[str, Any]]:
    """Analyze resources by account/subscription."""
    accounts: Dict[str, Dict[str, Any]] = {}

    for r in resources:
        # Use account_id (AWS) or subscription_id (Azure) or 'unknown'
        account = r.get('account_id') or r.get('subscription_id') or 'unknown'
        provider = get_provider(r.get('resource_type', ''))
        rtype = r.get('resource_type', 'unknown')
        size = r.get('size_gb', 0) or 0

        if account not in accounts:
            accounts[account] = {
                'count': 0,
                'size_gb': 0,
                'provider': '',
                'regions': set(),
                'types': {},
                'type_sizes': {}  # Track size per type
            }

        accounts[account]['count'] += 1
        accounts[account]['size_gb'] += size
        accounts[account]['provider'] = provider
        accounts[account]['regions'].add(r.get('region', 'unknown'))

        if rtype not in accounts[account]['types']:
            accounts[account]['types'][rtype] = 0
            accounts[account]['type_sizes'][rtype] = 0
        accounts[account]['types'][rtype] += 1
        accounts[account]['type_sizes'][rtype] += size

    # Convert sets to lists
    for account in accounts:
        accounts[account]['regions'] = list(accounts[account]['regions'])

    return accounts


def get_snapshots(resources: List[Dict]) -> List[Dict]:
    """Extract snapshot resources."""
    snapshot_types = [
        'aws:ec2:snapshot', 'aws:rds:snapshot', 'aws:rds:cluster-snapshot',
        'azure:snapshot', 'azure:disk:snapshot',
        'gcp:compute:snapshot',
    ]
    return [r for r in resources if r.get('resource_type') in snapshot_types]


def analyze_snapshots(resources: List[Dict]) -> Dict[str, Any]:
    """Analyze snapshot inventory."""
    snapshots = get_snapshots(resources)

    total_size = sum(s.get('size_gb', 0) or 0 for s in snapshots)

    # Group by type
    by_type = defaultdict(lambda: {'count': 0, 'size_gb': 0})
    for s in snapshots:
        rtype = s.get('resource_type', 'unknown')
        by_type[rtype]['count'] += 1
        by_type[rtype]['size_gb'] += s.get('size_gb', 0) or 0

    return {
        'total_count': len(snapshots),
        'total_size_gb': total_size,
        'by_type': dict(by_type),
        'snapshots': snapshots,
    }


def analyze_snapshot_patterns(resources: List[Dict]) -> Dict[str, Any]:
    """
    Analyze snapshot patterns to identify automated backups outside AWS Backup.

    Detects:
    - AWS Backup managed snapshots
    - DLM (Data Lifecycle Manager) managed snapshots
    - Script-based automated backups (daily/weekly/monthly patterns)
    - AMI artifacts
    - Cross-region/account copies
    - Manual/ad-hoc snapshots

    Returns detailed analysis for reporting.
    """
    ebs_snapshots = [r for r in resources if r.get('resource_type') == 'aws:ec2:snapshot']
    rds_snapshots = [r for r in resources if r.get('resource_type') in
                    ['aws:rds:snapshot', 'aws:rds:cluster-snapshot']]

    if not ebs_snapshots and not rds_snapshots:
        return {'has_data': False}

    # Categorize EBS snapshots by source
    categories = {
        'aws_backup': [],
        'dlm': [],
        'script_daily': [],
        'script_weekly': [],
        'script_monthly': [],
        'script_other': [],
        'ami_artifact': [],
        'cross_copy': [],
        'manual': [],
    }

    # Track description patterns for automated detection
    desc_patterns: Dict[str, int] = {}
    dlm_policies: Dict[str, Dict[str, Any]] = {}

    for s in ebs_snapshots:
        desc = (s.get('metadata', {}) or {}).get('description', '') or ''
        tags = s.get('tags', {}) or {}
        desc_lower = desc.lower()

        # Categorize by source
        if 'aws backup' in desc_lower or tags.get('aws:backup:source-resource'):
            categories['aws_backup'].append(s)
        elif tags.get('aws:dlm:lifecycle-policy-id'):
            categories['dlm'].append(s)
            # Track DLM policy details
            policy_id = tags.get('aws:dlm:lifecycle-policy-id')
            if policy_id:
                if policy_id not in dlm_policies:
                    dlm_policies[policy_id] = {
                        'count': 0,
                        'size_gb': 0,
                        'schedule_name': tags.get('aws:dlm:lifecycle-schedule-name', 'Unknown'),
                    }
                dlm_policies[policy_id]['count'] += 1
                dlm_policies[policy_id]['size_gb'] += s.get('size_gb', 0) or 0
        elif 'createimage' in desc_lower or 'for ami-' in desc_lower or 'destinationami' in desc_lower:
            categories['ami_artifact'].append(s)
        elif 'copied' in desc_lower:
            categories['cross_copy'].append(s)
        elif 'daily' in desc_lower:
            categories['script_daily'].append(s)
            _track_pattern(desc, desc_patterns)
        elif 'weekly' in desc_lower:
            categories['script_weekly'].append(s)
            _track_pattern(desc, desc_patterns)
        elif 'monthly' in desc_lower:
            categories['script_monthly'].append(s)
            _track_pattern(desc, desc_patterns)
        elif 'hourly' in desc_lower or 'backup' in desc_lower or 'snapshot' in desc_lower:
            # Likely automated but not explicit schedule
            categories['script_other'].append(s)
            _track_pattern(desc, desc_patterns)
        elif desc:
            # Has description but doesn't match patterns - could be manual or custom
            categories['manual'].append(s)
            _track_pattern(desc, desc_patterns)
        else:
            categories['manual'].append(s)

    # Build list of non-AWS-Backup/AMI snapshots for schedule analysis
    # Use IDs from categories instead of expensive list membership check
    non_backup = (categories['dlm'] + categories['script_daily'] + categories['script_weekly'] +
                  categories['script_monthly'] + categories['script_other'] +
                  categories['cross_copy'] + categories['manual'])
    schedule_analysis = _analyze_schedule_times(non_backup)

    # Analyze retention/age distribution
    retention_analysis = _analyze_retention(ebs_snapshots)

    # Analyze RDS snapshots
    rds_analysis = _analyze_rds_snapshots(rds_snapshots)

    # Calculate totals
    total_script_based = (len(categories['script_daily']) + len(categories['script_weekly']) +
                          len(categories['script_monthly']) + len(categories['script_other']))

    return {
        'has_data': True,
        'total_ebs_snapshots': len(ebs_snapshots),
        'total_rds_snapshots': len(rds_snapshots),
        'categories': {k: len(v) for k, v in categories.items()},
        'category_sizes': {k: sum(s.get('size_gb', 0) or 0 for s in v) for k, v in categories.items()},
        'total_script_based': total_script_based,
        'dlm_policies': dlm_policies,
        'desc_patterns': desc_patterns,
        'schedule_analysis': schedule_analysis,
        'retention_analysis': retention_analysis,
        'rds_analysis': rds_analysis,
    }


def _track_pattern(desc: str, patterns: Dict[str, int]) -> None:
    """Track description pattern, normalizing IDs."""
    # Normalize resource IDs for pattern matching
    normalized = re.sub(r'vol-[a-f0-9]+', 'vol-xxx', desc)
    normalized = re.sub(r'i-[a-f0-9]+', 'i-xxx', normalized)
    normalized = re.sub(r'snap-[a-f0-9]+', 'snap-xxx', normalized)
    normalized = re.sub(r'ami-[a-f0-9]+', 'ami-xxx', normalized)
    # Truncate long descriptions
    if len(normalized) > 100:
        normalized = normalized[:97] + '...'
    patterns[normalized] = patterns.get(normalized, 0) + 1


def _analyze_schedule_times(snapshots: List[Dict]) -> Dict[str, Any]:
    """Analyze creation times to detect scheduling patterns."""
    from collections import Counter

    hour_dist = Counter()
    dow_dist = Counter()

    for s in snapshots:
        meta = s.get('metadata', {}) or {}
        start_time = meta.get('start_time', '')
        if start_time:
            try:
                dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                hour_dist[dt.hour] += 1
                dow_dist[dt.strftime('%A')] += 1
            except Exception:
                pass

    # Find peak hours (likely scheduled times)
    total_with_time = sum(hour_dist.values())

    # Calculate percentages for peak hours
    peak_hours = []
    for hour, count in hour_dist.most_common(5):
        pct = (count / total_with_time * 100) if total_with_time else 0
        peak_hours.append((hour, pct))

    # Calculate percentages for day of week
    dow_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    dow_distribution = []
    for day in dow_order:
        count = dow_dist.get(day, 0)
        pct = (count / total_with_time * 100) if total_with_time else 0
        if count > 0:
            dow_distribution.append((day, pct))

    # Detect if there's a clear schedule (>30% in one hour = automated)
    likely_scheduled = False
    schedule_time = None
    if peak_hours and total_with_time > 0:
        top_hour, top_pct = peak_hours[0]
        if top_pct > 30:
            likely_scheduled = True
            schedule_time = f"{top_hour:02d}:00 UTC"

    return {
        'total_analyzed': total_with_time,
        'hour_distribution': dict(hour_dist),
        'day_distribution': dict(dow_dist),
        'peak_hours': peak_hours,
        'dow_distribution': dow_distribution,
        'likely_scheduled': likely_scheduled,
        'detected_schedule_time': schedule_time,
    }


def _analyze_retention(snapshots: List[Dict]) -> Dict[str, Any]:
    """Analyze snapshot ages to understand retention patterns."""
    now = datetime.now().astimezone()
    ages = []

    for s in snapshots:
        meta = s.get('metadata', {}) or {}
        start_time = meta.get('start_time', '')
        if start_time:
            try:
                dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                age = (now - dt).days
                if age >= 0:
                    ages.append(age)
            except Exception:
                pass

    if not ages:
        return {}

    # Age buckets matching what generate_snapshot_analysis expects
    under_7_days = sum(1 for a in ages if a < 7)
    _7_to_14_days = sum(1 for a in ages if 7 <= a < 14)
    _14_to_30_days = sum(1 for a in ages if 14 <= a < 30)
    _30_to_90_days = sum(1 for a in ages if 30 <= a < 90)
    _90_to_365_days = sum(1 for a in ages if 90 <= a < 365)
    over_365_days = sum(1 for a in ages if a >= 365)

    # Infer retention policy from distribution
    inferred_policies = []
    total = len(ages)
    if total > 0:
        if _7_to_14_days / total > 0.15:
            inferred_policies.append("~7 day retention (daily backups)")
        if _14_to_30_days / total > 0.15:
            inferred_policies.append("~14-30 day retention (weekly)")
        if _30_to_90_days / total > 0.10:
            inferred_policies.append("~30-90 day retention (monthly)")
        if over_365_days / total > 0.10:
            inferred_policies.append("Long-term/no deletion (>1 year old snapshots)")

    return {
        'under_7_days': under_7_days,
        '7_to_14_days': _7_to_14_days,
        '14_to_30_days': _14_to_30_days,
        '30_to_90_days': _30_to_90_days,
        '90_to_365_days': _90_to_365_days,
        'over_365_days': over_365_days,
        'oldest_days': max(ages),
        'newest_days': min(ages),
        'average_age': sum(ages) / len(ages),
        'inferred_policies': inferred_policies,
    }


def _analyze_rds_snapshots(snapshots: List[Dict]) -> Dict[str, Any]:
    """Analyze RDS snapshot patterns."""
    if not snapshots:
        return {'has_data': False}

    # Categorize by snapshot type
    automated = []
    manual = []
    aws_backup = []

    for s in snapshots:
        meta = s.get('metadata', {}) or {}
        snap_type = meta.get('snapshot_type', '')

        if snap_type == 'automated':
            automated.append(s)
        elif snap_type == 'awsbackup':
            aws_backup.append(s)
        else:
            manual.append(s)

    return {
        'has_data': True,
        'total': len(snapshots),
        'automated': len(automated),
        'automated_size_gb': sum(s.get('size_gb', 0) or 0 for s in automated),
        'manual': len(manual),
        'manual_size_gb': sum(s.get('size_gb', 0) or 0 for s in manual),
        'aws_backup': len(aws_backup),
        'aws_backup_size_gb': sum(s.get('size_gb', 0) or 0 for s in aws_backup),
    }



def _get_region_group(region: str) -> tuple:
    """
    Group cloud regions by geographic proximity for cluster placement.
    Returns (group_name, preferred_region) tuple.
    """
    # AWS region groupings
    AWS_GROUPS = {
        # US regions
        'us-east-1': ('US East', 'us-east-1'),
        'us-east-2': ('US East', 'us-east-1'),
        'us-west-1': ('US West', 'us-west-2'),
        'us-west-2': ('US West', 'us-west-2'),
        # Europe regions
        'eu-west-1': ('Europe West', 'eu-west-1'),
        'eu-west-2': ('Europe West', 'eu-west-1'),
        'eu-west-3': ('Europe West', 'eu-west-1'),
        'eu-central-1': ('Europe Central', 'eu-central-1'),
        'eu-central-2': ('Europe Central', 'eu-central-1'),
        'eu-north-1': ('Europe North', 'eu-north-1'),
        'eu-south-1': ('Europe South', 'eu-south-1'),
        # Asia Pacific
        'ap-northeast-1': ('Asia Pacific NE', 'ap-northeast-1'),
        'ap-northeast-2': ('Asia Pacific NE', 'ap-northeast-1'),
        'ap-northeast-3': ('Asia Pacific NE', 'ap-northeast-1'),
        'ap-southeast-1': ('Asia Pacific SE', 'ap-southeast-1'),
        'ap-southeast-2': ('Asia Pacific SE', 'ap-southeast-2'),
        'ap-southeast-3': ('Asia Pacific SE', 'ap-southeast-1'),
        'ap-south-1': ('Asia Pacific South', 'ap-south-1'),
        'ap-south-2': ('Asia Pacific South', 'ap-south-1'),
        # Other
        'ca-central-1': ('Canada', 'ca-central-1'),
        'sa-east-1': ('South America', 'sa-east-1'),
        'me-south-1': ('Middle East', 'me-south-1'),
        'af-south-1': ('Africa', 'af-south-1'),
    }

    # Azure region groupings (normalize to lowercase)
    AZURE_GROUPS = {
        'eastus': ('US East', 'eastus'),
        'eastus2': ('US East', 'eastus'),
        'westus': ('US West', 'westus2'),
        'westus2': ('US West', 'westus2'),
        'westus3': ('US West', 'westus2'),
        'centralus': ('US Central', 'centralus'),
        'northcentralus': ('US Central', 'centralus'),
        'southcentralus': ('US Central', 'centralus'),
        'westeurope': ('Europe West', 'westeurope'),
        'northeurope': ('Europe West', 'northeurope'),
        'uksouth': ('UK', 'uksouth'),
        'ukwest': ('UK', 'uksouth'),
    }

    # GCP region groupings
    GCP_GROUPS = {
        'us-east1': ('US East', 'us-east1'),
        'us-east4': ('US East', 'us-east1'),
        'us-east5': ('US East', 'us-east1'),
        'us-west1': ('US West', 'us-west1'),
        'us-west2': ('US West', 'us-west1'),
        'us-west3': ('US West', 'us-west1'),
        'us-west4': ('US West', 'us-west1'),
        'us-central1': ('US Central', 'us-central1'),
        'europe-west1': ('Europe West', 'europe-west1'),
        'europe-west2': ('Europe West', 'europe-west1'),
        'europe-west3': ('Europe West', 'europe-west1'),
        'europe-west4': ('Europe West', 'europe-west1'),
    }

    region_lower = region.lower()

    # Check each mapping
    if region in AWS_GROUPS:
        return AWS_GROUPS[region]
    if region_lower in AZURE_GROUPS:
        return AZURE_GROUPS[region_lower]
    if region_lower in GCP_GROUPS:
        return GCP_GROUPS[region_lower]

    # Default: use region as its own group
    return (region, region)


def _get_db_engine_group(resource: Dict) -> Optional[str]:
    """
    Get the normalized database engine group for a resource.
    Returns None if not a database resource.
    """
    rtype = resource.get('resource_type', '')
    meta = resource.get('metadata', {}) or {}

    # Skip read replicas
    if meta.get('is_read_replica'):
        return None

    # Skip DataWarehouse tier Azure SQL databases - they're Synapse dedicated SQL pools
    # and are counted separately as azure:synapse:sqlpool
    if rtype == 'azure:sql:database' and meta.get('tier') == 'DataWarehouse':
        return None

    # Determine raw engine
    engine = None
    if rtype in ['aws:rds:instance', 'aws:rds:cluster']:
        engine = meta.get('engine', 'Unknown')
    elif rtype == 'azure:sql:database':
        engine = 'SQL Server'
    elif rtype == 'azure:sql:managedinstance':
        engine = 'SQL Server'
    elif rtype == 'azure:cosmosdb:account':
        engine = 'Cosmos DB'
    elif rtype in ['azure:mysql:flexibleserver', 'azure:mysql:server']:
        engine = 'MySQL'
    elif rtype in ['azure:postgresql:flexibleserver', 'azure:postgresql:server']:
        engine = 'PostgreSQL'
    elif rtype == 'azure:mariadb:server':
        engine = 'MariaDB'
    elif rtype == 'gcp:sql:instance':
        db_version = meta.get('database_version', '')
        if 'MYSQL' in db_version.upper():
            engine = 'MySQL'
        elif 'POSTGRES' in db_version.upper():
            engine = 'PostgreSQL'
        elif 'SQLSERVER' in db_version.upper():
            engine = 'SQL Server'
        else:
            engine = db_version or 'Unknown'
    elif rtype == 'aws:dynamodb:table':
        return 'DB: DynamoDB'
    elif rtype == 'aws:neptune:cluster':
        return 'DB: Neptune'
    elif rtype == 'aws:docdb:cluster':
        return 'DB: DocumentDB'
    elif rtype == 'aws:redshift:cluster':
        return 'DB: Redshift'
    elif rtype in ['azure:synapse:workspace', 'azure:synapse:sqlpool']:
        return 'DB: Synapse'
    elif rtype == 'gcp:bigtable:instance':
        return 'DB: BigTable'
    elif rtype == 'gcp:spanner:instance':
        return 'DB: Spanner'
    else:
        return None  # Not a database

    # Normalize to engine groups
    engine_lower = engine.lower()
    if 'mysql' in engine_lower or 'mariadb' in engine_lower or 'aurora-mysql' in engine_lower:
        return 'DB: MySQL/MariaDB'
    elif 'postgres' in engine_lower or 'aurora-postgresql' in engine_lower:
        return 'DB: PostgreSQL'
    elif 'sqlserver' in engine_lower or 'sql server' in engine_lower:
        return 'DB: SQL Server'
    elif 'oracle' in engine_lower:
        return 'DB: Oracle'
    elif 'cosmos' in engine_lower:
        return 'DB: Cosmos DB'
    elif 'docdb' in engine_lower or 'documentdb' in engine_lower:
        return 'DB: DocumentDB'
    elif 'neptune' in engine_lower:
        return 'DB: Neptune'
    elif 'dynamodb' in engine_lower:
        return 'DB: DynamoDB'
    else:
        return f'DB: {engine}'


