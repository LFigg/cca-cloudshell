#!/usr/bin/env python3
"""
Generate a Protection Report Excel file from inventory.json

Creates an Excel workbook with:
- Summary tab: High-level statistics, counts, and sizes
- Protection Report tab: Detailed Instance → Volume → Snapshot hierarchy
- Backup Plans tab: All backup plans with rule details
- Backup Selections tab: Resources assigned to backup plans (if any)
"""
import json
import sys
from collections import defaultdict
from typing import Dict, List, Any, Optional
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils.dataframe import dataframe_to_rows


def load_inventory(filepath: str) -> Dict[str, Any]:
    """Load inventory JSON file."""
    with open(filepath) as f:
        return json.load(f)


def build_resource_index(resources: List[Dict]) -> Dict[str, Dict]:
    """Build index of resources by resource_id for quick lookup."""
    return {r['resource_id']: r for r in resources}


def get_ec2_instances(resources: List[Dict]) -> List[Dict]:
    """Get EC2 instances."""
    return [r for r in resources if r['resource_type'] == 'aws:ec2:instance']


def get_ebs_volumes(resources: List[Dict]) -> List[Dict]:
    """Get EBS volumes."""
    return [r for r in resources if r['resource_type'] == 'aws:ec2:volume']


def get_rds_instances(resources: List[Dict]) -> List[Dict]:
    """Get RDS instances and clusters."""
    return [r for r in resources if r['resource_type'] in ['aws:rds:instance', 'aws:rds:cluster']]


def get_other_primary_resources(resources: List[Dict]) -> List[Dict]:
    """Get other primary resources (S3, EFS, DynamoDB, etc.)."""
    other_types = [
        'aws:s3:bucket',
        'aws:efs:filesystem',
        'aws:dynamodb:table',
        'azure:vm',
        'azure:disk',
        'azure:sql:database',
        'azure:storage:account',
    ]
    return [r for r in resources if r['resource_type'] in other_types]


def get_snapshots(resources: List[Dict]) -> List[Dict]:
    """Get all snapshot resources."""
    snapshot_types = [
        'aws:ec2:snapshot',
        'aws:rds:snapshot',
        'aws:rds:cluster-snapshot',
        'azure:snapshot',
    ]
    return [r for r in resources if r['resource_type'] in snapshot_types]


def get_backup_plans(resources: List[Dict]) -> List[Dict]:
    """Get backup plans/policies."""
    plan_types = [
        'aws:backup:plan',
        'aws:backup:vault',
        'azure:backup:policy',
        'azure:recoveryservices:vault',
    ]
    return [r for r in resources if r['resource_type'] in plan_types]


def get_backup_selections(resources: List[Dict]) -> List[Dict]:
    """Get backup selections (resource-to-plan assignments)."""
    return [r for r in resources if r['resource_type'] == 'aws:backup:selection']


def get_protected_resources(resources: List[Dict]) -> List[Dict]:
    """Get resources that have actual recovery points in AWS Backup."""
    return [r for r in resources if r['resource_type'] == 'aws:backup:protected-resource']


def build_backup_selection_index(selections: List[Dict]) -> Dict[str, List[str]]:
    """
    Build index of resource ARN patterns to backup plan names.
    Returns dict: resource_arn -> [backup_plan_names]
    """
    resource_to_plans: Dict[str, List[str]] = defaultdict(list)
    
    for selection in selections:
        plan_name = selection.get('metadata', {}).get('backup_plan_name', '')
        
        # Direct resource ARNs
        resource_arns = selection.get('metadata', {}).get('resources', [])
        for arn in resource_arns:
            resource_to_plans[arn].append(plan_name)
        
        # Tag-based selections (store the selection for later matching)
        list_of_tags = selection.get('metadata', {}).get('list_of_tags', [])
        if list_of_tags:
            # Store selection info for tag-based matching
            selection_key = f"__tag_selection__{selection['resource_id']}"
            resource_to_plans[selection_key] = [plan_name]
    
    return dict(resource_to_plans)


def build_protected_resources_set(protected_resources: List[Dict]) -> set:
    """Build set of resource ARNs that have recovery points."""
    return {r.get('metadata', {}).get('resource_arn', '') for r in protected_resources}


def get_backup_plan_for_resource(
    resource: Dict,
    selection_index: Dict[str, List[str]],
    protected_set: set,
    backup_plans: List[Dict]
) -> tuple:
    """
    Determine backup plan and protection source for a resource.
    
    Returns: (backup_plan_name, protection_source)
    protection_source: 'backup_selection' | 'recovery_point' | 'inferred' | None
    """
    resource_arn = resource.get('resource_id', '')
    resource_type = resource.get('resource_type', '')
    
    # Check if directly in a backup selection
    if resource_arn in selection_index:
        return (', '.join(selection_index[resource_arn]), 'backup_selection')
    
    # Check for wildcard matches in selections (e.g., arn:aws:ec2:*:*:volume/*)
    for pattern, plans in selection_index.items():
        if pattern.startswith('__tag_selection__'):
            continue
        if '*' in pattern:
            # Simple wildcard matching
            import re
            regex = pattern.replace('*', '.*')
            if re.match(regex, resource_arn):
                return (', '.join(plans), 'backup_selection')
    
    # Check if resource has recovery points (is protected)
    if resource_arn in protected_set:
        return ('(has recovery points)', 'recovery_point')
    
    return (None, None)


def infer_backup_plan(snapshot: Dict, backup_plans: List[Dict]) -> Optional[str]:
    """Try to infer which backup plan created a snapshot based on tags/metadata."""
    tags = snapshot.get('tags', {})
    metadata = snapshot.get('metadata', {})
    description = metadata.get('description', '')
    
    backup_type = tags.get('BackupType', '')
    
    for plan in backup_plans:
        plan_name = plan.get('name', '').lower()
        plan_rules = plan.get('metadata', {}).get('rule_names', [])
        
        if backup_type:
            if backup_type.lower() in plan_name:
                return plan['name']
            for rule in plan_rules:
                if backup_type.lower() in rule.lower():
                    return plan['name']
        
        if 'daily' in description.lower() and 'daily' in plan_name:
            return plan['name']
        if 'weekly' in description.lower() and 'weekly' in plan_name:
            return plan['name']
    
    if backup_type == 'daily':
        return 'daily-backup-plan (inferred)'
    elif backup_type == 'weekly':
        return 'weekly-compliance-plan (inferred)'
    
    return None


def format_tags(tags: Dict) -> str:
    """Format tags as semicolon-separated string."""
    return '; '.join(f"{k}={v}" for k, v in tags.items()) if tags else ''


def generate_report(inventory_path: str, output_path: str):
    """Generate the protection report CSV with full hierarchy."""
    data = load_inventory(inventory_path)
    resources = data['resources']
    
    # Build indexes
    resource_index = build_resource_index(resources)
    
    # Categorize resources
    ec2_instances = get_ec2_instances(resources)
    ebs_volumes = get_ebs_volumes(resources)
    rds_instances = get_rds_instances(resources)
    other_resources = get_other_primary_resources(resources)
    snapshots = get_snapshots(resources)
    backup_plans = get_backup_plans(resources)
    
    # Get backup selections and protected resources for definitive matching
    backup_selections = get_backup_selections(resources)
    protected_resources = get_protected_resources(resources)
    
    # Build indexes for fast lookup
    selection_index = build_backup_selection_index(backup_selections)
    protected_set = build_protected_resources_set(protected_resources)
    
    # Filter out AMI snapshots
    user_snapshots = [
        s for s in snapshots 
        if 'Auto-created snapshot for AMI' not in s.get('metadata', {}).get('description', '')
    ]
    
    # Build volume-to-instance mapping
    volume_to_instance = {}
    for vol in ebs_volumes:
        parent = vol.get('parent_resource_id')
        if parent and parent in resource_index:
            volume_to_instance[vol['resource_id']] = resource_index[parent]
    
    # Build snapshot-to-volume mapping
    snapshot_to_volume = {}
    for snap in user_snapshots:
        if snap['resource_type'] == 'aws:ec2:snapshot':
            parent = snap.get('parent_resource_id')
            if parent and parent in resource_index:
                snapshot_to_volume[snap['resource_id']] = resource_index[parent]
    
    rows = []
    processed_volumes = set()
    
    # Process EC2 Instances with their volumes and snapshots
    for instance in ec2_instances:
        instance_id = instance['resource_id']
        
        # Find volumes attached to this instance
        attached_volumes = [v for v in ebs_volumes if v.get('parent_resource_id') == instance_id]
        
        if attached_volumes:
            for volume in attached_volumes:
                processed_volumes.add(volume['resource_id'])
                volume_id = volume['resource_id']
                
                # Find snapshots for this volume
                volume_snapshots = [s for s in user_snapshots 
                                   if s.get('parent_resource_id') == volume_id]
                
                # Check for definitive backup plan assignment (volume or instance level)
                vol_plan, vol_source = get_backup_plan_for_resource(
                    volume, selection_index, protected_set, backup_plans
                )
                inst_plan, inst_source = get_backup_plan_for_resource(
                    instance, selection_index, protected_set, backup_plans
                )
                
                if volume_snapshots:
                    for snap in volume_snapshots:
                        # For backup_plan: prefer definitive, then snapshot inference
                        backup_plan = vol_plan or inst_plan or infer_backup_plan(snap, backup_plans) or ''
                        protection_source = vol_source or inst_source or ('inferred' if backup_plan else '')
                        
                        rows.append({
                            'instance_name': instance['name'],
                            'instance_id': instance_id,
                            'instance_region': instance['region'],
                            'instance_tags': format_tags(instance.get('tags', {})),
                            'volume_name': volume['name'],
                            'volume_id': volume_id,
                            'volume_size_gb': volume['size_gb'],
                            'snapshot_name': snap['name'],
                            'snapshot_id': snap['resource_id'],
                            'snapshot_size_gb': snap['size_gb'],
                            'snapshot_created': snap.get('metadata', {}).get('start_time', ''),
                            'snapshot_description': snap.get('metadata', {}).get('description', ''),
                            'backup_plan': backup_plan,
                            'protection_source': protection_source,
                            'protection_status': 'Protected'
                        })
                else:
                    # Volume has no snapshots - but might still be in a backup plan
                    backup_plan = vol_plan or inst_plan or ''
                    protection_source = vol_source or inst_source or ''
                    has_backup_plan = bool(backup_plan)
                    
                    rows.append({
                        'instance_name': instance['name'],
                        'instance_id': instance_id,
                        'instance_region': instance['region'],
                        'instance_tags': format_tags(instance.get('tags', {})),
                        'volume_name': volume['name'],
                        'volume_id': volume_id,
                        'volume_size_gb': volume['size_gb'],
                        'snapshot_name': '',
                        'snapshot_id': '',
                        'snapshot_size_gb': '',
                        'snapshot_created': '',
                        'snapshot_description': '',
                        'backup_plan': backup_plan,
                        'protection_source': protection_source,
                        'protection_status': 'In Backup Plan' if has_backup_plan else 'Unprotected'
                    })
        else:
            # Instance has no attached volumes - check if instance itself is in backup
            inst_plan, inst_source = get_backup_plan_for_resource(
                instance, selection_index, protected_set, backup_plans
            )
            rows.append({
                'instance_name': instance['name'],
                'instance_id': instance_id,
                'instance_region': instance['region'],
                'instance_tags': format_tags(instance.get('tags', {})),
                'volume_name': '(no volumes)',
                'volume_id': '',
                'volume_size_gb': '',
                'snapshot_name': '',
                'snapshot_id': '',
                'snapshot_size_gb': '',
                'snapshot_created': '',
                'snapshot_description': '',
                'backup_plan': inst_plan or '',
                'protection_source': inst_source or '',
                'protection_status': 'In Backup Plan' if inst_plan else 'No Storage'
            })
    
    # Process orphan volumes (not attached to any instance)
    orphan_volumes = [v for v in ebs_volumes if v['resource_id'] not in processed_volumes]
    for volume in orphan_volumes:
        volume_id = volume['resource_id']
        volume_snapshots = [s for s in user_snapshots if s.get('parent_resource_id') == volume_id]
        
        # Check for definitive backup plan assignment
        vol_plan, vol_source = get_backup_plan_for_resource(
            volume, selection_index, protected_set, backup_plans
        )
        
        if volume_snapshots:
            for snap in volume_snapshots:
                backup_plan = vol_plan or infer_backup_plan(snap, backup_plans) or ''
                protection_source = vol_source or ('inferred' if backup_plan else '')
                
                rows.append({
                    'instance_name': '(orphan volume)',
                    'instance_id': '',
                    'instance_region': volume['region'],
                    'instance_tags': '',
                    'volume_name': volume['name'],
                    'volume_id': volume_id,
                    'volume_size_gb': volume['size_gb'],
                    'snapshot_name': snap['name'],
                    'snapshot_id': snap['resource_id'],
                    'snapshot_size_gb': snap['size_gb'],
                    'snapshot_created': snap.get('metadata', {}).get('start_time', ''),
                    'snapshot_description': snap.get('metadata', {}).get('description', ''),
                    'backup_plan': backup_plan,
                    'protection_source': protection_source,
                    'protection_status': 'Protected (orphan)'
                })
        else:
            # Orphan volume with no snapshots - check if in backup plan
            has_backup_plan = bool(vol_plan)
            rows.append({
                'instance_name': '(orphan volume)',
                'instance_id': '',
                'instance_region': volume['region'],
                'instance_tags': '',
                'volume_name': volume['name'],
                'volume_id': volume_id,
                'volume_size_gb': volume['size_gb'],
                'snapshot_name': '',
                'snapshot_id': '',
                'snapshot_size_gb': '',
                'snapshot_created': '',
                'snapshot_description': '',
                'backup_plan': vol_plan or '',
                'protection_source': vol_source or '',
                'protection_status': 'In Backup Plan (orphan)' if has_backup_plan else 'Unprotected (orphan)'
            })
    
    # Process RDS instances
    rds_snapshots = [s for s in user_snapshots if s['resource_type'] in ['aws:rds:snapshot', 'aws:rds:cluster-snapshot']]
    for rds in rds_instances:
        rds_id = rds['resource_id']
        db_identifier = rds['name']
        
        # Check for definitive backup plan assignment
        rds_plan, rds_source = get_backup_plan_for_resource(
            rds, selection_index, protected_set, backup_plans
        )
        
        # Find snapshots for this RDS
        rds_snaps = [s for s in rds_snapshots if s.get('parent_resource_id') == db_identifier]
        
        if rds_snaps:
            for snap in rds_snaps:
                backup_plan = rds_plan or infer_backup_plan(snap, backup_plans) or ''
                protection_source = rds_source or ('inferred' if backup_plan else '')
                
                rows.append({
                    'instance_name': rds['name'],
                    'instance_id': rds_id,
                    'instance_region': rds['region'],
                    'instance_tags': format_tags(rds.get('tags', {})),
                    'volume_name': f"({rds['resource_type'].split(':')[-1]} storage)",
                    'volume_id': '',
                    'volume_size_gb': rds['size_gb'],
                    'snapshot_name': snap['name'],
                    'snapshot_id': snap['resource_id'],
                    'snapshot_size_gb': snap['size_gb'],
                    'snapshot_created': snap.get('metadata', {}).get('snapshot_create_time', ''),
                    'snapshot_description': f"{snap.get('metadata', {}).get('snapshot_type', '')} snapshot",
                    'backup_plan': backup_plan,
                    'protection_source': protection_source,
                    'protection_status': 'Protected'
                })
        else:
            # RDS with no snapshots - check if in backup plan
            has_backup_plan = bool(rds_plan)
            rows.append({
                'instance_name': rds['name'],
                'instance_id': rds_id,
                'instance_region': rds['region'],
                'instance_tags': format_tags(rds.get('tags', {})),
                'volume_name': f"({rds['resource_type'].split(':')[-1]} storage)",
                'volume_id': '',
                'volume_size_gb': rds['size_gb'],
                'snapshot_name': '',
                'snapshot_id': '',
                'snapshot_size_gb': '',
                'snapshot_created': '',
                'snapshot_description': '',
                'backup_plan': rds_plan or '',
                'protection_source': rds_source or '',
                'protection_status': 'In Backup Plan' if has_backup_plan else 'Unprotected'
            })
    
    # Calculate summary statistics
    protected = len([r for r in rows if 'Protected' in r['protection_status'] or 'In Backup Plan' in r['protection_status']])
    unprotected = len([r for r in rows if 'Unprotected' in r['protection_status']])
    in_backup_plan = len([r for r in rows if 'In Backup Plan' in r['protection_status']])
    rows_with_snapshots = len([r for r in rows if r['snapshot_id']])
    
    unique_instances = len(set(r['instance_id'] for r in rows if r['instance_id']))
    unique_volumes = len(set(r['volume_id'] for r in rows if r['volume_id']))
    unique_snapshots = len(set(r['snapshot_id'] for r in rows if r['snapshot_id']))
    
    # Calculate sizes
    total_volume_size = sum(v['size_gb'] for v in ebs_volumes)
    orphan_volume_size = sum(v['size_gb'] for v in orphan_volumes)
    attached_volume_size = total_volume_size - orphan_volume_size
    total_snapshot_size = sum(s['size_gb'] for s in user_snapshots if s['resource_type'] == 'aws:ec2:snapshot')
    total_rds_size = sum(r['size_gb'] for r in rds_instances)
    total_rds_snapshot_size = sum(s['size_gb'] for s in user_snapshots if s['resource_type'] in ['aws:rds:snapshot', 'aws:rds:cluster-snapshot'])
    
    # Calculate protected vs unprotected sizes
    protected_volume_ids = set(r['volume_id'] for r in rows if r['volume_id'] and 'Protected' in r['protection_status'])
    unprotected_volume_ids = set(r['volume_id'] for r in rows if r['volume_id'] and 'Unprotected' in r['protection_status'])
    protected_volume_size = sum(v['size_gb'] for v in ebs_volumes if v['resource_id'] in protected_volume_ids)
    unprotected_volume_size = sum(v['size_gb'] for v in ebs_volumes if v['resource_id'] in unprotected_volume_ids)
    
    # Create Excel workbook
    wb = Workbook()
    
    # --- Summary Sheet ---
    ws_summary = wb.active
    assert ws_summary is not None, "Workbook must have an active sheet"
    ws_summary.title = "Summary"
    
    # Styles
    header_font = Font(bold=True, size=14)
    section_font = Font(bold=True, size=12)
    header_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
    header_font_white = Font(bold=True, color="FFFFFF")
    thin_border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
    )
    
    # Title
    ws_summary['A1'] = "Protection Report Summary"
    ws_summary['A1'].font = Font(bold=True, size=16)
    ws_summary.merge_cells('A1:D1')
    
    # Account info
    ws_summary['A3'] = "Account ID:"
    ws_summary['B3'] = data.get('account_id', 'N/A')
    ws_summary['A4'] = "Provider:"
    ws_summary['B4'] = data.get('provider', 'N/A')
    ws_summary['A5'] = "Report Generated:"
    ws_summary['B5'] = data.get('timestamp', 'N/A')
    
    # Resource counts section
    ws_summary['A7'] = "Resource Inventory"
    ws_summary['A7'].font = section_font
    
    summary_data = [
        ["Resource Type", "Count", "Size (GB)", "Notes"],
        ["EC2 Instances", len(ec2_instances), "", ""],
        ["EBS Volumes (Total)", len(ebs_volumes), f"{total_volume_size:,.1f}", ""],
        ["  - Attached Volumes", len(ebs_volumes) - len(orphan_volumes), f"{attached_volume_size:,.1f}", ""],
        ["  - Orphan Volumes", len(orphan_volumes), f"{orphan_volume_size:,.1f}", "Detached from instances"],
        ["EBS Snapshots", len([s for s in user_snapshots if s['resource_type'] == 'aws:ec2:snapshot']), f"{total_snapshot_size:,.1f}", ""],
        ["RDS Databases", len(rds_instances), f"{total_rds_size:,.1f}", "Allocated storage"],
        ["RDS Snapshots", len([s for s in user_snapshots if s['resource_type'] in ['aws:rds:snapshot', 'aws:rds:cluster-snapshot']]), f"{total_rds_snapshot_size:,.1f}", ""],
        ["Backup Plans", len([r for r in backup_plans if r['resource_type'] == 'aws:backup:plan']), "", ""],
        ["Backup Selections", len(backup_selections), "", ""],
        ["Protected Resources", len(protected_resources), "", "Resources with recovery points"],
    ]
    
    for row_idx, row_data in enumerate(summary_data, start=8):
        for col_idx, value in enumerate(row_data, start=1):
            cell = ws_summary.cell(row=row_idx, column=col_idx, value=value)
            cell.border = thin_border
            if row_idx == 8:  # Header row
                cell.fill = header_fill
                cell.font = header_font_white

    
    # Protection status section
    ws_summary['A21'] = "Protection Status by Volume"
    ws_summary['A21'].font = section_font
    
    status_data = [
        ["Status", "Volume Count", "Size (GB)", "Percentage"],
        ["Protected (with snapshots)", len(protected_volume_ids), f"{protected_volume_size:,.1f}", f"{protected_volume_size/total_volume_size*100:.1f}%" if total_volume_size else "0%"],
        ["In Backup Plan (no snapshots)", len([r for r in rows if r['volume_id'] and 'In Backup Plan' in r['protection_status']]), "", ""],
        ["Unprotected", len(unprotected_volume_ids), f"{unprotected_volume_size:,.1f}", f"{unprotected_volume_size/total_volume_size*100:.1f}%" if total_volume_size else "0%"],
        ["Total", len(ebs_volumes), f"{total_volume_size:,.1f}", "100%"],
    ]
    
    for row_idx, row_data in enumerate(status_data, start=22):
        for col_idx, value in enumerate(row_data, start=1):
            cell = ws_summary.cell(row=row_idx, column=col_idx, value=value)
            cell.border = thin_border
            if row_idx == 22:  # Header row
                cell.fill = header_fill
                cell.font = header_font_white
            elif row_idx == 26:  # Total row
                cell.font = Font(bold=True)
    
    # Adjust column widths for summary
    ws_summary.column_dimensions['A'].width = 30
    ws_summary.column_dimensions['B'].width = 15
    ws_summary.column_dimensions['C'].width = 15
    ws_summary.column_dimensions['D'].width = 30
    
    # --- Protection Report Sheet ---
    ws_report = wb.create_sheet(title="Protection Report")
    
    fieldnames = [
        'instance_name', 'instance_id', 'instance_region', 'instance_tags',
        'volume_name', 'volume_id', 'volume_size_gb',
        'snapshot_name', 'snapshot_id', 'snapshot_size_gb',
        'snapshot_created', 'snapshot_description', 'backup_plan', 'protection_source', 'protection_status'
    ]
    
    # Header row
    for col_idx, header in enumerate(fieldnames, start=1):
        cell = ws_report.cell(row=1, column=col_idx, value=header)
        cell.fill = header_fill
        cell.font = header_font_white
        cell.border = thin_border
    
    # Data rows
    status_colors = {
        'Protected': PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid"),
        'In Backup Plan': PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid"),
        'Unprotected': PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid"),
        'No Storage': PatternFill(start_color="DDDDDD", end_color="DDDDDD", fill_type="solid"),
    }
    
    for row_idx, row_data in enumerate(rows, start=2):
        status = row_data.get('protection_status', '')
        
        # Determine row color based on status
        row_fill = None
        for status_key, fill in status_colors.items():
            if status_key in status:
                row_fill = fill
                break
        
        for col_idx, field in enumerate(fieldnames, start=1):
            cell = ws_report.cell(row=row_idx, column=col_idx, value=row_data.get(field, ''))
            cell.border = thin_border
            if row_fill:
                cell.fill = row_fill
    
    # Adjust column widths for report
    column_widths = {
        'A': 20, 'B': 22, 'C': 12, 'D': 40,
        'E': 18, 'F': 25, 'G': 12,
        'H': 18, 'I': 45, 'J': 12,
        'K': 22, 'L': 30, 'M': 25, 'N': 15, 'O': 20
    }
    for col, width in column_widths.items():
        ws_report.column_dimensions[col].width = width
    
    # Freeze header row and enable filters
    ws_report.freeze_panes = 'A2'
    ws_report.auto_filter.ref = f"A1:O{len(rows) + 1}"
    
    # --- Backup Plans Sheet ---
    ws_plans = wb.create_sheet(title="Backup Plans")
    
    # Get only backup plans (not vaults)
    plans_only = [r for r in backup_plans if r['resource_type'] == 'aws:backup:plan']
    
    plan_fieldnames = [
        'Plan Name', 'Plan ID', 'Region', 'Version ID', 'Creation Date', 
        'Last Execution', 'Number of Rules', 'Rule Names', 'Rule Details'
    ]
    
    # Header row
    for col_idx, header in enumerate(plan_fieldnames, start=1):
        cell = ws_plans.cell(row=1, column=col_idx, value=header)
        cell.fill = header_fill
        cell.font = header_font_white
        cell.border = thin_border
    
    # Data rows
    for row_idx, plan in enumerate(plans_only, start=2):
        metadata = plan.get('metadata', {})
        rules = metadata.get('rules', [])
        
        # Format rule details as readable string
        rule_details_str = ""
        for rule in rules:
            details = []
            if rule.get('schedule'):
                details.append(f"Schedule: {rule['schedule']}")
            if rule.get('target_vault'):
                details.append(f"Vault: {rule['target_vault']}")
            if rule.get('delete_after_days'):
                details.append(f"Retention: {rule['delete_after_days']} days")
            if rule.get('move_to_cold_after_days'):
                details.append(f"Cold storage: {rule['move_to_cold_after_days']} days")
            rule_details_str += f"{rule.get('rule_name', 'unnamed')}: {', '.join(details)}\n"
        
        plan_data = [
            plan.get('name', ''),
            metadata.get('backup_plan_id', ''),
            plan.get('region', ''),
            metadata.get('version_id', ''),
            metadata.get('creation_date', ''),
            metadata.get('last_execution_date', '') or 'Never',
            metadata.get('number_of_rules', 0),
            ', '.join(metadata.get('rule_names', [])),
            rule_details_str.strip()
        ]
        
        for col_idx, value in enumerate(plan_data, start=1):
            cell = ws_plans.cell(row=row_idx, column=col_idx, value=value)
            cell.border = thin_border
            if col_idx == 9:  # Rule Details column - allow text wrap
                cell.alignment = Alignment(wrap_text=True, vertical='top')
    
    # Adjust column widths for plans
    plan_column_widths = {
        'A': 25, 'B': 40, 'C': 12, 'D': 50, 'E': 25,
        'F': 18, 'G': 15, 'H': 30, 'I': 60
    }
    for col, width in plan_column_widths.items():
        ws_plans.column_dimensions[col].width = width
    
    # Freeze header row and enable filters
    ws_plans.freeze_panes = 'A2'
    ws_plans.auto_filter.ref = f"A1:I{len(plans_only) + 1}"
    
    # --- Backup Selections Sheet (if any exist) ---
    if backup_selections:
        ws_selections = wb.create_sheet(title="Backup Selections")
        
        selection_fieldnames = [
            'Selection Name', 'Backup Plan', 'Plan ID', 'Region', 
            'IAM Role', 'Resources', 'Tags Conditions', 'Not Resources'
        ]
        
        # Header row
        for col_idx, header in enumerate(selection_fieldnames, start=1):
            cell = ws_selections.cell(row=1, column=col_idx, value=header)
            cell.fill = header_fill
            cell.font = header_font_white
            cell.border = thin_border
        
        # Data rows
        for row_idx, selection in enumerate(backup_selections, start=2):
            metadata = selection.get('metadata', {})
            
            selection_data = [
                selection.get('name', ''),
                metadata.get('backup_plan_name', ''),
                metadata.get('backup_plan_id', ''),
                selection.get('region', ''),
                metadata.get('iam_role_arn', ''),
                '\n'.join(metadata.get('resources', [])),
                str(metadata.get('list_of_tags', [])) if metadata.get('list_of_tags') else '',
                '\n'.join(metadata.get('not_resources', []))
            ]
            
            for col_idx, value in enumerate(selection_data, start=1):
                cell = ws_selections.cell(row=row_idx, column=col_idx, value=value)
                cell.border = thin_border
                if col_idx in [6, 7, 8]:  # Multi-line columns
                    cell.alignment = Alignment(wrap_text=True, vertical='top')
        
        # Adjust column widths
        selection_column_widths = {
            'A': 25, 'B': 25, 'C': 40, 'D': 12,
            'E': 50, 'F': 60, 'G': 40, 'H': 40
        }
        for col, width in selection_column_widths.items():
            ws_selections.column_dimensions[col].width = width
        
        ws_selections.freeze_panes = 'A2'
        ws_selections.auto_filter.ref = f"A1:H{len(backup_selections) + 1}"
    
    # Save workbook
    wb.save(output_path)
    
    # Print summary to console
    print(f"Protection Report Generated: {output_path}")
    print(f"=" * 60)
    print(f"EC2 Instances: {len(ec2_instances)}")
    print(f"EBS Volumes: {len(ebs_volumes)} ({total_volume_size:,.1f} GB)")
    print(f"  - Attached: {len(ebs_volumes) - len(orphan_volumes)} ({attached_volume_size:,.1f} GB)")
    print(f"  - Orphan: {len(orphan_volumes)} ({orphan_volume_size:,.1f} GB)")
    print(f"EBS Snapshots: {len([s for s in user_snapshots if s['resource_type'] == 'aws:ec2:snapshot'])} ({total_snapshot_size:,.1f} GB)")
    print(f"RDS Databases: {len(rds_instances)} ({total_rds_size:,.1f} GB)")
    print(f"RDS Snapshots: {len([s for s in user_snapshots if s['resource_type'] in ['aws:rds:snapshot', 'aws:rds:cluster-snapshot']])} ({total_rds_snapshot_size:,.1f} GB)")
    print(f"Backup Plans: {len(plans_only)}")
    print(f"Backup Selections: {len(backup_selections)}")
    print(f"Protected Resources: {len(protected_resources)}")
    print(f"-" * 60)
    print(f"Protected Volume Size: {protected_volume_size:,.1f} GB ({protected_volume_size/total_volume_size*100:.1f}%)" if total_volume_size else "Protected Volume Size: 0 GB")
    print(f"Unprotected Volume Size: {unprotected_volume_size:,.1f} GB ({unprotected_volume_size/total_volume_size*100:.1f}%)" if total_volume_size else "Unprotected Volume Size: 0 GB")


if __name__ == '__main__':
    inventory_path = sys.argv[1] if len(sys.argv) > 1 else 'tests/sample_output/inventory.json'
    output_path = sys.argv[2] if len(sys.argv) > 2 else 'tests/sample_output/protection_report.xlsx'
    
    generate_report(inventory_path, output_path)
