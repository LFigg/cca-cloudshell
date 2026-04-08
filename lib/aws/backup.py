"""
AWS Backup resource collection.

Collects backup vaults, recovery points, plans, selections, protected resources,
and region settings.
"""
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

import boto3

from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error

logger = logging.getLogger(__name__)


def _parse_kms_key_info(key_arn: str) -> dict:
    """
    Parse KMS key ARN to determine key type and ownership.

    Returns dict with:
        - encrypted: bool (always True for valid ARN)
        - encryption_type: 'aws_managed' | 'customer_managed' | 'unknown'
        - encryption_key_arn: the original ARN

    ARN formats:
        AWS-managed: arn:aws:kms:region:account:alias/aws/backup
        CMEK by key: arn:aws:kms:region:account:key/key-id
        CMEK by alias: arn:aws:kms:region:account:alias/custom-alias
    """
    if not key_arn:
        return {
            'encrypted': True,  # AWS Backup vaults are always encrypted
            'encryption_type': 'aws_managed',
            'encryption_key_arn': None
        }

    # AWS-managed service keys use alias/aws/<service> pattern
    # e.g., arn:aws:kms:us-east-1:123456789012:alias/aws/backup
    if ':alias/aws/' in key_arn:
        return {
            'encrypted': True,
            'encryption_type': 'aws_managed',
            'encryption_key_arn': key_arn
        }

    # Customer-managed keys use either:
    # - :key/<key-id> pattern (direct key reference)
    # - :alias/<alias-name> pattern (custom alias, not aws/*)
    if ':key/' in key_arn or ':alias/' in key_arn:
        return {
            'encrypted': True,
            'encryption_type': 'customer_managed',
            'encryption_key_arn': key_arn
        }

    # Unknown pattern - still encrypted but can't determine type
    return {
        'encrypted': True,
        'encryption_type': 'unknown',
        'encryption_key_arn': key_arn
    }


def collect_backup_vaults(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect AWS Backup vaults."""
    resources = []
    try:
        backup = session.client('backup', region_name=region)
        paginator = backup.get_paginator('list_backup_vaults')

        for page in paginator.paginate():
            for vault in page.get('BackupVaultList', []):
                vault_name = vault.get('BackupVaultName', '')

                # Parse KMS key info for encryption analysis
                kms_info = _parse_kms_key_info(vault.get('EncryptionKeyArn'))

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:backup:vault",
                    service_family="Backup",
                    resource_id=vault.get('BackupVaultArn', ''),
                    name=vault_name,
                    tags={},
                    size_gb=0.0,  # Size is in recovery points
                    metadata={
                        'number_of_recovery_points': vault.get('NumberOfRecoveryPoints', 0),
                        'encrypted': kms_info['encrypted'],
                        'encryption_type': kms_info['encryption_type'],
                        'encryption_key_arn': kms_info['encryption_key_arn'],
                        'creation_date': str(vault.get('CreationDate', '')),
                        'locked': vault.get('Locked', False)
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} Backup vaults")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Backup vaults", "aws")
        logger.error(f"[{region}] Failed to collect Backup vaults: {e}")

    return resources


def collect_backup_recovery_points(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect AWS Backup recovery points (actual backups) with sizes."""
    resources = []
    try:
        backup = session.client('backup', region_name=region)

        # First, get all vaults
        vaults_paginator = backup.get_paginator('list_backup_vaults')
        vault_names = []
        for page in vaults_paginator.paginate():
            for vault in page.get('BackupVaultList', []):
                vault_names.append(vault.get('BackupVaultName', ''))

        # Then get recovery points from each vault
        for vault_name in vault_names:
            try:
                rp_paginator = backup.get_paginator('list_recovery_points_by_backup_vault')
                for page in rp_paginator.paginate(BackupVaultName=vault_name):
                    for rp in page.get('RecoveryPoints', []):
                        # Size in bytes, convert to GB
                        size_bytes = rp.get('BackupSizeInBytes', 0) or 0
                        size_gb = size_bytes / (1024 ** 3)

                        # Check if this is a copy/replica
                        parent_rp_arn = rp.get('ParentRecoveryPointArn', '')
                        source_vault_arn = rp.get('SourceBackupVaultArn', '')
                        is_replica = bool(parent_rp_arn or source_vault_arn)

                        resource = CloudResource(
                            provider="aws",
                            account_id=account_id,
                            region=region,
                            resource_type="aws:backup:recovery-point",
                            service_family="Backup",
                            resource_id=rp.get('RecoveryPointArn', ''),
                            name=rp.get('RecoveryPointArn', '').split(':')[-1] if rp.get('RecoveryPointArn') else '',
                            tags={},
                            size_gb=round(size_gb, 2),
                            parent_resource_id=rp.get('ResourceArn'),  # The backed-up resource
                            metadata={
                                'resource_type': rp.get('ResourceType'),  # EC2, EBS, RDS, etc.
                                'resource_arn': rp.get('ResourceArn'),
                                'backup_vault_name': vault_name,
                                'status': rp.get('Status'),
                                'creation_date': str(rp.get('CreationDate', '')),
                                'completion_date': str(rp.get('CompletionDate', '')),
                                'lifecycle_delete_after_days': rp.get('Lifecycle', {}).get('DeleteAfterDays'),
                                'lifecycle_move_to_cold_after_days': rp.get('Lifecycle', {}).get('MoveToColdStorageAfterDays'),
                                'is_encrypted': rp.get('IsEncrypted', False),
                                'backup_size_bytes': size_bytes,
                                'is_parent': rp.get('IsParent', False),
                                'parent_recovery_point_arn': parent_rp_arn,
                                'source_backup_vault_arn': source_vault_arn,
                                'is_replica': is_replica
                            }
                        )
                        resources.append(resource)
            except Exception as e:
                check_and_raise_auth_error(e, f"collect recovery points from vault {vault_name}", "aws")
                logger.warning(f"[{region}] Failed to collect recovery points from vault {vault_name}: {e}")

        logger.info(f"[{region}] Found {len(resources)} Backup recovery points")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Backup recovery points", "aws")
        logger.error(f"[{region}] Failed to collect Backup recovery points: {e}")

    return resources


def collect_backup_plans(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect AWS Backup plans."""
    resources = []
    try:
        backup = session.client('backup', region_name=region)
        paginator = backup.get_paginator('list_backup_plans')

        for page in paginator.paginate():
            for plan in page.get('BackupPlansList', []):
                plan_id = plan.get('BackupPlanId', '')

                # Get plan details for rules
                try:
                    plan_details = backup.get_backup_plan(BackupPlanId=plan_id)
                    backup_plan = plan_details.get('BackupPlan', {})
                    rules = backup_plan.get('Rules', [])
                    rule_names = [r.get('RuleName', '') for r in rules]

                    # Extract rule details
                    rule_details = []
                    for rule in rules:
                        lifecycle = rule.get('Lifecycle', {})
                        rule_details.append({
                            'rule_name': rule.get('RuleName'),
                            'target_vault': rule.get('TargetBackupVaultName'),
                            'schedule': rule.get('ScheduleExpression'),
                            'start_window_minutes': rule.get('StartWindowMinutes'),
                            'completion_window_minutes': rule.get('CompletionWindowMinutes'),
                            'delete_after_days': lifecycle.get('DeleteAfterDays'),
                            'move_to_cold_after_days': lifecycle.get('MoveToColdStorageAfterDays')
                        })
                except Exception:
                    rules = []
                    rule_names = []
                    rule_details = []

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:backup:plan",
                    service_family="Backup",
                    resource_id=plan.get('BackupPlanArn', ''),
                    name=plan.get('BackupPlanName', ''),
                    tags={},
                    size_gb=0.0,
                    metadata={
                        'backup_plan_id': plan_id,
                        'version_id': plan.get('VersionId'),
                        'creation_date': str(plan.get('CreationDate', '')),
                        'last_execution_date': str(plan.get('LastExecutionDate', '')) if plan.get('LastExecutionDate') else None,
                        'number_of_rules': len(rules),
                        'rule_names': rule_names,
                        'rules': rule_details
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} Backup plans")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Backup plans", "aws")
        logger.error(f"[{region}] Failed to collect Backup plans: {e}")

    return resources


def _get_backup_selection_details(backup_client, plan_info: Dict, selection_info: Dict) -> Optional[Dict]:
    """Fetch backup selection details - parallel-friendly helper.

    Returns dict with selection details or None on failure.
    """
    plan_id = plan_info['plan_id']
    selection_id = selection_info.get('SelectionId', '')

    try:
        sel_details = backup_client.get_backup_selection(
            BackupPlanId=plan_id,
            SelectionId=selection_id
        )
        sel_data = sel_details.get('BackupSelection', {})

        return {
            'plan_id': plan_id,
            'plan_name': plan_info['plan_name'],
            'plan_arn': plan_info['plan_arn'],
            'selection_id': selection_id,
            'selection_name': sel_data.get('SelectionName', ''),
            'iam_role_arn': sel_data.get('IamRoleArn'),
            'resources': sel_data.get('Resources', []),
            'not_resources': sel_data.get('NotResources', []),
            'list_of_tags': sel_data.get('ListOfTags', []),
            'conditions': sel_data.get('Conditions', {}),
            'creation_date': str(selection_info.get('CreationDate', ''))
        }
    except Exception as e:
        logger.debug(f"Failed to get selection {selection_id} details: {e}")
        return None


def collect_backup_selections(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect AWS Backup selections (resources assigned to backup plans).

    Optimized with parallel fetching of selection details (CR-022).
    """
    resources = []
    try:
        backup = session.client('backup', region_name=region)

        # Phase 1: Collect all plans and their selections (list operations)
        selection_tasks = []  # List of (plan_info, selection_info) tuples

        plans_paginator = backup.get_paginator('list_backup_plans')
        for plans_page in plans_paginator.paginate():
            for plan in plans_page.get('BackupPlansList', []):
                plan_info = {
                    'plan_id': plan.get('BackupPlanId', ''),
                    'plan_name': plan.get('BackupPlanName', ''),
                    'plan_arn': plan.get('BackupPlanArn', '')
                }

                # Get selections for this plan
                try:
                    selections_paginator = backup.get_paginator('list_backup_selections')
                    for sel_page in selections_paginator.paginate(BackupPlanId=plan_info['plan_id']):
                        for selection in sel_page.get('BackupSelectionsList', []):
                            selection_tasks.append((plan_info, selection))
                except Exception as e:
                    check_and_raise_auth_error(e, f"list selections for plan {plan_info['plan_name']}", "aws")
                    logger.warning(f"[{region}] Failed to list selections for plan {plan_info['plan_name']}: {e}")

        if not selection_tasks:
            logger.info(f"[{region}] Found 0 Backup selections")
            return resources

        # Phase 2: Fetch selection details in parallel
        logger.debug(f"[{region}] Fetching details for {len(selection_tasks)} backup selections in parallel...")
        max_workers = min(10, len(selection_tasks))

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_get_backup_selection_details, backup, plan_info, sel_info): (plan_info, sel_info)
                for plan_info, sel_info in selection_tasks
            }

            for future in as_completed(futures):
                plan_info, sel_info = futures[future]
                try:
                    details = future.result()
                    if details:
                        resource = CloudResource(
                            provider="aws",
                            account_id=account_id,
                            region=region,
                            resource_type="aws:backup:selection",
                            service_family="Backup",
                            resource_id=details['selection_id'],
                            name=details['selection_name'],
                            tags={},
                            size_gb=0.0,
                            parent_resource_id=details['plan_arn'],
                            metadata={
                                'backup_plan_id': details['plan_id'],
                                'backup_plan_name': details['plan_name'],
                                'selection_id': details['selection_id'],
                                'iam_role_arn': details['iam_role_arn'],
                                'resources': details['resources'],
                                'not_resources': details['not_resources'],
                                'list_of_tags': details['list_of_tags'],
                                'conditions': details['conditions'],
                                'creation_date': details['creation_date']
                            }
                        )
                        resources.append(resource)
                except Exception as e:
                    check_and_raise_auth_error(e, "get selection details", "aws")
                    logger.warning(f"[{region}] Failed to get selection {sel_info.get('SelectionId', '')} details: {e}")

        logger.info(f"[{region}] Found {len(resources)} Backup selections")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Backup selections", "aws")
        logger.error(f"[{region}] Failed to collect Backup selections: {e}")

    return resources


def collect_backup_protected_resources(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect AWS Backup protected resources (resources with at least one recovery point)."""
    resources = []
    try:
        backup = session.client('backup', region_name=region)
        paginator = backup.get_paginator('list_protected_resources')

        for page in paginator.paginate():
            for protected in page.get('Results', []):
                resource_arn = protected.get('ResourceArn', '')
                resource_type = protected.get('ResourceType', '')  # e.g., EC2, EBS, RDS, etc.

                # Extract resource name from ARN
                resource_name = resource_arn.split('/')[-1] if '/' in resource_arn else resource_arn.split(':')[-1]

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:backup:protected-resource",
                    service_family="Backup",
                    resource_id=resource_arn,
                    name=resource_name,
                    tags={},
                    size_gb=0.0,
                    parent_resource_id=resource_arn,  # The actual protected resource
                    metadata={
                        'resource_type': resource_type,  # EC2, EBS, RDS, DynamoDB, EFS, etc.
                        'resource_arn': resource_arn,
                        'last_backup_time': str(protected.get('LastBackupTime', '')) if protected.get('LastBackupTime') else None
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} Backup protected resources")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Backup protected resources", "aws")
        logger.error(f"[{region}] Failed to collect Backup protected resources: {e}")

    return resources


def collect_backup_region_settings(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect AWS Backup region settings (resource type opt-in preferences).

    This is critical for understanding why resources might not be backed up even
    when they're in a backup selection - the resource type must be opted-in.

    Note: These settings are actually account-level (same across all regions).
    Collected once per account in collect_account() and marked as 'global' region.
    """
    resources = []
    try:
        backup = session.client('backup', region_name=region)

        # Get region settings - which resource types are opted-in for backup
        region_settings = backup.describe_region_settings()
        resource_type_opt_in = region_settings.get('ResourceTypeOptInPreference', {})
        resource_type_management = region_settings.get('ResourceTypeManagementPreference', {})

        # Create a single resource representing these settings
        resource = CloudResource(
            provider="aws",
            account_id=account_id,
            region=region,
            resource_type="aws:backup:region-settings",
            service_family="Backup",
            resource_id=f"arn:aws:backup:{region}:{account_id}:region-settings",
            name=f"backup-region-settings-{region}",
            tags={},
            size_gb=0.0,
            metadata={
                'resource_type_opt_in': resource_type_opt_in,
                'resource_type_management': resource_type_management,
                # Summarize which types are enabled/disabled
                'opted_in_types': [k for k, v in resource_type_opt_in.items() if v is True],
                'opted_out_types': [k for k, v in resource_type_opt_in.items() if v is False]
            }
        )
        resources.append(resource)

        # Log which resource types are opted out (potential issue)
        opted_out = [k for k, v in resource_type_opt_in.items() if v is False]
        if opted_out:
            logger.warning(f"[{region}] Resource types OPTED OUT from backup: {', '.join(opted_out)}")

        logger.info(f"[{region}] Collected Backup region settings")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Backup region settings", "aws")
        logger.error(f"[{region}] Failed to collect Backup region settings: {e}")

    return resources
