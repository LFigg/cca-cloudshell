# GCP Backup & DR collectors
"""Collectors for Backup & DR plans, vaults, data sources, and backups."""

import logging
from typing import List

from lib.gcp.utils import extract_location_from_name
from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error

logger = logging.getLogger(__name__)


def collect_backup_plans(project_id: str) -> List[CloudResource]:
    """
    Collect Backup & DR backup plans.

    Args:
        project_id: GCP project ID

    Returns:
        List of CloudResource objects for backup plans

    Example:
        plans = collect_backup_plans("my-gcp-project")
    """
    resources = []
    try:
        from google.cloud import backupdr_v1

        client = backupdr_v1.BackupDRClient()

        # List backup plans in all locations
        parent = f"projects/{project_id}/locations/-"

        for plan in client.list_backup_plans(parent=parent):
            labels = dict(plan.labels) if plan.labels else {}

            location = extract_location_from_name(plan.name)

            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region=location,
                resource_type="gcp:backupdr:plan",
                service_family="Backup",
                resource_id=plan.name,
                name=plan.name.split('/')[-1],
                tags=labels,
                size_gb=0.0,
                metadata={
                    'state': plan.state.name if hasattr(plan, 'state') and plan.state else '',
                    'description': plan.description if hasattr(plan, 'description') else '',
                    'size_source': 'not_applicable',
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Backup & DR plans")
    except ImportError:
        logger.warning("Backup & DR client not available")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Backup & DR plans", "gcp")
        logger.error(f"Failed to collect Backup & DR plans: {e}")

    return resources


def collect_backup_vaults(project_id: str) -> List[CloudResource]:
    """
    Collect Backup & DR backup vaults.

    Args:
        project_id: GCP project ID

    Returns:
        List of CloudResource objects for backup vaults
    """
    resources = []
    try:
        from google.cloud import backupdr_v1

        client = backupdr_v1.BackupDRClient()

        # List backup vaults in all locations
        parent = f"projects/{project_id}/locations/-"

        for vault in client.list_backup_vaults(parent=parent):
            labels = dict(vault.labels) if vault.labels else {}

            location = extract_location_from_name(vault.name)

            # total_stored_bytes is BackupVault's own real, measured storage
            # total ("Total size of the storage used by all backup
            # resources" per the SDK's field doc) - not a quota/estimate.
            total_size_bytes = getattr(vault, 'total_stored_bytes', 0) or 0
            size_gb = total_size_bytes / (1024 ** 3)

            resource = CloudResource(
                provider="gcp",
                account_id=project_id,
                region=location,
                resource_type="gcp:backupdr:vault",
                service_family="Backup",
                resource_id=vault.name,
                name=vault.name.split('/')[-1],
                tags=labels,
                size_gb=round(size_gb, 2),
                metadata={
                    'state': vault.state.name if hasattr(vault, 'state') and vault.state else '',
                    'description': getattr(vault, 'description', ''),
                    'backup_count': getattr(vault, 'backup_count', 0),
                    'total_stored_bytes': total_size_bytes,
                    'deletable': getattr(vault, 'deletable', True),
                    'etag': getattr(vault, 'etag', ''),
                    'size_source': 'usage',
                }
            )
            resources.append(resource)

        logger.info(f"Found {len(resources)} Backup & DR vaults")
    except ImportError:
        logger.warning("Backup & DR client not available")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Backup & DR vaults", "gcp")
        logger.error(f"Failed to collect Backup & DR vaults: {e}")

    return resources


def collect_backup_data_sources(project_id: str) -> List[CloudResource]:
    """
    Collect Backup & DR data sources (protected resources).

    Args:
        project_id: GCP project ID

    Returns:
        List of CloudResource objects for backup data sources
    """
    resources = []
    try:
        from google.cloud import backupdr_v1

        client = backupdr_v1.BackupDRClient()

        # First get all backup vaults
        parent = f"projects/{project_id}/locations/-"
        vault_names = []

        try:
            for vault in client.list_backup_vaults(parent=parent):
                vault_names.append(vault.name)
        except Exception as e:
            logger.warning(f"Failed to list backup vaults for {project_id}: {e}")

        # Then get data sources from each vault
        for vault_name in vault_names:
            try:
                for ds in client.list_data_sources(parent=vault_name):
                    labels = dict(ds.labels) if hasattr(ds, 'labels') and ds.labels else {}

                    location = extract_location_from_name(ds.name)

                    # total_stored_bytes is DataSource's own real, measured
                    # storage total ("bytes stored in this datasource" per
                    # the SDK's field doc) - not a quota/estimate.
                    total_size_bytes = getattr(ds, 'total_stored_bytes', 0) or 0
                    size_gb = total_size_bytes / (1024 ** 3)

                    resource = CloudResource(
                        provider="gcp",
                        account_id=project_id,
                        region=location,
                        resource_type="gcp:backupdr:datasource",
                        service_family="Backup",
                        resource_id=ds.name,
                        name=ds.name.split('/')[-1],
                        tags=labels,
                        size_gb=round(size_gb, 2),
                        parent_resource_id=vault_name,
                        metadata={
                            'state': ds.state.name if hasattr(ds, 'state') and ds.state else '',
                            'data_source_gcp_resource': getattr(ds, 'data_source_gcp_resource', {}).get('gcp_resourcename', ''),
                            'backup_count': getattr(ds, 'backup_count', 0),
                            'total_stored_bytes': total_size_bytes,
                            'backup_vault': vault_name.split('/')[-1],
                            'size_source': 'usage',
                        }
                    )
                    resources.append(resource)
            except Exception as e:
                check_and_raise_auth_error(e, f"collect data sources from vault {vault_name}", "gcp")
                logger.warning(f"Failed to collect data sources from vault {vault_name}: {e}")

        logger.info(f"Found {len(resources)} Backup & DR data sources")
    except ImportError:
        logger.warning("Backup & DR client not available")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Backup & DR data sources", "gcp")
        logger.error(f"Failed to collect Backup & DR data sources: {e}")

    return resources


def collect_backups(project_id: str) -> List[CloudResource]:
    """
    Collect Backup & DR backups (recovery points).

    Args:
        project_id: GCP project ID

    Returns:
        List of CloudResource objects for backups
    """
    resources = []
    try:
        from google.cloud import backupdr_v1

        client = backupdr_v1.BackupDRClient()

        # First get all backup vaults
        parent = f"projects/{project_id}/locations/-"
        vault_names = []

        try:
            for vault in client.list_backup_vaults(parent=parent):
                vault_names.append(vault.name)
        except Exception as e:
            logger.warning(f"Failed to list backup vaults for {project_id}: {e}")

        # Get data sources from each vault, then backups from each data source
        for vault_name in vault_names:
            try:
                for ds in client.list_data_sources(parent=vault_name):
                    try:
                        for backup in client.list_backups(parent=ds.name):
                            labels = dict(backup.labels) if hasattr(backup, 'labels') and backup.labels else {}

                            location = extract_location_from_name(backup.name)

                            # 'backup_appliance_backup_size_bytes' and
                            # 'gc_backup_size_bytes' don't exist anywhere on
                            # the installed SDK's Backup type (verified via
                            # its docstring/attributes) - getattr(...,0) was
                            # silently always returning 0, so every GCP
                            # Backup & DR backup always reported size_gb=0.0
                            # with no error. The real field is
                            # resource_size_bytes ("source resource size in
                            # bytes at the time of the backup") - a genuine
                            # point-in-time measurement, not a static
                            # allocation/quota.
                            size_bytes = getattr(backup, 'resource_size_bytes', 0) or 0
                            size_gb = size_bytes / (1024 ** 3)

                            resource = CloudResource(
                                provider="gcp",
                                account_id=project_id,
                                region=location,
                                resource_type="gcp:backupdr:backup",
                                service_family="Backup",
                                resource_id=backup.name,
                                name=backup.name.split('/')[-1],
                                tags=labels,
                                size_gb=round(size_gb, 2),
                                parent_resource_id=ds.name,
                                metadata={
                                    'state': backup.state.name if hasattr(backup, 'state') and backup.state else '',
                                    'backup_type': backup.backup_type.name if hasattr(backup, 'backup_type') and backup.backup_type else '',
                                    'create_time': str(getattr(backup, 'create_time', '')),
                                    'expire_time': str(getattr(backup, 'expire_time', '')),
                                    'consistency_time': str(getattr(backup, 'consistency_time', '')),
                                    'data_source': ds.name.split('/')[-1],
                                    'backup_vault': vault_name.split('/')[-1],
                                    'size_bytes': size_bytes,
                                    'size_source': 'usage' if size_bytes else 'unavailable',
                                }
                            )
                            resources.append(resource)
                    except Exception as e:
                        check_and_raise_auth_error(e, f"collect backups from data source {ds.name}", "gcp")
                        logger.warning(f"Failed to collect backups from data source {ds.name}: {e}")
            except Exception as e:
                check_and_raise_auth_error(e, f"collect data sources from vault {vault_name}", "gcp")
                logger.warning(f"Failed to collect data sources from vault {vault_name}: {e}")

        logger.info(f"Found {len(resources)} Backup & DR backups")
    except ImportError:
        logger.warning("Backup & DR client not available")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Backup & DR backups", "gcp")
        logger.error(f"Failed to collect Backup & DR backups: {e}")

    return resources
