"""
Entra ID Collector Module

Collects Entra ID (Azure AD) users and groups via Microsoft Graph API.
"""
import logging
from typing import List

from msgraph.graph_service_client import GraphServiceClient

from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error

from .helpers import (
    collect_all_pages_sync,
    run_sync,
)

logger = logging.getLogger(__name__)


def collect_entra_users(graph_client: GraphServiceClient, tenant_id: str) -> List[CloudResource]:
    """Collect Entra ID (Azure AD) users."""
    resources = []

    try:
        logger.info("Collecting Entra ID users...")
        users_response = run_sync(graph_client.users.get())

        # Collect all users across all pages
        all_users = collect_all_pages_sync(users_response)

        failed_count = 0
        if all_users:
            for user in all_users:
                try:
                    resource = CloudResource(
                        provider="entraid",
                        subscription_id=tenant_id,
                        region="global",
                        resource_type="entraid:user",
                        service_family="EntraID",
                        resource_id=user.id,
                        name=user.user_principal_name or user.display_name or "Unknown",
                        tags={},
                        size_gb=0.0,
                        metadata={
                            'user_principal_name': user.user_principal_name,
                            'display_name': user.display_name,
                            'mail': user.mail,
                            'account_enabled': user.account_enabled if hasattr(user, 'account_enabled') else True,
                            'user_type': user.user_type if hasattr(user, 'user_type') else 'Member',
                            'job_title': user.job_title if hasattr(user, 'job_title') else None,
                            'department': user.department if hasattr(user, 'department') else None,
                            'created_datetime': str(user.created_date_time) if hasattr(user, 'created_date_time') and user.created_date_time else None
                        }
                    )
                    resources.append(resource)
                except Exception as e:
                    failed_count += 1
                    logger.debug(f"Failed to process user {user.id}: {e}")
                    continue

        if failed_count > 0:
            logger.warning(f"Failed to process {failed_count} users during collection")
        logger.info(f"Collected {len(resources)} Entra ID users")

    except Exception as e:
        check_and_raise_auth_error(e, "collect Entra ID users", "m365")
        logger.error(f"Failed to collect Entra ID users: {e}")

    return resources


def collect_entra_groups(graph_client: GraphServiceClient, tenant_id: str) -> List[CloudResource]:
    """Collect Entra ID (Azure AD) groups."""
    resources = []

    try:
        logger.info("Collecting Entra ID groups...")
        groups_response = run_sync(graph_client.groups.get())

        # Collect all groups across all pages
        all_groups = collect_all_pages_sync(groups_response)

        if all_groups:
            failed_count = 0
            for group in all_groups:
                try:
                    member_count = 0
                    try:
                        members = run_sync(graph_client.groups.by_group_id(group.id).members.get())
                        member_count = len(members.value) if members and members.value else 0
                    except Exception as e:
                        logger.debug(f"Could not fetch member count for group {group.id}: {e}")
                        pass

                    resource = CloudResource(
                        provider="entraid",
                        subscription_id=tenant_id,
                        region="global",
                        resource_type="entraid:group",
                        service_family="EntraID",
                        resource_id=group.id,
                        name=group.display_name or "Unknown",
                        tags={},
                        size_gb=0.0,
                        metadata={
                            'display_name': group.display_name,
                            'description': group.description,
                            'mail': group.mail,
                            'mail_enabled': group.mail_enabled if hasattr(group, 'mail_enabled') else False,
                            'security_enabled': group.security_enabled if hasattr(group, 'security_enabled') else False,
                            'group_types': list(group.group_types) if hasattr(group, 'group_types') and group.group_types else [],
                            'member_count': member_count,
                            'created_datetime': str(group.created_date_time) if hasattr(group, 'created_date_time') and group.created_date_time else None,
                            'visibility': group.visibility if hasattr(group, 'visibility') else None
                        }
                    )
                    resources.append(resource)
                except Exception as e:
                    failed_count += 1
                    logger.debug(f"Failed to process group {group.id}: {e}")
                    continue

            if failed_count > 0:
                logger.warning(f"Failed to process {failed_count} groups during collection")
        logger.info(f"Collected {len(resources)} Entra ID groups")

    except Exception as e:
        check_and_raise_auth_error(e, "collect Entra ID groups", "m365")
        logger.error(f"Failed to collect Entra ID groups: {e}")

    return resources
