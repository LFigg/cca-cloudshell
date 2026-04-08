"""
Exchange Collector Module

Collects Exchange Online mailbox data via Microsoft Graph API usage reports.
"""
import logging
from typing import Any, Dict, List, Optional

from msgraph.graph_service_client import GraphServiceClient

from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error

from .helpers import (
    collect_all_pages_sync,
    get_csv_field,
    get_usage_report,
    parse_usage_report_csv,
    run_sync,
    safe_int,
)

logger = logging.getLogger(__name__)


def collect_exchange_mailboxes(
    graph_client: GraphServiceClient,
    tenant_id: str,
    mailbox_usage: Optional[Dict[str, Dict[str, Any]]] = None
) -> List[CloudResource]:
    """Collect Exchange Online mailboxes from usage report data.

    The usage report is the authoritative source as it includes all mailbox types:
    - User mailboxes (regular user mailboxes)
    - Shared mailboxes (shared departmental mailboxes)
    - Room/Equipment mailboxes (scheduling mailboxes)
    - Group mailboxes (M365 Group mailboxes)

    Args:
        graph_client: Microsoft Graph client
        tenant_id: Azure AD tenant ID
        mailbox_usage: Dict from collect_mailbox_usage_report() - if not provided, will collect
    """
    resources = []

    try:
        logger.info("Collecting Exchange mailboxes...")

        # Get mailbox data from usage report if not provided
        if mailbox_usage is None:
            mailbox_usage = collect_mailbox_usage_report(graph_client)

        if not mailbox_usage:
            logger.warning("No mailbox usage data available - mailbox collection may be incomplete")
            # Fall back to user-based collection
            return _collect_exchange_mailboxes_from_users(graph_client, tenant_id)

        # Create resources from usage report data (includes all mailbox types)
        for upn, usage_data in mailbox_usage.items():
            try:
                # Skip deleted mailboxes unless specifically tracking them
                if usage_data.get('is_deleted', False):
                    continue

                storage_gb = usage_data.get('storage_gb', 0.0)

                resource = CloudResource(
                    provider="microsoft365",
                    subscription_id=tenant_id,
                    region="global",
                    resource_type="m365:exchange:mailbox",
                    service_family="Exchange",
                    resource_id=upn,  # UPN as resource ID
                    name=usage_data.get('display_name') or upn,
                    tags={},
                    size_gb=storage_gb,
                    metadata={
                        'user_principal_name': usage_data.get('user_principal_name', upn),
                        'display_name': usage_data.get('display_name', ''),

                        # Mailbox type info
                        'mailbox_type': usage_data.get('mailbox_type', 'User'),
                        'recipient_type': usage_data.get('recipient_type', 'UserMailbox'),
                        'has_archive': usage_data.get('has_archive', False),

                        # Storage
                        'storage_used_gb': round(storage_gb, 2),
                        'item_count': usage_data.get('item_count', 0),

                        # Deleted items (recoverable items)
                        'deleted_item_count': usage_data.get('deleted_item_count', 0),
                        'deleted_item_size_gb': round(usage_data.get('deleted_item_size_gb', 0.0), 2),

                        # Quotas
                        'prohibit_send_receive_quota_gb': round(usage_data.get('prohibit_send_receive_quota_gb', 0.0), 2),
                        'quota_usage_percent': round(usage_data.get('quota_usage_percent', 0.0), 1),

                        # Activity
                        'last_activity_date': usage_data.get('last_activity_date', ''),
                        'created_date': usage_data.get('created_date', ''),
                    }
                )
                resources.append(resource)
            except Exception as e:
                logger.debug(f"Failed to process mailbox {upn}: {e}")
                continue

        # Log summary by type
        type_counts = {}
        for r in resources:
            t = r.metadata.get('mailbox_type', 'Unknown')
            type_counts[t] = type_counts.get(t, 0) + 1

        logger.info(f"Collected {len(resources)} Exchange mailboxes by type: {type_counts}")

    except Exception as e:
        check_and_raise_auth_error(e, "collect Exchange mailboxes", "m365")
        logger.error(f"Failed to collect Exchange mailboxes: {e}")

    return resources


def _collect_exchange_mailboxes_from_users(
    graph_client: GraphServiceClient,
    tenant_id: str
) -> List[CloudResource]:
    """Fallback: Collect Exchange mailboxes by iterating users.

    This is used when usage report data is not available.
    Note: This only captures user mailboxes, not shared/room/group mailboxes.
    """
    resources = []

    try:
        logger.info("Collecting Exchange mailboxes from users (fallback)...")
        users_response = run_sync(graph_client.users.get())
        all_users = collect_all_pages_sync(users_response)

        failed_count = 0
        skipped_no_mail = 0
        if all_users:
            for user in all_users:
                try:
                    if not user.mail:
                        skipped_no_mail += 1
                        continue

                    resource = CloudResource(
                        provider="microsoft365",
                        subscription_id=tenant_id,
                        region="global",
                        resource_type="m365:exchange:mailbox",
                        service_family="Exchange",
                        resource_id=user.id,
                        name=user.user_principal_name or user.display_name or "Unknown",
                        tags={},
                        size_gb=0.0,  # Size unknown without usage report
                        metadata={
                            'user_id': user.id,
                            'user_principal_name': user.user_principal_name,
                            'display_name': user.display_name,
                            'mail': user.mail,
                            'mailbox_type': 'User',
                            'recipient_type': 'UserMailbox',
                            'has_archive': False,
                            'account_enabled': user.account_enabled if hasattr(user, 'account_enabled') else True,
                            'created_datetime': str(user.created_date_time) if hasattr(user, 'created_date_time') and user.created_date_time else None,
                        }
                    )
                    resources.append(resource)
                except Exception as e:
                    failed_count += 1
                    logger.debug(f"Failed to process mailbox for user {user.id}: {e}")
                    continue

        if failed_count > 0:
            logger.warning(f"Failed to process {failed_count} mailboxes during collection")
        logger.info(f"Collected {len(resources)} user mailboxes (fallback mode, {skipped_no_mail} users had no mail)")

    except Exception as e:
        check_and_raise_auth_error(e, "collect Exchange mailboxes from users", "m365")
        logger.error(f"Failed to collect Exchange mailboxes: {e}")

    return resources


def collect_mailbox_usage_report(graph_client: GraphServiceClient) -> Dict[str, Dict[str, Any]]:
    """Collect Exchange mailbox usage report with comprehensive data.

    Returns dict keyed by user principal name with full mailbox details including:
    - Storage size (primary mailbox)
    - Item counts
    - Mailbox type (UserMailbox, SharedMailbox, SchedulingMailbox, GroupMailbox)
    - Archive status
    - Quotas
    - Activity dates
    - Deleted item info
    """
    logger.info("Collecting Exchange mailbox usage report...")

    csv_content = get_usage_report('getMailboxUsageDetail')
    if not csv_content:
        return {}

    rows = parse_usage_report_csv(csv_content)

    # Build lookup by user principal name
    mailboxes = {}
    for row in rows:
        upn = get_csv_field(row, 'User Principal Name', 'userPrincipalName')
        if not upn:
            continue

        # Storage used (bytes)
        storage_bytes = safe_int(get_csv_field(
            row, 'Storage Used (Byte)', 'Storage Used (Bytes)', 'storageUsedInBytes'
        ))

        # Item count
        item_count = safe_int(get_csv_field(row, 'Item Count', 'itemCount'))

        # Deleted items
        deleted_item_count = safe_int(get_csv_field(
            row, 'Deleted Item Count', 'deletedItemCount'
        ))
        deleted_item_size_bytes = safe_int(get_csv_field(
            row, 'Deleted Item Size (Byte)', 'Deleted Item Size (Bytes)', 'deletedItemSizeInBytes'
        ))

        # Mailbox type from Recipient Type field
        recipient_type = get_csv_field(row, 'Recipient Type', 'recipientType')

        # Map recipient types to friendly names
        mailbox_type_map = {
            'UserMailbox': 'User',
            'SharedMailbox': 'Shared',
            'RoomMailbox': 'Room',
            'EquipmentMailbox': 'Equipment',
            'SchedulingMailbox': 'Scheduling',
            'GroupMailbox': 'Group',
            'DiscoveryMailbox': 'Discovery',
        }
        mailbox_type = mailbox_type_map.get(recipient_type, recipient_type or 'User')

        # Archive status
        has_archive_raw = get_csv_field(row, 'Has Archive', 'hasArchive')
        has_archive = str(has_archive_raw).lower() in ('yes', 'true', '1') if has_archive_raw else False

        # Is deleted
        is_deleted_raw = get_csv_field(row, 'Is Deleted', 'isDeleted')
        is_deleted = str(is_deleted_raw).lower() in ('yes', 'true', '1') if is_deleted_raw else False

        # Quotas (bytes)
        issue_warning_quota = safe_int(get_csv_field(
            row, 'Issue Warning Quota (Byte)', 'Issue Warning Quota (Bytes)', 'issueWarningQuotaInBytes'
        ))
        prohibit_send_quota = safe_int(get_csv_field(
            row, 'Prohibit Send Quota (Byte)', 'Prohibit Send Quota (Bytes)', 'prohibitSendQuotaInBytes'
        ))
        prohibit_send_receive_quota = safe_int(get_csv_field(
            row, 'Prohibit Send/Receive Quota (Byte)', 'Prohibit Send/Receive Quota (Bytes)',
            'prohibitSendReceiveQuotaInBytes'
        ))
        deleted_item_quota = safe_int(get_csv_field(
            row, 'Deleted Item Quota (Byte)', 'Deleted Item Quota (Bytes)', 'deletedItemQuotaInBytes'
        ))

        # Dates
        display_name = get_csv_field(row, 'Display Name', 'displayName') or ''
        last_activity_date = get_csv_field(row, 'Last Activity Date', 'lastActivityDate') or ''
        created_date = get_csv_field(row, 'Created Date', 'createdDate') or ''
        deleted_date = get_csv_field(row, 'Deleted Date', 'deletedDate') or ''

        mailboxes[upn.lower()] = {
            # Identity
            'user_principal_name': upn,
            'display_name': display_name,

            # Type and status
            'recipient_type': recipient_type or 'UserMailbox',
            'mailbox_type': mailbox_type,
            'has_archive': has_archive,
            'is_deleted': is_deleted,

            # Storage
            'storage_bytes': storage_bytes,
            'storage_gb': storage_bytes / (1024**3),
            'item_count': item_count,

            # Deleted items (recoverable)
            'deleted_item_count': deleted_item_count,
            'deleted_item_size_bytes': deleted_item_size_bytes,
            'deleted_item_size_gb': deleted_item_size_bytes / (1024**3),

            # Quotas (in GB for readability)
            'issue_warning_quota_gb': issue_warning_quota / (1024**3) if issue_warning_quota else 0.0,
            'prohibit_send_quota_gb': prohibit_send_quota / (1024**3) if prohibit_send_quota else 0.0,
            'prohibit_send_receive_quota_gb': prohibit_send_receive_quota / (1024**3) if prohibit_send_receive_quota else 0.0,
            'deleted_item_quota_gb': deleted_item_quota / (1024**3) if deleted_item_quota else 0.0,

            # Calculate quota usage percentage
            'quota_usage_percent': (storage_bytes / prohibit_send_receive_quota * 100) if prohibit_send_receive_quota else 0.0,

            # Dates
            'last_activity_date': last_activity_date,
            'created_date': created_date,
            'deleted_date': deleted_date,
        }

    # Log summary by type
    type_counts = {}
    for mb in mailboxes.values():
        t = mb['mailbox_type']
        type_counts[t] = type_counts.get(t, 0) + 1

    logger.info(f"Collected usage data for {len(mailboxes)} Exchange mailboxes: {type_counts}")
    return mailboxes


def generate_exchange_summary(mailbox_usage: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Generate comprehensive Exchange Online summary matching sizing spreadsheet format.

    Categories:
    - User Active Mailboxes (active, not deleted, recipient type UserMailbox)
    - User Archive Mailboxes (has archive enabled - note: archive SIZE requires PowerShell)
    - SoftDeleted Active Mailboxes (is_deleted=True)
    - SoftDeleted Archive Mailboxes (is_deleted=True with archive)
    - Group Active Mailboxes (GroupMailbox recipient type)
    - Group Archive Mailboxes (GroupMailbox with archive)
    - PublicFolder Active Mailboxes (PublicFolderMailbox recipient type)
    """
    summary = {
        'user_active': {'count': 0, 'item_count': 0, 'item_size_gib': 0.0,
                        'recoverable_item_count': 0, 'recoverable_item_size_gib': 0.0},
        'user_archive_enabled': {'count': 0},  # Note: Archive SIZE not available via Graph API
        'softdeleted_active': {'count': 0, 'item_count': 0, 'item_size_gib': 0.0,
                               'recoverable_item_count': 0, 'recoverable_item_size_gib': 0.0},
        'softdeleted_archive': {'count': 0},
        'group_active': {'count': 0, 'item_count': 0, 'item_size_gib': 0.0,
                         'recoverable_item_count': 0, 'recoverable_item_size_gib': 0.0},
        'group_archive': {'count': 0},
        'publicfolder_active': {'count': 0, 'item_count': 0, 'item_size_gib': 0.0,
                                'recoverable_item_count': 0, 'recoverable_item_size_gib': 0.0},
        'shared_active': {'count': 0, 'item_count': 0, 'item_size_gib': 0.0,
                          'recoverable_item_count': 0, 'recoverable_item_size_gib': 0.0},
        'room_equipment_active': {'count': 0, 'item_count': 0, 'item_size_gib': 0.0,
                                   'recoverable_item_count': 0, 'recoverable_item_size_gib': 0.0},
    }

    for _upn, mb in mailbox_usage.items():
        recipient_type = mb.get('recipient_type', 'UserMailbox')
        is_deleted = mb.get('is_deleted', False)
        has_archive = mb.get('has_archive', False)

        item_count = mb.get('item_count', 0)
        item_size_gib = mb.get('storage_gb', 0.0)
        recoverable_count = mb.get('deleted_item_count', 0)
        recoverable_size_gib = mb.get('deleted_item_size_gb', 0.0)

        # Categorize by recipient type and status
        if recipient_type == 'GroupMailbox':
            if is_deleted:
                summary['softdeleted_active']['count'] += 1  # Soft-deleted groups
            else:
                summary['group_active']['count'] += 1
                summary['group_active']['item_count'] += item_count
                summary['group_active']['item_size_gib'] += item_size_gib
                summary['group_active']['recoverable_item_count'] += recoverable_count
                summary['group_active']['recoverable_item_size_gib'] += recoverable_size_gib
                if has_archive:
                    summary['group_archive']['count'] += 1

        elif recipient_type == 'PublicFolderMailbox':
            summary['publicfolder_active']['count'] += 1
            summary['publicfolder_active']['item_count'] += item_count
            summary['publicfolder_active']['item_size_gib'] += item_size_gib
            summary['publicfolder_active']['recoverable_item_count'] += recoverable_count
            summary['publicfolder_active']['recoverable_item_size_gib'] += recoverable_size_gib

        elif recipient_type == 'SharedMailbox':
            if is_deleted:
                summary['softdeleted_active']['count'] += 1
            else:
                summary['shared_active']['count'] += 1
                summary['shared_active']['item_count'] += item_count
                summary['shared_active']['item_size_gib'] += item_size_gib
                summary['shared_active']['recoverable_item_count'] += recoverable_count
                summary['shared_active']['recoverable_item_size_gib'] += recoverable_size_gib

        elif recipient_type in ('RoomMailbox', 'EquipmentMailbox', 'SchedulingMailbox'):
            summary['room_equipment_active']['count'] += 1
            summary['room_equipment_active']['item_count'] += item_count
            summary['room_equipment_active']['item_size_gib'] += item_size_gib
            summary['room_equipment_active']['recoverable_item_count'] += recoverable_count
            summary['room_equipment_active']['recoverable_item_size_gib'] += recoverable_size_gib

        else:  # UserMailbox or unknown
            if is_deleted:
                summary['softdeleted_active']['count'] += 1
                summary['softdeleted_active']['item_count'] += item_count
                summary['softdeleted_active']['item_size_gib'] += item_size_gib
                summary['softdeleted_active']['recoverable_item_count'] += recoverable_count
                summary['softdeleted_active']['recoverable_item_size_gib'] += recoverable_size_gib
                if has_archive:
                    summary['softdeleted_archive']['count'] += 1
            else:
                summary['user_active']['count'] += 1
                summary['user_active']['item_count'] += item_count
                summary['user_active']['item_size_gib'] += item_size_gib
                summary['user_active']['recoverable_item_count'] += recoverable_count
                summary['user_active']['recoverable_item_size_gib'] += recoverable_size_gib
                if has_archive:
                    summary['user_archive_enabled']['count'] += 1

    # Calculate totals for each category
    for category in summary.values():
        if 'item_count' in category:
            category['total_item_count'] = category['item_count'] + category.get('recoverable_item_count', 0)
            category['total_item_size_gib'] = round(
                category['item_size_gib'] + category.get('recoverable_item_size_gib', 0.0), 3
            )
            # Round individual values
            category['item_size_gib'] = round(category['item_size_gib'], 3)
            category['recoverable_item_size_gib'] = round(category.get('recoverable_item_size_gib', 0.0), 3)

    # Calculate grand totals
    summary['totals_default'] = {
        'count': summary['user_active']['count'],
        'item_count': summary['user_active']['item_count'],
        'item_size_gib': summary['user_active']['item_size_gib'],
        'recoverable_item_count': summary['user_active']['recoverable_item_count'],
        'recoverable_item_size_gib': summary['user_active']['recoverable_item_size_gib'],
        'total_item_count': summary['user_active']['total_item_count'],
        'total_item_size_gib': summary['user_active']['total_item_size_gib'],
    }

    # Totals with all options (including deleted, groups, shared, etc.)
    all_active_categories = ['user_active', 'group_active', 'publicfolder_active',
                              'shared_active', 'room_equipment_active', 'softdeleted_active']
    summary['totals_all'] = {
        'count': sum(summary[cat]['count'] for cat in all_active_categories),
        'item_count': sum(summary[cat].get('item_count', 0) for cat in all_active_categories),
        'item_size_gib': round(sum(summary[cat].get('item_size_gib', 0.0) for cat in all_active_categories), 3),
        'recoverable_item_count': sum(summary[cat].get('recoverable_item_count', 0) for cat in all_active_categories),
        'recoverable_item_size_gib': round(sum(summary[cat].get('recoverable_item_size_gib', 0.0) for cat in all_active_categories), 3),
    }
    summary['totals_all']['total_item_count'] = (
        summary['totals_all']['item_count'] + summary['totals_all']['recoverable_item_count']
    )
    summary['totals_all']['total_item_size_gib'] = round(
        summary['totals_all']['item_size_gib'] + summary['totals_all']['recoverable_item_size_gib'], 3
    )

    return summary
