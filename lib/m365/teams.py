"""
Teams Collector Module

Collects Microsoft Teams data via Microsoft Graph API.
"""
import logging
from typing import Any, Dict, List, Optional

from msgraph.graph_service_client import GraphServiceClient

from lib.models import CloudResource
from lib.utils import check_and_raise_auth_error

from .helpers import (
    USAGE_REPORT_PERIOD_DAYS,
    collect_all_pages_sync,
    get_csv_field,
    get_usage_report,
    parse_usage_report_csv,
    run_sync,
    safe_int,
)

logger = logging.getLogger(__name__)


def collect_teams(
    graph_client: GraphServiceClient,
    tenant_id: str,
    teams_usage: Optional[Dict[str, Dict[str, Any]]] = None
) -> List[CloudResource]:
    """Collect Microsoft Teams with storage from usage report.

    Args:
        graph_client: Microsoft Graph client
        tenant_id: Azure AD tenant ID
        teams_usage: Optional dict from collect_teams_usage_report() keyed by team_id
    """
    resources = []
    teams_usage = teams_usage or {}

    try:
        logger.info("Collecting Microsoft Teams...")
        groups_response = run_sync(graph_client.groups.get())

        # Collect all groups across all pages
        all_groups = collect_all_pages_sync(groups_response)

        failed_count = 0
        non_team_groups = 0
        if all_groups:
            for group in all_groups:
                try:
                    if not hasattr(group, 'resource_provisioning_options') or \
                       'Team' not in (group.resource_provisioning_options or []):
                        non_team_groups += 1
                        continue

                    # Get team details
                    try:
                        team = run_sync(graph_client.teams.by_team_id(group.id).get())
                    except Exception as e:
                        logger.debug(f"Could not fetch team details for {group.id}: {e}")
                        team = None

                    # Get usage data if available
                    usage = teams_usage.get(group.id.lower(), {})
                    size_gb = usage.get('storage_gb', 0.0)

                    resource = CloudResource(
                        provider="microsoft365",
                        subscription_id=tenant_id,
                        region="global",
                        resource_type="m365:teams:team",
                        service_family="Teams",
                        resource_id=group.id,
                        name=team.display_name if team else group.display_name or "Unknown",
                        tags={},
                        size_gb=size_gb,
                        metadata={
                            'group_id': group.id,
                            'description': (team.description if team else group.description) or None,
                            'visibility': (team.visibility if team and hasattr(team, 'visibility') else group.visibility) if hasattr(group, 'visibility') else None,
                            'created_datetime': str(group.created_date_time) if hasattr(group, 'created_date_time') and group.created_date_time else None,
                            'is_archived': team.is_archived if team and hasattr(team, 'is_archived') else False,
                            'web_url': team.web_url if team and hasattr(team, 'web_url') else None,
                            # Add usage metrics if available
                            'active_channels': usage.get('active_channels'),
                            'total_channels': usage.get('total_channels'),
                            'active_users': usage.get('active_users'),
                            'active_external_users': usage.get('active_external_users'),
                            'channel_messages': usage.get('channel_messages'),
                            'last_activity_date': usage.get('last_activity_date'),
                        }
                    )
                    resources.append(resource)
                except Exception as e:
                    failed_count += 1
                    logger.debug(f"Failed to process Team {group.id}: {e}")
                    continue

        if failed_count > 0:
            logger.warning(f"Failed to process {failed_count} Teams")
        total_storage = sum(r.size_gb for r in resources)
        logger.info(f"Collected {len(resources)} Teams ({total_storage:.2f} GB)")

    except Exception as e:
        check_and_raise_auth_error(e, "collect Teams", "m365")
        logger.error(f"Failed to collect Teams: {e}")

    return resources


def collect_teams_activity_report(graph_client: GraphServiceClient) -> Dict[str, Any]:
    """Collect Teams activity report for chat/meeting metrics.

    Returns dict with Teams chat and meeting activity data including:
    - Team chat message counts
    - Private chat message counts
    - Calls and meetings counts
    - Total estimated metered units
    """
    logger.info("Collecting Teams activity report...")

    csv_content = get_usage_report('getTeamsUserActivityUserDetail')
    if not csv_content:
        return {}

    rows = parse_usage_report_csv(csv_content)

    # Aggregate activity across all users
    totals = {
        'team_chat_message_count': 0,
        'private_chat_message_count': 0,
        'call_count': 0,
        'meeting_count': 0,
        'meetings_organized_count': 0,
        'meetings_attended_count': 0,
        'ad_hoc_meetings_organized_count': 0,
        'scheduled_one_time_meetings_organized_count': 0,
        'scheduled_recurring_meetings_organized_count': 0,
        'audio_duration_seconds': 0,
        'video_duration_seconds': 0,
        'screen_share_duration_seconds': 0,
        'active_users': 0,
        'users_with_activity': 0,
    }

    for row in rows:
        # Check if user had any activity
        has_activity = any([
            safe_int(get_csv_field(row, 'Team Chat Message Count', 'teamChatMessageCount')) > 0,
            safe_int(get_csv_field(row, 'Private Chat Message Count', 'privateChatMessageCount')) > 0,
            safe_int(get_csv_field(row, 'Call Count', 'callCount')) > 0,
            safe_int(get_csv_field(row, 'Meeting Count', 'meetingCount')) > 0,
        ])

        if has_activity:
            totals['users_with_activity'] += 1

        # Aggregate message counts
        totals['team_chat_message_count'] += safe_int(get_csv_field(
            row, 'Team Chat Message Count', 'teamChatMessageCount'
        ))
        totals['private_chat_message_count'] += safe_int(get_csv_field(
            row, 'Private Chat Message Count', 'privateChatMessageCount'
        ))

        # Aggregate calls/meetings
        totals['call_count'] += safe_int(get_csv_field(row, 'Call Count', 'callCount'))
        totals['meeting_count'] += safe_int(get_csv_field(row, 'Meeting Count', 'meetingCount'))
        totals['meetings_organized_count'] += safe_int(get_csv_field(
            row, 'Meetings Organized Count', 'meetingsOrganizedCount'
        ))
        totals['meetings_attended_count'] += safe_int(get_csv_field(
            row, 'Meetings Attended Count', 'meetingsAttendedCount'
        ))

        # Duration tracking (in seconds)
        totals['audio_duration_seconds'] += safe_int(get_csv_field(
            row, 'Audio Duration In Seconds', 'audioDurationInSeconds'
        ))
        totals['video_duration_seconds'] += safe_int(get_csv_field(
            row, 'Video Duration In Seconds', 'videoDurationInSeconds'
        ))
        totals['screen_share_duration_seconds'] += safe_int(get_csv_field(
            row, 'Screen Share Duration In Seconds', 'screenShareDurationInSeconds'
        ))

        totals['active_users'] += 1

    # Calculate estimated metered units (messages are the primary metered resource)
    # Microsoft's metering is complex, but chat messages are primary
    totals['estimated_metered_units_user_chats'] = totals['private_chat_message_count']
    totals['estimated_metered_units_channel_conversations'] = totals['team_chat_message_count']
    totals['total_estimated_metered_units'] = (
        totals['private_chat_message_count'] + totals['team_chat_message_count']
    )

    # Project for next year (linear projection from 180-day report period)
    days_in_period = USAGE_REPORT_PERIOD_DAYS
    projection_factor = 365 / days_in_period
    totals['projected_annual_metered_units'] = int(totals['total_estimated_metered_units'] * projection_factor)
    totals['total_metered_units_with_projection'] = (
        totals['total_estimated_metered_units'] + totals['projected_annual_metered_units']
    )

    logger.info(f"Collected Teams activity for {totals['active_users']} users: "
                f"{totals['total_estimated_metered_units']:,} metered units")
    return totals


def collect_teams_usage_report(graph_client: GraphServiceClient) -> Dict[str, Dict[str, Any]]:
    """Collect Teams team-level usage report with storage data.

    Returns dict keyed by Team ID with storage and activity metrics.
    Uses getTeamsTeamActivityDetail report which includes storage used per team.
    """
    logger.info("Collecting Teams team usage report...")

    csv_content = get_usage_report('getTeamsTeamActivityDetail')
    if not csv_content:
        return {}

    rows = parse_usage_report_csv(csv_content)

    # Debug: log column names from first row
    if rows:
        logger.debug(f"Teams team usage report columns: {list(rows[0].keys())}")
    else:
        logger.warning("Teams team usage report returned no data")
        return {}

    teams_usage = {}
    skipped = 0

    for row in rows:
        # Get team ID - the key field for matching
        team_id = get_csv_field(row, 'Team Id', 'teamId')
        if not team_id:
            skipped += 1
            continue

        # Get team name
        team_name = get_csv_field(row, 'Team Name', 'teamName') or ''

        # Storage used (in bytes)
        storage_bytes = safe_int(get_csv_field(row, 'Storage Used (Byte)', 'storageUsedInBytes'))
        storage_gb = storage_bytes / (1024**3) if storage_bytes else 0.0

        # Channel counts
        active_channels = safe_int(get_csv_field(row, 'Active Channels', 'activeChannels'))
        active_shared_channels = safe_int(get_csv_field(row, 'Active Shared Channels', 'activeSharedChannels'))
        total_channels = safe_int(get_csv_field(row, 'Total Channels', 'totalChannels'))

        # User counts
        active_users = safe_int(get_csv_field(row, 'Active Users', 'activeUsers'))
        active_external_users = safe_int(get_csv_field(row, 'Active External Users', 'activeExternalUsers'))
        active_guests = safe_int(get_csv_field(row, 'Active Guests', 'activeGuests'))

        # Activity counts
        channel_messages = safe_int(get_csv_field(row, 'Post Messages', 'postMessages'))
        reply_messages = safe_int(get_csv_field(row, 'Reply Messages', 'replyMessages'))
        urgent_messages = safe_int(get_csv_field(row, 'Urgent Messages', 'urgentMessages'))
        mentions = safe_int(get_csv_field(row, 'Mentions', 'mentions'))
        meetings_organized = safe_int(get_csv_field(row, 'Meetings Organized', 'meetingsOrganized'))

        # Last activity
        last_activity_date = get_csv_field(row, 'Last Activity Date', 'lastActivityDate') or ''

        teams_usage[team_id.lower()] = {
            'team_id': team_id,
            'team_name': team_name,
            'storage_bytes': storage_bytes,
            'storage_gb': storage_gb,
            'active_channels': active_channels,
            'active_shared_channels': active_shared_channels,
            'total_channels': total_channels,
            'active_users': active_users,
            'active_external_users': active_external_users,
            'active_guests': active_guests,
            'channel_messages': channel_messages,
            'reply_messages': reply_messages,
            'urgent_messages': urgent_messages,
            'mentions': mentions,
            'meetings_organized': meetings_organized,
            'last_activity_date': last_activity_date,
        }

    total_storage_gb = sum(t['storage_gb'] for t in teams_usage.values())
    logger.info(f"Collected usage data for {len(teams_usage)} Teams ({total_storage_gb:.2f} GB total storage)")
    if skipped > 0:
        logger.debug(f"Skipped {skipped} rows without Team ID")

    return teams_usage
