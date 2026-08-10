"""
M365 Collection Module - Authentication

Microsoft Graph API client initialization and credential handling.
"""

import logging
from typing import Optional, Tuple

from azure.identity import ClientSecretCredential
from msgraph.graph_service_client import GraphServiceClient

from lib.utils import check_and_raise_auth_error

logger = logging.getLogger(__name__)

# Graph API scopes
GRAPH_SCOPES = ['https://graph.microsoft.com/.default']


def get_graph_client(
    tenant_id: str,
    client_id: str,
    client_secret: str
) -> Tuple[GraphServiceClient, ClientSecretCredential]:
    """Create Microsoft Graph API client using client credentials.

    Args:
        tenant_id: Azure AD tenant ID
        client_id: App registration client/application ID
        client_secret: App registration client secret

    Returns:
        Tuple of (configured GraphServiceClient, the credential used to build
        it). Callers that need to fetch a usage report or paginate via raw
        HTTP (lib.m365.helpers.get_usage_report()/collect_all_pages_sync())
        need the credential explicitly - pass it down alongside graph_client
        rather than reaching for a module global.
    """
    credential = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret
    )
    return GraphServiceClient(credentials=credential, scopes=GRAPH_SCOPES), credential


def get_tenant_id_from_client(graph_client: GraphServiceClient) -> Optional[str]:
    """Extract tenant ID from Graph client if possible.

    Args:
        graph_client: Configured GraphServiceClient

    Returns:
        Tenant ID string if extractable, None otherwise
    """
    # The tenant ID can be extracted from organization info
    # This is a convenience method but requires making an API call
    from .helpers import run_sync
    try:
        org_response = run_sync(graph_client.organization.get())
        if org_response and org_response.value:
            return org_response.value[0].id
    except Exception as e:
        check_and_raise_auth_error(e, "extract tenant ID", "m365")
        logger.warning(f"Could not extract tenant ID: {e}")
    return None
