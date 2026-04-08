"""
M365 Collection Module - Authentication

Microsoft Graph API client initialization and credential handling.
"""

import logging
import os
from typing import Optional

from azure.identity import ClientSecretCredential, DefaultAzureCredential
from msgraph.graph_service_client import GraphServiceClient

from .helpers import set_graph_credential

logger = logging.getLogger(__name__)

# Graph API scopes
GRAPH_SCOPES = ['https://graph.microsoft.com/.default']


def _is_azure_environment() -> bool:
    """Check if running in Azure Cloud Shell or Azure VM."""
    # Azure Cloud Shell sets these
    if os.environ.get('AZURE_HTTP_USER_AGENT') or os.environ.get('ACC_CLOUD'):
        return True
    # Azure IMDS is only available on Azure VMs
    if os.environ.get('MSI_ENDPOINT') or os.environ.get('IDENTITY_ENDPOINT'):
        return True
    return False


def get_graph_client(
    tenant_id: str,
    client_id: str,
    client_secret: str
) -> GraphServiceClient:
    """Create Microsoft Graph API client using client credentials.

    Args:
        tenant_id: Azure AD tenant ID
        client_id: App registration client/application ID
        client_secret: App registration client secret

    Returns:
        Configured GraphServiceClient
    """
    credential = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret
    )
    set_graph_credential(credential)  # Store for pagination helpers
    return GraphServiceClient(credentials=credential, scopes=GRAPH_SCOPES)


def get_graph_client_default_credential() -> GraphServiceClient:
    """Create Microsoft Graph API client using DefaultAzureCredential.

    This uses the Azure Identity credential chain, which tries (in order):
    1. Environment variables (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
    2. Managed Identity (when running on Azure VMs, App Service, etc.)
    3. Azure CLI credentials (az login)
    4. Azure PowerShell credentials
    5. Interactive browser login (if enabled)

    This is the recommended approach for:
    - Azure Cloud Shell (uses managed identity automatically)
    - Azure VMs with managed identity
    - Local development with Azure CLI login

    Returns:
        Configured GraphServiceClient
    """
    # Skip ManagedIdentityCredential on non-Azure machines to avoid IMDS timeout
    # IMDS endpoint doesn't exist outside Azure, causing long hangs
    exclude_mi = not _is_azure_environment()
    if exclude_mi:
        logger.debug("Not in Azure environment, skipping ManagedIdentityCredential")

    credential = DefaultAzureCredential(
        exclude_managed_identity_credential=exclude_mi
    )
    set_graph_credential(credential)  # Store for pagination helpers
    return GraphServiceClient(credentials=credential, scopes=GRAPH_SCOPES)


def get_tenant_id_from_client(graph_client: GraphServiceClient) -> Optional[str]:
    """Extract tenant ID from Graph client if possible.

    This is useful when using DefaultAzureCredential where tenant ID
    isn't explicitly provided.

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
        logger.debug(f"Could not extract tenant ID: {e}")
    return None
