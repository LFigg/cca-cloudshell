"""Azure authentication and subscription discovery."""
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


def get_credential():
    """Get Azure credential.

    Managed identity is excluded: Azure Cloud Shell sets MSI_ENDPOINT for its
    legacy Cloud Shell identity relay, which ManagedIdentityCredential picks up
    ahead of AzureCliCredential. That relay doesn't support the ARM audience
    (https://management.azure.com) and fails with a ClientAuthenticationError
    rather than CredentialUnavailableError, which aborts the whole credential
    chain before AzureCliCredential (the one that actually works in Cloud
    Shell, since the session is already signed in) ever gets a turn.

    The authority is set from the active Azure cloud (see lib/azure/cloud.py)
    so a Government Cloud Shell session authenticates against
    login.microsoftonline.us instead of the public AAD authority.

    Returns:
        A DefaultAzureCredential instance
    """
    from azure.identity import DefaultAzureCredential

    from lib.azure.cloud import get_active_cloud
    return DefaultAzureCredential(
        exclude_managed_identity_credential=True,
        authority=get_active_cloud().authority,
    )


def get_subscriptions(credential) -> List[Dict]:
    """Get all accessible subscriptions.

    Args:
        credential: Azure credential object

    Returns:
        List of dicts with 'id', 'name', and 'state' for each subscription
    """
    from azure.mgmt.subscription import SubscriptionClient

    from lib.azure.cloud import get_active_cloud
    subscription_client = SubscriptionClient(credential, **get_active_cloud().arm_kwargs())
    subscriptions = []

    for sub in subscription_client.subscriptions.list():
        subscriptions.append({
            'id': sub.subscription_id,
            'name': sub.display_name,
            'state': sub.state
        })

    return subscriptions
