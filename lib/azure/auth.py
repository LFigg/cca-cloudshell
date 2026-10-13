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

    Returns:
        A DefaultAzureCredential instance
    """
    from azure.identity import DefaultAzureCredential
    return DefaultAzureCredential(exclude_managed_identity_credential=True)


def get_subscriptions(credential) -> List[Dict]:
    """Get all accessible subscriptions.

    Args:
        credential: Azure credential object

    Returns:
        List of dicts with 'id', 'name', and 'state' for each subscription
    """
    from azure.mgmt.subscription import SubscriptionClient

    subscription_client = SubscriptionClient(credential)
    subscriptions = []

    for sub in subscription_client.subscriptions.list():
        subscriptions.append({
            'id': sub.subscription_id,
            'name': sub.display_name,
            'state': sub.state
        })

    return subscriptions
