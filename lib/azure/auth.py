"""Azure authentication and subscription discovery."""
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


def get_credential():
    """Get Azure credential. In Cloud Shell, uses managed identity."""
    from azure.identity import DefaultAzureCredential
    return DefaultAzureCredential()


def get_subscriptions(credential) -> List[Dict]:
    """Get all accessible subscriptions."""
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
