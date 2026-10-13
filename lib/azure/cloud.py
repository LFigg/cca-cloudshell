"""Azure cloud (sovereign cloud) detection and endpoint resolution.

A single collect.py run targets exactly one Azure cloud (public, US
Government, or China), so the resolved config is cached process-wide here
rather than threaded as a parameter through every one of the ~40
azure-mgmt-* client constructor calls across lib/azure/*.py. Each call site
just does `**get_active_cloud().arm_kwargs()`.

Without this, every management client defaults to the public ARM endpoint
(https://management.azure.com) and every credential defaults to the public
AAD authority (https://login.microsoftonline.com) - which is wrong for a
Government tenant and fails as soon as a real API call is made, even once
the credential chain itself succeeds.
"""
import logging
import os
import subprocess
from dataclasses import dataclass
from typing import List, Optional

from azure.core._azure_clouds import AzureClouds
from azure.identity import AzureAuthorityHosts
from azure.mgmt.core.tools import get_arm_endpoints

logger = logging.getLogger(__name__)

# Azure CLI cloud names (`az cloud list --query [].name`) mapped to the SDK's
# own AzureClouds enum, which get_arm_endpoints() below is keyed on.
_CLOUD_NAME_TO_SETTING = {
    'AzureCloud': AzureClouds.AZURE_PUBLIC_CLOUD,
    'AzureUSGovernment': AzureClouds.AZURE_US_GOVERNMENT,
    'AzureChinaCloud': AzureClouds.AZURE_CHINA_CLOUD,
}

_AUTHORITY_BY_SETTING = {
    AzureClouds.AZURE_PUBLIC_CLOUD: AzureAuthorityHosts.AZURE_PUBLIC_CLOUD,
    AzureClouds.AZURE_US_GOVERNMENT: AzureAuthorityHosts.AZURE_GOVERNMENT,
    AzureClouds.AZURE_CHINA_CLOUD: AzureAuthorityHosts.AZURE_CHINA,
}


@dataclass(frozen=True)
class AzureCloudConfig:
    """Resolved AAD/ARM endpoints for one Azure cloud."""

    name: str
    authority: str
    resource_manager: str
    credential_scopes: List[str]

    def arm_kwargs(self) -> dict:
        """kwargs for any azure-mgmt-* ManagementClient/SubscriptionClient constructor."""
        return {'base_url': self.resource_manager, 'credential_scopes': self.credential_scopes}


def resolve_cloud_config(name: str) -> AzureCloudConfig:
    """Build an AzureCloudConfig for an Azure CLI cloud name, e.g. 'AzureUSGovernment'."""
    try:
        setting = _CLOUD_NAME_TO_SETTING[name]
    except KeyError:
        raise ValueError(
            f"Unknown Azure cloud '{name}'. Valid values: {', '.join(_CLOUD_NAME_TO_SETTING)}"
        )
    endpoints = get_arm_endpoints(setting)
    return AzureCloudConfig(
        name=name,
        authority=_AUTHORITY_BY_SETTING[setting],
        resource_manager=endpoints['resource_manager'].rstrip('/'),
        credential_scopes=list(endpoints['credential_scopes']),
    )


def detect_azure_cloud(explicit: Optional[str] = None) -> AzureCloudConfig:
    """Resolve which Azure cloud this run targets.

    Resolution order: `explicit` (e.g. a --azure-cloud CLI flag) >
    AZURE_CLOUD environment variable > the Azure CLI's configured active
    cloud (Cloud Shell sets this to match the portal it was opened from,
    e.g. portal.azure.us -> AzureUSGovernment) > AzureCloud (public), the
    SDK default.
    """
    name = explicit or os.environ.get('AZURE_CLOUD') or _active_cli_cloud_name() or 'AzureCloud'
    return resolve_cloud_config(name)


def _active_cli_cloud_name() -> Optional[str]:
    """The Azure CLI's active cloud name, or None if `az` isn't available/configured."""
    try:
        result = subprocess.run(
            ['az', 'cloud', 'show', '--query', 'name', '-o', 'tsv'],
            capture_output=True, text=True, timeout=10, check=True,
        )
        return result.stdout.strip() or None
    except Exception as e:
        logger.debug(f"Could not determine the Azure CLI's active cloud: {e}")
        return None


_active_cloud: Optional[AzureCloudConfig] = None


def set_active_cloud(cloud: AzureCloudConfig) -> None:
    """Set the cloud every azure-mgmt client built for the rest of this process uses."""
    global _active_cloud
    _active_cloud = cloud


def get_active_cloud() -> AzureCloudConfig:
    """The cloud set by set_active_cloud(), or AzureCloud (public) if never set."""
    return _active_cloud or resolve_cloud_config('AzureCloud')
