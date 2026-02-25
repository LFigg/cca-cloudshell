"""
Data models for CCA CloudShell collectors.
"""
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CloudResource:
    """
    Normalized cloud resource representation.
    """
    # Cloud provider info
    provider: str  # "aws", "azure", or "m365"
    account_id: Optional[str] = None  # AWS account ID
    subscription_id: Optional[str] = None  # Azure subscription ID or M365 tenant ID
    region: Optional[str] = None

    # Resource identification
    resource_type: str = ""  # e.g., "aws:ec2:instance", "azure:vm"
    service_family: str = ""  # e.g., "EC2", "RDS", "AzureVM"
    resource_id: str = ""
    name: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)

    # Capacity and sizing
    size_gb: float = 0.0

    # Relationships
    parent_resource_id: Optional[str] = None

    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class SizingSummary:
    """Aggregated sizing summary."""
    provider: str
    service_family: str
    resource_type: str
    resource_count: int = 0
    total_gb: float = 0.0

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return asdict(self)


def aggregate_sizing(resources: List[CloudResource]) -> List[SizingSummary]:
    """
    Aggregate resources into sizing summaries.
    """
    summaries: Dict[str, SizingSummary] = {}

    for resource in resources:
        key = f"{resource.provider}:{resource.service_family}:{resource.resource_type}"

        if key not in summaries:
            summaries[key] = SizingSummary(
                provider=resource.provider,
                service_family=resource.service_family,
                resource_type=resource.resource_type,
            )

        summaries[key].resource_count += 1
        summaries[key].total_gb += resource.size_gb

    return list(summaries.values())

