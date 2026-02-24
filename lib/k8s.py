"""
Kubernetes PVC collection utilities for EKS, AKS, and GKE clusters.

This module provides functions to:
1. Authenticate to K8s clusters via cloud provider credentials
2. Collect PersistentVolumeClaims (PVCs) and related resources
3. Map PVCs to their backing storage and consuming pods
"""
import base64
import logging
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from lib.models import CloudResource

logger = logging.getLogger(__name__)


@dataclass
class PVCInfo:
    """Detailed PVC information."""
    cluster_name: str
    namespace: str
    name: str
    storage_class: str
    access_modes: List[str]
    requested_size_gb: float
    actual_size_gb: float  # From bound PV
    status: str  # Bound, Pending, Lost
    bound_pv: str
    volume_mode: str  # Filesystem, Block
    pods_using: List[str]
    labels: Dict[str, str] = field(default_factory=dict)
    creation_time: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'cluster_name': self.cluster_name,
            'namespace': self.namespace,
            'name': self.name,
            'storage_class': self.storage_class,
            'access_modes': self.access_modes,
            'requested_size_gb': self.requested_size_gb,
            'actual_size_gb': self.actual_size_gb,
            'status': self.status,
            'bound_pv': self.bound_pv,
            'volume_mode': self.volume_mode,
            'pods_using': self.pods_using,
            'labels': self.labels,
            'creation_time': self.creation_time
        }


def parse_k8s_storage_size(size_str: str) -> float:
    """
    Parse Kubernetes storage size string to GB.
    
    Examples: "10Gi" -> 10.0, "100Mi" -> 0.1, "1Ti" -> 1024.0
    """
    if not size_str:
        return 0.0
    
    try:
        size_str = str(size_str).strip()
        
        # Handle numeric-only values (assume bytes)
        if size_str.isdigit():
            return float(size_str) / (1024**3)
        
        # Extract number and unit
        unit = ''
        num_str = size_str
        
        for suffix in ['Ti', 'Gi', 'Mi', 'Ki', 'T', 'G', 'M', 'K']:
            if size_str.endswith(suffix):
                unit = suffix
                num_str = size_str[:-len(suffix)]
                break
        
        value = float(num_str)
        
        # Convert to GB based on unit
        multipliers = {
            'Ti': 1024.0,      # Tebibyte
            'T': 1000.0,       # Terabyte
            'Gi': 1.0,         # Gibibyte 
            'G': 1000/1024,    # Gigabyte
            'Mi': 1/1024,      # Mebibyte
            'M': 1/1000,       # Megabyte
            'Ki': 1/(1024**2), # Kibibyte
            'K': 1/(1000**2),  # Kilobyte
            '': 1/(1024**3)    # Bytes
        }
        
        return value * multipliers.get(unit, 1/(1024**3))
    except (ValueError, AttributeError):
        logger.warning(f"Could not parse storage size: {size_str}")
        return 0.0


def get_k8s_client(
    api_endpoint: str,
    token: str,
    ca_data: Optional[str] = None,
    skip_tls_verify: bool = False
):
    """
    Create a Kubernetes API client.
    
    Args:
        api_endpoint: Kubernetes API server URL
        token: Bearer token for authentication
        ca_data: Base64-encoded CA certificate data
        skip_tls_verify: Skip TLS verification (not recommended)
    
    Returns:
        kubernetes.client.CoreV1Api instance or None
    """
    try:
        from kubernetes import client as k8s_client  # type: ignore[import-not-found]
        from kubernetes.client import Configuration  # type: ignore[import-not-found]
        
        config = Configuration()
        config.host = api_endpoint
        config.api_key = {"authorization": f"Bearer {token}"}
        config.api_key_prefix = {"authorization": "Bearer"}
        
        if skip_tls_verify:
            config.verify_ssl = False
        elif ca_data:
            # Write CA cert to temp file
            ca_bytes = base64.b64decode(ca_data)
            with tempfile.NamedTemporaryFile(delete=False, suffix='.crt') as f:
                f.write(ca_bytes)
                config.ssl_ca_cert = f.name
        
        api_client = k8s_client.ApiClient(config)
        return k8s_client.CoreV1Api(api_client)
        
    except ImportError:
        logger.warning("kubernetes package not installed. Install with: pip install kubernetes")
        return None
    except Exception as e:
        logger.error(f"Failed to create K8s client: {e}")
        return None


def collect_pvcs_from_cluster(
    core_api,
    cluster_name: str,
    namespaces: Optional[List[str]] = None
) -> Tuple[List[PVCInfo], Dict[str, Any]]:
    """
    Collect all PVCs from a Kubernetes cluster.
    
    Args:
        core_api: kubernetes.client.CoreV1Api instance
        cluster_name: Name of the cluster (for identification)
        namespaces: Optional list of namespaces to filter (None = all)
    
    Returns:
        Tuple of (list of PVCInfo, cluster_stats dict)
    """
    pvcs = []
    stats = {
        'cluster_name': cluster_name,
        'total_pvcs': 0,
        'total_requested_gb': 0.0,
        'total_actual_gb': 0.0,
        'bound_count': 0,
        'pending_count': 0,
        'namespaces_scanned': 0,
        'storage_classes': {}
    }
    
    try:
        # Get all PVs for size lookup (actual allocated size)
        pv_sizes = {}
        try:
            pvs = core_api.list_persistent_volume()
            for pv in pvs.items:
                capacity = pv.spec.capacity.get('storage', '0') if pv.spec.capacity else '0'
                pv_sizes[pv.metadata.name] = parse_k8s_storage_size(capacity)
        except Exception as e:
            logger.warning(f"[{cluster_name}] Could not list PVs: {e}")
        
        # Build pod -> PVC mappings
        pvc_to_pods: Dict[str, List[str]] = {}
        try:
            pods = core_api.list_pod_for_all_namespaces()
            for pod in pods.items:
                if pod.spec.volumes:
                    for vol in pod.spec.volumes:
                        if vol.persistent_volume_claim:
                            pvc_key = f"{pod.metadata.namespace}/{vol.persistent_volume_claim.claim_name}"
                            if pvc_key not in pvc_to_pods:
                                pvc_to_pods[pvc_key] = []
                            pvc_to_pods[pvc_key].append(pod.metadata.name)
        except Exception as e:
            logger.warning(f"[{cluster_name}] Could not list pods for PVC mapping: {e}")
        
        # Get PVCs
        if namespaces:
            all_pvcs = []
            for ns in namespaces:
                try:
                    ns_pvcs = core_api.list_namespaced_persistent_volume_claim(namespace=ns)
                    all_pvcs.extend(ns_pvcs.items)
                    stats['namespaces_scanned'] += 1
                except Exception as e:
                    logger.warning(f"[{cluster_name}] Could not list PVCs in namespace {ns}: {e}")
        else:
            all_pvcs_response = core_api.list_persistent_volume_claim_for_all_namespaces()
            all_pvcs = all_pvcs_response.items
            # Count unique namespaces
            stats['namespaces_scanned'] = len(set(pvc.metadata.namespace for pvc in all_pvcs))
        
        for pvc in all_pvcs:
            ns = pvc.metadata.namespace
            name = pvc.metadata.name
            
            # Parse requested size
            requests = pvc.spec.resources.requests if pvc.spec.resources else {}
            requested_size = parse_k8s_storage_size(requests.get('storage', '0'))
            
            # Get actual size from bound PV
            bound_pv = pvc.spec.volume_name or ''
            actual_size = pv_sizes.get(bound_pv, requested_size)
            
            # Get storage class
            storage_class = pvc.spec.storage_class_name or 'default'
            
            # Track storage class usage
            if storage_class not in stats['storage_classes']:
                stats['storage_classes'][storage_class] = {'count': 0, 'size_gb': 0.0}
            stats['storage_classes'][storage_class]['count'] += 1
            stats['storage_classes'][storage_class]['size_gb'] += requested_size
            
            # Get pods using this PVC
            pvc_key = f"{ns}/{name}"
            pods_using = pvc_to_pods.get(pvc_key, [])
            
            # Get status
            status = pvc.status.phase if pvc.status else 'Unknown'
            if status == 'Bound':
                stats['bound_count'] += 1
            elif status == 'Pending':
                stats['pending_count'] += 1
            
            # Get access modes
            access_modes = list(pvc.spec.access_modes) if pvc.spec.access_modes else []
            
            # Get volume mode
            volume_mode = pvc.spec.volume_mode or 'Filesystem'
            
            # Get creation time
            creation_time = None
            if pvc.metadata.creation_timestamp:
                creation_time = pvc.metadata.creation_timestamp.isoformat()
            
            pvc_info = PVCInfo(
                cluster_name=cluster_name,
                namespace=ns,
                name=name,
                storage_class=storage_class,
                access_modes=access_modes,
                requested_size_gb=round(requested_size, 2),
                actual_size_gb=round(actual_size, 2),
                status=status,
                bound_pv=bound_pv,
                volume_mode=volume_mode,
                pods_using=pods_using,
                labels=dict(pvc.metadata.labels) if pvc.metadata.labels else {},
                creation_time=creation_time
            )
            pvcs.append(pvc_info)
            
            stats['total_pvcs'] += 1
            stats['total_requested_gb'] += requested_size
            stats['total_actual_gb'] += actual_size
        
        logger.info(f"[{cluster_name}] Found {len(pvcs)} PVCs across {stats['namespaces_scanned']} namespaces")
        
    except Exception as e:
        logger.error(f"[{cluster_name}] Failed to collect PVCs: {e}")
    
    return pvcs, stats


# =============================================================================
# AWS EKS Authentication
# =============================================================================

def get_eks_token(session, cluster_name: str, region: str) -> Optional[str]:
    """
    Get a bearer token for EKS cluster authentication.
    
    Uses STS to generate a presigned URL that EKS accepts as a bearer token.
    This is equivalent to `aws eks get-token`.
    """
    try:
        import base64
        from botocore.signers import RequestSigner  # type: ignore[import-not-found]
        
        STS_TOKEN_EXPIRES_IN = 60 * 14  # 14 minutes (EKS tokens valid for 15 min)
        
        sts_client = session.client('sts', region_name=region)
        service_id = sts_client.meta.service_model.service_id
        
        signer = RequestSigner(
            service_id,
            region,
            'sts',
            'v4',
            session.get_credentials(),
            session.events
        )
        
        params = {
            'method': 'GET',
            'url': f'https://sts.{region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15',
            'body': {},
            'headers': {
                'x-k8s-aws-id': cluster_name
            },
            'context': {}
        }
        
        signed_url = signer.generate_presigned_url(
            params,
            region_name=region,
            expires_in=STS_TOKEN_EXPIRES_IN,
            operation_name=''
        )
        
        # Token is "k8s-aws-v1." + base64(signed_url)
        token = 'k8s-aws-v1.' + base64.urlsafe_b64encode(
            signed_url.encode('utf-8')
        ).decode('utf-8').rstrip('=')
        
        return token
        
    except Exception as e:
        logger.error(f"Failed to get EKS token for {cluster_name}: {e}")
        return None


def get_eks_cluster_config(session, cluster_name: str, region: str) -> Optional[Dict]:
    """
    Get EKS cluster endpoint and CA data.
    
    Returns dict with 'endpoint' and 'ca_data' keys.
    """
    try:
        eks = session.client('eks', region_name=region)
        cluster = eks.describe_cluster(name=cluster_name)['cluster']
        
        return {
            'endpoint': cluster.get('endpoint'),
            'ca_data': cluster.get('certificateAuthority', {}).get('data')
        }
    except Exception as e:
        logger.error(f"Failed to get EKS cluster config for {cluster_name}: {e}")
        return None


def collect_eks_pvcs(session, cluster_name: str, region: str, account_id: str) -> "List[CloudResource]":
    """
    Collect PVCs from an EKS cluster.
    
    Returns list of CloudResource objects.
    """
    from lib.models import CloudResource
    
    resources = []
    
    # Get cluster config
    config = get_eks_cluster_config(session, cluster_name, region)
    if not config:
        logger.warning(f"[{region}] Could not get config for EKS cluster {cluster_name}")
        return resources
    
    # Get auth token
    token = get_eks_token(session, cluster_name, region)
    if not token:
        logger.warning(f"[{region}] Could not get token for EKS cluster {cluster_name}")
        return resources
    
    # Create K8s client
    core_api = get_k8s_client(
        api_endpoint=config['endpoint'],
        token=token,
        ca_data=config['ca_data']
    )
    
    if not core_api:
        return resources
    
    # Collect PVCs
    pvcs, stats = collect_pvcs_from_cluster(core_api, cluster_name)
    
    # Convert to CloudResource format
    for pvc in pvcs:
        resource = CloudResource(
            provider="aws",
            account_id=account_id,
            region=region,
            resource_type="aws:eks:pvc",
            service_family="EKS",
            resource_id=f"arn:aws:eks:{region}:{account_id}:cluster/{cluster_name}/pvc/{pvc.namespace}/{pvc.name}",
            name=f"{pvc.namespace}/{pvc.name}",
            tags=pvc.labels,
            size_gb=pvc.actual_size_gb,
            parent_resource_id=f"arn:aws:eks:{region}:{account_id}:cluster/{cluster_name}",
            metadata={
                'cluster_name': cluster_name,
                'namespace': pvc.namespace,
                'pvc_name': pvc.name,
                'storage_class': pvc.storage_class,
                'access_modes': pvc.access_modes,
                'requested_size_gb': pvc.requested_size_gb,
                'status': pvc.status,
                'bound_pv': pvc.bound_pv,
                'volume_mode': pvc.volume_mode,
                'pods_using': pvc.pods_using,
                'creation_time': pvc.creation_time
            }
        )
        resources.append(resource)
    
    return resources


# =============================================================================
# Azure AKS Authentication
# =============================================================================

def get_aks_credentials(credential, subscription_id: str, resource_group: str, cluster_name: str) -> Optional[Dict]:
    """
    Get AKS cluster credentials (kubeconfig data).
    
    Returns dict with 'endpoint', 'token', and 'ca_data'.
    """
    try:
        from azure.mgmt.containerservice import ContainerServiceClient  # type: ignore[import-not-found]
        
        aks_client = ContainerServiceClient(credential, subscription_id)
        
        # Get admin credentials (includes token)
        creds = aks_client.managed_clusters.list_cluster_admin_credentials(
            resource_group_name=resource_group,
            resource_name=cluster_name
        )
        
        if not creds.kubeconfigs:
            logger.warning(f"No kubeconfig returned for AKS cluster {cluster_name}")
            return None
        
        # Parse kubeconfig YAML
        import yaml  # type: ignore[import-not-found]
        kubeconfig_data = creds.kubeconfigs[0].value.decode('utf-8')
        kubeconfig = yaml.safe_load(kubeconfig_data)
        
        cluster_info = kubeconfig.get('clusters', [{}])[0].get('cluster', {})
        user_info = kubeconfig.get('users', [{}])[0].get('user', {})
        
        # Get token (could be in token field or exec command)
        token = user_info.get('token')
        
        # If using Azure AD auth, we need to get token differently
        if not token and user_info.get('exec'):
            # Token requires exec - try to use Azure credential directly
            try:
                from azure.identity import DefaultAzureCredential  # type: ignore[import-not-found]
                # Get a token for the AKS cluster
                access_token = credential.get_token("6dae42f8-4368-4678-94ff-3960e28e3630/.default")
                token = access_token.token
            except Exception as e:
                logger.warning(f"Could not get Azure AD token for AKS: {e}")
                return None
        
        return {
            'endpoint': cluster_info.get('server'),
            'ca_data': cluster_info.get('certificate-authority-data'),
            'token': token
        }
        
    except Exception as e:
        logger.error(f"Failed to get AKS credentials for {cluster_name}: {e}")
        return None


def collect_aks_pvcs(credential, subscription_id: str, resource_group: str, cluster_name: str, location: str) -> "List[CloudResource]":
    """
    Collect PVCs from an AKS cluster.
    
    Returns list of CloudResource objects.
    """
    from lib.models import CloudResource
    
    resources = []
    
    # Get cluster credentials
    creds = get_aks_credentials(credential, subscription_id, resource_group, cluster_name)
    if not creds or not creds.get('token'):
        logger.warning(f"Could not get credentials for AKS cluster {cluster_name}")
        return resources
    
    # Create K8s client
    core_api = get_k8s_client(
        api_endpoint=creds['endpoint'],
        token=creds['token'],
        ca_data=creds.get('ca_data')
    )
    
    if not core_api:
        return resources
    
    # Collect PVCs
    pvcs, stats = collect_pvcs_from_cluster(core_api, cluster_name)
    
    # Convert to CloudResource format
    for pvc in pvcs:
        resource = CloudResource(
            provider="azure",
            subscription_id=subscription_id,
            region=location,
            resource_type="azure:aks:pvc",
            service_family="AKS",
            resource_id=f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.ContainerService/managedClusters/{cluster_name}/pvc/{pvc.namespace}/{pvc.name}",
            name=f"{pvc.namespace}/{pvc.name}",
            tags=pvc.labels,
            size_gb=pvc.actual_size_gb,
            parent_resource_id=f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.ContainerService/managedClusters/{cluster_name}",
            metadata={
                'cluster_name': cluster_name,
                'resource_group': resource_group,
                'namespace': pvc.namespace,
                'pvc_name': pvc.name,
                'storage_class': pvc.storage_class,
                'access_modes': pvc.access_modes,
                'requested_size_gb': pvc.requested_size_gb,
                'status': pvc.status,
                'bound_pv': pvc.bound_pv,
                'volume_mode': pvc.volume_mode,
                'pods_using': pvc.pods_using,
                'creation_time': pvc.creation_time
            }
        )
        resources.append(resource)
    
    return resources


# =============================================================================
# GCP GKE Authentication
# =============================================================================

def get_gke_credentials(project_id: str, location: str, cluster_name: str) -> Optional[Dict]:
    """
    Get GKE cluster credentials.
    
    Returns dict with 'endpoint', 'token', and 'ca_data'.
    """
    try:
        from google.cloud import container_v1  # type: ignore[import-not-found]
        import google.auth  # type: ignore[import-not-found]
        import google.auth.transport.requests  # type: ignore[import-not-found]
        
        # Get cluster info
        client = container_v1.ClusterManagerClient()
        cluster_path = f"projects/{project_id}/locations/{location}/clusters/{cluster_name}"
        cluster = client.get_cluster(name=cluster_path)
        
        # Get credentials
        credentials, _ = google.auth.default()
        credentials.refresh(google.auth.transport.requests.Request())
        
        return {
            'endpoint': f"https://{cluster.endpoint}",
            'ca_data': cluster.master_auth.cluster_ca_certificate,
            'token': credentials.token
        }
        
    except Exception as e:
        logger.error(f"Failed to get GKE credentials for {cluster_name}: {e}")
        return None


def collect_gke_pvcs(project_id: str, location: str, cluster_name: str) -> "List[CloudResource]":
    """
    Collect PVCs from a GKE cluster.
    
    Returns list of CloudResource objects.
    """
    from lib.models import CloudResource
    
    resources = []
    
    # Get cluster credentials
    creds = get_gke_credentials(project_id, location, cluster_name)
    if not creds:
        logger.warning(f"Could not get credentials for GKE cluster {cluster_name}")
        return resources
    
    # Create K8s client
    core_api = get_k8s_client(
        api_endpoint=creds['endpoint'],
        token=creds['token'],
        ca_data=creds.get('ca_data')
    )
    
    if not core_api:
        return resources
    
    # Collect PVCs
    pvcs, stats = collect_pvcs_from_cluster(core_api, cluster_name)
    
    # Convert to CloudResource format
    for pvc in pvcs:
        resource = CloudResource(
            provider="gcp",
            account_id=project_id,
            region=location,
            resource_type="gcp:gke:pvc",
            service_family="GKE",
            resource_id=f"projects/{project_id}/locations/{location}/clusters/{cluster_name}/pvc/{pvc.namespace}/{pvc.name}",
            name=f"{pvc.namespace}/{pvc.name}",
            tags=pvc.labels,
            size_gb=pvc.actual_size_gb,
            parent_resource_id=f"projects/{project_id}/locations/{location}/clusters/{cluster_name}",
            metadata={
                'cluster_name': cluster_name,
                'namespace': pvc.namespace,
                'pvc_name': pvc.name,
                'storage_class': pvc.storage_class,
                'access_modes': pvc.access_modes,
                'requested_size_gb': pvc.requested_size_gb,
                'status': pvc.status,
                'bound_pv': pvc.bound_pv,
                'volume_mode': pvc.volume_mode,
                'pods_using': pvc.pods_using,
                'creation_time': pvc.creation_time
            }
        )
        resources.append(resource)
    
    return resources
