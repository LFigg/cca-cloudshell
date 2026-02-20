"""
Utility functions for CCA CloudShell collectors.

Logging Level Standards:
------------------------
- ERROR: Collection function failures that stop an entire resource type
         "Failed to collect VMs: {e}"
- WARNING: Partial failures (nested loops), missing optional dependencies
           "Failed to assume role in account {id}: {e}"
           "azure-mgmt-redis not installed. Skipping Redis..."
- INFO: Progress messages, resource counts
        "Found 42 EC2 instances"
        "Collecting resources from subscription..."
- DEBUG: Per-item failures that don't affect overall collection
         "Failed to process item {id}: {e}"
"""
import json
import csv
import logging
import os
import sys
from datetime import datetime, timezone
from typing import List, Dict, Any, Callable, TypeVar, Optional, TYPE_CHECKING
import uuid
from functools import wraps

# Type checking imports (not imported at runtime)
if TYPE_CHECKING:
    from rich.console import Console  # type: ignore[import-untyped]
    from rich.progress import Progress, TaskID  # type: ignore[import-untyped]

# Retry decorator for API calls
try:
    from tenacity import (  # type: ignore[import-untyped]
        retry,
        stop_after_attempt,
        wait_exponential,
        retry_if_exception_type,
        before_sleep_log,
    )
    TENACITY_AVAILABLE = True
except ImportError:
    TENACITY_AVAILABLE = False

# Progress display with rich
try:
    from rich.console import Console  # type: ignore[import-untyped]
    from rich.progress import (  # type: ignore[import-untyped]
        Progress,
        SpinnerColumn,
        TextColumn,
        BarColumn,
        TaskProgressColumn,
        TimeElapsedColumn,
        MofNCompleteColumn,
    )
    from rich.live import Live  # type: ignore[import-untyped]
    from rich.table import Table  # type: ignore[import-untyped]
    from rich.panel import Panel  # type: ignore[import-untyped]
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

logger = logging.getLogger(__name__)

# Type variable for generic function decorator
F = TypeVar('F', bound=Callable[..., Any])


def retry_with_backoff(
    max_attempts: int = 3,
    min_wait: float = 1,
    max_wait: float = 60,
    exceptions: tuple = (Exception,)
) -> Callable[[F], F]:
    """
    Decorator for retrying functions with exponential backoff.
    
    Args:
        max_attempts: Maximum number of retry attempts (default: 3)
        min_wait: Minimum wait time between retries in seconds (default: 1)
        max_wait: Maximum wait time between retries in seconds (default: 60)
        exceptions: Tuple of exception types to retry on (default: all Exceptions)
    
    Returns:
        Decorated function with retry logic
    
    Example:
        @retry_with_backoff(max_attempts=5, exceptions=(ConnectionError, TimeoutError))
        def call_api():
            ...
    """
    if TENACITY_AVAILABLE:
        def decorator(func: F) -> F:
            # These are guaranteed to be defined when TENACITY_AVAILABLE is True
            return retry(  # type: ignore[possibly-undefined]
                stop=stop_after_attempt(max_attempts),  # type: ignore[possibly-undefined]
                wait=wait_exponential(multiplier=1, min=min_wait, max=max_wait),  # type: ignore[possibly-undefined]
                retry=retry_if_exception_type(exceptions),  # type: ignore[possibly-undefined]
                before_sleep=before_sleep_log(logger, logging.WARNING),  # type: ignore[possibly-undefined]
                reraise=True
            )(func)
        return decorator
    else:
        # Fallback implementation without tenacity
        def decorator(func: F) -> F:
            @wraps(func)
            def wrapper(*args, **kwargs):
                last_exception: BaseException = Exception("No attempts made")
                wait_time = min_wait
                
                for attempt in range(max_attempts):
                    try:
                        return func(*args, **kwargs)
                    except exceptions as e:
                        last_exception = e
                        if attempt < max_attempts - 1:
                            logger.warning(
                                f"Retry {attempt + 1}/{max_attempts} for {func.__name__} "
                                f"after {wait_time}s due to: {e}"
                            )
                            import time
                            time.sleep(wait_time)
                            wait_time = min(wait_time * 2, max_wait)
                        else:
                            raise
                raise last_exception
            return wrapper  # type: ignore
        return decorator


# =============================================================================
# Progress Tracking
# =============================================================================

class ProgressTracker:
    """
    Progress tracker for collection operations with rich display.
    
    Falls back to simple print statements if rich is not available or
    stdout is not a TTY (e.g., when piping output).
    
    Usage:
        with ProgressTracker("AWS", total_regions=5) as tracker:
            for region in regions:
                tracker.start_region(region)
                
                for task in tasks:
                    tracker.update_task(f"Collecting {task}...")
                    resources = collect_task(...)
                    tracker.add_resources(len(resources), sum(r.size_gb for r in resources))
                
                tracker.complete_region()
    """
    
    def __init__(
        self,
        provider: str,
        total_regions: int = 0,
        total_accounts: int = 0,
        show_progress: bool = True
    ):
        self.provider = provider
        self.total_regions = total_regions
        self.total_accounts = total_accounts
        self.show_progress = show_progress and sys.stdout.isatty()
        
        # Counters
        self.completed_regions = 0
        self.completed_accounts = 0
        self.total_resources = 0
        self.total_capacity_gb = 0.0
        self.current_region = ""
        self.current_account = ""
        self.current_task = ""
        
        # Rich components (typed for IDE support)
        self._console: Optional["Console"] = None
        self._progress: Optional["Progress"] = None
        self._live = None
        self._main_task: Optional["TaskID"] = None
        self._use_rich = RICH_AVAILABLE and self.show_progress
    
    def __enter__(self):
        if self._use_rich:
            from rich.console import Console  # type: ignore[import-untyped]
            from rich.progress import (  # type: ignore[import-untyped]
                Progress, SpinnerColumn, TextColumn, 
                BarColumn, MofNCompleteColumn, TimeElapsedColumn
            )
            self._console = Console()
            self._progress = Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=self._console,
                transient=False,
            )
            
            total = self.total_regions or self.total_accounts or 1
            desc = f"{self.provider} Collection"
            assert self._progress is not None  # Guaranteed by _use_rich check above
            self._main_task = self._progress.add_task(desc, total=total)
            self._progress.start()
        else:
            print(f"\n{'='*60}")
            print(f"{self.provider} Collection Starting")
            print(f"{'='*60}")
            if self.total_regions:
                print(f"Regions: {self.total_regions}")
            if self.total_accounts:
                print(f"Accounts: {self.total_accounts}")
            print()
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._use_rich:
            assert self._progress is not None
            assert self._console is not None
            self._progress.stop()
            self._console.print()
            self._print_summary_rich()
        else:
            self._print_summary_plain()
        return False
    
    def start_region(self, region: str):
        """Mark the start of processing a region."""
        self.current_region = region
        if self._use_rich:
            assert self._progress is not None
            self._progress.update(
                self._main_task,
                description=f"{self.provider} [{region}]"
            )
        else:
            print(f"  [{region}] Starting collection...")
    
    def start_account(self, account_id: str, account_name: str = ""):
        """Mark the start of processing an account."""
        self.current_account = account_id
        display = f"{account_id} ({account_name})" if account_name else account_id
        if self._use_rich:
            assert self._progress is not None
            self._progress.update(
                self._main_task,
                description=f"{self.provider} Account: {display}"
            )
        else:
            print(f"\nAccount: {display}")
    
    def update_task(self, task_description: str):
        """Update the current task being performed."""
        self.current_task = task_description
        if self._use_rich:
            assert self._progress is not None
            region_info = f"[{self.current_region}] " if self.current_region else ""
            self._progress.update(
                self._main_task,
                description=f"{self.provider} {region_info}{task_description}"
            )
    
    def add_resources(self, count: int, capacity_gb: float = 0.0):
        """Add discovered resources to the running total."""
        self.total_resources += count
        self.total_capacity_gb += capacity_gb
    
    def complete_region(self):
        """Mark a region as complete."""
        self.completed_regions += 1
        if self._use_rich:
            assert self._progress is not None
            self._progress.update(self._main_task, advance=1)
        else:
            capacity_tb = self.total_capacity_gb / 1024
            print(f"  [{self.current_region}] Complete - Running total: {self.total_resources:,} resources, {capacity_tb:.2f} TB")
    
    def complete_account(self):
        """Mark an account as complete."""
        self.completed_accounts += 1
        if self._use_rich:
            assert self._progress is not None
            self._progress.update(self._main_task, advance=1)
    
    def log_resource_count(self, resource_type: str, count: int, capacity_gb: float = 0.0):
        """Log a resource count (for detailed tracking)."""
        self.add_resources(count, capacity_gb)
        # Don't print individual counts in progress mode - too noisy
        # The logger.info calls in collectors still work for verbose mode
    
    def _print_summary_rich(self):
        """Print a formatted summary using rich."""
        from rich.table import Table  # type: ignore[import-untyped]
        from rich.panel import Panel  # type: ignore[import-untyped]
        
        capacity_tb = self.total_capacity_gb / 1024
        
        table = Table(title=f"{self.provider} Collection Summary", show_header=False)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        if self.total_regions:
            table.add_row("Regions", str(self.completed_regions))
        if self.total_accounts:
            table.add_row("Accounts", str(self.completed_accounts))
        table.add_row("Total Resources", f"{self.total_resources:,}")
        table.add_row("Total Capacity", f"{capacity_tb:,.2f} TB ({self.total_capacity_gb:,.2f} GB)")
        
        assert self._console is not None
        self._console.print(Panel(table))
    
    def _print_summary_plain(self):
        """Print a plain text summary."""
        capacity_tb = self.total_capacity_gb / 1024
        
        print(f"\n{'='*60}")
        print(f"{self.provider} Collection Complete")
        print(f"{'='*60}")
        if self.total_regions:
            print(f"  Regions:         {self.completed_regions}")
        if self.total_accounts:
            print(f"  Accounts:        {self.completed_accounts}")
        print(f"  Total Resources: {self.total_resources:,}")
        print(f"  Total Capacity:  {capacity_tb:,.2f} TB ({self.total_capacity_gb:,.2f} GB)")
        print()


def generate_run_id() -> str:
    """Generate a unique run ID."""
    return f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{str(uuid.uuid4())[:8]}"


def get_timestamp() -> str:
    """Get current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def format_bytes_to_gb(bytes_value: int) -> float:
    """Convert bytes to GB."""
    if not bytes_value:
        return 0.0
    return round(bytes_value / (1024**3), 2)


def format_gb_to_tb(gb_value: float) -> float:
    """Convert GB to TB."""
    if not gb_value:
        return 0.0
    return round(gb_value / 1024, 2)


def tags_to_dict(tags: Any) -> Dict[str, str]:
    """
    Convert cloud provider tag list to dictionary.
    
    Supports:
    - AWS format: [{"Key": "Name", "Value": "my-instance"}]
    - Azure format: {"Name": "my-instance"} (already a dict)
    """
    if not tags:
        return {}
    
    # Already a dict (Azure format)
    if isinstance(tags, dict):
        return tags
    
    # AWS format (list of dicts)
    if isinstance(tags, list):
        return {tag.get("Key", ""): tag.get("Value", "") for tag in tags if tag.get("Key")}
    
    return {}


def get_name_from_tags(tags: Dict[str, str], resource_id: str = "") -> str:
    """Get name from tags, falling back to resource ID."""
    return tags.get("Name", tags.get("name", resource_id))


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Setup logging configuration."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        stream=sys.stderr
    )
    
    return logging.getLogger(__name__)


def write_json(data: Any, filepath: str) -> None:
    """Write data to JSON file with secure permissions."""
    # Handle S3 paths
    if filepath.startswith("s3://"):
        write_to_s3(data, filepath)
        return
    
    # Handle Azure blob paths
    if filepath.startswith("https://") and ".blob.core.windows.net" in filepath:
        write_to_blob(data, filepath)
        return
    
    # Handle GCS paths
    if filepath.startswith("gs://"):
        write_to_gcs(data, filepath)
        return
    
    # Local file - create with restrictive permissions (owner read/write only)
    # This protects inventory data which may contain sensitive resource metadata
    fd = os.open(filepath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    except Exception:
        os.close(fd)
        raise
    print(f"Wrote {filepath}")


def write_csv(data: List[Dict], filepath: str, fieldnames: Optional[List[str]] = None) -> None:
    """Write data to CSV file."""
    if not data:
        return
    
    if not fieldnames:
        fieldnames = list(data[0].keys())
    
    # Handle S3 paths
    if filepath.startswith("s3://"):
        import io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
        write_to_s3(output.getvalue(), filepath, content_type="text/csv")
        return
    
    # Handle Azure blob paths
    if filepath.startswith("https://") and ".blob.core.windows.net" in filepath:
        import io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
        write_to_blob(output.getvalue(), filepath)
        return
    
    # Handle GCS paths
    if filepath.startswith("gs://"):
        import io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
        write_to_gcs(output.getvalue(), filepath, content_type="text/csv")
        return
    
    # Local file
    with open(filepath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
    print(f"Wrote {filepath}")


def write_to_s3(data: Any, s3_path: str, content_type: str = "application/json") -> None:
    """Write data to S3 bucket."""
    try:
        import boto3
    except ImportError:
        print("ERROR: boto3 not installed. Install with: pip install boto3")
        raise
    
    # Parse S3 path: s3://bucket/key
    parts = s3_path.replace("s3://", "").split("/", 1)
    bucket = parts[0]
    key = parts[1] if len(parts) > 1 else "output.json"
    
    try:
        s3 = boto3.client('s3')
        
        if isinstance(data, str):
            body = data
        else:
            body = json.dumps(data, indent=2, default=str)
        
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ContentType=content_type
        )
        print(f"Wrote s3://{bucket}/{key}")
    except Exception as e:
        print(f"ERROR: Failed to write to S3 ({s3_path}): {e}")
        raise


def write_to_blob(data: Any, blob_url: str) -> None:
    """Write data to Azure Blob Storage."""
    try:
        from azure.storage.blob import BlobClient  # type: ignore[import-not-found]
        from azure.identity import DefaultAzureCredential  # type: ignore[import-not-found]
    except ImportError:
        print("ERROR: azure-storage-blob not installed. Install with: pip install azure-storage-blob azure-identity")
        raise
    
    try:
        credential = DefaultAzureCredential()
        blob_client = BlobClient.from_blob_url(blob_url, credential=credential)
        
        if isinstance(data, str):
            body = data
        else:
            body = json.dumps(data, indent=2, default=str)
        
        blob_client.upload_blob(body, overwrite=True)
        print(f"Wrote {blob_url}")
    except Exception as e:
        print(f"ERROR: Failed to write to Azure Blob ({blob_url}): {e}")
        raise


def write_to_gcs(data: Any, gcs_path: str, content_type: str = "application/json") -> None:
    """Write data to Google Cloud Storage."""
    try:
        from google.cloud import storage  # type: ignore[import-not-found]
    except ImportError:
        print("ERROR: google-cloud-storage not installed. Install with: pip install google-cloud-storage")
        raise
    
    # Parse GCS path: gs://bucket/key
    parts = gcs_path.replace("gs://", "").split("/", 1)
    bucket_name = parts[0]
    blob_name = parts[1] if len(parts) > 1 else "output.json"
    
    try:
        client = storage.Client()
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        
        if isinstance(data, str):
            body = data
        else:
            body = json.dumps(data, indent=2, default=str)
        
        blob.upload_from_string(body, content_type=content_type)
        print(f"Wrote gs://{bucket_name}/{blob_name}")
    except Exception as e:
        print(f"ERROR: Failed to write to GCS ({gcs_path}): {e}")
        raise


# =============================================================================
# Permission Pre-Check Functions
# =============================================================================

def check_aws_permissions(session) -> Dict[str, Any]:
    """
    Check AWS permissions before starting collection.
    
    Returns dict with 'success' bool and 'errors' list.
    """
    results = {'success': True, 'errors': [], 'warnings': []}
    
    try:
        # Test STS (required for account ID)
        sts = session.client('sts')
        sts.get_caller_identity()
    except Exception as e:
        results['success'] = False
        results['errors'].append(f"STS access denied: {e}")
        return results  # Fatal - can't proceed without this
    
    # Test EC2 (describe regions - basic permission)
    try:
        ec2 = session.client('ec2', region_name='us-east-1')
        ec2.describe_regions(MaxResults=1)
    except Exception as e:
        results['warnings'].append(f"EC2 describe_regions failed (may limit region discovery): {e}")
    
    # Test S3 list buckets
    try:
        s3 = session.client('s3')
        s3.list_buckets()
    except Exception as e:
        results['warnings'].append(f"S3 list_buckets failed: {e}")
    
    return results


def check_azure_permissions(credential, subscription_id: str) -> Dict[str, Any]:
    """
    Check Azure permissions before starting collection.
    
    Returns dict with 'success' bool and 'errors' list.
    """
    results = {'success': True, 'errors': [], 'warnings': []}
    
    try:
        from azure.mgmt.compute import ComputeManagementClient  # type: ignore[import-not-found]
        
        # Test Compute access
        compute_client = ComputeManagementClient(credential, subscription_id)
        # Just create the iterator, don't actually list
        list(compute_client.virtual_machines.list_all())[:1]
    except ImportError:
        results['errors'].append("azure-mgmt-compute not installed")
        results['success'] = False
    except Exception as e:
        error_msg = str(e)
        if 'AuthorizationFailed' in error_msg or 'AuthenticationFailed' in error_msg:
            results['errors'].append(f"Compute access denied: {e}")
            results['success'] = False
        else:
            results['warnings'].append(f"Compute check failed (may be transient): {e}")
    
    return results


def check_gcp_permissions(project_id: str) -> Dict[str, Any]:
    """
    Check GCP permissions before starting collection.
    
    Returns dict with 'success' bool and 'errors' list.
    """
    results = {'success': True, 'errors': [], 'warnings': []}
    
    try:
        from google.cloud import compute_v1  # type: ignore[import-not-found]
        
        # Test Compute access with a simple zones list
        client = compute_v1.ZonesClient()
        list(client.list(project=project_id))[:1]
    except ImportError:
        results['errors'].append("google-cloud-compute not installed")
        results['success'] = False
    except Exception as e:
        error_msg = str(e)
        if '403' in error_msg or 'Permission' in error_msg:
            results['errors'].append(f"Compute access denied: {e}")
            results['success'] = False
        else:
            results['warnings'].append(f"Compute check failed (may be transient): {e}")
    
    return results


def check_m365_permissions(graph_client, tenant_id: str) -> Dict[str, Any]:
    """
    Check M365 Graph API permissions before starting collection.
    
    Returns dict with 'success' bool and 'errors' list.
    """
    results = {'success': True, 'errors': [], 'warnings': []}
    
    # Test Users.Read.All
    try:
        response = graph_client.users.get()
        if not response:
            results['warnings'].append("Users API returned empty response")
    except Exception as e:
        error_msg = str(e)
        if 'Authorization' in error_msg or '403' in error_msg:
            results['errors'].append(f"Users.Read.All permission missing or denied: {e}")
            results['success'] = False
        else:
            results['warnings'].append(f"Users check failed: {e}")
    
    # Test Sites.Read.All
    try:
        response = graph_client.sites.get()
        if not response:
            results['warnings'].append("Sites API returned empty response")
    except Exception as e:
        error_msg = str(e)
        if 'Authorization' in error_msg or '403' in error_msg:
            results['warnings'].append(f"Sites.Read.All may be missing: {e}")
        # Not fatal - SharePoint might just be empty
    
    return results


def print_permission_check_results(results: Dict[str, Any], cloud: str) -> bool:
    """Print permission check results and return True if collection should proceed."""
    if results['errors']:
        print(f"\n{'='*60}")
        print(f"{cloud.upper()} PERMISSION CHECK FAILED")
        print('='*60)
        for error in results['errors']:
            print(f"  ERROR: {error}")
        print()
        return False
    
    if results['warnings']:
        print(f"\n{'='*60}")
        print(f"{cloud.upper()} PERMISSION WARNINGS")
        print('='*60)
        for warning in results['warnings']:
            print(f"  WARNING: {warning}")
        print("  Collection will continue but some resources may be missed.")
        print()
    
    return True


def print_summary_table(summaries: List[Dict]) -> None:
    """Print a summary table to console."""
    if not summaries:
        print("No resources found.")
        return
    
    # Calculate column widths
    headers = ["Service", "Type", "Count", "Size (GB)"]
    rows = []
    
    for s in summaries:
        rows.append([
            s.get("service_family", ""),
            s.get("resource_type", "").split(":")[-1],
            str(s.get("resource_count", 0)),
            f"{s.get('total_gb', 0):,.1f}",
        ])
    
    # Calculate widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    
    # Print header
    header_line = " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    separator = "-+-".join("-" * w for w in widths)
    
    print("\n" + header_line)
    print(separator)
    
    # Print rows
    for row in rows:
        print(" | ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
    
    # Print totals
    total_count = sum(s.get("resource_count", 0) for s in summaries)
    total_gb = sum(s.get("total_gb", 0) for s in summaries)
    print(separator)
    print(f"{'TOTAL'.ljust(widths[0])} | {' '.ljust(widths[1])} | {str(total_count).ljust(widths[2])} | {f'{total_gb:,.1f}'.ljust(widths[3])} |")
    print()
