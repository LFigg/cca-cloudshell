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
import csv
import json
import logging
import os
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from functools import wraps
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple, TypeVar

# Type checking imports (not imported at runtime)
if TYPE_CHECKING:
    from rich.console import Console
    from rich.progress import Progress, TaskID

# Retry decorator for API calls
try:
    from tenacity import (
        before_sleep_log,
        retry,
        retry_if_exception_type,
        stop_after_attempt,
        wait_exponential,
    )
    TENACITY_AVAILABLE = True
except ImportError:
    TENACITY_AVAILABLE = False

# Progress display with rich (imports used in functions when RICH_AVAILABLE is True)
try:
    from rich.console import Console
    from rich.live import Live  # noqa: F401
    from rich.panel import Panel  # noqa: F401
    from rich.progress import (  # noqa: F401
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.table import Table  # noqa: F401
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
            from rich.console import Console
            from rich.progress import (
                BarColumn,
                MofNCompleteColumn,
                Progress,
                SpinnerColumn,
                TextColumn,
                TimeElapsedColumn,
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
            assert self._main_task is not None
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
            assert self._main_task is not None
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
            assert self._main_task is not None
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
            assert self._main_task is not None
            self._progress.update(self._main_task, advance=1)
        else:
            capacity_tb = self.total_capacity_gb / 1024
            print(f"  [{self.current_region}] Complete - Running total: {self.total_resources:,} resources, {capacity_tb:.2f} TB")

    def complete_account(self):
        """Mark an account as complete."""
        self.completed_accounts += 1
        if self._use_rich:
            assert self._progress is not None
            assert self._main_task is not None
            self._progress.update(self._main_task, advance=1)

    def log_resource_count(self, resource_type: str, count: int, capacity_gb: float = 0.0):
        """Log a resource count (for detailed tracking)."""
        self.add_resources(count, capacity_gb)
        # Don't print individual counts in progress mode - too noisy
        # The logger.info calls in collectors still work for verbose mode

    def _print_summary_rich(self):
        """Print a formatted summary using rich."""
        from rich.panel import Panel
        from rich.table import Table

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


def mask_account_id(arn: str) -> str:
    """
    Mask the account ID in an AWS ARN for safe logging.

    Example: arn:aws:iam::123456789012:role/MyRole
          -> arn:aws:iam::***:role/MyRole
    """
    import re
    # Match AWS account ID pattern (12 digits) in ARN
    return re.sub(r'(\d{12})', '***', arn)


class AuthError(Exception):
    """Custom exception for authentication/authorization failures.

    Raised when a cloud API returns an auth error that should stop collection
    rather than being silently caught and logged.
    """
    def __init__(self, message: str, provider: str, original_error: Optional[Exception] = None):
        self.provider = provider
        self.original_error = original_error
        super().__init__(message)


# AWS error codes that indicate auth/permission issues
AWS_AUTH_ERROR_CODES = {
    'AccessDenied', 'AccessDeniedException', 'UnauthorizedAccess',
    'UnauthorizedOperation', 'InvalidClientTokenId', 'ExpiredToken',
    'ExpiredTokenException', 'AuthFailure', 'InvalidIdentityToken',
    'CredentialsNotFound', 'SignatureDoesNotMatch',
}

# Azure error status codes that indicate auth/permission issues
AZURE_AUTH_STATUS_CODES = {401, 403}

# GCP exception types that indicate auth/permission issues
GCP_AUTH_EXCEPTION_NAMES = {'PermissionDenied', 'Unauthenticated', 'Forbidden'}

# M365/Graph error codes that indicate auth/permission issues
M365_AUTH_ERROR_CODES = {'Authorization_RequestDenied', 'InvalidAuthenticationToken'}


def is_auth_error(exc: Exception) -> bool:
    """
    Check if an exception represents an authentication/authorization error.

    Detects auth errors across cloud providers:
    - AWS: ClientError with specific error codes
    - Azure: HttpResponseError with 401/403 status
    - GCP: PermissionDenied, Unauthenticated exceptions
    - M365: ODataError with auth-related codes

    Args:
        exc: The exception to check

    Returns:
        True if the exception is an authentication/authorization error
    """
    exc_type_name = type(exc).__name__

    # AWS - botocore ClientError
    if exc_type_name == 'ClientError':
        error_code = getattr(exc, 'response', {}).get('Error', {}).get('Code', '')
        return error_code in AWS_AUTH_ERROR_CODES

    # Azure - HttpResponseError or ClientAuthenticationError
    if exc_type_name in ('HttpResponseError', 'ClientAuthenticationError'):
        status_code = getattr(exc, 'status_code', None)
        if status_code in AZURE_AUTH_STATUS_CODES:
            return True
        # Also check for auth-related error messages
        error_msg = str(exc).lower()
        return 'authentication' in error_msg or 'authorization' in error_msg

    # GCP - PermissionDenied, Unauthenticated
    if exc_type_name in GCP_AUTH_EXCEPTION_NAMES:
        return True

    # M365 - ODataError
    if exc_type_name == 'ODataError':
        error = getattr(exc, 'error', None)
        if error:
            error_code = getattr(error, 'code', '')
            return error_code in M365_AUTH_ERROR_CODES

    return False


def check_and_raise_auth_error(exc: Exception, context: str, provider: str) -> None:
    """
    Check if exception is an auth error and raise AuthError if so.

    Call this in exception handlers before logging and continuing.
    If the exception is an auth error, raises AuthError to fail early.
    Otherwise, returns normally so the caller can log and continue.

    Args:
        exc: The caught exception
        context: Description of what was being attempted (e.g., "collect VMs")
        provider: Cloud provider name (aws, azure, gcp, m365)

    Raises:
        AuthError: If exc is an authentication/authorization error
    """
    if is_auth_error(exc):
        raise AuthError(
            f"Authentication/authorization error while trying to {context}: {exc}",
            provider=provider,
            original_error=exc
        ) from exc


def parallel_collect(
    collection_tasks: List[Tuple[str, Callable, tuple]],
    parallel_workers: int = 1,
    tracker: Optional['ProgressTracker'] = None,
    logger: Optional[logging.Logger] = None
) -> List[Any]:
    """
    Execute collection tasks either serially or in parallel.

    This is a shared utility to avoid duplicating the parallel/serial collection
    pattern across collectors. Each task is a tuple of (name, function, args).

    Args:
        collection_tasks: List of (name, collect_fn, args) tuples
        parallel_workers: Number of threads (1 = serial, >1 = parallel)
        tracker: Optional ProgressTracker for UI updates
        logger: Optional logger for debug/warning messages

    Returns:
        List of all collected items (flattened from all tasks)

    Raises:
        AuthError: If any task encounters an authentication error
    """
    all_results: List[Any] = []
    _logger = logger or logging.getLogger(__name__)

    if parallel_workers <= 1:
        # Serial collection
        for name, collect_fn, args in collection_tasks:
            if tracker:
                tracker.update_task(f"Collecting {name}...")
            try:
                result = collect_fn(*args)
                if result:
                    all_results.extend(result)
                    if tracker:
                        # Sum size_gb if items have that attribute
                        total_size = sum(
                            getattr(r, 'size_gb', 0) for r in result
                        )
                        tracker.add_resources(len(result), total_size)
            except AuthError:
                raise  # Re-raise auth errors to stop collection
            except Exception as e:
                _logger.warning(f"Error collecting {name}: {e}")
    else:
        # Parallel collection
        _logger.info(f"Using parallel collection with {parallel_workers} threads")
        if tracker:
            tracker.update_task(f"Collecting resources in parallel ({parallel_workers} threads)...")

        def execute_task(task_tuple: Tuple[str, Callable, tuple]) -> Tuple[str, List[Any]]:
            name, collect_fn, args = task_tuple
            try:
                result = collect_fn(*args)
                return name, result or []
            except AuthError:
                raise  # Re-raise auth errors to stop collection
            except Exception as e:
                _logger.warning(f"Error collecting {name}: {e}")
                return name, []

        with ThreadPoolExecutor(max_workers=parallel_workers) as executor:
            futures = {
                executor.submit(execute_task, task): task[0]
                for task in collection_tasks
            }

            for future in as_completed(futures):
                task_name = futures[future]
                try:
                    name, result = future.result()
                    if result:
                        all_results.extend(result)
                        _logger.debug(f"Collected {len(result)} {name}")
                except AuthError:
                    raise  # Re-raise auth errors to stop collection
                except Exception as e:
                    _logger.warning(f"Task {task_name} failed: {e}")

        # Update tracker with final counts
        if tracker and all_results:
            total_size = sum(getattr(r, 'size_gb', 0) for r in all_results)
            tracker.add_resources(len(all_results), total_size)

    return all_results


def hash_sensitive_id(value: str, prefix: str = "") -> str:
    """
    Hash a sensitive ID using consistent hashing.

    Preserves a prefix for readability while hashing the unique portion.
    Uses first 8 chars of SHA256 for uniqueness with minimal collision risk.

    Example: i-0abc123def456 -> i-a3f8b2c1
             vpc-12345678 -> vpc-b7d4e9f2
    """
    import hashlib
    if not value:
        return value
    hash_val = hashlib.sha256(value.encode()).hexdigest()[:8]
    return f"{prefix}{hash_val}" if prefix else hash_val


def _redact_value(value: str) -> tuple:
    """
    Check if a value matches sensitive patterns and return redacted version.
    Preserves context (regions, service suffixes) while hashing sensitive parts.

    Returns (was_redacted, redacted_value) tuple.
    """
    import re

    # AWS resource IDs - preserve prefix, hash the ID portion
    aws_id_patterns = [
        (r'^(i-)[0-9a-f]+$', r'\1'),                    # EC2 instances
        (r'^(vol-)[0-9a-f]+$', r'\1'),                  # EBS volumes
        (r'^(snap-)[0-9a-f]+$', r'\1'),                 # EBS snapshots
        (r'^(vpc-)[0-9a-f]+$', r'\1'),                  # VPCs
        (r'^(subnet-)[0-9a-f]+$', r'\1'),               # Subnets
        (r'^(sg-)[0-9a-f]+$', r'\1'),                   # Security groups
        (r'^(eni-)[0-9a-f]+$', r'\1'),                  # Network interfaces
        (r'^(igw-)[0-9a-f]+$', r'\1'),                  # Internet gateways
        (r'^(rtb-)[0-9a-f]+$', r'\1'),                  # Route tables
        (r'^(acl-)[0-9a-f]+$', r'\1'),                  # Network ACLs
        (r'^(ami-)[0-9a-f]+$', r'\1'),                  # AMIs
        (r'^(fs-)[0-9a-f]+$', r'\1'),                   # EFS file systems
        (r'^(fsap-)[0-9a-f]+$', r'\1'),                 # EFS access points
    ]

    for pattern, _prefix_group in aws_id_patterns:
        match = re.match(pattern, value, re.IGNORECASE)
        if match:
            prefix = match.group(1)
            return (True, f"{prefix}{hash_sensitive_id(value, '')[:8]}")

    # AWS ARNs - preserve structure (service, region, resource type), hash account+resource name
    # Format: arn:partition:service:region:account:resource
    arn_match = re.match(r'^(arn:aws[-a-z]*):([^:]+):([^:]*):(\d{12}):(.+)$', value)
    if arn_match:
        partition, service, region, account, resource = arn_match.groups()
        hashed_account = hash_sensitive_id(account, '')[:8]
        hashed_resource = hash_sensitive_id(resource, '')[:8]
        region_part = region if region else '*'
        return (True, f"{partition}:{service}:{region_part}:{hashed_account}:{hashed_resource}")

    # Azure resource IDs - preserve structure, hash subscription and resource group
    # /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
    azure_match = re.match(
        r'^(/subscriptions/)([0-9a-f-]{36})(/resourceGroups/)([^/]+)(/providers/.+)$',
        value, re.IGNORECASE
    )
    if azure_match:
        pre_sub, sub_id, pre_rg, rg_name, rest = azure_match.groups()
        hashed_sub = hash_sensitive_id(sub_id, '')[:8]
        hashed_rg = hash_sensitive_id(rg_name, '')[:8]
        # Also redact the resource name at the end
        rest_parts = rest.rsplit('/', 1)
        if len(rest_parts) == 2:
            rest = f"{rest_parts[0]}/{hash_sensitive_id(rest_parts[1], '')[:8]}"
        return (True, f"{pre_sub}{hashed_sub}{pre_rg}{hashed_rg}{rest}")

    # Azure subscription ID alone
    azure_sub_match = re.match(r'^(/subscriptions/)([0-9a-f-]{36})$', value, re.IGNORECASE)
    if azure_sub_match:
        return (True, f"/subscriptions/{hash_sensitive_id(azure_sub_match.group(2), '')[:8]}")

    # GCP resource IDs - preserve structure (projects/xxx/...), hash project name
    gcp_match = re.match(r'^(projects/)([^/]+)(.*)$', value)
    if gcp_match:
        prefix, project, rest = gcp_match.groups()
        hashed_project = hash_sensitive_id(project, '')[:8]
        return (True, f"{prefix}{hashed_project}{rest}")

    # Database endpoints - preserve region and service suffix, hash hostname
    # mydb.cluster-xyz.us-east-1.rds.amazonaws.com -> redacted.us-east-1.rds.amazonaws.com
    rds_match = re.match(r'^([^.]+)\.([^.]+\.)?([a-z0-9-]+\.rds\.amazonaws\.com)$', value, re.IGNORECASE)
    if rds_match:
        hostname, cluster, suffix = rds_match.groups()
        hashed_host = hash_sensitive_id(hostname, '')[:8]
        return (True, f"redacted-{hashed_host}.{suffix}")

    # Azure SQL endpoints - hash server name, preserve suffix
    azure_sql_match = re.match(r'^([^.]+)(\.database\.windows\.net)$', value, re.IGNORECASE)
    if azure_sql_match:
        server, suffix = azure_sql_match.groups()
        hashed_server = hash_sensitive_id(server, '')[:8]
        return (True, f"redacted-{hashed_server}{suffix}")

    # GCP SQL endpoints
    gcp_sql_match = re.match(r'^([^.]+)(\.sql\.goog)$', value, re.IGNORECASE)
    if gcp_sql_match:
        server, suffix = gcp_sql_match.groups()
        hashed_server = hash_sensitive_id(server, '')[:8]
        return (True, f"redacted-{hashed_server}{suffix}")

    # GUIDs (M365/Entra IDs, subscription IDs, etc.)
    if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.IGNORECASE):
        return (True, f"id-{hash_sensitive_id(value.lower(), '')[:8]}")

    return (False, value)

# Field names that should always be hashed (case-insensitive check)
_SENSITIVE_FIELD_NAMES = {
    'account_id', 'subscription_id', 'tenant_id', 'resource_id',
    'parent_resource_id', 'vpc_id', 'subnet_id', 'security_group_id',
    'endpoint', 'host', 'server', 'connection_string',
}

# Field name patterns that indicate arrays of sensitive IDs
_SENSITIVE_ARRAY_FIELD_PATTERNS = [
    'subnet_ids', 'security_group_ids', 'availability_zones',
    'attached_disks', 'attached_volumes', 'network_interface_ids',
]


def redact_sensitive_data(data: Any, _depth: int = 0) -> Any:
    """
    Recursively redact sensitive data in a dictionary or list.

    Uses consistent hashing so the same ID always produces the same hash,
    allowing correlation within a single collection run. Preserves context
    like regions, service suffixes, and resource structures.

    Args:
        data: Dictionary, list, or primitive value to redact
        _depth: Internal recursion depth tracker

    Returns:
        Redacted copy of the data with sensitive values hashed
    """
    # Prevent infinite recursion
    if _depth > 50:
        return data

    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            key_lower = key.lower()

            # Check if field name indicates sensitive data
            if key_lower in _SENSITIVE_FIELD_NAMES:
                if isinstance(value, str) and value:
                    # Try context-preserving redaction first
                    was_redacted, redacted = _redact_value(value)
                    if was_redacted:
                        result[key] = redacted
                    else:
                        # Fall back to simple hash with field prefix
                        result[key] = hash_sensitive_id(value, f"{key_lower[:3]}-")
                elif isinstance(value, list):
                    redacted_list = []
                    for v in value:
                        if isinstance(v, str):
                            was_redacted, redacted = _redact_value(v)
                            redacted_list.append(redacted if was_redacted else hash_sensitive_id(v, f"{key_lower[:3]}-"))
                        else:
                            redacted_list.append(v)
                    result[key] = redacted_list
                else:
                    result[key] = value
            # Check array field patterns
            elif any(pattern in key_lower for pattern in _SENSITIVE_ARRAY_FIELD_PATTERNS):
                if isinstance(value, list):
                    redacted_list = []
                    for v in value:
                        if isinstance(v, str):
                            was_redacted, redacted = _redact_value(v)
                            redacted_list.append(redacted if was_redacted else hash_sensitive_id(v, "id-"))
                        else:
                            redacted_list.append(v)
                    result[key] = redacted_list
                else:
                    result[key] = value
            # Recursively process nested structures
            elif isinstance(value, (dict, list)):
                result[key] = redact_sensitive_data(value, _depth + 1)
            # Check value patterns for strings
            elif isinstance(value, str):
                was_redacted, redacted = _redact_value(value)
                result[key] = redacted if was_redacted else value
            else:
                result[key] = value
        return result

    elif isinstance(data, list):
        return [redact_sensitive_data(item, _depth + 1) for item in data]

    elif isinstance(data, str):
        was_redacted, redacted = _redact_value(data)
        return redacted if was_redacted else data

    else:
        return data


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


# Patterns for redacting sensitive data in log messages (compiled for performance)
_LOG_REDACT_PATTERNS = None

def _get_log_redact_patterns():
    """Get compiled regex patterns for log redaction (lazy initialization)."""
    global _LOG_REDACT_PATTERNS
    if _LOG_REDACT_PATTERNS is None:
        import re
        _LOG_REDACT_PATTERNS = [
            # AWS ARNs - preserve structure (partition:service:region:account:resource)
            # Must come before account ID pattern to match full ARN first
            (re.compile(r'(arn:aws[-a-z]*):([a-z0-9-]+):([a-z0-9-]*):(\d{12}):([^\s,\]}"\']+)'),
             lambda m: f"{m.group(1)}:{m.group(2)}:{m.group(3) or '*'}:{hash_sensitive_id(m.group(4), '')[:8]}:{hash_sensitive_id(m.group(5), '')[:8]}"),
            # AWS account IDs (12 digits, but not timestamps or other numbers)
            (re.compile(r'\b(\d{12})\b(?!\d)'), lambda m: f"acc-{hash_sensitive_id(m.group(1), '')[:8]}"),
            # AWS resource IDs - preserve prefix
            (re.compile(r'\b(i-[0-9a-f]{8,17})\b'), lambda m: f"i-{hash_sensitive_id(m.group(1), '')[:8]}"),
            (re.compile(r'\b(vol-[0-9a-f]{8,17})\b'), lambda m: f"vol-{hash_sensitive_id(m.group(1), '')[:8]}"),
            (re.compile(r'\b(snap-[0-9a-f]{8,17})\b'), lambda m: f"snap-{hash_sensitive_id(m.group(1), '')[:8]}"),
            (re.compile(r'\b(vpc-[0-9a-f]{8,17})\b'), lambda m: f"vpc-{hash_sensitive_id(m.group(1), '')[:8]}"),
            (re.compile(r'\b(subnet-[0-9a-f]{8,17})\b'), lambda m: f"subnet-{hash_sensitive_id(m.group(1), '')[:8]}"),
            (re.compile(r'\b(sg-[0-9a-f]{8,17})\b'), lambda m: f"sg-{hash_sensitive_id(m.group(1), '')[:8]}"),
            (re.compile(r'\b(eni-[0-9a-f]{8,17})\b'), lambda m: f"eni-{hash_sensitive_id(m.group(1), '')[:8]}"),
            (re.compile(r'\b(fs-[0-9a-f]{8,17})\b'), lambda m: f"fs-{hash_sensitive_id(m.group(1), '')[:8]}"),
            (re.compile(r'\b(ami-[0-9a-f]{8,17})\b'), lambda m: f"ami-{hash_sensitive_id(m.group(1), '')[:8]}"),
            # Azure subscription IDs and resource paths - preserve structure
            # Must come before GUID pattern to match full paths first
            (re.compile(r'(/subscriptions/)([0-9a-f-]{36})(/resourceGroups/)([^/\s]+)(/providers/[^\s,\]}"\']+)'),
             lambda m: f"{m.group(1)}{hash_sensitive_id(m.group(2), '')[:8]}{m.group(3)}{hash_sensitive_id(m.group(4), '')[:8]}{m.group(5)}"),
            (re.compile(r'(/subscriptions/)([0-9a-f-]{36})(?![/])'),
             lambda m: f"{m.group(1)}{hash_sensitive_id(m.group(2), '')[:8]}"),
            # GUIDs (subscription IDs, tenant IDs, etc.)
            (re.compile(r'\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b', re.IGNORECASE),
             lambda m: f"id-{hash_sensitive_id(m.group(1).lower(), '')[:8]}"),
            # GCP project references - preserve 'projects/' prefix
            (re.compile(r'(projects/)([a-z][a-z0-9-]{4,28}[a-z0-9])(/[^\s,\]}"\']*)?'),
             lambda m: f"{m.group(1)}{hash_sensitive_id(m.group(2), '')[:8]}{m.group(3) or ''}"),
            # Database endpoints - preserve region and service suffix
            (re.compile(r'([a-z0-9-]+)(\.[a-z0-9-]*)?\.([a-z0-9-]+\.rds\.amazonaws\.com)'),
             lambda m: f"redacted-{hash_sensitive_id(m.group(1), '')[:8]}.{m.group(3)}"),
            (re.compile(r'([a-z0-9-]+)(\.database\.windows\.net)'),
             lambda m: f"redacted-{hash_sensitive_id(m.group(1), '')[:8]}{m.group(2)}"),
        ]
    return _LOG_REDACT_PATTERNS


def redact_log_message(message: str) -> str:
    """
    Redact sensitive data from a log message using consistent hashing.

    Uses the same hashing approach as redact_sensitive_data() for consistency
    between log files and output files.
    """
    if not message:
        return message

    for pattern, replacer in _get_log_redact_patterns():
        message = pattern.sub(replacer, message)

    return message


class RedactingFilter(logging.Filter):
    """
    Logging filter that redacts sensitive data from log messages.

    Uses consistent hashing so the same ID produces the same hash,
    allowing correlation between logs and redacted output files.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact sensitive data from the log record message."""
        if record.msg:
            record.msg = redact_log_message(str(record.msg))
        if record.args:
            # Also redact any args that might contain sensitive data
            record.args = tuple(
                redact_log_message(str(arg)) if isinstance(arg, str) else arg
                for arg in record.args
            )
        return True


def setup_logging(level: str = "INFO", output_dir: Optional[str] = None) -> logging.Logger:
    """
    Setup logging configuration with console and optional file output.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        output_dir: If provided, also write logs to a file in this directory

    Returns:
        Logger instance
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Clear existing handlers to avoid duplicates
    root_logger.handlers.clear()

    # Console handler (stderr)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File handler (if output_dir provided)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        log_file = os.path.join(output_dir, f"cca_log_{timestamp}.log")

        file_handler = logging.FileHandler(log_file, mode='w')
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        # Add redacting filter to file handler (protects sensitive data in persisted logs)
        file_handler.addFilter(RedactingFilter())
        root_logger.addHandler(file_handler)

        # Log the log file location (meta!)
        root_logger.info(f"Logging to: {log_file}")

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
        from azure.identity import DefaultAzureCredential
        from azure.storage.blob import BlobClient
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
        from google.cloud import storage
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
        from azure.mgmt.compute import ComputeManagementClient

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
        from google.cloud import compute_v1

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
