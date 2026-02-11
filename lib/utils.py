"""
Utility functions for CCA CloudShell collectors.
"""
import json
import csv
import logging
import sys
from datetime import datetime, timezone
from typing import List, Dict, Any, Callable, TypeVar
import uuid
from functools import wraps

# Retry decorator for API calls
try:
    from tenacity import (
        retry,
        stop_after_attempt,
        wait_exponential,
        retry_if_exception_type,
        before_sleep_log,
    )
    TENACITY_AVAILABLE = True
except ImportError:
    TENACITY_AVAILABLE = False

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
            return retry(
                stop=stop_after_attempt(max_attempts),
                wait=wait_exponential(multiplier=1, min=min_wait, max=max_wait),
                retry=retry_if_exception_type(exceptions),
                before_sleep=before_sleep_log(logger, logging.WARNING),
                reraise=True
            )(func)
        return decorator
    else:
        # Fallback implementation without tenacity
        def decorator(func: F) -> F:
            @wraps(func)
            def wrapper(*args, **kwargs):
                last_exception = None
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
    """Write data to JSON file."""
    # Handle S3 paths
    if filepath.startswith("s3://"):
        write_to_s3(data, filepath)
        return
    
    # Handle Azure blob paths
    if filepath.startswith("https://") and ".blob.core.windows.net" in filepath:
        write_to_blob(data, filepath)
        return
    
    # Local file
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    print(f"Wrote {filepath}")


def write_csv(data: List[Dict], filepath: str, fieldnames: List[str] = None) -> None:
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
    
    # Local file
    with open(filepath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
    print(f"Wrote {filepath}")


def write_to_s3(data: Any, s3_path: str, content_type: str = "application/json") -> None:
    """Write data to S3 bucket."""
    import boto3
    
    # Parse S3 path: s3://bucket/key
    parts = s3_path.replace("s3://", "").split("/", 1)
    bucket = parts[0]
    key = parts[1] if len(parts) > 1 else "output.json"
    
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


def write_to_blob(data: Any, blob_url: str) -> None:
    """Write data to Azure Blob Storage."""
    try:
        from azure.storage.blob import BlobClient
        from azure.identity import DefaultAzureCredential
        
        credential = DefaultAzureCredential()
        blob_client = BlobClient.from_blob_url(blob_url, credential=credential)
        
        if isinstance(data, str):
            body = data
        else:
            body = json.dumps(data, indent=2, default=str)
        
        blob_client.upload_blob(body, overwrite=True)
        print(f"Wrote {blob_url}")
    except ImportError:
        print("ERROR: azure-storage-blob not installed. Install with: pip install azure-storage-blob")
        raise


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
