#!/usr/bin/env python3
"""
CCA CloudShell - AWS Resource Collector

Collects AWS resources for cloud protection assessment.
Optimized for AWS CloudShell with minimal dependencies.
Supports single-account and multi-account collection.

Usage:
    # Single account (current credentials)
    python3 aws_collect.py
    python3 aws_collect.py --regions us-east-1,us-west-2
    python3 aws_collect.py --output s3://my-bucket/assessments/

    # Multi-account via role assumption
    python3 aws_collect.py --role-arn arn:aws:iam::123456789012:role/CCARole
    python3 aws_collect.py --role-arns arn:aws:iam::111:role/CCA,arn:aws:iam::222:role/CCA

    # Multi-account via AWS Organizations discovery
    python3 aws_collect.py --org-role CCARole

    # With external ID (use env var to avoid shell history exposure)
    export CCA_EXTERNAL_ID="your-secret-external-id"
    python3 aws_collect.py --org-role CCARole

    # Large environments: auto-batching with checkpoint
    python3 aws_collect.py --org-role CCARole --batch-size 25 -o ./collection/

    # Resume from checkpoint after failure/timeout
    python3 aws_collect.py --org-role CCARole --resume ./collection/checkpoint.json

    # Collect specific accounts only (retry failed)
    python3 aws_collect.py --org-role CCARole --accounts 111111111111,222222222222

    # Load accounts from file
    python3 aws_collect.py --org-role CCARole --account-file accounts.txt
"""
import argparse
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

# boto3 is pre-installed in AWS CloudShell
import boto3
from botocore.exceptions import ClientError

# Add lib to path for imports
sys.path.insert(0, '.')
from lib.change_rate import (
    aggregate_change_rates,
    finalize_change_rate_output,
    format_change_rate_output,
    get_aws_cloudwatch_client,
    get_ebs_volume_change_rate,
    get_efs_change_rate,
    get_fsx_change_rate,
    get_rds_transaction_log_rate,
    get_rds_write_iops_change_rate,
    get_s3_change_rate,
    merge_change_rates,
)
from lib.constants import BYTES_PER_GB
from lib.config import generate_sample_config, load_config
from lib.k8s import collect_eks_pvcs
from lib.models import CloudResource, aggregate_sizing
from lib.utils import (
    AuthError,
    ProgressTracker,
    check_and_raise_auth_error,
    format_bytes_to_gb,
    generate_run_id,
    get_name_from_tags,
    get_timestamp,
    mask_account_id,
    print_summary_table,
    redact_sensitive_data,
    retry_with_backoff,
    setup_logging,
    tags_to_dict,
    write_csv,
    write_json,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Session Management
# =============================================================================

def is_running_in_cloudshell() -> bool:
    """Check if running in AWS CloudShell environment."""
    return os.environ.get('AWS_EXECUTION_ENV') == 'CloudShell'


def get_session(profile: Optional[str] = None, region: Optional[str] = None) -> boto3.Session:
    """Create boto3 session. In CloudShell, credentials are automatic."""
    return boto3.Session(profile_name=profile, region_name=region)


def get_account_id(session: boto3.Session) -> str:
    """Get AWS account ID."""
    sts = session.client('sts')
    return sts.get_caller_identity()['Account']


def get_enabled_regions(session: boto3.Session) -> List[str]:
    """Get list of enabled regions."""
    ec2 = session.client('ec2', region_name='us-east-1')
    response = ec2.describe_regions(AllRegions=False)
    return sorted([r.get('RegionName', '') for r in response.get('Regions', []) if r.get('RegionName')])


def assume_role(
    session: boto3.Session,
    role_arn: str,
    external_id: Optional[str] = None,
    session_name: str = "CCACloudShell"
) -> boto3.Session:
    """
    Assume an IAM role and return a new session with temporary credentials.

    Args:
        session: Source boto3 session for making the AssumeRole call
        role_arn: ARN of the role to assume (e.g., arn:aws:iam::123456789012:role/CCARole)
        external_id: Optional external ID for additional security
        session_name: Session name for CloudTrail auditing

    Returns:
        New boto3 Session with assumed role credentials
    """
    sts = session.client('sts')

    assume_params = {
        'RoleArn': role_arn,
        'RoleSessionName': session_name,
        'DurationSeconds': 3600  # 1 hour
    }

    if external_id:
        assume_params['ExternalId'] = external_id

    try:
        response = sts.assume_role(**assume_params)
        credentials = response['Credentials']

        return boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
    except ClientError as e:
        # Mask account ID in logs to prevent information disclosure
        masked_arn = mask_account_id(role_arn)
        logger.error(f"Failed to assume role {masked_arn}: {e}")
        raise


def discover_org_accounts(session: boto3.Session, include_suspended: bool = False) -> List[Dict[str, str]]:
    """
    Discover all accounts in the AWS Organization.

    Requires organizations:ListAccounts permission.

    Args:
        session: boto3 session (must have Organizations access)
        include_suspended: Whether to include suspended accounts

    Returns:
        List of dicts with 'id', 'name', 'email', 'status' for each account
    """
    accounts = []
    try:
        org = session.client('organizations')
        paginator = org.get_paginator('list_accounts')

        for page in paginator.paginate():
            for account in page.get('Accounts', []):
                status = account.get('Status', 'UNKNOWN')
                if status == 'ACTIVE' or (include_suspended and status == 'SUSPENDED'):
                    accounts.append({
                        'id': account.get('Id', ''),
                        'name': account.get('Name', ''),
                        'email': account.get('Email', ''),
                        'status': status
                    })

        logger.info(f"Discovered {len(accounts)} accounts in organization")
        return accounts

    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code == 'AWSOrganizationsNotInUseException':
            logger.warning("AWS Organizations is not enabled for this account")
        elif error_code == 'AccessDeniedException':
            logger.error("Access denied to Organizations API. Need organizations:ListAccounts permission.")
        else:
            logger.error(f"Failed to list organization accounts: {e}")
        return []


# =============================================================================
# Checkpoint Management (for resume/batching)
# =============================================================================

def load_checkpoint(checkpoint_file: str) -> Dict[str, Any]:
    """Load checkpoint data from file."""
    default = {
        'completed_accounts': [],
        'failed_accounts': [],
        'in_progress': None,
        'batch_number': 0,
        'started_at': None
    }
    if os.path.exists(checkpoint_file) and os.path.getsize(checkpoint_file) > 0:
        try:
            with open(checkpoint_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            logger.warning(f"Could not read checkpoint file {checkpoint_file}, starting fresh")
            return default
    return default


def save_checkpoint(checkpoint_file: str, checkpoint: Dict[str, Any]) -> None:
    """Save checkpoint data to file atomically.

    Uses write-to-temp-then-rename pattern to prevent data loss if process
    is killed during write. Uses try/finally to ensure temp file cleanup
    on all exception types including KeyboardInterrupt and SystemExit.
    """
    checkpoint['updated_at'] = get_timestamp()
    dir_name = os.path.dirname(checkpoint_file) or '.'
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=dir_name, delete=False, suffix='.tmp') as f:
            json.dump(checkpoint, f, indent=2)
            temp_path = f.name
        os.replace(temp_path, checkpoint_file)  # Atomic on POSIX
        temp_path = None  # Clear on success - file was renamed, nothing to clean up
        logger.debug(f"Checkpoint saved: {len(checkpoint.get('completed_accounts', []))} completed")
    finally:
        # Clean up temp file on any failure (including KeyboardInterrupt, SystemExit)
        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass  # Best effort cleanup - don't mask original exception


def load_account_list(file_path: str) -> List[str]:
    """
    Load account IDs from a file (one per line).
    Supports comments with # and empty lines.
    Validates that each account ID is a valid 12-digit AWS account ID.
    """
    import re
    accounts = []
    invalid_accounts = []

    with open(file_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            # Skip empty lines and comments
            if line and not line.startswith('#'):
                # Handle "account_id,account_name" format
                account_id = line.split(',')[0].strip()
                if account_id:
                    # Validate AWS account ID format (exactly 12 digits)
                    if re.match(r'^\d{12}$', account_id):
                        accounts.append(account_id)
                    else:
                        invalid_accounts.append((line_num, account_id))

    if invalid_accounts:
        error_lines = [f"  Line {num}: '{acc}'" for num, acc in invalid_accounts[:5]]
        if len(invalid_accounts) > 5:
            error_lines.append(f"  ... and {len(invalid_accounts) - 5} more")
        raise ValueError(
            f"Invalid AWS account IDs in {file_path} (must be 12 digits):\n" +
            "\n".join(error_lines)
        )

    return accounts


def validate_account_ids(account_ids: List[str], source: str = "input") -> List[str]:
    """
    Validate a list of AWS account IDs (must be exactly 12 digits).

    Args:
        account_ids: List of account IDs to validate
        source: Description of where the IDs came from (for error messages)

    Returns:
        The validated list of account IDs

    Raises:
        ValueError: If any account ID is invalid
    """
    import re
    invalid = [acc for acc in account_ids if not re.match(r'^\d{12}$', acc)]

    if invalid:
        examples = invalid[:3]
        msg = f"Invalid AWS account IDs in {source} (must be 12 digits): {examples}"
        if len(invalid) > 3:
            msg += f" ... and {len(invalid) - 3} more"
        raise ValueError(msg)

    return account_ids


def chunk_list(lst: List, chunk_size: int) -> List[List]:
    """Split a list into chunks of specified size."""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def get_sso_token_expiry() -> Optional[datetime]:
    """
    Check when the current SSO token expires.
    Returns the expiration datetime or None if not using SSO.
    """
    sso_cache_dir = os.path.expanduser('~/.aws/sso/cache')
    if not os.path.exists(sso_cache_dir):
        return None
    
    latest_expiry = None
    try:
        for filename in os.listdir(sso_cache_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(sso_cache_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                        if 'expiresAt' in data:
                            # Parse ISO format: 2024-01-15T12:00:00Z
                            expiry_str = data['expiresAt']
                            expiry = datetime.fromisoformat(expiry_str.replace('Z', '+00:00'))
                            if latest_expiry is None or expiry > latest_expiry:
                                latest_expiry = expiry
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue
    except OSError:
        pass
    
    return latest_expiry


def refresh_sso_credentials(profile: Optional[str] = None) -> bool:
    """
    Refresh SSO credentials by running aws sso login.
    Returns True if successful, False otherwise.
    """
    sso_cmd = ['aws', 'sso', 'login']
    if profile:
        sso_cmd.extend(['--profile', profile])
    
    try:
        result = subprocess.run(sso_cmd, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        logger.warning(f"SSO login failed: {e.stderr}")
        return False
    except FileNotFoundError:
        logger.warning("AWS CLI not found - cannot refresh SSO credentials")
        return False


def distribute_accounts(accounts: List[Dict], num_workers: int) -> List[List[Dict]]:
    """Distribute accounts evenly across workers using round-robin."""
    workers: List[List[Dict]] = [[] for _ in range(num_workers)]
    for i, account in enumerate(accounts):
        workers[i % num_workers].append(account)
    return [w for w in workers if w]  # Filter out empty workers


def load_parallel_checkpoint(checkpoint_file: str) -> Dict[str, Any]:
    """Load parallel collection checkpoint."""
    if os.path.exists(checkpoint_file):
        try:
            with open(checkpoint_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load parallel checkpoint: {e}")
    return {
        'completed_accounts': [],
        'failed_accounts': [],
        'workers': {},
        'started_at': None
    }


def save_parallel_checkpoint(checkpoint_file: str, checkpoint: Dict[str, Any]) -> None:
    """Save parallel collection checkpoint."""
    try:
        with open(checkpoint_file, 'w') as f:
            json.dump(checkpoint, f, indent=2)
    except Exception as e:
        logger.warning(f"Could not save parallel checkpoint: {e}")


def collect_worker_results(worker_dirs: List[str]) -> Dict[str, Any]:
    """
    Collect results from all worker checkpoint files.
    Returns aggregated completed/failed accounts.
    """
    completed = set()
    failed = set()
    
    for worker_dir in worker_dirs:
        checkpoint_file = os.path.join(worker_dir, 'checkpoint.json')
        if os.path.exists(checkpoint_file):
            try:
                with open(checkpoint_file, 'r') as f:
                    worker_checkpoint = json.load(f)
                    completed.update(worker_checkpoint.get('completed_accounts', []))
                    failed.update(worker_checkpoint.get('failed_accounts', []))
            except Exception:
                pass
    
    return {
        'completed_accounts': list(completed),
        'failed_accounts': list(failed - completed)  # Remove any that succeeded on retry
    }


def run_parallel_account_collection(
    accounts_to_collect: List[Dict[str, Any]],
    args,
    base_session: 'boto3.Session',
    regions: Optional[List[str]],
    checkpoint: Dict[str, Any],
    checkpoint_file: str
) -> int:
    """
    Run parallel account collection using subprocess workers.
    
    Spawns N worker processes, each collecting a subset of accounts.
    Each worker uses --batch-size for checkpointing, enabling resume on failure.
    
    Features:
    - Automatic checkpointing per worker
    - Resume capability via --resume
    - Progress monitoring across all workers
    - Automatic output merging
    
    Returns exit code (0 = success, 1 = partial failure, 2 = total failure).
    """
    num_workers = min(args.parallel_accounts, len(accounts_to_collect))
    output_base = args.output.rstrip('/')
    parallel_checkpoint_file = os.path.join(output_base, 'parallel_checkpoint.json')
    
    # Load or create parallel checkpoint
    parallel_checkpoint = load_parallel_checkpoint(parallel_checkpoint_file)
    already_completed = set(parallel_checkpoint.get('completed_accounts', []))
    
    # Filter out already-completed accounts (for resume)
    if already_completed:
        original_count = len(accounts_to_collect)
        accounts_to_collect = [a for a in accounts_to_collect if a['id'] not in already_completed]
        if len(accounts_to_collect) < original_count:
            logger.info(f"Resuming: {len(already_completed)} accounts already completed, {len(accounts_to_collect)} remaining")
            print(f"\n  Resuming parallel collection: {len(already_completed)} done, {len(accounts_to_collect)} remaining\n")
    
    if not accounts_to_collect:
        print("All accounts already collected. Nothing to do.")
        return 0
    
    # Distribute accounts across workers
    worker_accounts = distribute_accounts(accounts_to_collect, num_workers)
    num_workers = len(worker_accounts)  # May be less if fewer accounts than workers
    
    # Check SSO token expiry and warn if needed
    sso_expiry = get_sso_token_expiry()
    estimated_runtime_minutes = len(accounts_to_collect) * 1.25 / num_workers  # Per-account time / parallelism
    sso_refresh_interval = 45 * 60  # Refresh SSO every 45 minutes to stay ahead of 1-hour expiry
    
    if sso_expiry:
        now = datetime.now(timezone.utc)
        remaining_minutes = (sso_expiry - now).total_seconds() / 60
        
        if remaining_minutes < 5:
            print("\n" + "=" * 70)
            print("WARNING: SSO token expires in less than 5 minutes!")
            print("=" * 70)
            if args.sso_refresh:
                print("  Refreshing SSO credentials before starting...")
                if refresh_sso_credentials(args.profile):
                    print("  SSO refresh successful")
                    sso_expiry = get_sso_token_expiry()
                else:
                    print("  SSO refresh failed - credentials may expire during collection")
            else:
                print("  Consider using --sso-refresh to auto-refresh during collection")
            print("=" * 70 + "\n")
        elif remaining_minutes < estimated_runtime_minutes:
            print("\n" + "=" * 70)
            print(f"WARNING: SSO token expires in {remaining_minutes:.0f} minutes")
            print(f"         Estimated runtime: {estimated_runtime_minutes:.0f} minutes")
            print("=" * 70)
            if args.sso_refresh:
                print("  Auto-refresh enabled - credentials will be refreshed during collection")
            else:
                print("  Consider using --sso-refresh to auto-refresh during collection")
                print("  Or credentials may expire before completion")
            print("=" * 70 + "\n")
    
    # Create worker output directories and account files
    worker_dirs = []
    worker_account_files = []
    
    for i, accounts in enumerate(worker_accounts):
        worker_dir = f"{output_base}/worker_{i+1:02d}"
        os.makedirs(worker_dir, exist_ok=True)
        worker_dirs.append(worker_dir)
        
        # Write account IDs to temp file for this worker
        account_file = f"{worker_dir}/accounts.txt"
        with open(account_file, 'w') as f:
            for acc in accounts:
                f.write(f"{acc['id']}\n")
        worker_account_files.append(account_file)
        
        logger.info(f"Worker {i+1}: {len(accounts)} accounts -> {worker_dir}")
    
    # Save initial parallel checkpoint
    parallel_checkpoint['started_at'] = parallel_checkpoint.get('started_at') or get_timestamp()
    parallel_checkpoint['total_accounts'] = len(accounts_to_collect) + len(already_completed)
    parallel_checkpoint['num_workers'] = num_workers
    parallel_checkpoint['workers'] = {
        f"worker_{i+1:02d}": {
            'accounts': [a['id'] for a in accounts],
            'dir': worker_dirs[i],
            'status': 'pending'
        }
        for i, accounts in enumerate(worker_accounts)
    }
    save_parallel_checkpoint(parallel_checkpoint_file, parallel_checkpoint)
    
    # Build base command (exclude args that we'll override)
    base_cmd = [sys.executable, sys.argv[0]]
    
    # Pass through relevant args
    if args.org_role:
        base_cmd.extend(['--org-role', args.org_role])
    if args.external_id:
        base_cmd.extend(['--external-id', args.external_id])
    if args.profile:
        base_cmd.extend(['--profile', args.profile])
    if args.regions:
        base_cmd.extend(['--regions', args.regions])
    if args.parallel_regions:
        base_cmd.extend(['--parallel-regions', str(args.parallel_regions)])
    if args.include_storage_sizes:
        base_cmd.append('--include-storage-sizes')
    if args.include_change_rate:
        base_cmd.extend(['--include-change-rate'])
        base_cmd.extend(['--change-rate-days', str(args.change_rate_days)])
    if args.skip_pvc:
        base_cmd.append('--skip-pvc')
    if args.log_level:
        base_cmd.extend(['--log-level', args.log_level])
    if args.include_resource_ids:
        base_cmd.append('--include-resource-ids')
    if args.org_name:
        base_cmd.extend(['--org-name', args.org_name])
    
    # Force sequential mode for workers + enable checkpointing within each worker
    base_cmd.extend(['--parallel-accounts', '1'])
    base_cmd.extend(['--batch-size', '10'])  # Checkpoint every 10 accounts
    
    # Spawn worker processes
    workers: List[subprocess.Popen] = []
    start_time = time.time()
    
    for i, (worker_dir, account_file) in enumerate(zip(worker_dirs, worker_account_files)):
        cmd = base_cmd + ['--account-file', account_file, '-o', worker_dir]
        logger.info(f"Starting worker {i+1}/{num_workers}")
        
        # Update worker status
        parallel_checkpoint['workers'][f"worker_{i+1:02d}"]['status'] = 'running'
        save_parallel_checkpoint(parallel_checkpoint_file, parallel_checkpoint)
        
        # Start subprocess
        log_file = f"{worker_dir}/worker.log"
        with open(log_file, 'w') as log_f:
            proc = subprocess.Popen(
                cmd,
                stdout=log_f,
                stderr=subprocess.STDOUT,
                cwd=os.getcwd()
            )
            workers.append(proc)
    
    print(f"\n  Started {num_workers} workers with checkpointing enabled")
    print(f"  Output directories: {output_base}/worker_01 through worker_{num_workers:02d}")
    print(f"  Checkpoint file: {parallel_checkpoint_file}")
    print(f"  Worker logs: {output_base}/worker_XX/worker.log")
    if args.sso_refresh:
        print(f"  SSO auto-refresh: enabled (will refresh when token < 10 min remaining)")
    print("")
    sso_flag = " --sso-refresh" if args.sso_refresh else ""
    print(f"  To resume if interrupted: python3 {sys.argv[0]} --resume {parallel_checkpoint_file}{sso_flag}")
    print("")
    
    # Monitor workers until completion
    completed = [False] * num_workers
    return_codes: List[Optional[int]] = [None] * num_workers
    last_progress_update = 0
    last_sso_check = 0
    
    while not all(completed):
        time.sleep(5)  # Poll every 5 seconds
        
        status_parts = []
        for i, proc in enumerate(workers):
            worker_key = f"worker_{i+1:02d}"
            if completed[i]:
                status = "✓" if return_codes[i] == 0 else "✗"
            else:
                ret = proc.poll()
                if ret is not None:
                    completed[i] = True
                    return_codes[i] = ret
                    status = "✓" if ret == 0 else "✗"
                    parallel_checkpoint['workers'][worker_key]['status'] = 'completed' if ret == 0 else 'failed'
                    parallel_checkpoint['workers'][worker_key]['exit_code'] = ret
                else:
                    status = "..."
            status_parts.append(f"W{i+1}:{status}")
        
        elapsed = time.time() - start_time
        completed_count = sum(1 for c in completed if c)
        
        # Update checkpoint periodically (every 30 seconds)
        if elapsed - last_progress_update > 30:
            results = collect_worker_results(worker_dirs)
            parallel_checkpoint['completed_accounts'] = list(set(already_completed) | set(results['completed_accounts']))
            parallel_checkpoint['failed_accounts'] = results['failed_accounts']
            save_parallel_checkpoint(parallel_checkpoint_file, parallel_checkpoint)
            last_progress_update = elapsed
        
        # Proactive SSO refresh (check every 60 seconds if --sso-refresh enabled)
        if args.sso_refresh and (elapsed - last_sso_check > 60):
            last_sso_check = elapsed
            sso_expiry = get_sso_token_expiry()
            if sso_expiry:
                now = datetime.now(timezone.utc)
                remaining_minutes = (sso_expiry - now).total_seconds() / 60
                
                if remaining_minutes < 10:  # Refresh when < 10 min remaining
                    print(f"\n\n  SSO token expires in {remaining_minutes:.0f} minutes - refreshing...")
                    if refresh_sso_credentials(args.profile):
                        print("  SSO credentials refreshed successfully")
                    else:
                        print("  WARNING: SSO refresh failed - workers may fail soon")
                    print("")  # Blank line before resuming status
        
        print(f"\r  [{elapsed//60:.0f}m {elapsed%60:.0f}s] {' '.join(status_parts)} ({completed_count}/{num_workers} workers done)", end="", flush=True)
    
    print("\n")  # New line after progress
    
    # Final checkpoint update - collect all worker results
    results = collect_worker_results(worker_dirs)
    parallel_checkpoint['completed_accounts'] = list(set(already_completed) | set(results['completed_accounts']))
    parallel_checkpoint['failed_accounts'] = results['failed_accounts']
    parallel_checkpoint['finished_at'] = get_timestamp()
    save_parallel_checkpoint(parallel_checkpoint_file, parallel_checkpoint)
    
    # Summary
    elapsed = time.time() - start_time
    successful_workers = sum(1 for r in return_codes if r == 0)
    failed_workers = num_workers - successful_workers
    total_completed = len(parallel_checkpoint['completed_accounts'])
    total_failed = len(parallel_checkpoint['failed_accounts'])
    
    print("=" * 70)
    print(f"PARALLEL COLLECTION COMPLETE")
    print("=" * 70)
    print(f"  Duration: {elapsed/60:.1f} minutes ({elapsed/3600:.2f} hours)")
    print(f"  Workers: {successful_workers} succeeded, {failed_workers} failed")
    print(f"  Accounts: {total_completed} completed, {total_failed} failed")
    
    # Collect failed accounts for retry info
    if total_failed > 0:
        print(f"\n  Failed accounts: {', '.join(parallel_checkpoint['failed_accounts'][:5])}")
        if total_failed > 5:
            print(f"    ... and {total_failed - 5} more (see checkpoint file)")
        print(f"\n  To retry failed accounts only:")
        print(f"    python3 {sys.argv[0]} --org-role {args.org_role or 'ROLE'} \\")
        print(f"      --accounts {','.join(parallel_checkpoint['failed_accounts'][:3])}...")
    
    if failed_workers > 0:
        print(f"\n  Failed worker logs:")
        for i, ret in enumerate(return_codes):
            if ret != 0:
                print(f"    Worker {i+1}: {worker_dirs[i]}/worker.log")
    
    # Merge outputs
    print(f"\n  Merging outputs from {num_workers} workers...")
    merged_dir = f"{output_base}/merged"
    os.makedirs(merged_dir, exist_ok=True)
    
    try:
        # Import and use merge functionality
        merge_script = os.path.join(os.path.dirname(__file__), 'scripts', 'merge_batch_outputs.py')
        if os.path.exists(merge_script):
            merge_cmd = [sys.executable, merge_script] + worker_dirs + ['-o', merged_dir]
            result = subprocess.run(merge_cmd, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"  Merged output: {merged_dir}/")
            else:
                logger.warning(f"Merge script failed: {result.stderr}")
                print(f"  Merge failed - outputs available in worker directories")
        else:
            # Manual merge: find all cca_inv and cca_sum files
            print(f"  Worker outputs available in: {output_base}/worker_XX/")
    except Exception as e:
        logger.warning(f"Error during merge: {e}")
        print(f"  Merge error - outputs available in worker directories")
    
    print("=" * 70)
    
    if failed_workers == 0:
        return 0
    elif successful_workers > 0:
        return 1  # Partial success
    else:
        return 2  # Total failure


def collect_account(
    session: boto3.Session,
    account_id: str,
    regions: Optional[List[str]] = None,
    tracker: Optional[ProgressTracker] = None,
    include_storage_sizes: bool = False,
    parallel_regions: int = 1
) -> List[CloudResource]:
    """
    Collect all resources from a single AWS account.

    Args:
        session: boto3 session with credentials for this account
        account_id: AWS account ID
        regions: List of regions to collect from (None = all enabled)
        tracker: Optional progress tracker for UI feedback
        include_storage_sizes: If True, query CloudWatch for S3 bucket sizes
        parallel_regions: Number of regions to collect in parallel (1 = serial)

    Returns:
        List of CloudResource objects
    """
    resources = []

    # Get regions if not specified
    if regions is None:
        regions = get_enabled_regions(session)

    logger.info(f"Collecting from account {account_id} across {len(regions)} regions (parallel={parallel_regions})")

    # S3 is global
    if tracker:
        tracker.update_task("Collecting S3 buckets...")
    s3_resources = collect_s3_buckets(session, account_id, include_sizes=include_storage_sizes)
    resources.extend(s3_resources)
    if tracker:
        tracker.add_resources(len(s3_resources), sum(r.size_gb for r in s3_resources))

    # Backup region settings are account-level (same across all regions), collect once
    if tracker:
        tracker.update_task("Collecting Backup region settings...")
    # Use first region to make the API call, but treat as account-level resource
    backup_region = regions[0] if regions else 'us-east-1'
    backup_settings = collect_backup_region_settings(session, backup_region, account_id)
    # Change region to 'global' since settings apply account-wide
    for resource in backup_settings:
        resource.region = 'global'
        resource.resource_id = f"arn:aws:backup:{account_id}:region-settings"
    resources.extend(backup_settings)
    if tracker and backup_settings:
        tracker.add_resources(len(backup_settings), 0)

    # Regional resources - can parallelize across regions
    if parallel_regions > 1 and len(regions) > 1:
        # Parallel collection (no tracker updates - runs in background)
        logger.info(f"Collecting {len(regions)} regions in parallel (workers={parallel_regions})")
        with ThreadPoolExecutor(max_workers=parallel_regions) as executor:
            futures = {
                executor.submit(collect_region, session, region, account_id, None): region
                for region in regions
            }
            for future in as_completed(futures):
                region = futures[future]
                try:
                    region_resources = future.result()
                    resources.extend(region_resources)
                    logger.info(f"[{region}] Completed: {len(region_resources)} resources")
                except Exception as e:
                    logger.error(f"[{region}] Failed: {e}")
    else:
        # Serial collection (with tracker updates)
        for region in regions:
            if tracker:
                tracker.start_region(region)
            region_resources = collect_region(session, region, account_id, tracker)
            resources.extend(region_resources)
            if tracker:
                tracker.complete_region()

    logger.info(f"Collected {len(resources)} resources from account {account_id}")
    return resources


# =============================================================================
# EC2 Collectors
# =============================================================================

def collect_ec2_instances(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect EC2 instances."""
    resources = []
    try:
        ec2 = session.client('ec2', region_name=region)
        paginator = ec2.get_paginator('describe_instances')

        for page in paginator.paginate():
            for reservation in page.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    tags = tags_to_dict(instance.get('Tags', []))

                    # Get attached volumes
                    attached_volumes = [
                        d.get('Ebs', {}).get('VolumeId', '')
                        for d in instance.get('BlockDeviceMappings', [])
                        if d.get('Ebs', {}).get('VolumeId')
                    ]

                    instance_id = instance.get('InstanceId', '')
                    resource = CloudResource(
                        provider="aws",
                        account_id=account_id,
                        region=region,
                        resource_type="aws:ec2:instance",
                        service_family="EC2",
                        resource_id=instance_id,
                        name=get_name_from_tags(tags, instance_id),
                        tags=tags,
                        size_gb=0.0,
                        metadata={
                            'instance_type': instance.get('InstanceType'),
                            'state': instance.get('State', {}).get('Name'),
                            'platform': instance.get('Platform', 'linux'),
                            'vpc_id': instance.get('VpcId'),
                            'attached_volumes': attached_volumes
                        }
                    )
                    resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} EC2 instances")
    except Exception as e:
        check_and_raise_auth_error(e, "collect EC2 instances", "aws")
        logger.error(f"[{region}] Failed to collect EC2 instances: {e}")

    return resources


def collect_ebs_volumes(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect EBS volumes."""
    resources = []
    try:
        ec2 = session.client('ec2', region_name=region)
        paginator = ec2.get_paginator('describe_volumes')

        for page in paginator.paginate():
            for volume in page['Volumes']:
                tags = tags_to_dict(volume.get('Tags', []))

                attachments = volume.get('Attachments', [])
                attached_instance = attachments[0].get('InstanceId') if attachments else None

                volume_id = volume.get('VolumeId', '')
                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:ec2:volume",
                    service_family="EC2",
                    resource_id=volume_id,
                    name=get_name_from_tags(tags, volume_id),
                    tags=tags,
                    size_gb=float(volume.get('Size', 0)),
                    parent_resource_id=attached_instance,
                    metadata={
                        'volume_type': volume.get('VolumeType'),
                        'state': volume.get('State'),
                        'encrypted': volume.get('Encrypted', False),
                        'attached_instance': attached_instance
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} EBS volumes")
    except Exception as e:
        check_and_raise_auth_error(e, "collect EBS volumes", "aws")
        logger.error(f"[{region}] Failed to collect EBS volumes: {e}")

    return resources


def collect_ebs_snapshots(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect EBS snapshots owned by this account."""
    resources = []
    try:
        ec2 = session.client('ec2', region_name=region)
        paginator = ec2.get_paginator('describe_snapshots')

        # Only get snapshots owned by this account ('self' works for both real AWS and moto)
        for page in paginator.paginate(OwnerIds=['self']):
            for snapshot in page.get('Snapshots', []):
                tags = tags_to_dict(snapshot.get('Tags', []))
                snapshot_id = snapshot.get('SnapshotId', '')

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:ec2:snapshot",
                    service_family="EC2",
                    resource_id=snapshot_id,
                    name=get_name_from_tags(tags, snapshot_id),
                    tags=tags,
                    size_gb=float(snapshot.get('VolumeSize', 0)),
                    parent_resource_id=snapshot.get('VolumeId'),
                    metadata={
                        'volume_id': snapshot.get('VolumeId'),
                        'state': snapshot.get('State'),
                        'encrypted': snapshot.get('Encrypted', False),
                        'start_time': str(snapshot.get('StartTime', '')),
                        'description': snapshot.get('Description', '')
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} EBS snapshots")
    except Exception as e:
        check_and_raise_auth_error(e, "collect EBS snapshots", "aws")
        logger.error(f"[{region}] Failed to collect EBS snapshots: {e}")

    return resources


# =============================================================================
# RDS Collectors
# =============================================================================

def collect_rds_instances(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect RDS database instances."""
    resources = []
    try:
        rds = session.client('rds', region_name=region)
        paginator = rds.get_paginator('describe_db_instances')

        for page in paginator.paginate():
            for db in page['DBInstances']:
                # Check if this is a read replica
                replica_source = db.get('ReadReplicaSourceDBInstanceIdentifier')
                replica_ids = db.get('ReadReplicaDBInstanceIdentifiers', [])

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:rds:instance",
                    service_family="RDS",
                    resource_id=db.get('DBInstanceArn', ''),
                    name=db.get('DBInstanceIdentifier', ''),
                    tags={},
                    size_gb=float(db.get('AllocatedStorage', 0)),
                    metadata={
                        'engine': db.get('Engine'),
                        'engine_version': db.get('EngineVersion'),
                        'instance_class': db.get('DBInstanceClass'),
                        'status': db.get('DBInstanceStatus'),
                        'multi_az': db.get('MultiAZ', False),
                        'encrypted': db.get('StorageEncrypted', False),
                        'is_read_replica': bool(replica_source),
                        'read_replica_source': replica_source,
                        'read_replica_ids': replica_ids,
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} RDS instances")
    except Exception as e:
        check_and_raise_auth_error(e, "collect RDS instances", "aws")
        logger.error(f"[{region}] Failed to collect RDS instances: {e}")

    return resources


def get_aurora_cluster_storage(session: boto3.Session, region: str, cluster_id: str) -> float:
    """Get actual storage used by an Aurora cluster from CloudWatch metrics.

    Aurora clusters report AllocatedStorage as 1 in the RDS API, but the actual
    storage can be retrieved from CloudWatch's VolumeBytesUsed metric.

    Note: For multiple clusters, use get_aurora_cluster_storage_batch() which is
    more efficient (single API call vs N calls).

    Args:
        session: boto3 session
        region: AWS region
        cluster_id: Aurora cluster identifier (not ARN)

    Returns:
        Storage in GB, or 0.0 if metric unavailable
    """
    try:
        cloudwatch = session.client('cloudwatch', region_name=region)

        # Get the most recent VolumeBytesUsed metric (last 24 hours)
        response = cloudwatch.get_metric_statistics(
            Namespace='AWS/RDS',
            MetricName='VolumeBytesUsed',
            Dimensions=[
                {'Name': 'DBClusterIdentifier', 'Value': cluster_id}
            ],
            StartTime=datetime.now(timezone.utc) - timedelta(hours=24),
            EndTime=datetime.now(timezone.utc),
            Period=3600,  # 1 hour granularity
            Statistics=['Average']
        )

        datapoints = response.get('Datapoints', [])
        if datapoints:
            # Get the most recent datapoint
            latest = max(datapoints, key=lambda x: x['Timestamp'])
            bytes_used = latest.get('Average', 0)
            # Convert bytes to GB
            return round(bytes_used / (1024 ** 3), 2)
    except Exception as e:
        logger.debug(f"[{region}] Could not get CloudWatch storage for Aurora cluster {cluster_id}: {e}")

    return 0.0


def get_aurora_cluster_storage_batch(session: boto3.Session, region: str, cluster_ids: List[str]) -> Dict[str, float]:
    """Batch fetch storage for multiple Aurora clusters using GetMetricData API.

    Uses CloudWatch's get_metric_data API which can fetch up to 500 metrics
    in a single call, much more efficient than individual get_metric_statistics calls.

    Args:
        session: boto3 session
        region: AWS region
        cluster_ids: List of Aurora cluster identifiers

    Returns:
        Dict mapping cluster_id to storage in GB (missing clusters return 0.0)
    """
    if not cluster_ids:
        return {}

    results = {cid: 0.0 for cid in cluster_ids}

    try:
        cloudwatch = session.client('cloudwatch', region_name=region)

        # Build metric queries for all clusters (max 500 per API call)
        # Use sanitized IDs for metric query IDs (must match [a-z][a-zA-Z0-9_]*)
        queries = []
        id_map = {}  # Map query ID back to cluster ID

        for i, cluster_id in enumerate(cluster_ids):
            query_id = f"m{i}"
            id_map[query_id] = cluster_id
            queries.append({
                'Id': query_id,
                'MetricStat': {
                    'Metric': {
                        'Namespace': 'AWS/RDS',
                        'MetricName': 'VolumeBytesUsed',
                        'Dimensions': [{'Name': 'DBClusterIdentifier', 'Value': cluster_id}]
                    },
                    'Period': 3600,
                    'Stat': 'Average'
                },
                'ReturnData': True
            })

        # Batch in groups of 500 (CloudWatch limit)
        start_time = datetime.now(timezone.utc) - timedelta(hours=24)
        end_time = datetime.now(timezone.utc)

        for batch_start in range(0, len(queries), 500):
            batch_queries = queries[batch_start:batch_start + 500]

            response = cloudwatch.get_metric_data(
                MetricDataQueries=batch_queries,
                StartTime=start_time,
                EndTime=end_time
            )

            # Process results
            for metric_result in response.get('MetricDataResults', []):
                query_id = metric_result.get('Id', '')
                values = metric_result.get('Values', [])

                if query_id in id_map and values:
                    # Get most recent value (values are sorted newest first)
                    bytes_used = values[0]
                    cluster_id = id_map[query_id]
                    results[cluster_id] = round(bytes_used / BYTES_PER_GB, 2)

        logger.debug(f"[{region}] Batch fetched CloudWatch storage for {len(cluster_ids)} Aurora clusters")
    except Exception as e:
        logger.debug(f"[{region}] Could not batch fetch CloudWatch storage: {e}")

    return results


def collect_rds_clusters(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect RDS Aurora clusters.

    Optimized with batch CloudWatch metrics fetch (CR-023).
    """
    resources = []
    try:
        rds = session.client('rds', region_name=region)
        paginator = rds.get_paginator('describe_db_clusters')

        # Phase 1: Collect all cluster data
        clusters_data = []
        aurora_cluster_ids = []

        for page in paginator.paginate():
            for cluster in page['DBClusters']:
                cluster_id = cluster.get('DBClusterIdentifier', '')
                api_storage = float(cluster.get('AllocatedStorage', 0))

                clusters_data.append({
                    'cluster': cluster,
                    'cluster_id': cluster_id,
                    'api_storage': api_storage
                })

                # Track Aurora clusters that need CloudWatch lookup (API reports 1 for Aurora)
                if api_storage <= 1:
                    aurora_cluster_ids.append(cluster_id)

        if not clusters_data:
            logger.info(f"[{region}] Found 0 RDS clusters")
            return resources

        # Phase 2: Batch fetch CloudWatch storage for Aurora clusters
        cloudwatch_storage = {}
        if aurora_cluster_ids:
            cloudwatch_storage = get_aurora_cluster_storage_batch(session, region, aurora_cluster_ids)

        # Phase 3: Build CloudResource objects
        for data in clusters_data:
            cluster = data['cluster']
            cluster_id = data['cluster_id']
            api_storage = data['api_storage']

            # Use CloudWatch value if available and API reports placeholder value
            cw_storage = cloudwatch_storage.get(cluster_id, 0.0)
            actual_storage = cw_storage if cw_storage > 0 and api_storage <= 1 else api_storage

            resource = CloudResource(
                provider="aws",
                account_id=account_id,
                region=region,
                resource_type="aws:rds:cluster",
                service_family="RDS",
                resource_id=cluster.get('DBClusterArn', ''),
                name=cluster_id,
                tags={},
                size_gb=actual_storage,
                metadata={
                    'engine': cluster.get('Engine'),
                    'engine_version': cluster.get('EngineVersion'),
                    'status': cluster.get('Status'),
                    'multi_az': cluster.get('MultiAZ', False),
                    'encrypted': cluster.get('StorageEncrypted', False),
                    'storage_source': 'cloudwatch' if cw_storage > 0 and api_storage <= 1 else 'api'
                }
            )
            resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} RDS clusters")
    except Exception as e:
        check_and_raise_auth_error(e, "collect RDS clusters", "aws")
        logger.error(f"[{region}] Failed to collect RDS clusters: {e}")

    return resources


def collect_rds_snapshots(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect RDS DB snapshots."""
    resources = []
    try:
        rds = session.client('rds', region_name=region)
        paginator = rds.get_paginator('describe_db_snapshots')

        for page in paginator.paginate():
            for snapshot in page.get('DBSnapshots', []):
                snapshot_id = snapshot.get('DBSnapshotIdentifier', '')

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:rds:snapshot",
                    service_family="RDS",
                    resource_id=snapshot.get('DBSnapshotArn', ''),
                    name=snapshot_id,
                    tags={},
                    size_gb=float(snapshot.get('AllocatedStorage', 0)),
                    parent_resource_id=snapshot.get('DBInstanceIdentifier'),
                    metadata={
                        'db_instance_id': snapshot.get('DBInstanceIdentifier'),
                        'engine': snapshot.get('Engine'),
                        'status': snapshot.get('Status'),
                        'snapshot_type': snapshot.get('SnapshotType'),
                        'encrypted': snapshot.get('Encrypted', False),
                        'snapshot_create_time': str(snapshot.get('SnapshotCreateTime', ''))
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} RDS snapshots")
    except Exception as e:
        check_and_raise_auth_error(e, "collect RDS snapshots", "aws")
        logger.error(f"[{region}] Failed to collect RDS snapshots: {e}")

    return resources


def collect_rds_cluster_snapshots(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect RDS Aurora cluster snapshots."""
    resources = []
    try:
        rds = session.client('rds', region_name=region)
        paginator = rds.get_paginator('describe_db_cluster_snapshots')

        for page in paginator.paginate():
            for snapshot in page.get('DBClusterSnapshots', []):
                snapshot_id = snapshot.get('DBClusterSnapshotIdentifier', '')

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:rds:cluster-snapshot",
                    service_family="RDS",
                    resource_id=snapshot.get('DBClusterSnapshotArn', ''),
                    name=snapshot_id,
                    tags={},
                    size_gb=float(snapshot.get('AllocatedStorage', 0)),
                    parent_resource_id=snapshot.get('DBClusterIdentifier'),
                    metadata={
                        'db_cluster_id': snapshot.get('DBClusterIdentifier'),
                        'engine': snapshot.get('Engine'),
                        'status': snapshot.get('Status'),
                        'snapshot_type': snapshot.get('SnapshotType'),
                        'encrypted': snapshot.get('StorageEncrypted', False),
                        'snapshot_create_time': str(snapshot.get('SnapshotCreateTime', ''))
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} RDS cluster snapshots")
    except Exception as e:
        check_and_raise_auth_error(e, "collect RDS cluster snapshots", "aws")
        logger.error(f"[{region}] Failed to collect RDS cluster snapshots: {e}")

    return resources


# =============================================================================
# S3 Collector
# =============================================================================

def get_s3_bucket_size_from_cloudwatch(session: boto3.Session, bucket_name: str, region: str) -> float:
    """Get S3 bucket size from CloudWatch metrics.

    Returns size in GB, or 0.0 if metrics unavailable.
    """
    try:
        # CloudWatch metrics for S3 are stored in the bucket's region
        cw_region = region if region != 'unknown' else 'us-east-1'
        cloudwatch = session.client('cloudwatch', region_name=cw_region)

        # Query BucketSizeBytes metric (updated daily by S3)
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=3)  # Look back 3 days for latest metric

        response = cloudwatch.get_metric_statistics(
            Namespace='AWS/S3',
            MetricName='BucketSizeBytes',
            Dimensions=[
                {'Name': 'BucketName', 'Value': bucket_name},
                {'Name': 'StorageType', 'Value': 'StandardStorage'}
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,  # Daily
            Statistics=['Average']
        )

        datapoints = response.get('Datapoints', [])
        if datapoints:
            # Get the most recent datapoint
            latest = max(datapoints, key=lambda x: x['Timestamp'])
            size_bytes = latest.get('Average', 0)
            return size_bytes / (1024 ** 3)  # Convert to GB

        return 0.0
    except Exception as e:
        logger.debug(f"Could not get CloudWatch size for bucket {bucket_name}: {e}")
        return 0.0


def _get_bucket_location_and_tags(s3_client, bucket_name: str) -> Dict[str, Any]:
    """Get bucket location and tags in parallel-friendly way.

    Returns dict with bucket_name, region, and tags.
    """
    result = {'name': bucket_name, 'region': 'unknown', 'tags': {}}

    # Get bucket region
    try:
        location = s3_client.get_bucket_location(Bucket=bucket_name)
        result['region'] = location.get('LocationConstraint') or 'us-east-1'
    except ClientError as e:
        logger.debug(f"Could not get location for bucket {bucket_name}: {e}")

    # Get bucket tags
    try:
        tag_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
        for tag in tag_response.get('TagSet', []):
            result['tags'][tag['Key']] = tag['Value']
    except ClientError:
        # NoSuchTagSet is common - bucket has no tags
        pass

    return result


@retry_with_backoff(max_attempts=3, exceptions=(ClientError,))
def collect_s3_buckets(session: boto3.Session, account_id: str, include_sizes: bool = False) -> List[CloudResource]:
    """Collect S3 buckets (global service).

    Args:
        session: boto3 session
        account_id: AWS account ID
        include_sizes: If True, query CloudWatch for bucket sizes (slower but accurate)
    """
    resources = []
    try:
        s3 = session.client('s3')
        response = s3.list_buckets()

        # Get bucket names and creation dates
        buckets = []
        for bucket in response.get('Buckets', []):
            bucket_name = bucket.get('Name', '')
            if bucket_name:
                buckets.append({
                    'name': bucket_name,
                    'creation_date': str(bucket.get('CreationDate', ''))
                })

        if not buckets:
            logger.info("Found 0 S3 buckets")
            return resources

        # Parallel fetch of bucket locations and tags (CR-021 optimization)
        logger.debug(f"Fetching locations and tags for {len(buckets)} buckets in parallel...")
        bucket_info = []
        max_workers = min(10, len(buckets))  # Cap at 10 to avoid S3 throttling

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_get_bucket_location_and_tags, s3, b['name']): b
                for b in buckets
            }
            for future in as_completed(futures):
                bucket_data = futures[future]
                try:
                    info = future.result()
                    info['creation_date'] = bucket_data['creation_date']
                    bucket_info.append(info)
                except Exception as e:
                    logger.debug(f"Failed to get info for bucket {bucket_data['name']}: {e}")
                    # Still include bucket with defaults
                    bucket_info.append({
                        'name': bucket_data['name'],
                        'region': 'unknown',
                        'tags': {},
                        'creation_date': bucket_data['creation_date']
                    })

        # Second pass: get sizes from CloudWatch if requested
        total_size_gb = 0.0

        if include_sizes:
            logger.info(f"Fetching S3 bucket sizes from CloudWatch ({len(bucket_info)} buckets)...")
            buckets_by_region: Dict[str, List[Dict]] = {}
            for info in bucket_info:
                region = info['region']
                if region not in buckets_by_region:
                    buckets_by_region[region] = []
                buckets_by_region[region].append(info)

            for region, region_buckets in buckets_by_region.items():
                for info in region_buckets:
                    size_gb = get_s3_bucket_size_from_cloudwatch(session, info['name'], region)
                    info['size_gb'] = size_gb
                    total_size_gb += size_gb
        else:
            for info in bucket_info:
                info['size_gb'] = 0.0

        # Create resources
        for info in bucket_info:
            resource = CloudResource(
                provider="aws",
                account_id=account_id,
                region=info['region'],
                resource_type="aws:s3:bucket",
                service_family="S3",
                resource_id=f"arn:aws:s3:::{info['name']}",
                name=info['name'],
                tags=info['tags'],
                size_gb=info['size_gb'],
                metadata={
                    'creation_date': info['creation_date'],
                    'size_note': 'Use --include-storage-sizes for accurate sizing' if not include_sizes else None
                }
            )
            resources.append(resource)

        size_note = f" ({total_size_gb:.1f} GB)" if include_sizes else " (sizes not collected)"
        logger.info(f"Found {len(resources)} S3 buckets{size_note}")
    except Exception as e:
        check_and_raise_auth_error(e, "collect S3 buckets", "aws")
        logger.error(f"Failed to collect S3 buckets: {e}")

    return resources


# =============================================================================
# EFS Collector
# =============================================================================

def collect_efs_filesystems(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect EFS file systems."""
    resources = []
    try:
        efs = session.client('efs', region_name=region)
        paginator = efs.get_paginator('describe_file_systems')

        for page in paginator.paginate():
            for fs in page['FileSystems']:
                tags = {t['Key']: t['Value'] for t in fs.get('Tags', [])}

                # Size is in bytes
                size_bytes = fs.get('SizeInBytes', {}).get('Value', 0)

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:efs:filesystem",
                    service_family="EFS",
                    resource_id=fs['FileSystemId'],
                    name=tags.get('Name', fs['FileSystemId']),
                    tags=tags,
                    size_gb=format_bytes_to_gb(size_bytes),
                    metadata={
                        'lifecycle_state': fs.get('LifeCycleState'),
                        'performance_mode': fs.get('PerformanceMode'),
                        'encrypted': fs.get('Encrypted', False)
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} EFS file systems")
    except Exception as e:
        check_and_raise_auth_error(e, "collect EFS", "aws")
        logger.error(f"[{region}] Failed to collect EFS: {e}")

    return resources


# =============================================================================
# EKS Collector
# =============================================================================

def collect_eks_clusters(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect EKS clusters."""
    resources = []
    try:
        eks = session.client('eks', region_name=region)

        # Paginate through all clusters
        clusters = []
        next_token = None
        while True:
            if next_token:
                response = eks.list_clusters(nextToken=next_token)
            else:
                response = eks.list_clusters()
            clusters.extend(response.get('clusters', []))
            next_token = response.get('nextToken')
            if not next_token:
                break

        for cluster_name in clusters:
            try:
                cluster = eks.describe_cluster(name=cluster_name)['cluster']

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:eks:cluster",
                    service_family="EKS",
                    resource_id=cluster.get('arn', ''),
                    name=cluster_name,
                    tags=cluster.get('tags', {}),
                    size_gb=0.0,
                    metadata={
                        'status': cluster.get('status'),
                        'version': cluster.get('version'),
                        'endpoint': cluster.get('endpoint')
                    }
                )
                resources.append(resource)
            except Exception as e:
                check_and_raise_auth_error(e, f"describe EKS cluster {cluster_name}", "aws")
                logger.warning(f"[{region}] Failed to describe EKS cluster {cluster_name}: {e}")

        logger.info(f"[{region}] Found {len(resources)} EKS clusters")
    except Exception as e:
        check_and_raise_auth_error(e, "collect EKS clusters", "aws")
        logger.error(f"[{region}] Failed to collect EKS clusters: {e}")

    return resources


def collect_eks_nodegroups(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect EKS node groups with instance mapping."""
    resources = []
    try:
        eks = session.client('eks', region_name=region)

        # Paginate through all clusters
        clusters = []
        next_token = None
        while True:
            if next_token:
                response = eks.list_clusters(nextToken=next_token)
            else:
                response = eks.list_clusters()
            clusters.extend(response.get('clusters', []))
            next_token = response.get('nextToken')
            if not next_token:
                break

        for cluster_name in clusters:
            try:
                # Paginate through all nodegroups for this cluster
                nodegroups = []
                ng_next_token = None
                while True:
                    if ng_next_token:
                        ng_response = eks.list_nodegroups(clusterName=cluster_name, nextToken=ng_next_token)
                    else:
                        ng_response = eks.list_nodegroups(clusterName=cluster_name)
                    nodegroups.extend(ng_response.get('nodegroups', []))
                    ng_next_token = ng_response.get('nextToken')
                    if not ng_next_token:
                        break

                for ng_name in nodegroups:
                    try:
                        ng = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)['nodegroup']

                        # Get Auto Scaling group info if available
                        asg_name = ''
                        if ng.get('resources', {}).get('autoScalingGroups'):
                            asg_name = ng['resources']['autoScalingGroups'][0].get('name', '')

                        resource = CloudResource(
                            provider="aws",
                            account_id=account_id,
                            region=region,
                            resource_type="aws:eks:nodegroup",
                            service_family="EKS",
                            resource_id=ng.get('nodegroupArn', ''),
                            name=ng_name,
                            tags=ng.get('tags', {}),
                            size_gb=0.0,
                            parent_resource_id=cluster_name,
                            metadata={
                                'cluster_name': cluster_name,
                                'status': ng.get('status'),
                                'capacity_type': ng.get('capacityType'),
                                'instance_types': ng.get('instanceTypes', []),
                                'scaling_config': ng.get('scalingConfig', {}),
                                'asg_name': asg_name,
                            }
                        )
                        resources.append(resource)
                    except Exception as e:
                        check_and_raise_auth_error(e, f"describe nodegroup {ng_name}", "aws")
                        logger.warning(f"[{region}] Failed to describe nodegroup {ng_name}: {e}")
            except Exception as e:
                check_and_raise_auth_error(e, f"list nodegroups for cluster {cluster_name}", "aws")
                logger.warning(f"[{region}] Failed to list nodegroups for cluster {cluster_name}: {e}")

        logger.info(f"[{region}] Found {len(resources)} EKS node groups")
    except Exception as e:
        check_and_raise_auth_error(e, "collect EKS node groups", "aws")
        logger.error(f"[{region}] Failed to collect EKS node groups: {e}")

    return resources


# =============================================================================
# Lambda Collector
# =============================================================================

def collect_lambda_functions(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect Lambda functions."""
    resources = []
    try:
        lambda_client = session.client('lambda', region_name=region)
        paginator = lambda_client.get_paginator('list_functions')

        for page in paginator.paginate():
            for func in page['Functions']:
                code_size_bytes = func.get('CodeSize', 0)
                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:lambda:function",
                    service_family="Lambda",
                    resource_id=func.get('FunctionArn', ''),
                    name=func.get('FunctionName', ''),
                    tags={},
                    size_gb=code_size_bytes / BYTES_PER_GB,  # For jump bag sizing
                    metadata={
                        'runtime': func.get('Runtime'),
                        'memory': func.get('MemorySize'),
                        'timeout': func.get('Timeout'),
                        'code_size': code_size_bytes
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} Lambda functions")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Lambda functions", "aws")
        logger.error(f"[{region}] Failed to collect Lambda functions: {e}")

    return resources


# =============================================================================
# DynamoDB Collector
# =============================================================================

def collect_dynamodb_tables(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect DynamoDB tables.

    Note: DynamoDB has no batch describe API, so we parallelize describe_table
    calls to improve performance. API call count remains O(n) but wall-clock
    time is significantly reduced.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    resources = []
    try:
        dynamodb = session.client('dynamodb', region_name=region)
        paginator = dynamodb.get_paginator('list_tables')

        # Collect all table names first
        table_names = []
        for page in paginator.paginate():
            table_names.extend(page['TableNames'])

        if not table_names:
            logger.info(f"[{region}] Found 0 DynamoDB tables")
            return resources

        def describe_table(table_name: str) -> Optional[CloudResource]:
            """Describe a single table and return CloudResource."""
            try:
                table = dynamodb.describe_table(TableName=table_name)['Table']
                size_bytes = table.get('TableSizeBytes', 0)

                return CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:dynamodb:table",
                    service_family="DynamoDB",
                    resource_id=table.get('TableArn', ''),
                    name=table_name,
                    tags={},
                    size_gb=format_bytes_to_gb(size_bytes),
                    metadata={
                        'status': table.get('TableStatus'),
                        'item_count': table.get('ItemCount', 0),
                        'billing_mode': table.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED')
                    }
                )
            except Exception as e:
                check_and_raise_auth_error(e, f"describe DynamoDB table {table_name}", "aws")
                logger.warning(f"[{region}] Failed to describe DynamoDB table {table_name}: {e}")
                return None

        # Parallelize describe_table calls (max 10 concurrent to avoid throttling)
        max_workers = min(10, len(table_names))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(describe_table, name): name for name in table_names}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    resources.append(result)

        logger.info(f"[{region}] Found {len(resources)} DynamoDB tables")
    except Exception as e:
        check_and_raise_auth_error(e, "collect DynamoDB tables", "aws")
        logger.error(f"[{region}] Failed to collect DynamoDB tables: {e}")

    return resources


# =============================================================================
# FSx Collector
# =============================================================================

def collect_fsx_filesystems(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect FSx file systems."""
    resources = []
    try:
        fsx = session.client('fsx', region_name=region)
        paginator = fsx.get_paginator('describe_file_systems')

        for page in paginator.paginate():
            for fs in page['FileSystems']:
                tags = {t['Key']: t['Value'] for t in fs.get('Tags', [])}

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:fsx:filesystem",
                    service_family="FSx",
                    resource_id=fs['FileSystemId'],
                    name=tags.get('Name', fs['FileSystemId']),
                    tags=tags,
                    size_gb=float(fs.get('StorageCapacity', 0)),
                    metadata={
                        'filesystem_type': fs.get('FileSystemType'),
                        'lifecycle': fs.get('Lifecycle'),
                        'storage_type': fs.get('StorageType')
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} FSx file systems")
    except Exception as e:
        check_and_raise_auth_error(e, "collect FSx", "aws")
        logger.error(f"[{region}] Failed to collect FSx: {e}")

    return resources


# =============================================================================
# ElastiCache Collector
# =============================================================================

def collect_elasticache_clusters(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect ElastiCache clusters."""
    resources = []
    try:
        elasticache = session.client('elasticache', region_name=region)
        paginator = elasticache.get_paginator('describe_cache_clusters')

        for page in paginator.paginate(ShowCacheNodeInfo=True):
            for cluster in page['CacheClusters']:
                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:elasticache:cluster",
                    service_family="ElastiCache",
                    resource_id=cluster.get('ARN', cluster['CacheClusterId']),
                    name=cluster['CacheClusterId'],
                    tags={},
                    size_gb=0.0,
                    metadata={
                        'engine': cluster.get('Engine'),
                        'engine_version': cluster.get('EngineVersion'),
                        'node_type': cluster.get('CacheNodeType'),
                        'num_nodes': cluster.get('NumCacheNodes', 0),
                        'status': cluster.get('CacheClusterStatus')
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} ElastiCache clusters")
    except Exception as e:
        check_and_raise_auth_error(e, "collect ElastiCache", "aws")
        logger.error(f"[{region}] Failed to collect ElastiCache: {e}")

    return resources


# =============================================================================
# AWS Backup Collectors
# =============================================================================

def _parse_kms_key_info(key_arn: str) -> dict:
    """
    Parse KMS key ARN to determine key type and ownership.

    Returns dict with:
        - encrypted: bool (always True for valid ARN)
        - encryption_type: 'aws_managed' | 'customer_managed' | 'unknown'
        - encryption_key_arn: the original ARN

    ARN formats:
        AWS-managed: arn:aws:kms:region:account:alias/aws/backup
        CMEK by key: arn:aws:kms:region:account:key/key-id
        CMEK by alias: arn:aws:kms:region:account:alias/custom-alias
    """
    if not key_arn:
        return {
            'encrypted': True,  # AWS Backup vaults are always encrypted
            'encryption_type': 'aws_managed',
            'encryption_key_arn': None
        }

    # AWS-managed service keys use alias/aws/<service> pattern
    # e.g., arn:aws:kms:us-east-1:123456789012:alias/aws/backup
    if ':alias/aws/' in key_arn:
        return {
            'encrypted': True,
            'encryption_type': 'aws_managed',
            'encryption_key_arn': key_arn
        }

    # Customer-managed keys use either:
    # - :key/<key-id> pattern (direct key reference)
    # - :alias/<alias-name> pattern (custom alias, not aws/*)
    if ':key/' in key_arn or ':alias/' in key_arn:
        return {
            'encrypted': True,
            'encryption_type': 'customer_managed',
            'encryption_key_arn': key_arn
        }

    # Unknown pattern - still encrypted but can't determine type
    return {
        'encrypted': True,
        'encryption_type': 'unknown',
        'encryption_key_arn': key_arn
    }


def collect_backup_vaults(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect AWS Backup vaults."""
    resources = []
    try:
        backup = session.client('backup', region_name=region)
        paginator = backup.get_paginator('list_backup_vaults')

        for page in paginator.paginate():
            for vault in page.get('BackupVaultList', []):
                vault_name = vault.get('BackupVaultName', '')

                # Parse KMS key info for encryption analysis
                kms_info = _parse_kms_key_info(vault.get('EncryptionKeyArn'))

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:backup:vault",
                    service_family="Backup",
                    resource_id=vault.get('BackupVaultArn', ''),
                    name=vault_name,
                    tags={},
                    size_gb=0.0,  # Size is in recovery points
                    metadata={
                        'number_of_recovery_points': vault.get('NumberOfRecoveryPoints', 0),
                        'encrypted': kms_info['encrypted'],
                        'encryption_type': kms_info['encryption_type'],
                        'encryption_key_arn': kms_info['encryption_key_arn'],
                        'creation_date': str(vault.get('CreationDate', '')),
                        'locked': vault.get('Locked', False)
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} Backup vaults")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Backup vaults", "aws")
        logger.error(f"[{region}] Failed to collect Backup vaults: {e}")

    return resources


def collect_backup_recovery_points(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect AWS Backup recovery points (actual backups) with sizes."""
    resources = []
    try:
        backup = session.client('backup', region_name=region)

        # First, get all vaults
        vaults_paginator = backup.get_paginator('list_backup_vaults')
        vault_names = []
        for page in vaults_paginator.paginate():
            for vault in page.get('BackupVaultList', []):
                vault_names.append(vault.get('BackupVaultName', ''))

        # Then get recovery points from each vault
        for vault_name in vault_names:
            try:
                rp_paginator = backup.get_paginator('list_recovery_points_by_backup_vault')
                for page in rp_paginator.paginate(BackupVaultName=vault_name):
                    for rp in page.get('RecoveryPoints', []):
                        # Size in bytes, convert to GB
                        size_bytes = rp.get('BackupSizeInBytes', 0) or 0
                        size_gb = size_bytes / (1024 ** 3)

                        # Check if this is a copy/replica
                        parent_rp_arn = rp.get('ParentRecoveryPointArn', '')
                        source_vault_arn = rp.get('SourceBackupVaultArn', '')
                        is_replica = bool(parent_rp_arn or source_vault_arn)

                        resource = CloudResource(
                            provider="aws",
                            account_id=account_id,
                            region=region,
                            resource_type="aws:backup:recovery-point",
                            service_family="Backup",
                            resource_id=rp.get('RecoveryPointArn', ''),
                            name=rp.get('RecoveryPointArn', '').split(':')[-1] if rp.get('RecoveryPointArn') else '',
                            tags={},
                            size_gb=round(size_gb, 2),
                            parent_resource_id=rp.get('ResourceArn'),  # The backed-up resource
                            metadata={
                                'resource_type': rp.get('ResourceType'),  # EC2, EBS, RDS, etc.
                                'resource_arn': rp.get('ResourceArn'),
                                'backup_vault_name': vault_name,
                                'status': rp.get('Status'),
                                'creation_date': str(rp.get('CreationDate', '')),
                                'completion_date': str(rp.get('CompletionDate', '')),
                                'lifecycle_delete_after_days': rp.get('Lifecycle', {}).get('DeleteAfterDays'),
                                'lifecycle_move_to_cold_after_days': rp.get('Lifecycle', {}).get('MoveToColdStorageAfterDays'),
                                'is_encrypted': rp.get('IsEncrypted', False),
                                'backup_size_bytes': size_bytes,
                                'is_parent': rp.get('IsParent', False),
                                'parent_recovery_point_arn': parent_rp_arn,
                                'source_backup_vault_arn': source_vault_arn,
                                'is_replica': is_replica
                            }
                        )
                        resources.append(resource)
            except Exception as e:
                check_and_raise_auth_error(e, f"collect recovery points from vault {vault_name}", "aws")
                logger.warning(f"[{region}] Failed to collect recovery points from vault {vault_name}: {e}")

        logger.info(f"[{region}] Found {len(resources)} Backup recovery points")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Backup recovery points", "aws")
        logger.error(f"[{region}] Failed to collect Backup recovery points: {e}")

    return resources


def collect_backup_plans(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect AWS Backup plans."""
    resources = []
    try:
        backup = session.client('backup', region_name=region)
        paginator = backup.get_paginator('list_backup_plans')

        for page in paginator.paginate():
            for plan in page.get('BackupPlansList', []):
                plan_id = plan.get('BackupPlanId', '')

                # Get plan details for rules
                try:
                    plan_details = backup.get_backup_plan(BackupPlanId=plan_id)
                    backup_plan = plan_details.get('BackupPlan', {})
                    rules = backup_plan.get('Rules', [])
                    rule_names = [r.get('RuleName', '') for r in rules]

                    # Extract rule details
                    rule_details = []
                    for rule in rules:
                        lifecycle = rule.get('Lifecycle', {})
                        rule_details.append({
                            'rule_name': rule.get('RuleName'),
                            'target_vault': rule.get('TargetBackupVaultName'),
                            'schedule': rule.get('ScheduleExpression'),
                            'start_window_minutes': rule.get('StartWindowMinutes'),
                            'completion_window_minutes': rule.get('CompletionWindowMinutes'),
                            'delete_after_days': lifecycle.get('DeleteAfterDays'),
                            'move_to_cold_after_days': lifecycle.get('MoveToColdStorageAfterDays')
                        })
                except Exception:
                    rules = []
                    rule_names = []
                    rule_details = []

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:backup:plan",
                    service_family="Backup",
                    resource_id=plan.get('BackupPlanArn', ''),
                    name=plan.get('BackupPlanName', ''),
                    tags={},
                    size_gb=0.0,
                    metadata={
                        'backup_plan_id': plan_id,
                        'version_id': plan.get('VersionId'),
                        'creation_date': str(plan.get('CreationDate', '')),
                        'last_execution_date': str(plan.get('LastExecutionDate', '')) if plan.get('LastExecutionDate') else None,
                        'number_of_rules': len(rules),
                        'rule_names': rule_names,
                        'rules': rule_details
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} Backup plans")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Backup plans", "aws")
        logger.error(f"[{region}] Failed to collect Backup plans: {e}")

    return resources


def _get_backup_selection_details(backup_client, plan_info: Dict, selection_info: Dict) -> Optional[Dict]:
    """Fetch backup selection details - parallel-friendly helper.

    Returns dict with selection details or None on failure.
    """
    plan_id = plan_info['plan_id']
    selection_id = selection_info.get('SelectionId', '')

    try:
        sel_details = backup_client.get_backup_selection(
            BackupPlanId=plan_id,
            SelectionId=selection_id
        )
        sel_data = sel_details.get('BackupSelection', {})

        return {
            'plan_id': plan_id,
            'plan_name': plan_info['plan_name'],
            'plan_arn': plan_info['plan_arn'],
            'selection_id': selection_id,
            'selection_name': sel_data.get('SelectionName', ''),
            'iam_role_arn': sel_data.get('IamRoleArn'),
            'resources': sel_data.get('Resources', []),
            'not_resources': sel_data.get('NotResources', []),
            'list_of_tags': sel_data.get('ListOfTags', []),
            'conditions': sel_data.get('Conditions', {}),
            'creation_date': str(selection_info.get('CreationDate', ''))
        }
    except Exception as e:
        logger.debug(f"Failed to get selection {selection_id} details: {e}")
        return None


def collect_backup_selections(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect AWS Backup selections (resources assigned to backup plans).

    Optimized with parallel fetching of selection details (CR-022).
    """
    resources = []
    try:
        backup = session.client('backup', region_name=region)

        # Phase 1: Collect all plans and their selections (list operations)
        selection_tasks = []  # List of (plan_info, selection_info) tuples

        plans_paginator = backup.get_paginator('list_backup_plans')
        for plans_page in plans_paginator.paginate():
            for plan in plans_page.get('BackupPlansList', []):
                plan_info = {
                    'plan_id': plan.get('BackupPlanId', ''),
                    'plan_name': plan.get('BackupPlanName', ''),
                    'plan_arn': plan.get('BackupPlanArn', '')
                }

                # Get selections for this plan
                try:
                    selections_paginator = backup.get_paginator('list_backup_selections')
                    for sel_page in selections_paginator.paginate(BackupPlanId=plan_info['plan_id']):
                        for selection in sel_page.get('BackupSelectionsList', []):
                            selection_tasks.append((plan_info, selection))
                except Exception as e:
                    check_and_raise_auth_error(e, f"list selections for plan {plan_info['plan_name']}", "aws")
                    logger.warning(f"[{region}] Failed to list selections for plan {plan_info['plan_name']}: {e}")

        if not selection_tasks:
            logger.info(f"[{region}] Found 0 Backup selections")
            return resources

        # Phase 2: Fetch selection details in parallel
        logger.debug(f"[{region}] Fetching details for {len(selection_tasks)} backup selections in parallel...")
        max_workers = min(10, len(selection_tasks))

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_get_backup_selection_details, backup, plan_info, sel_info): (plan_info, sel_info)
                for plan_info, sel_info in selection_tasks
            }

            for future in as_completed(futures):
                plan_info, sel_info = futures[future]
                try:
                    details = future.result()
                    if details:
                        resource = CloudResource(
                            provider="aws",
                            account_id=account_id,
                            region=region,
                            resource_type="aws:backup:selection",
                            service_family="Backup",
                            resource_id=details['selection_id'],
                            name=details['selection_name'],
                            tags={},
                            size_gb=0.0,
                            parent_resource_id=details['plan_arn'],
                            metadata={
                                'backup_plan_id': details['plan_id'],
                                'backup_plan_name': details['plan_name'],
                                'selection_id': details['selection_id'],
                                'iam_role_arn': details['iam_role_arn'],
                                'resources': details['resources'],
                                'not_resources': details['not_resources'],
                                'list_of_tags': details['list_of_tags'],
                                'conditions': details['conditions'],
                                'creation_date': details['creation_date']
                            }
                        )
                        resources.append(resource)
                except Exception as e:
                    check_and_raise_auth_error(e, f"get selection details", "aws")
                    logger.warning(f"[{region}] Failed to get selection {sel_info.get('SelectionId', '')} details: {e}")

        logger.info(f"[{region}] Found {len(resources)} Backup selections")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Backup selections", "aws")
        logger.error(f"[{region}] Failed to collect Backup selections: {e}")

    return resources


def collect_backup_protected_resources(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect AWS Backup protected resources (resources with at least one recovery point)."""
    resources = []
    try:
        backup = session.client('backup', region_name=region)
        paginator = backup.get_paginator('list_protected_resources')

        for page in paginator.paginate():
            for protected in page.get('Results', []):
                resource_arn = protected.get('ResourceArn', '')
                resource_type = protected.get('ResourceType', '')  # e.g., EC2, EBS, RDS, etc.

                # Extract resource name from ARN
                resource_name = resource_arn.split('/')[-1] if '/' in resource_arn else resource_arn.split(':')[-1]

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:backup:protected-resource",
                    service_family="Backup",
                    resource_id=resource_arn,
                    name=resource_name,
                    tags={},
                    size_gb=0.0,
                    parent_resource_id=resource_arn,  # The actual protected resource
                    metadata={
                        'resource_type': resource_type,  # EC2, EBS, RDS, DynamoDB, EFS, etc.
                        'resource_arn': resource_arn,
                        'last_backup_time': str(protected.get('LastBackupTime', '')) if protected.get('LastBackupTime') else None
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} Backup protected resources")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Backup protected resources", "aws")
        logger.error(f"[{region}] Failed to collect Backup protected resources: {e}")

    return resources


def collect_backup_region_settings(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect AWS Backup region settings (resource type opt-in preferences).

    This is critical for understanding why resources might not be backed up even
    when they're in a backup selection - the resource type must be opted-in.

    Note: These settings are actually account-level (same across all regions).
    Collected once per account in collect_account() and marked as 'global' region.
    """
    resources = []
    try:
        backup = session.client('backup', region_name=region)

        # Get region settings - which resource types are opted-in for backup
        region_settings = backup.describe_region_settings()
        resource_type_opt_in = region_settings.get('ResourceTypeOptInPreference', {})
        resource_type_management = region_settings.get('ResourceTypeManagementPreference', {})

        # Create a single resource representing these settings
        resource = CloudResource(
            provider="aws",
            account_id=account_id,
            region=region,
            resource_type="aws:backup:region-settings",
            service_family="Backup",
            resource_id=f"arn:aws:backup:{region}:{account_id}:region-settings",
            name=f"backup-region-settings-{region}",
            tags={},
            size_gb=0.0,
            metadata={
                'resource_type_opt_in': resource_type_opt_in,
                'resource_type_management': resource_type_management,
                # Summarize which types are enabled/disabled
                'opted_in_types': [k for k, v in resource_type_opt_in.items() if v is True],
                'opted_out_types': [k for k, v in resource_type_opt_in.items() if v is False]
            }
        )
        resources.append(resource)

        # Log which resource types are opted out (potential issue)
        opted_out = [k for k, v in resource_type_opt_in.items() if v is False]
        if opted_out:
            logger.warning(f"[{region}] Resource types OPTED OUT from backup: {', '.join(opted_out)}")

        logger.info(f"[{region}] Collected Backup region settings")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Backup region settings", "aws")
        logger.error(f"[{region}] Failed to collect Backup region settings: {e}")

    return resources


# =============================================================================
# Redshift Collector
# =============================================================================

def collect_redshift_clusters(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect Amazon Redshift clusters."""
    resources = []
    try:
        redshift = session.client('redshift', region_name=region)
        paginator = redshift.get_paginator('describe_clusters')

        for page in paginator.paginate():
            for cluster in page.get('Clusters', []):
                cluster_id = cluster.get('ClusterIdentifier', '')

                # Calculate total storage from number of nodes * node storage
                num_nodes = cluster.get('NumberOfNodes', 1)
                node_type = cluster.get('NodeType', '')

                # Redshift node storage estimates (GB per node)
                node_storage_map = {
                    'dc2.large': 160, 'dc2.8xlarge': 2560,
                    'ra3.xlplus': 32000, 'ra3.4xlarge': 128000, 'ra3.16xlarge': 128000,
                    'ds2.xlarge': 2000, 'ds2.8xlarge': 16000,
                }
                storage_per_node = node_storage_map.get(node_type, 0)
                total_storage_gb = num_nodes * storage_per_node

                tags = {t['Key']: t['Value'] for t in cluster.get('Tags', [])}

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:redshift:cluster",
                    service_family="Redshift",
                    resource_id=f"arn:aws:redshift:{region}:{account_id}:cluster:{cluster_id}",
                    name=cluster_id,
                    tags=tags,
                    size_gb=float(total_storage_gb),
                    metadata={
                        'node_type': node_type,
                        'number_of_nodes': num_nodes,
                        'cluster_status': cluster.get('ClusterStatus'),
                        'db_name': cluster.get('DBName'),
                        'encrypted': cluster.get('Encrypted', False),
                        'total_storage_capacity_gb': total_storage_gb,
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} Redshift clusters")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Redshift clusters", "aws")
        logger.error(f"[{region}] Failed to collect Redshift clusters: {e}")

    return resources


# =============================================================================
# DocumentDB Collector
# =============================================================================

def collect_documentdb_clusters(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect Amazon DocumentDB (MongoDB-compatible) clusters."""
    resources = []
    try:
        docdb = session.client('docdb', region_name=region)
        paginator = docdb.get_paginator('describe_db_clusters')

        for page in paginator.paginate(Filters=[{'Name': 'engine', 'Values': ['docdb']}]):
            for cluster in page.get('DBClusters', []):
                cluster_id = cluster.get('DBClusterIdentifier', '')

                # Get storage used if available
                storage_gb = float(cluster.get('AllocatedStorage', 0))

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:docdb:cluster",
                    service_family="DocumentDB",
                    resource_id=cluster.get('DBClusterArn', ''),
                    name=cluster_id,
                    tags={},
                    size_gb=storage_gb,
                    metadata={
                        'status': cluster.get('Status'),
                        'engine': cluster.get('Engine'),
                        'engine_version': cluster.get('EngineVersion'),
                        'db_cluster_members': len(cluster.get('DBClusterMembers', [])),
                        'storage_encrypted': cluster.get('StorageEncrypted', False),
                        'backup_retention_period': cluster.get('BackupRetentionPeriod'),
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} DocumentDB clusters")
    except Exception as e:
        check_and_raise_auth_error(e, "collect DocumentDB clusters", "aws")
        logger.error(f"[{region}] Failed to collect DocumentDB clusters: {e}")

    return resources


# =============================================================================
# Neptune Collector
# =============================================================================

def collect_neptune_clusters(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect Amazon Neptune (graph database) clusters."""
    resources = []
    try:
        neptune = session.client('neptune', region_name=region)
        paginator = neptune.get_paginator('describe_db_clusters')

        for page in paginator.paginate(Filters=[{'Name': 'engine', 'Values': ['neptune']}]):
            for cluster in page.get('DBClusters', []):
                cluster_id = cluster.get('DBClusterIdentifier', '')

                # Neptune storage is auto-scaling, allocated storage is estimate
                storage_gb = float(cluster.get('AllocatedStorage', 0))

                resource = CloudResource(
                    provider="aws",
                    account_id=account_id,
                    region=region,
                    resource_type="aws:neptune:cluster",
                    service_family="Neptune",
                    resource_id=cluster.get('DBClusterArn', ''),
                    name=cluster_id,
                    tags={},
                    size_gb=storage_gb,
                    metadata={
                        'status': cluster.get('Status'),
                        'engine': cluster.get('Engine'),
                        'engine_version': cluster.get('EngineVersion'),
                        'db_cluster_members': len(cluster.get('DBClusterMembers', [])),
                        'storage_encrypted': cluster.get('StorageEncrypted', False),
                        'backup_retention_period': cluster.get('BackupRetentionPeriod'),
                        'serverless': cluster.get('ServerlessV2ScalingConfiguration') is not None,
                    }
                )
                resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} Neptune clusters")
    except Exception as e:
        check_and_raise_auth_error(e, "collect Neptune clusters", "aws")
        logger.error(f"[{region}] Failed to collect Neptune clusters: {e}")

    return resources


# =============================================================================
# OpenSearch Service Collector
# =============================================================================

def collect_opensearch_domains(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect Amazon OpenSearch Service domains."""
    resources = []
    try:
        opensearch = session.client('opensearch', region_name=region)

        # List all domain names first
        domain_list = opensearch.list_domain_names().get('DomainNames', [])
        domain_names = [d['DomainName'] for d in domain_list]

        if domain_names:
            # Describe domains in batches (max 5 per call)
            for i in range(0, len(domain_names), 5):
                batch = domain_names[i:i+5]
                domains_info = opensearch.describe_domains(DomainNames=batch)

                for domain in domains_info.get('DomainStatusList', []):
                    domain_name = domain.get('DomainName', '')

                    # Calculate storage from EBS config
                    ebs_options = domain.get('EBSOptions', {})
                    cluster_config = domain.get('ClusterConfig', {})

                    volume_size = ebs_options.get('VolumeSize', 0)
                    instance_count = cluster_config.get('InstanceCount', 1)
                    total_storage_gb = volume_size * instance_count

                    # Add warm storage if configured
                    if cluster_config.get('WarmEnabled'):
                        warm_count = cluster_config.get('WarmCount', 0)
                        # Warm nodes have fixed storage based on type
                        warm_storage = warm_count * 500  # Approximate
                        total_storage_gb += warm_storage

                    tags = domain.get('Tags', {})
                    if isinstance(tags, list):
                        tags = {t['Key']: t['Value'] for t in tags}

                    resource = CloudResource(
                        provider="aws",
                        account_id=account_id,
                        region=region,
                        resource_type="aws:opensearch:domain",
                        service_family="OpenSearch",
                        resource_id=domain.get('ARN', ''),
                        name=domain_name,
                        tags=tags,
                        size_gb=float(total_storage_gb),
                        metadata={
                            'engine_version': domain.get('EngineVersion'),
                            'instance_type': cluster_config.get('InstanceType'),
                            'instance_count': instance_count,
                            'dedicated_master_enabled': cluster_config.get('DedicatedMasterEnabled', False),
                            'zone_awareness_enabled': cluster_config.get('ZoneAwarenessEnabled', False),
                            'warm_enabled': cluster_config.get('WarmEnabled', False),
                            'ebs_enabled': ebs_options.get('EBSEnabled', False),
                            'volume_type': ebs_options.get('VolumeType'),
                            'processing': domain.get('Processing', False),
                        }
                    )
                    resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} OpenSearch domains")
    except Exception as e:
        check_and_raise_auth_error(e, "collect OpenSearch domains", "aws")
        logger.error(f"[{region}] Failed to collect OpenSearch domains: {e}")

    return resources


# =============================================================================
# MemoryDB for Redis Collector
# =============================================================================

def collect_memorydb_clusters(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect Amazon MemoryDB for Redis clusters."""
    resources = []
    try:
        memorydb = session.client('memorydb', region_name=region)

        # List all clusters
        clusters_response = memorydb.describe_clusters()

        for cluster in clusters_response.get('Clusters', []):
            cluster_name = cluster.get('Name', '')

            # Calculate data size from shards and node type
            num_shards = cluster.get('NumberOfShards', 1)
            node_type = cluster.get('NodeType', '')

            # MemoryDB node memory sizes (GB) - data size estimate
            node_memory_map = {
                'db.t4g.small': 1.37, 'db.t4g.medium': 3.09,
                'db.r6g.large': 13.07, 'db.r6g.xlarge': 26.32,
                'db.r6g.2xlarge': 52.82, 'db.r6g.4xlarge': 105.81,
                'db.r6g.8xlarge': 209.55, 'db.r6g.12xlarge': 317.77,
                'db.r6g.16xlarge': 419.09,
                'db.r7g.large': 13.07, 'db.r7g.xlarge': 26.32,
                'db.r7g.2xlarge': 52.82, 'db.r7g.4xlarge': 105.81,
            }
            memory_per_node = node_memory_map.get(node_type, 0)
            replicas = cluster.get('NumReplicasPerShard', 0) + 1  # +1 for primary
            total_memory_gb = num_shards * replicas * memory_per_node

            resource = CloudResource(
                provider="aws",
                account_id=account_id,
                region=region,
                resource_type="aws:memorydb:cluster",
                service_family="MemoryDB",
                resource_id=cluster.get('ARN', ''),
                name=cluster_name,
                tags={},
                size_gb=float(total_memory_gb),
                metadata={
                    'status': cluster.get('Status'),
                    'node_type': node_type,
                    'number_of_shards': num_shards,
                    'num_replicas_per_shard': cluster.get('NumReplicasPerShard', 0),
                    'engine_version': cluster.get('EngineVersion'),
                    'tls_enabled': cluster.get('TLSEnabled', False),
                    'snapshot_retention_limit': cluster.get('SnapshotRetentionLimit', 0),
                    'data_tiering': cluster.get('DataTiering', 'false'),
                }
            )
            resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} MemoryDB clusters")
    except Exception as e:
        check_and_raise_auth_error(e, "collect MemoryDB clusters", "aws")
        logger.error(f"[{region}] Failed to collect MemoryDB clusters: {e}")

    return resources


# =============================================================================
# Timestream Collector
# =============================================================================

def collect_timestream_databases(session: boto3.Session, region: str, account_id: str) -> List[CloudResource]:
    """Collect Amazon Timestream databases and tables."""
    resources = []
    try:
        timestream = session.client('timestream-write', region_name=region)

        # List databases
        paginator = timestream.get_paginator('list_databases')

        for page in paginator.paginate():
            for db in page.get('Databases', []):
                db_name = db.get('DatabaseName', '')

                # List tables in database
                table_paginator = timestream.get_paginator('list_tables')
                for table_page in table_paginator.paginate(DatabaseName=db_name):
                    for table in table_page.get('Tables', []):
                        table_name = table.get('TableName', '')

                        # Get table details for metrics
                        try:
                            table_details = timestream.describe_table(
                                DatabaseName=db_name,
                                TableName=table_name
                            ).get('Table', {})

                            # Storage metrics (if available)
                            table_details.get('MagneticStoreWriteProperties', {}).get('MagneticStoreRejectedDataLocation', {})
                            retention_memory = table_details.get('RetentionProperties', {}).get('MemoryStoreRetentionPeriodInHours', 0)
                            retention_magnetic = table_details.get('RetentionProperties', {}).get('MagneticStoreRetentionPeriodInDays', 0)
                        except Exception:
                            retention_memory = 0
                            retention_magnetic = 0

                        resource = CloudResource(
                            provider="aws",
                            account_id=account_id,
                            region=region,
                            resource_type="aws:timestream:table",
                            service_family="Timestream",
                            resource_id=table.get('Arn', ''),
                            name=f"{db_name}/{table_name}",
                            tags={},
                            size_gb=0.0,  # Timestream doesn't expose storage size directly
                            metadata={
                                'database_name': db_name,
                                'table_name': table_name,
                                'table_status': table.get('TableStatus'),
                                'memory_retention_hours': retention_memory,
                                'magnetic_retention_days': retention_magnetic,
                            }
                        )
                        resources.append(resource)

        logger.info(f"[{region}] Found {len(resources)} Timestream tables")
    except Exception as e:
        # Timestream is not available in all regions
        if 'not available' in str(e).lower() or 'not supported' in str(e).lower():
            logger.debug(f"[{region}] Timestream not available in this region")
        else:
            logger.error(f"[{region}] Failed to collect Timestream: {e}")

    return resources


# =============================================================================
# Main Collection Logic
# =============================================================================

def collect_region(session: boto3.Session, region: str, account_id: str, tracker: Optional[ProgressTracker] = None) -> List[CloudResource]:
    """Collect all resources in a region."""
    resources = []

    logger.info(f"Collecting resources in {region}...")

    def collect_and_track(name: str, collect_fn, *args):
        """Helper to collect resources and update tracker."""
        if tracker:
            tracker.update_task(f"Collecting {name}...")
        result = collect_fn(*args)
        if tracker and result:
            tracker.add_resources(len(result), sum(r.size_gb for r in result))
        return result

    # EC2
    resources.extend(collect_and_track("EC2 instances", collect_ec2_instances, session, region, account_id))
    resources.extend(collect_and_track("EBS volumes", collect_ebs_volumes, session, region, account_id))
    resources.extend(collect_and_track("EBS snapshots", collect_ebs_snapshots, session, region, account_id))

    # RDS
    resources.extend(collect_and_track("RDS instances", collect_rds_instances, session, region, account_id))
    resources.extend(collect_and_track("RDS clusters", collect_rds_clusters, session, region, account_id))
    resources.extend(collect_and_track("RDS snapshots", collect_rds_snapshots, session, region, account_id))
    resources.extend(collect_and_track("RDS cluster snapshots", collect_rds_cluster_snapshots, session, region, account_id))

    # Storage
    resources.extend(collect_and_track("EFS filesystems", collect_efs_filesystems, session, region, account_id))
    resources.extend(collect_and_track("FSx filesystems", collect_fsx_filesystems, session, region, account_id))

    # Containers & Compute
    resources.extend(collect_and_track("EKS clusters", collect_eks_clusters, session, region, account_id))
    resources.extend(collect_and_track("EKS node groups", collect_eks_nodegroups, session, region, account_id))
    resources.extend(collect_and_track("Lambda functions", collect_lambda_functions, session, region, account_id))

    # Databases
    resources.extend(collect_and_track("DynamoDB tables", collect_dynamodb_tables, session, region, account_id))
    resources.extend(collect_and_track("ElastiCache clusters", collect_elasticache_clusters, session, region, account_id))
    resources.extend(collect_and_track("Redshift clusters", collect_redshift_clusters, session, region, account_id))
    resources.extend(collect_and_track("DocumentDB clusters", collect_documentdb_clusters, session, region, account_id))
    resources.extend(collect_and_track("Neptune clusters", collect_neptune_clusters, session, region, account_id))
    resources.extend(collect_and_track("OpenSearch domains", collect_opensearch_domains, session, region, account_id))
    resources.extend(collect_and_track("MemoryDB clusters", collect_memorydb_clusters, session, region, account_id))
    resources.extend(collect_and_track("Timestream tables", collect_timestream_databases, session, region, account_id))

    # AWS Backup
    resources.extend(collect_and_track("Backup vaults", collect_backup_vaults, session, region, account_id))
    resources.extend(collect_and_track("Backup recovery points", collect_backup_recovery_points, session, region, account_id))
    resources.extend(collect_and_track("Backup plans", collect_backup_plans, session, region, account_id))
    resources.extend(collect_and_track("Backup selections", collect_backup_selections, session, region, account_id))
    resources.extend(collect_and_track("Backup protected resources", collect_backup_protected_resources, session, region, account_id))
    # Note: Backup region settings collected once per account in collect_account(), not per region

    return resources


# =============================================================================
# Change Rate Collection
# =============================================================================

def collect_resource_change_rates(
    session: boto3.Session,
    resources: List[CloudResource],
    days: int = 7,
    parallel_regions: int = 1
) -> Dict[str, Any]:
    """
    Collect change rate metrics from CloudWatch for the collected resources.

    Args:
        session: boto3 session
        resources: List of CloudResource objects collected from the account
        days: Number of days to sample for metrics
        parallel_regions: Number of regions to process in parallel

    Returns:
        Dict with change rate summaries by service family
    """
    change_rates: List[Dict[str, Any]] = []

    # Group resources by region for efficient CloudWatch access
    resources_by_region: Dict[str, List[CloudResource]] = {}
    for r in resources:
        if r.region and r.region != 'global':
            resources_by_region.setdefault(r.region, []).append(r)

    def collect_region_change_rates(region: str, region_resources: List[CloudResource]) -> List[Dict[str, Any]]:
        """Collect change rates for all resources in a region."""
        region_rates = []
        try:
            cloudwatch = get_aws_cloudwatch_client(session, region)
        except Exception as e:
            logger.warning(f"Could not create CloudWatch client for {region}: {e}")
            return region_rates

        for resource in region_resources:
            try:
                rate_entry = _collect_single_resource_change_rate(
                    cloudwatch, resource, days
                )
                if rate_entry:
                    region_rates.append(rate_entry)
            except Exception as e:
                logger.debug(f"Error collecting change rate for {resource.resource_id}: {e}")
                continue

        logger.info(f"[{region}] Collected change rates for {len(region_rates)} resources")
        return region_rates

    # Process regions (parallel or serial)
    if parallel_regions > 1 and len(resources_by_region) > 1:
        logger.info(f"Collecting change rates from {len(resources_by_region)} regions in parallel (workers={parallel_regions})")
        with ThreadPoolExecutor(max_workers=parallel_regions) as executor:
            futures = {
                executor.submit(collect_region_change_rates, region, region_resources): region
                for region, region_resources in resources_by_region.items()
            }
            for future in as_completed(futures):
                region = futures[future]
                try:
                    region_rates = future.result()
                    change_rates.extend(region_rates)
                except Exception as e:
                    logger.error(f"[{region}] Failed to collect change rates: {e}")
    else:
        for region, region_resources in resources_by_region.items():
            region_rates = collect_region_change_rates(region, region_resources)
            change_rates.extend(region_rates)

    # Also collect for global resources like S3
    try:
        # Use us-east-1 for S3 CloudWatch metrics
        s3_cloudwatch = get_aws_cloudwatch_client(session, 'us-east-1')
        for resource in resources:
            if resource.service_family == 'S3' and resource.size_gb > 0:
                try:
                    bucket_name = resource.metadata.get('bucket_name', resource.name)
                    if bucket_name:
                        data_change = get_s3_change_rate(
                            s3_cloudwatch, bucket_name, resource.size_gb, days
                        )
                        if data_change:
                            change_rates.append({
                                'provider': 'aws',
                                'service_family': 'S3',
                                'size_gb': resource.size_gb,
                                'data_change': data_change
                            })
                except Exception as e:
                    logger.debug(f"Error collecting S3 change rate for {resource.name}: {e}")
    except Exception as e:
        logger.debug(f"Error creating S3 CloudWatch client: {e}")

    # Aggregate change rates by service family
    summaries = aggregate_change_rates(change_rates)
    return format_change_rate_output(summaries)


def _collect_single_resource_change_rate(
    cloudwatch,
    resource: CloudResource,
    days: int
) -> Optional[Dict[str, Any]]:
    """
    Collect change rate for a single resource based on its type.
    """
    service_family = resource.service_family

    if service_family == 'EBS':
        # EBS volumes
        volume_id = resource.metadata.get('volume_id') or resource.resource_id.split('/')[-1]
        if volume_id.startswith('vol-'):
            data_change = get_ebs_volume_change_rate(
                cloudwatch, volume_id, resource.size_gb, days
            )
            if data_change:
                return {
                    'provider': 'aws',
                    'service_family': 'EBS',
                    'size_gb': resource.size_gb,
                    'data_change': data_change
                }

    elif service_family in ('RDS', 'Aurora'):
        # RDS instances and Aurora
        db_id = resource.metadata.get('db_instance_id') or resource.metadata.get('db_cluster_id')
        engine = resource.metadata.get('engine', '').lower()

        if db_id:
            data_change = get_rds_write_iops_change_rate(
                cloudwatch, db_id, resource.size_gb, days
            )
            tlog_metrics = get_rds_transaction_log_rate(
                cloudwatch, db_id, engine, days
            )

            if data_change or tlog_metrics:
                return {
                    'provider': 'aws',
                    'service_family': service_family,
                    'size_gb': resource.size_gb,
                    'data_change': data_change,
                    'transaction_logs': tlog_metrics
                }

    elif service_family in ('DocumentDB', 'Neptune', 'OpenSearch', 'Redshift'):
        # Other database services - use WriteIOPS equivalent metrics
        # For these services, we use size and estimate based on typical patterns
        # (CloudWatch metrics vary by service)
        pass

    elif service_family == 'EFS':
        # EFS filesystems
        fs_id = resource.metadata.get('filesystem_id') or resource.resource_id.split('/')[-1]
        if fs_id.startswith('fs-'):
            data_change = get_efs_change_rate(
                cloudwatch, fs_id, resource.size_gb, days
            )
            if data_change:
                return {
                    'provider': 'aws',
                    'service_family': 'EFS',
                    'size_gb': resource.size_gb,
                    'data_change': data_change
                }

    elif service_family == 'FSx':
        # FSx filesystems (Lustre, Windows, ONTAP, OpenZFS)
        fs_id = resource.metadata.get('filesystem_id') or resource.resource_id.split('/')[-1]
        if fs_id.startswith('fs-'):
            data_change = get_fsx_change_rate(
                cloudwatch, fs_id, resource.size_gb, days
            )
            if data_change:
                return {
                    'provider': 'aws',
                    'service_family': 'FSx',
                    'size_gb': resource.size_gb,
                    'data_change': data_change
                }

    return None


def main():
    parser = argparse.ArgumentParser(
        description='CCA CloudShell - AWS Resource Collector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single account (current credentials)
  python3 aws_collect.py

  # Specific regions
  python3 aws_collect.py --regions us-east-1,us-west-2

  # Assume role in another account
  python3 aws_collect.py --role-arn arn:aws:iam::123456789012:role/CCARole

  # Multiple accounts via role assumption
  python3 aws_collect.py --role-arns arn:aws:iam::111:role/CCA,arn:aws:iam::222:role/CCA

  # Auto-discover all accounts in AWS Organization
  python3 aws_collect.py --org-role CCARole

  # Organization discovery with external ID
  python3 aws_collect.py --org-role CCARole --external-id MySecretId

Large Environment Examples:
  # Auto-batch 100+ accounts into groups of 25, with checkpoint
  python3 aws_collect.py --org-role CCARole --batch-size 25 -o ./collection/

  # Parallel region collection (4x-8x faster)
  python3 aws_collect.py --org-role CCARole --parallel-regions 8

  # Parallel regions + change rate collection
  python3 aws_collect.py --org-role CCARole --parallel-regions 8 --include-change-rate

  # Resume after credential timeout (uses checkpoint.json)
  python3 aws_collect.py --org-role CCARole --resume ./collection/checkpoint.json

  # Retry only failed accounts
  python3 aws_collect.py --org-role CCARole --accounts 111111111111,222222222222

  # Load account list from file
  python3 aws_collect.py --org-role CCARole --account-file accounts.txt -o ./output/

  # Auto-refresh SSO credentials between batches (recommended for SSO users)
  python3 aws_collect.py --org-role CCARole --batch-size 20 --sso-refresh

  # Interactive mode: pause and prompt between batches
  python3 aws_collect.py --org-role CCARole --batch-size 20 --interactive

  # Timed pause between batches (manual refresh)
  python3 aws_collect.py --org-role CCARole --batch-size 20 --pause-between-batches 60
"""
    )

    # Basic options
    parser.add_argument('--config', '-c', help='Path to YAML config file')
    parser.add_argument('--generate-config', action='store_true',
                        help='Generate a sample config file and exit')
    parser.add_argument('--profile', help='AWS profile name (optional in CloudShell)')
    parser.add_argument('--regions', help='Comma-separated list of regions (default: all enabled)')
    parser.add_argument('--output', '-o', help='Output directory or S3 path', default='.')
    parser.add_argument('--log-level', help='Logging level', default='INFO')
    parser.add_argument(
        '--org-name',
        help='Organization name to include in output (used for report filenames)'
    )

    # Data collection options
    parser.add_argument(
        '--include-storage-sizes',
        action='store_true',
        help='Query CloudWatch for S3 bucket sizes (slower but accurate)'
    )
    parser.add_argument(
        '--include-change-rate',
        action='store_true',
        help='Collect data change rates from CloudWatch (for sizing tool DCR overrides)'
    )
    parser.add_argument(
        '--skip-pvc',
        action='store_true',
        help='Skip PVC collection from EKS clusters (PVCs are collected by default when clusters are found)'
    )
    parser.add_argument(
        '--change-rate-days',
        type=int,
        default=7,
        help='Number of days to sample for change rate metrics (default: 7)'
    )
    parser.add_argument(
        '--parallel-regions',
        type=int,
        default=None,
        metavar='N',
        help='Number of regions to collect in parallel. Default: 4 (or 1 in CloudShell). '
             'Higher values (4-8) significantly speed up collection but use more memory.'
    )

    # Multi-account options
    parser.add_argument(
        '--role-arn',
        help='Single role ARN to assume for collection (e.g., arn:aws:iam::123456789012:role/CCARole)'
    )
    parser.add_argument(
        '--role-arns',
        help='Comma-separated list of role ARNs to assume for multi-account collection'
    )
    parser.add_argument(
        '--org-role',
        help='Role name to assume in each Organization account (e.g., CCARole). '
             'Discovers all accounts via Organizations API and assumes arn:aws:iam::<account>:role/<org-role>'
    )
    parser.add_argument(
        '--external-id',
        default=os.environ.get('CCA_EXTERNAL_ID'),
        help='External ID for role assumption (applies to all role assumptions). '
             'Can also be set via CCA_EXTERNAL_ID env var to avoid shell history exposure.'
    )
    parser.add_argument(
        '--skip-accounts',
        help='Comma-separated list of account IDs to skip (useful with --org-role)'
    )

    # Batching options (for large environments)
    parser.add_argument(
        '--accounts',
        help='Comma-separated list of account IDs to include (only collect these accounts)'
    )
    parser.add_argument(
        '--account-file',
        help='File containing account IDs to collect (one per line, supports # comments)'
    )
    parser.add_argument(
        '--batch-size',
        type=int,
        help='Auto-batch: collect N accounts per batch, output to numbered subfolders. '
             'Saves checkpoint for resume capability.'
    )
    parser.add_argument(
        '--resume',
        metavar='CHECKPOINT',
        help='Resume collection from checkpoint file (created by --batch-size)'
    )
    parser.add_argument(
        '--checkpoint',
        help='Path for checkpoint file (default: <output>/checkpoint.json)'
    )
    parser.add_argument(
        '--pause-between-batches',
        type=int,
        default=0,
        metavar='SECONDS',
        help='Pause N seconds between batches (allows manual credential refresh)'
    )
    parser.add_argument(
        '--sso-refresh',
        action='store_true',
        help='Run "aws sso login" between batches to refresh SSO credentials'
    )
    parser.add_argument(
        '--interactive',
        action='store_true',
        help='Prompt and wait for user input between batches (for manual credential refresh)'
    )
    parser.add_argument(
        '--parallel-accounts',
        type=int,
        default=None,
        metavar='N',
        help='Number of accounts to collect in parallel using subprocess workers. '
             'Auto-tunes to 4 for 50+ accounts, 8 for 100+ accounts. '
             'Set to 1 to disable auto-parallelization.'
    )
    parser.add_argument(
        '--no-auto-parallel',
        action='store_true',
        help='Disable automatic parallel account collection for large environments'
    )
    parser.add_argument(
        '--include-resource-ids',
        action='store_true',
        help='Include full resource IDs/ARNs in output (default: redact for privacy)'
    )

    args = parser.parse_args()

    # Smart default for parallel_regions based on environment
    if args.parallel_regions is None:
        if is_running_in_cloudshell():
            args.parallel_regions = 1  # CloudShell has memory constraints
        else:
            args.parallel_regions = 4  # Default to parallel on EC2/local

    # Handle --generate-config
    if args.generate_config:
        print(generate_sample_config())
        sys.exit(0)

    # Setup logging - write to file if output is local directory
    log_dir = args.output if not args.output.startswith(('s3://', 'gs://', 'https://')) else None
    setup_logging(args.log_level, output_dir=log_dir)

    # Load configuration from file/env/args
    try:
        config = load_config(args)
        if config:
            logger.debug(f"Loaded configuration: {list(config.keys())}")
    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.warning(f"Could not load config file: {e}")

    # Ensure include_storage_sizes has a default
    if not hasattr(args, 'include_storage_sizes'):
        args.include_storage_sizes = False

    # Create base session
    try:
        base_session = get_session(args.profile)
    except Exception as e:
        logger.error(f"Failed to create AWS session: {e}")
        logger.error("Check your AWS credentials are configured correctly.")
        sys.exit(1)

    try:
        base_account_id = get_account_id(base_session)
    except Exception as e:
        logger.error(f"Failed to get AWS account ID: {e}")
        logger.error("Check your credentials have sts:GetCallerIdentity permission.")
        sys.exit(1)

    # Parse regions
    regions = None
    if args.regions:
        regions = [r.strip() for r in args.regions.split(',')]

    # Parse account filters
    skip_accounts = set()
    if args.skip_accounts:
        skip_list = [a.strip() for a in args.skip_accounts.split(',')]
        validate_account_ids(skip_list, "--skip-accounts")
        skip_accounts = set(skip_list)

    include_accounts = None  # None means "all accounts"
    if args.accounts:
        include_list = [a.strip() for a in args.accounts.split(',')]
        validate_account_ids(include_list, "--accounts")
        include_accounts = set(include_list)
    elif args.account_file:
        include_accounts = set(load_account_list(args.account_file))
        logger.info(f"Loaded {len(include_accounts)} accounts from {args.account_file}")

    # Check for resume mode
    checkpoint_file = args.checkpoint or os.path.join(args.output.rstrip('/'), 'checkpoint.json')
    checkpoint: Dict[str, Any] = {'completed_accounts': [], 'failed_accounts': []}
    is_parallel_resume = False

    if args.resume:
        checkpoint_file = args.resume
        checkpoint = load_checkpoint(checkpoint_file)
        
        # Detect if this is a parallel checkpoint (has 'workers' key)
        if 'workers' in checkpoint:
            is_parallel_resume = True
            # For parallel resume, extract output directory from checkpoint path
            if args.output == '.':
                args.output = os.path.dirname(checkpoint_file)
                logger.info(f"Auto-detected output directory from checkpoint: {args.output}")
        
        already_done = set(checkpoint.get('completed_accounts', []))
        logger.info(f"Resuming: {len(already_done)} accounts already completed")
        skip_accounts = skip_accounts | already_done

    # Build list of accounts to collect
    accounts_to_collect: List[Dict[str, Any]] = []

    if args.org_role:
        # Organizations discovery mode
        logger.info("Discovering accounts via AWS Organizations...")
        org_accounts = discover_org_accounts(base_session)

        if not org_accounts:
            logger.error("No accounts discovered. Check Organizations permissions or use --role-arns instead.")
            sys.exit(1)

        for account in org_accounts:
            acc_id = account['id']

            # Apply include filter
            if include_accounts is not None and acc_id not in include_accounts:
                continue

            # Apply skip filter
            if acc_id in skip_accounts:
                logger.info(f"Skipping account {acc_id} ({account['name']})")
                continue

            accounts_to_collect.append(account)

    elif args.role_arns:
        # Explicit multi-account role assumption - extract account IDs from ARNs
        role_arns = [r.strip() for r in args.role_arns.split(',')]
        for role_arn in role_arns:
            # Extract account ID from ARN format arn:aws:iam::ACCOUNT_ID:role/...
            try:
                acc_id = role_arn.split(':')[4]
                if include_accounts is not None and acc_id not in include_accounts:
                    continue
                if acc_id in skip_accounts:
                    continue
                accounts_to_collect.append({'id': acc_id, 'name': '', 'role_arn': role_arn})
            except (IndexError, ValueError):
                logger.warning(f"Could not parse account ID from role ARN: {role_arn}")
                accounts_to_collect.append({'id': '', 'name': '', 'role_arn': role_arn})

    elif args.role_arn:
        # Single role assumption
        acc_id = args.role_arn.split(':')[4] if ':' in args.role_arn else ''
        accounts_to_collect.append({'id': acc_id, 'name': '', 'role_arn': args.role_arn})

    else:
        # Single account mode (current credentials)
        accounts_to_collect.append({'id': base_account_id, 'name': '', 'is_base': True})

    if not accounts_to_collect:
        logger.error("No accounts to collect from (all filtered out)")
        sys.exit(1)

    # Auto-tune parallel accounts based on environment size
    num_accounts = len(accounts_to_collect)
    num_regions = len(regions) if regions else 20  # Assume ~20 regions if not specified
    total_region_calls = num_accounts * num_regions

    # Estimated time: ~1.25 min per account with current optimizations
    MINUTES_PER_ACCOUNT = 1.25
    estimated_minutes = num_accounts * MINUTES_PER_ACCOUNT
    estimated_hours = estimated_minutes / 60

    # Auto-tune --parallel-accounts if not explicitly set
    if args.parallel_accounts is None and not args.no_auto_parallel and not is_running_in_cloudshell():
        # If resuming a parallel collection, restore the worker count from checkpoint
        if is_parallel_resume and checkpoint.get('num_workers'):
            args.parallel_accounts = checkpoint['num_workers']
            logger.info(f"Resuming parallel collection with {args.parallel_accounts} workers")
        elif num_accounts >= 100:
            args.parallel_accounts = 8
        elif num_accounts >= 50:
            args.parallel_accounts = 4
        else:
            args.parallel_accounts = 1
    elif args.parallel_accounts is None:
        args.parallel_accounts = 1

    # If parallel accounts > 1 and we have multiple accounts, spawn worker subprocesses
    if args.parallel_accounts > 1 and num_accounts > 1:
        parallel_hours = estimated_hours / args.parallel_accounts
        print("\n" + "=" * 70)
        print(f"PARALLEL COLLECTION: {num_accounts} accounts across {args.parallel_accounts} workers")
        print("=" * 70)
        print(f"  Sequential estimate: {estimated_hours:.1f} hours")
        print(f"  Parallel estimate:   ~{parallel_hours:.1f} hours ({args.parallel_accounts}x speedup)")
        
        # Suggest --sso-refresh for long-running collections if using SSO
        sso_expiry = get_sso_token_expiry()
        parallel_minutes = estimated_minutes / args.parallel_accounts
        if sso_expiry and parallel_minutes > 45 and not args.sso_refresh:
            now = datetime.now(timezone.utc)
            remaining_minutes = (sso_expiry - now).total_seconds() / 60
            print("")
            print(f"  TIP: SSO token expires in {remaining_minutes:.0f} min, runtime ~{parallel_minutes:.0f} min")
            print(f"       Consider adding --sso-refresh for automatic credential refresh")
        
        print("")
        print(f"  Spawning {args.parallel_accounts} parallel worker processes...")
        print("=" * 70 + "\n")

        # Run parallel collection and exit
        exit_code = run_parallel_account_collection(
            accounts_to_collect=accounts_to_collect,
            args=args,
            base_session=base_session,
            regions=regions,
            checkpoint=checkpoint,
            checkpoint_file=checkpoint_file
        )
        sys.exit(exit_code)
    elif num_accounts >= 50:
        # Large environment but running sequentially (CloudShell or --no-auto-parallel)
        print("\n" + "=" * 70)
        print(f"LARGE ENVIRONMENT: {num_accounts} accounts (sequential mode)")
        print("=" * 70)
        print(f"  Estimated runtime: {estimated_hours:.1f} hours ({estimated_minutes:.0f} minutes)")
        if is_running_in_cloudshell():
            print("")
            print("  CloudShell detected - parallel accounts disabled (memory constraints)")
            print("  Consider running from an EC2 instance for faster collection")
        elif args.no_auto_parallel:
            print("")
            print("  Auto-parallel disabled via --no-auto-parallel")
            print(f"  To enable: remove --no-auto-parallel (will use {8 if num_accounts >= 100 else 4} workers)")
        print("")
        print("  Tip: Use --batch-size for checkpointing/resume capability")
        print("=" * 70 + "\n")

    # Recommend maximum parallel collection for very large environments
    if args.parallel_regions < 8 and not is_running_in_cloudshell():
        if num_accounts >= 50 or total_region_calls >= 500:
            print("\n" + "=" * 70)
            print("TIP: Very large environment detected!")
            print(f"     {num_accounts} accounts × {num_regions} regions = {total_region_calls} region collections")
            print("")
            print("     Current: --parallel-regions {}".format(args.parallel_regions))
            print("     Consider increasing for faster collection:")
            print("       python3 aws_collect.py ... --parallel-regions 8")
            print("")
            print("     Estimated speedup: ~{:.0f}x faster".format(min(8 / args.parallel_regions, num_regions)))
            if args.include_change_rate:
                print("     (Change rate collection will also be parallelized)")
            print("=" * 70 + "\n")
    elif is_running_in_cloudshell() and (num_accounts >= 50 or total_region_calls >= 500):
        print("\n" + "=" * 70)
        print("WARNING: Very large environment detected in CloudShell!")
        print(f"         {num_accounts} accounts × {num_regions} regions = {total_region_calls} region collections")
        print("")
        print("         CloudShell has limited memory (1GB). For best results:")
        print("         1. Use --batch-size 10 to process fewer accounts at once")
        print("         2. Or run from an EC2 instance with --parallel-regions 8")
        print("=" * 70 + "\n")

    # Warn about CloudShell memory limits with parallel collection
    if is_running_in_cloudshell() and args.parallel_regions > 1:
        print("\n" + "=" * 70)
        print("NOTE: Running parallel collection in CloudShell")
        print(f"      --parallel-regions {args.parallel_regions}")
        print("")
        print("      CloudShell has a 1GB memory limit. If you encounter memory")
        print("      errors, try reducing --parallel-regions or use --batch-size.")
        print("=" * 70 + "\n")

    # Handle batching
    batches = [accounts_to_collect]  # Default: single batch with all accounts

    if args.batch_size and len(accounts_to_collect) > args.batch_size:
        batches = chunk_list(accounts_to_collect, args.batch_size)
        logger.info(f"Split {len(accounts_to_collect)} accounts into {len(batches)} batches of up to {args.batch_size}")

        # Initialize checkpoint for batch tracking
        checkpoint['total_accounts'] = len(accounts_to_collect)
        checkpoint['batch_size'] = args.batch_size
        checkpoint['total_batches'] = len(batches)
        checkpoint['started_at'] = checkpoint.get('started_at') or get_timestamp()

    # Collect from all batches
    all_collected_accounts: List[Dict[str, Any]] = []
    all_summaries = []
    output_base = args.output.rstrip('/')
    run_id = generate_run_id()  # Initialize here, may be overwritten per batch

    for batch_num, batch_accounts in enumerate(batches, 1):
        # Determine output path for this batch
        if len(batches) > 1:
            batch_output = f"{output_base}/batch{batch_num:02d}"
            os.makedirs(batch_output, exist_ok=True)
            print(f"\n{'='*60}")
            print(f"BATCH {batch_num}/{len(batches)}: {len(batch_accounts)} accounts")
            print(f"{'='*60}")
        else:
            batch_output = output_base

        # Build sessions for this batch
        account_sessions: List[tuple] = []

        for account in batch_accounts:
            acc_id = account['id']
            acc_name = account.get('name', '')

            if account.get('is_base'):
                # Use current credentials
                account_sessions.append((base_session, acc_id, acc_name))
            elif account.get('role_arn'):
                # Explicit role ARN provided
                try:
                    assumed_session = assume_role(base_session, account['role_arn'], args.external_id)
                    if not acc_id:
                        acc_id = get_account_id(assumed_session)
                    logger.info(f"Assumed role in account {acc_id}")
                    account_sessions.append((assumed_session, acc_id, acc_name))
                except Exception as e:
                    logger.warning(f"Failed to assume role {account['role_arn']}: {e}")
                    checkpoint['failed_accounts'].append(acc_id)
                    continue
            else:
                # Org discovery mode - construct role ARN
                if acc_id == base_account_id:
                    logger.info(f"Using current credentials for management account {acc_id} ({acc_name})")
                    account_sessions.append((base_session, acc_id, acc_name))
                else:
                    role_arn = f"arn:aws:iam::{acc_id}:role/{args.org_role}"
                    try:
                        assumed_session = assume_role(base_session, role_arn, args.external_id)
                        logger.info(f"Assumed role in account {acc_id} ({acc_name})")
                        account_sessions.append((assumed_session, acc_id, acc_name))
                    except Exception as e:
                        logger.warning(f"Failed to assume role in account {acc_id} ({acc_name}): {e}")
                        checkpoint['failed_accounts'].append(acc_id)
                        continue

        if not account_sessions:
            logger.warning(f"No valid sessions for batch {batch_num}, skipping")
            continue

        # Collect from all accounts in this batch
        batch_resources: List[CloudResource] = []
        batch_collected: List[Dict[str, Any]] = []

        total_regions = len(regions) if regions else len(get_enabled_regions(base_session))

        with ProgressTracker("AWS", total_regions=total_regions * len(account_sessions)) as tracker:
            for session, account_id, account_name in account_sessions:
                try:
                    # Update checkpoint: mark in progress
                    checkpoint['in_progress'] = account_id
                    if args.batch_size:
                        save_checkpoint(checkpoint_file, checkpoint)

                    tracker.start_account(account_id, account_name or "")

                    account_resources = collect_account(
                        session, account_id, regions, tracker,
                        include_storage_sizes=args.include_storage_sizes,
                        parallel_regions=args.parallel_regions
                    )
                    batch_resources.extend(account_resources)

                    batch_collected.append({
                        'account_id': account_id,
                        'account_name': account_name,
                        'resource_count': len(account_resources)
                    })

                    # Update checkpoint: mark completed
                    checkpoint['completed_accounts'].append(account_id)
                    checkpoint['in_progress'] = None
                    if args.batch_size:
                        save_checkpoint(checkpoint_file, checkpoint)

                except AuthError as e:
                    logger.error(f"Authentication/authorization error for account {account_id}: {e}")
                    logger.error("Check that the IAM role has required permissions.")
                    checkpoint['failed_accounts'].append(account_id)
                    checkpoint['in_progress'] = None
                    if args.batch_size:
                        save_checkpoint(checkpoint_file, checkpoint)
                    continue
                except Exception as e:
                    logger.error(f"Failed to collect from account {account_id}: {e}")
                    checkpoint['failed_accounts'].append(account_id)
                    checkpoint['in_progress'] = None
                    if args.batch_size:
                        save_checkpoint(checkpoint_file, checkpoint)
                    continue

        # Generate summaries for this batch
        batch_summaries = aggregate_sizing(batch_resources)

        # Collect change rates if requested
        change_rate_data = None
        if args.include_change_rate:
            logger.info("Collecting change rate metrics from CloudWatch...")
            print("Collecting change rate metrics from CloudWatch...")
            all_change_rates = {}
            for session, account_id, _account_name in account_sessions:
                try:
                    # Filter resources for this account
                    account_resources = [r for r in batch_resources if r.account_id == account_id]
                    cr_data = collect_resource_change_rates(session, account_resources, args.change_rate_days, args.parallel_regions)
                    merge_change_rates(all_change_rates, cr_data)
                except Exception as e:
                    logger.warning(f"Failed to collect change rates for account {account_id}: {e}")

            if all_change_rates:
                change_rate_data = finalize_change_rate_output(
                    all_change_rates, args.change_rate_days, "CloudWatch"
                )
                logger.info(f"Collected change rates for {len(all_change_rates)} service families")

        # Collect PVCs from EKS clusters (automatic when clusters are discovered)
        eks_clusters = [r for r in batch_resources if r.resource_type == 'aws:eks:cluster']

        if eks_clusters and not args.skip_pvc:
            logger.info("Collecting PVCs from EKS clusters...")
            print("Collecting PVCs from EKS clusters...")

            pvc_count = 0
            for session, account_id, _account_name in account_sessions:
                account_clusters = [c for c in eks_clusters if c.account_id == account_id]
                for cluster in account_clusters:
                    if not cluster.name or not cluster.region:
                        continue
                    try:
                        cluster_pvcs = collect_eks_pvcs(
                            session,
                            cluster.name,
                            cluster.region,
                            account_id
                        )
                        batch_resources.extend(cluster_pvcs)
                        pvc_count += len(cluster_pvcs)
                        if cluster_pvcs:
                            logger.info(f"[{cluster.region}] Found {len(cluster_pvcs)} PVCs in cluster {cluster.name}")
                    except ImportError:
                        logger.info("kubernetes package not installed - skipping PVC collection (pip install kubernetes)")
                        print("Note: Install 'kubernetes' package for PVC collection: pip install kubernetes")
                        break
                    except Exception as e:
                        logger.warning(f"Failed to collect PVCs from cluster {cluster.name}: {e}")
                else:
                    continue
                break  # Break outer loop if ImportError occurred

            if pvc_count > 0:
                print(f"Collected {pvc_count} PVCs from {len(eks_clusters)} EKS clusters")
        elif eks_clusters and args.skip_pvc:
            logger.info("Skipping PVC collection (--skip-pvc specified)")

        # Write batch outputs
        run_id = generate_run_id()
        timestamp = get_timestamp()

        is_multi_account = len(batch_collected) > 1
        account_ids = [a['account_id'] for a in batch_collected]

        output_data = {
            'run_id': run_id,
            'timestamp': timestamp,
            'provider': 'aws',
            'org_name': args.org_name if args.org_name else None,
            'account_id': account_ids[0] if len(account_ids) == 1 else account_ids,
            'accounts': batch_collected if is_multi_account else None,
            'regions': regions if regions else 'all',
            'resource_count': len(batch_resources),
            'resources': [r.to_dict() for r in batch_resources]
        }

        summary_data = {
            'run_id': run_id,
            'timestamp': timestamp,
            'provider': 'aws',
            'org_name': args.org_name if args.org_name else None,
            'account_id': account_ids[0] if len(account_ids) == 1 else account_ids,
            'accounts': batch_collected if is_multi_account else None,
            'total_resources': len(batch_resources),
            'total_capacity_gb': sum(s.total_gb for s in batch_summaries),
            'summaries': [s.to_dict() for s in batch_summaries],
            'change_rates': change_rate_data if change_rate_data else None
        }

        # Remove None values
        output_data = {k: v for k, v in output_data.items() if v is not None}
        summary_data = {k: v for k, v in summary_data.items() if v is not None}

        # Redact sensitive IDs unless --include-resource-ids is specified
        if not args.include_resource_ids:
            output_data = redact_sensitive_data(output_data)
            summary_data = redact_sensitive_data(summary_data)

        # Handle S3 output
        if batch_output.startswith('s3://'):
            batch_output = f"{batch_output}/{run_id}"

        # Write outputs
        file_ts = datetime.now(timezone.utc).strftime('%H%M%S')
        write_json(output_data, f"{batch_output}/cca_aws_inv_{file_ts}.json")
        write_json(summary_data, f"{batch_output}/cca_aws_sum_{file_ts}.json")

        # Write change rate data to separate file if collected
        if change_rate_data:
            change_rate_output = {
                'run_id': run_id,
                'timestamp': timestamp,
                'provider': 'aws',
                'account_id': account_ids[0] if len(account_ids) == 1 else account_ids,
                **change_rate_data
            }
            if not args.include_resource_ids:
                change_rate_output = redact_sensitive_data(change_rate_output)
            write_json(change_rate_output, f"{batch_output}/cca_aws_change_rates_{file_ts}.json")

        csv_data = [s.to_dict() for s in batch_summaries]
        write_csv(csv_data, f"{batch_output}/cca_aws_sizing.csv")

        # Track for final summary
        all_collected_accounts.extend(batch_collected)
        all_summaries.extend(batch_summaries)

        # Print batch results
        if len(batches) > 1:
            print(f"\nBatch {batch_num} complete: {len(batch_collected)} accounts, {len(batch_resources)} resources")
            print(f"Output: {batch_output}/")

        # Handle credential refresh between batches
        if batch_num < len(batches):
            if args.sso_refresh:
                print(f"\n{'='*60}")
                print(f"Refreshing SSO credentials before batch {batch_num + 1}...")
                print(f"{'='*60}")
                sso_cmd = ['aws', 'sso', 'login']
                if args.profile:
                    sso_cmd.extend(['--profile', args.profile])
                try:
                    subprocess.run(sso_cmd, check=True)
                    print("SSO login successful, continuing...")
                    # Recreate base session with refreshed credentials
                    base_session = get_session(args.profile)
                except subprocess.CalledProcessError as e:
                    print(f"SSO login failed (exit code {e.returncode})")
                    print("You can resume later with: --resume " + checkpoint_file)
                    sys.exit(1)
                except FileNotFoundError:
                    print("Error: 'aws' CLI not found. Install AWS CLI or use --interactive instead.")
                    sys.exit(1)

            elif args.interactive:
                print(f"\n{'='*60}")
                print(f"BATCH {batch_num}/{len(batches)} COMPLETE")
                print(f"{'='*60}")
                print("Refresh your credentials now if needed.")
                print("  - AWS SSO: aws sso login" + (f" --profile {args.profile}" if args.profile else ""))
                print("  - IAM User: update ~/.aws/credentials")
                print(f"Progress saved to: {checkpoint_file}")
                input("\nPress ENTER to continue to batch " + str(batch_num + 1) + "...")
                # Recreate base session with potentially refreshed credentials
                base_session = get_session(args.profile)

            elif args.pause_between_batches:
                print(f"\nPausing {args.pause_between_batches} seconds before next batch...")
                print("(Refresh credentials now if using SSO)")
                time.sleep(args.pause_between_batches)

    # Final checkpoint update
    if args.batch_size:
        checkpoint['completed_at'] = get_timestamp()
        save_checkpoint(checkpoint_file, checkpoint)
        print(f"\nCheckpoint saved: {checkpoint_file}")
        if checkpoint['failed_accounts']:
            print(f"Failed accounts ({len(checkpoint['failed_accounts'])}): {', '.join(checkpoint['failed_accounts'])}")
            print(f"Re-run with: --accounts {','.join(checkpoint['failed_accounts'])}")

    # Print final summary
    if len(all_collected_accounts) > 1:
        print(f"\n{'='*60}")
        print("COLLECTION COMPLETE")
        print(f"{'='*60}")
        print(f"Total accounts: {len(all_collected_accounts)}")
        for acc in all_collected_accounts:
            name_str = f" ({acc['account_name']})" if acc.get('account_name') else ""
            print(f"  - {acc['account_id']}{name_str}: {acc['resource_count']} resources")

    print(f"\nRun ID: {run_id}")
    print_summary_table([s.to_dict() for s in all_summaries])
    print(f"Output: {output_base}/")

    if len(batches) > 1:
        print(f"\nTo merge batches: python3 scripts/merge_batch_outputs.py {output_base}/")

    # Exit with error if all accounts failed
    if not all_collected_accounts and checkpoint.get('failed_accounts'):
        print(f"\nERROR: All {len(checkpoint['failed_accounts'])} account(s) failed to collect.")
        sys.exit(1)


if __name__ == '__main__':
    main()
