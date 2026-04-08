"""
AWS parallel collection and checkpoint management.

Provides multi-account parallel collection using subprocess workers,
checkpoint save/load functionality, and worker result collection.
"""
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3

from lib.aws.auth import get_sso_token_expiry, refresh_sso_credentials
from lib.utils import get_timestamp

logger = logging.getLogger(__name__)


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


def distribute_accounts(accounts: List[Dict], num_workers: int) -> List[List[Dict]]:
    """Distribute accounts evenly across workers using round-robin."""
    workers: List[List[Dict]] = [[] for _ in range(num_workers)]
    for i, account in enumerate(accounts):
        workers[i % num_workers].append(account)
    return [w for w in workers if w]  # Filter out empty workers


def run_parallel_account_collection(
    accounts_to_collect: List[Dict[str, Any]],
    args,
    base_session: boto3.Session,
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
    if args.skip_storage_sizes:
        base_cmd.append('--skip-storage-sizes')
    if args.skip_change_rate:
        base_cmd.append('--skip-change-rate')
    else:
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
        print("  SSO auto-refresh: enabled (will refresh when token < 10 min remaining)")
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
    print("PARALLEL COLLECTION COMPLETE")
    print("=" * 70)
    print(f"  Duration: {elapsed/60:.1f} minutes ({elapsed/3600:.2f} hours)")
    print(f"  Workers: {successful_workers} succeeded, {failed_workers} failed")
    print(f"  Accounts: {total_completed} completed, {total_failed} failed")

    # Collect failed accounts for retry info
    if total_failed > 0:
        print(f"\n  Failed accounts: {', '.join(parallel_checkpoint['failed_accounts'][:5])}")
        if total_failed > 5:
            print(f"    ... and {total_failed - 5} more (see checkpoint file)")
        print("\n  To retry failed accounts only:")
        print(f"    python3 {sys.argv[0]} --org-role {args.org_role or 'ROLE'} \\")
        print(f"      --accounts {','.join(parallel_checkpoint['failed_accounts'][:3])}...")

    if failed_workers > 0:
        print("\n  Failed worker logs:")
        for i, ret in enumerate(return_codes):
            if ret != 0:
                print(f"    Worker {i+1}: {worker_dirs[i]}/worker.log")

    # Merge outputs
    print(f"\n  Merging outputs from {num_workers} workers...")
    merged_dir = f"{output_base}/merged"
    os.makedirs(merged_dir, exist_ok=True)

    try:
        # Import and use merge functionality
        merge_script = os.path.join(os.path.dirname(__file__), '..', '..', 'scripts', 'merge_batch_outputs.py')
        if os.path.exists(merge_script):
            merge_cmd = [sys.executable, merge_script] + worker_dirs + ['-o', merged_dir]
            result = subprocess.run(merge_cmd, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"  Merged output: {merged_dir}/")
            else:
                logger.warning(f"Merge script failed: {result.stderr}")
                print("  Merge failed - outputs available in worker directories")
        else:
            # Manual merge: find all cca_inv and cca_sum files
            print(f"  Worker outputs available in: {output_base}/worker_XX/")
    except Exception as e:
        logger.warning(f"Error during merge: {e}")
        print("  Merge error - outputs available in worker directories")

    print("=" * 70)

    if failed_workers == 0:
        return 0
    elif successful_workers > 0:
        return 1  # Partial success
    else:
        return 2  # Total failure
