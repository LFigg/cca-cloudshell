#!/usr/bin/env bash
#
# Parallel per-account AWS collection driver for SSO setups where each
# account needs its own distinct AWS CLI profile (IAM Identity Center
# permission set) rather than one role chain-assumable from a single base
# session - i.e. --org-role and --role-arns can't be used.
#
# This replaces a sequential "one account at a time" loop with N concurrent
# `collect.py --profile <profile> -o <output>/<account_id>` invocations,
# while staying safe against the two failure modes that actually hit a
# customer run previously:
#   1. Running the same account's collection more than once (wastes hours
#      and, if the two runs land in the same output dir, produces duplicate
#      resources that inflate every total downstream). This script skips
#      any account whose output directory already has a successful
#      inventory file, and refuses to start a second instance of itself
#      against the same output directory.
#   2. Losing visibility into progress with many processes running at once.
#      Each account gets its own status file (so a concurrent write from
#      one account's worker can never corrupt another's).
#
# Usage:
#   ./scripts/collect_parallel_profiles.sh accounts.csv ./output 6
#
#   accounts.csv: one "account_id,profile_name" pair per line.
#     A header row is fine - any line where the first field isn't all
#     digits is skipped. Blank lines and lines starting with # are skipped.
#   ./output:     base output directory (created if missing).
#   6:            number of accounts to collect concurrently (default 6).
#
# Any arguments after the first three are passed through to collect.py
# unchanged for every account, e.g.:
#   ./scripts/collect_parallel_profiles.sh accounts.csv ./output 6 \
#       --parallel-regions 4 --sso-refresh
#
# To resume after an interruption (Ctrl-C, laptop sleep, etc.), just run the
# exact same command again - already-completed accounts are skipped
# automatically.
#
# Deliberately uses only features present in bash 3.2 (macOS's shipped
# bash) - no `read -u`, no `wait -n`, no `mapfile`/`readarray`, and no
# `set -u` (bash 3.2 treats an empty array's "${arr[@]}" expansion as
# unset under nounset, unlike 4.4+). Concurrency is via xargs -P, which
# both BSD (macOS) and GNU xargs support.
set -o pipefail

ACCOUNTS_FILE="${1:?Usage: $0 <accounts.csv> <output_dir> [concurrency] [extra collect.py args...]}"
OUTPUT_DIR="${2:?Usage: $0 <accounts.csv> <output_dir> [concurrency] [extra collect.py args...]}"
CONCURRENCY="${3:-6}"
shift 3 2>/dev/null || shift "$#"
EXTRA_ARGS=("$@")

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COLLECT_PY="$REPO_ROOT/collect.py"
WORKER="$REPO_ROOT/scripts/_collect_one_account.sh"
STATUS_DIR="$OUTPUT_DIR/.status"
LOCK_DIR="$OUTPUT_DIR/.run.lock"

if [[ ! -f "$ACCOUNTS_FILE" ]]; then
    echo "ERROR: accounts file not found: $ACCOUNTS_FILE" >&2
    exit 1
fi
if [[ ! -f "$COLLECT_PY" ]]; then
    echo "ERROR: collect.py not found at $COLLECT_PY" >&2
    exit 1
fi
if [[ ! -f "$WORKER" ]]; then
    echo "ERROR: worker script not found at $WORKER" >&2
    exit 1
fi
if ! [[ "$CONCURRENCY" =~ ^[0-9]+$ ]] || [[ "$CONCURRENCY" -lt 1 ]]; then
    echo "ERROR: concurrency must be a positive integer, got: $CONCURRENCY" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR" "$STATUS_DIR"
chmod +x "$WORKER"

# --- Single-instance lock -----------------------------------------------
# mkdir is atomic on every filesystem this is likely to run on (Linux,
# macOS, WSL, Git Bash/MSYS2 on NTFS) - unlike flock(1), which macOS does
# not ship. This is the single most important safety net here: it is
# exactly what would have stopped the original run from being started
# multiple times concurrently against the same accounts.
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "ERROR: another instance of this script already appears to be running" >&2
    echo "       against $OUTPUT_DIR (lock dir exists: $LOCK_DIR)." >&2
    echo "       If no other instance is actually running (e.g. it crashed)," >&2
    echo "       remove the lock manually first: rmdir '$LOCK_DIR'" >&2
    exit 1
fi

already_collected() {
    local account_id="$1"
    local acct_output="$OUTPUT_DIR/$account_id"
    # Safe to skip only if a previous run already wrote real inventory
    # output for this account - not just an empty/half-made directory.
    compgen -G "$acct_output/cca_aws_inv_*.json" > /dev/null 2>&1
}

START_TIME=$(date +%s)
WORK_LIST="$(mktemp "${TMPDIR:-/tmp}/collect_work.XXXXXX")"
EXTRA_ARGS_FILE="$(mktemp "${TMPDIR:-/tmp}/collect_extra_args.XXXXXX")"

# A single handler bound to EXIT, INT, and TERM together would run its
# cleanup on a signal but NOT actually stop the script (the trap returns
# and execution continues from wherever it was) - INT/TERM need their own
# handlers that explicitly exit. Note: xargs may not forward the signal to
# already-running collect.py children, so a Ctrl-C/kill here can leave
# individual collect.py processes running; check `pgrep -f collect.py` if
# that matters and kill them separately.
_cleanup() { rm -f "$WORK_LIST" "$EXTRA_ARGS_FILE" 2>/dev/null; rmdir "$LOCK_DIR" 2>/dev/null; }
trap '_cleanup' EXIT
trap '_cleanup; exit 130' INT
trap '_cleanup; exit 143' TERM

# One extra collect.py argument per line, read back by the worker (no
# mapfile/readarray needed - see _collect_one_account.sh).
: > "$EXTRA_ARGS_FILE"
for arg in "${EXTRA_ARGS[@]:-}"; do
    [[ -n "$arg" ]] && printf '%s\n' "$arg" >> "$EXTRA_ARGS_FILE"
done

TOTAL=0
SKIPPED=0

while IFS=, read -r account_id profile _rest; do
    account_id="$(echo "${account_id:-}" | tr -d '[:space:]')"
    profile="$(echo "${profile:-}" | tr -d '[:space:]')"

    [[ -z "$account_id" ]] && continue
    [[ "$account_id" =~ ^[0-9]+$ ]] || continue  # skip header / malformed rows
    if [[ -z "$profile" ]]; then
        echo "WARNING: no profile given for account $account_id, skipping" >&2
        continue
    fi

    TOTAL=$((TOTAL + 1))

    if already_collected "$account_id"; then
        echo "  [skip] $account_id already has inventory output"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    # account_id then profile - xargs (no -I) appends these, in order,
    # after the fixed arguments given to it below.
    printf '%s %s\n' "$account_id" "$profile" >> "$WORK_LIST"
done < "$ACCOUNTS_FILE"

LAUNCHED=$(wc -l < "$WORK_LIST" | tr -d ' ')
echo ""
echo "Collecting $LAUNCHED accounts ($SKIPPED already done, $TOTAL total) with concurrency $CONCURRENCY..."
echo "Per-account logs/status: $STATUS_DIR/<account_id>.{status,log}"
echo ""

if [[ "$LAUNCHED" -gt 0 ]]; then
    # One worker process per line (-L 1), up to $CONCURRENCY at a time.
    # Each line is "account_id profile" - xargs splits it on whitespace
    # and appends both as trailing args after the fixed ones.
    xargs -P "$CONCURRENCY" -L 1 "$WORKER" "$COLLECT_PY" "$OUTPUT_DIR" "$STATUS_DIR" "$EXTRA_ARGS_FILE" < "$WORK_LIST"
fi

# --- Summary --------------------------------------------------------------
ELAPSED=$(( $(date +%s) - START_TIME ))
COMPLETE_COUNT=0
FAILED_COUNT=0
for f in "$STATUS_DIR"/*.status; do
    [[ -e "$f" ]] || continue
    if grep -q '^COMPLETE' "$f" 2>/dev/null; then
        COMPLETE_COUNT=$((COMPLETE_COUNT + 1))
    elif grep -q '^FAILED' "$f" 2>/dev/null; then
        FAILED_COUNT=$((FAILED_COUNT + 1))
    fi
done

echo "============================================================"
echo "PARALLEL COLLECTION COMPLETE"
echo "============================================================"
printf "  Duration: %dm %ds\n" $((ELAPSED / 60)) $((ELAPSED % 60))
echo "  Accounts this run: $LAUNCHED launched, $SKIPPED already done"
echo "  Results across all status files: $COMPLETE_COUNT completed, $FAILED_COUNT failed"
if [[ "$FAILED_COUNT" -gt 0 ]]; then
    echo ""
    echo "  Failed accounts:"
    for f in "$STATUS_DIR"/*.status; do
        [[ -e "$f" ]] || continue
        if grep -q '^FAILED' "$f" 2>/dev/null; then
            acct="$(basename "$f" .status)"
            echo "    - $acct: $(cat "$f") (see $STATUS_DIR/$acct.log)"
        fi
    done
    echo ""
    echo "  Re-run this exact command to retry only the accounts that"
    echo "  haven't succeeded yet - everything else is skipped automatically."
fi
echo ""
echo "  To merge all account outputs into one inventory/summary/cost file:"
echo "    python3 $REPO_ROOT/scripts/merge_batch_outputs.py $OUTPUT_DIR/"
echo "============================================================"
