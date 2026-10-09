#!/usr/bin/env bash
# Internal helper for collect_parallel_profiles.sh - collects exactly one
# account and writes its status file. Not meant to be run directly.
#
# Args: <collect.py path> <output_dir> <status_dir> <extra_args_file> <account_id> <profile>
# extra_args_file: one collect.py argument per line (may be empty/missing).
set -o pipefail

COLLECT_PY="$1"
OUTPUT_DIR="$2"
STATUS_DIR="$3"
EXTRA_ARGS_FILE="$4"
ACCOUNT_ID="$5"
PROFILE="$6"

ACCT_OUTPUT="$OUTPUT_DIR/$ACCOUNT_ID"
STATUS_FILE="$STATUS_DIR/$ACCOUNT_ID.status"
LOG_FILE="$STATUS_DIR/$ACCOUNT_ID.log"

# Build the extra-args array the bash-3.2-compatible way (no mapfile/readarray).
EXTRA_ARGS=()
if [[ -f "$EXTRA_ARGS_FILE" ]]; then
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        EXTRA_ARGS[${#EXTRA_ARGS[@]}]="$line"
    done < "$EXTRA_ARGS_FILE"
fi

mkdir -p "$ACCT_OUTPUT"
echo "STARTING $(date '+%Y-%m-%d %H:%M:%S')" > "$STATUS_FILE"

if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
    python3 "$COLLECT_PY" --cloud aws --profile "$PROFILE" -o "$ACCT_OUTPUT" \
        --org-name "$ACCOUNT_ID" "${EXTRA_ARGS[@]}" >"$LOG_FILE" 2>&1
else
    python3 "$COLLECT_PY" --cloud aws --profile "$PROFILE" -o "$ACCT_OUTPUT" \
        --org-name "$ACCOUNT_ID" >"$LOG_FILE" 2>&1
fi
RC=$?

if [[ $RC -eq 0 ]]; then
    echo "COMPLETE $(date '+%Y-%m-%d %H:%M:%S') RC=$RC" > "$STATUS_FILE"
else
    echo "FAILED $(date '+%Y-%m-%d %H:%M:%S') RC=$RC" > "$STATUS_FILE"
fi
