"""
AWS helper utilities.

Provides utility functions for account validation, list chunking, and account file loading.
"""
import logging
import re
from typing import List

logger = logging.getLogger(__name__)


def chunk_list(lst: List, chunk_size: int) -> List[List]:
    """Split a list into chunks of specified size."""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def load_account_list(file_path: str) -> List[str]:
    """
    Load account IDs from a file (one per line).
    Supports comments with # and empty lines.
    Validates that each account ID is a valid 12-digit AWS account ID.
    """
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
    invalid = [acc for acc in account_ids if not re.match(r'^\d{12}$', acc)]

    if invalid:
        examples = invalid[:3]
        msg = f"Invalid AWS account IDs in {source} (must be 12 digits): {examples}"
        if len(invalid) > 3:
            msg += f" ... and {len(invalid) - 3} more"
        raise ValueError(msg)

    return account_ids
