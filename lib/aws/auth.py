"""
AWS authentication and session management.

Provides session creation, role assumption, and organization discovery.
"""
import json
import logging
import os
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from lib.utils import mask_account_id

logger = logging.getLogger(__name__)


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
        subprocess.run(sso_cmd, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        logger.warning(f"SSO login failed: {e.stderr}")
        return False
    except FileNotFoundError:
        logger.warning("AWS CLI not found - cannot refresh SSO credentials")
        return False
