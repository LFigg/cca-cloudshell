"""
CCA CloudShell - Configuration Management

Supports loading configuration from:
1. YAML config file (--config)
2. Environment variables (CCA_*)
3. Command-line arguments (highest priority)

Config file example:
```yaml
org_name: "acme-corp"
output: "./collections"

aws:
  org_role: CCARole
  external_id: ${CCA_EXTERNAL_ID}  # env var substitution
  skip_accounts:
    - "999999999999"
  include_storage_sizes: true
  regions:
    - us-east-1
    - us-west-2
```
"""
import os
import re
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

# Try to import yaml, but make it optional
try:
    import yaml  # type: ignore[import-untyped]
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    yaml = None  # type: ignore


# Default config file locations (checked in order)
DEFAULT_CONFIG_PATHS = [
    './cca-config.yaml',
    './cca-config.yml',
    '~/.cca/config.yaml',
    '~/.cca/config.yml',
]

# Environment variable prefix
ENV_PREFIX = 'CCA_'

# Mapping from config keys to env vars
ENV_VAR_MAPPING = {
    'org_name': 'CCA_ORG_NAME',
    'output': 'CCA_OUTPUT',
    'log_level': 'CCA_LOG_LEVEL',
    'aws.profile': 'CCA_AWS_PROFILE',
    'aws.org_role': 'CCA_ORG_ROLE',
    'aws.external_id': 'CCA_EXTERNAL_ID',
    'aws.regions': 'CCA_REGIONS',
    'aws.skip_accounts': 'CCA_SKIP_ACCOUNTS',
    'aws.include_storage_sizes': 'CCA_INCLUDE_STORAGE_SIZES',
    'azure.subscription': 'CCA_AZURE_SUBSCRIPTION',
    'gcp.project': 'CCA_GCP_PROJECT',
}


def _substitute_env_vars(value: Any) -> Any:
    """Substitute ${ENV_VAR} patterns in string values."""
    if isinstance(value, str):
        # Pattern: ${VAR_NAME} or ${VAR_NAME:-default}
        pattern = r'\$\{([^}:]+)(?::-([^}]*))?\}'
        
        def replace(match):
            var_name = match.group(1)
            default = match.group(2) or ''
            return os.environ.get(var_name, default)
        
        return re.sub(pattern, replace, value)
    elif isinstance(value, dict):
        return {k: _substitute_env_vars(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [_substitute_env_vars(item) for item in value]
    return value


def _get_nested(data: Dict, key_path: str, default: Any = None) -> Any:
    """Get a nested value from a dict using dot notation."""
    keys = key_path.split('.')
    value = data
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return default
    return value


def _set_nested(data: Dict, key_path: str, value: Any) -> None:
    """Set a nested value in a dict using dot notation."""
    keys = key_path.split('.')
    for key in keys[:-1]:
        data = data.setdefault(key, {})
    data[keys[-1]] = value


def load_config_file(config_path: str) -> Dict[str, Any]:
    """Load configuration from a YAML file."""
    if not HAS_YAML:
        logger.warning("PyYAML not installed. Config file support disabled. Install with: pip install pyyaml")
        return {}
    
    path = Path(config_path).expanduser()
    
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    
    # Security check: warn if config file has loose permissions
    import stat
    file_mode = path.stat().st_mode
    if file_mode & (stat.S_IRWXG | stat.S_IRWXO):  # Group or world access
        logger.warning(f"Config file {config_path} has loose permissions. "
                      f"Consider: chmod 600 {config_path}")
    
    logger.info(f"Loading config from {path}")
    
    with open(path) as f:
        config = yaml.safe_load(f) or {}  # type: ignore[union-attr]
    
    # Substitute environment variables
    config = _substitute_env_vars(config)
    
    return config


def find_default_config() -> Optional[str]:
    """Find a config file in default locations."""
    for path in DEFAULT_CONFIG_PATHS:
        expanded = Path(path).expanduser()
        if expanded.exists():
            return str(expanded)
    return None


def load_env_config() -> Dict[str, Any]:
    """Load configuration from environment variables."""
    config: Dict[str, Any] = {}
    
    for config_key, env_var in ENV_VAR_MAPPING.items():
        value = os.environ.get(env_var)
        if value is not None:
            # Handle comma-separated lists
            if config_key in ('aws.regions', 'aws.skip_accounts'):
                value = [v.strip() for v in value.split(',') if v.strip()]
            # Handle booleans
            elif config_key in ('aws.include_storage_sizes',):
                value = value.lower() in ('true', '1', 'yes')
            
            _set_nested(config, config_key, value)
    
    return config


def merge_configs(*configs: Dict[str, Any]) -> Dict[str, Any]:
    """Merge multiple config dicts. Later configs override earlier ones."""
    result: Dict[str, Any] = {}
    
    for config in configs:
        for key, value in config.items():
            if isinstance(value, dict) and isinstance(result.get(key), dict):
                result[key] = merge_configs(result[key], value)
            elif value is not None:
                result[key] = value
    
    return result


def args_to_config(args) -> Dict[str, Any]:
    """Convert argparse args to config dict format."""
    config: Dict[str, Any] = {'aws': {}}
    
    # Map argparse attributes to config structure
    arg_mapping = {
        'org_name': 'org_name',
        'output': 'output',
        'log_level': 'log_level',
        'profile': 'aws.profile',
        'regions': 'aws.regions',
        'role_arn': 'aws.role_arn',
        'role_arns': 'aws.role_arns',
        'org_role': 'aws.org_role',
        'external_id': 'aws.external_id',
        'skip_accounts': 'aws.skip_accounts',
        'accounts': 'aws.accounts',
        'account_file': 'aws.account_file',
        'batch_size': 'aws.batch_size',
        'resume': 'aws.resume',
        'checkpoint': 'aws.checkpoint',
        'pause_between_batches': 'aws.pause_between_batches',
        'sso_refresh': 'aws.sso_refresh',
        'interactive': 'aws.interactive',
        'include_storage_sizes': 'aws.include_storage_sizes',
    }
    
    for arg_name, config_key in arg_mapping.items():
        value = getattr(args, arg_name, None)
        if value is not None:
            # Handle comma-separated string to list conversion
            if arg_name in ('regions', 'skip_accounts', 'accounts', 'role_arns') and isinstance(value, str):
                value = [v.strip() for v in value.split(',') if v.strip()]
            _set_nested(config, config_key, value)
    
    return config


def config_to_args(config: Dict[str, Any], args) -> None:
    """Apply config values to argparse args object."""
    # Flat mappings
    if 'org_name' in config:
        args.org_name = config['org_name']
    if 'output' in config:
        args.output = config['output']
    if 'log_level' in config:
        args.log_level = config['log_level']
    
    # AWS-specific mappings
    aws_config = config.get('aws', {})
    
    if 'profile' in aws_config and not getattr(args, 'profile', None):
        args.profile = aws_config['profile']
    if 'regions' in aws_config and not getattr(args, 'regions', None):
        regions = aws_config['regions']
        args.regions = ','.join(regions) if isinstance(regions, list) else regions
    if 'role_arn' in aws_config and not getattr(args, 'role_arn', None):
        args.role_arn = aws_config['role_arn']
    if 'role_arns' in aws_config and not getattr(args, 'role_arns', None):
        role_arns = aws_config['role_arns']
        args.role_arns = ','.join(role_arns) if isinstance(role_arns, list) else role_arns
    if 'org_role' in aws_config and not getattr(args, 'org_role', None):
        args.org_role = aws_config['org_role']
    if 'external_id' in aws_config and not getattr(args, 'external_id', None):
        args.external_id = aws_config['external_id']
    if 'skip_accounts' in aws_config and not getattr(args, 'skip_accounts', None):
        skip = aws_config['skip_accounts']
        args.skip_accounts = ','.join(skip) if isinstance(skip, list) else skip
    if 'accounts' in aws_config and not getattr(args, 'accounts', None):
        accounts = aws_config['accounts']
        args.accounts = ','.join(accounts) if isinstance(accounts, list) else accounts
    if 'account_file' in aws_config and not getattr(args, 'account_file', None):
        args.account_file = aws_config['account_file']
    if 'batch_size' in aws_config and not getattr(args, 'batch_size', None):
        args.batch_size = aws_config['batch_size']
    if 'include_storage_sizes' in aws_config:
        args.include_storage_sizes = aws_config['include_storage_sizes']


def load_config(args) -> Dict[str, Any]:
    """
    Load configuration from all sources and merge them.
    
    Priority (highest to lowest):
    1. CLI arguments
    2. Config file (--config or default location)
    3. Environment variables
    
    Returns merged config dict.
    """
    configs = []
    
    # 1. Environment variables (lowest priority)
    env_config = load_env_config()
    if env_config:
        logger.debug("Loaded config from environment variables")
        configs.append(env_config)
    
    # 2. Config file
    config_path = getattr(args, 'config', None)
    if config_path:
        file_config = load_config_file(config_path)
        configs.append(file_config)
    else:
        # Check for default config file
        default_config = find_default_config()
        if default_config:
            logger.info(f"Found default config file: {default_config}")
            file_config = load_config_file(default_config)
            configs.append(file_config)
    
    # 3. CLI arguments (highest priority)
    cli_config = args_to_config(args)
    configs.append(cli_config)
    
    # Merge all configs
    merged = merge_configs(*configs)
    
    # Apply merged config back to args
    config_to_args(merged, args)
    
    return merged


def generate_sample_config() -> str:
    """Generate a sample config file content."""
    return '''# CCA CloudShell Configuration
# See docs/getting-started.md for details
#
# Environment variable substitution supported:
#   ${VAR_NAME}           - required env var
#   ${VAR_NAME:-default}  - env var with default value

# =============================================================================
# Common Settings (apply to all collectors)
# =============================================================================

# Organization name (used in report filenames)
org_name: "my-organization"

# Output directory for collection results
output: "./collections"

# Logging level: DEBUG, INFO, WARNING, ERROR
log_level: INFO


# =============================================================================
# AWS Settings (aws_collect.py)
# =============================================================================
aws:
  # AWS CLI profile (optional, uses default/CloudShell credentials if not set)
  # profile: my-profile
  
  # IAM role name to assume in each Organization account
  # Required for multi-account collection via Organizations
  org_role: CCACollectorRole
  
  # External ID for role assumption (recommended for security)
  # Can use environment variable: ${CCA_EXTERNAL_ID}
  external_id: ${CCA_EXTERNAL_ID}
  
  # Specific regions to collect (default: all enabled regions)
  # regions:
  #   - us-east-1
  #   - us-west-2
  #   - eu-west-1
  
  # Account IDs to skip during collection
  # skip_accounts:
  #   - "999999999999"  # sandbox/dev account
  #   - "888888888888"  # security account
  
  # Collect only specific accounts (useful for retrying failed accounts)
  # accounts:
  #   - "111111111111"
  #   - "222222222222"
  
  # Include S3 bucket sizes via CloudWatch (slower, adds ~2 API calls per bucket)
  include_storage_sizes: false
  
  # Batch size for large orgs (creates checkpoint files for resume)
  # batch_size: 25


# =============================================================================
# Azure Settings (azure_collect.py)
# =============================================================================
azure:
  # Specific subscription ID (leave empty for all accessible subscriptions)
  # subscription: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  
  # Filter to specific regions (default: all regions with resources)
  # regions:
  #   - eastus
  #   - westus2
  #   - westeurope


# =============================================================================
# GCP Settings (gcp_collect.py)
# =============================================================================
gcp:
  # Specific project ID (leave empty to scan all accessible projects)
  # project: "my-project-id"
  
  # Collect from all projects (alternative to specifying project)
  # all_projects: true


# =============================================================================
# Microsoft 365 Settings (m365_collect.py)
# =============================================================================
# Note: M365 requires Azure AD App Registration with Microsoft Graph permissions.
# Client secret MUST be set via environment variable for security.
#
# Required API permissions (Application type):
#   - Sites.Read.All (SharePoint)
#   - User.Read.All (Users, OneDrive, Exchange)
#   - Group.Read.All (Groups, Teams)
#   - TeamSettings.Read.All (Teams details)
#
m365:
  # Azure AD tenant ID
  tenant_id: ${MS365_TENANT_ID}
  
  # App registration client ID
  client_id: ${MS365_CLIENT_ID}
  
  # Client secret (always use env var, never put secrets in config files!)
  # client_secret: ${MS365_CLIENT_SECRET}
  
  # Include Entra ID (Azure AD) users and groups
  # include_entra: true


# =============================================================================
# Cost Collection Settings (cost_collect.py)
# =============================================================================
cost:
  # Date range for cost analysis (default: last 30 days)
  # start_date: "2026-01-01"
  # end_date: "2026-01-31"
  
  # Include Organization-level costs (AWS) - requires management account
  # org_costs: true
'''
