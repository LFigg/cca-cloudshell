# Configuration Examples

This folder contains example YAML configuration files for each cloud collector.

## Quick Start

1. Copy the appropriate example to your working directory:
   ```bash
   cp config-examples/aws-organization.yaml cca-config.yaml
   ```

2. Edit the file to match your environment

3. Set any required environment variables:
   ```bash
   export CCA_EXTERNAL_ID="your-external-id"  # AWS
   export MS365_TENANT_ID="your-tenant-id"    # M365
   export MS365_CLIENT_ID="your-client-id"    # M365
   export MS365_CLIENT_SECRET="your-secret"   # M365
   ```

4. Run with config:
   ```bash
   python collect.py --cloud aws --config cca-config.yaml
   ```

## Available Examples

| File | Use Case |
|------|----------|
| [aws-single-account.yaml](aws-single-account.yaml) | Single AWS account, direct credentials |
| [aws-organization.yaml](aws-organization.yaml) | AWS Organizations, cross-account roles |
| [azure.yaml](azure.yaml) | Azure subscriptions |
| [gcp.yaml](gcp.yaml) | Google Cloud projects |
| [m365.yaml](m365.yaml) | Microsoft 365 via Graph API |

## Generate a New Config

You can also generate a complete config template:
```bash
python collect.py --generate-config > cca-config.yaml
```

## Environment Variable Substitution

Config files support environment variable substitution:
- `${VAR_NAME}` - Required env var (fails if not set)
- `${VAR_NAME:-default}` - Env var with fallback default

Example:
```yaml
aws:
  external_id: ${CCA_EXTERNAL_ID}
  log_level: ${LOG_LEVEL:-INFO}
```

## Auto-Discovery

If you name your config `cca-config.yaml` in the current directory or `~/.cca/config.yaml`, 
it will be loaded automatically without needing `--config`:
```bash
# These are auto-discovered:
./cca-config.yaml
./cca-config.yml
~/.cca/config.yaml
~/.cca/config.yml
```
