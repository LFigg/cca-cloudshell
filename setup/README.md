# Permission Setup Scripts

This folder contains scripts and templates to set up permissions for each cloud platform.

**Default Permissions Include:**
- Resource inventory collection (VMs, storage, databases, etc.)
- Change rate metrics (CloudWatch/Azure Monitor/Cloud Monitoring)
- Cost collection (Cost Explorer, Cost Management, BigQuery billing)

## Quick Reference

| Cloud | Setup Script | IAM Template |
|-------|--------------|--------------|
| **AWS** | [setup-aws-permissions.sh](setup-aws-permissions.sh) | [aws-iam-role.yaml](aws-iam-role.yaml) |
| **AWS StackSet** | — | [aws-stackset-member-role.yaml](aws-stackset-member-role.yaml) |
| **Azure** | [setup-azure-permissions.sh](setup-azure-permissions.sh) | [azure-custom-role.json](azure-custom-role.json) |
| **GCP** | [setup-gcp-permissions.sh](setup-gcp-permissions.sh) | [gcp-custom-role.yaml](gcp-custom-role.yaml) |
| **M365** | [setup-m365-permissions.sh](setup-m365-permissions.sh) | — (uses Entra ID App Registration) |

---

## AWS Setup

Run the setup script:
```bash
# Single account setup
./setup/setup-aws-permissions.sh

# With external ID for cross-account security
./setup/setup-aws-permissions.sh --external-id your-secret-id

# Check existing permissions
./setup/setup-aws-permissions.sh --check

# Deploy to all Organization accounts via StackSet
./setup/setup-aws-permissions.sh --stackset --external-id your-secret-id

# Enable Organizations API access (for --org-role)
./setup/setup-aws-permissions.sh --enable-org

# Disable cost collection (enabled by default)
./setup/setup-aws-permissions.sh --no-cost
```

Or deploy CloudFormation directly:
```bash
aws cloudformation create-stack \
  --stack-name cca-collector \
  --template-body file://setup/aws-iam-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM
```

See [AWS CloudFormation docs](../docs/aws-cloudformation.md) for multi-account StackSet details.

---

## Azure Setup

### Option 1: Built-in Reader Role (Recommended)

Run the setup script:
```bash
# Current subscription
./setup/setup-azure-permissions.sh

# Specific subscription
./setup/setup-azure-permissions.sh <subscription-id>

# All accessible subscriptions
./setup/setup-azure-permissions.sh --all
```

Or manually via Azure CLI:
```bash
# Get your user object ID
USER_ID=$(az ad signed-in-user show --query id -o tsv)

# Assign Reader role
az role assignment create \
  --assignee "$USER_ID" \
  --role "Reader" \
  --scope "/subscriptions/<subscription-id>"
```

### Option 2: Custom Role (Least Privilege)

Deploy the ARM template:
```bash
# Get your user object ID
USER_ID=$(az ad signed-in-user show --query id -o tsv)

# Deploy custom role with assignment
az deployment sub create \
  --location eastus \
  --template-file setup/azure-custom-role.json \
  --parameters principalId="$USER_ID"
```

Or deploy just the role definition (assign separately):
```bash
az deployment sub create \
  --location eastus \
  --template-file setup/azure-custom-role.json
```

---

## GCP Setup

### Option 1: Predefined Viewer Role (Recommended)

Run the setup script:
```bash
# Current project
./setup/setup-gcp-permissions.sh

# Specific project
./setup/setup-gcp-permissions.sh <project-id>

# All accessible projects
./setup/setup-gcp-permissions.sh --all
```

Or manually via gcloud:
```bash
# Get current account
ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)")

# Grant Viewer role
gcloud projects add-iam-policy-binding <project-id> \
  --member="user:${ACCOUNT}" \
  --role="roles/viewer"
```

### Option 2: Custom Role (Least Privilege)

Create the custom role:
```bash
# At project level
gcloud iam roles create CCACloudShellReader \
  --project=<project-id> \
  --file=setup/gcp-custom-role.yaml

# Grant to user
gcloud projects add-iam-policy-binding <project-id> \
  --member="user:<email>" \
  --role="projects/<project-id>/roles/CCACloudShellReader"
```

Or at organization level:
```bash
gcloud iam roles create CCACloudShellReader \
  --organization=<org-id> \
  --file=setup/gcp-custom-role.yaml
```

---

## Microsoft 365 Setup

M365 requires an Azure AD (Entra ID) App Registration with Microsoft Graph API permissions.

### Prerequisites

- Azure CLI installed and logged in (`az login`)
- **Global Administrator** or **Application Administrator** role in your Entra ID tenant

### Quick Setup (Recommended)

Run the setup script:
```bash
# Interactive setup - creates app registration and grants permissions
./setup/setup-m365-permissions.sh

# Custom app name
./setup/setup-m365-permissions.sh --app-name "My CCA Collector"

# Check existing setup
./setup/setup-m365-permissions.sh --check

# Grant admin consent to existing app
./setup/setup-m365-permissions.sh --grant-consent

# Output credentials to file
./setup/setup-m365-permissions.sh --output-env ~/.cca-m365-credentials
```

The script will:
1. Create an Azure AD App Registration
2. Configure Microsoft Graph API permissions
3. Create a client secret
4. Grant admin consent
5. Output the environment variables needed

### Required Permissions

The script configures these Microsoft Graph API permissions:

| Permission | Purpose |
|------------|---------|
| `Sites.Read.All` | Read SharePoint sites |
| `Files.Read.All` | Read OneDrive files/storage |
| `User.Read.All` | Read user profiles & mailbox info |
| `Mail.Read` | Read mailbox metadata |
| `Team.ReadBasic.All` | Read Teams information |
| `Group.Read.All` | Read group membership |
| `Reports.Read.All` | Usage reports for sizing/growth metrics |
| `Directory.Read.All` | Read Entra ID users/groups |

### Manual Setup (Azure Portal)

If you prefer manual setup:

1. Go to **Azure Portal** → **Microsoft Entra ID** → **App registrations**
2. Click **New registration**
3. Name: `CCA CloudShell M365 Collector`
4. Supported account types: **Single tenant**
5. Click **Register**
6. Note the **Application (client) ID** and **Directory (tenant) ID**
7. Go to **Certificates & secrets** → **New client secret**
8. Note the secret value (shown only once)
9. Go to **API permissions** → **Add a permission** → **Microsoft Graph** → **Application permissions**
10. Add each permission from the table above
11. Click **Grant admin consent for [Your Tenant]**

### Environment Variables

After setup, configure these environment variables:
```bash
export MS365_TENANT_ID="your-tenant-id"
export MS365_CLIENT_ID="your-client-id"
export MS365_CLIENT_SECRET="your-client-secret"
```

Or source the credentials file if you used `--output-env`:
```bash
source ~/.cca-m365-credentials
```

### Running the Collector

```bash
# Run M365 collector
python m365_collect.py

# Or use unified collector
python collect.py --cloud m365
```

See [docs/collectors/m365.md](../docs/collectors/m365.md) for detailed usage options.

---

## Service Principals / Service Accounts

For automated/CI scenarios, you may want to use service principals instead of user accounts:

### Azure Service Principal
```bash
# Create service principal with Reader role
az ad sp create-for-rbac \
  --name "cca-collector" \
  --role "Reader" \
  --scopes "/subscriptions/<subscription-id>"
```

### GCP Service Account
```bash
# Create service account
gcloud iam service-accounts create cca-collector \
  --display-name="CCA Collector"

# Grant Viewer role
gcloud projects add-iam-policy-binding <project-id> \
  --member="serviceAccount:cca-collector@<project-id>.iam.gserviceaccount.com" \
  --role="roles/viewer"

# Create key file
gcloud iam service-accounts keys create cca-collector-key.json \
  --iam-account=cca-collector@<project-id>.iam.gserviceaccount.com
```

---

## Verifying Permissions

After setup, verify permissions work:

```bash
# Azure
az resource list --query "[0].name" -o tsv

# GCP
gcloud compute instances list --limit=1

# AWS
aws ec2 describe-regions --query "Regions[0].RegionName" --output text
```

Or use the unified collector which verifies automatically:
```bash
python collect.py --cloud azure
python collect.py --cloud gcp
python collect.py --cloud aws
```
