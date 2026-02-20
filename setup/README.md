# Permission Setup Scripts

This folder contains scripts and templates to set up permissions for each cloud platform.

## Quick Reference

| Cloud | Setup Script | IAM Template |
|-------|--------------|--------------|
| **AWS** | [setup-aws-permissions.sh](setup-aws-permissions.sh) | [aws-iam-role.yaml](aws-iam-role.yaml) |
| **Azure** | [setup-azure-permissions.sh](setup-azure-permissions.sh) | [azure-custom-role.json](azure-custom-role.json) |
| **GCP** | [setup-gcp-permissions.sh](setup-gcp-permissions.sh) | [gcp-custom-role.yaml](gcp-custom-role.yaml) |

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

# Enable Organizations and Cost Explorer access
./setup/setup-aws-permissions.sh --enable-org --enable-cost
```

Or deploy CloudFormation directly:
```bash
aws cloudformation create-stack \
  --stack-name cca-collector \
  --template-body file://setup/aws-iam-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM
```

See [aws-cloudformation-README.md](aws-cloudformation-README.md) for multi-account StackSet details.

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

M365 requires an Azure AD App Registration. See [docs/collectors/m365.md](../docs/collectors/m365.md) for:
- Creating an App Registration
- Granting Microsoft Graph API permissions
- Admin consent requirements

No IAM scripts needed - permissions are granted through Azure AD portal.

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
