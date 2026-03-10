#!/bin/bash
# CCA CloudShell - Microsoft 365 Permission Setup
#
# This script creates an Azure AD (Entra ID) App Registration with the
# Microsoft Graph API permissions needed for the M365 collector.
#
# Prerequisites:
#   - Azure CLI installed and logged in (az login)
#   - Global Administrator or Application Administrator role in Entra ID
#
# Usage:
#   ./setup-m365-permissions.sh                    # Interactive setup
#   ./setup-m365-permissions.sh --app-name NAME    # Custom app name
#   ./setup-m365-permissions.sh --check            # Check existing setup
#   ./setup-m365-permissions.sh --grant-consent    # Grant admin consent to existing app

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Defaults
APP_NAME="CCA CloudShell M365 Collector"
CHECK_ONLY=false
GRANT_CONSENT_ONLY=false
OUTPUT_ENV_FILE=""
SECRET_VALIDITY_YEARS=1

# Microsoft Graph API permission IDs (Application permissions)
# These are well-known GUIDs for Microsoft Graph
# Format: "PermissionName:PermissionID"
GRAPH_PERMISSIONS=(
    "Sites.Read.All:332a536c-c7ef-4017-ab91-336970924f0d"
    "Files.Read.All:01d4889c-1287-42c6-ac1f-5d1e02578ef6"
    "User.Read.All:df021288-bdef-4463-88db-98f22de89214"
    "Mail.Read:810c84a8-4a9e-49e6-bf7d-12d183f40d01"
    "Team.ReadBasic.All:2280dda6-0bfd-44ee-a2f4-cb867cfc4c1e"
    "Group.Read.All:5b567255-7703-4780-807c-7be8301ae99b"
    "Reports.Read.All:230c1aed-a721-4c5d-9cb4-a90514e508ef"
    "Directory.Read.All:7ab1d382-f21e-4acd-a863-ba3e13f7da61"
)

# Microsoft Graph resource ID
GRAPH_RESOURCE_ID="00000003-0000-0000-c000-000000000000"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --app-name)
            APP_NAME="$2"
            shift 2
            ;;
        --check)
            CHECK_ONLY=true
            shift
            ;;
        --grant-consent)
            GRANT_CONSENT_ONLY=true
            shift
            ;;
        --output-env)
            OUTPUT_ENV_FILE="$2"
            shift 2
            ;;
        --secret-years)
            SECRET_VALIDITY_YEARS="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --app-name NAME      App registration name (default: 'CCA CloudShell M365 Collector')"
            echo "  --check              Check existing app registration and permissions"
            echo "  --grant-consent      Grant admin consent to existing app"
            echo "  --output-env FILE    Write environment variables to file"
            echo "  --secret-years N     Client secret validity in years (default: 1)"
            echo "  --help               Show this help message"
            echo ""
            echo "Required Permissions:"
            echo "  - Sites.Read.All      Read SharePoint sites"
            echo "  - Files.Read.All      Read OneDrive files/storage"
            echo "  - User.Read.All       Read user profiles & mailbox info"
            echo "  - Mail.Read           Read mailbox metadata"
            echo "  - Team.ReadBasic.All  Read Teams information"
            echo "  - Group.Read.All      Read group membership"
            echo "  - Reports.Read.All    Usage reports for change rate"
            echo "  - Directory.Read.All  Read Entra ID users/groups"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║          CCA CloudShell - M365 Permission Setup               ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    echo -e "${RED}Error: Azure CLI not found.${NC}"
    echo "Install from: https://docs.microsoft.com/cli/azure/install-azure-cli"
    exit 1
fi

# Check if logged in
if ! az account show &> /dev/null 2>&1; then
    echo -e "${YELLOW}Not logged in. Running 'az login'...${NC}"
    az login
fi

# Get tenant info
TENANT_ID=$(az account show --query tenantId -o tsv)
TENANT_NAME=$(az account show --query tenantDisplayName -o tsv 2>/dev/null || echo "Unknown")

echo -e "${GREEN}Tenant: ${TENANT_NAME}${NC}"
echo -e "${GREEN}Tenant ID: ${TENANT_ID}${NC}"
echo ""

# Function to check for existing app
find_existing_app() {
    az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv 2>/dev/null || echo ""
}

# Function to check permissions on an app
check_app_permissions() {
    local app_id=$1
    echo -e "${CYAN}Checking permissions for app: ${app_id}${NC}"
    
    # Get required permissions
    permissions=$(az ad app show --id "$app_id" --query "requiredResourceAccess[?resourceAppId=='${GRAPH_RESOURCE_ID}'].resourceAccess[].id" -o tsv 2>/dev/null)
    
    echo ""
    echo -e "${BOLD}Permission Status:${NC}"
    
    for perm_entry in "${GRAPH_PERMISSIONS[@]}"; do
        perm_name="${perm_entry%%:*}"
        perm_id="${perm_entry##*:}"
        if echo "$permissions" | grep -q "$perm_id"; then
            echo -e "  ${GREEN}✓${NC} ${perm_name}"
        else
            echo -e "  ${RED}✗${NC} ${perm_name}"
        fi
    done
    
    # Check admin consent status
    echo ""
    sp_id=$(az ad sp list --filter "appId eq '${app_id}'" --query "[0].id" -o tsv 2>/dev/null || echo "")
    if [ -n "$sp_id" ]; then
        echo -e "${GREEN}✓ Service principal exists (app is consented)${NC}"
    else
        echo -e "${YELLOW}⚠ No service principal - admin consent may be required${NC}"
    fi
}

# Check-only mode
if [ "$CHECK_ONLY" = true ]; then
    existing_app_id=$(find_existing_app)
    
    if [ -n "$existing_app_id" ]; then
        echo -e "${GREEN}Found existing app registration: ${APP_NAME}${NC}"
        echo -e "App ID: ${existing_app_id}"
        check_app_permissions "$existing_app_id"
    else
        echo -e "${YELLOW}No app registration found with name: ${APP_NAME}${NC}"
        echo ""
        echo "Run without --check to create a new app registration."
    fi
    exit 0
fi

# Grant consent only mode
if [ "$GRANT_CONSENT_ONLY" = true ]; then
    existing_app_id=$(find_existing_app)
    
    if [ -z "$existing_app_id" ]; then
        echo -e "${RED}No app registration found with name: ${APP_NAME}${NC}"
        exit 1
    fi
    
    echo -e "${CYAN}Granting admin consent for app: ${existing_app_id}${NC}"
    
    # Create service principal if it doesn't exist
    sp_id=$(az ad sp list --filter "appId eq '${existing_app_id}'" --query "[0].id" -o tsv 2>/dev/null || echo "")
    if [ -z "$sp_id" ]; then
        echo "Creating service principal..."
        az ad sp create --id "$existing_app_id" --output none
    fi
    
    # Grant admin consent
    echo "Granting admin consent (this may take a moment)..."
    if az ad app permission admin-consent --id "$existing_app_id" 2>/dev/null; then
        echo -e "${GREEN}✓ Admin consent granted successfully${NC}"
    else
        echo -e "${YELLOW}⚠ Could not grant consent automatically.${NC}"
        echo ""
        echo "Please grant consent manually in the Azure Portal:"
        echo "  1. Go to: https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/CallAnAPI/appId/${existing_app_id}"
        echo "  2. Click 'Grant admin consent for ${TENANT_NAME}'"
    fi
    exit 0
fi

# Check for existing app
existing_app_id=$(find_existing_app)

if [ -n "$existing_app_id" ]; then
    echo -e "${YELLOW}App registration already exists: ${APP_NAME}${NC}"
    echo -e "App ID: ${existing_app_id}"
    echo ""
    read -p "Do you want to use the existing app? (y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Exiting. Use --app-name to specify a different name."
        exit 1
    fi
    APP_ID="$existing_app_id"
else
    # Create app registration
    echo -e "${CYAN}Creating app registration: ${APP_NAME}${NC}"
    
    APP_ID=$(az ad app create \
        --display-name "$APP_NAME" \
        --sign-in-audience "AzureADMyOrg" \
        --query appId -o tsv)
    
    if [ -z "$APP_ID" ]; then
        echo -e "${RED}Failed to create app registration${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Created app registration${NC}"
    echo -e "  App ID: ${APP_ID}"
fi

# Build permission request JSON
echo ""
echo -e "${CYAN}Configuring Microsoft Graph permissions...${NC}"

# Build the resource access array
RESOURCE_ACCESS=""
for perm_entry in "${GRAPH_PERMISSIONS[@]}"; do
    perm_id="${perm_entry##*:}"
    if [ -n "$RESOURCE_ACCESS" ]; then
        RESOURCE_ACCESS="${RESOURCE_ACCESS},"
    fi
    RESOURCE_ACCESS="${RESOURCE_ACCESS}{\"id\":\"${perm_id}\",\"type\":\"Role\"}"
done

# Add permissions to app
az ad app update --id "$APP_ID" \
    --required-resource-accesses "[{\"resourceAppId\":\"${GRAPH_RESOURCE_ID}\",\"resourceAccess\":[${RESOURCE_ACCESS}]}]" \
    --output none 2>/dev/null

echo -e "${GREEN}✓ Added Graph API permissions:${NC}"
for perm_entry in "${GRAPH_PERMISSIONS[@]}"; do
    perm_name="${perm_entry%%:*}"
    echo "    - ${perm_name}"
done

# Create service principal if it doesn't exist
echo ""
echo -e "${CYAN}Creating service principal...${NC}"

sp_id=$(az ad sp list --filter "appId eq '${APP_ID}'" --query "[0].id" -o tsv 2>/dev/null || echo "")
if [ -z "$sp_id" ]; then
    az ad sp create --id "$APP_ID" --output none
    echo -e "${GREEN}✓ Service principal created${NC}"
else
    echo -e "${GREEN}✓ Service principal already exists${NC}"
fi

# Create client secret
echo ""
echo -e "${CYAN}Creating client secret...${NC}"

# Calculate end date
END_DATE=$(date -v+${SECRET_VALIDITY_YEARS}y +%Y-%m-%d 2>/dev/null || date -d "+${SECRET_VALIDITY_YEARS} year" +%Y-%m-%d)

CLIENT_SECRET=$(az ad app credential reset \
    --id "$APP_ID" \
    --display-name "CCA Collector Secret" \
    --end-date "$END_DATE" \
    --query password -o tsv 2>/dev/null)

if [ -z "$CLIENT_SECRET" ]; then
    echo -e "${RED}Failed to create client secret${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Client secret created (valid until ${END_DATE})${NC}"

# Grant admin consent
echo ""
echo -e "${CYAN}Granting admin consent...${NC}"

if az ad app permission admin-consent --id "$APP_ID" 2>/dev/null; then
    echo -e "${GREEN}✓ Admin consent granted${NC}"
else
    echo -e "${YELLOW}⚠ Could not grant consent automatically.${NC}"
    echo ""
    echo "You may need to grant consent manually in the Azure Portal:"
    echo "  https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/CallAnAPI/appId/${APP_ID}"
fi

# Output results
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}                    Setup Complete!                             ${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BOLD}App Registration Details:${NC}"
echo -e "  App Name:      ${APP_NAME}"
echo -e "  App ID:        ${APP_ID}"
echo -e "  Tenant ID:     ${TENANT_ID}"
echo ""
echo -e "${BOLD}Environment Variables:${NC}"
echo ""
echo -e "${CYAN}export MS365_TENANT_ID=\"${TENANT_ID}\"${NC}"
echo -e "${CYAN}export MS365_CLIENT_ID=\"${APP_ID}\"${NC}"
echo -e "${CYAN}export MS365_CLIENT_SECRET=\"${CLIENT_SECRET}\"${NC}"
echo ""

# Write to env file if requested
if [ -n "$OUTPUT_ENV_FILE" ]; then
    cat > "$OUTPUT_ENV_FILE" << EOF
# CCA CloudShell M365 Credentials
# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
# App: ${APP_NAME}

export MS365_TENANT_ID="${TENANT_ID}"
export MS365_CLIENT_ID="${APP_ID}"
export MS365_CLIENT_SECRET="${CLIENT_SECRET}"
EOF
    echo -e "${GREEN}✓ Credentials written to: ${OUTPUT_ENV_FILE}${NC}"
    echo -e "${YELLOW}  ⚠ Keep this file secure and do not commit to version control${NC}"
    echo ""
fi

echo -e "${BOLD}Next Steps:${NC}"
echo "  1. Set the environment variables above (or source the env file)"
echo "  2. Run the M365 collector:"
echo ""
echo -e "${CYAN}     python m365_collect.py${NC}"
echo ""
echo "  3. Or use the unified collector:"
echo ""
echo -e "${CYAN}     python collect.py --cloud m365${NC}"
echo ""

# Security notes
echo -e "${YELLOW}Security Notes:${NC}"
echo "  • Store credentials securely (e.g., environment variables, secrets manager)"
echo "  • Do not commit credentials to version control"
echo "  • The client secret expires on ${END_DATE}"
echo "  • Rotate credentials periodically for security"
echo ""

# Verify permissions can be used
echo -e "${CYAN}Verifying setup...${NC}"
sleep 2  # Give Azure a moment to propagate

# Test if we can get a token (this validates the app registration worked)
if command -v curl &> /dev/null; then
    token_response=$(curl -s -X POST \
        "https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=${APP_ID}&client_secret=${CLIENT_SECRET}&scope=https://graph.microsoft.com/.default&grant_type=client_credentials" \
        2>/dev/null || echo "")
    
    if echo "$token_response" | grep -q "access_token"; then
        echo -e "${GREEN}✓ Successfully obtained access token${NC}"
        echo -e "${GREEN}✓ App registration is working correctly${NC}"
    else
        echo -e "${YELLOW}⚠ Could not verify token - admin consent may still be propagating${NC}"
        echo "  Wait a few minutes and try running the collector"
    fi
else
    echo -e "${YELLOW}⚠ curl not available, skipping token verification${NC}"
fi

echo ""
echo -e "${GREEN}Setup complete!${NC}"
