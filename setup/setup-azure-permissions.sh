#!/bin/bash
# CCA CloudShell - Azure Permission Setup
#
# This script assigns the Reader role to enable the CCA collector.
# Run this for each subscription you want to collect from.
#
# Prerequisites:
#   - Azure CLI installed and logged in (az login)
#   - Owner or User Access Administrator role on the subscription
#
# Usage:
#   ./setup-azure-permissions.sh                    # Current subscription
#   ./setup-azure-permissions.sh <subscription-id>  # Specific subscription
#   ./setup-azure-permissions.sh --all              # All accessible subscriptions

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║           CCA CloudShell - Azure Permission Setup             ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    echo -e "${RED}Error: Azure CLI not found. Install from: https://docs.microsoft.com/cli/azure/install-azure-cli${NC}"
    exit 1
fi

# Check if logged in
if ! az account show &> /dev/null; then
    echo -e "${YELLOW}Not logged in. Running 'az login'...${NC}"
    az login
fi

# Get current user
CURRENT_USER=$(az ad signed-in-user show --query id -o tsv 2>/dev/null || echo "")
CURRENT_USER_NAME=$(az ad signed-in-user show --query userPrincipalName -o tsv 2>/dev/null || echo "Service Principal")

echo -e "${GREEN}Logged in as: ${CURRENT_USER_NAME}${NC}"
echo ""

# Function to assign Reader role to a subscription
assign_reader_role() {
    local sub_id=$1
    local sub_name=$2
    
    echo -e "${CYAN}Processing subscription: ${sub_name} (${sub_id})${NC}"
    
    # Check if Reader role is already assigned
    existing=$(az role assignment list \
        --assignee "${CURRENT_USER}" \
        --role "Reader" \
        --scope "/subscriptions/${sub_id}" \
        --query "[0].id" -o tsv 2>/dev/null || echo "")
    
    if [ -n "$existing" ]; then
        echo -e "${GREEN}  ✓ Reader role already assigned${NC}"
        return 0
    fi
    
    # Assign Reader role
    echo -e "  Assigning Reader role..."
    if az role assignment create \
        --assignee "${CURRENT_USER}" \
        --role "Reader" \
        --scope "/subscriptions/${sub_id}" \
        --output none 2>/dev/null; then
        echo -e "${GREEN}  ✓ Reader role assigned successfully${NC}"
    else
        echo -e "${YELLOW}  ⚠ Could not assign role (may already exist or lack permissions)${NC}"
    fi
}

# Determine which subscriptions to process
if [ "$1" == "--all" ]; then
    echo -e "${CYAN}Processing all accessible subscriptions...${NC}"
    echo ""
    
    # Get all subscriptions
    subscriptions=$(az account list --query "[].{id:id, name:name}" -o tsv)
    
    while IFS=$'\t' read -r sub_id sub_name; do
        assign_reader_role "$sub_id" "$sub_name"
        echo ""
    done <<< "$subscriptions"
    
elif [ -n "$1" ]; then
    # Specific subscription provided
    sub_id=$1
    sub_name=$(az account show --subscription "$sub_id" --query name -o tsv 2>/dev/null || echo "$sub_id")
    assign_reader_role "$sub_id" "$sub_name"
    
else
    # Current subscription
    sub_id=$(az account show --query id -o tsv)
    sub_name=$(az account show --query name -o tsv)
    assign_reader_role "$sub_id" "$sub_name"
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Setup complete! You can now run:${NC}"
echo -e "${CYAN}  python collect.py --cloud azure${NC}"
echo ""

# Verify access
echo -e "${CYAN}Verifying access...${NC}"
if az resource list --query "[0].name" -o tsv &>/dev/null; then
    echo -e "${GREEN}  ✓ Can list resources${NC}"
else
    echo -e "${YELLOW}  ⚠ Could not list resources - role assignment may take a few minutes to propagate${NC}"
fi
