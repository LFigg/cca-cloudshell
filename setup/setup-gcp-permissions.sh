#!/bin/bash
# CCA CloudShell - GCP Permission Setup
#
# This script grants the Viewer role to enable the CCA collector.
# Run this for each project you want to collect from.
#
# Prerequisites:
#   - gcloud CLI installed and authenticated (gcloud auth login)
#   - Owner or IAM Admin role on the project(s)
#
# Usage:
#   ./setup-gcp-permissions.sh                    # Current project
#   ./setup-gcp-permissions.sh <project-id>       # Specific project
#   ./setup-gcp-permissions.sh --all              # All accessible projects

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║            CCA CloudShell - GCP Permission Setup              ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}Error: gcloud CLI not found. Install from: https://cloud.google.com/sdk/docs/install${NC}"
    exit 1
fi

# Check if authenticated
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" &> /dev/null; then
    echo -e "${YELLOW}Not authenticated. Running 'gcloud auth login'...${NC}"
    gcloud auth login
fi

# Get current user/service account
CURRENT_ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)")
echo -e "${GREEN}Logged in as: ${CURRENT_ACCOUNT}${NC}"
echo ""

# Determine member format (user: or serviceAccount:)
if [[ "$CURRENT_ACCOUNT" == *"gserviceaccount.com" ]]; then
    MEMBER="serviceAccount:${CURRENT_ACCOUNT}"
else
    MEMBER="user:${CURRENT_ACCOUNT}"
fi

# Function to grant Viewer role to a project
grant_viewer_role() {
    local project_id=$1
    
    echo -e "${CYAN}Processing project: ${project_id}${NC}"
    
    # Check if Viewer role is already assigned
    existing=$(gcloud projects get-iam-policy "$project_id" \
        --flatten="bindings[].members" \
        --filter="bindings.role:roles/viewer AND bindings.members:${MEMBER}" \
        --format="value(bindings.role)" 2>/dev/null || echo "")
    
    if [ -n "$existing" ]; then
        echo -e "${GREEN}  ✓ Viewer role already assigned${NC}"
        return 0
    fi
    
    # Grant Viewer role
    echo -e "  Granting Viewer role..."
    if gcloud projects add-iam-policy-binding "$project_id" \
        --member="$MEMBER" \
        --role="roles/viewer" \
        --quiet 2>/dev/null; then
        echo -e "${GREEN}  ✓ Viewer role granted successfully${NC}"
    else
        echo -e "${YELLOW}  ⚠ Could not grant role (may already exist or lack permissions)${NC}"
    fi
}

# Determine which projects to process
if [ "$1" == "--all" ]; then
    echo -e "${CYAN}Processing all accessible projects...${NC}"
    echo ""
    
    # Get all projects
    projects=$(gcloud projects list --format="value(projectId)")
    
    for project_id in $projects; do
        grant_viewer_role "$project_id"
        echo ""
    done
    
elif [ -n "$1" ]; then
    # Specific project provided
    grant_viewer_role "$1"
    
else
    # Current project
    project_id=$(gcloud config get-value project 2>/dev/null)
    if [ -z "$project_id" ]; then
        echo -e "${YELLOW}No default project set. Specify a project:${NC}"
        echo -e "${CYAN}  ./setup-gcp-permissions.sh <project-id>${NC}"
        echo -e "${CYAN}  ./setup-gcp-permissions.sh --all${NC}"
        exit 1
    fi
    grant_viewer_role "$project_id"
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Setup complete! You can now run:${NC}"
echo -e "${CYAN}  python collect.py --cloud gcp${NC}"
echo ""

# Verify access
if [ -n "$project_id" ]; then
    echo -e "${CYAN}Verifying access...${NC}"
    if gcloud compute instances list --project="$project_id" --limit=1 &>/dev/null; then
        echo -e "${GREEN}  ✓ Can list compute instances${NC}"
    else
        echo -e "${YELLOW}  ⚠ Could not list instances - role may take a few minutes to propagate${NC}"
    fi
fi
