#!/bin/bash
# CCA CloudShell - AWS Permission Setup
#
# This script deploys the IAM role needed for the CCA collector.
# For multi-account setups, it can also deploy to member accounts via StackSets.
#
# Prerequisites:
#   - AWS CLI installed and configured
#   - Sufficient IAM permissions to create roles/stacks
#
# Usage:
#   ./setup-aws-permissions.sh                    # Single account setup
#   ./setup-aws-permissions.sh --external-id XXX  # With external ID for security
#   ./setup-aws-permissions.sh --stackset         # Deploy to all org accounts
#   ./setup-aws-permissions.sh --check            # Check existing permissions

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Defaults
STACK_NAME="cca-collector"
ROLE_NAME="CCACollectorRole"
EXTERNAL_ID=""
USE_STACKSET=false
CHECK_ONLY=false
ENABLE_ORG=false
ENABLE_COST=false
TEMPLATE_FILE="setup/aws-iam-role.yaml"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --external-id)
            EXTERNAL_ID="$2"
            shift 2
            ;;
        --role-name)
            ROLE_NAME="$2"
            shift 2
            ;;
        --stack-name)
            STACK_NAME="$2"
            shift 2
            ;;
        --stackset)
            USE_STACKSET=true
            shift
            ;;
        --enable-org)
            ENABLE_ORG=true
            shift
            ;;
        --enable-cost)
            ENABLE_COST=true
            shift
            ;;
        --check)
            CHECK_ONLY=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --external-id ID    Set external ID for cross-account security"
            echo "  --role-name NAME    IAM role name (default: CCACollectorRole)"
            echo "  --stack-name NAME   CloudFormation stack name (default: cca-collector)"
            echo "  --stackset          Deploy to all Organization accounts via StackSet"
            echo "  --enable-org        Enable Organizations API access (for --org-role)"
            echo "  --enable-cost       Enable Cost Explorer API access (for cost_collect.py)"
            echo "  --check             Check existing permissions without deploying"
            echo "  --help              Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║            CCA CloudShell - AWS Permission Setup              ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI not found.${NC}"
    echo "Install from: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
    exit 1
fi

# Check credentials
echo -e "${CYAN}Checking AWS credentials...${NC}"
if ! IDENTITY=$(aws sts get-caller-identity 2>/dev/null); then
    echo -e "${RED}Error: AWS credentials not configured.${NC}"
    echo "Configure with: aws configure"
    echo "Or use environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY"
    exit 1
fi

ACCOUNT_ID=$(echo "$IDENTITY" | grep -o '"Account": "[^"]*' | cut -d'"' -f4)
USER_ARN=$(echo "$IDENTITY" | grep -o '"Arn": "[^"]*' | cut -d'"' -f4)

echo -e "${GREEN}  Account:  ${ACCOUNT_ID}${NC}"
echo -e "${GREEN}  Identity: ${USER_ARN}${NC}"
echo ""

# Check-only mode
if [ "$CHECK_ONLY" = true ]; then
    echo -e "${CYAN}Checking existing permissions...${NC}"
    echo ""
    
    # Check EC2
    if aws ec2 describe-regions --query "Regions[0].RegionName" --output text &>/dev/null; then
        echo -e "${GREEN}  ✓ EC2: DescribeRegions${NC}"
    else
        echo -e "${RED}  ✗ EC2: No access${NC}"
    fi
    
    # Check S3
    if aws s3api list-buckets --query "Buckets[0].Name" --output text &>/dev/null; then
        echo -e "${GREEN}  ✓ S3: ListBuckets${NC}"
    else
        echo -e "${RED}  ✗ S3: No access${NC}"
    fi
    
    # Check RDS
    if aws rds describe-db-instances --max-records 1 &>/dev/null; then
        echo -e "${GREEN}  ✓ RDS: DescribeDBInstances${NC}"
    else
        echo -e "${YELLOW}  ⚠ RDS: No access (may not have instances)${NC}"
    fi
    
    # Check Organizations
    if aws organizations describe-organization &>/dev/null; then
        echo -e "${GREEN}  ✓ Organizations: Access enabled${NC}"
    else
        echo -e "${YELLOW}  – Organizations: No access (single account mode)${NC}"
    fi
    
    # Check AWS Backup
    if aws backup list-backup-vaults --max-results 1 &>/dev/null; then
        echo -e "${GREEN}  ✓ AWS Backup: ListBackupVaults${NC}"
    else
        echo -e "${YELLOW}  ⚠ AWS Backup: No access${NC}"
    fi
    
    # Check Cost Explorer
    if aws ce get-cost-and-usage --time-period Start=$(date -v-1d +%Y-%m-%d),End=$(date +%Y-%m-%d) --granularity DAILY --metrics "BlendedCost" &>/dev/null; then
        echo -e "${GREEN}  ✓ Cost Explorer: Access enabled${NC}"
    else
        echo -e "${YELLOW}  – Cost Explorer: No access${NC}"
    fi
    
    echo ""
    echo -e "${CYAN}To deploy the CCA collector role, run:${NC}"
    echo -e "  $0"
    exit 0
fi

# Find template file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/aws-iam-role.yaml" ]; then
    TEMPLATE_FILE="$SCRIPT_DIR/aws-iam-role.yaml"
elif [ -f "setup/aws-iam-role.yaml" ]; then
    TEMPLATE_FILE="setup/aws-iam-role.yaml"
elif [ -f "aws-iam-role.yaml" ]; then
    TEMPLATE_FILE="aws-iam-role.yaml"
else
    echo -e "${RED}Error: Cannot find aws-iam-role.yaml template${NC}"
    exit 1
fi

echo -e "${CYAN}Using template: ${TEMPLATE_FILE}${NC}"
echo ""

# Build parameters
PARAMS="ParameterKey=RoleName,ParameterValue=${ROLE_NAME}"

if [ -n "$EXTERNAL_ID" ]; then
    PARAMS="$PARAMS ParameterKey=ExternalId,ParameterValue=${EXTERNAL_ID}"
fi

if [ "$ENABLE_ORG" = true ]; then
    PARAMS="$PARAMS ParameterKey=EnableOrganizationsAccess,ParameterValue=true"
fi

if [ "$ENABLE_COST" = true ]; then
    PARAMS="$PARAMS ParameterKey=EnableCostExplorerAccess,ParameterValue=true"
fi

# StackSet deployment for multi-account
if [ "$USE_STACKSET" = true ]; then
    echo -e "${CYAN}Deploying via CloudFormation StackSet (Organization-wide)...${NC}"
    
    # Check if we're in management account
    if ! aws organizations describe-organization &>/dev/null; then
        echo -e "${RED}Error: StackSet deployment requires Organizations access.${NC}"
        echo "Run from the management account or a delegated administrator."
        exit 1
    fi
    
    STACKSET_NAME="${STACK_NAME}-roles"
    
    # Add trusted account for cross-account access
    PARAMS="$PARAMS ParameterKey=TrustedAccountId,ParameterValue=${ACCOUNT_ID}"
    
    # Check if StackSet exists
    if aws cloudformation describe-stack-set --stack-set-name "$STACKSET_NAME" &>/dev/null; then
        echo -e "${YELLOW}StackSet already exists. Updating...${NC}"
        aws cloudformation update-stack-set \
            --stack-set-name "$STACKSET_NAME" \
            --template-body "file://${TEMPLATE_FILE}" \
            --capabilities CAPABILITY_NAMED_IAM \
            --parameters $PARAMS \
            --operation-preferences FailureToleranceCount=0,MaxConcurrentCount=10
    else
        echo -e "${CYAN}Creating StackSet...${NC}"
        aws cloudformation create-stack-set \
            --stack-set-name "$STACKSET_NAME" \
            --template-body "file://${TEMPLATE_FILE}" \
            --capabilities CAPABILITY_NAMED_IAM \
            --permission-model SERVICE_MANAGED \
            --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
            --parameters $PARAMS
        
        echo -e "${CYAN}Deploying to all accounts in organization...${NC}"
        
        # Get root OU
        ROOT_ID=$(aws organizations list-roots --query "Roots[0].Id" --output text)
        
        aws cloudformation create-stack-instances \
            --stack-set-name "$STACKSET_NAME" \
            --deployment-targets OrganizationalUnitIds="$ROOT_ID" \
            --regions "$(aws ec2 describe-regions --query 'Regions[0].RegionName' --output text)"
    fi
    
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}StackSet deployment initiated!${NC}"
    echo -e "${CYAN}Check status with:${NC}"
    echo -e "  aws cloudformation list-stack-instances --stack-set-name ${STACKSET_NAME}"
    echo ""
    echo -e "${CYAN}Once complete, run:${NC}"
    echo -e "  python collect.py --cloud aws -- --org-role ${ROLE_NAME}"
    
else
    # Single account deployment
    echo -e "${CYAN}Deploying CloudFormation stack...${NC}"
    
    # Check if stack exists
    if aws cloudformation describe-stacks --stack-name "$STACK_NAME" &>/dev/null; then
        echo -e "${YELLOW}Stack already exists. Updating...${NC}"
        if aws cloudformation update-stack \
            --stack-name "$STACK_NAME" \
            --template-body "file://${TEMPLATE_FILE}" \
            --capabilities CAPABILITY_NAMED_IAM \
            --parameters $PARAMS 2>/dev/null; then
            echo -e "${CYAN}Waiting for update to complete...${NC}"
            aws cloudformation wait stack-update-complete --stack-name "$STACK_NAME"
        else
            echo -e "${GREEN}No changes needed.${NC}"
        fi
    else
        echo -e "${CYAN}Creating stack...${NC}"
        aws cloudformation create-stack \
            --stack-name "$STACK_NAME" \
            --template-body "file://${TEMPLATE_FILE}" \
            --capabilities CAPABILITY_NAMED_IAM \
            --parameters $PARAMS
        
        echo -e "${CYAN}Waiting for stack creation to complete...${NC}"
        aws cloudformation wait stack-create-complete --stack-name "$STACK_NAME"
    fi
    
    # Get role ARN
    ROLE_ARN=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --query "Stacks[0].Outputs[?OutputKey=='RoleArn'].OutputValue" \
        --output text 2>/dev/null || echo "")
    
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Setup complete!${NC}"
    if [ -n "$ROLE_ARN" ]; then
        echo -e "${CYAN}  Role ARN: ${ROLE_ARN}${NC}"
    fi
    echo ""
    echo -e "${CYAN}You can now run:${NC}"
    echo -e "  python collect.py --cloud aws"
fi

echo ""
