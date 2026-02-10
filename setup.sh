#!/bin/bash
# CCA CloudShell - Setup Script
# Run this script first to install dependencies
#
# Quick Start:
#   curl -sL https://github.com/LFigg/cca-cloudshell/archive/refs/heads/main.tar.gz | tar xz
#   cd cca-cloudshell-main
#   ./setup.sh

set -e

echo "========================================"
echo "CCA CloudShell - Setup"
echo "========================================"

# Detect environment
if [ -n "$AWS_EXECUTION_ENV" ]; then
    echo "Detected: AWS CloudShell"
    SHELL_TYPE="aws"
elif [ -n "$ACC_TERM_ID" ] || [ -d "/home/$USER/clouddrive" ]; then
    echo "Detected: Azure Cloud Shell"
    SHELL_TYPE="azure"
else
    echo "Detected: Local/Other environment"
    SHELL_TYPE="local"
fi

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
echo "Python version: $PYTHON_VERSION"

# Install dependencies based on collector type
echo ""
echo "Which collector(s) do you want to set up?"
echo "  1) AWS only (minimal dependencies)"
echo "  2) Azure only"
echo "  3) M365 only"
echo "  4) All collectors"
echo ""
read -p "Enter choice [1-4, default=4]: " choice
choice=${choice:-4}

case $choice in
    1)
        echo "Installing AWS dependencies..."
        pip3 install --quiet boto3
        ;;
    2)
        echo "Installing Azure dependencies..."
        pip3 install --quiet azure-identity azure-mgmt-compute azure-mgmt-storage \
            azure-mgmt-sql azure-mgmt-cosmosdb azure-mgmt-containerservice \
            azure-mgmt-web azure-mgmt-resource
        ;;
    3)
        echo "Installing M365 dependencies..."
        pip3 install --quiet msgraph-sdk azure-identity
        ;;
    4)
        echo "Installing all dependencies..."
        pip3 install --quiet -r requirements.txt
        ;;
    *)
        echo "Invalid choice. Installing all dependencies..."
        pip3 install --quiet -r requirements.txt
        ;;
esac

echo ""
echo "========================================"
echo "Setup complete!"
echo "========================================"
echo ""
echo "Run the collectors:"
echo "  AWS:   python3 aws_collect.py --help"
echo "  Azure: python3 azure_collect.py --help"
echo "  M365:  python3 m365_collect.py --help"
echo ""

# Quick test
if [ "$SHELL_TYPE" = "aws" ]; then
    echo "AWS CloudShell detected - you can run aws_collect.py immediately"
    echo "Your AWS credentials are already configured."
elif [ "$SHELL_TYPE" = "azure" ]; then
    echo "Azure Cloud Shell detected - you can run azure_collect.py immediately"
    echo "Your Azure credentials are already configured via DefaultAzureCredential."
fi
