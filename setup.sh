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
elif [ "$CLOUD_SHELL" = "true" ] || [ -n "$DEVSHELL_GCLOUD_CONFIG" ]; then
    echo "Detected: Google Cloud Shell"
    SHELL_TYPE="gcp"
else
    echo "Detected: Local/Other environment"
    SHELL_TYPE="local"
fi

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
echo "Python version: $PYTHON_VERSION"

# Set pip flags based on environment (Azure Cloud Shell requires --user)
PIP_FLAGS="--quiet"
if [ "$SHELL_TYPE" = "azure" ]; then
    PIP_FLAGS="--quiet --user"
    echo "Note: Using --user flag for pip (required in Azure Cloud Shell)"
fi

# Install dependencies based on collector type
echo ""
echo "Which collector(s) do you want to set up?"
echo "  1) AWS only (minimal dependencies)"
echo "  2) Azure only"
echo "  3) GCP only"
echo "  4) M365 only"
echo "  5) All collectors"
echo ""
read -p "Enter choice [1-5, default=5]: " choice
choice=${choice:-5}

case $choice in
    1)
        echo "Installing AWS dependencies..."
        pip3 install $PIP_FLAGS boto3 rich tenacity
        ;;
    2)
        echo "Installing Azure dependencies..."
        pip3 install $PIP_FLAGS azure-identity azure-mgmt-compute azure-mgmt-storage \
            azure-mgmt-sql azure-mgmt-cosmosdb azure-mgmt-containerservice \
            azure-mgmt-web azure-mgmt-resource azure-mgmt-subscription \
            azure-mgmt-recoveryservices azure-mgmt-recoveryservicesbackup \
            azure-mgmt-redis azure-mgmt-costmanagement azure-mgmt-rdbms \
            azure-mgmt-synapse azure-mgmt-netapp azure-storage-blob \
            rich tenacity
        ;;
    3)
        echo "Installing GCP dependencies..."
        pip3 install $PIP_FLAGS google-cloud-compute google-cloud-storage \
            google-api-python-client google-cloud-container google-cloud-functions \
            google-cloud-resource-manager rich tenacity
        ;;
    4)
        echo "Installing M365 dependencies..."
        pip3 install $PIP_FLAGS msgraph-sdk azure-identity rich tenacity
        ;;
    5)
        echo "Installing all dependencies..."
        pip3 install $PIP_FLAGS -r requirements.txt
        ;;
    *)
        echo "Invalid choice. Installing all dependencies..."
        pip3 install $PIP_FLAGS -r requirements.txt
        ;;
esac

echo ""
echo "========================================"
echo "Setup complete!"
echo "========================================"
echo ""
echo "Start collection:"
echo "  python3 collect.py              # Auto-detect cloud and collect"
echo "  python3 collect.py --setup      # Interactive setup wizard"
echo ""
echo "Direct collector access (advanced):"
echo "  python3 collect.py --cloud aws"
echo "  python3 collect.py --cloud azure"
echo "  python3 collect.py --cloud gcp"
echo "  python3 collect.py --cloud m365"
echo ""

# Environment-specific guidance and offer to run
if [ "$SHELL_TYPE" = "aws" ]; then
    echo "AWS CloudShell detected - credentials are pre-configured."
    echo ""
    read -p "Run collection now? [Y/n]: " run_now
    run_now=${run_now:-Y}
    if [[ "$run_now" =~ ^[Yy]$ ]]; then
        echo ""
        exec python3 collect.py --cloud aws
    fi
elif [ "$SHELL_TYPE" = "azure" ]; then
    echo "Azure Cloud Shell detected - credentials are pre-configured."
    echo ""
    read -p "Run collection now? [Y/n]: " run_now
    run_now=${run_now:-Y}
    if [[ "$run_now" =~ ^[Yy]$ ]]; then
        echo ""
        exec python3 collect.py --cloud azure
    fi
elif [ "$SHELL_TYPE" = "gcp" ]; then
    echo "Google Cloud Shell detected - credentials are pre-configured."
    echo ""
    read -p "Run collection now? [Y/n]: " run_now
    run_now=${run_now:-Y}
    if [[ "$run_now" =~ ^[Yy]$ ]]; then
        echo ""
        exec python3 collect.py --cloud gcp
    fi
else
    echo "Local environment detected."
    echo "Configure credentials for your target cloud before running."
    echo ""
    read -p "Run interactive setup wizard? [Y/n]: " run_wizard
    run_wizard=${run_wizard:-Y}
    if [[ "$run_wizard" =~ ^[Yy]$ ]]; then
        echo ""
        exec python3 collect.py --setup
    fi
fi

echo ""
echo "Run compatibility check: python3 tests/test_cloudshell_compat.py"
