#!/bin/bash
# CCA CloudShell - Run All Collectors
# Combines output from AWS, Azure, GCP, and M365 collectors

set -e

OUTPUT_DIR="${1:-./cca_combined_output}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "========================================"
echo "CCA CloudShell - Combined Collection"
echo "========================================"
echo "Output Directory: $OUTPUT_DIR"
echo "Timestamp: $TIMESTAMP"
echo "========================================"

mkdir -p "$OUTPUT_DIR"

# Initialize combined results
COMBINED_INVENTORY="[]"
TOTAL_RESOURCES=0
TOTAL_STORAGE_GB=0

# AWS Collection (if credentials available)
if command -v aws &> /dev/null && aws sts get-caller-identity &> /dev/null 2>&1; then
    echo ""
    echo ">>> Running AWS Collector..."
    AWS_OUTPUT="$OUTPUT_DIR/aws"
    python3 aws_collect.py -o "$AWS_OUTPUT" 2>&1 || true
    
    # Find the latest inventory file
    AWS_INVENTORY=$(ls -t "$AWS_OUTPUT"/inventory_*.json 2>/dev/null | head -1)
    if [ -n "$AWS_INVENTORY" ] && [ -f "$AWS_INVENTORY" ]; then
        echo "AWS inventory: $AWS_INVENTORY"
    fi
else
    echo ""
    echo ">>> Skipping AWS (no credentials configured)"
fi

# Azure Collection (if credentials available)
if python3 -c "from azure.identity import DefaultAzureCredential; DefaultAzureCredential()" &> /dev/null 2>&1; then
    echo ""
    echo ">>> Running Azure Collector..."
    AZURE_OUTPUT="$OUTPUT_DIR/azure"
    python3 azure_collect.py -o "$AZURE_OUTPUT" 2>&1 || true
    
    AZURE_INVENTORY=$(ls -t "$AZURE_OUTPUT"/inventory_*.json 2>/dev/null | head -1)
    if [ -n "$AZURE_INVENTORY" ] && [ -f "$AZURE_INVENTORY" ]; then
        echo "Azure inventory: $AZURE_INVENTORY"
    fi
else
    echo ""
    echo ">>> Skipping Azure (no credentials configured)"
    echo "    Set up Azure credentials or run in Azure Cloud Shell"
fi

# GCP Collection (if credentials available)
if python3 -c "import google.auth; google.auth.default()" &> /dev/null 2>&1; then
    echo ""
    echo ">>> Running GCP Collector..."
    GCP_OUTPUT="$OUTPUT_DIR/gcp"
    python3 gcp_collect.py --output "$GCP_OUTPUT" 2>&1 || true
    
    GCP_INVENTORY=$(ls -t "$GCP_OUTPUT"/cca_inv_*.json 2>/dev/null | head -1)
    if [ -n "$GCP_INVENTORY" ] && [ -f "$GCP_INVENTORY" ]; then
        echo "GCP inventory: $GCP_INVENTORY"
    fi
else
    echo ""
    echo ">>> Skipping GCP (no credentials configured)"
    echo "    Set up GCP credentials or run in Google Cloud Shell"
fi

# M365 Collection (if credentials available)
if [ -n "$MS365_TENANT_ID" ] && [ -n "$MS365_CLIENT_ID" ] && [ -n "$MS365_CLIENT_SECRET" ]; then
    echo ""
    echo ">>> Running M365 Collector..."
    M365_OUTPUT="$OUTPUT_DIR/m365"
    python3 m365_collect.py -o "$M365_OUTPUT" 2>&1 || true
    
    M365_INVENTORY=$(ls -t "$M365_OUTPUT"/inventory_*.json 2>/dev/null | head -1)
    if [ -n "$M365_INVENTORY" ] && [ -f "$M365_INVENTORY" ]; then
        echo "M365 inventory: $M365_INVENTORY"
    fi
else
    echo ""
    echo ">>> Skipping M365 (credentials not configured)"
    echo "    Set MS365_TENANT_ID, MS365_CLIENT_ID, MS365_CLIENT_SECRET env vars"
fi

echo ""
echo "========================================"
echo "Collection Complete"
echo "========================================"
echo "Output directory: $OUTPUT_DIR"
echo ""
echo "Individual outputs:"
echo "  AWS:   $OUTPUT_DIR/aws/"
echo "  Azure: $OUTPUT_DIR/azure/"
echo "  GCP:   $OUTPUT_DIR/gcp/"
echo "  M365:  $OUTPUT_DIR/m365/"
echo "========================================"
