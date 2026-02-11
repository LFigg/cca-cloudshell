#!/bin/bash
# Run tests and generate protection report
#
# Usage: ./tests/run_tests_and_report.sh [test_type]
#   test_type: all (default), unit, large-all, large-aws, large-azure, large-gcp, large-m365

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Use python3 if python is not available
PYTHON="${PYTHON:-$(command -v python3 || command -v python)}"

TEST_TYPE="${1:-all}"

echo "========================================"
echo "CCA CloudShell - Test & Report Runner"
echo "========================================"
echo ""

# Run tests based on type
case "$TEST_TYPE" in
    large-aws)
        echo "Running AWS large-scale integration test..."
        $PYTHON -m pytest tests/test_large_scale_aws.py -v -s
        INVENTORY="tests/large_scale_output/aws/cca_inv_*.json"
        ;;
    large-azure)
        echo "Running Azure large-scale integration test..."
        $PYTHON -m pytest tests/test_large_scale_azure.py -v -s
        INVENTORY="tests/large_scale_output/azure/cca_inv_*.json"
        ;;
    large-gcp)
        echo "Running GCP large-scale integration test..."
        $PYTHON -m pytest tests/test_large_scale_gcp.py -v -s
        INVENTORY="tests/large_scale_output/gcp/cca_inv_*.json"
        ;;
    large-m365)
        echo "Running M365 large-scale integration test..."
        $PYTHON -m pytest tests/test_large_scale_m365.py -v -s
        INVENTORY="tests/large_scale_output/m365/cca_inv_*.json"
        ;;
    large-all)
        echo "Running all large-scale integration tests..."
        $PYTHON -m pytest tests/test_large_scale_*.py -v -s
        INVENTORY="tests/large_scale_output/*/cca_inv_*.json"
        ;;
    unit)
        echo "Running unit tests..."
        $PYTHON -m pytest tests/test_aws_collect.py tests/test_azure_collect.py tests/test_gcp_collect.py tests/test_m365_collect.py -v
        echo ""
        echo "Unit tests complete. No inventory generated."
        exit 0
        ;;
    all|*)
        echo "Running all tests..."
        $PYTHON -m pytest tests/ -v
        INVENTORY="tests/large_scale_output/*/cca_inv_*.json"
        ;;
esac

echo ""
echo "========================================"
echo "Generating Protection Reports"
echo "========================================"
echo ""

# Find all inventory files and generate reports
for INV_FILE in $(ls -t $INVENTORY 2>/dev/null); do
    if [ -f "$INV_FILE" ]; then
        echo "Processing: $INV_FILE"
        REPORT_DIR=$(dirname "$INV_FILE")
        REPORT_FILE="$REPORT_DIR/protection_report.xlsx"
        $PYTHON scripts/generate_protection_report.py "$INV_FILE" "$REPORT_FILE" || true
        echo ""
    fi
done

echo ""
echo "========================================"
echo "Complete!"
echo "========================================"
echo ""
echo "Output files:"
for dir in aws azure gcp m365; do
    if [ -d "tests/large_scale_output/$dir" ]; then
        echo ""
        echo "=== $dir ==="
        ls -la tests/large_scale_output/$dir/*.xlsx tests/large_scale_output/$dir/*.json 2>/dev/null || echo "  (no files)"
    fi
done
