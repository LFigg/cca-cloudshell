#!/bin/bash
# Run tests and generate protection and cost reports
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
echo "Generating Cost Reports"
echo "========================================"
echo ""

# Generate per-cloud cost reports from fixtures (typical customer workflow)
for CLOUD in aws azure gcp; do
    if [ -f "tests/fixtures/${CLOUD}/cca_cost_inv_sample.json" ] && [ -f "tests/fixtures/${CLOUD}/cca_cost_sum_sample.json" ]; then
        echo "Processing: tests/fixtures/${CLOUD}/ (${CLOUD^^} cost data)"
        $PYTHON scripts/generate_cost_report.py \
            --inventory "tests/fixtures/${CLOUD}/cca_cost_inv_sample.json" \
            --summary "tests/fixtures/${CLOUD}/cca_cost_sum_sample.json" \
            --output "tests/fixtures/${CLOUD}/cost_report.xlsx" || true
        echo ""
    fi
done

# Generate combined multi-cloud cost report (optional - all clouds)
if [ -f "tests/fixtures/cca_cost_inv_sample.json" ] && [ -f "tests/fixtures/cca_cost_sum_sample.json" ]; then
    echo "Processing: tests/fixtures/ (Multi-cloud combined data)"
    $PYTHON scripts/generate_cost_report.py \
        --inventory "tests/fixtures/cca_cost_inv_sample.json" \
        --summary "tests/fixtures/cca_cost_sum_sample.json" \
        --output "tests/fixtures/cost_report_combined.xlsx" || true
    echo ""
fi

# Check for any generated cost files from test runs
for COST_INV_FILE in $(ls -t tests/large_scale_output/*/cca_cost_inv_*.json tests/sample_output/cca_cost_inv_*.json 2>/dev/null); do
    if [ -f "$COST_INV_FILE" ]; then
        echo "Processing: $COST_INV_FILE"
        COST_DIR=$(dirname "$COST_INV_FILE")
        # Extract timestamp from inventory filename (e.g., cca_cost_inv_123456.json -> 123456)
        COST_TS=$(basename "$COST_INV_FILE" | sed 's/cca_cost_inv_\([0-9]*\)\.json/\1/')
        COST_SUM_FILE="$COST_DIR/cca_cost_sum_${COST_TS}.json"
        COST_REPORT_FILE="$COST_DIR/cost_report.xlsx"
        
        if [ -f "$COST_SUM_FILE" ]; then
            $PYTHON scripts/generate_cost_report.py --inventory "$COST_INV_FILE" --summary "$COST_SUM_FILE" --output "$COST_REPORT_FILE" || true
        else
            echo "  Warning: Summary file not found: $COST_SUM_FILE"
        fi
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
        ls -la tests/large_scale_output/$dir/*.xlsx tests/large_scale_output/$dir/*.json tests/large_scale_output/$dir/*.csv 2>/dev/null || echo "  (no files)"
    fi
done

# Also check sample_output for cost reports
if [ -d "tests/sample_output" ]; then
    echo ""
    echo "=== sample_output ==="
    ls -la tests/sample_output/*.xlsx tests/sample_output/*.json tests/sample_output/*.csv 2>/dev/null || echo "  (no files)"
fi

# Show fixtures cost reports (per-cloud)
if [ -d "tests/fixtures" ]; then
    echo ""
    echo "=== fixtures (cost reports) ==="
    for CLOUD in aws azure gcp; do
        if [ -d "tests/fixtures/${CLOUD}" ]; then
            echo "  --- ${CLOUD} ---"
            ls -la tests/fixtures/${CLOUD}/*.xlsx tests/fixtures/${CLOUD}/*.json 2>/dev/null | sed 's/^/  /' || echo "    (no files)"
        fi
    done
    echo "  --- combined (multi-cloud) ---"
    ls -la tests/fixtures/*.xlsx tests/fixtures/*.json 2>/dev/null | sed 's/^/  /' || echo "    (no files)"
fi
