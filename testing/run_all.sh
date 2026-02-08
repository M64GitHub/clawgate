#!/usr/bin/env bash
#
# ClawGate Integration Test Runner
#
# Builds the project, then runs each test suite sequentially.
# Supports selective runs: ./run_all.sh file_ops git security

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BOLD='' NC=''
fi

# All suites in default order
ALL_SUITES=(
    tokens
    file_ops
    git
    security
    tools
    mcp
    daemon
)

# Select suites to run
if [ $# -gt 0 ]; then
    SUITES=("$@")
else
    SUITES=("${ALL_SUITES[@]}")
fi

# Build
echo -e "${BOLD}Building ClawGate...${NC}"
if ! (cd "$PROJECT_DIR" && zig build 2>&1); then
    echo -e "${RED}Build failed${NC}"
    exit 1
fi
echo -e "${GREEN}Build OK${NC}"
echo ""

# Run suites
declare -A RESULTS
TOTAL_PASS=0
TOTAL_FAIL=0

for suite in "${SUITES[@]}"; do
    script="$SCRIPT_DIR/test_${suite}.sh"
    if [ ! -f "$script" ]; then
        echo -e "${YELLOW}SKIP${NC}: $script not found"
        RESULTS[$suite]="SKIP"
        continue
    fi

    echo -e "${BOLD}Running: test_${suite}.sh${NC}"
    echo "----------------------------------------"

    set +e
    bash "$script"
    rc=$?
    set -e

    if [ "$rc" -eq 0 ]; then
        RESULTS[$suite]="PASS"
        TOTAL_PASS=$((TOTAL_PASS + 1))
    else
        RESULTS[$suite]="FAIL($rc)"
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
    fi
    echo ""
done

# Grand summary
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}  Grand Summary${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""

for suite in "${SUITES[@]}"; do
    result="${RESULTS[$suite]:-SKIP}"
    case "$result" in
        PASS)
            echo -e "  ${GREEN}PASS${NC}  test_${suite}.sh"
            ;;
        SKIP)
            echo -e "  ${YELLOW}SKIP${NC}  test_${suite}.sh"
            ;;
        *)
            echo -e "  ${RED}${result}${NC}  test_${suite}.sh"
            ;;
    esac
done

echo ""
echo -e "Suites passed: $TOTAL_PASS  Failed: $TOTAL_FAIL"
echo ""

if [ "$TOTAL_FAIL" -gt 0 ]; then
    echo -e "${RED}SOME SUITES FAILED${NC}"
    exit 1
fi

echo -e "${GREEN}ALL SUITES PASSED${NC}"
exit 0
