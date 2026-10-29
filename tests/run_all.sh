#!/bin/sh
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

echo "${BOLD}====================================================${NC}"
echo "${BOLD}         proc-sentry Regression Test Suite          ${NC}"
echo "${BOLD}====================================================${NC}"

run_test() {
    TEST_NAME="$1"
    TEST_BIN="$2"

    echo ""
    echo "[*] Running: ${TEST_NAME} (${TEST_BIN})..."
    if "./${TEST_BIN}"; then
        echo "${GREEN}[PASS] ${TEST_NAME}${NC}"
    else
        echo "${RED}[FAIL] ${TEST_NAME}${NC}"
        exit 1
    fi
}

# Ensure all test binaries exist
run_test "Stage 1: Process Crawler" "test_crawler"
run_test "Stage 2: Exe Symlink Audit" "test_exe"
run_test "Stage 3: Memory Maps Scanner" "test_maps"
run_test "Stage 5: Environment Audit" "test_env"

echo ""
echo "${BOLD}====================================================${NC}"
echo "${GREEN}${BOLD}[+] All regression tests passed successfully!${NC}"
echo "${BOLD}====================================================${NC}"
