#!/usr/bin/env bash
#
# Integration test for glob pattern matching in ClawGate.
#
# Tests all glob pattern types:
# - /** recursive wildcard
# - /* single-level wildcard
# - *.ext extension patterns
# - exact path matching

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CLAWGATE="$PROJECT_DIR/zig-out/bin/clawgate"
TEST_DIR="/tmp/clawgate_glob_test_$$"
FIXTURE_TGZ="$SCRIPT_DIR/fixtures/testdata.tgz"
PIDS_TO_KILL=()
TEST_FAILURES=0
AGENT_PID=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_test() { echo -e "${YELLOW}[TEST]${NC} $1"; }

# Assertion: command succeeds and output matches expected
assert_content_equals() {
    local desc="$1"
    local expected="$2"
    local cmd="$3"
    log_test "$desc"
    local actual
    if ! actual=$(eval "$cmd" 2>&1); then
        log_error "  FAIL: Command failed: $cmd"
        log_error "  Output: $actual"
        TEST_FAILURES=$((TEST_FAILURES + 1))
        return 1
    fi
    if [ "$expected" = "$actual" ]; then
        log_info "  PASS"
        return 0
    else
        log_error "  FAIL: Content mismatch"
        log_error "  Expected: $expected"
        log_error "  Got: $actual"
        TEST_FAILURES=$((TEST_FAILURES + 1))
        return 1
    fi
}

# Assertion: command should fail with specific error
assert_failure() {
    local desc="$1"
    local cmd="$2"
    local expected_error="$3"
    log_test "$desc (expect DENIED)"
    local output
    if output=$(eval "$cmd" 2>&1); then
        log_error "  FAIL: Expected denial but command succeeded"
        log_error "  Output: $output"
        TEST_FAILURES=$((TEST_FAILURES + 1))
        return 1
    else
        if echo "$output" | grep -q "$expected_error"; then
            log_info "  PASS: Correctly denied"
            return 0
        else
            log_error "  FAIL: Wrong error message"
            log_error "  Expected to contain: $expected_error"
            log_error "  Got: $output"
            TEST_FAILURES=$((TEST_FAILURES + 1))
            return 1
        fi
    fi
}

cleanup() {
    log_info "Cleaning up..."

    for pid in "${PIDS_TO_KILL[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done

    rm -rf "$TEST_DIR"
    rm -f ~/.clawgate/tokens/*.token 2>/dev/null || true

    if [ "$STARTED_NATS" = "1" ]; then
        log_info "Stopping nats-server..."
        killall nats-server 2>/dev/null || true
    fi

    log_info "Cleanup complete"
}

trap cleanup EXIT

# Clear tokens and restart agent daemon
clear_tokens() {
    rm -f ~/.clawgate/tokens/*.token 2>/dev/null || true
    if [ -n "$AGENT_PID" ] && kill -0 "$AGENT_PID" 2>/dev/null; then
        kill "$AGENT_PID" 2>/dev/null || true
    fi
    sleep 0.3
    "$CLAWGATE" --mode agent &
    AGENT_PID=$!
    PIDS_TO_KILL+=($AGENT_PID)
    sleep 0.5
}

# === PREREQUISITES ===

if [ ! -x "$CLAWGATE" ]; then
    log_error "clawgate not found at $CLAWGATE"
    log_error "Run 'zig build' first"
    exit 1
fi

if [ ! -f "$FIXTURE_TGZ" ]; then
    log_error "Test fixture not found: $FIXTURE_TGZ"
    log_error "Run: bash tests/create_fixture.sh"
    exit 1
fi

# === SETUP ===

mkdir -p "$TEST_DIR"
log_info "Test directory: $TEST_DIR"

tar -xzf "$FIXTURE_TGZ" -C "$TEST_DIR"
log_info "Extracted test fixture"

STARTED_NATS=0
if ! pgrep -x nats-server >/dev/null; then
    log_info "Starting nats-server..."
    nats-server &
    PIDS_TO_KILL+=($!)
    STARTED_NATS=1
    sleep 1
else
    log_info "nats-server already running"
fi

log_info "Generating keys..."
"$CLAWGATE" keygen --force

log_info "Starting resource daemon..."
"$CLAWGATE" --mode resource &
RESOURCE_PID=$!
PIDS_TO_KILL+=($RESOURCE_PID)
sleep 1

if ! kill -0 "$RESOURCE_PID" 2>/dev/null; then
    log_error "Resource daemon failed to start"
    exit 1
fi
log_info "Resource daemon running (PID: $RESOURCE_PID)"

mkdir -p ~/.clawgate/tokens
log_info "Starting agent daemon..."
"$CLAWGATE" --mode agent &
AGENT_PID=$!
PIDS_TO_KILL+=($AGENT_PID)
sleep 1

if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    log_error "Agent daemon failed to start"
    exit 1
fi
log_info "Agent daemon running (PID: $AGENT_PID)"

# Define test file paths
TESTDATA="$TEST_DIR/testdata"
ROOT_TXT="$TESTDATA/root.txt"
ROOT_BIN="$TESTDATA/root.bin"
LEVEL1_TXT="$TESTDATA/level1/file1.txt"
LEVEL1_ZIG="$TESTDATA/level1/file1.zig"
LEVEL2_TXT="$TESTDATA/level1/level2/deep.txt"
LEVEL2_ZIG="$TESTDATA/level1/level2/deep.zig"
LEVEL3_TXT="$TESTDATA/level1/level2/level3/deepest.txt"
OTHER_TXT="$TESTDATA/other/separate.txt"

# === TEST CASES ===

echo ""
echo "========================================"
echo "  TEST 1: Recursive Wildcard /**"
echo "========================================"
echo ""

clear_tokens

TOKEN=$("$CLAWGATE" grant --read "$TESTDATA/**")
"$CLAWGATE" token add "$TOKEN"
sleep 0.3

assert_content_equals "/** -> root.txt" \
    "$(cat "$ROOT_TXT")" \
    "\"$CLAWGATE\" cat \"$ROOT_TXT\""

assert_content_equals "/** -> level1/file1.txt" \
    "$(cat "$LEVEL1_TXT")" \
    "\"$CLAWGATE\" cat \"$LEVEL1_TXT\""

assert_content_equals "/** -> level1/level2/deep.txt" \
    "$(cat "$LEVEL2_TXT")" \
    "\"$CLAWGATE\" cat \"$LEVEL2_TXT\""

assert_content_equals "/** -> level1/level2/level3/deepest.txt" \
    "$(cat "$LEVEL3_TXT")" \
    "\"$CLAWGATE\" cat \"$LEVEL3_TXT\""

assert_content_equals "/** -> other/separate.txt" \
    "$(cat "$OTHER_TXT")" \
    "\"$CLAWGATE\" cat \"$OTHER_TXT\""


echo ""
echo "========================================"
echo "  TEST 2: Single-Level Wildcard /*"
echo "========================================"
echo ""

clear_tokens

TOKEN=$("$CLAWGATE" grant --read "$TESTDATA/*")
"$CLAWGATE" token add "$TOKEN"
sleep 0.3

assert_content_equals "/* -> root.txt (direct child)" \
    "$(cat "$ROOT_TXT")" \
    "\"$CLAWGATE\" cat \"$ROOT_TXT\""

# Binary test: verify content via xxd
log_test "/* -> root.bin (direct child, binary via xxd)"
EXPECTED_HEX=$(xxd "$ROOT_BIN")
ACTUAL_HEX=$("$CLAWGATE" cat "$ROOT_BIN" | xxd)
if [ "$EXPECTED_HEX" = "$ACTUAL_HEX" ]; then
    log_info "  PASS"
else
    log_error "  FAIL: Binary content mismatch"
    TEST_FAILURES=$((TEST_FAILURES + 1))
fi

assert_failure "/* denies level1/file1.txt (nested)" \
    "\"$CLAWGATE\" cat \"$LEVEL1_TXT\"" \
    "No token grants read access"

assert_failure "/* denies level2/deep.txt (deeply nested)" \
    "\"$CLAWGATE\" cat \"$LEVEL2_TXT\"" \
    "No token grants read access"


echo ""
echo "========================================"
echo "  TEST 3: Nested Single-Level /level1/*"
echo "========================================"
echo ""

clear_tokens

TOKEN=$("$CLAWGATE" grant --read "$TESTDATA/level1/*")
"$CLAWGATE" token add "$TOKEN"
sleep 0.3

assert_content_equals "level1/* -> file1.txt" \
    "$(cat "$LEVEL1_TXT")" \
    "\"$CLAWGATE\" cat \"$LEVEL1_TXT\""

assert_content_equals "level1/* -> file1.zig" \
    "$(cat "$LEVEL1_ZIG")" \
    "\"$CLAWGATE\" cat \"$LEVEL1_ZIG\""

assert_failure "level1/* denies level2/deep.txt" \
    "\"$CLAWGATE\" cat \"$LEVEL2_TXT\"" \
    "No token grants read access"

assert_failure "level1/* denies root.txt" \
    "\"$CLAWGATE\" cat \"$ROOT_TXT\"" \
    "No token grants read access"


echo ""
echo "========================================"
echo "  TEST 4: Nested Recursive /level1/**"
echo "========================================"
echo ""

clear_tokens

TOKEN=$("$CLAWGATE" grant --read "$TESTDATA/level1/**")
"$CLAWGATE" token add "$TOKEN"
sleep 0.3

assert_content_equals "level1/** -> file1.txt" \
    "$(cat "$LEVEL1_TXT")" \
    "\"$CLAWGATE\" cat \"$LEVEL1_TXT\""

assert_content_equals "level1/** -> level2/deep.txt" \
    "$(cat "$LEVEL2_TXT")" \
    "\"$CLAWGATE\" cat \"$LEVEL2_TXT\""

assert_content_equals "level1/** -> level3/deepest.txt" \
    "$(cat "$LEVEL3_TXT")" \
    "\"$CLAWGATE\" cat \"$LEVEL3_TXT\""

assert_failure "level1/** denies root.txt" \
    "\"$CLAWGATE\" cat \"$ROOT_TXT\"" \
    "No token grants read access"

assert_failure "level1/** denies other/separate.txt" \
    "\"$CLAWGATE\" cat \"$OTHER_TXT\"" \
    "No token grants read access"


echo ""
echo "========================================"
echo "  TEST 5: Extension Pattern /*.txt"
echo "========================================"
echo ""

clear_tokens

TOKEN=$("$CLAWGATE" grant --read "$TESTDATA/*.txt")
"$CLAWGATE" token add "$TOKEN"
sleep 0.3

assert_content_equals "/*.txt -> root.txt" \
    "$(cat "$ROOT_TXT")" \
    "\"$CLAWGATE\" cat \"$ROOT_TXT\""

assert_failure "/*.txt denies root.bin (wrong extension)" \
    "\"$CLAWGATE\" cat \"$ROOT_BIN\"" \
    "No token grants read access"

assert_failure "/*.txt denies level1/file1.txt (nested)" \
    "\"$CLAWGATE\" cat \"$LEVEL1_TXT\"" \
    "No token grants read access"


echo ""
echo "========================================"
echo "  TEST 6: Extension Pattern /level1/*.zig"
echo "========================================"
echo ""

clear_tokens

TOKEN=$("$CLAWGATE" grant --read "$TESTDATA/level1/*.zig")
"$CLAWGATE" token add "$TOKEN"
sleep 0.3

assert_content_equals "level1/*.zig -> file1.zig" \
    "$(cat "$LEVEL1_ZIG")" \
    "\"$CLAWGATE\" cat \"$LEVEL1_ZIG\""

assert_failure "level1/*.zig denies file1.txt (wrong extension)" \
    "\"$CLAWGATE\" cat \"$LEVEL1_TXT\"" \
    "No token grants read access"

assert_failure "level1/*.zig denies level2/deep.zig (nested)" \
    "\"$CLAWGATE\" cat \"$LEVEL2_ZIG\"" \
    "No token grants read access"


echo ""
echo "========================================"
echo "  TEST 7: Exact Path Match"
echo "========================================"
echo ""

clear_tokens

TOKEN=$("$CLAWGATE" grant --read "$ROOT_TXT")
"$CLAWGATE" token add "$TOKEN"
sleep 0.3

assert_content_equals "Exact -> root.txt" \
    "$(cat "$ROOT_TXT")" \
    "\"$CLAWGATE\" cat \"$ROOT_TXT\""

assert_failure "Exact denies root.bin (different file)" \
    "\"$CLAWGATE\" cat \"$ROOT_BIN\"" \
    "No token grants read access"

assert_failure "Exact denies level1/file1.txt" \
    "\"$CLAWGATE\" cat \"$LEVEL1_TXT\"" \
    "No token grants read access"


echo ""
echo "========================================"
echo "  TEST 8: Binary File Integrity"
echo "========================================"
echo ""

clear_tokens

TOKEN=$("$CLAWGATE" grant --read "$TESTDATA/**")
"$CLAWGATE" token add "$TOKEN"
sleep 0.3

# Binary file integrity test - verify content matches via xxd
log_test "Binary file content integrity"
EXPECTED_HEX=$(xxd "$ROOT_BIN")
ACTUAL_HEX=$("$CLAWGATE" cat "$ROOT_BIN" | xxd)
if [ "$EXPECTED_HEX" = "$ACTUAL_HEX" ]; then
    log_info "  PASS: Binary content matches"
else
    log_error "  FAIL: Binary content mismatch"
    TEST_FAILURES=$((TEST_FAILURES + 1))
fi


# === RESULTS ===

echo ""
echo "========================================"
if [ $TEST_FAILURES -eq 0 ]; then
    echo -e "${GREEN}  All glob pattern tests passed!${NC}"
else
    echo -e "${RED}  $TEST_FAILURES test(s) FAILED${NC}"
fi
echo "========================================"
echo ""

exit $TEST_FAILURES
