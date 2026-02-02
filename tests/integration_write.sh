#!/usr/bin/env bash
#
# Integration test for file write operations in ClawGate.
#
# Tests:
# - Write with --write permission
# - Write then read back verification
# - Binary content write/verify
# - Overwrite existing files
# - Create files in nested directories
# - Permission denial tests

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CLAWGATE="$PROJECT_DIR/zig-out/bin/clawgate"
TEST_DIR="/tmp/clawgate_write_test_$$"
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

# Assertion: file exists
assert_file_exists() {
    local path="$1"
    log_test "File exists: $path"
    if [ -f "$path" ]; then
        log_info "  PASS"
        return 0
    else
        log_error "  FAIL: File does not exist"
        TEST_FAILURES=$((TEST_FAILURES + 1))
        return 1
    fi
}

# Assertion: file content matches
assert_file_content() {
    local desc="$1"
    local path="$2"
    local expected="$3"
    log_test "$desc"
    if [ ! -f "$path" ]; then
        log_error "  FAIL: File does not exist: $path"
        TEST_FAILURES=$((TEST_FAILURES + 1))
        return 1
    fi
    local actual
    actual=$(cat "$path")
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

# Assertion: command output matches expected
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

# Assertion: command should fail
assert_failure() {
    local desc="$1"
    local cmd="$2"
    local expected_error="$3"
    log_test "$desc (expect DENIED)"
    local output
    if output=$(eval "$cmd" 2>&1); then
        log_error "  FAIL: Expected failure but command succeeded"
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
    log_error "clawgate not found. Run 'zig build' first"
    exit 1
fi

# === SETUP ===

mkdir -p "$TEST_DIR"
mkdir -p "$TEST_DIR/writeable"
mkdir -p "$TEST_DIR/writeable/nested/deep"
mkdir -p "$TEST_DIR/readonly"

# Create initial test files
printf "original content" > "$TEST_DIR/writeable/existing.txt"
printf "readonly content" > "$TEST_DIR/readonly/file.txt"

log_info "Test directory: $TEST_DIR"

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

WRITEABLE="$TEST_DIR/writeable"
READONLY="$TEST_DIR/readonly"

# === TEST CASES ===

echo ""
echo "========================================"
echo "  TEST 1: Basic Write Operation"
echo "========================================"
echo ""

clear_tokens

TOKEN=$("$CLAWGATE" grant --write "$WRITEABLE/**")
"$CLAWGATE" token add "$TOKEN"
sleep 0.3

NEW_FILE="$WRITEABLE/new_file.txt"
log_test "Write new file with --content"
"$CLAWGATE" write --content "Hello from ClawGate write test!" "$NEW_FILE"

assert_file_exists "$NEW_FILE"
assert_file_content "Written content matches" "$NEW_FILE" "Hello from ClawGate write test!"


echo ""
echo "========================================"
echo "  TEST 2: Write and Read Back"
echo "========================================"
echo ""

clear_tokens

TOKEN=$("$CLAWGATE" grant --read --write "$WRITEABLE/**")
"$CLAWGATE" token add "$TOKEN"
sleep 0.3

READBACK_FILE="$WRITEABLE/readback.txt"
CONTENT="Content for read-back verification"
"$CLAWGATE" write --content "$CONTENT" "$READBACK_FILE"

assert_content_equals "Read back written content via clawgate" \
    "$CONTENT" \
    "\"$CLAWGATE\" cat \"$READBACK_FILE\""


echo ""
echo "========================================"
echo "  TEST 3: Overwrite Existing File"
echo "========================================"
echo ""

clear_tokens

TOKEN=$("$CLAWGATE" grant --write "$WRITEABLE/**")
"$CLAWGATE" token add "$TOKEN"
sleep 0.3

EXISTING="$WRITEABLE/existing.txt"
log_test "Overwrite existing file"
"$CLAWGATE" write --content "new overwritten content" "$EXISTING"

assert_file_content "Overwritten content" "$EXISTING" "new overwritten content"


echo ""
echo "========================================"
echo "  TEST 4: Write in Nested Directory"
echo "========================================"
echo ""

clear_tokens

TOKEN=$("$CLAWGATE" grant --write "$WRITEABLE/**")
"$CLAWGATE" token add "$TOKEN"
sleep 0.3

NESTED_FILE="$WRITEABLE/nested/deep/nested_file.txt"
log_test "Write to nested directory"
"$CLAWGATE" write --content "nested content" "$NESTED_FILE"

assert_file_exists "$NESTED_FILE"
assert_file_content "Nested content" "$NESTED_FILE" "nested content"


echo ""
echo "========================================"
echo "  TEST 5: Write from stdin (pipe)"
echo "========================================"
echo ""

clear_tokens

TOKEN=$("$CLAWGATE" grant --write "$WRITEABLE/**")
"$CLAWGATE" token add "$TOKEN"
sleep 0.3

PIPE_FILE="$WRITEABLE/piped.txt"
log_test "Write content from pipe/stdin"
echo -n "piped content from echo" | "$CLAWGATE" write "$PIPE_FILE"

assert_file_exists "$PIPE_FILE"
assert_file_content "Piped content" "$PIPE_FILE" "piped content from echo"


echo ""
echo "========================================"
echo "  TEST 6: Binary Content Write"
echo "========================================"
echo ""

clear_tokens

TOKEN=$("$CLAWGATE" grant --read --write "$WRITEABLE/**")
"$CLAWGATE" token add "$TOKEN"
sleep 0.3

# Binary content write and verify
BINARY_FILE="$WRITEABLE/binary.bin"
log_test "Write binary content"
printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR' | "$CLAWGATE" write "$BINARY_FILE"

WRITTEN=$(xxd "$BINARY_FILE")
EXPECTED=$(printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR' | xxd)
if [ "$EXPECTED" = "$WRITTEN" ]; then
    log_info "  PASS: Binary content matches"
else
    log_error "  FAIL: Binary content mismatch"
    TEST_FAILURES=$((TEST_FAILURES + 1))
fi


echo ""
echo "========================================"
echo "  TEST 7: Write with Read-Only Token (DENIED)"
echo "========================================"
echo ""

clear_tokens

TOKEN=$("$CLAWGATE" grant --read "$READONLY/**")
"$CLAWGATE" token add "$TOKEN"
sleep 0.3

READONLY_FILE="$READONLY/attempt.txt"
assert_failure "Write with read-only token" \
    "\"$CLAWGATE\" write --content 'should fail' \"$READONLY_FILE\"" \
    "No token grants write access"


echo ""
echo "========================================"
echo "  TEST 8: Write Outside Granted Scope (DENIED)"
echo "========================================"
echo ""

clear_tokens

TOKEN=$("$CLAWGATE" grant --write "$WRITEABLE/**")
"$CLAWGATE" token add "$TOKEN"
sleep 0.3

assert_failure "Write outside scope" \
    "\"$CLAWGATE\" write --content 'should fail' \"$READONLY/attempt.txt\"" \
    "No token grants write access"


echo ""
echo "========================================"
echo "  TEST 9: Append Mode"
echo "========================================"
echo ""

clear_tokens

TOKEN=$("$CLAWGATE" grant --read --write "$WRITEABLE/**")
"$CLAWGATE" token add "$TOKEN"
sleep 0.3

APPEND_FILE="$WRITEABLE/append.txt"
"$CLAWGATE" write --content "first line" "$APPEND_FILE"

log_test "Append to existing file"
"$CLAWGATE" write --append --content " second line" "$APPEND_FILE"

assert_file_content "Appended content" "$APPEND_FILE" "first line second line"


echo ""
echo "========================================"
echo "  TEST 10: Single-Level Write Scope"
echo "========================================"
echo ""

clear_tokens

TOKEN=$("$CLAWGATE" grant --write "$WRITEABLE/*")
"$CLAWGATE" token add "$TOKEN"
sleep 0.3

ROOT_WRITE="$WRITEABLE/root_write.txt"
log_test "Write to direct child with /* scope"
"$CLAWGATE" write --content "root level" "$ROOT_WRITE"
assert_file_exists "$ROOT_WRITE"

assert_failure "Write to nested with /* scope" \
    "\"$CLAWGATE\" write --content 'should fail' \"$WRITEABLE/nested/fail.txt\"" \
    "No token grants write access"


# === RESULTS ===

echo ""
echo "========================================"
if [ $TEST_FAILURES -eq 0 ]; then
    echo -e "${GREEN}  All write operation tests passed!${NC}"
else
    echo -e "${RED}  $TEST_FAILURES test(s) FAILED${NC}"
fi
echo "========================================"
echo ""

exit $TEST_FAILURES
