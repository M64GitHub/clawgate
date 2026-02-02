#!/usr/bin/env bash
#
# Basic integration test for ClawGate (E2E TCP + IPC architecture)
#
# Tests the full flow: keygen -> grant -> agent daemon -> resource daemon
# -> CLI commands via IPC
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CLAWGATE="$PROJECT_DIR/zig-out/bin/clawgate"
TEST_DIR="/tmp/clawgate_integration_test_$$"
PIDS_TO_KILL=()

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    log_info "Cleaning up..."

    # Kill spawned processes
    for pid in "${PIDS_TO_KILL[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done

    # Remove test directory
    rm -rf "$TEST_DIR"

    log_info "Cleanup complete"
}

trap cleanup EXIT

# Check prerequisites
if [ ! -x "$CLAWGATE" ]; then
    log_error "clawgate not found at $CLAWGATE"
    log_error "Run 'zig build' first"
    exit 1
fi

# Create test directory
mkdir -p "$TEST_DIR"
log_info "Test directory: $TEST_DIR"

# Step 1: Generate keys
log_info "Step 1: Generating keys..."
"$CLAWGATE" keygen --force
log_info "Keys generated"

# Step 2: Create test file
TEST_FILE="$TEST_DIR/hello.txt"
TEST_CONTENT="Hello from ClawGate integration test!"
echo "$TEST_CONTENT" > "$TEST_FILE"
log_info "Step 2: Created test file: $TEST_FILE"

# Step 3: Grant read access to test directory (with /** for recursive access)
log_info "Step 3: Granting read access to $TEST_DIR/**..."
TOKEN=$("$CLAWGATE" grant --read "$TEST_DIR/**")
if [ -z "$TOKEN" ]; then
    log_error "Failed to generate token"
    exit 1
fi
log_info "Token generated (${#TOKEN} chars)"

# Step 4: Add token to agent
log_info "Step 4: Adding token..."
mkdir -p ~/.clawgate/tokens
"$CLAWGATE" token add "$TOKEN"
log_info "Token added"

# Step 5: Start agent daemon (in background)
log_info "Step 5: Starting agent daemon..."
"$CLAWGATE" --mode agent &
AGENT_PID=$!
PIDS_TO_KILL+=($AGENT_PID)
sleep 1

# Check agent daemon is running
if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    log_error "Agent daemon failed to start"
    exit 1
fi
log_info "Agent daemon running (PID: $AGENT_PID)"

# Step 6: Start resource daemon (connects to agent)
log_info "Step 6: Starting resource daemon..."
"$CLAWGATE" --mode resource --connect localhost:4223 &
RESOURCE_PID=$!
PIDS_TO_KILL+=($RESOURCE_PID)
sleep 2

# Check resource daemon is running
if ! kill -0 "$RESOURCE_PID" 2>/dev/null; then
    log_error "Resource daemon failed to start"
    exit 1
fi
log_info "Resource daemon running (PID: $RESOURCE_PID)"

# Step 7: Test CLI commands via IPC
log_info "Step 7: Testing CLI commands via IPC..."

# Test cat command
log_info "  Testing 'cat' command..."
CAT_OUTPUT=$("$CLAWGATE" cat "$TEST_FILE" 2>&1) || {
    log_error "cat command failed"
    log_error "Output: $CAT_OUTPUT"
    exit 1
}
if [[ "$CAT_OUTPUT" == *"$TEST_CONTENT"* ]]; then
    log_info "  cat: PASSED"
else
    log_error "cat: FAILED - unexpected output"
    log_error "Expected: $TEST_CONTENT"
    log_error "Got: $CAT_OUTPUT"
    exit 1
fi

# Test stat command
log_info "  Testing 'stat' command..."
STAT_OUTPUT=$("$CLAWGATE" stat "$TEST_FILE" 2>&1) || {
    log_error "stat command failed"
    log_error "Output: $STAT_OUTPUT"
    exit 1
}
if [[ "$STAT_OUTPUT" == *"Exists:"*"true"* ]]; then
    log_info "  stat: PASSED"
else
    log_error "stat: FAILED - unexpected output"
    log_error "Got: $STAT_OUTPUT"
    exit 1
fi

# Test ls command
log_info "  Testing 'ls' command..."
LS_OUTPUT=$("$CLAWGATE" ls "$TEST_DIR" 2>&1) || {
    log_error "ls command failed"
    log_error "Output: $LS_OUTPUT"
    exit 1
}
if [[ "$LS_OUTPUT" == *"hello.txt"* ]]; then
    log_info "  ls: PASSED"
else
    log_error "ls: FAILED - unexpected output"
    log_error "Got: $LS_OUTPUT"
    exit 1
fi

# Cleanup
log_info "Stopping daemons..."
kill $RESOURCE_PID 2>/dev/null || true
kill $AGENT_PID 2>/dev/null || true
wait $RESOURCE_PID 2>/dev/null || true
wait $AGENT_PID 2>/dev/null || true
PIDS_TO_KILL=()

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  All integration tests passed!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
exit 0
