#!/usr/bin/env bash
#
# Basic integration test for ClawGate
#
# Tests the full flow: keygen -> resource daemon -> grant -> cat
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
        fi
    done

    # Remove test directory
    rm -rf "$TEST_DIR"

    # Kill nats-server if we started it
    if [ "$STARTED_NATS" = "1" ]; then
        log_info "Stopping nats-server..."
        killall nats-server 2>/dev/null || true
    fi

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

# Start NATS if not running
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

# Generate keys
log_info "Generating keys..."
"$CLAWGATE" keygen --force

# Create test file
TEST_FILE="$TEST_DIR/hello.txt"
echo "Hello from ClawGate integration test!" > "$TEST_FILE"
log_info "Created test file: $TEST_FILE"

# Start resource daemon in background
log_info "Starting resource daemon..."
"$CLAWGATE" --mode resource &
RESOURCE_PID=$!
PIDS_TO_KILL+=($RESOURCE_PID)
sleep 1

# Check resource daemon is running
if ! kill -0 "$RESOURCE_PID" 2>/dev/null; then
    log_error "Resource daemon failed to start"
    exit 1
fi
log_info "Resource daemon running (PID: $RESOURCE_PID)"

# Grant read access to test directory (with /** for recursive access)
log_info "Granting read access to $TEST_DIR/**..."
TOKEN=$("$CLAWGATE" grant --read "$TEST_DIR/**")
if [ -z "$TOKEN" ]; then
    log_error "Failed to generate token"
    exit 1
fi
log_info "Token generated (${#TOKEN} chars)"

# Add token to agent
log_info "Adding token..."
"$CLAWGATE" token add "$TOKEN"

# Create tokens directory if needed
mkdir -p ~/.clawgate/tokens

# Start agent daemon in background
log_info "Starting agent daemon..."
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

# Test: Read file via clawgate cat
log_info "Testing: clawgate cat $TEST_FILE"
RESULT=$("$CLAWGATE" cat "$TEST_FILE" 2>&1) || {
    log_error "clawgate cat failed"
    log_error "Output: $RESULT"
    exit 1
}

EXPECTED="Hello from ClawGate integration test!"
if [ "$RESULT" = "$EXPECTED" ]; then
    log_info "SUCCESS: File content matches"
else
    log_error "FAILED: Content mismatch"
    log_error "Expected: $EXPECTED"
    log_error "Got: $RESULT"
    exit 1
fi

# Test: List directory
log_info "Testing: clawgate ls $TEST_DIR"
RESULT=$("$CLAWGATE" ls "$TEST_DIR" 2>&1) || {
    log_error "clawgate ls failed"
    log_error "Output: $RESULT"
    exit 1
}

if echo "$RESULT" | grep -q "hello.txt"; then
    log_info "SUCCESS: Directory listing contains hello.txt"
else
    log_error "FAILED: hello.txt not found in listing"
    log_error "Got: $RESULT"
    exit 1
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  All integration tests passed!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

exit 0
