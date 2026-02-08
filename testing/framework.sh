#!/usr/bin/env bash
#
# ClawGate Integration Test Framework
#
# Shared library sourced by all test suites.
# Provides daemon management, assertions, token helpers, and cleanup.

# Strict mode (suites source this, so set here)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CG="$PROJECT_DIR/zig-out/bin/clawgate"

TEST_PORT="${CLAWGATE_TEST_PORT:-63280}"
TEST_HOME="/tmp/clawgate_test_$$"
TEST_DIR="/tmp/clawgate_testdata_$$"

# Track PIDs for cleanup
_PIDS_TO_KILL=()
AGENT_PID=""
RESOURCE_PID=""

# Test counters
_TEST_COUNT=0
_PASS_COUNT=0
_FAIL_COUNT=0
_SKIP_COUNT=0
_SUITE_NAME=""

# --- Color output ---

if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' BOLD='' NC=''
fi

log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# --- Suite lifecycle ---

suite_begin() {
    _SUITE_NAME="$1"
    _TEST_COUNT=0
    _PASS_COUNT=0
    _FAIL_COUNT=0
    _SKIP_COUNT=0

    # Isolated HOME
    export HOME="$TEST_HOME"
    mkdir -p "$HOME/.clawgate/tokens"
    mkdir -p "$HOME/.clawgate/keys"
    mkdir -p "$HOME/.clawgate/logs"
    mkdir -p "$TEST_DIR"

    if [ ! -x "$CG" ]; then
        log_error "clawgate not found at $CG"
        log_error "Run 'zig build' first"
        exit 1
    fi

    echo ""
    echo -e "${BOLD}=============================${NC}"
    echo -e "${BOLD}  Suite: ${_SUITE_NAME}${NC}"
    echo -e "${BOLD}=============================${NC}"
    echo ""
}

suite_end() {
    echo ""
    echo -e "${BOLD}--- ${_SUITE_NAME} ---${NC}"
    echo -n "  Tests: $_TEST_COUNT  "
    echo -n -e "${GREEN}Passed: $_PASS_COUNT${NC}  "
    if [ "$_FAIL_COUNT" -gt 0 ]; then
        echo -n -e "${RED}Failed: $_FAIL_COUNT${NC}  "
    else
        echo -n "Failed: 0  "
    fi
    if [ "$_SKIP_COUNT" -gt 0 ]; then
        echo -e "${YELLOW}Skipped: $_SKIP_COUNT${NC}"
    else
        echo "Skipped: 0"
    fi
    echo ""

    return "$_FAIL_COUNT"
}

# --- Test lifecycle ---

test_begin() {
    _TEST_COUNT=$((_TEST_COUNT + 1))
    echo -e "${BLUE}[TEST]${NC}  $1"
}

test_pass() {
    _PASS_COUNT=$((_PASS_COUNT + 1))
    echo -e "  ${GREEN}PASS${NC}"
}

test_fail() {
    _FAIL_COUNT=$((_FAIL_COUNT + 1))
    echo -e "  ${RED}FAIL${NC}: $1"
}

test_skip() {
    _SKIP_COUNT=$((_SKIP_COUNT + 1))
    echo -e "  ${YELLOW}SKIP${NC}: $1"
}

# --- Assertions ---

assert_equals() {
    local expected="$1"
    local actual="$2"
    if [ "$expected" = "$actual" ]; then
        test_pass
    else
        test_fail "expected '$expected', got '$actual'"
    fi
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    if echo "$haystack" | grep -qF "$needle"; then
        test_pass
    else
        test_fail "output does not contain '$needle'"
    fi
}

assert_not_contains() {
    local haystack="$1"
    local needle="$2"
    if echo "$haystack" | grep -qF "$needle"; then
        test_fail "output unexpectedly contains '$needle'"
    else
        test_pass
    fi
}

assert_succeeds() {
    local cmd="$1"
    local output
    if output=$(eval "$cmd" 2>&1); then
        test_pass
    else
        test_fail "command failed: $cmd"
        echo "    output: $output"
    fi
}

assert_fails() {
    local cmd="$1"
    local expected_error="${2:-}"
    local output
    if output=$(eval "$cmd" 2>&1); then
        test_fail "expected failure but command succeeded"
        echo "    output: $output"
        return
    fi
    if [ -n "$expected_error" ]; then
        if echo "$output" | grep -q "$expected_error"; then
            test_pass
        else
            test_fail "wrong error (expected '$expected_error')"
            echo "    output: $output"
        fi
    else
        test_pass
    fi
}

assert_file_exists() {
    local path="$1"
    if [ -f "$path" ]; then
        test_pass
    else
        test_fail "file does not exist: $path"
    fi
}

assert_file_content() {
    local path="$1"
    local expected="$2"
    if [ ! -f "$path" ]; then
        test_fail "file does not exist: $path"
        return
    fi
    local actual
    actual=$(cat "$path")
    if [ "$expected" = "$actual" ]; then
        test_pass
    else
        test_fail "content mismatch in $path"
        echo "    expected: $expected"
        echo "    got:      $actual"
    fi
}

# --- Key management ---

generate_keys() {
    "$CG" keygen --force >/dev/null 2>&1
}

# --- Token management ---

grant_token() {
    "$CG" grant "$@"
}

add_token() {
    "$CG" token add "$1" >/dev/null 2>&1
}

clear_tokens() {
    rm -f "$HOME/.clawgate/tokens/"*.token 2>/dev/null || true
}

grant_and_add() {
    local token
    token=$(grant_token "$@")
    add_token "$token"
}

clear_tokens_and_restart_agent() {
    clear_tokens
    if [ -n "$AGENT_PID" ] \
        && kill -0 "$AGENT_PID" 2>/dev/null; then
        kill "$AGENT_PID" 2>/dev/null || true
        wait "$AGENT_PID" 2>/dev/null || true
    fi
    sleep 0.3
    start_agent
}

# --- Daemon management ---

start_agent() {
    "$CG" --mode agent \
        --listen "0.0.0.0:$TEST_PORT" \
        >/dev/null 2>&1 &
    AGENT_PID=$!
    _PIDS_TO_KILL+=("$AGENT_PID")
    sleep 1
    if ! kill -0 "$AGENT_PID" 2>/dev/null; then
        log_error "Agent daemon failed to start"
        return 1
    fi
    log_info "Agent daemon running (PID: $AGENT_PID)"
}

start_resource() {
    "$CG" --mode resource \
        --connect "localhost:$TEST_PORT" \
        >/dev/null 2>&1 &
    RESOURCE_PID=$!
    _PIDS_TO_KILL+=("$RESOURCE_PID")
    sleep 2
    if ! kill -0 "$RESOURCE_PID" 2>/dev/null; then
        log_error "Resource daemon failed to start"
        return 1
    fi
    log_info "Resource daemon running (PID: $RESOURCE_PID)"
}

start_daemons() {
    start_agent
    start_resource
}

stop_daemons() {
    if [ -n "$RESOURCE_PID" ] \
        && kill -0 "$RESOURCE_PID" 2>/dev/null; then
        kill "$RESOURCE_PID" 2>/dev/null || true
        wait "$RESOURCE_PID" 2>/dev/null || true
    fi
    RESOURCE_PID=""
    if [ -n "$AGENT_PID" ] \
        && kill -0 "$AGENT_PID" 2>/dev/null; then
        kill "$AGENT_PID" 2>/dev/null || true
        wait "$AGENT_PID" 2>/dev/null || true
    fi
    AGENT_PID=""
}

restart_agent() {
    if [ -n "$AGENT_PID" ] \
        && kill -0 "$AGENT_PID" 2>/dev/null; then
        kill "$AGENT_PID" 2>/dev/null || true
        wait "$AGENT_PID" 2>/dev/null || true
    fi
    AGENT_PID=""
    sleep 0.3
    start_agent
}

check_daemons_running() {
    if [ -z "$AGENT_PID" ] \
        || ! kill -0 "$AGENT_PID" 2>/dev/null; then
        log_error "Agent daemon not running"
        return 1
    fi
    if [ -z "$RESOURCE_PID" ] \
        || ! kill -0 "$RESOURCE_PID" 2>/dev/null; then
        log_error "Resource daemon not running"
        return 1
    fi
    return 0
}

# --- Git helpers ---

create_test_repo() {
    local path="$1"
    mkdir -p "$path"
    git -C "$path" init -q
    git -C "$path" config user.email "test@clawgate.dev"
    git -C "$path" config user.name "ClawGate Test"
    echo "initial" > "$path/README.md"
    git -C "$path" add -A
    git -C "$path" commit -q -m "Initial commit"
}

# --- Cleanup ---

_cleanup() {
    log_info "Cleaning up..."
    for pid in "${_PIDS_TO_KILL[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    rm -rf "$TEST_HOME" "$TEST_DIR"
    log_info "Cleanup complete"
}

trap _cleanup EXIT
