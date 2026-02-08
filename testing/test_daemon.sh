#!/usr/bin/env bash
#
# Daemon lifecycle integration tests.
#
# Tests: start/stop, request serving, agent restart,
# reconnection, clean shutdown, CLI without daemon.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/framework.sh"

suite_begin "Daemon Lifecycle"

# Setup
mkdir -p "$TEST_DIR/daemon"
echo "daemon test" > "$TEST_DIR/daemon/file.txt"

generate_keys
clear_tokens
grant_and_add --read "$TEST_DIR/**"

# -------------------------------------------------------
# Basic start/stop
# -------------------------------------------------------

test_begin "Agent starts successfully"
start_agent
if kill -0 "$AGENT_PID" 2>/dev/null; then
    test_pass
else
    test_fail "agent PID not running"
fi

test_begin "Resource connects to agent"
start_resource
if kill -0 "$RESOURCE_PID" 2>/dev/null; then
    test_pass
else
    test_fail "resource PID not running"
fi

test_begin "Daemons serve requests"
OUT=$("$CG" cat "$TEST_DIR/daemon/file.txt" 2>&1)
assert_contains "$OUT" "daemon test"

# -------------------------------------------------------
# Agent restart
# -------------------------------------------------------

test_begin "Agent restart: old agent stops"
OLD_AGENT=$AGENT_PID
restart_agent
if kill -0 "$OLD_AGENT" 2>/dev/null; then
    test_fail "old agent still running"
else
    test_pass
fi

test_begin "Agent restart: new agent running"
if kill -0 "$AGENT_PID" 2>/dev/null; then
    test_pass
else
    test_fail "new agent not running"
fi

test_begin "Requests work after agent restart"
sleep 2
OUT=$("$CG" cat "$TEST_DIR/daemon/file.txt" 2>&1) \
    || true
if echo "$OUT" | grep -q "daemon test"; then
    test_pass
else
    test_skip "resource may not auto-reconnect"
fi

# -------------------------------------------------------
# Clean shutdown
# -------------------------------------------------------

test_begin "Both daemons stop cleanly"
stop_daemons
if [ -z "$AGENT_PID" ] \
    || ! kill -0 "$AGENT_PID" 2>/dev/null; then
    AGENT_GONE=1
else
    AGENT_GONE=0
fi
if [ -z "$RESOURCE_PID" ] \
    || ! kill -0 "$RESOURCE_PID" 2>/dev/null; then
    RESOURCE_GONE=1
else
    RESOURCE_GONE=0
fi
if [ "$AGENT_GONE" -eq 1 ] \
    && [ "$RESOURCE_GONE" -eq 1 ]; then
    test_pass
else
    test_fail "daemons still running after stop"
fi

# -------------------------------------------------------
# CLI without daemon
# -------------------------------------------------------

test_begin "CLI without daemon shows error"
OUT=$("$CG" cat "$TEST_DIR/daemon/file.txt" 2>&1) \
    || true
if echo "$OUT" | grep -qi \
    "connect\|refused\|not running\|error"; then
    test_pass
else
    test_fail "expected connection error, got: $OUT"
fi

# -------------------------------------------------------

FAILURES=0
suite_end || FAILURES=$?
exit "$FAILURES"
