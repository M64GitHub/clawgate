#!/usr/bin/env bash
#
# MCP JSON-RPC integration tests.
#
# Tests: initialize, tools/list, tools/call, error handling.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/framework.sh"

suite_begin "MCP Protocol"

# Setup
mkdir -p "$TEST_DIR/mcp"
echo "mcp test content" > "$TEST_DIR/mcp/file.txt"

generate_keys
clear_tokens
grant_and_add --read "$TEST_DIR/**"

# Helper to send JSON-RPC to MCP server via stdin
mcp_call() {
    local json="$1"
    # MCP uses newline-delimited JSON over stdio
    echo "$json" | timeout 5 "$CG" mcp-server 2>/dev/null \
        || true
}

# -------------------------------------------------------
# initialize
# -------------------------------------------------------

test_begin "MCP initialize returns server info"
OUT=$(mcp_call '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}')
if echo "$OUT" | grep -q "clawgate"; then
    test_pass
else
    test_fail "initialize response missing 'clawgate'"
    echo "    output: $OUT"
fi

# -------------------------------------------------------
# tools/list
# -------------------------------------------------------

test_begin "MCP tools/list returns tools"
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
LIST='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
OUT=$(printf '%s\n%s\n' "$INIT" "$LIST" \
    | timeout 5 "$CG" mcp-server 2>/dev/null || true)
assert_contains "$OUT" "clawgate_read_file"

test_begin "tools/list includes write tool"
assert_contains "$OUT" "clawgate_write_file"

test_begin "tools/list includes list tool"
assert_contains "$OUT" "clawgate_list_directory"

test_begin "tools/list includes stat tool"
assert_contains "$OUT" "clawgate_stat"

test_begin "tools/list includes git tool"
assert_contains "$OUT" "clawgate_git"

test_begin "tools/list includes tool tool"
assert_contains "$OUT" "clawgate_tool"

test_begin "tools/list includes tool_list tool"
assert_contains "$OUT" "clawgate_tool_list"

# -------------------------------------------------------
# tools/call (needs running daemons for file access)
# -------------------------------------------------------

start_daemons

test_begin "MCP tools/call read_file returns content"
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
CALL='{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"clawgate_read_file","arguments":{"path":"'"$TEST_DIR/mcp/file.txt"'"}}}'
OUT=$(printf '%s\n%s\n' "$INIT" "$CALL" \
    | timeout 5 "$CG" mcp-server 2>/dev/null || true)
assert_contains "$OUT" "mcp test content"

stop_daemons

# -------------------------------------------------------
# Unknown method
# -------------------------------------------------------

test_begin "MCP unknown method returns error"
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
BAD='{"jsonrpc":"2.0","id":4,"method":"bogus/method","params":{}}'
OUT=$(printf '%s\n%s\n' "$INIT" "$BAD" \
    | timeout 5 "$CG" mcp-server 2>/dev/null || true)
assert_contains "$OUT" "error"

# -------------------------------------------------------

FAILURES=0
suite_end || FAILURES=$?
exit "$FAILURES"
