#!/usr/bin/env bash
#
# Tool management integration tests.
#
# Tests: register, ls, info, update, remove, test, invoke.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/framework.sh"

suite_begin "Tool Management"

generate_keys

# -------------------------------------------------------
# Local tool lifecycle (no daemons needed)
# -------------------------------------------------------

test_begin "tool register"
OUT=$("$CG" tool register calc \
    --command "bc -l" \
    --description "Calculator" 2>&1)
assert_contains "$OUT" "registered"

test_begin "tool ls shows registered tool"
OUT=$("$CG" tool list 2>&1)
assert_contains "$OUT" "calc"

test_begin "tool info shows details"
OUT=$("$CG" tool info calc 2>&1)
assert_contains "$OUT" "bc -l"

test_begin "tool update description"
OUT=$("$CG" tool update calc \
    --description "Updated calculator" 2>&1)
INFO=$("$CG" tool info calc 2>&1)
assert_contains "$INFO" "Updated calculator"

test_begin "duplicate registration rejected"
assert_fails \
    "\"$CG\" tool register calc --command 'bc -l'" \
    "already"

test_begin "tool test runs locally"
OUT=$(echo "2 + 3" | "$CG" tool test calc 2>&1)
assert_contains "$OUT" "5"

test_begin "tool remove"
OUT=$("$CG" tool remove calc 2>&1)
LIST=$("$CG" tool list 2>&1)
assert_not_contains "$LIST" "calc"

# -------------------------------------------------------
# Allowlist / denylist
# -------------------------------------------------------

test_begin "tool with allowlist blocks unknown flags"
"$CG" tool register greet \
    --command "echo" \
    --allow-args "hello" \
    --allow-args "world" \
    --description "Greeter" >/dev/null 2>&1
OUT=$(echo "" | "$CG" tool test greet hello 2>&1)
assert_contains "$OUT" "hello"

test_begin "allowlist blocks non-allowed arg"
assert_fails \
    "echo '' | \"$CG\" tool test greet --evil" \
    "Blocked\|blocked\|ARG_BLOCKED"

"$CG" tool remove greet >/dev/null 2>&1 || true

test_begin "tool with denylist blocks denied flags"
"$CG" tool register safer \
    --command "echo" \
    --deny-args "--rm" \
    --deny-args "-rf" \
    --description "Safer echo" >/dev/null 2>&1
OUT=$(echo "" | "$CG" tool test safer "hi" 2>&1)
assert_contains "$OUT" "hi"

test_begin "denylist allows non-denied args"
OUT=$(echo "" | "$CG" tool test safer "ok" 2>&1)
assert_contains "$OUT" "ok"

test_begin "denylist blocks denied arg"
assert_fails \
    "echo '' | \"$CG\" tool test safer --rm" \
    "Blocked\|blocked\|ARG_BLOCKED"

"$CG" tool remove safer >/dev/null 2>&1 || true

# -------------------------------------------------------
# Remote tool invocation (with daemons)
# -------------------------------------------------------

"$CG" tool register remote_echo \
    --command "echo" \
    --description "Remote echo test" >/dev/null 2>&1

clear_tokens
grant_and_add --tool remote_echo --read "$TEST_DIR/**"
start_daemons

test_begin "invoke tool via daemon"
OUT=$("$CG" tool remote_echo "hello_remote" 2>&1)
assert_contains "$OUT" "hello_remote"

stop_daemons

test_begin "wrong tool scope denied"
"$CG" tool register other_tool \
    --command "echo" \
    --description "Other" >/dev/null 2>&1
clear_tokens
grant_and_add --tool remote_echo --read "$TEST_DIR/**"
start_daemons
assert_fails \
    "\"$CG\" tool other_tool 'test'" \
    "TOOL_DENIED\|No token grants"
stop_daemons

"$CG" tool remove remote_echo >/dev/null 2>&1 || true
"$CG" tool remove other_tool >/dev/null 2>&1 || true

# -------------------------------------------------------

FAILURES=0
suite_end || FAILURES=$?
exit "$FAILURES"
