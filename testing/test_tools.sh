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
# Hot-reload (register/remove while daemons running)
# -------------------------------------------------------

# Grant token for echo_hot BEFORE it exists (--tool does
# not validate existence) so the CLI can find a matching
# token. The resource daemon must hot-reload the registry
# to see the newly registered tool.
clear_tokens
grant_and_add --tool echo_hot --read "$TEST_DIR/**"
start_daemons

test_begin "tool registered after daemon start works"
"$CG" tool register echo_hot \
    --command "echo" \
    --description "Hot reload test" >/dev/null 2>&1
OUT=$(echo "" | "$CG" tool echo_hot "hot_hello" 2>&1)
assert_contains "$OUT" "hot_hello"

test_begin "tool removed after daemon start is denied"
"$CG" tool remove echo_hot >/dev/null 2>&1
assert_fails \
    "echo '' | \"$CG\" tool echo_hot 'should_fail'" \
    "TOOL_DENIED\|not registered"

stop_daemons
"$CG" tool remove echo_hot >/dev/null 2>&1 || true

# -------------------------------------------------------
# Remote tool discovery (remote-list)
# -------------------------------------------------------

"$CG" tool register rl_calc \
    --command "bc -l" \
    --description "Calculator" >/dev/null 2>&1
"$CG" tool register rl_grep \
    --command "grep" \
    --description "Safe grep" >/dev/null 2>&1

test_begin "remote-list shows all registered tools"
clear_tokens
grant_and_add --tool rl_calc --read "$TEST_DIR/**"
start_daemons
OUT=$("$CG" tool remote-list 2>&1)
assert_contains "$OUT" "rl_calc"

test_begin "remote-list includes all tools regardless of grant"
assert_contains "$OUT" "rl_grep"
stop_daemons

test_begin "remote-list with --tools-all shows all"
clear_tokens
grant_and_add --tools-all --read "$TEST_DIR/**"
start_daemons
OUT=$("$CG" tool remote-list 2>&1)
assert_contains "$OUT" "rl_calc"

test_begin "remote-list --tools-all includes second tool"
assert_contains "$OUT" "rl_grep"

test_begin "remote-list output has description"
assert_contains "$OUT" "Calculator"
stop_daemons

test_begin "remote-list works without tool grant"
clear_tokens
grant_and_add --read "$TEST_DIR/**"
start_daemons
OUT=$("$CG" tool remote-list 2>&1)
assert_contains "$OUT" "rl_calc"

test_begin "remote-list without tool grant shows all tools"
assert_contains "$OUT" "rl_grep"
stop_daemons

test_begin "remote-list with no tools registered"
"$CG" tool remove rl_calc >/dev/null 2>&1 || true
"$CG" tool remove rl_grep >/dev/null 2>&1 || true
clear_tokens
grant_and_add --read "$TEST_DIR/**"
start_daemons
OUT=$("$CG" tool remote-list 2>&1)
assert_contains "$OUT" "No tools available"
stop_daemons

test_begin "remote-list shows all tools with any token"
"$CG" tool register rl_a \
    --command "echo" \
    --description "Tool A" >/dev/null 2>&1
"$CG" tool register rl_b \
    --command "echo" \
    --description "Tool B" >/dev/null 2>&1
"$CG" tool register rl_c \
    --command "echo" \
    --description "Tool C" >/dev/null 2>&1
clear_tokens
grant_and_add --read "$TEST_DIR/**"
start_daemons
OUT=$("$CG" tool remote-list 2>&1)
assert_contains "$OUT" "rl_a"

test_begin "discovery shows all tools unconditionally"
assert_contains "$OUT" "rl_b"

test_begin "discovery includes third tool"
assert_contains "$OUT" "rl_c"
stop_daemons

"$CG" tool remove rl_a >/dev/null 2>&1 || true
"$CG" tool remove rl_b >/dev/null 2>&1 || true
"$CG" tool remove rl_c >/dev/null 2>&1 || true

# -------------------------------------------------------
# Tokenless IPC security (raw socket tests)
# -------------------------------------------------------

# Determine IPC socket path (same logic as daemon)
if [ -n "${XDG_RUNTIME_DIR:-}" ]; then
    SOCK="$XDG_RUNTIME_DIR/clawgate.sock"
else
    SOCK="/tmp/clawgate-$(id -u).sock"
fi

# Send raw JSON to daemon IPC socket, return response.
# Bypasses CLI to simulate attacker with socket access.
ipc_raw() {
    local json="$1"
    python3 -c "
import socket, struct, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(sys.argv[2])
msg = sys.argv[1].encode()
s.sendall(struct.pack('>I', len(msg)) + msg)
hdr = b''
while len(hdr) < 4: hdr += s.recv(4 - len(hdr))
ln = struct.unpack('>I', hdr)[0]
d = b''
while len(d) < ln: d += s.recv(ln - len(d))
print(d.decode())
s.close()
" "$json" "$SOCK" 2>/dev/null
}

"$CG" tool register sec_echo \
    --command "echo" \
    --description "Security test tool" >/dev/null 2>&1

clear_tokens
grant_and_add --tool sec_echo --read "$TEST_DIR/**"
start_daemons

test_begin "tokenless read rejected"
OUT=$(ipc_raw '{"op":"read","params":{"path":"/etc/passwd"}}')
assert_contains "$OUT" "Token required"

test_begin "tokenless write rejected"
OUT=$(ipc_raw '{"op":"write","params":{"path":"/tmp/x","content":"pwned"}}')
assert_contains "$OUT" "Token required"

test_begin "tokenless git rejected"
OUT=$(ipc_raw '{"op":"git","params":{"repo":"/tmp","args":["status"]}}')
assert_contains "$OUT" "Token required"

test_begin "tokenless tool invoke rejected"
OUT=$(ipc_raw '{"op":"tool","params":{"name":"sec_echo","args":["pwned"]}}')
assert_contains "$OUT" "Token required"

test_begin "tokenless list rejected"
OUT=$(ipc_raw '{"op":"list","params":{"path":"/"}}')
assert_contains "$OUT" "Token required"

test_begin "tokenless stat rejected"
OUT=$(ipc_raw '{"op":"stat","params":{"path":"/etc/passwd"}}')
assert_contains "$OUT" "Token required"

test_begin "empty tokenless request rejected"
OUT=$(ipc_raw '{}')
assert_contains "$OUT" "Token required"

test_begin "tokenless tool_list cannot read files"
OUT=$(ipc_raw '{"op":"tool_list","params":{"path":"/etc/passwd"}}')
assert_not_contains "$OUT" "root:"

stop_daemons

"$CG" tool remove sec_echo >/dev/null 2>&1 || true

# -------------------------------------------------------

FAILURES=0
suite_end || FAILURES=$?
exit "$FAILURES"
