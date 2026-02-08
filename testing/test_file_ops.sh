#!/usr/bin/env bash
#
# File operation integration tests.
#
# Tests: cat, ls, write, stat through running daemons.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/framework.sh"

suite_begin "File Operations"

# Setup test data
FIXTURE_TGZ="$SCRIPT_DIR/fixtures/testdata.tgz"
if [ -f "$FIXTURE_TGZ" ]; then
    tar -xzf "$FIXTURE_TGZ" -C "$TEST_DIR"
fi

TESTDATA="$TEST_DIR/testdata"
mkdir -p "$TESTDATA"
printf "Hello from ClawGate!" > "$TESTDATA/hello.txt"
printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR' \
    > "$TESTDATA/binary.bin"
mkdir -p "$TESTDATA/subdir"
printf "nested file" > "$TESTDATA/subdir/nested.txt"
mkdir -p "$TEST_DIR/writeable"
mkdir -p "$TEST_DIR/writeable/deep"
mkdir -p "$TEST_DIR/readonly"
printf "original" > "$TEST_DIR/writeable/existing.txt"
printf "readonly" > "$TEST_DIR/readonly/file.txt"

generate_keys
grant_and_add --read --write "$TEST_DIR/**"
start_daemons

# -------------------------------------------------------
# cat tests
# -------------------------------------------------------

test_begin "cat reads text file"
OUT=$("$CG" cat "$TESTDATA/hello.txt" 2>/dev/null)
assert_equals "Hello from ClawGate!" "$OUT"

test_begin "cat reads binary file (xxd match)"
EXPECTED_HEX=$(xxd "$TESTDATA/binary.bin")
ACTUAL_HEX=$("$CG" cat "$TESTDATA/binary.bin" 2>/dev/null \
    | xxd)
assert_equals "$EXPECTED_HEX" "$ACTUAL_HEX"

test_begin "cat with --offset and --length"
OUT=$("$CG" cat --offset 6 --length 4 \
    "$TESTDATA/hello.txt" 2>/dev/null)
assert_equals "from" "$OUT"

# -------------------------------------------------------
# ls tests
# -------------------------------------------------------

test_begin "ls lists directory entries"
OUT=$("$CG" ls "$TESTDATA" 2>&1)
assert_contains "$OUT" "hello.txt"

test_begin "ls shows subdirectory"
assert_contains "$OUT" "subdir"

# -------------------------------------------------------
# stat tests
# -------------------------------------------------------

test_begin "stat existing file"
OUT=$("$CG" stat "$TESTDATA/hello.txt" 2>&1)
assert_contains "$OUT" "true"

test_begin "stat nonexistent file"
OUT=$("$CG" stat "$TESTDATA/nope.txt" 2>&1) || true
# Either error or Exists: false
if echo "$OUT" | grep -q "false\|FILE_NOT_FOUND"; then
    test_pass
else
    test_fail "unexpected stat output: $OUT"
fi

# -------------------------------------------------------
# write tests
# -------------------------------------------------------

test_begin "write new file with --content"
WFILE="$TEST_DIR/writeable/new.txt"
"$CG" write --content "written content" "$WFILE" 2>&1
assert_file_content "$WFILE" "written content"

test_begin "write from stdin pipe"
PFILE="$TEST_DIR/writeable/piped.txt"
echo -n "piped data" | "$CG" write "$PFILE" 2>&1
assert_file_content "$PFILE" "piped data"

test_begin "write --append mode"
AFILE="$TEST_DIR/writeable/append.txt"
"$CG" write --content "first" "$AFILE" 2>&1
"$CG" write --append --content " second" "$AFILE" 2>&1
assert_file_content "$AFILE" "first second"

test_begin "overwrite existing file"
"$CG" write --content "overwritten" \
    "$TEST_DIR/writeable/existing.txt" 2>&1
assert_file_content \
    "$TEST_DIR/writeable/existing.txt" "overwritten"

test_begin "write with read-only token denied"
stop_daemons
clear_tokens
grant_and_add --read "$TEST_DIR/readonly/**"
start_daemons
assert_fails \
    "\"$CG\" write --content 'fail' \"$TEST_DIR/readonly/x.txt\"" \
    "No token grants write access"

test_begin "write outside scope denied"
assert_fails \
    "\"$CG\" write --content 'fail' /tmp/outside.txt" \
    "No token grants write access"

# -------------------------------------------------------

stop_daemons

FAILURES=0
suite_end || FAILURES=$?
exit "$FAILURES"
