#!/usr/bin/env bash
#
# Security integration tests.
#
# Tests: forbidden paths, scope enforcement, symlink rejection.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/framework.sh"

suite_begin "Security"

# Setup
mkdir -p "$TEST_DIR/allowed"
echo "public data" > "$TEST_DIR/allowed/file.txt"
mkdir -p "$TEST_DIR/allowed/sub"
echo "nested" > "$TEST_DIR/allowed/sub/deep.txt"

# Create fake sensitive paths under our test HOME
mkdir -p "$HOME/.ssh"
echo "fake key" > "$HOME/.ssh/id_rsa"
mkdir -p "$HOME/.gnupg"
echo "fake gpg" > "$HOME/.gnupg/private-keys"
mkdir -p "$HOME/.aws"
echo "fake creds" > "$HOME/.aws/credentials"
mkdir -p "$HOME/.clawgate/keys"
echo "fake secret" > "$HOME/.clawgate/keys/secret.key"
mkdir -p "$TEST_DIR/project"
echo "DB_PASSWORD=secret" > "$TEST_DIR/project/.env"
echo '{"key":"val"}' > "$TEST_DIR/project/credentials.json"
echo "safe file" > "$TEST_DIR/project/app.txt"

generate_keys

# -------------------------------------------------------
# Forbidden paths (broad scope token, still blocked)
# -------------------------------------------------------

# Grant very broad access
clear_tokens
grant_and_add --read "/**"
start_daemons

test_begin "~/.ssh/id_rsa blocked"
assert_fails \
    "\"$CG\" cat \"$HOME/.ssh/id_rsa\"" \
    "ACCESS_DENIED"

test_begin "~/.gnupg/private-keys blocked"
assert_fails \
    "\"$CG\" cat \"$HOME/.gnupg/private-keys\"" \
    "ACCESS_DENIED"

test_begin "~/.aws/credentials blocked"
assert_fails \
    "\"$CG\" cat \"$HOME/.aws/credentials\"" \
    "ACCESS_DENIED"

test_begin "~/.clawgate/keys/secret.key blocked"
assert_fails \
    "\"$CG\" cat \"$HOME/.clawgate/keys/secret.key\"" \
    "ACCESS_DENIED"

test_begin ".env file blocked"
assert_fails \
    "\"$CG\" cat \"$TEST_DIR/project/.env\"" \
    "ACCESS_DENIED"

test_begin "credentials.json blocked"
assert_fails \
    "\"$CG\" cat \"$TEST_DIR/project/credentials.json\"" \
    "ACCESS_DENIED"

test_begin "Normal file allowed with /** token"
OUT=$("$CG" cat "$TEST_DIR/project/app.txt" 2>&1)
assert_contains "$OUT" "safe file"

stop_daemons

# -------------------------------------------------------
# Scope enforcement: /** vs /* vs exact
# -------------------------------------------------------

test_begin "/** allows recursive access"
clear_tokens
grant_and_add --read "$TEST_DIR/allowed/**"
start_daemons
OUT=$("$CG" cat "$TEST_DIR/allowed/file.txt" 2>&1)
assert_contains "$OUT" "public data"

test_begin "/** allows nested access"
OUT=$("$CG" cat "$TEST_DIR/allowed/sub/deep.txt" 2>&1)
assert_contains "$OUT" "nested"
stop_daemons

test_begin "/* allows single level"
clear_tokens
grant_and_add --read "$TEST_DIR/allowed/*"
start_daemons
OUT=$("$CG" cat "$TEST_DIR/allowed/file.txt" 2>&1)
assert_contains "$OUT" "public data"

test_begin "/* denies nested path"
assert_fails \
    "\"$CG\" cat \"$TEST_DIR/allowed/sub/deep.txt\"" \
    "No token grants read access"
stop_daemons

test_begin "Exact path matches only that file"
clear_tokens
grant_and_add --read "$TEST_DIR/allowed/file.txt"
start_daemons
OUT=$("$CG" cat "$TEST_DIR/allowed/file.txt" 2>&1)
assert_contains "$OUT" "public data"

test_begin "Exact path denies other files"
assert_fails \
    "\"$CG\" cat \"$TEST_DIR/allowed/sub/deep.txt\"" \
    "No token grants read access"
stop_daemons

# -------------------------------------------------------
# Symlink rejection
# -------------------------------------------------------

test_begin "Symlink read rejected"
clear_tokens
grant_and_add --read "$TEST_DIR/**"
ln -sf "$TEST_DIR/allowed/file.txt" \
    "$TEST_DIR/allowed/link.txt"
start_daemons
assert_fails \
    "\"$CG\" cat \"$TEST_DIR/allowed/link.txt\"" \
    "IS_SYMLINK"
stop_daemons

# -------------------------------------------------------

FAILURES=0
suite_end || FAILURES=$?
exit "$FAILURES"
