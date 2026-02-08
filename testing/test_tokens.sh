#!/usr/bin/env bash
#
# Token management integration tests.
#
# Tests: grant, add, list, remove, revoke, expiry.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/framework.sh"

suite_begin "Token Management"

generate_keys

# -------------------------------------------------------
# Grant produces JWT for each permission tier
# -------------------------------------------------------

test_begin "grant --read produces JWT"
TOKEN=$("$CG" grant --read "$TEST_DIR/**")
assert_contains "$TOKEN" "eyJ"

test_begin "grant --write produces JWT"
TOKEN=$("$CG" grant --write "$TEST_DIR/**")
assert_contains "$TOKEN" "eyJ"

test_begin "grant --git produces JWT"
TOKEN=$("$CG" grant --git "$TEST_DIR/**")
assert_contains "$TOKEN" "eyJ"

test_begin "grant --git-write produces JWT"
TOKEN=$("$CG" grant --git-write "$TEST_DIR/**")
assert_contains "$TOKEN" "eyJ"

test_begin "grant --git-full produces JWT"
TOKEN=$("$CG" grant --git-full "$TEST_DIR/**")
assert_contains "$TOKEN" "eyJ"

# -------------------------------------------------------
# Token add / list / remove
# -------------------------------------------------------

clear_tokens

test_begin "token add stores token"
TOKEN=$("$CG" grant --read "$TEST_DIR/**")
ADD_OUT=$("$CG" token add "$TOKEN" 2>&1)
assert_contains "$ADD_OUT" "Token added"

test_begin "token list shows stored token"
LIST_OUT=$("$CG" token list 2>&1)
assert_contains "$LIST_OUT" "Stored tokens"

test_begin "token list includes scope path"
assert_contains "$LIST_OUT" "$TEST_DIR"

# Extract token ID from list output
TOKEN_ID=$(echo "$LIST_OUT" \
    | grep "ID:" | head -1 | awk '{print $2}')

test_begin "token remove deletes token"
if [ -n "$TOKEN_ID" ]; then
    RM_OUT=$("$CG" token remove "$TOKEN_ID" 2>&1)
    assert_contains "$RM_OUT" "removed"
else
    test_fail "could not extract token ID"
fi

test_begin "token list empty after remove"
LIST_OUT2=$("$CG" token list 2>&1)
assert_not_contains "$LIST_OUT2" "$TOKEN_ID"

# -------------------------------------------------------
# Token expiration
# -------------------------------------------------------

# Start daemons FIRST with a long-lived token, then test
# TTL behavior with short-lived tokens while daemons run.
clear_tokens
mkdir -p "$TEST_DIR/ttl"
echo "ttl test" > "$TEST_DIR/ttl/file.txt"

# Use a long-lived token to bootstrap daemons
grant_and_add --read "$TEST_DIR/ttl/**"
start_daemons

# Verify basic read works
test_begin "token with valid TTL works"
OUT=$("$CG" cat "$TEST_DIR/ttl/file.txt" 2>&1) || true
assert_contains "$OUT" "ttl test"

# Now test expiry: grant short-lived token, wait, try
stop_daemons
clear_tokens
SHORT_TOKEN=$("$CG" grant --read --ttl 2s "$TEST_DIR/ttl/**")
add_token "$SHORT_TOKEN"
sleep 3

test_begin "expired token rejected by CLI"
# The CLI loads tokens from disk and checks expiry locally
# An expired token won't match in findForPath
OUT=$("$CG" cat "$TEST_DIR/ttl/file.txt" 2>&1) || true
if echo "$OUT" | grep -q \
    "TOKEN_EXPIRED\|No token grants\|expired"; then
    test_pass
else
    test_fail "expected expiry error, got: $OUT"
fi

# -------------------------------------------------------
# Token revocation
# -------------------------------------------------------

clear_tokens

test_begin "revoke token by ID"
TOKEN=$("$CG" grant --read "$TEST_DIR/**")
add_token "$TOKEN"
LIST_OUT=$("$CG" token list 2>&1)
TOKEN_ID=$(echo "$LIST_OUT" \
    | grep "ID:" | head -1 | awk '{print $2}')
if [ -n "$TOKEN_ID" ]; then
    REVOKE_OUT=$("$CG" revoke "$TOKEN_ID" 2>&1)
    assert_contains "$REVOKE_OUT" "evoked"
else
    test_fail "could not extract token ID for revocation"
fi

test_begin "revoked list shows revoked token"
if [ -n "$TOKEN_ID" ]; then
    REV_LIST=$("$CG" revoked ls 2>&1)
    assert_contains "$REV_LIST" "$TOKEN_ID"
else
    test_skip "no token ID"
fi

test_begin "revoked token rejected by resource daemon"
if [ -n "$TOKEN_ID" ]; then
    mkdir -p "$TEST_DIR/revoke"
    echo "revoke test" > "$TEST_DIR/revoke/file.txt"
    start_daemons
    OUT=$("$CG" cat "$TEST_DIR/revoke/file.txt" 2>&1) \
        || true
    assert_contains "$OUT" "TOKEN_REVOKED"
    stop_daemons
else
    test_skip "no token ID"
fi

# -------------------------------------------------------

FAILURES=0
suite_end || FAILURES=$?
exit "$FAILURES"
