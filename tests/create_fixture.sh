#!/usr/bin/env bash
#
# Create test fixture for integration tests.
#
# Run from project root: bash tests/create_fixture.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FIXTURE_DIR="/tmp/clawgate_fixture_$$"
OUTPUT_DIR="$SCRIPT_DIR/fixtures"

mkdir -p "$FIXTURE_DIR/testdata"
mkdir -p "$FIXTURE_DIR/testdata/level1/level2/level3"
mkdir -p "$FIXTURE_DIR/testdata/other"
mkdir -p "$OUTPUT_DIR"

# Create text files with known content (no trailing newline for exact matching)
printf "This is the root text file." > "$FIXTURE_DIR/testdata/root.txt"
printf "Level 1 text file content." > "$FIXTURE_DIR/testdata/level1/file1.txt"
printf 'const std = @import("std");' > "$FIXTURE_DIR/testdata/level1/file1.zig"
printf "Level 2 deep text content." > "$FIXTURE_DIR/testdata/level1/level2/deep.txt"
printf "pub fn main() void {}" > "$FIXTURE_DIR/testdata/level1/level2/deep.zig"
printf "Level 3 deepest content." > "$FIXTURE_DIR/testdata/level1/level2/level3/deepest.txt"
printf "Other directory content." > "$FIXTURE_DIR/testdata/other/separate.txt"

# Create binary file (PNG header signature - 16 bytes)
printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR' > "$FIXTURE_DIR/testdata/root.bin"

# Create tarball
cd "$FIXTURE_DIR"
tar -czf testdata.tgz testdata

# Move to output directory
mv testdata.tgz "$OUTPUT_DIR/"

# Cleanup
rm -rf "$FIXTURE_DIR"

echo "Created: $OUTPUT_DIR/testdata.tgz"
