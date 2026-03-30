#!/bin/bash
# ============================================================
# test.sh - Automated Test Suite for SecFS
# 
# Secure Encrypted and Versioned Filesystem using FUSE
#
# This script tests all major filesystem operations:
#   1. File creation and writing
#   2. File reading (verifying decryption)
#   3. Encryption verification (raw storage is ciphertext)
#   4. File versioning (automatic backups)
#   5. File rename
#   6. File deletion
#   7. Directory operations
#   8. Operation logging
#
# Usage:
#   chmod +x test.sh
#   ./test.sh
#
# Prerequisites:
#   - SecFS binary (secfs) must be compiled
#   - mountpoint/ and storage/ directories must exist
# ============================================================

set -e  # Exit on first error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'  # No Color

# Configuration
BINARY="./secfs"
MOUNT_DIR="./mountpoint"
STORAGE_DIR="./storage"
VERSIONS_DIR="./storage/.versions"
LOG_FILE="./logs.txt"

# Test counters
PASS=0
FAIL=0
TOTAL=0

# ============================================================
# Helper Functions
# ============================================================

print_header() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${BOLD}       SecFS - Automated Test Suite                   ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}\n"
}

print_test() {
    TOTAL=$((TOTAL + 1))
    echo -e "${YELLOW}[TEST $TOTAL]${NC} $1"
}

pass() {
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}✓ PASSED${NC}: $1"
}

fail() {
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}✗ FAILED${NC}: $1"
}

cleanup() {
    echo -e "\n${CYAN}[*] Cleaning up...${NC}"
    # Unmount if mounted
    fusermount -u "$MOUNT_DIR" 2>/dev/null || true
    sleep 1
    echo -e "${GREEN}[✓] Cleanup complete${NC}"
}

# Trap to ensure cleanup on exit
trap cleanup EXIT

# ============================================================
# Pre-flight Checks
# ============================================================

print_header

echo -e "${CYAN}[*] Pre-flight checks...${NC}"

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo -e "${RED}ERROR: SecFS binary not found. Run 'make' first.${NC}"
    exit 1
fi
echo -e "  ✓ SecFS binary found"

# Create directories
mkdir -p "$MOUNT_DIR" "$STORAGE_DIR" "$VERSIONS_DIR"
echo -e "  ✓ Directories created"

# Clean up any previous mount
fusermount -u "$MOUNT_DIR" 2>/dev/null || true

# Remove old test data
rm -rf "${STORAGE_DIR:?}"/*
mkdir -p "$VERSIONS_DIR"
rm -f "$LOG_FILE"
echo -e "  ✓ Previous test data cleaned"

# ============================================================
# Mount the Filesystem
# ============================================================

echo -e "\n${CYAN}[*] Mounting SecFS...${NC}"
$BINARY -f "$MOUNT_DIR" &
SECFS_PID=$!
sleep 2  # Wait for mount to complete

# Verify mount
if mountpoint -q "$MOUNT_DIR" 2>/dev/null || mount | grep -q "$MOUNT_DIR"; then
    echo -e "  ${GREEN}✓ SecFS mounted at $MOUNT_DIR (PID: $SECFS_PID)${NC}"
else
    echo -e "  ${RED}✗ Failed to mount SecFS${NC}"
    exit 1
fi

# ============================================================
# Test 1: Create and Write a File
# ============================================================

print_test "Create and write a file"

echo "Hello, SecFS! This is a test file." > "$MOUNT_DIR/hello.txt"
if [ -f "$MOUNT_DIR/hello.txt" ]; then
    pass "File created successfully"
else
    fail "File was not created"
fi

# ============================================================
# Test 2: Read Back the File (Verify Decryption)
# ============================================================

print_test "Read file content (transparent decryption)"

CONTENT=$(cat "$MOUNT_DIR/hello.txt")
EXPECTED="Hello, SecFS! This is a test file."
if [ "$CONTENT" = "$EXPECTED" ]; then
    pass "Content matches: '$CONTENT'"
else
    fail "Content mismatch. Expected: '$EXPECTED', Got: '$CONTENT'"
fi

# ============================================================
# Test 3: Verify Encryption (Raw Storage Check)
# ============================================================

print_test "Verify file is encrypted in storage"

if [ -f "$STORAGE_DIR/hello.txt" ]; then
    # The raw storage file should NOT contain the plaintext
    RAW_CONTENT=$(cat "$STORAGE_DIR/hello.txt" 2>/dev/null || echo "binary")
    if [ "$RAW_CONTENT" != "$EXPECTED" ]; then
        pass "Storage file is encrypted (raw content differs from plaintext)"
    else
        fail "Storage file appears to be unencrypted!"
    fi
else
    fail "Storage file not found"
fi

# ============================================================
# Test 4: File Versioning
# ============================================================

print_test "File versioning on modification"

# Modify the file to trigger versioning
echo "Modified content - version 2" > "$MOUNT_DIR/hello.txt"
sleep 1

# Check if a version was created
VERSION_FILES=$(ls "$VERSIONS_DIR"/ 2>/dev/null | grep "hello.txt.v" || true)
if [ -n "$VERSION_FILES" ]; then
    pass "Version backup created: $VERSION_FILES"
else
    fail "No version backup found in $VERSIONS_DIR"
fi

# Modify again to test incrementing version numbers
echo "Modified again - version 3" > "$MOUNT_DIR/hello.txt"
sleep 1

VERSION_COUNT=$(ls "$VERSIONS_DIR"/ 2>/dev/null | grep -c "hello.txt.v" || echo "0")
if [ "$VERSION_COUNT" -ge 2 ]; then
    pass "Multiple versions created ($VERSION_COUNT versions)"
else
    fail "Expected at least 2 versions, found $VERSION_COUNT"
fi

# ============================================================
# Test 5: Read Modified File
# ============================================================

print_test "Read modified file content"

CONTENT=$(cat "$MOUNT_DIR/hello.txt")
EXPECTED="Modified again - version 3"
if [ "$CONTENT" = "$EXPECTED" ]; then
    pass "Modified content reads correctly: '$CONTENT'"
else
    fail "Content mismatch. Expected: '$EXPECTED', Got: '$CONTENT'"
fi

# ============================================================
# Test 6: Create Multiple Files
# ============================================================

print_test "Create multiple files"

echo "File A content" > "$MOUNT_DIR/file_a.txt"
echo "File B content" > "$MOUNT_DIR/file_b.txt"
echo "File C content" > "$MOUNT_DIR/file_c.txt"

COUNT=$(ls "$MOUNT_DIR" | wc -l)
if [ "$COUNT" -ge 4 ]; then  # hello.txt + file_a + file_b + file_c
    pass "Multiple files created ($COUNT files visible)"
else
    fail "Expected at least 4 files, found $COUNT"
fi

# ============================================================
# Test 7: Directory Operations
# ============================================================

print_test "Create and use subdirectory"

mkdir "$MOUNT_DIR/subdir"
echo "Nested file content" > "$MOUNT_DIR/subdir/nested.txt"
NESTED_CONTENT=$(cat "$MOUNT_DIR/subdir/nested.txt")
if [ "$NESTED_CONTENT" = "Nested file content" ]; then
    pass "Subdirectory and nested file work correctly"
else
    fail "Nested file content mismatch: '$NESTED_CONTENT'"
fi

# ============================================================
# Test 8: Rename Operation
# ============================================================

print_test "Rename a file"

mv "$MOUNT_DIR/file_a.txt" "$MOUNT_DIR/file_a_renamed.txt"
if [ -f "$MOUNT_DIR/file_a_renamed.txt" ] && [ ! -f "$MOUNT_DIR/file_a.txt" ]; then
    RENAMED_CONTENT=$(cat "$MOUNT_DIR/file_a_renamed.txt")
    if [ "$RENAMED_CONTENT" = "File A content" ]; then
        pass "File renamed successfully, content preserved"
    else
        fail "Renamed file content mismatch"
    fi
else
    fail "Rename operation failed"
fi

# ============================================================
# Test 9: Delete Operation
# ============================================================

print_test "Delete a file"

rm "$MOUNT_DIR/file_b.txt"
if [ ! -f "$MOUNT_DIR/file_b.txt" ]; then
    pass "File deleted successfully"
else
    fail "File still exists after deletion"
fi

# ============================================================
# Test 10: .versions Directory Hidden
# ============================================================

print_test ".versions directory hidden from mount"

LISTING=$(ls "$MOUNT_DIR")
if echo "$LISTING" | grep -q ".versions"; then
    fail ".versions is visible in mount listing"
else
    pass ".versions correctly hidden from mount listing"
fi

# ============================================================
# Test 11: Check Log File
# ============================================================

print_test "Operation logging"

if [ -f "$LOG_FILE" ]; then
    LOG_LINES=$(wc -l < "$LOG_FILE")
    echo -e "  Log file contains $LOG_LINES entries:"
    
    # Check for key operations in the log
    HAS_MOUNT=$(grep -c "MOUNT" "$LOG_FILE" || echo "0")
    HAS_CREATE=$(grep -c "CREATE" "$LOG_FILE" || echo "0")
    HAS_WRITE=$(grep -c "WRITE" "$LOG_FILE" || echo "0")
    HAS_READ=$(grep -c "READ" "$LOG_FILE" || echo "0")
    HAS_DELETE=$(grep -c "DELETE" "$LOG_FILE" || echo "0")
    HAS_RENAME=$(grep -c "RENAME" "$LOG_FILE" || echo "0")
    
    echo -e "    MOUNT: $HAS_MOUNT | CREATE: $HAS_CREATE | WRITE: $HAS_WRITE"
    echo -e "    READ: $HAS_READ | DELETE: $HAS_DELETE | RENAME: $HAS_RENAME"
    
    if [ "$HAS_WRITE" -gt 0 ] && [ "$HAS_CREATE" -gt 0 ]; then
        pass "Operations are being logged with timestamps"
    else
        fail "Expected log entries not found"
    fi
    
    # Show sample log entries
    echo -e "\n  ${CYAN}Sample log entries:${NC}"
    head -5 "$LOG_FILE" | while read -r line; do
        echo -e "    $line"
    done
else
    fail "Log file not found"
fi

# ============================================================
# Test 12: Large File Test
# ============================================================

print_test "Large file encryption/decryption"

# Generate a larger test string (1000+ characters)
LARGE_DATA=$(python3 -c "print('A' * 5000)" 2>/dev/null || printf '%0.sA' $(seq 1 5000))
echo "$LARGE_DATA" > "$MOUNT_DIR/large_file.txt"
LARGE_READ=$(cat "$MOUNT_DIR/large_file.txt")
if [ "$LARGE_READ" = "$LARGE_DATA" ]; then
    pass "Large file (5KB+) encrypted and decrypted correctly"
else
    fail "Large file content mismatch"
fi

# ============================================================
# Test Summary
# ============================================================

echo -e "\n${CYAN}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}Test Results Summary${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo -e "  Total:  $TOTAL"
echo -e "  ${GREEN}Passed: $PASS${NC}"
echo -e "  ${RED}Failed: $FAIL${NC}"

if [ "$FAIL" -eq 0 ]; then
    echo -e "\n${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           ALL TESTS PASSED! ✓                       ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    EXIT_CODE=0
else
    echo -e "\n${RED}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║           SOME TESTS FAILED! ✗                      ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════╝${NC}"
    EXIT_CODE=1
fi

echo ""
exit $EXIT_CODE
