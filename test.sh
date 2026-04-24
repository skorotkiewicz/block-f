#!/bin/bash
# Test bypass attempts against block protection
# Usage: ./test.sh <file>

TARGET="${1:-test.md}"

echo "=== Bypass Test Suite ==="
echo "Target: $TARGET"
echo ""

# Check if file exists
if [ ! -e "$TARGET" ]; then
    echo "ERROR: Target does not exist: $TARGET"
    exit 1
fi

# Check current permissions
echo "=== Current State ==="
ls -la "$TARGET"
lsattr "$TARGET" 2>/dev/null || echo "lsattr not available (need root to check immutable bit)"
echo ""

# Store original content for comparison
ORIGINAL=$(cat "$TARGET" 2>/dev/null)
echo "Original content: $ORIGINAL"
echo ""

ATTEMPTS=0
FAILED=0
PASSED=0

test_bypass() {
    local name="$1"
    local cmd="$2"

    echo "=== Test: $name ==="
    ATTEMPTS=$((ATTEMPTS + 1))

    if eval "$cmd" 2>/dev/null; then
        echo "✗ BYPASSED! Command succeeded"
        FAILED=$((FAILED + 1))
        return 1
    else
        echo "✓ BLOCKED"
        PASSED=$((PASSED + 1))
        return 0
    fi
}

# Test 1: Direct write
test_bypass "Direct write (>)" "echo 'bypass 1: direct' > '$TARGET'"

# Test 2: Append
test_bypass "Append (>>)" "echo 'bypass 2: append' >> '$TARGET'"

# Test 3: chmod then write (race condition)
test_bypass "chmod +w then write" "chmod +w '$TARGET' && echo 'bypass 3: chmod race' > '$TARGET'"

# Test 4: Write temp then move
echo "bypass 4: temp+mv" > /tmp/test_new.md
test_bypass "Write temp + mv" "mv /tmp/test_new.md '$TARGET'"

# Test 5: cp overwrite
echo "bypass 5: cp" > /tmp/cp_test.md
test_bypass "cp overwrite" "cp /tmp/cp_test.md '$TARGET'"

# Test 6: Try to delete and recreate
test_bypass "rm then recreate" "rm '$TARGET' && echo 'bypass 6: deleted' > '$TARGET'"

# Test 7: Rename then create
test_bypass "rename then create" "mv '$TARGET' '${TARGET}.bak' && echo 'bypass 7: renamed' > '$TARGET'"

# Test 8: sed in-place
test_bypass "sed -i" "sed -i 's/.*/bypass 8: sed/' '$TARGET'"

# Test 9: dd with conv=notrunc
echo "bypass 9: dd" > /tmp/dd_test.md
test_bypass "dd overwrite" "dd if=/tmp/dd_test.md of='$TARGET' conv=notrunc"

# Test 10: Python open with O_TRUNC
test_bypass "Python O_TRUNC" "python3 -c \"import os; fd = os.open('$TARGET', os.O_WRONLY | os.O_TRUNC); os.write(fd, b'bypass 10: python'); os.close(fd)\""

# Test 11: Python mmap
test_bypass "Python mmap" "python3 -c \"import mmap, os; fd = os.open('$TARGET', os.O_RDONLY); mm = mmap.mmap(fd, 0, access=mmap.ACCESS_WRITE); mm[0:3] = b'XXX'; os.close(fd)\""

# Test 12: Try chattr -i (remove immutable)
test_bypass "chattr -i" "chattr -i '$TARGET' && echo 'bypass 12: removed immutable' > '$TARGET'"

# Test 13: Create hardlink and modify through it (same filesystem)
if [ ! -L "$TARGET" ]; then
    ln "$TARGET" /tmp/hardlink_test 2>/dev/null
    if [ $? -eq 0 ]; then
        test_bypass "Hardlink same fs" "echo 'bypass 13: hardlink' > /tmp/hardlink_test"
        rm -f /tmp/hardlink_test
    else
        echo "=== Test: Hardlink same fs ==="
        echo "✗ SKIPPED (cannot create hardlink)"
    fi
fi

# Test 14: Symlink attack - replace file with symlink
if [ ! -L "$TARGET" ]; then
    test_bypass "Symlink swap" "rm '$TARGET' 2>/dev/null; ln -s /tmp/writable_test.md '$TARGET'; echo 'bypass 14: symlink' > '$TARGET'"
fi

# Test 15: Check if we can use sudo
test_bypass "sudo tee" "echo 'bypass 15: sudo' | sudo tee '$TARGET' > /dev/null"

echo ""
echo "=== Results ==="
echo "Total attempts: $ATTEMPTS"
echo "Blocked: $PASSED"
echo "Bypassed: $FAILED"
echo ""

# Check final state
echo "=== Final State ==="
ls -la "$TARGET"
lsattr "$TARGET" 2>/dev/null || true

echo ""
echo "Final content:"
cat "$TARGET"

if [ "$FAILED" -gt 0 ]; then
    echo ""
    echo "⚠️  WARNING: $FAILED bypass(es) succeeded!"
    exit 1
else
    echo ""
    echo "✓ All bypass attempts blocked!"
    exit 0
fi
