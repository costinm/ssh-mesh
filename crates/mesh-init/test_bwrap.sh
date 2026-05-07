#!/bin/bash
set -euo pipefail

# test_bwrap.sh: Integration test for mesh-init using bubblewrap
#
# Tests:
# 1. Daemon starts and loads configs
# 2. Starting a service creates correct cgroup limits
# 3. Memory admission control works
# 4. Reload command works
# 5. Stop and cleanup work

WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Detect the cargo target dir (may be under a specific target triple)
TARGET_DIR=$(cargo metadata --format-version 1 --manifest-path "$WORKSPACE_DIR/Cargo.toml" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['target_directory'])" 2>/dev/null || echo "$WORKSPACE_DIR/target")
# Check for musl target in .cargo/config.toml
if [ -f "$WORKSPACE_DIR/.cargo/config.toml" ] && grep -q 'target = "x86_64-unknown-linux-musl"' "$WORKSPACE_DIR/.cargo/config.toml"; then
    BIN_DIR="${TARGET_DIR}/x86_64-unknown-linux-musl/debug"
else
    BIN_DIR="${TARGET_DIR}/debug"
fi
MESH_INIT="${BIN_DIR}/mesh-init"
MESH="${BIN_DIR}/mesh"
RUN_DIR="/tmp/mesh-init-test-$$"
mkdir -p "$RUN_DIR"
export MESH_INIT_RUN="$RUN_DIR"
SOCKET="$RUN_DIR/control.sock"
PASSED=0
FAILED=0

cleanup() {
    if [ -n "${DAEMON_PID:-}" ]; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -rf "$RUN_DIR"
}
trap cleanup EXIT

pass() {
    PASSED=$((PASSED + 1))
    echo "  ✓ $1"
}

fail() {
    FAILED=$((FAILED + 1))
    echo "  ✗ $1"
}

assert_contains() {
    if echo "$1" | grep -q "$2"; then
        pass "$3"
    else
        fail "$3 (expected '$2' in output)"
        echo "    Got: $1"
    fi
}

# ============================================================================
# Build
# ============================================================================

echo "=== Building mesh and mesh-init ==="
cargo build -p mesh -p mesh-init -p fsd 2>&1 | tail -1

echo "Copying test configs..."
bash "${WORKSPACE_DIR}/crates/mesh-init/copy_testdata.sh" 2>&1 | tail -1

# ============================================================================
# Test 1: Daemon startup with a minimal config dir
# ============================================================================

echo ""
echo "=== Test: Daemon startup ==="

TESTDIR=$(mktemp -d)
cp "${WORKSPACE_DIR}/crates/mesh-init/testdata/memlimit.toml" "$TESTDIR/"
cp "${WORKSPACE_DIR}/crates/mesh-init/testdata/activated.toml" "$TESTDIR/"

# Start daemon in background (not in bwrap for now since cgroups need host access)
export MESH_INIT_DIR="$TESTDIR"
RUST_LOG=info "$MESH_INIT" &
DAEMON_PID=$!
sleep 1

# Check it's alive
if kill -0 "$DAEMON_PID" 2>/dev/null; then
    pass "Daemon started (PID $DAEMON_PID)"
else
    fail "Daemon failed to start"
    exit 1
fi

# ============================================================================
# Test 2: Status shows the loaded service
# ============================================================================

echo ""
echo "=== Test: Status ==="

STATUS=$("$MESH" mesh-init status 2>/dev/null || echo "ERROR")
assert_contains "$STATUS" "memlimit" "Status shows memlimit service"

# ============================================================================
# Test 3: Memory admission — status after start
# ============================================================================

echo ""
echo "=== Test: Start service ==="

START_RESULT=$("$MESH" mesh-init start memlimit 2>/dev/null || echo "ERROR")
sleep 0.5
assert_contains "$START_RESULT" "pid" "Start returns PID"

# Check status shows it running
STATUS=$($MESH mesh-init status memlimit 2>/dev/null || echo "ERROR")
assert_contains "$STATUS" '"state": "running"' "Service is running"

# ============================================================================
# Test 4: Cgroup memory limits are set
# ============================================================================

echo ""
echo "=== Test: Cgroup limits ==="

CGROUP_PATH="/sys/fs/cgroup/mesh.slice/memlimit.scope"
if [ -d "$CGROUP_PATH" ]; then
    pass "Cgroup directory exists"

    # Check memory.low = 64M = 67108864
    if [ -f "$CGROUP_PATH/memory.low" ]; then
        MEM_LOW=$(cat "$CGROUP_PATH/memory.low")
        if [ "$MEM_LOW" = "67108864" ]; then
            pass "memory.low = 67108864 (64M)"
        else
            fail "memory.low = $MEM_LOW (expected 67108864)"
        fi
    else
        fail "memory.low file not found"
    fi

    # Check memory.high = 256M = 268435456
    if [ -f "$CGROUP_PATH/memory.high" ]; then
        MEM_HIGH=$(cat "$CGROUP_PATH/memory.high")
        if [ "$MEM_HIGH" = "268435456" ]; then
            pass "memory.high = 268435456 (256M)"
        else
            fail "memory.high = $MEM_HIGH (expected 268435456)"
        fi
    else
        fail "memory.high file not found"
    fi

    # Check memory.max = 512M = 536870912
    if [ -f "$CGROUP_PATH/memory.max" ]; then
        MEM_MAX=$(cat "$CGROUP_PATH/memory.max")
        if [ "$MEM_MAX" = "536870912" ]; then
            pass "memory.max = 536870912 (512M)"
        else
            fail "memory.max = $MEM_MAX (expected 536870912)"
        fi
    else
        fail "memory.max file not found"
    fi

    # Check cpu.weight = 50
    if [ -f "$CGROUP_PATH/cpu.weight" ]; then
        CPU_W=$(cat "$CGROUP_PATH/cpu.weight")
        if [ "$CPU_W" = "50" ]; then
            pass "cpu.weight = 50"
        else
            fail "cpu.weight = $CPU_W (expected 50)"
        fi
    else
        fail "cpu.weight file not found"
    fi
else
    fail "Cgroup directory does not exist (may need root)"
    echo "    (This is expected on non-root and in some container environments)"
fi

# ============================================================================
# Test 5: Reload
# ============================================================================

echo ""
echo "=== Test: Reload ==="

RELOAD_RESULT=$("$MESH" mesh-init reload 2>/dev/null || echo "ERROR")
assert_contains "$RELOAD_RESULT" "reloaded" "Reload command works"

# ============================================================================
# Test 6: Stop
# ============================================================================

echo ""
echo "=== Test: Stop ==="

STOP_RESULT=$("$MESH" mesh-init stop memlimit 2>/dev/null || echo "ERROR")
sleep 0.5
assert_contains "$STOP_RESULT" "OK" "Stop returns OK"

STATUS=$($MESH mesh-init status memlimit 2>/dev/null || echo "ERROR")
assert_contains "$STATUS" '"state": "stopped"' "Service is stopped after stop"

# ============================================================================
# Test 7: Shutdown
# ============================================================================

echo ""
echo "=== Test: Activation ==="
sleep 0.5
RESPONSE=$(echo "" | nc 127.0.0.1 14022 || echo "NC_FAILED")
assert_contains "$RESPONSE" "SUCCESS" "Activated service returned SUCCESS on TCP port 14022"

echo ""
echo "=== Test: Shutdown ==="
$MESH mesh-init shutdown 2>/dev/null || true
sleep 2

if kill -0 "$DAEMON_PID" 2>/dev/null; then
    fail "Daemon still running after shutdown"
    kill "$DAEMON_PID" 2>/dev/null || true
else
    pass "Daemon exited after shutdown"
fi
unset DAEMON_PID

# ============================================================================
# Test 8: Command execution mode (mesh-init sleep 1)
# ============================================================================

echo ""
echo "=== Test: Command execution mode ==="
$MESH_INIT sleep 1
# If we reached here, it exited as expected
pass "Command execution mode works (exited)"

# ============================================================================
# Test 9: Execution mode loads default.toml and init-* configs
# ============================================================================

echo ""
echo "=== Test: Execution mode with configs ==="

EXEC_DIR=$(mktemp -d)
# Create default.toml
cat <<EOF > "$EXEC_DIR/default.toml"
[service]
name = "default"
command = "_placeholder_"
priority = 0

[resources]
memory_max = "128M"

[environment]
TEST_FROM_DEFAULT = "yes"
EOF

# Create init-setup.toml (oneshot, runs first)
INIT_MARKER="$EXEC_DIR/init_ran"
cat <<EOF > "$EXEC_DIR/init-setup.toml"
[service]
name = "init-setup"
command = "/bin/sh"
args = ["-c", "touch $INIT_MARKER"]
priority = 10
oneshot = true
EOF

export MESH_INIT_DIR="$EXEC_DIR"
# Run mesh-init in execution mode with a simple command
$MESH_INIT /bin/sh -c "test -f $INIT_MARKER && echo INIT_FIRST"
EXEC_EXIT=$?

if [ "$EXEC_EXIT" -eq 0 ]; then
    pass "Execution mode with configs exited cleanly"
else
    fail "Execution mode with configs failed (exit: $EXEC_EXIT)"
fi

if [ -f "$INIT_MARKER" ]; then
    pass "init-setup ran and created marker file"
else
    fail "init-setup did not run (marker file missing)"
fi

rm -rf "$EXEC_DIR"

# Clean up cgroup if possible
rmdir "$CGROUP_PATH" 2>/dev/null || true
rmdir /sys/fs/cgroup/mesh.slice 2>/dev/null || true

# ============================================================================
# Test 10: 9p Mounting (xinetd UDS)
# ============================================================================

echo ""
echo "=== Test: 9p Mount ==="

MNT_DIR=$(mktemp -d)
mkdir -p "$MNT_DIR"

# Start daemon with unpfs_xinetd_uds configuration
export MESH_INIT_DIR="$TESTDIR"
cp "${WORKSPACE_DIR}/crates/mesh-init/testdata/unpfs_xinetd_uds.toml" "$TESTDIR/"
sed -i "s|command = \"./unpfs\"|command = \"$BIN_DIR/unpfs\"|g" "$TESTDIR/unpfs_xinetd_uds.toml"
RUST_LOG=info "$MESH_INIT" &
DAEMON_PID=$!
sleep 1

# Try to connect with 9mount if available
if command -v 9mount >/dev/null; then
    echo "Attempting to use 9mount..."
    # 9mount may fail because it defaults to 9P2000 instead of 9P2000.L
    9mount -i 'unix!/tmp/unpfs_xinetd.sock' "$MNT_DIR" 2>/dev/null || echo "9mount failed (expected if it does not support 9P2000.L default)"
fi

# Fallback/Primary test with standard mount
echo "Testing with sudo mount..."
if sudo mount -t 9p -o version=9p2000.L,trans=unix,uname=$USER /tmp/unpfs_xinetd.sock "$MNT_DIR" 2>/dev/null; then
    pass "Successfully mounted 9p using sudo mount"
    sudo umount "$MNT_DIR"
else
    fail "Failed to mount 9p using sudo mount"
fi

kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
rm -rf "$MNT_DIR"
rm -rf "$TESTDIR"

# ============================================================================
# Summary
# ============================================================================

echo ""
echo "==========================="
echo "  Results: $PASSED passed, $FAILED failed"
echo "==========================="

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
