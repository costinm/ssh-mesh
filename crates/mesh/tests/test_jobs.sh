#!/usr/bin/env bash
set -e

# Build the workspace to ensure mesh-init is available
cargo build -p mesh-init

# Setup test directories
TEST_DIR="/tmp/mesh-jobs-test"
JOBS_DIR="$TEST_DIR/jobs"
MESH_INIT_SOCK="$TEST_DIR/mesh-init.sock"
MESH_INIT_CONF="$TEST_DIR/config"

mkdir -p "$JOBS_DIR/work"
mkdir -p "$MESH_INIT_CONF"

# Copy the example jobs into place
cp crates/mesh/tests/jobs_testdata/*.toml "$JOBS_DIR/"
cp crates/mesh/tests/jobs_testdata/work/*.toml "$JOBS_DIR/sync-data/work/" 2>/dev/null || mkdir -p "$JOBS_DIR/sync-data/work" && cp crates/mesh/tests/jobs_testdata/work/*.toml "$JOBS_DIR/sync-data/work/"

export MESH_INIT_DIR="$MESH_INIT_CONF"
export MESH_INIT_RUN="$TEST_DIR"

echo "Starting mesh-init daemon in background..."
./target/debug/mesh-init &
MESH_INIT_PID=$!

sleep 2

echo "Mesh init running on $MESH_INIT_SOCK"

# Note: In a complete implementation, mesh-init would start the JobScheduler.
# This script serves as the scaffold for manual testing as requested.
# You can now send requests to the socket or trigger events.

echo "Waiting for 5 seconds..."
sleep 5

echo "Stopping mesh-init..."
kill $MESH_INIT_PID

echo "Done testing."
