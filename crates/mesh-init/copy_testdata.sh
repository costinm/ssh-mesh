#!/bin/bash
set -e

# copy_testdata.sh: Copies test configs and test binaries/scripts to target/debug

WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET_DIR="${WORKSPACE_DIR}/target/debug"

echo "Creating ${TARGET_DIR}/testdata..."
mkdir -p "${TARGET_DIR}/testdata"

echo "Copying test configs..."
cp -r "${WORKSPACE_DIR}/crates/mesh-init/testdata/"* "${TARGET_DIR}/testdata/"

echo "Done. Test data available in ${TARGET_DIR}/testdata/"
