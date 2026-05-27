#!/bin/bash
set -e

# JNI integration test — builds the JAR + native library, then runs MainTest.
#
# Layout created under target/opt/ssh-mesh/:
#   bin/dmesh.jar
#   lib/<arch>/libdmesh.so

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
BASE_DIR=$(dirname "$SCRIPT_DIR")
cd "$BASE_DIR"

DEST="target/opt/ssh-mesh"

echo "=== Building JNI JAR + native library ==="
source scripts/build.sh
jni "$DEST"

echo ""
echo "=== Running MainTest ==="
java -jar "$DEST/bin/dmesh.jar" --help  # Quick smoke test

# For the full integration test, run MainTest directly from the JAR's classpath
# since MainTest isn't the Main-Class in the manifest.
java -cp "$DEST/bin/dmesh.jar" com.github.costinm.dmeshnative.MainTest

echo ""
echo "=== All JNI tests passed ==="
