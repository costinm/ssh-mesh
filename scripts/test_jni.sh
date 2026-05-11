#!/bin/bash
set -e

# Configuration
TARGET_DIR="target"
JAVA_OUT_DIR="$TARGET_DIR/java-classes"
JNI_LIB_NAME="libdmesh.so"
HOST_TARGET="x86_64-unknown-linux-gnu"
MUSL_TARGET="x86_64-unknown-linux-musl"

# 1. Build the JNI library for the host (GNU)
echo "Building JNI library for host (GNU)..."
cargo build -p dmesh --target "$HOST_TARGET" --release

# 2. Build for musl if requested/available
if [[ "$1" == "--musl" ]]; then
    if command -v musl-gcc &> /dev/null; then
        echo "Building JNI library for musl..."
        cargo build -p dmesh --target "$MUSL_TARGET" --release
    else
        echo "Warning: musl-gcc not found. Skipping musl build."
    fi
fi

# 3. Find android.jar for compilation (needed for some classes potentially)
# Although for basic JNI test we might not need it if we only use standard Java APIs.
# However, Rust.java might use some android-isms if it's shared.
# Let's try compiling without it first, or find it if possible.
ANDROID_JAR=$(find /opt/Android/Sdk/platforms -name "android.jar" | sort -V | tail -n 1 2>/dev/null || echo "")

# 4. Compile Java classes
echo "Compiling Java classes..."
mkdir -p "$JAVA_OUT_DIR"
SRC_DIR="java/rust/src/main/java"
find "$SRC_DIR" -name "*.java" > "$TARGET_DIR/java_sources.txt"

if [ -n "$ANDROID_JAR" ]; then
    javac -d "$JAVA_OUT_DIR" -cp "$ANDROID_JAR" @"$TARGET_DIR/java_sources.txt"
else
    javac -d "$JAVA_OUT_DIR" @"$TARGET_DIR/java_sources.txt"
fi

# 5. Run the test
echo "Running JNI test (amd64)..."

# Determine which library to use
LIB_PATH="$TARGET_DIR/$HOST_TARGET/release"
if [[ "$1" == "--musl" && -f "$TARGET_DIR/$MUSL_TARGET/release/$JNI_LIB_NAME" ]]; then
    LIB_PATH="$TARGET_DIR/$MUSL_TARGET/release"
fi

echo "Using library from: $LIB_PATH"

# Set LD_LIBRARY_PATH just in case, though java.library.path should be enough for System.loadLibrary
export LD_LIBRARY_PATH="$LIB_PATH:$LD_LIBRARY_PATH"

java -Djava.library.path="$LIB_PATH" -cp "$JAVA_OUT_DIR" com.github.costinm.dmeshnative.Main
