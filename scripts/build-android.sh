#!/bin/bash
set -e

# Configuration
# Try to find Android SDK in common locations
if [ -z "$ANDROID_HOME" ]; then
    if [ -d "/opt/Android/Sdk" ]; then
        export ANDROID_HOME="/opt/Android/Sdk"
    elif [ -d "$HOME/Android/Sdk" ]; then
        export ANDROID_HOME="$HOME/Android/Sdk"
    else
        echo "Error: ANDROID_HOME not set and not found in common locations."
        exit 1
    fi
fi

SDK_DIR="$ANDROID_HOME"
BUILD_DIR="target/build-android"
AAR_NAME="dmesh.aar"
NDK_VERSION="25.2.9519653"

if [ -d "$SDK_DIR/ndk/$NDK_VERSION" ]; then
    export ANDROID_NDK_HOME="$SDK_DIR/ndk/$NDK_VERSION"
else
    # Fallback to any installed NDK if specified version is missing
    INSTALLED_NDK=$(ls -1 "$SDK_DIR/ndk" 2>/dev/null | head -n 1)
    if [ -n "$INSTALLED_NDK" ]; then
        export ANDROID_NDK_HOME="$SDK_DIR/ndk/$INSTALLED_NDK"
    else
        echo "Error: No NDK found in $SDK_DIR/ndk"
        exit 1
    fi
fi

# Function to check Rust and basic build tools
check_rust_tools() {
    echo "Checking Rust and build tools..."
    for tool in rustup cargo zip javac jar cargo-ndk; do
        if ! command -v "$tool" &> /dev/null; then
            echo "Error: $tool is not installed."
            exit 1
        fi
    done
}

# Function to set up the entire environment
setup_env() {
    check_rust_tools
    
    echo "Using Android SDK: $ANDROID_HOME"
    echo "Using Android NDK: $ANDROID_NDK_HOME"

    echo "Ensuring rust targets are installed..."
    rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
}

# Function to build Rust code
build_rust() {
    echo "Building Rust code for Android architectures..."
    
    # Mapping of rust target to Android arch name
    declare -A targets
    targets=(
        ["aarch64-linux-android"]="arm64-v8a"
        ["armv7-linux-androideabi"]="armeabi-v7a"
        ["i686-linux-android"]="x86"
        ["x86_64-linux-android"]="x86_64"
    )

    # Use cargo-ndk to handle the heavy lifting
    for target in "${!targets[@]}"; do
        echo "Building for $target..."
        cargo ndk -t "$target" -o "$BUILD_DIR/jni" build -p dmesh --release
    done
    
    # cargo-ndk -o build/jni will create build/jni/arm64-v8a/libdmesh.so etc.
    # Note: cargo-ndk sometimes uses slightly different arch names or paths,
    # but -o usually follows the jniLibs convention which matches our needs.
}

# Function to build Java classes
build_java() {
    echo "Building Java classes..."
    
    # Find the highest available android.jar
    ANDROID_JAR=$(find "$SDK_DIR/platforms" -name "android.jar" | sort -V | tail -n 1)
    if [ -z "$ANDROID_JAR" ]; then
        echo "Error: Could not find android.jar in $SDK_DIR/platforms. Check your SDK installation."
        exit 1
    fi

    mkdir -p "$BUILD_DIR/java"
    
    # Source directory for Java files
    SRC_DIR="java/rust/src/main/java"
    
    # Compile all Java files in the source tree
    find "$SRC_DIR" -name "*.java" > "$BUILD_DIR/java_sources.txt"
    javac -d "$BUILD_DIR/java" -cp "$ANDROID_JAR" @"$BUILD_DIR/java_sources.txt"

    # Create classes.jar
    echo "Creating classes.jar..."
    (cd "$BUILD_DIR/java" && jar cvf "../classes.jar" .)
}

# Function to package the AAR
package_aar() {
    echo "Packaging AAR..."

    # Create a temporary directory for AAR structure
    TMP_AAR_DIR=$(mktemp -d)
    
    # 1. Create AndroidManifest.xml
    cat <<EOF > "$TMP_AAR_DIR/AndroidManifest.xml"
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.github.costinm.dmeshnative">
</manifest>
EOF

    # 2. Copy classes.jar
    cp "$BUILD_DIR/classes.jar" "$TMP_AAR_DIR/"

    # 3. Copy JNI libs (already prepared by cargo-ndk)
    cp -r "$BUILD_DIR/jni" "$TMP_AAR_DIR/"

    # 4. Zip everything into .aar
    (cd "$TMP_AAR_DIR" && zip -r "$AAR_NAME" .)
    mkdir -p target
    cp "$TMP_AAR_DIR/$AAR_NAME" "target/"
    
    # Cleanup
    rm -rf "$TMP_AAR_DIR"

    echo "Successfully created target/$AAR_NAME"
}

# Main logic
main() {
    setup_env

    if [[ "$1" == "--setup" ]]; then
        return
    fi

    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"

    build_rust
    build_java
    package_aar
}

main "$@"
