#!/bin/bash

# Keep the Dockerfile in sync

export CC_aarch64_unknown_linux_musl=aarch64-linux-gnu-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc 

# Musl SDK must be installed - the script will download in setup() if missing.
export MUSL_DIR=${MUSL_DIR:-/opt/musl}
export PATH=$MUSL_DIR/bin:$PATH
    
# export PATH="$MUSL_DIR/x86_64-linux-musl-native/bin:$PATH"
# export CC_x86_64_unknown_linux_musl=x86_64-linux-musl-gcc
# export CXX_x86_64_unknown_linux_musl=x86_64-linux-musl-g++
# export AR_x86_64_unknown_linux_musl=x86_64-linux-musl-ar
# export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc

#RUST_FLAGS="-j 1"

export DEST=${DEST:-/opt/ssh-mesh}

CRATES="mesh-init ssh-mesh mesh pmond mesh9p traceweb sftp-server lmesh"
BIN_TARGETS="h2t meshkeys sshmc mesh-init ssh-mesh mesh pmond mesh9p traceweb sftp-server lmesh"

setup() {
    if [ ! -d "$MUSL_DIR" ]; then
        mkdir -p $MUSL_DIR
        cd $MUSL_DIR
        # No -O - stdout
        curl -L https://musl.cc/x86_64-linux-musl-native.tgz | \
            tar xzf -
    fi 

}
debug() {
    cargo build --target x86_64-unknown-linux-musl --workspace

    #_all x86_64-unknown-linux-musl 
}

release() {
    # (cd crates/otel && docker run --rm -v /ws/rust/ssh-mesh:/home/rust/src \
    #   -w /home/rust/src/crates/otel \
    #   messense/rust-musl-cross:x86_64-musl \
    #   cargo build --release --bin otel)

    _all x86_64-unknown-linux-musl --release
}

arm() {
    _all aarch64-unknown-linux-musl --release
}

_all() {
    local target=$1
    local mode=$2
    
    for bin in $CRATES; do
        cargo build ${RUST_FLAGS} --target $target ${mode} -p $bin
    done


    #cargo build --target $target ${mode} --features pmon -p ssh-mesh
}

# upstream unpfs
unpfs() {
    cargo install --target x86_64-unknown-linux-musl unpfs
}

push() {
    # Can't push debug builds - the embeded files are loaded from disk.
    release
    scp target/x86_64-unknown-linux-musl/release/{pmond,ssh-mesh} a1:/data/INITOS/bin
}

dist() {
    local dest="${1:-$HOME/opt/ssh-mesh}"
    mkdir -p "$dest/bin"

    echo "Building release binaries with musl..."
    #release
    cargo build --target x86_64-unknown-linux-musl --release --workspace
    echo "Copying binaries..."
    for bin in $BIN_TARGETS; do
        cp target/x86_64-unknown-linux-musl/release/$bin $dest/bin
    done

    #find target/x86_64-unknown-linux-musl/release -maxdepth 1 -type f -executable -exec cp {} "$dest/bin/" \;
    
    echo "Stripping binaries..."
    strip "$dest/bin/"* || true

    local root_conf="$dest/root/.config/mesh-init"
    local root_jobs="$dest/root/.config/mesh/jobs"

    local sys_conf="$dest/system/.config/mesh-init"
    local sys_jobs="$dest/system/.config/mesh/jobs"

    mkdir -p "$root_conf" "$root_jobs/work" "$sys_conf" "$sys_jobs/work"

    echo "Setting up mesh-init configs..."
    for f in crates/mesh-init/testdata/*.toml; do
        cp "$f" "$root_conf/"
        cp "$f" "$sys_conf/"
    done

    # Modify system configs to use different ports
    sed -i 's/15022/25022/g; s/8080/8081/g; s/8081/8082/g; s/14022/24022/g' "$sys_conf/"*.toml

    echo "Creating job files..."
    cat <<EOF > "$root_jobs/status_network.toml"
name = "status_network"
command = "/bin/sh"
args = ["-c", "echo 'Network is unmetered' > $dest/root_network_status.txt"]
priority = 500
persisted = false

[schedule]
periodic_secs = 60

[constraints]
network_type = "unmetered"
EOF

    cat <<EOF > "$root_jobs/status_periodic.toml"
name = "status_periodic"
command = "/bin/sh"
args = ["-c", "date > $dest/root_periodic_status.txt"]
priority = 500
persisted = false

[schedule]
periodic_secs = 30
EOF

    cp "$root_jobs/status_network.toml" "$sys_jobs/status_network.toml"
    sed -i "s|root_network_status|system_network_status|g" "$sys_jobs/status_network.toml"
    
    cp "$root_jobs/status_periodic.toml" "$sys_jobs/status_periodic.toml"
    sed -i "s|root_periodic_status|system_periodic_status|g" "$sys_jobs/status_periodic.toml"

    echo "Dist completed at $dest"
}

install() {
    local dest="${1:-/opt/ssh-mesh}"
    
    mkdir -p "$dest/bin" "$dest/lib"

    echo "Building release binaries with musl..."
    cargo build --target x86_64-unknown-linux-musl --release --workspace

    echo "Copying Rust binaries..."
    for bin in $BIN_TARGETS dmesh; do
        if [ -f "target/x86_64-unknown-linux-musl/release/$bin" ]; then
            if [ "$bin" == "dmesh" ]; then
                cp "target/x86_64-unknown-linux-musl/release/$bin" "$dest/bin/${bin}_rs"
            else
                cp "target/x86_64-unknown-linux-musl/release/$bin" "$dest/bin/"
            fi
        fi
    done
    
    echo "Copying scripts..."
    cp -r bin/* "$dest/bin/"
    chmod +x "$dest/bin/"*

    echo "Setting up Python environment..."
    python3 -m venv "$dest/.venv"
    "$dest/.venv/bin/pip" install -U pip maturin
    (cd python && "$dest/.venv/bin/maturin" build --release -o "$dest/wheels")
    "$dest/.venv/bin/pip" install --no-index --find-links="$dest/wheels" dmesh
    
    jni "$dest"
    echo "Install completed at $dest"
}

# Build JNI shared library + Java JAR.
# Layout: $dest/bin/dmesh.jar  $dest/lib/<arch>/libdmesh.so
# The .so must use a GNU target because musl does not support cdylib.
jni() {
    local dest="${1:-target/opt/ssh-mesh}"
    mkdir -p "$dest/bin" "$dest/lib"

    # Determine host architecture (Android convention names)
    local host_arch
    case "$(uname -m)" in
        x86_64)  host_arch="x86_64" ;;
        aarch64) host_arch="arm64-v8a" ;;
        armv7*)  host_arch="armeabi-v7a" ;;
        i?86)    host_arch="x86" ;;
        *)       host_arch="$(uname -m)" ;;
    esac

    # Build the JNI .so with GNU target (musl drops cdylib)
    local gnu_target
    case "$(uname -m)" in
        x86_64)  gnu_target="x86_64-unknown-linux-gnu" ;;
        aarch64) gnu_target="aarch64-unknown-linux-gnu" ;;
        *)       gnu_target="$(uname -m)-unknown-linux-gnu" ;;
    esac

    echo "Building JNI native library for $gnu_target..."
    cargo build -p dmesh --target "$gnu_target" --release \
        --no-default-features --features jni-wrapper

    local so_path="target/$gnu_target/release/libdmesh.so"
    if [ ! -f "$so_path" ]; then
        echo "Error: $so_path not found after build"
        return 1
    fi

    mkdir -p "$dest/lib/$host_arch"
    cp "$so_path" "$dest/lib/$host_arch/"
    echo "  -> $dest/lib/$host_arch/libdmesh.so"

    # Compile Java classes
    echo "Compiling Java classes..."
    local classes_dir="target/java/classes"
    rm -rf "$classes_dir"
    mkdir -p "$classes_dir"
    javac -d "$classes_dir" $(find java/rust/src/main/java -name "*.java")

    # Create JAR with Main-Class manifest
    echo "Creating dmesh.jar..."
    mkdir -p target/java
    echo "Main-Class: com.github.costinm.dmeshnative.Main" > target/java/MANIFEST.MF
    jar cfm "$dest/bin/dmesh.jar" target/java/MANIFEST.MF -C "$classes_dir" .
    echo "  -> $dest/bin/dmesh.jar"
}

# Build aarch64 release binaries into a separate dist directory.
arm_release() {
    local dest="${1:-target/dist-aarch64}"
    mkdir -p "$dest/bin" "$dest/lib/arm64-v8a"

    echo "Building aarch64 release (musl) for all crates..."
    cargo build --target aarch64-unknown-linux-musl --release --workspace

    echo "Copying aarch64 binaries..."
    for bin in $BIN_TARGETS dmesh; do
        if [ -f "target/aarch64-unknown-linux-musl/release/$bin" ]; then
            if [ "$bin" == "dmesh" ]; then
                cp "target/aarch64-unknown-linux-musl/release/$bin" "$dest/bin/${bin}_rs"
            else
                cp "target/aarch64-unknown-linux-musl/release/$bin" "$dest/bin/"
            fi
        fi
    done

    echo "Building JNI .so for aarch64..."
    cargo build -p dmesh --target aarch64-unknown-linux-gnu --release \
        --no-default-features --features jni-wrapper
    if [ -f "target/aarch64-unknown-linux-gnu/release/libdmesh.so" ]; then
        cp "target/aarch64-unknown-linux-gnu/release/libdmesh.so" "$dest/lib/arm64-v8a/"
    fi

    echo "Copying scripts..."
    cp -r bin/* "$dest/bin/"
    chmod +x "$dest/bin/"*

    # Build the JAR (arch-independent) if not already present
    if [ ! -f "$dest/bin/dmesh.jar" ]; then
        local classes_dir="target/java/classes"
        rm -rf "$classes_dir"
        mkdir -p "$classes_dir" target/java
        javac -d "$classes_dir" $(find java/rust/src/main/java -name "*.java")
        echo "Main-Class: com.github.costinm.dmeshnative.Main" > target/java/MANIFEST.MF
        jar cfm "$dest/bin/dmesh.jar" target/java/MANIFEST.MF -C "$classes_dir" .
    fi

    echo "aarch64 release completed at $dest"
}

"$@"
