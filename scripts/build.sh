#!/bin/bash

# Keep the Dockerfile in sync

export CC_aarch64_unknown_linux_musl=aarch64-linux-gnu-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc 


export MUSL_DIR=${MUSL_DIR:-/x/opt/musl}
export PATH=$MUSL_DIR/bin:$PATH
    
debug() {
    _all x86_64-unknown-linux-musl 
}

setup() {
    # No -O, single
    mkdir -p $MUSL_DIR
    cd $MUSL_DIR
    curl -L https://musl.cc/x86_64-linux-musl-native.tgz | \
        tar xzf -
    export PATH="$PWD/x86_64-linux-musl-native/bin:$PATH"
    export CC_x86_64_unknown_linux_musl=x86_64-linux-musl-gcc
    export CXX_x86_64_unknown_linux_musl=x86_64-linux-musl-g++
    export AR_x86_64_unknown_linux_musl=x86_64-linux-musl-ar
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc
}

#RUST_FLAGS="-j 1"

export DEST=${DEST:-/opt/ssh-mesh}

CRATES="mesh-init ssh-mesh mesh pmond mesh9p traceweb sftp-server lmesh"
BIN_TARGETS="h2t meshkeys sshmc mesh-init ssh-mesh mesh pmond mesh9p traceweb sftp-server lmesh"

release() {
    # (cd crates/otel && docker run --rm -v /ws/rust/ssh-mesh:/home/rust/src \
    #   -w /home/rust/src/crates/otel \
    #   messense/rust-musl-cross:x86_64-musl \
    #   cargo build --release --bin otel)

    _all x86_64-unknown-linux-musl --release

}

_all() {
    local target=$1
    local mode=$2
    
    for bin in $CRATES; do
        cargo build ${RUST_FLAGS} --target $target ${mode} -p $bin
    done


    #cargo build --target $target ${mode} --features pmon -p ssh-mesh
}

# upstream one 
unpfs() {
    cargo install --target x86_64-unknown-linux-musl unpfs
}

arm() {
    _all aarch64-unknown-linux-musl --release
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

"$@"
