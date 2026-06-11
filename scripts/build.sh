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

CRATES="mesh-init ssh-mesh mesh pmond mcp mesh9p traceweb sftp-server lmesh ssh-config"
BIN_TARGETS="h2t meshkeys sshmc mesh-init ssh-mesh mesh pmond mcp-pmond mesh9p traceweb sftp-server lmesh ssh-config"
INSTALL_BIN_TARGETS="$BIN_TARGETS dmesh"
EXAMPLE_BIN_TARGETS="mesh-init ssh-mesh sshmc pmond lmesh mcp-pmond mesh9p sftp-server h2t meshkeys"

copy_runtime_bins() {
    local src="$1"
    local dest="$2"
    shift 2
    local bins="$*"
    local missing=0

    mkdir -p "$dest"
    for bin in $bins; do
        if [ -f "$src/$bin" ]; then
            cp -f "$src/$bin" "$dest/"
            chmod +x "$dest/$bin"
        else
            echo "Missing runtime binary: $src/$bin" >&2
            missing=1
        fi
    done

    return "$missing"
}

find_busybox() {
    local busybox="${1:-}"

    if [ -n "$busybox" ] && [ -x "$busybox" ]; then
        printf '%s\n' "$busybox"
        return 0
    fi
    if command -v busybox >/dev/null 2>&1; then
        command -v busybox
        return 0
    fi
    if [ -x "/ws/initos/target/nix/bin/busybox" ]; then
        printf '%s\n' "/ws/initos/target/nix/bin/busybox"
        return 0
    fi
    if [ -x "/usr/bin/busybox" ]; then
        printf '%s\n' "/usr/bin/busybox"
        return 0
    fi

    return 1
}

default_nix_profile() {
    local target_profile="$PWD/target/nix/profile"
    if [ ! -e "$target_profile" ] && [ -e "$PWD/target/nix/profiles" ]; then
        target_profile="$PWD/target/nix/profiles"
    fi
    printf '%s\n' "$target_profile"
}

install_busybox_tree() {
    local busybox="$1"
    local dest="$2"

    rm -rf "$dest/bin"
    mkdir -p "$dest/bin"
    cp -f "$busybox" "$dest/bin/busybox"
    chmod +x "$dest/bin/busybox"
    (
        cd "$dest/bin"
        for applet in $(./busybox --list); do
            if [ "$applet" != "busybox" ] && [ ! -e "$applet" ]; then
                ln -s busybox "$applet"
            fi
        done
    )
}

stage_examples() {
    local src="${1:-}"
    local root="${2:-${SSH_MESH_EXAMPLE_ROOT:-$PWD/target/examples}}"
    local opt="${3:-${SSH_MESH_OPT_DIR:-$root/opt}}"
    local busybox

    if [ -z "$src" ]; then
        if [ -d "target/x86_64-unknown-linux-musl/release" ]; then
            src="target/x86_64-unknown-linux-musl/release"
        else
            src="target/debug"
        fi
    fi

    if [ ! -d "$src" ]; then
        echo "Example binary source does not exist: $src" >&2
        return 1
    fi

    busybox="$(find_busybox "${SSH_MESH_BUSYBOX:-}")" || {
        echo "Missing required busybox; set SSH_MESH_BUSYBOX=/path/to/busybox" >&2
        return 1
    }

    echo "Staging examples from $src"
    echo "  state root: $root"
    echo "  opt root:   $opt"

    rm -rf "$root/bin" "$opt/ssh-mesh/bin"
    mkdir -p "$opt/ssh-mesh/bin" "$root/examples"
    copy_runtime_bins "$src" "$opt/ssh-mesh/bin" $EXAMPLE_BIN_TARGETS
    cp -f linux/bin/vrun "$opt/ssh-mesh/bin/vrun"
    chmod +x "$opt/ssh-mesh/bin/vrun"
    ln -sf vrun "$opt/ssh-mesh/bin/initos-vrun"
    install_busybox_tree "$busybox" "$opt/busybox"

    rm -rf "$root/examples/bwrap-nonet" "$root/examples/vm-nonet"
    cp -a docs/examples/bwrap-nonet "$root/examples/bwrap-nonet"
    cp -a docs/examples/vm-nonet "$root/examples/vm-nonet"

    echo "Examples staged under $root"
}

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
    local dest="${1:-target/opt/ssh-mesh}"
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
command = "/opt/busybox/bin/sh"
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
command = "/opt/busybox/bin/sh"
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
    local release_dir="target/x86_64-unknown-linux-musl/release"
    
    mkdir -p "$dest/bin"

    echo "Building release binaries with musl..."
    cargo build --target x86_64-unknown-linux-musl --release --workspace

    echo "Installing runtime binaries to $dest/bin..."
    copy_runtime_bins "$release_dir" "$dest/bin" $BIN_TARGETS
    if [ -f "$release_dir/dmesh" ]; then
        cp -f "$release_dir/dmesh" "$dest/bin/dmesh_rs"
        chmod +x "$dest/bin/dmesh_rs"
    fi
    
    echo "Copying scripts..."
    cp -r bin/* "$dest/bin/"
    cp -f linux/bin/vrun "$dest/bin/vrun"
    ln -sf vrun "$dest/bin/initos-vrun"
    chmod +x "$dest/bin/"*

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

erofs() {
    local out="${1:-$PWD/target/erofs}"
    local busybox="${2:-busybox}"
    local initos_vm="${3:-bin/initos-init-vm}"
    local mesh_bin="${4:-}"

    busybox="$(find_busybox "$busybox")" || {
        echo "Error: busybox binary not found" >&2
        return 1
    }

    # Fallback for mesh_bin to debug if release is not found
    if [ -z "$mesh_bin" ] || [ ! -d "$mesh_bin" ]; then
        if [ -d "target/x86_64-unknown-linux-musl/release" ]; then
            mesh_bin="target/x86_64-unknown-linux-musl/release"
        elif [ -d "target/x86_64-unknown-linux-musl/debug" ]; then
            mesh_bin="target/x86_64-unknown-linux-musl/debug"
        else
            mesh_bin="target/x86_64-unknown-linux-musl/release"
        fi
    fi

    mkdir -p "$out/img" "$out/bin"
    local rootfs="$out/rootfs"
    rm -rf "$rootfs"
    
    # Pre-create all expected VM directories/mountpoints to avoid Read-only FS errors
    mkdir -p "$rootfs"/{opt/busybox/bin,opt/initos/bin,opt/ssh-mesh/bin}
    mkdir -p "$rootfs"/{dev,dev/shm,proc,sys,sysroot,home,mnt,media/cdrom,media/usb,run,etc,tmp,x,data,z,a,nix,src,initos,boot/efi,var/cache,var/log,usr/bin,usr/sbin,usr/lib,usr/lib64,out,lib}

    install_busybox_tree "$busybox" "$rootfs/opt/busybox"

    ln -s opt/busybox/bin "$rootfs/bin"
    ln -s opt/busybox/bin "$rootfs/sbin"

    if [ -f "$initos_vm" ]; then
        cp "$initos_vm" "$rootfs/opt/initos/bin/initos-init-vm"
        chmod +x "$rootfs/opt/initos/bin/initos-init-vm"
    fi

    if [ -d "$mesh_bin" ]; then
        copy_runtime_bins "$mesh_bin" "$rootfs/opt/ssh-mesh/bin" $BIN_TARGETS
    fi

    mkfs.erofs --all-root --force-uid=0 -T0 -zlz4 "$out/img/ssh-mesh.erofs" "$rootfs"
    ln -sf ssh-mesh.erofs "$out/img/initos.erofs"

    cat > "$out/bin/ssh-mesh-erofs" <<EOF
#!/bin/sh
echo "$out/img/ssh-mesh.erofs"
EOF
    chmod +x "$out/bin/ssh-mesh-erofs"
    
    echo "EROFS image created at $out/img/ssh-mesh.erofs"
}


vm() {
    local profile="${1:-$PWD/target/vm/initos-vm}"
    echo "Building VM profile into $profile..."
    nix build .#default -o "$profile"
}

profile() {
    # Default NIX_PROFILE target path
    local target_profile="${1:-${NIX_PROFILE:-$(default_nix_profile)}}"

    # If target_profile is a real directory and not a symlink, delete it so Nix can manage it
    if [ -d "${target_profile}" ] && [ ! -L "${target_profile}" ]; then
        echo "Removing non-symlink directory at ${target_profile} so Nix can manage the profile..."
        rm -rf "${target_profile}"
    fi

    echo "Updating Nix profile: ${target_profile}"
    if nix profile list --profile "${target_profile}" 2>/dev/null | grep -q "ssh-mesh"; then
        echo "Upgrading ssh-mesh package in profile..."
        nix profile upgrade --profile "${target_profile}" --all
    else
        echo "Adding ssh-mesh package to profile..."
        nix profile add . --profile "${target_profile}"
    fi

    # Build microvm runners and create their stamps
    local microvm_work="target/vm/microvm-echo"
    local profile_real=$(readlink -f "${target_profile}")
    mkdir -p "${microvm_work}"
    for hv in crosvm qemu cloud-hypervisor; do
        local rlink="${microvm_work}/runner-${hv}"
        local stamp="${microvm_work}/runner-${hv}.sha256"
        local fhash
        fhash=$(printf '%s\n' "${profile_real}" "${hv}" "$(sha256sum "tests/microvm-echo/flake.nix" 2>/dev/null | awk '{print $1}')" | sha256sum | awk '{print $1}')
        if [ ! -L "${rlink}" ] || [ ! -f "${stamp}" ] || [ "$(cat "${stamp}" 2>/dev/null)" != "${fhash}" ]; then
            rm -f "${rlink}"
            echo "Building microvm runner for ${hv}..."
            nix build ./tests/microvm-echo#runner-${hv} --override-input initosProfile "path:${profile_real}" -o "${rlink}"
            printf '%s\n' "${fhash}" > "${stamp}"
        fi
    done
}

build() {
    # Default NIX_PROFILE target path
    local target_profile="${1:-${NIX_PROFILE:-$(default_nix_profile)}}"
    
    echo "=== 1. Building release binaries with musl ==="
    cargo build --target x86_64-unknown-linux-musl --release --workspace
    
    echo "=== 2. Building JNI native library and Java classes ==="
    jni "target/opt/ssh-mesh"
    
    echo "=== 3. Staging local examples ==="
    stage_examples "target/x86_64-unknown-linux-musl/release" "$PWD/target/examples" "$PWD/target/examples/opt"

    echo "=== 4. Building EROFS rootfs ==="
    erofs "target/erofs" "$(which busybox 2>/dev/null || echo "")" "bin/initos-init-vm" "target/x86_64-unknown-linux-musl/release"
    
    echo "=== 5. Assembling and upgrading local VM profile ==="
    profile "${target_profile}"
}
"$@"
