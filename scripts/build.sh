#!/bin/bash

# Keep the Dockerfile in sync

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

export CC_aarch64_unknown_linux_musl=aarch64-linux-gnu-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc 

#RUST_FLAGS="-j 1"

export DEST=${DEST:-/opt/ssh-mesh}

CRATES="mesh-init ssh-mesh mesh pmond mcp mesh9p traceweb sftp-server lmesh ssh-config"
BIN_TARGETS="h2t meshkeys sshmc mesh-init ssh-mesh mesh pmond mcp-pmond mesh9p traceweb sftp-server lmesh ssh-config"
INSTALL_BIN_TARGETS="$BIN_TARGETS dmesh"
EXAMPLE_BIN_TARGETS="mesh-init ssh-mesh mesh sshmc pmond lmesh mcp-pmond mesh9p sftp-server h2t meshkeys"

help() {
    cat <<'EOF'
Usage: scripts/build.sh [command] [args...]

Default command:
  scripts/build.sh
      Build Rust musl release binaries and create distributable artifacts under
      target/dist, including target/dist/opt and target/dist/img/ssh-mesh.erofs.

Fresh target/examples sequence:
  scripts/build.sh profile
      Build/update the repo-local Nix profile with VM helpers, kernels, rootfs
      assets, and hypervisors used by the examples.

  scripts/build.sh
      Build the Rust binaries and create target/dist artifacts.

  docs/examples/start_all.sh
      Start host1, host2, host3-vm, and activated app environments.

Common commands:
  help                 Show this help.
  rust                 Build x86_64 musl release Rust binaries.
  deps [path]          Add missing build dependencies to the Nix profile.
  deploy_examples      Compatibility alias for dist.
  stage_examples       Compatibility alias for staging target/dist/opt.
  stage_example_tree   Refresh checked-in example files under target/examples.
  profile [path]       Build/update the Nix profile. Default: target/nix/profile,
                       or existing target/nix/profiles.
  dist [path]          Build release binaries into an install-like tree.
  erofs [out ...]      Build the VM EROFS rootfs image.
  install [path]       Install runtime binaries and scripts. Default: /opt/ssh-mesh.
  dmesh_java [path]    Build dmesh plus the Java/JNI artifacts.
  build [profile]      Full local build: Rust, examples, EROFS, profile.

Environment:
  SSH_MESH_BUSYBOX         Busybox path used for staged target/dist/opt/busybox.
  NIX_PROFILE              Nix profile used by examples. Default: target/nix/profile,
                           or existing target/nix/profiles.
EOF
}

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
    if [ -n "${NIX_PROFILE:-}" ] && [ -x "${NIX_PROFILE}/bin/busybox" ]; then
        printf '%s\n' "${NIX_PROFILE}/bin/busybox"
        return 0
    fi
    if [ -x "$PWD/target/nix/profile/bin/busybox" ]; then
        printf '%s\n' "$PWD/target/nix/profile/bin/busybox"
        return 0
    fi
    if [ -x "$PWD/target/nix/profiles/bin/busybox" ]; then
        printf '%s\n' "$PWD/target/nix/profiles/bin/busybox"
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
        if [ -e "$PWD/target/nix/profiles/profile" ]; then
            target_profile="$PWD/target/nix/profiles/profile"
        else
            target_profile="$PWD/target/nix/profiles"
        fi
    fi
    printf '%s\n' "$target_profile"
}

resolve_nix_profile() {
    local profile_path="${1:-$(default_nix_profile)}"

    if [ -d "$profile_path" ] && [ ! -d "$profile_path/bin" ] && [ -e "$profile_path/profile" ]; then
        profile_path="$profile_path/profile"
    fi

    printf '%s\n' "$profile_path"
}

prepend_nix_profile_path() {
    local profile_path

    profile_path="$(resolve_nix_profile "${1:-$(default_nix_profile)}")"

    if [ -d "$profile_path/bin" ]; then
        case ":${PATH:-}:" in
            *":$profile_path/bin:"*) ;;
            *) export PATH="$profile_path/bin:${PATH:-}" ;;
        esac
    fi
}

prepare_nix_profile_path() {
    local target_profile="$1"

    if [ -d "${target_profile}" ] && [ ! -L "${target_profile}" ]; then
        echo "Removing non-symlink directory at ${target_profile} so Nix can manage the profile..."
        rm -rf "${target_profile}"
    fi
}

configure_musl_toolchain() {
    local profile_path
    local linker
    local ar

    profile_path="$(resolve_nix_profile "${1:-$(default_nix_profile)}")"
    prepend_nix_profile_path "$profile_path"

    linker="$(command -v x86_64-unknown-linux-musl-gcc || true)"
    if [ -z "$linker" ]; then
        linker="$(command -v x86_64-linux-musl-gcc || true)"
    fi
    if [ -z "$linker" ]; then
        echo "Missing x86_64 musl gcc in PATH; run scripts/build.sh deps" >&2
        return 1
    fi

    export CC_x86_64_unknown_linux_musl="$linker"
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$linker"

    ar="$(command -v x86_64-unknown-linux-musl-ar || true)"
    if [ -n "$ar" ]; then
        export AR_x86_64_unknown_linux_musl="$ar"
    fi
}

configure_swagger_ui_assets() {
    local profile_path
    local swagger_zip

    profile_path="$(resolve_nix_profile "${1:-$(default_nix_profile)}")"
    swagger_zip="$profile_path/share/ssh-mesh/swagger-ui/v5.17.14.zip"

    if [ ! -e "$swagger_zip" ]; then
        echo "Missing Swagger UI zip in Nix profile; run scripts/build.sh deps" >&2
        return 1
    fi

    export SWAGGER_UI_DOWNLOAD_URL="file://$swagger_zip"
}

add_nix_profile_deps() {
    local target_profile="${1:-${NIX_PROFILE:-$(default_nix_profile)}}"
    shift || true
    local deps="${*:-musl-toolchain swagger-ui-assets}"
    local dep

    target_profile="$(resolve_nix_profile "$target_profile")"
    prepare_nix_profile_path "$target_profile"

    echo "Adding missing Nix profile dependencies to: ${target_profile}"
    for dep in $deps; do
        if nix profile list --profile "${target_profile}" 2>/dev/null | grep -q "$dep"; then
            echo "  ${dep}: already present"
        else
            echo "  ${dep}: nix profile add .#${dep}"
            nix profile add ".#${dep}" --profile "${target_profile}" || return $?
        fi
    done

    prepend_nix_profile_path "$target_profile"
}

deps() {
    add_nix_profile_deps "$@"
}

ensure_musl_toolchain_profile() {
    local target_profile="${1:-${NIX_PROFILE:-$(default_nix_profile)}}"

    target_profile="$(resolve_nix_profile "$target_profile")"
    prepend_nix_profile_path "$target_profile"
    if ! command -v x86_64-unknown-linux-musl-gcc >/dev/null 2>&1 ||
       ! command -v x86_64-linux-musl-gcc >/dev/null 2>&1; then
        add_nix_profile_deps "$target_profile" musl-toolchain
    fi
    if [ ! -e "$target_profile/share/ssh-mesh/swagger-ui/v5.17.14.zip" ]; then
        add_nix_profile_deps "$target_profile" swagger-ui-assets
    fi

    configure_musl_toolchain "$target_profile"
    configure_swagger_ui_assets "$target_profile"
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

stage_opt_tree() {
    local src="$1"
    local opt="$2"
    local busybox="$3"

    rm -rf "$opt/ssh-mesh" "$opt/busybox" "$opt/initos"
    mkdir -p "$opt/ssh-mesh/bin" "$opt/initos/bin"

    copy_runtime_bins "$src" "$opt/ssh-mesh/bin" $EXAMPLE_BIN_TARGETS
    cp -f linux/bin/vrun "$opt/ssh-mesh/bin/vrun"
    ln -sf vrun "$opt/ssh-mesh/bin/initos-vrun"
    cp -f bin/run_bwrap.sh "$opt/ssh-mesh/bin/run_bwrap.sh"
    cp -f bin/run_podman.sh "$opt/ssh-mesh/bin/run_podman.sh"
    chmod +x "$opt/ssh-mesh/bin/"*

    cp -f bin/initos-init-vm "$opt/initos/bin/initos-init-vm"
    chmod +x "$opt/initos/bin/initos-init-vm"

    install_busybox_tree "$busybox" "$opt/busybox"
}

stage_examples() {
    local src="${1:-}"
    local root="${2:-$PWD/target/dist}"
    local opt="$root/opt"
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
    echo "  artifact root: $root"
    echo "  opt root:   $opt"

    mkdir -p "$root"
    stage_opt_tree "$src" "$opt" "$busybox"

    echo "Artifacts staged under $root"
}

stage_example_tree() {
    local root="${1:-$PWD/target/examples}"
    local opt="${2:-$PWD/target/dist/opt}"

    if [ ! -d "docs/examples" ]; then
        echo "Missing docs/examples source tree" >&2
        return 1
    fi
    if [ ! -d "$opt/ssh-mesh/bin" ]; then
        echo "Missing staged /opt tree under $opt; run scripts/build.sh first" >&2
        return 1
    fi

    echo "Refreshing example tree under $root"
    mkdir -p "$root" "$root/bin"
    cp -a docs/examples/. "$root/"
    cp -a "$opt/ssh-mesh/bin/." "$root/bin/"
    if [ -x "$opt/busybox/bin/busybox" ]; then
        cp -f "$opt/busybox/bin/busybox" "$root/bin/busybox"
        chmod +x "$root/bin/busybox"
    fi
}

rust() {
    ensure_musl_toolchain_profile "${NIX_PROFILE:-$(default_nix_profile)}"
    echo "Building release binaries with musl..."
    cargo build --target x86_64-unknown-linux-musl --release --workspace --exclude dmesh
}

deploy_examples() {
    local src="${1:-target/x86_64-unknown-linux-musl/release}"
    local root="${2:-$PWD/target/dist}"

    stage_examples "$src" "$root"
    stage_example_tree "$PWD/target/examples" "$root/opt"
}

default() {
    rust
    dist "$PWD/target/dist" "target/x86_64-unknown-linux-musl/release"
    stage_example_tree "$PWD/target/examples" "$PWD/target/dist/opt"
}

setup() {
    ensure_musl_toolchain_profile "${NIX_PROFILE:-$(default_nix_profile)}"
}
debug() {
    ensure_musl_toolchain_profile "${NIX_PROFILE:-$(default_nix_profile)}"
    cargo build --target x86_64-unknown-linux-musl --workspace --exclude dmesh

    #_all x86_64-unknown-linux-musl 
}

release() {

    _all x86_64-unknown-linux-musl --release
}

arm() {
    _all aarch64-unknown-linux-musl --release
}

_all() {
    local target=$1
    local mode=$2

    if [ "$target" = "x86_64-unknown-linux-musl" ]; then
        ensure_musl_toolchain_profile "${NIX_PROFILE:-$(default_nix_profile)}"
    fi
    
    for bin in $CRATES; do
        cargo build ${RUST_FLAGS} --target $target ${mode} -p $bin
    done


    #cargo build --target $target ${mode} --features pmon -p ssh-mesh
}

# upstream unpfs
unpfs() {
    ensure_musl_toolchain_profile "${NIX_PROFILE:-$(default_nix_profile)}"
    cargo install --target x86_64-unknown-linux-musl unpfs
}

push() {
    # Can't push debug builds - the embeded files are loaded from disk.
    release
    scp target/x86_64-unknown-linux-musl/release/{pmond,ssh-mesh} a1:/data/INITOS/bin
}

dist() {
    local dest="${1:-$PWD/target/dist}"
    local release_dir="${2:-target/x86_64-unknown-linux-musl/release}"
    local busybox

    if [ ! -x "$release_dir/ssh-mesh" ]; then
        rust
    fi

    busybox="$(find_busybox "${SSH_MESH_BUSYBOX:-}")" || {
        echo "Missing required busybox; set SSH_MESH_BUSYBOX=/path/to/busybox" >&2
        return 1
    }

    echo "Creating dist artifacts under $dest"
    mkdir -p "$dest"
    stage_opt_tree "$release_dir" "$dest/opt" "$busybox"
    erofs "$dest" "$busybox" "bin/initos-init-vm" "$dest/opt"

    local profile_path="${NIX_PROFILE:-$(default_nix_profile)}"
    if [ -f "$profile_path/img/vmlinux-cloud" ]; then
        cp -f "$profile_path/img/vmlinux-cloud" "$dest/img/vmlinux-cloud"
    elif [ -f "$profile_path/img/bzImage" ]; then
        cp -f "$profile_path/img/bzImage" "$dest/img/bzImage"
    else
        echo "Warning: no VM kernel found under $profile_path/img; run scripts/build.sh profile for VM examples" >&2
    fi

    local modules_src=""
    if [ -f "$profile_path/img/modules-cloud.erofs" ]; then
        modules_src="$profile_path/img/modules-cloud.erofs"
    elif [ -f "$profile_path/img/modules-cloudfs.erofs" ]; then
        modules_src="$profile_path/img/modules-cloudfs.erofs"
    elif [ -f "$profile_path/img/modules.erofs" ]; then
        modules_src="$profile_path/img/modules.erofs"
    fi
    if [ -n "$modules_src" ]; then
        cp -f "$modules_src" "$dest/img/modules-cloud.erofs"
        ln -sf modules-cloud.erofs "$dest/img/modules-cloudfs.erofs"
    else
        echo "Warning: no VM modules EROFS found under $profile_path/img; run scripts/build.sh profile for VM examples" >&2
    fi

    echo "Dist completed at $dest"
}

install() {
    local dest="${1:-/opt/ssh-mesh}"
    local release_dir="target/x86_64-unknown-linux-musl/release"
    
    mkdir -p "$dest/bin"

    rust

    echo "Installing runtime binaries to $dest/bin..."
    copy_runtime_bins "$release_dir" "$dest/bin" $BIN_TARGETS
    
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

dmesh_java() {
    local dest="${1:-target/opt/ssh-mesh}"
    local release_dir="target/x86_64-unknown-linux-musl/release"

    mkdir -p "$dest/bin"

    ensure_musl_toolchain_profile "${NIX_PROFILE:-$(default_nix_profile)}"

    echo "Building dmesh release binary with musl..."
    cargo build -p dmesh --target x86_64-unknown-linux-musl --release

    if [ -f "$release_dir/dmesh" ]; then
        cp -f "$release_dir/dmesh" "$dest/bin/dmesh_rs"
        chmod +x "$dest/bin/dmesh_rs"
        echo "  -> $dest/bin/dmesh_rs"
    fi

    jni "$dest"
}

# Build aarch64 release binaries into a separate dist directory.
arm_release() {
    local dest="${1:-target/dist-aarch64}"
    mkdir -p "$dest/bin" "$dest/lib/arm64-v8a"

    echo "Building aarch64 release (musl) for runtime crates..."
    cargo build --target aarch64-unknown-linux-musl --release --workspace --exclude dmesh

    echo "Copying aarch64 binaries..."
    for bin in $BIN_TARGETS; do
        if [ -f "target/aarch64-unknown-linux-musl/release/$bin" ]; then
            cp "target/aarch64-unknown-linux-musl/release/$bin" "$dest/bin/"
        fi
    done

    echo "Copying scripts..."
    cp -r bin/* "$dest/bin/"
    chmod +x "$dest/bin/"*

    echo "aarch64 release completed at $dest"
}

erofs() {
    local out="${1:-$PWD/target/erofs}"
    local busybox="${2:-busybox}"
    local initos_vm="${3:-bin/initos-init-vm}"
    local opt_src="${4:-$PWD/target/dist/opt}"

    busybox="$(find_busybox "$busybox")" || {
        echo "Error: busybox binary not found" >&2
        return 1
    }

    mkdir -p "$out/img" "$out/bin"
    local rootfs="$out/rootfs"
    rm -rf "$rootfs"
    
    # Pre-create all expected VM directories/mountpoints to avoid Read-only FS errors
    mkdir -p "$rootfs"/{opt/busybox/bin,opt/initos/bin,opt/ssh-mesh/bin}
    mkdir -p "$rootfs"/{dev,dev/shm,proc,sys,sysroot,home,mnt,media/cdrom,media/usb,run,etc,tmp,out,x,data,z,a,nix,src,initos,boot/efi,var/cache,var/log,usr/bin,usr/sbin,usr/lib,usr/lib64,lib,lib/modules,lib/firmware}

    ln -s opt/busybox/bin "$rootfs/bin"
    ln -s opt/busybox/bin "$rootfs/sbin"

    if [ -d "$opt_src/ssh-mesh/bin" ] && [ -d "$opt_src/busybox/bin" ]; then
        cp -a "$opt_src/." "$rootfs/opt/"
    else
        echo "Staged opt tree not found at $opt_src; creating one from release binaries"
        stage_opt_tree "target/x86_64-unknown-linux-musl/release" "$rootfs/opt" "$busybox"
    fi

    if [ -f "$initos_vm" ] && [ ! -x "$rootfs/opt/initos/bin/initos-init-vm" ]; then
        cp -f "$initos_vm" "$rootfs/opt/initos/bin/initos-init-vm"
        chmod +x "$rootfs/opt/initos/bin/initos-init-vm"
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

    prepare_nix_profile_path "$target_profile"

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
    rust

    echo "=== 2. Assembling and upgrading local VM profile ==="
    profile "${target_profile}"

    echo "=== 3. Creating dist artifacts ==="
    dist "$PWD/target/dist" "target/x86_64-unknown-linux-musl/release"

    echo "=== 4. Refreshing example tree ==="
    stage_example_tree "$PWD/target/examples" "$PWD/target/dist/opt"
}

main() {
    local cmd="${1:-default}"
    if [ "$#" -gt 0 ]; then
        shift
    fi

    case "$cmd" in
        -h|--help|help)
            help
            ;;
        default|rust|deps|deploy_examples|stage_examples|stage_example_tree|setup|debug|release|arm|unpfs|push|dist|install|jni|dmesh_java|arm_release|erofs|vm|profile|build)
            "$cmd" "$@"
            ;;
        *)
            echo "Unknown command: $cmd" >&2
            echo >&2
            help >&2
            return 2
            ;;
    esac
}

main "$@"
