{
  description = "ssh-mesh — SSH library and L4 proxy with certificate/JWT authentication";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        # MUSL target string for the current system
        muslTarget =
          if system == "x86_64-linux" then "x86_64-unknown-linux-musl"
          else if system == "aarch64-linux" then "aarch64-unknown-linux-musl"
          else throw "Unsupported system: ${system}";

        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        # Rust toolchain with musl target support
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          targets = [ muslTarget ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain (_: rustToolchain);

        # Common source filtering
        src = ./.;

        # Pre-fetch Swagger UI zip for utoipa-swagger-ui (no network in Nix sandbox)
        swaggerUiZip = pkgs.fetchurl {
          url = "https://github.com/swagger-api/swagger-ui/archive/refs/tags/v5.17.14.zip";
          sha256 = "1p6cf4zf3jrswqa9b7wwgxhp3ca2v5qrzxzfp8gv35r0h78484j8";
        };

        # Common build inputs
        nativeBuildInputs = with pkgs; [
          pkg-config
          curl
          python3
        ];

        # Common args for static MUSL builds
        # Following the official Crane cross-musl pattern:
        # just set CARGO_BUILD_TARGET + crt-static, no cross-compiler needed
        # for same-architecture builds.
        commonArgs = {
          inherit src nativeBuildInputs;
          version = "0.1.0";
          strictDeps = true;
          doCheck = false; # Tests require network/system resources

          CARGO_BUILD_TARGET = muslTarget;
          CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";

          # Copy pre-fetched Swagger UI zip so utoipa-swagger-ui's build.rs
          # can find it via the file:// protocol. Use install to set writable
          # permissions (nix store files are read-only).
          preBuild = ''
            install -m644 ${swaggerUiZip} $PWD/v5.17.14.zip
            export SWAGGER_UI_DOWNLOAD_URL="file://$PWD/v5.17.14.zip"
          '';
        };

        # Build workspace dependencies first (for caching)
        cargoArtifacts = craneLib.buildDepsOnly (commonArgs // {
          pname = "ssh-mesh-deps";
          cargoExtraArgs = "--features pmon -p ssh-mesh -p pmond";
        });

        # Build dependencies for the aggregate workspace package.
        allCargoArtifacts = craneLib.buildDepsOnly (commonArgs // {
          pname = "ssh-mesh-all-deps";
          cargoExtraArgs = "--workspace --bins --features ssh-mesh/pmon";
        });

        # Aggregate package containing all workspace binaries/components.
        ssh-mesh-full = craneLib.buildPackage (commonArgs // {
          cargoArtifacts = allCargoArtifacts;
          pname = "ssh-mesh-full";
          cargoExtraArgs = "--workspace --bins --features ssh-mesh/pmon";
        });

        # ssh-mesh binary — the primary binary
        ssh-mesh = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "ssh-mesh";
          cargoExtraArgs = "--features pmon -p ssh-mesh";
        });

        # pmond binary
        pmond = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "pmond";
          cargoExtraArgs = "-p pmond";
        });

        # mesh-init binary
        mesh-init = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "mesh-init";
          cargoExtraArgs = "-p mesh-init";
        });

        # h2t binary
        h2t = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "h2t";
          cargoExtraArgs = "-p ssh-mesh --bin h2t";
        });

        # meshkeys binary
        meshkeys = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "meshkeys";
          cargoExtraArgs = "-p ssh-mesh --bin meshkeys";
        });

        # sshmc binary
        sshmc = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "sshmc";
          cargoExtraArgs = "-p ssh-mesh --bin sshmc";
        });

        # traceweb binary
        traceweb = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "traceweb";
          cargoExtraArgs = "-p traceweb";
        });

        bobInitScript = pkgs.writeText "bob-init" ''
          #!/opt/busybox/bin/sh
          set -eu

          export PATH=/opt/ssh-mesh/bin:/opt/busybox/bin

          log() {
            echo "[bob-init] $*"
          }

          mount_fs() {
            type="$1"
            source="$2"
            target="$3"
            shift 3
            mkdir -p "$target"
            mount -t "$type" "$source" "$target" "$@" || log "mount $target failed"
          }

          mkdir -p /dev /proc /sys /run /tmp /home/bob /mesh
          mount_fs proc proc /proc
          mount_fs sysfs sysfs /sys
          mount_fs devtmpfs devtmpfs /dev || mount_fs tmpfs tmpfs /dev
          mount_fs tmpfs tmpfs /run
          mount_fs tmpfs tmpfs /tmp
          chmod 1777 /tmp

          [ -e /dev/null ] || mknod -m 666 /dev/null c 1 3
          [ -e /dev/console ] || mknod -m 600 /dev/console c 5 1

          if mount -t 9p -o trans=virtio,version=9p2000.L,msize=1048576 meshshared /mesh; then
            log "mounted 9p tag meshshared at /mesh"
          else
            log "9p tag meshshared not available; using embedded bob config"
          fi

          if [ -d /mesh/bob/home/bob ]; then
            mkdir -p /home/bob
            if mount -o bind /mesh/bob/home/bob /home/bob; then
              log "bound /mesh/bob/home/bob to /home/bob"
            else
              log "bind mount failed; copying /mesh/bob/home/bob into /home/bob"
              cp -a /mesh/bob/home/bob/. /home/bob/ 2>/dev/null || true
            fi
          fi

          mkdir -p \
            /home/bob/.config/mesh-init \
            /home/bob/.config/ssh-mesh \
            /home/bob/.run/mesh-init \
            /home/bob/.run/ssh-mesh/mux \
            /home/bob/.ssh

          if [ -d /etc/bob-home ]; then
            for file in /etc/bob-home/.config/mesh-init/*.toml; do
              name="$(basename "$file")"
              [ -e "/home/bob/.config/mesh-init/$name" ] || cp "$file" "/home/bob/.config/mesh-init/$name"
            done
            [ -e /home/bob/.config/ssh-mesh/mesh.yaml ] || \
              cp /etc/bob-home/.config/ssh-mesh/mesh.yaml /home/bob/.config/ssh-mesh/mesh.yaml
            [ -e /home/bob/.ssh/config ] || cp /etc/bob-home/.ssh/config /home/bob/.ssh/config
          fi
          chmod 700 /home/bob/.ssh
          chmod 600 /home/bob/.ssh/config 2>/dev/null || true

          ip link set lo up 2>/dev/null || true
          ip link set eth0 up 2>/dev/null || true
          udhcpc -i eth0 -q -n -t 5 2>/dev/null || log "dhcp on eth0 failed"

          export HOME=/home/bob
          export USER=bob
          export LOGNAME=bob
          export RUST_LOG=''${RUST_LOG:-info}
          export MESH_INIT_SOCK=/home/bob/.run/mesh-init/control.sock
          export MESH_INIT_RUN=/home/bob/.run/mesh-init
          export MESH_INIT_DIR=/home/bob/.config/mesh-init
          export SSH_MESH_HOME_ROOT=/home

          log "starting mesh-init"
          exec mesh-init
        '';

        bobSshMeshService = pkgs.writeText "bob-ssh-mesh.toml" ''
          [service]
          name = "init-ssh-mesh-bob"
          command = "ssh-mesh"
          priority = 100
          oneshot = false

          [resources]
          memory_high = "256M"
          memory_max = "512M"
          cpu_weight = 100

          [environment]
          PATH = "/opt/ssh-mesh/bin:/usr/local/bin:/usr/bin:/bin"
          RUST_LOG = "info"
          SSH_PORT = "18322"
          HTTP_PORT = "18380"
          MUX_DIR = "/home/bob/.run/ssh-mesh/mux"
          MESH_INIT_SOCK = "/home/bob/.run/mesh-init/control.sock"
          SSH_MESH_HOME_ROOT = "/home"
        '';

        bobPmondService = pkgs.writeText "bob-pmond.toml" ''
          [service]
          name = "pmond"
          command = "pmond"
          args = ["--uds", "control.sock"]
          priority = 180
          oneshot = false

          [resources]
          memory_high = "128M"
          memory_max = "256M"
          cpu_weight = 50

          [environment]
          PATH = "/opt/ssh-mesh/bin:/usr/local/bin:/usr/bin:/bin"
          RUST_LOG = "info"
        '';

        bobLmeshService = pkgs.writeText "bob-lmesh.toml" ''
          [service]
          name = "lmesh"
          command = "lmesh"
          args = ["--uds", "control.sock"]
          priority = 190
          oneshot = false

          [resources]
          memory_high = "64M"
          memory_max = "128M"
          cpu_weight = 50

          [environment]
          PATH = "/opt/ssh-mesh/bin:/usr/local/bin:/usr/bin:/bin"
          RUST_LOG = "info"
        '';

        bobMcpPmondService = pkgs.writeText "bob-mcp-pmond.toml" ''
          [service]
          name = "mcp-pmond"
          command = "mcp-pmond"
          args = ["--uds", "control.sock"]
          priority = 200
          oneshot = false

          [resources]
          memory_high = "128M"
          memory_max = "256M"
          cpu_weight = 50

          [environment]
          PATH = "/opt/ssh-mesh/bin:/usr/local/bin:/usr/bin:/bin"
          RUST_LOG = "info"
        '';

        bobMeshConfig = pkgs.writeText "bob-mesh.yaml" ''
          ssh_port: 18322
          http_port: 18380
          trusted_uds_path: /mesh/shared/bob/trusted.sock

          clients:
            alice:
              transport: uds
              user: bob
              uds_path: /mesh/shared/alice/trusted.sock
              keep_alive: true
              reconnect_interval_secs: 2

              local_forward:
                - bind_address: 127.0.0.1
                  port: 19003
                  host: 127.0.0.1
                  host_port: 18222

              remote_forward:
                - bind_address: 127.0.0.1
                  port: 19103
                  host: 127.0.0.1
                  host_port: 18380

            user:
              transport: uds
              user: bob
              uds_path: /mesh/shared/user/trusted.sock
              keep_alive: true
              reconnect_interval_secs: 2

              local_forward:
                - bind_address: 127.0.0.1
                  port: 19004
                  host: 127.0.0.1
                  host_port: 18422

              remote_forward:
                - bind_address: 127.0.0.1
                  port: 19104
                  host: 127.0.0.1
                  host_port: 18380
        '';

        bobSshConfig = pkgs.writeText "bob-ssh-config" ''
          Host bob-tcp
            HostName 127.0.0.1
            Port 18322
            User bob

          Host bob-h2
            HostName ignored
            User bob
            ProxyCommand h2t http://127.0.0.1:18380/_m/_ssh
        '';

        bobRunnerScript = pkgs.writeShellScript "run-bob-vm" ''
          set -euo pipefail

          export PATH="/opt/ssh-mesh/bin:${pkgs.qemu}/bin:''${PATH}"

          need() {
            command -v "$1" >/dev/null 2>&1 || {
              echo "missing required command: $1" >&2
              exit 1
            }
          }

          need qemu-system-x86_64

          node="bob"
          root_dir="''${SSH_MESH_EXAMPLE_ROOT:-''${HOME}/.local/share/ssh-mesh/examples}"
          state_dir="''${root_dir}/''${node}"
          home_dir="''${state_dir}/home/''${node}"
          shared_dir="''${root_dir}/shared"
          vm_dir="''${SSH_MESH_BOB_VM_DIR:-/opt/ssh-mesh/share/bob-vm}"
          kernel="''${SSH_MESH_BOB_KERNEL:-}"
          initrd="''${SSH_MESH_BOB_INITRD:-}"
          host_ssh_port="''${SSH_MESH_BOB_HOST_SSH_PORT:-18322}"
          host_http_port="''${SSH_MESH_BOB_HOST_HTTP_PORT:-18380}"

          if [ -z "''${kernel}" ] && [ -z "''${initrd}" ] && [ -n "''${vm_dir}" ]; then
            kernel="''${vm_dir}/bzImage"
            initrd="''${vm_dir}/initrd.img"
          fi

          if [ -z "''${kernel}" ] || [ -z "''${initrd}" ] || [ ! -r "''${kernel}" ] || [ ! -r "''${initrd}" ]; then
            cat >&2 <<EOF
          Bob requires a readable kernel and initrd.

          Set SSH_MESH_BOB_VM_DIR, or set SSH_MESH_BOB_KERNEL and SSH_MESH_BOB_INITRD.
          EOF
            exit 2
          fi

          mkdir -p \
            "''${home_dir}/.config/mesh-init" \
            "''${home_dir}/.config/ssh-mesh" \
            "''${home_dir}/.run/mesh-init" \
            "''${home_dir}/.run/ssh-mesh/mux" \
            "''${home_dir}/.ssh" \
            "''${shared_dir}/''${node}"

          echo "bob kernel: ''${kernel}"
          echo "bob initrd: ''${initrd}"
          echo "bob shared 9p root: ''${root_dir}"
          echo "bob HOME inside guest: /home/bob"
          echo "bob persistent HOME source: /mesh/bob/home/bob"
          echo "bob host forwards: 127.0.0.1:''${host_ssh_port}->18322, 127.0.0.1:''${host_http_port}->18380"

          qemu_args=(
            -m "''${SSH_MESH_BOB_QEMU_MEMORY:-1024}"
            -smp "''${SSH_MESH_BOB_QEMU_CPUS:-2}"
            -kernel "''${kernel}"
            -initrd "''${initrd}"
            -append "console=hvc0 panic=5 net.ifnames=0"
            -virtfs "local,path=''${root_dir},mount_tag=meshshared,security_model=mapped-xattr"
            -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:''${host_ssh_port}-:18322,hostfwd=tcp:127.0.0.1:''${host_http_port}-:18380"
            -device "virtio-net-pci,netdev=net0"
            -device "virtio-serial-pci"
            -chardev "stdio,id=hvc0,signal=off"
            -device "virtconsole,chardev=hvc0"
            -display "none"
            -serial "none"
            -monitor "none"
          )

          if [ "''${SSH_MESH_BOB_ENABLE_VSOCK:-auto}" != "0" ] && [ -e /dev/vhost-vsock ]; then
            qemu_args+=(
              -device "vhost-vsock-pci,guest-cid=''${SSH_MESH_BOB_VSOCK_CID:-42}"
            )
          fi

          exec qemu-system-x86_64 "''${qemu_args[@]}" ''${SSH_MESH_BOB_QEMU_EXTRA:-}
        '';

        bob-vm = pkgs.runCommand "bob-vm" {
          nativeBuildInputs = with pkgs; [ cpio gzip ];
        } ''
          set -eu

          root="$PWD/root"
          mkdir -p \
            "$out/share/bob-vm" \
            "$out/bin" \
            "$root/opt/busybox/bin" \
            "$root/opt/ssh-mesh/bin" \
            "$root/dev" "$root/proc" "$root/sys" "$root/run" "$root/tmp" \
            "$root/home" "$root/mesh" "$root/etc/bob-home/.config/mesh-init" \
            "$root/etc/bob-home/.config/ssh-mesh" "$root/etc/bob-home/.ssh"

          cp ${pkgs.linuxPackages_latest.kernel}/bzImage "$out/share/bob-vm/bzImage"
          cp ${pkgs.busybox}/bin/busybox "$root/opt/busybox/bin/busybox"
          chmod 0755 "$root/opt/busybox/bin/busybox"

          for applet in $(${pkgs.busybox}/bin/busybox --list); do
            ln -s busybox "$root/opt/busybox/bin/$applet"
          done

          cp ${ssh-mesh-full}/bin/* "$root/opt/ssh-mesh/bin/"
          chmod 0755 "$root"/opt/ssh-mesh/bin/*

          cp ${bobInitScript} "$root/init"
          chmod 0755 "$root/init"

          cp ${bobSshMeshService} "$root/etc/bob-home/.config/mesh-init/ssh-mesh.toml"
          cp ${bobPmondService} "$root/etc/bob-home/.config/mesh-init/pmond.toml"
          cp ${bobLmeshService} "$root/etc/bob-home/.config/mesh-init/lmesh.toml"
          cp ${bobMcpPmondService} "$root/etc/bob-home/.config/mesh-init/mcp-pmond.toml"
          cp ${bobMeshConfig} "$root/etc/bob-home/.config/ssh-mesh/mesh.yaml"
          cp ${bobSshConfig} "$root/etc/bob-home/.ssh/config"

          cat > "$root/etc/passwd" <<'EOF'
          root:x:0:0:root:/root:/opt/busybox/bin/sh
          bob:x:1000:1000:bob:/home/bob:/opt/busybox/bin/sh
          EOF
          cat > "$root/etc/group" <<'EOF'
          root:x:0:
          bob:x:1000:
          EOF

          (cd "$root" && find . -print0 | cpio --null -o -H newc | gzip -9n > "$out/share/bob-vm/initrd.img")

          substitute ${bobRunnerScript} "$out/bin/run-bob-vm" \
            --replace-fail "/opt/ssh-mesh/share/bob-vm" "$out/share/bob-vm"
          chmod 0755 "$out/bin/run-bob-vm"
        '';
      in
      {
        packages = {
          inherit ssh-mesh ssh-mesh-full mesh-init pmond h2t meshkeys sshmc traceweb;
          default = ssh-mesh-full;
        } // pkgs.lib.optionalAttrs (system == "x86_64-linux") {
          inherit bob-vm;
        };

        # Development shell with all tools
        devShells.default = craneLib.devShell {
          packages = with pkgs; [
            rustToolchain
            pkg-config
            cargo-watch
            cargo-edit
          ];
        };

        checks = {
          inherit ssh-mesh ssh-mesh-full mesh-init pmond;
          # Run clippy
          ssh-mesh-clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            pname = "ssh-mesh-clippy";
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });
          # Check formatting
          ssh-mesh-fmt = craneLib.cargoFmt {
            inherit src;
            pname = "ssh-mesh-fmt";
            version = "0.1.0";
          };
        };
      }
    );
}
