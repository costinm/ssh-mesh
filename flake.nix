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
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        muslTarget = "x86_64-unknown-linux-musl";

        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          targets = [ muslTarget ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain (_: rustToolchain);

        # Filter source to only Cargo/Rust files — excludes .git, target/, java/, python/, etc.
        src = craneLib.cleanCargoSource ./.;

        # Pre-fetch Swagger UI zip for utoipa-swagger-ui (no network in Nix sandbox)
        swaggerUiZip = pkgs.fetchurl {
          url = "https://github.com/swagger-api/swagger-ui/archive/refs/tags/v5.17.14.zip";
          sha256 = "1p6cf4zf3jrswqa9b7wwgxhp3ca2v5qrzxzfp8gv35r0h78484j8";
        };

        nativeBuildInputs = with pkgs; [
          pkg-config
          curl
          python3
        ];

        # Common args for static MUSL builds
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

        # Native glibc build args for dmesh. dmesh carries Python/JNI wrapper
        # defaults and is intentionally kept out of the static MUSL aggregate.
        nativeArgs = {
          inherit src nativeBuildInputs;
          version = "0.1.0";
          strictDeps = true;
          doCheck = false;

          preBuild = ''
            install -m644 ${swaggerUiZip} $PWD/v5.17.14.zip
            export SWAGGER_UI_DOWNLOAD_URL="file://$PWD/v5.17.14.zip"
          '';
        };

        mainCargoExtraArgs =
          "--workspace --bins --exclude dmesh --features ssh-mesh/openapi,mesh-tun/bin-full";

        # Build main workspace deps once — shared by all main binary outputs.
        # Kernel, VM, and rootfs packages remain separate opt-in outputs.
        cargoArtifacts = craneLib.buildDepsOnly (commonArgs // {
          pname = "ssh-mesh";
          cargoExtraArgs = mainCargoExtraArgs;
        });

        # Helper to define a package with minimal boilerplate
        mkPackage = pname: cargoExtraArgs:
          craneLib.buildPackage (commonArgs // {
            inherit pname cargoArtifacts;
            cargoExtraArgs = cargoExtraArgs;
          });

        # ── Packages ──────────────────────────────────────────────

        musl-toolchain = pkgs.runCommand "ssh-mesh-musl-toolchain" { } ''
          mkdir -p "$out"
          for path in ${pkgs.pkgsCross.musl64.stdenv.cc}/*; do
            name="$(basename "$path")"
            if [ "$name" != bin ]; then
              ln -s "$path" "$out/$name"
            fi
          done

          mkdir -p "$out/bin"
          for path in ${pkgs.pkgsCross.musl64.stdenv.cc}/bin/*; do
            ln -s "$path" "$out/bin/$(basename "$path")"
          done
          for tool in gcc g++ cc c++ cpp ar as ld ld.bfd ld.gold nm objcopy objdump ranlib readelf size strings strip; do
            if [ -e "$out/bin/x86_64-unknown-linux-musl-$tool" ] &&
               [ ! -e "$out/bin/x86_64-linux-musl-$tool" ]; then
              ln -s "x86_64-unknown-linux-musl-$tool" "$out/bin/x86_64-linux-musl-$tool"
            fi
          done
        '';

        swagger-ui-assets = pkgs.runCommand "ssh-mesh-swagger-ui-assets" { } ''
          mkdir -p "$out/share/ssh-mesh/swagger-ui"
          ln -s ${swaggerUiZip} "$out/share/ssh-mesh/swagger-ui/v5.17.14.zip"
        '';

        build-deps = pkgs.symlinkJoin {
          name = "ssh-mesh-build-deps";
          paths = [ musl-toolchain swagger-ui-assets mesh-net-tools ];
        };

        mesh-net-tools = pkgs.symlinkJoin {
          name = "ssh-mesh-net-tools";
          paths = with pkgs; [
            bubblewrap
            iperf3
            iproute2
            nftables
            util-linux
          ];
        };

        # Aggregate: main runtime binaries built in a single cargo invocation.
        ssh-mesh-full = mkPackage "ssh-mesh-full" mainCargoExtraArgs;

        selectBins = pname: bins:
          pkgs.runCommand pname { } ''
            mkdir -p "$out/bin"
            ${pkgs.lib.concatMapStringsSep "\n" (bin: ''
              ln -s ${ssh-mesh-full}/bin/${bin} "$out/bin/${bin}"
            '') bins}
          '';

        ssh-mesh  = selectBins "ssh-mesh"  [ "ssh-mesh" ];
        pmond     = selectBins "pmond"     [ "pmond" ];
        mesh-init = selectBins "mesh-init" [ "mesh-init" ];
        h2t       = selectBins "h2t"       [ "h2t" ];
        meshkeys  = selectBins "meshkeys"  [ "meshkeys" ];
        sshmc     = selectBins "sshmc"     [ "sshmc" ];
        gen-openapi = selectBins "gen-openapi" [ "gen-openapi" ];
        traceweb  = selectBins "traceweb"  [ "traceweb" ];
        sftp-server = selectBins "sftp-server" [ "sftp-server" ];
        mesh-tun = selectBins "mesh-tun" [ "mesh-tun" ];

        dmesh = craneLib.buildPackage (nativeArgs // {
          pname = "dmesh";
          cargoExtraArgs = "-p dmesh";
        });

        # ── Docker image ──────────────────────────────────────────

        sshm = pkgs.dockerTools.buildLayeredImage {
          name = "ghcr.io/costinm/sshm";
          tag = "latest";
          contents = [ ssh-mesh-full ];
          config = {
            Entrypoint = [ "${ssh-mesh-full}/bin/ssh-mesh" ];
            Env = [ "PATH=/bin:/usr/bin" ];
          };
        };

        # ── EROFS VM Rootfs ───────────────────────────────────────

        initos-erofs = pkgs.runCommand "ssh-mesh.erofs" {
          nativeBuildInputs = [ pkgs.erofs-utils ];
        } ''
          bash ${./scripts/build.sh} erofs "$out" "${pkgs.pkgsStatic.busybox}/bin/busybox" "${./bin/initos-init-vm}" "${ssh-mesh-full}/bin"
        '';

        # ── Linux Kernel & VM ─────────────────────────────────────

        kernelConfigSrc = pkgs.lib.cleanSourceWith {
          src = ./linux;
          filter = path: type:
            let
              rel = pkgs.lib.removePrefix "${toString ./linux}/" (toString path);
            in
            rel == "6.18" || pkgs.lib.hasPrefix "6.18/" rel
            || rel == "fragments" || pkgs.lib.hasPrefix "fragments/" rel;
        };

        kernel-cloud = import ./linux/kernel-cloud.nix {
          inherit pkgs;
          src = kernelConfigSrc;
        };

        initos-vm = pkgs.runCommand "initos-vm" { } ''
          mkdir -p "$out"/{bin,boot,img}

          ln -s ${kernel-cloud}/img/vmlinux "$out/img/vmlinux-cloud"

          for m in ${kernel-cloud}/img/modules-*.erofs; do
            if [ -f "$m" ]; then
              ln -s "$m" "$out/img/modules-cloud.erofs"
            fi
          done

          ln -s ${pkgs.cloud-hypervisor}/bin/cloud-hypervisor "$out/bin/cloud-hypervisor"
          ln -s ${pkgs.cloud-hypervisor}/bin/ch-remote "$out/bin/ch-remote"
          ln -s ${pkgs.virtiofsd}/bin/virtiofsd "$out/bin/virtiofsd"
          ln -s ${pkgs.qemu_kvm}/bin/qemu-system-x86_64 "$out/bin/qemu-system-x86_64"
          ln -s ${pkgs.crosvm}/bin/crosvm "$out/bin/crosvm"
          ln -s ${pkgs.socat}/bin/socat "$out/bin/socat"
          ln -s ${pkgs.pkgsStatic.busybox}/bin/busybox "$out/bin/busybox"
          ln -s ${pkgs.tmux}/bin/tmux "$out/bin/tmux"
          ln -s ${pkgs.curl}/bin/curl "$out/bin/curl"
          ln -s ${pkgs.bubblewrap}/bin/bwrap "$out/bin/bwrap"
          
          cp ${./linux/bin/vrun} "$out/bin/vrun"
          chmod +x "$out/bin/vrun"
          ln -s vrun "$out/bin/initos-vrun"
        '';

        initos-vm-image = pkgs.dockerTools.buildLayeredImage {
          name = "ghcr.io/costinm/initos-vm";
          tag = "latest";
          contents = [
            initos-vm
            pkgs.bash
            pkgs.coreutils
          ];
          config = {
            Cmd = [ "${initos-vm}/bin/vrun" ];
            Env = [
              "PATH=/bin:/usr/bin"
            ];
          };
        };

      in
      {
        packages = {
            inherit ssh-mesh ssh-mesh-full mesh-init pmond h2t meshkeys sshmc gen-openapi traceweb sftp-server mesh-tun dmesh sshm initos-erofs kernel-cloud initos-vm initos-vm-image musl-toolchain swagger-ui-assets mesh-net-tools build-deps;
            default = ssh-mesh-full;
        };

        apps = {
          vm-cloud = {
            type = "app";
            program = "${initos-vm}/bin/vrun";
          };
        };

        devShells.default = craneLib.devShell {
          packages = with pkgs; [
            rustToolchain
            pkg-config
            cargo-watch
            cargo-edit
            iperf3
            iproute2
            nftables
          ];
        };

        checks = {
          inherit ssh-mesh-full;
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
