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

        # Build workspace deps once — shared by all packages
        cargoArtifacts = craneLib.buildDepsOnly (commonArgs // {
          pname = "ssh-mesh";
          cargoExtraArgs = "--workspace --bins --features ssh-mesh/pmon";
        });

        # Helper to define a package with minimal boilerplate
        mkPackage = pname: cargoExtraArgs:
          craneLib.buildPackage (commonArgs // {
            inherit pname cargoArtifacts;
            cargoExtraArgs = cargoExtraArgs;
          });

        # ── Packages ──────────────────────────────────────────────

        # Aggregate: all workspace binaries
        ssh-mesh-full = mkPackage "ssh-mesh-full"
          "--workspace --bins --features ssh-mesh/pmon";

        ssh-mesh  = mkPackage "ssh-mesh"  "--features pmon -p ssh-mesh";
        pmond     = mkPackage "pmond"     "-p pmond";
        mesh-init = mkPackage "mesh-init" "-p mesh-init";
        h2t       = mkPackage "h2t"       "-p ssh-mesh --bin h2t";
        meshkeys  = mkPackage "meshkeys"  "-p ssh-mesh --bin meshkeys";
        sshmc     = mkPackage "sshmc"     "-p ssh-mesh --bin sshmc";
        traceweb  = mkPackage "traceweb"  "-p traceweb";

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
            inherit ssh-mesh ssh-mesh-full mesh-init pmond h2t meshkeys sshmc sshm initos-erofs kernel-cloud initos-vm initos-vm-image;
            default = pkgs.symlinkJoin {
              name = "ssh-mesh-default";
              paths = [ ssh-mesh-full initos-erofs initos-vm ];
            };
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
