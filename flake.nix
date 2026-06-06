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
        # MUSL target string for the current system
        muslTarget = "x86_64-unknown-linux-musl";

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

        bobExampleConfig = ./docs/examples/bob/config;

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

        vm-cloud-profile = pkgs.runCommand "ssh-mesh-vm-cloud-profile" { } ''
          mkdir -p "$out"/{bin,img,nix-support,opt/busybox/bin,opt/initos/bin}

          ln -s ${kernel-cloud}/img/bzImage "$out/img/bzImage"
          ln -s ${kernel-cloud}/img/vmlinux "$out/img/vmlinux-cloud"
          ln -s ${kernel-cloud}/img/config "$out/img/kernel.config"

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
          ln -s ${./linux/bin/vrun} "$out/bin/vrun.lib"
          ln -s ${./linux/bin/initos-vrun} "$out/bin/initos-vrun"
          ln -s ${./linux/bin/initos-init-vm} "$out/opt/initos/bin/initos-init-vm"
          ln -s ${pkgs.pkgsStatic.busybox}/bin/busybox "$out/opt/busybox/bin/busybox"

          cat > "$out/nix-support/artifacts.tsv" <<EOF
          vm-cloud-profile	$out
          kernel-cloud	${kernel-cloud}
          cloud-hypervisor	${pkgs.cloud-hypervisor}
          virtiofsd	${pkgs.virtiofsd}
          qemu	${pkgs.qemu_kvm}
          crosvm	${pkgs.crosvm}
          busybox	${pkgs.pkgsStatic.busybox}
          EOF

          cat > "$out/README" <<EOF
          ssh-mesh VM cloud profile

          Important paths:
            $out/img/bzImage
            $out/img/vmlinux-cloud
            $out/img/modules-cloud.erofs
            $out/bin/initos-vrun
          EOF
        '';

        vm-cloud-profile-image = pkgs.dockerTools.buildLayeredImageWithNixDb {
          name = "ghcr.io/costinm/ssh-mesh-vm-cloud-profile";
          tag = "latest";
          contents = [
            vm-cloud-profile
            pkgs.bash
            pkgs.coreutils
            pkgs.findutils
            pkgs.nix
          ];
          config = {
            Cmd = [ "/bin/bash" ];
            Env = [
              "NIX_PAGER=cat"
              "PATH=/bin:/usr/bin"
              "USER=root"
            ];
            Labels = {
              "org.opencontainers.image.description" = "ssh-mesh VM cloud profile with kernel artifacts, hypervisors, and Nix closure";
              "org.opencontainers.image.source" = "https://github.com/costinm/ssh-mesh";
              "org.ssh-mesh.nix.artifacts-file" = "/nix-support/artifacts.tsv";
              "org.ssh-mesh.nix.store-paths-file" = "/nix-support/artifact-store-paths";
            };
          };
          extraCommands = ''
            mkdir -p nix-support
            cat > nix-support/artifact-store-paths <<EOF
            ${vm-cloud-profile}
            EOF
          '';
        };

        bob-rootfs = pkgs.runCommand "bob-rootfs" {
          nativeBuildInputs = with pkgs; [ erofs-utils ];
        } ''
          OUT="$out" \
            BUSYBOX="${pkgs.pkgsStatic.busybox}/bin/busybox" \
            INITOS_INIT_VM="${./linux/bin/initos-init-vm}" \
            bash ${./scripts/nix/build-bob-rootfs.sh}
        '';

        bob-vm = pkgs.runCommand "bob-vm" {
          nativeBuildInputs = [ ];
        } ''
          OUT="$out" \
            KERNEL_CLOUD="${kernel-cloud}" \
            BOB_ROOTFS="${bob-rootfs}" \
            BOB_CONFIG="${bobExampleConfig}" \
            BOB_INITOS_POD="${./docs/examples/bob/initos-pod}" \
            BOB_RUNNER="${./docs/examples/bob/run-bob-vm}" \
            SSH_MESH_FULL="${ssh-mesh-full}" \
            bash ${./scripts/nix/assemble-bob-vm.sh}
        '';
      in
      {
        packages = {
          inherit
            ssh-mesh ssh-mesh-full mesh-init pmond h2t meshkeys sshmc traceweb
            vm-cloud-profile vm-cloud-profile-image;
          default = ssh-mesh-full;
        } // pkgs.lib.optionalAttrs (system == "x86_64-linux") {
          inherit bob-rootfs bob-vm kernel-cloud;
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
