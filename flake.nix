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
    (flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        muslTarget = "x86_64-unknown-linux-musl";

        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rustfmt" "clippy" ];
          targets = [ muslTarget ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain (_: rustToolchain);

        # Filter source to Cargo/Rust files plus compile-time resources used by
        # include_str!/RustEmbed. This still excludes .git, target/, java/,
        # python/, etc.
        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            (craneLib.filterCargoSources path type)
            || pkgs.lib.hasInfix "/resources/" (toString path)
            || pkgs.lib.hasInfix "/web/" (toString path);
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
        };

        # Native glibc build args for Python.
        # defaults and is intentionally kept out of the static MUSL aggregate.
        nativeArgs = {
          inherit src nativeBuildInputs;
          version = "0.1.0";
          strictDeps = true;
          doCheck = false;
        };

        mainCargoExtraArgs =
          "--workspace --bins --features mesh-tun/bin-full";

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
            postInstall = ''
              mkdir -p "$out/share/ssh-mesh/nixos"
              cp ${./nixos/module.nix} "$out/share/ssh-mesh/nixos/module.nix"
              cp ${./nixos/example.nix} "$out/share/ssh-mesh/nixos/example.nix"
            '';
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

        build-deps = pkgs.symlinkJoin {
          name = "ssh-mesh-build-deps";
          paths = [ musl-toolchain mesh-net-tools ];
        };

        mesh-net-tools = pkgs.symlinkJoin {
          name = "ssh-mesh-net-tools";
          paths = with pkgs; [
            bubblewrap
            iperf3
            iproute2
            netcat
            nftables
            util-linux
          ];
        };

        dev-tools = pkgs.symlinkJoin {
          name = "ssh-mesh-dev-tools";
          paths = with pkgs; [
            build-deps
            rustToolchain
            pkg-config
            cargo-watch
            cargo-edit
            curl
            netcat
            jq
            nixos-install-tools
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
            mkdir -p "$out/share"
            ln -s ${ssh-mesh-full}/share/ssh-mesh "$out/share/ssh-mesh"
          '';

        ssh-mesh  = selectBins "ssh-mesh"  [ "ssh-mesh" ];
        mesh-init = selectBins "mesh-init" [ "mesh-init" ];
        h2t       = selectBins "h2t"       [ "h2t" ];
        meshkeys  = selectBins "meshkeys"  [ "meshkeys" ];
        sshmc     = selectBins "sshmc"     [ "sshmc" ];
        traceweb  = selectBins "traceweb"  [ "traceweb" ];
        sftp-server = selectBins "sftp-server" [ "sftp-server" ];
        mesh-tun = selectBins "mesh-tun" [ "mesh-tun" ];

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
            nixos-install-tools = pkgs.nixos-install-tools;
            inherit ssh-mesh ssh-mesh-full mesh-init h2t meshkeys sshmc traceweb sftp-server mesh-tun sshm initos-erofs kernel-cloud initos-vm initos-vm-image musl-toolchain mesh-net-tools build-deps dev-tools;
            default = ssh-mesh-full;
        };

        apps = {
          vm-cloud = {
            type = "app";
            program = "${initos-vm}/bin/vrun";
          };
        };

        devShells.default = craneLib.devShell {
          packages = [ dev-tools ];
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
    )) // {
      nixosModules.default = ./nixos/module.nix;

      nixosConfigurations = {
        containerSystem = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            ./nixos/module.nix
            ({ pkgs, ... }: {
              services.ssh-mesh = {
                enable = true;
                package = self.packages.x86_64-linux.ssh-mesh-full;
                authorizedKeys = [
                  (builtins.readFile ./crates/ssh-mesh/tests/testdata/alice/id_ecdsa.pub)
                ];
              };

              boot.isContainer = true;
              boot.loader.grub.enable = false;
              boot.loader.systemd-boot.enable = false;

              environment.systemPackages = with pkgs; [
                bash
                coreutils
                util-linux
              ];

              system.stateVersion = "26.05";
            })
          ];
        };

        vmSystem = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            "${nixpkgs}/nixos/modules/virtualisation/qemu-vm.nix"
            ./nixos/module.nix
            ({ pkgs, ... }: {
              services.ssh-mesh = {
                enable = true;
                package = self.packages.x86_64-linux.ssh-mesh-full;
                authorizedKeys = [
                  (builtins.readFile ./crates/ssh-mesh/tests/testdata/alice/id_ecdsa.pub)
                ];
              };

              virtualisation = {
                graphics = false;
                memorySize = 1024;
                cores = 1;
                forwardPorts = [
                  { from = "host"; host.port = 14022; guest.port = 15022; }
                  { from = "host"; host.port = 28080; guest.port = 8080; }
                ];
                sharedDirectories = {
                  home = {
                    source = "target/nixos-vm-fs/home";
                    target = "/home";
                    securityModel = "mapped-xattr";
                  };
                  opt = {
                    source = "target/nixos-vm-fs/opt";
                    target = "/opt";
                    securityModel = "mapped-xattr";
                  };
                };
              };

              services.getty.autologinUser = "root";

              system.activationScripts.vm-testdata-keys.text = ''
                install -d -m 0750 -o ssh-mesh -g ssh-mesh /home/ssh-mesh/etc
                install -m 0600 -o ssh-mesh -g ssh-mesh ${./crates/ssh-mesh/tests/testdata/alice/id_ecdsa} /home/ssh-mesh/etc/id_ecdsa
                install -m 0644 -o ssh-mesh -g ssh-mesh ${./crates/ssh-mesh/tests/testdata/alice/id_ecdsa.pub} /home/ssh-mesh/etc/id_ecdsa.pub
              '';

              boot.loader.grub.enable = false;

              system.stateVersion = "26.05";
            })
          ];
        };
      };
    };
}
