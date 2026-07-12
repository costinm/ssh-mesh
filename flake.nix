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
              for app in ssh-mesh mesh-init lmesh traceweb; do
                if [ -d "${./crates}/$app/resources" ]; then
                  mkdir -p "$out/opt/$app/resources"
                  cp -a "${./crates}/$app/resources/." "$out/opt/$app/resources/"
                fi
              done
              cp ${./bin/vrun} "$out/bin/vrun"
              chmod +x "$out/bin/vrun"
              ln -s vrun "$out/bin/initos-vrun"
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
          paths = with pkgs; [
            musl-toolchain
            rustToolchain
            pkg-config
            curl
            python3
          ];
        };

        runtime-deps = pkgs.symlinkJoin {
          name = "ssh-mesh-runtime-deps";
          paths = with pkgs; [
            bubblewrap
            busybox
            iperf3
            iproute2
            netcat
            nftables
            util-linux
          ];
        };

        wpa-supplicant-nan = pkgs.wpa_supplicant.overrideAttrs (old: {
          pname = "wpa-supplicant-nan";
          extraConfig = (old.extraConfig or "") + ''

            # ssh-mesh/lmesh real-hardware NAN/USD test build.
            CONFIG_CTRL_IFACE=y
            CONFIG_DRIVER_NL80211=y
            CONFIG_LIBNL32=y
            CONFIG_NAN_USD=y
            CONFIG_P2P=y
          '';
        });

        radio-preflight = pkgs.writeShellApplication {
          name = "lmesh-radio-preflight";
          runtimeInputs = with pkgs; [
            coreutils
            gawk
            gnugrep
            iproute2
            iw
            wpa-supplicant-nan
          ];
          text = ''
            set -u

            iw_bin="''${IW:-iw}"
            ip_bin="''${IP:-ip}"
            rfkill_bin="''${RFKILL:-rfkill}"
            wpa_supplicant_bin="''${LMESH_WPA_SUPPLICANT:-wpa_supplicant}"
            wpa_cli_bin="''${WPA_CLI:-wpa_cli}"
            iface="''${LMESH_WIFI_IFACE:-wlan1}"
            ctrl_dir="''${LMESH_WPA_CTRL_DIR:-/run/ssh-mesh-wpa}"

            section() {
              printf '\n== %s ==\n' "$1"
            }

            run_optional() {
              local label="$1"
              shift
              printf '\n-- %s: %s\n' "$label" "$*"
              if command -v "$1" >/dev/null 2>&1 || [ -x "$1" ]; then
                "$@" 2>&1 || true
              else
                printf 'missing: %s\n' "$1"
              fi
            }

            section "helpers"
            for helper in "$iw_bin" "$ip_bin" "$rfkill_bin" "$wpa_supplicant_bin" "$wpa_cli_bin"; do
              if command -v "$helper" >/dev/null 2>&1 || [ -x "$helper" ]; then
                command -v "$helper" 2>/dev/null || printf '%s\n' "$helper"
              else
                printf 'missing: %s\n' "$helper"
              fi
            done

            section "process capabilities"
            grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/$$/status

            section "interfaces"
            run_optional "ip links" "$ip_bin" -o link show
            run_optional "iw dev" "$iw_bin" dev

            section "phys and NAN support"
            if command -v "$iw_bin" >/dev/null 2>&1 || [ -x "$iw_bin" ]; then
              "$iw_bin" phy 2>&1 | awk '
                /^Wiphy / {
                  if (phy != "") {
                    printf "%s mentions_nan=%s nan_interface_mode=%s nan_frame_sections=%s\n", phy, mentions, mode, frames
                  }
                  phy=$2; mentions="no"; mode="no"; frames="no"
                }
                /NAN/ { mentions="yes" }
                /^[[:space:]]+\* NAN$/ { mode="yes" }
                /^[[:space:]]+\* NAN:/ { frames="yes" }
                /NAN function/ { frames="yes" }
                { print }
                END {
                  if (phy != "") {
                    printf "%s mentions_nan=%s nan_interface_mode=%s nan_frame_sections=%s\n", phy, mentions, mode, frames
                  }
                }'
            else
              printf 'missing: %s\n' "$iw_bin"
            fi

            section "rfkill"
            run_optional "rfkill" "$rfkill_bin" list

            section "wpa"
            printf 'iface=%s\nctrl_dir=%s\n' "$iface" "$ctrl_dir"
            client_dir="/tmp/lmesh-radio-preflight-$$"
            mkdir -p "$client_dir"
            run_optional "wpa_supplicant version" "$wpa_supplicant_bin" -v
            run_optional "wpa status" "$wpa_cli_bin" -p "$ctrl_dir" -i "$iface" -s "$client_dir" STATUS
            run_optional "wpa NAN_GET_CAPABILITY" "$wpa_cli_bin" -p "$ctrl_dir" -i "$iface" -s "$client_dir" NAN_GET_CAPABILITY
          '';
        };

        radio-deps = pkgs.symlinkJoin {
          name = "ssh-mesh-radio-deps";
          paths = with pkgs; [
            iproute2
            iw
            socat
            usbutils
            util-linux
            wpa-supplicant-nan
            radio-preflight
          ];
        };

        # Aggregate: main runtime binaries built in a single cargo invocation.
        ssh-mesh = mkPackage "ssh-mesh" mainCargoExtraArgs;

        # ── Docker image ──────────────────────────────────────────

        sshm = pkgs.dockerTools.buildLayeredImage {
          name = "ghcr.io/costinm/sshm";
          tag = "latest";
          contents = [ ssh-mesh ];
          config = {
            Entrypoint = [ "${ssh-mesh}/bin/mesh-init" ];
            Env = [ "PATH=/bin:/usr/bin" ];
          };
        };

      in
      {
        packages = {
            inherit ssh-mesh sshm musl-toolchain build-deps runtime-deps;
            inherit wpa-supplicant-nan radio-deps radio-preflight;
            default = ssh-mesh;
        };

        checks = {
          inherit ssh-mesh;
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
                package = self.packages.x86_64-linux.ssh-mesh;
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
                package = self.packages.x86_64-linux.ssh-mesh;
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
