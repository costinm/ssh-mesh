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

        crossPkgs = import nixpkgs {
          inherit system overlays;
          crossSystem.config = muslTarget;
        };

        # Use latest stable Rust (edition 2024 requires >= 1.85)
        rustToolchain = crossPkgs.rust-bin.stable.latest.default.override {
          targets = [ muslTarget ];
        };

        craneLib = (crane.mkLib crossPkgs).overrideToolchain rustToolchain;

        # Common source filtering
        src = craneLib.cleanCargoSource ./.;

        # Common build inputs
        nativeBuildInputs = with pkgs; [
          pkg-config
        ];

        buildInputs = with pkgs; [
          musl
        ];

        # Common args for all builds
        commonArgs = {
          inherit src;
          strictDeps = true;
          doCheck = false; # Tests require network/system resources

          inherit nativeBuildInputs buildInputs;

          CARGO_BUILD_TARGET = "${pkgs.stdenv.hostPlatform.config}";
        };

        # Common args for static MUSL builds
        muslArgs = commonArgs // {
          CARGO_BUILD_TARGET = muslTarget;
          CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
        };

        # Build workspace dependencies first (for caching)
        cargoArtifacts = craneLib.buildDepsOnly (muslArgs // {
          pname = "ssh-mesh-deps";
          cargoExtraArgs = "--features pmon";
        });

        # ssh-mesh binary — the primary binary
        ssh-mesh = craneLib.buildPackage (muslArgs // {
          inherit cargoArtifacts;
          pname = "ssh-mesh";
          cargoExtraArgs = "--features pmon -p ssh-mesh";
        });

        # pmond binary
        pmond = craneLib.buildPackage (muslArgs // {
          inherit cargoArtifacts;
          pname = "pmond";
          cargoExtraArgs = "-p pmond";
        });

        # h2t binary
        h2t = craneLib.buildPackage (muslArgs // {
          inherit cargoArtifacts;
          pname = "h2t";
          cargoExtraArgs = "-p ssh-mesh --bin h2t";
        });

        # meshkeys binary
        meshkeys = craneLib.buildPackage (muslArgs // {
          inherit cargoArtifacts;
          pname = "meshkeys";
          cargoExtraArgs = "-p ssh-mesh --bin meshkeys";
        });

        # sshmc binary
        sshmc = craneLib.buildPackage (muslArgs // {
          inherit cargoArtifacts;
          pname = "sshmc";
          cargoExtraArgs = "-p ssh-mesh --bin sshmc";
        });

        # otel binary
        otel = craneLib.buildPackage (muslArgs // {
          inherit cargoArtifacts;
          pname = "otel";
          cargoExtraArgs = "-p otel";
        });
      in
      {
        packages = {
          inherit ssh-mesh pmond h2t meshkeys sshmc otel;
          default = ssh-mesh;
        };

        # Development shell with all tools
        devShells.default = craneLib.devShell {
          packages = with pkgs; [
            rustToolchain
            pkg-config
            musl
            cargo-watch
            cargo-edit
          ];
        };

        checks = {
          inherit ssh-mesh pmond;
          # Run clippy
          ssh-mesh-clippy = craneLib.cargoClippy (muslArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });
          # Check formatting
          ssh-mesh-fmt = craneLib.cargoFmt {
            inherit src;
          };
        };
      }
    );
}
