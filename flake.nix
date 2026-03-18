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
        src = craneLib.cleanCargoSource ./.;

        # Pre-fetch Swagger UI zip for utoipa-swagger-ui (no network in Nix sandbox)
        swaggerUiZip = pkgs.fetchurl {
          url = "https://github.com/swagger-api/swagger-ui/archive/refs/tags/v5.17.14.zip";
          sha256 = "1p6cf4zf3jrswqa9b7wwgxhp3ca2v5qrzxzfp8gv35r0h78484j8";
        };

        # Common build inputs
        nativeBuildInputs = with pkgs; [
          pkg-config
          curl
        ];

        # Common args for static MUSL builds
        # Following the official Crane cross-musl pattern:
        # just set CARGO_BUILD_TARGET + crt-static, no cross-compiler needed
        # for same-architecture builds.
        commonArgs = {
          inherit src nativeBuildInputs;
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
          cargoExtraArgs = "--features pmon";
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

        # otel binary
        otel = craneLib.buildPackage (commonArgs // {
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
            cargo-watch
            cargo-edit
          ];
        };

        checks = {
          inherit ssh-mesh pmond;
          # Run clippy
          ssh-mesh-clippy = craneLib.cargoClippy (commonArgs // {
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

