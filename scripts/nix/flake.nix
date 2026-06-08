{
  description = "Isolated profile for Rust and Android development";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }: 
  let
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      inherit system;
      config.allowUnfree = true; # Required for the Android SDK
    };
  in {
    packages.${system}.default = pkgs.buildEnv {
      name = "dev-env";
      paths = with pkgs; [
        rustc
        cargo
        rustfmt
        clippy
        android-tools       # Includes adb, fastboot, etc.
        android-studio      # If you need the IDE
      ];
    };
  };
}