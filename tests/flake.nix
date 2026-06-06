{
  description = "ssh-mesh Test Environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    ssh-mesh-flake.url = "path:../";
  };

  outputs = { self, nixpkgs, flake-utils, ssh-mesh-flake }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        ssh-mesh = ssh-mesh-flake.packages.${system}.ssh-mesh-full;
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.curl
            pkgs.bubblewrap
            pkgs.qemu
            pkgs.tmux
            ssh-mesh
          ];
        };
      }
    );
}
