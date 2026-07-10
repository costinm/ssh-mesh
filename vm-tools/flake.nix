{
  description = "VM helper tools for ssh-mesh examples and tests";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };

        vm-tools = pkgs.runCommand "ssh-mesh-vm-tools" { } ''
          mkdir -p "$out/bin"

          ln -s ${pkgs.cloud-hypervisor}/bin/cloud-hypervisor "$out/bin/"
          ln -s ${pkgs.cloud-hypervisor}/bin/ch-remote "$out/bin/"
          ln -s ${pkgs.virtiofsd}/bin/virtiofsd "$out/bin/"
          ln -s ${pkgs.qemu_kvm}/bin/qemu-system-x86_64 "$out/bin/"
          ln -s ${pkgs.crosvm}/bin/crosvm "$out/bin/"
          ln -s ${pkgs.crun}/bin/crun "$out/bin/"
        '';
      in
      {
        packages = {
          inherit vm-tools;
          default = vm-tools;
        };
      }
    );
}
