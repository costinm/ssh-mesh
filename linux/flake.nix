{
  description = "kernel for VMs";

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
        pkgs = import nixpkgs {
          inherit system;
        };

        kernelConfigSrc = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            let
              rel = pkgs.lib.removePrefix "${toString ./.}/" (toString path);
            in
            rel == "6.18" || pkgs.lib.hasPrefix "6.18/" rel
            || rel == "fragments" || pkgs.lib.hasPrefix "fragments/" rel;
        };

        kernel-cloud = import ./kernel-cloud.nix {
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
          
          cp ${./bin/vrun} "$out/bin/vrun"
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
          inherit kernel-cloud initos-vm initos-vm-image;
          default = initos-vm;
        };

        apps = {
          vm-cloud = {
            type = "app";
            program = "${initos-vm}/bin/vrun";
          };
        };
      }
    );
}
