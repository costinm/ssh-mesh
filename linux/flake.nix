{
  description = "kernel for VMs without initrd";

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

        vm-cloud-profile = pkgs.runCommand "initos-vm-cloud-profile" { } ''
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
          ln -s ${./bin/vrun} "$out/bin/vrun.lib"

          mkdir -p "$out/opt"/{busybox/bin,initos/bin}
          ln -s ${pkgs.pkgsStatic.busybox}/bin/busybox "$out/opt/busybox/bin/busybox"
          ln -s ${./bin/initos-init-vm} "$out/opt/initos/bin/initos-init-vm"
          chmod 755 "$out/opt/initos/bin/initos-init-vm"
          ln -s ${./bin/initos-vrun} "$out/bin/initos-vrun"

          cat > "$out/README" <<EOF
          initos VM cloud profile

          Important paths:
            $out/img/vmlinux-cloud
            $out/img/modules-cloud.erofs
            $out/opt

          sidecar/bin/vrun-compatible entrypoint:
            $out/bin/initos-vrun
          EOF
        '';

      in
      {
        packages = {
          inherit kernel-cloud 
                  vm-cloud-profile;
          default = vm-cloud-profile;
        };

        apps = {
          vm-cloud = {
            type = "app";
            program = "${vm-cloud-profile}/bin/initos-vrun";
          };
        };
      }
    );
}
