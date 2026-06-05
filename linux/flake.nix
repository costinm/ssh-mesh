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

        kernel-cloud = import ./kernel-cloud.nix {
        };
        pkgs = import nixpkgs;

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
          ln -s ${./bin/vrun} "$out/bin/vrun"

          cat > "$out/bin/vrun" <<EOF
#!${pkgs.runtimeShell}
export VIRT="\''${VIRT:-$out}"
export PATH="$out/bin:\$PATH"
exec "$out/bin/vrun" "\$@"
EOF
          chmod 755 "$out/bin/vrun"

          cat > "$out/README" <<EOF
          initos VM cloud profile

          Important paths:
            $out/img/vmlinux-cloud
            $out/img/modules-cloud.erofs
            $out/opt

            $out/bin/vrun
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
