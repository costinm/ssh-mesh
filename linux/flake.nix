{
  description = "kernel for VMs";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        lib = pkgs.lib;
        pkgs = import nixpkgs {
          inherit system;
        };

        kernelConfigSrc = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            let
              rel = pkgs.lib.removePrefix "${toString ./.}/" (toString path);
            in
            rel == "base" || pkgs.lib.hasPrefix "base/" rel
            || rel == "fragments" || pkgs.lib.hasPrefix "fragments/" rel;
        };

        baseKernel = pkgs.linuxPackages_latest.kernel;

        configBranch = "base";
        configFragments = [
          "common.fragment"
          "builtins.fragment"
          "filesystems.fragment"
          "crypto.fragment"
          "containers.fragment"
          "net.fragment"
          "cloud.fragment"
          "virtio.fragment"
        ];

        mergeFragmentCommands = lib.concatMapStringsSep "\n" (fragment: ''
          "$kernelSrc/scripts/kconfig/merge_config.sh" -m -O "$buildRoot" "$buildRoot/.config" ${kernelConfigSrc}/fragments/${fragment}
        '') configFragments;

        mergedConfig = pkgs.runCommand "initos-kernel-cloud-config-${baseKernel.version}" {
          nativeBuildInputs = with pkgs; [
            bc
            bison
            flex
            gnumake
            openssl
            perl
            rust-bindgen-unwrapped
            rustc-unwrapped
            stdenv.cc
            xz
          ];
          RUST_LIB_SRC = pkgs.rustPlatform.rustLibSrc;
          KRUSTFLAGS = "--remap-path-prefix ${pkgs.rustPlatform.rustLibSrc}=/";
        } ''
          tar -xf ${baseKernel.src}
          kernelSrc="$PWD/linux-${baseKernel.version}"
          buildRoot="$PWD/build"
          mergeRoot="$PWD/merge"
          mkdir -p "$buildRoot" "$mergeRoot"

          install -m 0644 ${kernelConfigSrc}/${configBranch}/config/config.cloud-amd64 "$buildRoot/.config"
          cd "$mergeRoot"
          "$kernelSrc/scripts/kconfig/merge_config.sh" -m -O "$buildRoot" "$buildRoot/.config" ${kernelConfigSrc}/${configBranch}/config/config.cloud
          ${mergeFragmentCommands}

          make -C "$kernelSrc" O="$buildRoot" ARCH=x86 olddefconfig
          cp "$buildRoot/.config" "$out"
        '';

        kernel = pkgs.linuxKernel.manualConfig {
          pname = "initos-kernel-cloud";
          inherit (baseKernel) version src modDirVersion;
          configfile = mergedConfig;
          config = {
            CONFIG_MODULES = "y";
            CONFIG_RUST = "y";
          };
          allowImportFromDerivation = true;
        };
        kernelVmlinuxOutput = if kernel ? dev then kernel.dev else kernel;
        kernelModulesOutput = if kernel ? modules then kernel.modules else kernel;

        kernel-cloud = pkgs.runCommand "initos-kernel-cloud" {
          nativeBuildInputs = [ pkgs.erofs-utils ];
          passthru = {
            inherit kernel mergedConfig;
          };
        } ''
          kernel_dir="$out/opt/ssh-mesh-kernel"
          mkdir -p "$kernel_dir"

          if [ -f ${kernel}/bzImage ]; then
            cp ${kernel}/bzImage "$kernel_dir/bzImage"
          elif [ -f ${kernel}/vmlinuz ]; then
            cp ${kernel}/vmlinuz "$kernel_dir/bzImage"
          else
            echo "ERROR: could not find built x86 kernel image in ${kernel}" >&2
            find ${kernel} -maxdepth 2 -type f >&2
            exit 1
          fi
          ln -s bzImage "$kernel_dir/vmlinux-cloud"

          if [ -f ${kernelVmlinuxOutput}/vmlinux ]; then
            cp ${kernelVmlinuxOutput}/vmlinux "$kernel_dir/vmlinux"
          else
            echo "ERROR: could not find built x86 vmlinux in ${kernelVmlinuxOutput}" >&2
            find ${kernelVmlinuxOutput} -maxdepth 2 -type f >&2
            exit 1
          fi

          if [ -f ${kernel}/System.map ]; then
            cp ${kernel}/System.map "$kernel_dir/System.map"
          fi

          cp ${mergedConfig} "$kernel_dir/config"
          cp ${pkgs.pkgsStatic.busybox}/bin/busybox "$kernel_dir/busybox"
          chmod +x "$kernel_dir/busybox"

          moduleDir=${kernelModulesOutput}/lib/modules/${kernel.modDirVersion}
          if [ -d "$moduleDir" ]; then
            (cd "$moduleDir" && mkfs.erofs -zlz4 "$kernel_dir/modules-${kernel.modDirVersion}.erofs" .)
            ln -s "modules-${kernel.modDirVersion}.erofs" "$kernel_dir/modules-cloud.erofs"
            ln -s modules-cloud.erofs "$kernel_dir/modules-cloudfs.erofs"
          fi

          echo "kernel-cloud:"
          ls -lh "$kernel_dir"
        '';

      in
      {
        packages = {
          inherit kernel-cloud;
          default = kernel-cloud;
        };
      }
    );
}
