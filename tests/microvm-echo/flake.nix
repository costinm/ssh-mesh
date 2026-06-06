{
  description = "initos microvm echo test";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    microvm.url = "github:microvm-nix/microvm.nix";
    initosProfile = {
      url = "path:./empty-profile";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, microvm, initosProfile }:
  let
    system = "x86_64-linux";
    pkgs = nixpkgs.legacyPackages.${system};
    kernel = pkgs.runCommand "initos-microvm-kernel" { outputs = [ "out" "dev" ]; } ''
      mkdir -p "$out" "$dev"
      ln -s "${initosProfile}/img/vmlinux-cloud" "$out/${pkgs.stdenv.hostPlatform.linux-kernel.target}"
      ln -s "${initosProfile}/img/vmlinux-cloud" "$dev/vmlinux"
    '';
    emptyToplevel = pkgs.runCommand "initos-microvm-empty-toplevel" { } "mkdir -p $out";
    mkMicrovmConfig = hypervisor: rec {
      hostName = "initos-microvm";
      inherit hypervisor;
      vmHostPackages = pkgs;
      inherit kernel;
      initrdPath = "${initosProfile}/boot/initrd.img";
      vcpu = 1;
      mem = 512;
      hugepageMem = false;
      balloon = false;
      initialBalloonMem = 0;
      deflateOnOOM = true;
      hotplugMem = 0;
      hotpluggedMem = 0;
      user = null;
      cpu = null;
      interfaces = [];
      forwardPorts = [];
      devices = [];
      shares = [
        ({
          proto = "9p";
          tag = "src";
          source = "../../target/vm/microvm-echo/share";
          mountPoint = "/src";
          securityModel = "mapped";
          readOnly = false;
          socket = null;
          cache = "auto";
        } // pkgs.lib.optionalAttrs (hypervisor == "cloud-hypervisor") {
          proto = "virtiofs";
          socket = "../../target/vm/microvm-echo/src.sock";
        })
      ];
      volumes = [
        {
          image = "${initosProfile}/img/initos.erofs";
          serial = null;
          direct = false;
          readOnly = true;
          label = null;
          mountPoint = null;
          size = 0;
          autoCreate = false;
          mkfsExtraArgs = [];
          fsType = "ext4";
          imageType = "raw";
        }
      ];
      socket = if hypervisor == "crosvm" then "../../target/vm/microvm-echo/crosvm.sock" else null;
      vsock = { cid = null; };
      graphics = {
        enable = false;
        backend = "gtk";
        socket = "initos-microvm-gpu.sock";
      };
      cloud-hypervisor = {
        package = pkgs.cloud-hypervisor;
        extraArgs = [];
        platformOEMStrings = [];
      };
      crosvm = {
        package = pkgs.crosvm;
        extraArgs = [ "--disable-sandbox" ];
        pivotRoot = null;
      };
      storeOnDisk = false;
      storeDisk = "";
      credentialFiles = {};
      qemu = {
        machine = "q35";
        machineOpts = null;
        extraArgs = [];
        serialConsole = true;
        pcieRootPorts = [];
        package = pkgs.qemu_kvm;
      };
      optimize.enable = true;
      prettyProcnames = true;
      registerWithMachined = false;
      machineId = null;
      preStart = "";
      extraArgsScript = null;
      binScripts = {};
      systemSymlink = false;
      kernelParams = [
        "root=/dev/vda"
        "rootfstype=erofs"
        "rootwait"
        "init=/opt/initos/bin/initos-init-vm"
        "net.ifnames=0"
        "initos_host=initos-microvm"
      ];
    };
    mkRunner = hypervisor: microvm.lib.buildRunner {
      inherit pkgs;
      microvmConfig = mkMicrovmConfig hypervisor;
      toplevel = emptyToplevel;
    };
  in {
    packages.${system} = rec {
      runner-qemu = mkRunner "qemu";
      runner-crosvm = mkRunner "crosvm";
      runner-cloud-hypervisor = mkRunner "cloud-hypervisor";
      runner = runner-crosvm;
      default = runner-crosvm;
    };
  };
}
