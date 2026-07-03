{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.ssh-mesh;
in {
  options.services.ssh-mesh = {
    enable = mkEnableOption "ssh-mesh L4 proxy and activation daemon";

    package = mkOption {
      type = types.package;
      description = "The ssh-mesh package to use.";
    };
  };

  config = mkIf cfg.enable {
    # Create the users expected by mesh-init and ssh-mesh.
    # system user (UID 1000)
    users.users.system = {
      isNormalUser = true;
      uid = 1000;
      group = "system";
      extraGroups = [ "wheel" ];
    };
    users.groups.system = { gid = 1000; };

    # sshd service user (mesh-init expects UID 103)
    users.users.sshd = {
      isSystemUser = true;
      uid = 103;
      group = "sshd";
    };
    users.groups.sshd = { gid = 103; };

    # ssh-mesh service user (mesh-init expects UID 150)
    users.users.ssh-mesh = {
      isSystemUser = true;
      uid = 150;
      group = "ssh-mesh";
    };
    users.groups.ssh-mesh = { gid = 150; };

    # Systemd Slice for cgroup delegation
    systemd.slices.mesh = {
      description = "Mesh Slice";
      sliceConfig = {
        Delegate = true;
      };
    };

    # Systemd Service for mesh-init
    systemd.services.mesh-init = {
      description = "Mesh Init Daemon";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];
      environment = {
        MESH_INIT_DIR = "/etc/mesh-init";
        MESH_INIT_RUN = "/run/mesh-init";
      };
      serviceConfig = {
        ExecStart = "/opt/ssh-mesh/bin/mesh-init";
        Slice = "mesh.slice";
        Delegate = true;
        Type = "simple";
        Restart = "always";
      };
    };

    # Symlink /opt/ssh-mesh to the package in the Nix store
    system.activationScripts.opt-ssh-mesh = {
      text = ''
        mkdir -p /opt
        ln -sfn ${cfg.package} /opt/ssh-mesh
      '';
      deps = [];
    };

    # mesh-init socket-activated configuration for ssh-mesh on port 15022
    environment.etc."mesh-init/ssh-mesh.toml".text = ''
      [Service]
      ExecStart = "/opt/ssh-mesh/bin/ssh-mesh"
      OOMScoreAdjust = -900

      [Resources]
      MemoryMax = "1G"
      CPUWeight = 100

      [Environment]
      RUST_LOG = "info"
      SSH_PORT = "15022"
      HTTP_PORT = "8080"
      SSH_BASEDIR = "/etc/ssh-mesh"

      [Socket]
      ListenStream = "15022"
      Accept = false
    '';

    # Allow default ports in firewall
    networking.firewall.allowedTCPPorts = [ 15022 8080 ];
  };
}
