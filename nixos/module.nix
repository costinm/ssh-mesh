{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.ssh-mesh;
  lines = concatStringsSep "\n";
  sshMeshToml = pkgs.writeText "ssh-mesh.toml" ''
    [Service]
    ExecStart = "/opt/ssh-mesh/bin/ssh-mesh"
    User = "150"
    Group = "150"
    WorkingDirectory = "/home/ssh-mesh"
    OOMScoreAdjust = -900
    StandardOutput = "inherit"
    StandardError = "inherit"

    [Resources]
    MemoryMax = "1G"
    CPUWeight = 100

    [Environment]
    RUST_LOG = "info"
    MESH_HOME_BASE = "/home"
    MESH_OPT_BASE = "/opt"
    MESH_RUN_BASE = "/run/mesh"
    MESH_INIT_SOCK = "/run/mesh/mesh-init/mesh.sock"
    SSH_MUX = "/home/ssh-mesh/run/ssh-mesh/mux"

    [Socket]
    Accept = false
    SocketMode = 0o666

    [[Socket.Listen]]
    Type = "stream"
    Address = "0.0.0.0:15022"
    Name = "ssh"

    [[Socket.Listen]]
    Type = "stream"
    Address = "0.0.0.0:8080"
    Name = "http"

    [[Socket.Listen]]
    Type = "stream"
    Address = "/run/mesh/ssh-mesh/mesh.sock"
    Name = "jsonl"
  '';
  authorizedKeysFile = pkgs.writeText "authorized_keys" (
    lines cfg.authorizedKeys + optionalString (cfg.authorizedKeys != []) "\n"
  );
in {
  options.services.ssh-mesh = {
    enable = mkEnableOption "ssh-mesh L4 proxy and activation daemon";

    package = mkOption {
      type = types.package;
      description = "The ssh-mesh package to use.";
    };

    authorizedKeys = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Public keys allowed to authenticate to the ssh-mesh SSH server.";
    };

    openFirewall = mkOption {
      type = types.bool;
      default = true;
      description = "Open the default ssh-mesh SSH and HTTP ports in the firewall.";
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
      home = "/home/system";
      createHome = true;
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
      home = "/home/ssh-mesh";
      createHome = true;
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
        RUST_LOG = "info";
        MESH_RUN_BASE = "/run/mesh";
        MESH_INIT_SOCK = "/run/mesh/mesh-init/mesh.sock";
      };
      serviceConfig = {
        ExecStart = "/opt/ssh-mesh/bin/mesh-init";
        WorkingDirectory = "/home/system";
        Slice = "mesh.slice";
        Delegate = true;
        Type = "simple";
        Restart = "always";
        StandardOutput = "journal";
        StandardError = "journal";
      };
    };

    system.activationScripts.ssh-mesh-layout = {
      text = ''
        mkdir -p /opt
        ln -sfn ${cfg.package} /opt/ssh-mesh

        install -d -m 0755 -o root -g root /run/mesh
        install -d -m 0755 -o system -g system /home/system
        install -d -m 0750 -o ssh-mesh -g ssh-mesh /home/ssh-mesh
        install -d -m 0755 -o system -g system /home/system/etc/mesh-init /home/system/run /home/system/logs
        install -d -m 0750 -o ssh-mesh -g ssh-mesh /home/ssh-mesh/etc /home/ssh-mesh/run/ssh-mesh /home/ssh-mesh/run/ssh-mesh/mux /home/ssh-mesh/logs
        install -m 0644 -o system -g system ${sshMeshToml} /home/system/etc/mesh-init/ssh-mesh.toml
        install -m 0644 -o ssh-mesh -g ssh-mesh ${authorizedKeysFile} /home/ssh-mesh/etc/authorized_keys
      '';
    };

    systemd.tmpfiles.rules = [
      "d /run/mesh 0755 root root -"
    ];

    # Allow default ports in firewall
    networking.firewall.allowedTCPPorts = mkIf cfg.openFirewall [ 15022 8080 ];
  };
}
