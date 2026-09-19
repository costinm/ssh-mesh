# Reusable NixOS module for mesh-init and the ssh-mesh service.
#
# mesh-init runs as a foreground systemd service and supervises the ssh-mesh
# service itself (ssh-mesh is a child of mesh-init, never a systemd unit).
# Service configuration lives in mutable operator state under
# /home/system/etc/mesh-init and is seeded on first start from the packaged
# defaults in /opt/ssh-mesh/share/mesh-init/defaults; this module deliberately
# does not render or replace files there.
#
# Usage:
#
#   imports = [ ssh-mesh.nixosModules.mesh-init ];
#   services.mesh-init = {
#     enable = true;
#     package = ssh-mesh.packages.${pkgs.system}.ssh-mesh;
#     authorizedKeys = [ "ssh-ed25519 AAAA..." ];
#   };
#
# mesh-init without the ssh-mesh service is supported by removing
# ssh-mesh.toml from /home/system/etc/mesh-init; the supervisor and control
# socket keep running.

{
  config,
  lib,
  pkgs,
  ...
}:

with lib;

let
  cfg = config.services.mesh-init;
  authorizedKeysFile = pkgs.writeText "authorized_keys" (
    concatStringsSep "\n" cfg.authorizedKeys + optionalString (cfg.authorizedKeys != [ ]) "\n"
  );
  meshPath = "/opt/ssh-mesh/bin:/run/current-system/sw/bin:/usr/local/bin:/usr/bin:/bin";
in
{
  options.services.mesh-init = {
    enable = mkEnableOption "the mesh-init service supervisor (with the ssh-mesh L4 proxy as its managed child)";

    package = mkOption {
      type = types.package;
      description = "The ssh-mesh package providing mesh-init, mesh, and ssh-mesh.";
    };

    authorizedKeys = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = ''
        Public keys allowed to authenticate to the ssh-mesh SSH server.
        Installed at /home/ssh-mesh/.ssh/authorized_keys; mutable operator
        state, so leave empty to manage the file by hand.
      '';
    };

    resumeReconcile = mkOption {
      type = types.bool;
      default = true;
      description = "Run a bounded mesh-init reconcile after suspend/resume.";
    };

    openFirewall = mkOption {
      type = types.bool;
      default = true;
      description = "Open the default ssh-mesh SSH and HTTP ports in the firewall.";
    };
  };

  config = mkIf cfg.enable {
    # Identities expected by mesh-init and ssh-mesh. /home/system is mutable
    # operator state and is not treated as NixOS configuration data.
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

    # Stable /opt/ssh-mesh symlink plus the directory skeletons the services
    # need. Files under /home/system/etc/mesh-init are created by mesh-init
    # from the packaged defaults, never by activation scripts.
    system.activationScripts.mesh-init = {
      text = ''
        mkdir -p /opt
        ln -sfn ${cfg.package} /opt/ssh-mesh

        install -d -m 0755 -o root -g root /run/mesh
        install -d -m 0750 -o ssh-mesh -g ssh-mesh /home/ssh-mesh/.ssh \
          /home/ssh-mesh/etc /home/ssh-mesh/run/ssh-mesh /home/ssh-mesh/run/ssh-mesh/mux
        install -m 0644 -o ssh-mesh -g ssh-mesh ${authorizedKeysFile} \
          /home/ssh-mesh/.ssh/authorized_keys
      '';
    };

    systemd.tmpfiles.rules = [
      "d /run/mesh 0755 root root -"
    ];

    # Cgroup subtree delegated to mesh-init for service resource control.
    systemd.slices.mesh = {
      description = "Mesh cgroup slice";
      sliceConfig = {
        Delegate = true;
      };
    };

    systemd.services.mesh-init = {
      description = "mesh-init service supervisor and ssh-mesh host";
      after = [ "local-fs.target" ];
      wantedBy = [ "multi-user.target" ];
      environment = {
        HOME = "/home/system";
        RUST_LOG = "info";
        PATH = mkForce meshPath;
        MESH_RUN_BASE = "/run/mesh";
        MESH_INIT_SOCK = "/run/mesh/mesh-init/mesh.sock";
      };
      serviceConfig = {
        ExecStart = "/opt/ssh-mesh/bin/mesh-init";
        WorkingDirectory = "/home/system";
        Slice = "mesh.slice";
        Type = "simple";
        Restart = "on-failure";
        RestartSec = "2s";
        StandardOutput = "journal";
        StandardError = "journal";
      };
    };

    powerManagement.resumeCommands = mkIf cfg.resumeReconcile (mkAfter ''
      PATH=${meshPath}
      export PATH
      timeout 5 mesh mesh-init mesh-init reconcile
    '');

    networking.firewall.allowedTCPPorts = mkIf cfg.openFirewall [
      15022
      8080
    ];
  };
}
