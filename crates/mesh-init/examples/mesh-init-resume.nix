# NixOS fragment for reconciling mesh-init services after suspend/hibernate.
# Pass the ssh-mesh package as a module argument and import this file:
#
#   _module.args.meshPackage = inputs.ssh-mesh.packages.${pkgs.system}.default;
#   imports = [
#     "${inputs.ssh-mesh}/crates/mesh-init/examples/mesh-init-resume.nix"
#   ];
#
# Apply and test:
#   sudo nixos-rebuild switch
#   sudo mesh mesh-init mesh-init reconcile
#   sudo systemctl suspend
#   journalctl -b -u post-resume.service
#
# NixOS provides powerManagement.resumeCommands for this purpose, so it does
# not need a mutable script installed under /usr/lib/systemd/system-sleep.

{ lib, pkgs, meshPackage, ... }:

let
  resumePath = lib.makeBinPath [ meshPackage pkgs.coreutils ];
in
{
  environment.systemPackages = [ meshPackage ];

  powerManagement.resumeCommands = ''
    # Keep meshPackage first so this hook uses the selected ssh-mesh build.
    PATH=${resumePath}:/opt/ssh-mesh/bin:/usr/local/bin:/usr/bin
    export PATH
    timeout 5 mesh mesh-init mesh-init reconcile
  '';
}
