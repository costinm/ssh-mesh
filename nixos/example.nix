# Usage example for the ssh-mesh NixOS module.
#
# In a flake-based NixOS configuration, import the module with:
#
#   imports = [ ssh-mesh.nixosModules.mesh-init ];
#
# and set the package to:
#
#   ssh-mesh.packages.${pkgs.system}.ssh-mesh

{
  config,
  pkgs,
  sshMesh,
  ...
}:

{
  imports = [ ./module.nix ];

  services.mesh-init = {
    enable = true;
    package = sshMesh.packages.${pkgs.system}.ssh-mesh;
    authorizedKeys = [
      # "ssh-ed25519 AAAA... your-key"
    ];
  };

  system.stateVersion = "26.05";
}
