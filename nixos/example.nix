# Minimal NixOS host configuration for ssh-mesh.
#
# In a flake-based NixOS configuration, import the module with:
#
#   imports = [ ssh-mesh.nixosModules.default ];
#
# and set package to:
#
#   ssh-mesh.packages.${pkgs.system}.ssh-mesh-full

{
  config,
  pkgs,
  sshMesh,
  ...
}:

{
  imports = [ ./module.nix ];

  services.ssh-mesh = {
    enable = true;
    package = sshMesh.packages.${pkgs.system}.ssh-mesh-full;
    authorizedKeys = [
      # "ssh-ed25519 AAAA... your-key"
    ];
  };

  system.stateVersion = "26.05";
}
