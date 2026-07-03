# Example NixOS configuration for ssh-mesh
# This configuration enables the ssh-mesh L4 proxy and process activation daemon (mesh-init).
# It will automatically create the systemd units, delegate the mesh slice, create expected users
# (system, sshd, ssh-mesh), and configure the socket-activated ssh-mesh service on default ports.

{ config, pkgs, ... }:

{
  imports = [
    # Path to the ssh-mesh NixOS module
    ./module.nix
  ];

  # Enable the ssh-mesh service
  services.ssh-mesh = {
    enable = true;
    
    # Specify the package to use. When using within a flake, this typically points to:
    # self.packages.${pkgs.system}.ssh-mesh-full
    package = pkgs.ssh-mesh; 
  };

  # Example setup of the system user's authorized keys for testing/SSH access
  users.users.system.openssh.authorizedKeys.keys = [
    # Add your SSH public key here to log in as 'system'
  ];

  # Standard state version
  system.stateVersion = "26.05";
}
