# ssh-mesh on NixOS

The NixOS module starts `mesh-init` as a normal systemd service and lets
`mesh-init` socket-activate `ssh-mesh` on the default SSH and HTTP ports.
Mutable app state is kept under `/home/APP`; package/profile paths are under
`/opt/APP` and point at read-only Nix store outputs.

## Flake Usage

Add this repository as an input and import the module:

```nix
{
  inputs.ssh-mesh.url = "github:costinm/ssh-mesh";

  outputs = { nixpkgs, ssh-mesh, ... }: {
    nixosConfigurations.host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      specialArgs = { sshMesh = ssh-mesh; };
      modules = [
        ssh-mesh.nixosModules.default
        ./configuration.nix
      ];
    };
  };
}
```

Then enable the service in `configuration.nix`:

```nix
{ pkgs, sshMesh, ... }:

{
  services.ssh-mesh = {
    enable = true;
    package = sshMesh.packages.${pkgs.system}.ssh-mesh;
    authorizedKeys = [
      "ssh-ed25519 AAAA... your-key"
    ];
  };
}
```

## Runtime Shape

- systemd starts `mesh-init.service`.
- `mesh-init` runs as root and uses the code defaults:
  `/home/system/etc/mesh-init` for service files and
  `/run/mesh/mesh-init/mesh.sock` for its local mesh endpoint.
- `/home/system/etc/mesh-init/ssh-mesh.toml` defines named activation sockets:
  `ssh` on TCP `15022`, `http` on TCP `8080`, and the mesh endpoint on
  `/run/mesh/ssh-mesh/mesh.sock` for local app IPC.
- Public local app IPC uses `/run/mesh/<app>/mesh.sock`. The socket name is
  protocol-neutral; current apps may speak line JSON, JSON-RPC/MCP-shaped
  requests, or text protocols on the same endpoint.
- `ssh-mesh` runs as UID `150` with mutable state under `/home/ssh-mesh`.
  It reads keys and SSH authorization from `/home/ssh-mesh/etc`.
- `/opt/ssh-mesh` points at the configured Nix store package. It is a friendly
  read-only profile path for service configs and examples.
- The module does not use `/etc/ssh-mesh`, `/etc/mesh-init`, or
  `/run/mesh-init`.

## Module Notes

For VM-based integration testing of `mesh-init` and `ssh-mesh` together, see
the `initos` repository at `github.com/costinm/initos`. The `vm/` directory
there provides the kernel, `vrun` launcher, and test harnesses. VMs connect to
`ssh-mesh` via vsock and nftables-based traffic capture (Istio-style), with
`mesh-init` managing the process lifecycle.
