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
    package = sshMesh.packages.${pkgs.system}.ssh-mesh-full;
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

## Start a Test VM

Prepare the host-mounted `/home` and `/opt` trees, then build and start the
manual NixOS VM:

```bash
mkdir -p target/nixos-vm-fs/home target/nixos-vm-fs/opt
nix build .#nixosConfigurations.vmSystem.config.system.build.vm -o target/nixos-vm
target/nixos-vm/bin/run-nixos-vm
```

That VM starts `mesh-init.service`, mounts host `target/nixos-vm-fs/home` at
guest `/home`, mounts host `target/nixos-vm-fs/opt` at guest `/opt`, starts
`ssh-mesh` through mesh-init activation, and forwards guest TCP `15022` to host
TCP `14022`. The guest also has `/nix` mounted by the NixOS VM environment.

In another terminal, connect with the testdata key:

```bash
ssh -i crates/ssh-mesh/tests/testdata/alice/id_ecdsa \
  -p 14022 \
  -o IdentitiesOnly=yes \
  -o IdentityAgent=none \
  -o CertificateFile=none \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  system@127.0.0.1 true
```

Use `journalctl -u mesh-init -f` in the VM to watch `mesh-init` and activated
`ssh-mesh` logs.

The `IdentitiesOnly`, `IdentityAgent`, and `CertificateFile` options keep the
host OpenSSH client from offering unrelated agent keys or configured
certificates. The manual VM authorizes only the raw Alice test key.

After the VM is running, run the SSH-driven VM integration test with:

```bash
scripts/verify_nixos.sh
```

The test does not boot the VM. It copies checked-in fixtures from
`tests/nixos/mesh-init` into `target/nixos-vm-fs`, connects to the running VM
with OpenSSH, verifies that systemd started `mesh-init`, checks the shared
`/run/mesh` sockets, verifies `/opt` then `/home` config layering, tests
on-demand UID allocation, and runs mesh-init resource and hardening checks.
