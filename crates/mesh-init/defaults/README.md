# Packaged mesh-init defaults

These files are installed under `/opt/ssh-mesh/share/mesh-init/defaults` and
seeded into the mutable configuration directory (`/home/system/etc/mesh-init`
as root) on first start.

Rules:

- Seeding only happens when the destination lacks a `.seeded` completion
  marker; each default file is copied only when it does not already exist.
- Existing files are never overwritten, deleted, or relinked. Local edits are
  preserved byte-for-byte.
- The marker is written only after every default file is present at the
  destination, so an interrupted first start is completed on the next start.
- Package upgrades never merge new defaults automatically. Use
  `/opt/ssh-mesh/bin/mesh-init seed` to copy missing files from a newer
  package, or `mesh-init seed --preview` to list them.

Mutable operator state (never packaged, never seeded):

- `/home/ssh-mesh/etc/authorized_keys` — SSH public keys allowed by ssh-mesh.
- `/home/system/etc/uidmap` — service identity allocations.
- Logs and runtime state under `/home/system/logs` and `/run/mesh`.
