#!/usr/bin/env bash
# Verification script for ssh-mesh on NixOS

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

echo "=== 1. Setting up SSH Keypair for testing ==="
# We use the existing pre-generated ecdsa keys from the repository.
# Ensure correct permissions on the private key.
chmod 600 crates/ssh-mesh/tests/testdata/alice/id_ecdsa

echo "=== 2. Building NixOS Container System ==="
nix build .#nixosConfigurations.containerSystem.config.system.build.toplevel -o target/container-toplevel

echo "=== 3. Installing NixOS to target/nixos (without bootloader) ==="
mkdir -p target/nixos
# We run nixos-install using sudo as it needs root to set up the file structure and permissions
echo "Running nixos-install to target/nixos..."
sudo env PATH="$PATH" nixos-install --no-bootloader --no-root-passwd --root "$PROJECT_ROOT/target/nixos" --system "$PROJECT_ROOT/target/container-toplevel"

echo "=== 4. Verifying container system installation ==="
# Since the target system is not booted, activation scripts have not run yet.
# So we verify that the built NixOS system closure references the ssh-mesh-full package
# and contains the correct mesh-init TOML configuration files.

if nix-store -q --references target/container-toplevel | grep -q "ssh-mesh-full"; then
    echo "✓ ssh-mesh-full is present in the container system closure"
else
    echo "✗ ssh-mesh-full is not present in the container system closure"
    exit 1
fi

ETC_TOML="target/container-toplevel/etc/mesh-init/ssh-mesh.toml"
if [ -f "$ETC_TOML" ]; then
    echo "✓ etc/mesh-init/ssh-mesh.toml exists in the system closure"
else
    echo "✗ etc/mesh-init/ssh-mesh.toml does not exist in the system closure"
    exit 1
fi

echo "=== 5. Building NixOS QEMU VM ==="
nix build .#nixosConfigurations.vmSystem.config.system.build.vm -o target/vm-build

echo "=== 6. Booting NixOS QEMU VM ==="
mkdir -p target/vm-run
cd target/vm-run

# Clean up previous VM state if any
rm -f vmSystem.qcow2

echo "Starting QEMU VM in background..."
(
  sleep 25
  echo "ip a"
  echo "ss -tulpn"
  echo "journalctl -u mesh-init --no-pager"
) | ../vm-build/bin/run-nixos-vm &
VM_PID=$!

cleanup() {
    echo "Stopping VM (PID $VM_PID)..."
    kill "$VM_PID" 2>/dev/null || true
    wait "$VM_PID" 2>/dev/null || true
    cd "$PROJECT_ROOT"
}
trap cleanup EXIT

echo "Waiting for VM to boot and SSH port 25022 to open..."
SSH_OPTS="-i ../../crates/ssh-mesh/tests/testdata/alice/id_ecdsa -p 25022 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=2"

for i in $(seq 1 60); do
    if ssh $SSH_OPTS system@localhost "echo ALIVE" >/dev/null 2>&1; then
        echo "VM is booted and SSH is accessible!"
        break
    fi
    sleep 2
    if [ "$i" -eq 60 ]; then
        echo "Timeout waiting for VM to boot"
        exit 1
    fi
done

echo "=== 7. Running Verification Tests inside VM ==="

echo "Checking systemd service status of mesh-init..."
ssh $SSH_OPTS system@localhost "systemctl status mesh-init --no-pager"

echo "Checking default ports / activation..."
ssh $SSH_OPTS system@localhost "ss -tulpn | grep 15022"

echo "Running mesh-init hardening tests inside NixOS VM..."
ssh $SSH_OPTS system@localhost "
  /opt/ssh-mesh/bin/mesh-init start hardening-mounts
  /opt/ssh-mesh/bin/mesh-init start hardening-process
  /opt/ssh-mesh/bin/mesh-init start hardening-caps-drop
  /opt/ssh-mesh/bin/mesh-init start hardening-caps-ambient
"

# Wait a moment for oneshot tests to execute and write results
sleep 2

echo "Retrieving test results from VM..."
ssh $SSH_OPTS system@localhost "
  echo -n 'mounts test: ' && cat /run/results-mounts
  echo -n 'process test: ' && cat /run/results-process
  echo -n 'caps-drop test: ' && cat /run/results-caps-drop
  echo -n 'caps-ambient test: ' && cat /run/results-caps-ambient
"

echo "=== All checks completed successfully ==="
