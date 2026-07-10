#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -P "${SCRIPT_DIR}/.." && pwd -P)"
cd "${PROJECT_ROOT}"

POD="${POD:-mesh-init-root-test}"
VM_STATE="${VM_STATE:-${PROJECT_ROOT}/target/vm/${POD}}"
SRC="${SRC:-${VM_STATE}/src}"
LOG="${VM_STATE}/qemu.log"
NIX_PROFILE="${NIX_PROFILE:-}"
if [[ -z "${NIX_PROFILE}" ]]; then
  if [[ -x "${PROJECT_ROOT}/target/nix/profile/bin/initos-vrun" ]]; then
    NIX_PROFILE="${PROJECT_ROOT}/target/nix/profile"
  elif [[ -x "${PROJECT_ROOT}/target/nix/bin/initos-vrun" ]]; then
    NIX_PROFILE="${PROJECT_ROOT}/target/nix"
  elif [[ -x "${PROJECT_ROOT}/target/examples/bin/initos-vrun" ]]; then
    NIX_PROFILE="${PROJECT_ROOT}/target/examples"
  elif [[ -x "${PROJECT_ROOT}/target/dist/opt/ssh-mesh/bin/initos-vrun" ]]; then
    NIX_PROFILE="${PROJECT_ROOT}/target/dist/opt/ssh-mesh"
  else
    NIX_PROFILE="/ws/initos/target/nix"
  fi
fi
PROFILE="${PROFILE:-${NIX_PROFILE}}"

VRUN="${VRUN:-}"
if [[ -z "${VRUN}" ]]; then
  if [[ -x "${PROJECT_ROOT}/target/dist/opt/ssh-mesh/bin/initos-vrun" ]]; then
    VRUN="${PROJECT_ROOT}/target/dist/opt/ssh-mesh/bin/initos-vrun"
  elif command -v initos-vrun >/dev/null 2>&1; then
    VRUN="$(command -v initos-vrun)"
  fi
fi
ROOTFS="${ROOTFS:-${PROJECT_ROOT}/target/dist/img/ssh-mesh.erofs}"

if [[ -z "${VRUN}" ]] ||
   ! PATH="${PROFILE}/bin:${PATH}" VIRT="${PROFILE}" VIRT_ROOTFS="${ROOTFS}" "${VRUN}" available qemuvirt >/dev/null 2>&1; then
  echo "skipping mesh-init root hardening VM test; vrun, optional VM profile, custom kernel, rootfs, or qemu is missing"
  exit 0
fi

rm -rf "${VM_STATE}/run" "${VM_STATE}/images" "${SRC}"
mkdir -p "${VM_STATE}/run" "${VM_STATE}/images" "${SRC}/bin" "${SRC}/initos"

cargo build -p mesh-init
cp "${PROJECT_ROOT}/target/x86_64-unknown-linux-musl/debug/mesh-init" "${SRC}/bin/mesh-init"
chmod 755 "${SRC}/bin/mesh-init"

cat > "${SRC}/initos/initos-pod" <<'EOF'
#!/opt/busybox/bin/sh
set -eu

case "${1:-start}" in
  start) ;;
  *)
    echo "unsupported command: $1" >&2
    exit 1
    ;;
esac

export PATH=/opt/busybox/bin:/src/bin:/bin:/sbin:/usr/bin:/usr/sbin
export MESH_INIT_DIR=/run/mesh-init/etc
export MESH_INIT_RUN=/run/mesh-init
export MESH_INIT_PRIVILEGED_UIDS=0

mkdir -p /sys/fs/cgroup
if [ ! -f /sys/fs/cgroup/cgroup.controllers ]; then
  mount -t cgroup2 none /sys/fs/cgroup
fi

rm -rf /run/mesh-init /run/results /run/readonly /run/protected-ro /run/masked-file /run/cap-secret
mkdir -p "${MESH_INIT_DIR}" "${MESH_INIT_RUN}" /run/results /run/readonly /run/protected-ro
chmod 777 /run/results
echo host-home-marker > /home/mesh-init-host-marker
echo readonly > /run/readonly/file
echo protected > /run/protected-ro/file
echo masked > /run/masked-file
echo cap-secret > /run/cap-secret
chmod 000 /run/cap-secret

pass() {
  echo "PASS $1"
}

fail() {
  echo "FAIL $1"
  exit 1
}

wait_for_file() {
  path="$1"
  label="$2"
  for _ in $(seq 1 100); do
    [ -e "$path" ] && return 0
    sleep 0.05
  done
  fail "timed out waiting for ${label}"
}

wait_for_socket() {
  path="$1"
  label="$2"
  for _ in $(seq 1 100); do
    [ -S "$path" ] && return 0
    sleep 0.05
  done
  fail "timed out waiting for ${label}"
}

wait_for_tcp() {
  port="$1"
  label="$2"
  for _ in $(seq 1 100); do
    if echo "" | nc 127.0.0.1 "$port" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.05
  done
  fail "timed out waiting for ${label}"
}

cat > "${MESH_INIT_DIR}/memlimit.toml" <<'TOML'
[Service]
ExecStart = "/opt/busybox/bin/sleep 3600"
OOMScoreAdjust = -500
StandardOutput = "inherit"
StandardError = "inherit"

[Resources]
MemoryMin = "64M"
MemoryHigh = "256M"
MemoryMax = "512M"
CPUWeight = 50

[Environment]
RUST_LOG = "info"
TOML

cat > "${MESH_INIT_DIR}/activated_svc.toml" <<'TOML'
[Service]
ExecStart = "/opt/busybox/bin/sh -c 'echo SUCCESS'"
OOMScoreAdjust = -800
StandardOutput = "inherit"
StandardError = "inherit"

[Socket]
ListenStream = "14032"
Accept = true
TOML

cat > "${MESH_INIT_DIR}/auth_test_svc.toml" <<'TOML'
[Service]
ExecStart = "/opt/busybox/bin/sh -c 'echo SUCCESS PEER=$X_PEER_UID'"
OOMScoreAdjust = -800
StandardOutput = "inherit"
StandardError = "inherit"

[[Peer]]
uid = 9999

[Socket]
Accept = true

[[Socket.Listen]]
Type = "stream"
Address = "/run/mesh-init-auth-test.sock"

[[Socket.Listen]]
Type = "stream"
Address = "14033"
TOML

cat > "${MESH_INIT_DIR}/hardening-mounts.toml" <<'TOML'
[Service]
Type = "oneshot"
ExecStart = "/opt/busybox/bin/sh -c 'set -eu; grep -q \" /tmp \" /proc/self/mountinfo; if [ -e /opt ]; then grep -Eq \" /opt ro(,| )\" /proc/self/mountinfo; fi; if [ -e /nix ]; then grep -Eq \" /nix ro(,| )\" /proc/self/mountinfo; fi; touch /tmp/private-ok; [ -c /dev/null ]; [ -c /dev/zero ]; [ ! -e /dev/kmsg ]; [ ! -e /home/mesh-init-host-marker ]; ! touch /etc/mesh-init-should-not-write 2>/dev/null; ! sh -c \"echo x > /run/readonly/file\" 2>/dev/null; ! sh -c \"echo x > /run/protected-ro/file\" 2>/dev/null; ! sh -c \"echo x > /run/masked-file\" 2>/dev/null; echo PASS mounts > /run/results/mounts'"
PrivateTmp = true
PrivateDevices = true
ProtectHome = "yes"
ProtectSystem = "strict"
ReadWritePaths = ["/run/results"]
ReadOnlyPaths = ["/run/readonly", "/run/protected-ro"]
InaccessiblePaths = ["/run/masked-file"]
StandardOutput = "inherit"
StandardError = "inherit"
TOML

cat > "${MESH_INIT_DIR}/hardening-process.toml" <<'TOML'
[Service]
Type = "oneshot"
ExecStart = "/opt/busybox/bin/sh -c 'set -eu; grep -q \"^NoNewPrivs:[[:space:]]*1\" /proc/self/status; ! grep -q \"eth0:\" /proc/net/dev; touch /run/results/umask-file; [ \"$(stat -c %a /run/results/umask-file)\" = \"600\" ]; id -G | grep -qw 0; echo PASS process > /run/results/process'"
NoNewPrivileges = true
PrivateNetwork = true
UMask = "0077"
SupplementaryGroups = ["0"]
StandardOutput = "inherit"
StandardError = "inherit"
TOML

cat > "${MESH_INIT_DIR}/hardening-caps-drop.toml" <<'TOML'
[Service]
Type = "oneshot"
ExecStart = "/opt/busybox/bin/sh -c 'set -eu; grep -q \"^CapEff:[[:space:]]*0000000000000001\" /proc/self/status; ! cat /run/cap-secret >/dev/null 2>&1; echo PASS caps-drop > /run/results/caps-drop'"
CapabilityBoundingSet = ["CAP_CHOWN"]
StandardOutput = "inherit"
StandardError = "inherit"
TOML

cat > "${MESH_INIT_DIR}/hardening-caps-ambient.toml" <<'TOML'
[Service]
Type = "oneshot"
ExecStart = "/opt/busybox/bin/sh -c 'set -eu; grep -Eq \"^CapAmb:[[:space:]]*0*400$\" /proc/self/status; echo PASS caps-ambient > /run/results/caps-ambient'"
User = "65534"
Group = "65534"
CapabilityBoundingSet = ["CAP_NET_BIND_SERVICE", "CAP_SETPCAP"]
AmbientCapabilities = ["CAP_NET_BIND_SERVICE"]
StandardOutput = "inherit"
StandardError = "inherit"
TOML

cat > "${MESH_INIT_DIR}/hardening-missing-protect.toml" <<'TOML'
[Service]
Type = "oneshot"
ExecStart = "/opt/busybox/bin/true"
ProtectHome = "hide-mostly"
StandardOutput = "inherit"
StandardError = "inherit"
TOML

/src/bin/mesh-init &
daemon_pid=$!
trap 'kill "$daemon_pid" 2>/dev/null || true' EXIT
wait_for_socket "${MESH_INIT_RUN}/control.sock" "mesh-init control socket"
pass "daemon-started"

status="$({ /src/bin/mesh-init status || true; } 2>&1)"
echo "$status" | grep -q "memlimit" || fail "status did not show memlimit"
pass "status-loads-configs"

start_out="$({ /src/bin/mesh-init start memlimit || true; } 2>&1)"
echo "$start_out" | grep -q "pid" || fail "memlimit start did not return pid: ${start_out}"
pass "start-service"

status="$({ /src/bin/mesh-init status memlimit || true; } 2>&1)"
echo "$status" | grep -q '"state": "running"' || fail "memlimit is not running: ${status}"
pass "service-running"

cg=/sys/fs/cgroup/mesh.slice/memlimit.scope
[ -d "$cg" ] || fail "cgroup missing: $cg"
[ "$(cat "$cg/memory.low")" = "67108864" ] || fail "memory.low mismatch"
[ "$(cat "$cg/memory.high")" = "268435456" ] || fail "memory.high mismatch"
[ "$(cat "$cg/memory.max")" = "536870912" ] || fail "memory.max mismatch"
[ "$(cat "$cg/cpu.weight")" = "50" ] || fail "cpu.weight mismatch"
pass "cgroup-resources"

reload_out="$({ /src/bin/mesh-init reload || true; } 2>&1)"
echo "$reload_out" | grep -q "reloaded" || fail "reload failed: ${reload_out}"
pass "reload"

activation="$(echo "" | nc 127.0.0.1 14032 || true)"
echo "$activation" | grep -q "SUCCESS" || fail "TCP activation failed: ${activation}"
pass "tcp-activation"

auth_tcp="$(echo "" | nc 127.0.0.1 14033 2>/dev/null || true)"
[ -z "$auth_tcp" ] || fail "auth TCP activation unexpectedly succeeded: ${auth_tcp}"
pass "auth-rejects-tcp"

if nc -h 2>&1 | grep -q -- '-U'; then
  auth_uds="$(echo "" | nc -U /run/mesh-init-auth-test.sock 2>/dev/null || true)"
  echo "$auth_uds" | grep -q "SUCCESS PEER=0" || fail "auth UDS activation failed: ${auth_uds}"
  pass "auth-uds"
else
  pass "auth-uds-skipped"
fi

/src/bin/mesh-init start hardening-mounts >/dev/null
wait_for_file /run/results/mounts "mount hardening marker"

/src/bin/mesh-init start hardening-process >/dev/null
wait_for_file /run/results/process "process hardening marker"

/src/bin/mesh-init start hardening-caps-drop >/dev/null
wait_for_file /run/results/caps-drop "capability drop marker"

/src/bin/mesh-init start hardening-caps-ambient >/dev/null
wait_for_file /run/results/caps-ambient "ambient capability marker"

if /src/bin/mesh-init start hardening-missing-protect >/run/results/missing-protect.out 2>&1; then
  fail "unsupported sandbox service unexpectedly started"
fi
grep -q "unsupported ProtectHome" /run/results/missing-protect.out || fail "unsupported ProtectHome warning missing"
pass "unsupported-service-fails"

for marker in mounts process caps-drop caps-ambient; do
  cat "/run/results/${marker}"
done

stop_out="$({ /src/bin/mesh-init stop memlimit || true; } 2>&1)"
echo "$stop_out" | grep -q "OK" || fail "stop failed: ${stop_out}"
status="$({ /src/bin/mesh-init status memlimit || true; } 2>&1)"
echo "$status" | grep -q '"state": "stopped"' || fail "memlimit not stopped: ${status}"
pass "stop-service"

/src/bin/mesh-init shutdown >/dev/null 2>&1 || true
for _ in $(seq 1 100); do
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    trap - EXIT
    pass "shutdown"
    break
  fi
  sleep 0.05
done
if kill -0 "$daemon_pid" 2>/dev/null; then
  fail "daemon still running after shutdown"
fi

echo "mesh-init root hardening VM test passed"
EOF
chmod 755 "${SRC}/initos/initos-pod"
cp "${SRC}/initos/initos-pod" "${SRC}/initos-pod"

if [[ ! -x "${PROFILE}/bin/initos-vrun" ]]; then
  echo "Error: VM profile not found at ${PROFILE}. Run scripts/build.sh test vm_qemu_echo." >&2
  exit 1
fi

run_direct_qemu_9p() {
  local virt_root="${VIRT:-${PROFILE}}"
  local kernel="${VIRT_KERNEL:-${virt_root}/opt/ssh-mesh-kernel/vmlinux-cloud}"
  local rootfs="${VIRT_ROOTFS:-${ROOTFS}}"
  local modules="${VIRT_MODULES:-${virt_root}/opt/ssh-mesh-kernel/modules-cloud.erofs}"
  local qemu="${VIRT_QEMU:-$(command -v qemu-system-x86_64)}"
  local accel machine modules_args

  [[ -x "${qemu}" ]]
  [[ -r "${kernel}" ]]
  [[ -r "${rootfs}" ]]

  if [[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
    accel="-enable-kvm -cpu host,+x2apic,-sgx"
    machine="q35,accel=kvm:tcg,acpi=on,mem-merge=on"
  else
    accel="-cpu max"
    machine="q35,accel=tcg,acpi=on,mem-merge=on"
  fi

  modules_args=()
  if [[ -r "${modules}" ]]; then
    modules_args=(
      -drive "id=vdb,format=raw,file=${modules},if=none,discard=unmap,cache=none,read-only=on"
      -device virtio-blk-pci,drive=vdb
    )
  fi

  timeout --foreground "${TIMEOUT:-120}s" \
  "${qemu}" \
    -name "${POD}" \
    -nodefaults \
    -no-user-config \
    -m "${vm_mem:-512M}" \
    -M "${machine}" \
    -no-reboot \
    -smp "${vm_cpu:-1}" \
    ${accel} \
    -nographic \
    -kernel "${kernel}" \
    -drive "id=vda,format=raw,file=${rootfs},if=none,discard=unmap,cache=none,read-only=on" \
    -device virtio-blk-pci,drive=vda \
    "${modules_args[@]}" \
    -device virtio-rng-pci \
    -device i8042 \
    -fsdev "local,id=src,path=${SRC},security_model=none,multidevs=remap" \
    -device virtio-9p-pci,fsdev=src,mount_tag=src \
    -device virtio-serial-pci \
    -chardev stdio,id=console,signal=off \
    -device virtconsole,chardev=console \
    -serial none \
    -append "root=/dev/vda rootfstype=erofs rootwait loglevel=7 console=hvc0 init=/opt/initos/bin/initos-init-vm net.ifnames=0 panic=1 initos_host=${POD} trace_clock=global panic_on_oops=1 reboot=acpi initos_modules=/dev/vdb initos_cmd=\"qemuvirt\""
}

if command -v virtiofsd >/dev/null 2>&1 || [[ -x "${VIRT:-${PROFILE}}/bin/virtiofsd" || -x "${VIRT:-${PROFILE}}/virtiofsd" ]]; then
  timeout --foreground "${TIMEOUT:-120}s" \
    env POD="${POD}" SRC="${SRC}" WORK="${VM_STATE}/run" IMGDIR="${VM_STATE}/images" \
      PATH="${PROFILE}/bin:${PATH}" VIRT="${PROFILE}" VIRT_ROOTFS="${ROOTFS}" \
    "${VRUN}" qemuvirt 2>&1 | tee "${LOG}"
else
  run_direct_qemu_9p 2>&1 | tee "${LOG}"
fi

grep -q "PASS mounts" "${LOG}"
grep -q "PASS process" "${LOG}"
grep -q "PASS caps-drop" "${LOG}"
grep -q "PASS caps-ambient" "${LOG}"
grep -q "PASS unsupported-service-fails" "${LOG}"
grep -q "mesh-init root hardening VM test passed" "${LOG}"
echo "mesh-init root hardening qemu test passed"
