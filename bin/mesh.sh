#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
base="${MESH_BASE:-${repo}/target/mesh}"
mesh_path="${repo}/target/x86_64-unknown-linux-musl/release:${PATH}"
PATH="${mesh_path}"

host_home="${base}/host"
config_dir="${host_home}/.config/mesh-init"
init_run="${host_home}/.run/mesh-init"
tun_run="${base}/run/mesh-tun"
logs="${base}/logs"
results="${base}/results"

mkdirs() {
  mkdir -p "${config_dir}" "${init_run}" "${tun_run}" "${logs}" "${results}"
}

env_init() {
  HOME="${host_home}" MESH_INIT_DIR="${config_dir}" MESH_INIT_RUN="${init_run}" "$@"
}

env_tun() {
  MESH_TUN_RUN="${tun_run}" \
  MESH_TUN_MODE=uds \
  MESH_TUN_TCP_REWRITE=false \
  MESH_TUN_CONTROL_SOCKET="${tun_run}/control.sock" \
  MESH_TUN_BWRAP_SOCKET="${tun_run}/bwrap.sock" \
  MESH_TUN_SOCKET="${tun_run}/qemu.sock" \
  "$@"
}

stop() {
  if [ -f "${base}/iperf3.pid" ]; then
    kill "$(cat "${base}/iperf3.pid")" 2>/dev/null || true
    rm -f "${base}/iperf3.pid"
  fi
  if [ -f "${base}/mesh-init.pid" ]; then
    kill "$(cat "${base}/mesh-init.pid")" 2>/dev/null || true
    rm -f "${base}/mesh-init.pid"
  fi
  if [ -f "${base}/mesh-tun.pid" ]; then
    kill "$(cat "${base}/mesh-tun.pid")" 2>/dev/null || true
    rm -f "${base}/mesh-tun.pid"
  fi
}

reset() {
  stop
  rm -rf "${base}"
  mkdirs
}

build() {
  cargo build --release --target x86_64-unknown-linux-musl -p mesh -p mesh-init -p mesh-tun
}

mesh_tun() {
  mkdirs
  env_tun exec mesh-tun
}

mesh_tun_bg() {
  mkdirs
  env_tun mesh-tun >"${logs}/mesh-tun.log" 2>&1 &
  echo "$!" >"${base}/mesh-tun.pid"
  wait_sock "${tun_run}/control.sock"
}

mesh_init() {
  mkdirs
  env_init exec mesh-init
}

mesh_init_bg() {
  mkdirs
  env_init mesh-init >"${logs}/mesh-init.log" 2>&1 &
  echo "$!" >"${base}/mesh-init.pid"
  wait_sock "${init_run}/control.sock"
}

wait_sock() {
  sock="$1"
  for _ in $(seq 1 100); do
    [ -S "${sock}" ] && return 0
    sleep 0.05
  done
  echo "socket did not appear: ${sock}" >&2
  return 1
}

mesh_init_ctl() {
  MESH_INIT_RUN="${init_run}" mesh mesh-init "$@"
}

write_mesh_tun_service() {
  mkdirs
  cat >"${config_dir}/mesh-tun-app.toml" <<EOF
[service]
name = "mesh-tun-app"
command = "bwrap"
args = [
  "--unshare-user",
  "--unshare-net",
  "--uid", "0",
  "--gid", "0",
  "--ro-bind-try", "/usr", "/usr",
  "--ro-bind-try", "/bin", "/bin",
  "--ro-bind-try", "/etc", "/etc",
  "--ro-bind-try", "/lib", "/lib",
  "--ro-bind-try", "/lib64", "/lib64",
  "--ro-bind-try", "/nix", "/nix",
  "--bind", "${repo}", "${repo}",
  "--bind", "${init_run}", "/run/mesh-init",
  "--proc", "/proc",
  "--dev", "/dev",
  "--tmpfs", "/tmp",
  "--setenv", "PATH", "${mesh_path}",
  "--setenv", "MESH_INIT_RUN", "/run/mesh-init",
  "--",
  "/bin/sh", "-lc",
  "PATH='${mesh_path}'; export PATH; mesh mesh-init register-namespace mesh-tun-app --kind user --path /proc/self/ns/user --target-pid \$\$; mesh mesh-init register-namespace mesh-tun-app --kind net --path /proc/self/ns/net --target-pid \$\$; sleep 300"
]

[network]
backend = "mesh-tun"
control_socket = "${tun_run}/control.sock"
if_name = "tap0"
address = "10.5.0.2/24"
gateway = "10.5.0.1"
default_route = true
EOF
}

write_pasta_service() {
  mkdirs
  cat >"${config_dir}/pasta-app.toml" <<EOF
[service]
name = "pasta-app"
command = "unshare"
args = ["--net", "--", "/bin/sh", "-lc", "sleep 300"]

[network]
backend = "pasta"
command = "pasta"
args = ["--map-host-loopback", "192.168.1.254", "--config-net", "{pid}"]
EOF
}

write_mesh_tun_speed_service() {
  host="$1"
  port="$2"
  duration="$3"
  reverse="${4:-}"
  mkdirs
  cat >"${config_dir}/mesh-tun-speed.toml" <<EOF
[service]
name = "mesh-tun-speed"
command = "bwrap"
oneshot = true
args = [
  "--unshare-user",
  "--unshare-net",
  "--uid", "0",
  "--gid", "0",
  "--ro-bind-try", "/usr", "/usr",
  "--ro-bind-try", "/bin", "/bin",
  "--ro-bind-try", "/etc", "/etc",
  "--ro-bind-try", "/lib", "/lib",
  "--ro-bind-try", "/lib64", "/lib64",
  "--ro-bind-try", "/nix", "/nix",
  "--bind", "${repo}", "${repo}",
  "--bind", "${init_run}", "/run/mesh-init",
  "--proc", "/proc",
  "--dev", "/dev",
  "--tmpfs", "/tmp",
  "--setenv", "PATH", "${mesh_path}",
  "--setenv", "MESH_INIT_RUN", "/run/mesh-init",
  "--",
  "/bin/sh", "-lc",
  "PATH='${mesh_path}'; export PATH; mesh mesh-init register-namespace mesh-tun-speed --kind user --path /proc/self/ns/user --target-pid \$\$; mesh mesh-init register-namespace mesh-tun-speed --kind net --path /proc/self/ns/net --target-pid \$\$; for _ in \$(seq 1 100); do [ -e /sys/class/net/tap0 ] && break; sleep 0.1; done; iperf3 -c '${host}' -p '${port}' -t '${duration}' -f m --connect-timeout 5000 ${reverse} > '${results}/mesh-tun-speed.txt' 2> '${results}/mesh-tun-speed.err'"
]

[network]
backend = "mesh-tun"
control_socket = "${tun_run}/control.sock"
if_name = "tap0"
address = "10.5.0.2/24"
gateway = "10.5.0.1"
default_route = true
EOF
}

write_pasta_speed_service() {
  host="$1"
  port="$2"
  duration="$3"
  reverse="${4:-}"
  mkdirs
  cat >"${config_dir}/pasta-speed.toml" <<EOF
[service]
name = "pasta-speed"
command = "unshare"
oneshot = true
args = ["--user", "--map-root-user", "--net", "--", "/bin/sh", "-lc", "sleep 1; iperf3 -c '${host}' -p '${port}' -t '${duration}' -f m --connect-timeout 5000 ${reverse} > '${results}/pasta-speed.txt' 2> '${results}/pasta-speed.err'"]

[network]
backend = "pasta"
command = "pasta"
args = ["--config-net", "{pid}"]
EOF
}

write_host_net_speed_service() {
  host="$1"
  port="$2"
  duration="$3"
  reverse="${4:-}"
  mkdirs
  cat >"${config_dir}/host-net-speed.toml" <<EOF
[service]
name = "host-net-speed"
command = "bwrap"
oneshot = true
args = [
  "--ro-bind-try", "/usr", "/usr",
  "--ro-bind-try", "/bin", "/bin",
  "--ro-bind-try", "/etc", "/etc",
  "--ro-bind-try", "/lib", "/lib",
  "--ro-bind-try", "/lib64", "/lib64",
  "--ro-bind-try", "/nix", "/nix",
  "--bind", "${repo}", "${repo}",
  "--proc", "/proc",
  "--dev", "/dev",
  "--tmpfs", "/tmp",
  "--",
  "/bin/sh", "-lc",
  "iperf3 -c '${host}' -p '${port}' -t '${duration}' -f m --connect-timeout 5000 ${reverse} > '${results}/host-net-speed.txt' 2> '${results}/host-net-speed.err'"
]
EOF
}

test_mesh_tun() {
  reset
  write_mesh_tun_service
  mesh_tun_bg
  mesh_init_bg
  mesh_init_ctl start mesh-tun-app >/dev/null
  wait_status_field mesh-tun-app '"mesh_tun_attached": true'
  mesh_init_ctl stop mesh-tun-app >/dev/null || true
}

test_pasta() {
  reset
  write_pasta_service
  mesh_init_bg
  mesh_init_ctl start pasta-app >/dev/null
  wait_status_field pasta-app '"network_pid"'
  mesh_init_ctl stop pasta-app >/dev/null || true
}

wait_status_field() {
  name="$1"
  field="$2"
  for _ in $(seq 1 100); do
    status="$(mesh_init_ctl status "${name}")"
    printf '%s\n' "${status}" | grep -q "${field}" && return 0
    sleep 0.1
  done
  printf '%s\n' "${status}"
  return 1
}

wait_file() {
  path="$1"
  for _ in $(seq 1 200); do
    [ -s "${path}" ] && return 0
    sleep 0.1
  done
  echo "file did not appear: ${path}" >&2
  [ -f "${path%.txt}.err" ] && cat "${path%.txt}.err" >&2
  return 1
}

speed_host() {
  if [ -n "${MESH_SPEED_HOST:-}" ]; then
    printf '%s\n' "${MESH_SPEED_HOST}"
    return 0
  fi
  ip -4 route get 1.1.1.1 | awk '
    {
      for (i = 1; i <= NF; i++) {
        if ($i == "src") {
          print $(i + 1)
          exit
        }
      }
    }
  '
}

start_iperf3_server() {
  host="$1"
  port="$2"
  rm -f "${base}/iperf3.pid"
  pkill -f "iperf3 -s .* -p ${port}" 2>/dev/null || true
  iperf3 -s -B "${MESH_SPEED_BIND:-0.0.0.0}" -p "${port}" >"${logs}/iperf3-${port}.log" 2>&1 &
  echo "$!" >"${base}/iperf3.pid"
  sleep 0.2
  if kill -0 "$(cat "${base}/iperf3.pid")" 2>/dev/null; then
    return 0
  fi
  cat "${logs}/iperf3-${port}.log" >&2 || true
  return 1
}

stop_iperf3_server() {
  if [ -f "${base}/iperf3.pid" ]; then
    kill "$(cat "${base}/iperf3.pid")" 2>/dev/null || true
    rm -f "${base}/iperf3.pid"
  fi
}

print_iperf_result() {
  backend="$1"
  file="$2"
  sender="$(awk '/sender$/ {line=$0} END {print line}' "${file}")"
  receiver="$(awk '/receiver$/ {line=$0} END {print line}' "${file}")"
  printf '%s sender: %s\n' "${backend}" "${sender}"
  printf '%s receiver: %s\n' "${backend}" "${receiver}"
}

mesh_tun_stats() {
  timeout 2 sh -c 'printf "stats\n" | nc -U "$1"' sh "${tun_run}/control.sock"
}

speed_mesh_tun() {
  host="${1:-$(speed_host)}"
  port="${2:-55201}"
  duration="${3:-5}"
  reverse="${4:-}"
  reset
  start_iperf3_server "${host}" "${port}"
  write_mesh_tun_speed_service "${host}" "${port}" "${duration}" "${reverse}"
  mesh_tun_bg
  mesh_init_bg
  mesh_init_ctl start mesh-tun-speed >/dev/null
  wait_file "${results}/mesh-tun-speed.txt"
  stop_iperf3_server
  print_iperf_result mesh-tun "${results}/mesh-tun-speed.txt"
  mesh_tun_stats | tr ' ' '\n' | grep -E '^(ok|tap_|tcp_|route_|tun_|fallback_|control_)' || true
  mesh_init_ctl stop mesh-tun-speed >/dev/null 2>&1 || true
}

speed_mesh_tun_reverse() {
  speed_mesh_tun "${1:-$(speed_host)}" "${2:-55211}" "${3:-5}" "-R"
}

speed_pasta() {
  host="${1:-${MESH_PASTA_HOST:-192.168.1.254}}"
  port="${2:-55202}"
  duration="${3:-5}"
  reverse="${4:-}"
  reset
  MESH_SPEED_BIND=127.0.0.1 start_iperf3_server "${host}" "${port}"
  write_pasta_speed_service "${host}" "${port}" "${duration}" "${reverse}"
  mesh_init_bg
  mesh_init_ctl start pasta-speed >/dev/null
  wait_file "${results}/pasta-speed.txt"
  stop_iperf3_server
  print_iperf_result pasta "${results}/pasta-speed.txt"
  mesh_init_ctl stop pasta-speed >/dev/null 2>&1 || true
}

speed_pasta_reverse() {
  speed_pasta "${1:-${MESH_PASTA_HOST:-192.168.1.254}}" "${2:-55212}" "${3:-5}" "-R"
}

speed_host_net() {
  host="${1:-$(speed_host)}"
  port="${2:-55203}"
  duration="${3:-5}"
  reverse="${4:-}"
  reset
  start_iperf3_server "${host}" "${port}"
  write_host_net_speed_service "${host}" "${port}" "${duration}" "${reverse}"
  mesh_init_bg
  mesh_init_ctl start host-net-speed >/dev/null
  wait_file "${results}/host-net-speed.txt"
  stop_iperf3_server
  print_iperf_result host-net "${results}/host-net-speed.txt"
  mesh_init_ctl stop host-net-speed >/dev/null 2>&1 || true
}

speed_host_net_reverse() {
  speed_host_net "${1:-$(speed_host)}" "${2:-55213}" "${3:-5}" "-R"
}

speed_compare() {
  host="${1:-$(speed_host)}"
  duration="${2:-5}"
  mesh_tun_result="$(speed_mesh_tun "${host}" 55201 "${duration}")"
  pasta_result="$(speed_pasta "${MESH_PASTA_HOST:-192.168.1.254}" 55202 "${duration}")"
  host_net_result="$(speed_host_net "${host}" 55203 "${duration}")"
  printf '%s\n%s\n%s\n' "${mesh_tun_result}" "${pasta_result}" "${host_net_result}"
}

speed_compare_reverse() {
  host="${1:-$(speed_host)}"
  duration="${2:-5}"
  mesh_tun_result="$(speed_mesh_tun_reverse "${host}" 55211 "${duration}")"
  pasta_result="$(speed_pasta_reverse "${MESH_PASTA_HOST:-192.168.1.254}" 55212 "${duration}")"
  host_net_result="$(speed_host_net_reverse "${host}" 55213 "${duration}")"
  printf '%s\n%s\n%s\n' "${mesh_tun_result}" "${pasta_result}" "${host_net_result}"
}

stress_mesh_tun() {
  rounds="${1:-25}"
  for _ in $(seq 1 "${rounds}"); do
    test_mesh_tun
  done
}

cmd="${1:-}"
shift || true
case "${cmd}" in
  build|reset|stop|mesh-tun|mesh-tun-bg|mesh-init|mesh-init-bg|test-mesh-tun|test-pasta|speed-mesh-tun|speed-mesh-tun-reverse|speed-pasta|speed-pasta-reverse|speed-host-net|speed-host-net-reverse|speed-compare|speed-compare-reverse|stress-mesh-tun)
    "${cmd//-/_}" "$@"
    ;;
  *)
    echo "usage: bin/mesh.sh {build|reset|stop|mesh-tun|mesh-tun-bg|mesh-init|mesh-init-bg|test-mesh-tun|test-pasta|speed-mesh-tun|speed-mesh-tun-reverse|speed-pasta|speed-pasta-reverse|speed-host-net|speed-host-net-reverse|speed-compare|speed-compare-reverse|stress-mesh-tun}" >&2
    exit 2
    ;;
esac
