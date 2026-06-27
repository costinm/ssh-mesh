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
  MESH_TUN_CONTROL_SOCKET="${tun_run}/control.sock" \
  MESH_TUN_BWRAP_SOCKET="${tun_run}/bwrap.sock" \
  MESH_TUN_SOCKET="${tun_run}/qemu.sock" \
  "$@"
}

stop() {
  stop_iperf3_servers
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
  if [ -n "${MESH_TUN_EGRESS_REDIRECT_PORT:-}" ]; then
    printf 'egress_redirect_port = %s\n' "${MESH_TUN_EGRESS_REDIRECT_PORT}" >>"${config_dir}/mesh-tun-speed.toml"
  fi
  if [ -n "${MESH_TUN_EGRESS_REDIRECT_UID:-}" ]; then
    printf 'egress_redirect_uid = %s\n' "${MESH_TUN_EGRESS_REDIRECT_UID}" >>"${config_dir}/mesh-tun-speed.toml"
  fi
}

write_mesh_tun_speed_service_named() {
  local name="$1"
  local result_name="$2"
  local address="$3"
  local host="$4"
  local port="$5"
  local duration="$6"
  local reverse="${7:-}"
  mkdirs
  cat >"${config_dir}/${name}.toml" <<EOF
[service]
name = "${name}"
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
  "PATH='${mesh_path}'; export PATH; mesh mesh-init register-namespace ${name} --kind user --path /proc/self/ns/user --target-pid \$\$; mesh mesh-init register-namespace ${name} --kind net --path /proc/self/ns/net --target-pid \$\$; for _ in \$(seq 1 100); do [ -e /sys/class/net/tap0 ] && break; sleep 0.1; done; iperf3 -c '${host}' -p '${port}' -t '${duration}' -f m --connect-timeout 5000 ${reverse} > '${results}/${result_name}.txt' 2> '${results}/${result_name}.err'"
]

[network]
backend = "mesh-tun"
control_socket = "${tun_run}/control.sock"
if_name = "tap0"
address = "${address}/24"
gateway = "10.5.0.1"
default_route = true
EOF
}

write_mesh_tun_concurrent_service() {
  local host="$1"
  local port="$2"
  local duration="$3"
  local reverse="${4:-}"
  mkdirs
  port2=$((port + 1))
  port3=$((port + 2))
  cat >"${config_dir}/mesh-tun-concurrent.toml" <<EOF
[service]
name = "mesh-tun-concurrent"
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
  "PATH='${mesh_path}'; export PATH; mesh mesh-init register-namespace mesh-tun-concurrent --kind user --path /proc/self/ns/user --target-pid \$\$; mesh mesh-init register-namespace mesh-tun-concurrent --kind net --path /proc/self/ns/net --target-pid \$\$; for _ in \$(seq 1 100); do [ -e /sys/class/net/tap0 ] && break; sleep 0.1; done; iperf3 -c '${host}' -p '${port}' -t '${duration}' -f m --connect-timeout 5000 ${reverse} > '${results}/mesh-tun-concurrent-1.txt' 2> '${results}/mesh-tun-concurrent-1.err' & p1=\$!; iperf3 -c '${host}' -p '${port2}' -t '${duration}' -f m --connect-timeout 5000 ${reverse} > '${results}/mesh-tun-concurrent-2.txt' 2> '${results}/mesh-tun-concurrent-2.err' & p2=\$!; iperf3 -c '${host}' -p '${port3}' -t '${duration}' -f m --connect-timeout 5000 ${reverse} > '${results}/mesh-tun-concurrent-3.txt' 2> '${results}/mesh-tun-concurrent-3.err' & p3=\$!; wait \$p1; r1=\$?; wait \$p2; r2=\$?; wait \$p3; r3=\$?; exit \$((r1 + r2 + r3))"
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
  pasta_args='["--config-net", "{pid}"]'
  if [ -n "${MESH_PASTA_MAP_HOST_LOOPBACK:-}" ]; then
    pasta_args='["--map-host-loopback", "'"${MESH_PASTA_MAP_HOST_LOOPBACK}"'", "--config-net", "{pid}"]'
  fi
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
args = ${pasta_args}
EOF
}

write_pasta_speed_service_named() {
  local name="$1"
  local result_name="$2"
  local host="$3"
  local port="$4"
  local duration="$5"
  local reverse="${6:-}"
  mkdirs
  cat >"${config_dir}/${name}.toml" <<EOF
[service]
name = "${name}"
command = "unshare"
oneshot = true
args = ["--user", "--map-root-user", "--net", "--", "/bin/sh", "-lc", "sleep 1; iperf3 -c '${host}' -p '${port}' -t '${duration}' -f m --connect-timeout 5000 ${reverse} > '${results}/${result_name}.txt' 2> '${results}/${result_name}.err'"]

[network]
backend = "pasta"
command = "pasta"
args = ["--config-net", "{pid}"]
EOF
}

write_pasta_concurrent_service() {
  local host="$1"
  local port="$2"
  local duration="$3"
  local reverse="${4:-}"
  local port2=$((port + 1))
  local port3=$((port + 2))
  mkdirs
  cat >"${config_dir}/pasta-concurrent.toml" <<EOF
[service]
name = "pasta-concurrent"
command = "unshare"
oneshot = true
args = ["--user", "--map-root-user", "--net", "--", "/bin/sh", "-lc", "sleep 1; iperf3 -c '${host}' -p '${port}' -t '${duration}' -f m --connect-timeout 5000 ${reverse} > '${results}/pasta-concurrent-1.txt' 2> '${results}/pasta-concurrent-1.err' & p1=\$!; iperf3 -c '${host}' -p '${port2}' -t '${duration}' -f m --connect-timeout 5000 ${reverse} > '${results}/pasta-concurrent-2.txt' 2> '${results}/pasta-concurrent-2.err' & p2=\$!; iperf3 -c '${host}' -p '${port3}' -t '${duration}' -f m --connect-timeout 5000 ${reverse} > '${results}/pasta-concurrent-3.txt' 2> '${results}/pasta-concurrent-3.err' & p3=\$!; wait \$p1; r1=\$?; wait \$p2; r2=\$?; wait \$p3; r3=\$?; exit \$((r1 + r2 + r3))"]

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
  for _ in $(seq 1 600); do
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
  local host="$1"
  local port="$2"
  rm -f "${base}/iperf3.pid" "${base}/iperf3-${port}.pid"
  pkill -f "iperf3 -s .* -p ${port}" 2>/dev/null || true
  iperf3 -s -B "${MESH_SPEED_BIND:-0.0.0.0}" -p "${port}" >"${logs}/iperf3-${port}.log" 2>&1 &
  echo "$!" >"${base}/iperf3.pid"
  echo "$!" >"${base}/iperf3-${port}.pid"
  sleep 0.2
  if kill -0 "$(cat "${base}/iperf3-${port}.pid")" 2>/dev/null; then
    return 0
  fi
  cat "${logs}/iperf3-${port}.log" >&2 || true
  return 1
}

stop_iperf3_server() {
  stop_iperf3_servers
}

stop_iperf3_servers() {
  for pidfile in "${base}"/iperf3*.pid; do
    [ -f "${pidfile}" ] || continue
    kill "$(cat "${pidfile}")" 2>/dev/null || true
    rm -f "${pidfile}"
  done
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
  mesh_tun_stats | tr ' ' '\n' | grep -E '^(ok|tap_|tcp_|egress_|route_|tun_|fallback_|control_)' || true
  mesh_init_ctl stop mesh-tun-speed >/dev/null 2>&1 || true
}

speed_mesh_tun_reverse() {
  speed_mesh_tun "${1:-$(speed_host)}" "${2:-55211}" "${3:-5}" "-R"
}

speed_mesh_tun_egress() {
  host="${1:-$(speed_host)}"
  port="${2:-55221}"
  duration="${3:-5}"
  reverse="${4:-}"
  egress_port="${MESH_TUN_EGRESS_REDIRECT_PORT:-15001}"
  export MESH_TUN_EGRESS_REDIRECT_PORT="${egress_port}"
  reset
  start_iperf3_server "${host}" "${port}"
  write_mesh_tun_speed_service "${host}" "${port}" "${duration}" "${reverse}"
  mesh_tun_bg
  mesh_init_bg
  mesh_init_ctl start mesh-tun-speed >/dev/null
  wait_file "${results}/mesh-tun-speed.txt"
  stop_iperf3_server
  print_iperf_result mesh-tun-egress "${results}/mesh-tun-speed.txt"
  mesh_tun_stats | tr ' ' '\n' | grep -E '^(ok|tap_|tcp_|egress_|route_|tun_|fallback_|control_)' || true
  mesh_init_ctl stop mesh-tun-speed >/dev/null 2>&1 || true
}

speed_mesh_tun_egress_reverse() {
  speed_mesh_tun_egress "${1:-$(speed_host)}" "${2:-55231}" "${3:-5}" "-R"
}

speed_mesh_tun_concurrent() {
  local host="${1:-$(speed_host)}"
  local port="${2:-55301}"
  local duration="${3:-10}"
  local reverse="${4:-}"
  local port1="${port}"
  local port2=$((port + 1))
  local port3=$((port + 2))
  reset
  start_iperf3_server "${host}" "${port1}"
  start_iperf3_server "${host}" "${port2}"
  start_iperf3_server "${host}" "${port3}"
  write_mesh_tun_concurrent_service "${host}" "${port1}" "${duration}" "${reverse}"
  mesh_tun_bg
  mesh_init_bg
  mesh_init_ctl start mesh-tun-concurrent >/dev/null
  wait_file "${results}/mesh-tun-concurrent-1.txt"
  wait_file "${results}/mesh-tun-concurrent-2.txt"
  wait_file "${results}/mesh-tun-concurrent-3.txt"
  stop_iperf3_servers
  print_iperf_result mesh-tun-concurrent-1 "${results}/mesh-tun-concurrent-1.txt"
  print_iperf_result mesh-tun-concurrent-2 "${results}/mesh-tun-concurrent-2.txt"
  print_iperf_result mesh-tun-concurrent-3 "${results}/mesh-tun-concurrent-3.txt"
  mesh_tun_stats | tr ' ' '\n' | grep -E '^(ok|tap_|tcp_|egress_|route_|tun_|fallback_|control_)' || true
  mesh_init_ctl stop mesh-tun-concurrent >/dev/null 2>&1 || true
}

speed_mesh_tun_concurrent_reverse() {
  speed_mesh_tun_concurrent "${1:-$(speed_host)}" "${2:-55311}" "${3:-10}" "-R"
}

speed_mesh_tun_3_containers() {
  local host="${1:-$(speed_host)}"
  local port="${2:-55321}"
  local duration="${3:-10}"
  local reverse="${4:-}"
  local port1="${port}"
  local port2=$((port + 1))
  local port3=$((port + 2))
  reset
  start_iperf3_server "${host}" "${port1}"
  start_iperf3_server "${host}" "${port2}"
  start_iperf3_server "${host}" "${port3}"
  write_mesh_tun_speed_service_named mesh-tun-speed-1 mesh-tun-3-containers-1 10.5.0.2 "${host}" "${port1}" "${duration}" "${reverse}"
  write_mesh_tun_speed_service_named mesh-tun-speed-2 mesh-tun-3-containers-2 10.5.0.3 "${host}" "${port2}" "${duration}" "${reverse}"
  write_mesh_tun_speed_service_named mesh-tun-speed-3 mesh-tun-3-containers-3 10.5.0.4 "${host}" "${port3}" "${duration}" "${reverse}"
  mesh_tun_bg
  mesh_init_bg
  mesh_init_ctl start mesh-tun-speed-1 >/dev/null
  mesh_init_ctl start mesh-tun-speed-2 >/dev/null
  mesh_init_ctl start mesh-tun-speed-3 >/dev/null
  wait_file "${results}/mesh-tun-3-containers-1.txt"
  wait_file "${results}/mesh-tun-3-containers-2.txt"
  wait_file "${results}/mesh-tun-3-containers-3.txt"
  stop_iperf3_servers
  print_iperf_result mesh-tun-3-containers-1 "${results}/mesh-tun-3-containers-1.txt"
  print_iperf_result mesh-tun-3-containers-2 "${results}/mesh-tun-3-containers-2.txt"
  print_iperf_result mesh-tun-3-containers-3 "${results}/mesh-tun-3-containers-3.txt"
  mesh_tun_stats | tr ' ' '\n' | grep -E '^(ok|tap_|tcp_|egress_|route_|tun_|fallback_|control_)' || true
  mesh_init_ctl stop mesh-tun-speed-1 >/dev/null 2>&1 || true
  mesh_init_ctl stop mesh-tun-speed-2 >/dev/null 2>&1 || true
  mesh_init_ctl stop mesh-tun-speed-3 >/dev/null 2>&1 || true
}

speed_mesh_tun_3_containers_reverse() {
  speed_mesh_tun_3_containers "${1:-$(speed_host)}" "${2:-55331}" "${3:-10}" "-R"
}

speed_pasta() {
  host="${1:-${MESH_PASTA_HOST:-192.168.1.254}}"
  port="${2:-55202}"
  duration="${3:-5}"
  reverse="${4:-}"
  reset
  MESH_SPEED_BIND="${MESH_SPEED_BIND:-127.0.0.1}" start_iperf3_server "${host}" "${port}"
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

speed_pasta_concurrent() {
  local host="${1:-${MESH_PASTA_HOST:-192.168.1.254}}"
  local port="${2:-55401}"
  local duration="${3:-10}"
  local reverse="${4:-}"
  local port1="${port}"
  local port2=$((port + 1))
  local port3=$((port + 2))
  reset
  MESH_SPEED_BIND="${MESH_SPEED_BIND:-127.0.0.1}" start_iperf3_server "${host}" "${port1}"
  MESH_SPEED_BIND="${MESH_SPEED_BIND:-127.0.0.1}" start_iperf3_server "${host}" "${port2}"
  MESH_SPEED_BIND="${MESH_SPEED_BIND:-127.0.0.1}" start_iperf3_server "${host}" "${port3}"
  write_pasta_concurrent_service "${host}" "${port1}" "${duration}" "${reverse}"
  mesh_init_bg
  mesh_init_ctl start pasta-concurrent >/dev/null
  wait_file "${results}/pasta-concurrent-1.txt"
  wait_file "${results}/pasta-concurrent-2.txt"
  wait_file "${results}/pasta-concurrent-3.txt"
  stop_iperf3_servers
  print_iperf_result pasta-concurrent-1 "${results}/pasta-concurrent-1.txt"
  print_iperf_result pasta-concurrent-2 "${results}/pasta-concurrent-2.txt"
  print_iperf_result pasta-concurrent-3 "${results}/pasta-concurrent-3.txt"
  mesh_init_ctl stop pasta-concurrent >/dev/null 2>&1 || true
}

speed_pasta_concurrent_reverse() {
  speed_pasta_concurrent "${1:-${MESH_PASTA_HOST:-192.168.1.254}}" "${2:-55411}" "${3:-10}" "-R"
}

speed_pasta_3_containers() {
  local host="${1:-${MESH_PASTA_HOST:-192.168.1.254}}"
  local port="${2:-55421}"
  local duration="${3:-10}"
  local reverse="${4:-}"
  local port1="${port}"
  local port2=$((port + 1))
  local port3=$((port + 2))
  reset
  MESH_SPEED_BIND="${MESH_SPEED_BIND:-127.0.0.1}" start_iperf3_server "${host}" "${port1}"
  MESH_SPEED_BIND="${MESH_SPEED_BIND:-127.0.0.1}" start_iperf3_server "${host}" "${port2}"
  MESH_SPEED_BIND="${MESH_SPEED_BIND:-127.0.0.1}" start_iperf3_server "${host}" "${port3}"
  write_pasta_speed_service_named pasta-speed-1 pasta-3-containers-1 "${host}" "${port1}" "${duration}" "${reverse}"
  write_pasta_speed_service_named pasta-speed-2 pasta-3-containers-2 "${host}" "${port2}" "${duration}" "${reverse}"
  write_pasta_speed_service_named pasta-speed-3 pasta-3-containers-3 "${host}" "${port3}" "${duration}" "${reverse}"
  mesh_init_bg
  mesh_init_ctl start pasta-speed-1 >/dev/null
  mesh_init_ctl start pasta-speed-2 >/dev/null
  mesh_init_ctl start pasta-speed-3 >/dev/null
  wait_file "${results}/pasta-3-containers-1.txt"
  wait_file "${results}/pasta-3-containers-2.txt"
  wait_file "${results}/pasta-3-containers-3.txt"
  stop_iperf3_servers
  print_iperf_result pasta-3-containers-1 "${results}/pasta-3-containers-1.txt"
  print_iperf_result pasta-3-containers-2 "${results}/pasta-3-containers-2.txt"
  print_iperf_result pasta-3-containers-3 "${results}/pasta-3-containers-3.txt"
  mesh_init_ctl stop pasta-speed-1 >/dev/null 2>&1 || true
  mesh_init_ctl stop pasta-speed-2 >/dev/null 2>&1 || true
  mesh_init_ctl stop pasta-speed-3 >/dev/null 2>&1 || true
}

speed_pasta_3_containers_reverse() {
  speed_pasta_3_containers "${1:-${MESH_PASTA_HOST:-192.168.1.254}}" "${2:-55431}" "${3:-10}" "-R"
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
  build|reset|stop|mesh-tun|mesh-tun-bg|mesh-init|mesh-init-bg|test-mesh-tun|test-pasta|speed-mesh-tun|speed-mesh-tun-reverse|speed-mesh-tun-egress|speed-mesh-tun-egress-reverse|speed-mesh-tun-concurrent|speed-mesh-tun-concurrent-reverse|speed-mesh-tun-3-containers|speed-mesh-tun-3-containers-reverse|speed-pasta|speed-pasta-reverse|speed-pasta-concurrent|speed-pasta-concurrent-reverse|speed-pasta-3-containers|speed-pasta-3-containers-reverse|speed-host-net|speed-host-net-reverse|speed-compare|speed-compare-reverse|stress-mesh-tun)
    "${cmd//-/_}" "$@"
    ;;
  *)
    echo "usage: bin/mesh.sh {build|reset|stop|mesh-tun|mesh-tun-bg|mesh-init|mesh-init-bg|test-mesh-tun|test-pasta|speed-mesh-tun|speed-mesh-tun-reverse|speed-mesh-tun-egress|speed-mesh-tun-egress-reverse|speed-mesh-tun-concurrent|speed-mesh-tun-concurrent-reverse|speed-mesh-tun-3-containers|speed-mesh-tun-3-containers-reverse|speed-pasta|speed-pasta-reverse|speed-pasta-concurrent|speed-pasta-concurrent-reverse|speed-pasta-3-containers|speed-pasta-3-containers-reverse|speed-host-net|speed-host-net-reverse|speed-compare|speed-compare-reverse|stress-mesh-tun}" >&2
    exit 2
    ;;
esac
