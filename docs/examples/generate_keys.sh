#!/usr/bin/env bash
set -euo pipefail

examples_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace_dir="$(cd "${examples_dir}/../.." && pwd)"
ca_dir="${examples_dir}/ca"
domain="${SSH_MESH_EXAMPLE_DOMAIN:-example.m}"

find_meshkeys() {
  if [ -n "${MESHKEYS:-}" ]; then
    printf '%s\n' "${MESHKEYS}"
  elif [ -x "${workspace_dir}/target/x86_64-unknown-linux-musl/release/meshkeys" ]; then
    printf '%s\n' "${workspace_dir}/target/x86_64-unknown-linux-musl/release/meshkeys"
  elif [ -x "${workspace_dir}/target/debug/meshkeys" ]; then
    printf '%s\n' "${workspace_dir}/target/debug/meshkeys"
  elif command -v meshkeys >/dev/null 2>&1; then
    command -v meshkeys
  else
    echo "meshkeys not found; build it with: cargo build -p ssh-mesh --bin meshkeys" >&2
    return 1
  fi
}

meshkeys="$(find_meshkeys)"
nodes="host2 host1 host3-vm"
users="root"

user_principals="system,host1,host2,host3-vm"
user_principals="${user_principals},system@host2.example.m,system@host3-vm.example.m"
user_principals="${user_principals},system@app1-bwrap.example.m"
user_principals="${user_principals},system@app2-qemu.example.m"
user_principals="${user_principals},system@app3-crosvm.example.m"
user_principals="${user_principals},system@app4-ch.example.m"

rm -rf "${ca_dir}"
mkdir -p "${ca_dir}"
"${meshkeys}" --cadir "${ca_dir}" --domain "${domain}" genca

for node in ${nodes}; do
  ssh_dir="${examples_dir}/${node}/home/system/.ssh"
  rm -rf "${ssh_dir}"
  mkdir -p "${ssh_dir}"

  "${meshkeys}" \
    --nodedir "${ssh_dir}" \
    --name "${node}" \
    --domain "${domain}" \
    gen

  case "${node}" in
    host1) principals="${user_principals}" ;;
    *) principals="system" ;;
  esac

  "${meshkeys}" \
    --cadir "${ca_dir}" \
    --nodedir "${ssh_dir}" \
    --name "${node}" \
    --domain "${domain}" \
    --host-principals "${node}.${domain},${node},127.0.0.1" \
    --user-principals "${principals}" \
    sign

  cp "${ca_dir}/id_ecdsa.pub" "${ssh_dir}/authorized_cas"
  chmod 700 "${ssh_dir}"
  chmod 600 "${ssh_dir}/id_ecdsa"
  chmod 644 \
    "${ssh_dir}/authorized_cas" \
    "${ssh_dir}/id_ecdsa.pub" \
    "${ssh_dir}/id_ecdsa.crt" \
    "${ssh_dir}/id_ecdsa-host-cert.pub" \
    "${ssh_dir}/id_ecdsa-user-cert.pub"
done

for user in ${users}; do
  ssh_dir="${examples_dir}/${user}/home/${user}/.ssh"
  rm -rf "${ssh_dir}"
  mkdir -p "${ssh_dir}"

  "${meshkeys}" \
    --nodedir "${ssh_dir}" \
    --name "${user}" \
    --domain "${domain}" \
    gen

  "${meshkeys}" \
    --cadir "${ca_dir}" \
    --nodedir "${ssh_dir}" \
    --name "${user}" \
    --domain "${domain}" \
    --host-principals "${user}.${domain},${user}" \
    --user-principals "${user}@${domain}" \
    sign

  cp "${ca_dir}/id_ecdsa.pub" "${ssh_dir}/authorized_cas"
  chmod 700 "${ssh_dir}"
  chmod 600 "${ssh_dir}/id_ecdsa"
  chmod 644 \
    "${ssh_dir}/authorized_cas" \
    "${ssh_dir}/id_ecdsa.pub" \
    "${ssh_dir}/id_ecdsa.crt" \
    "${ssh_dir}/id_ecdsa-host-cert.pub" \
    "${ssh_dir}/id_ecdsa-user-cert.pub"
done

chmod 700 "${ca_dir}"
chmod 600 "${ca_dir}/id_ecdsa"
chmod 644 "${ca_dir}/id_ecdsa.pub" "${ca_dir}/id_ecdsa.crt"

echo "Generated example keys and certificates with ${meshkeys}"
