#!/usr/bin/env bash
# Build and exercise both supported container variants. Each starts mesh-init
# as PID 1; the first HTTP request must socket-activate ssh-mesh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ENGINE="${ENGINE:-}"
if [ -z "${ENGINE}" ]; then
  if command -v podman >/dev/null 2>&1; then
    ENGINE=podman
  elif command -v docker >/dev/null 2>&1; then
    ENGINE=docker
  else
    echo "error: neither podman nor docker is installed" >&2
    exit 1
  fi
fi

NIX_IMAGE_REF="${NIX_IMAGE_REF:-ssh-mesh:nix}"
DOCKERFILE_IMAGE_REF="${DOCKERFILE_IMAGE_REF:-ssh-mesh:netshoot}"
CONTAINER_BUILD_NETWORK="${CONTAINER_BUILD_NETWORK:-host}"
TEST_DIR="$(mktemp -d -t ssh-mesh-docker-test.XXXXXX)"
CONTAINER_NAME=""

cleanup() {
  if [ -n "${CONTAINER_NAME}" ]; then
    "${ENGINE}" rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  fi
  rm -rf "${TEST_DIR}"
}
trap cleanup EXIT

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

wait_for() {
  local label="$1"
  local timeout_secs="$2"
  shift 2
  local deadline=$((SECONDS + timeout_secs))
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    if "$@" >/dev/null 2>&1; then
      echo "ok: ${label}"
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for ${label}" >&2
  return 1
}

container_port() {
  "${ENGINE}" port "${CONTAINER_NAME}" "$1/tcp" | head -n1 | sed -E 's/.*:([0-9]+)$/\1/'
}

container_http_ok() {
  curl -fsS --max-time 2 "http://127.0.0.1:${HOST_HTTP_PORT}/" >/dev/null
}

mesh_init_started_ssh_mesh() {
  "${ENGINE}" exec "${CONTAINER_NAME}" /opt/ssh-mesh/bin/mesh \
    mesh-init mesh-init status ssh-mesh | grep -q '"state": "running"'
}

show_logs() {
  "${ENGINE}" logs "${CONTAINER_NAME}" 2>&1 | tail -80 >&2 || true
}

build_nix_image() {
  echo "=== Building Nix mesh-init image ==="
  nix build .#sshm --out-link target/result-sshm
  gzip -dc target/result-sshm | "${ENGINE}" load
  "${ENGINE}" tag docker.io/costinm/sshm:latest "${NIX_IMAGE_REF}"
}

build_dockerfile_image() {
  echo "=== Building netshoot mesh-init image ==="
  "${ENGINE}" build --network "${CONTAINER_BUILD_NETWORK}" \
    --target netshoot --tag "${DOCKERFILE_IMAGE_REF}" "${REPO_ROOT}"
}

test_image() {
  local label="$1"
  local image="$2"
  CONTAINER_NAME="ssh-mesh-${label}-$$"

  echo "=== Starting ${label} image through mesh-init ==="
  "${ENGINE}" run -d \
    --name "${CONTAINER_NAME}" \
    -p 127.0.0.1::15022 \
    -p 127.0.0.1::8080 \
    -e "SSH_AUTHORIZED_CAS=${CA_PUB_CONTENT}" \
    -e MESH_LOG_FILE=/dev/stderr \
    "${image}" >/dev/null

  HOST_SSH_PORT="$(container_port 15022)"
  HOST_HTTP_PORT="$(container_port 8080)"
  [ -n "${HOST_SSH_PORT}" ] && [ -n "${HOST_HTTP_PORT}" ] || {
    echo "container port publishing failed for ${label}" >&2
    show_logs
    return 1
  }

  wait_for "${label} HTTP activation" 45 container_http_ok || {
    show_logs
    return 1
  }
  wait_for "${label} mesh-init supervises ssh-mesh" 20 mesh_init_started_ssh_mesh || {
    show_logs
    return 1
  }

  local entrypoint
  entrypoint="$("${ENGINE}" inspect --format '{{.Path}}' "${CONTAINER_NAME}")"
  [ "${entrypoint}" = "/opt/ssh-mesh/bin/mesh-init" ] || {
    echo "expected mesh-init PID 1, got ${entrypoint}" >&2
    return 1
  }

  local ssh_opts=(
    -i "${CLIENT_KEY}"
    -o "CertificateFile=${CLIENT_KEY}-cert.pub"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ConnectTimeout=10
    -o BatchMode=yes
    -p "${HOST_SSH_PORT}"
  )
  local id_output
  id_output="$(ssh "${ssh_opts[@]}" root@127.0.0.1 id 2>&1)" || {
    echo "SSH failed for ${label}: ${id_output}" >&2
    show_logs
    return 1
  }
  printf '%s\n' "${id_output}" | grep -q 'uid=0' || {
    echo "unexpected SSH identity for ${label}: ${id_output}" >&2
    return 1
  }
  echo "ok: ${label} SSH session via socket-activated ssh-mesh"

  "${ENGINE}" rm -f "${CONTAINER_NAME}" >/dev/null
  CONTAINER_NAME=""
}

need nix
need "${ENGINE}"
need ssh
need ssh-keygen
need curl

CA_KEY="${TEST_DIR}/ca_key"
CLIENT_KEY="${TEST_DIR}/client_key"
ssh-keygen -q -t ecdsa -b 256 -N "" -f "${CA_KEY}"
ssh-keygen -q -t ecdsa -b 256 -N "" -f "${CLIENT_KEY}"
ssh-keygen -q -s "${CA_KEY}" -I "container-test" -n root -V "+1d" "${CLIENT_KEY}.pub"
CA_PUB_CONTENT="$(cat "${CA_KEY}.pub")"

build_nix_image
build_dockerfile_image
test_image nix "${NIX_IMAGE_REF}"
test_image netshoot "${DOCKERFILE_IMAGE_REF}"

echo "container integration tests passed"
