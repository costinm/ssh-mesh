#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: import-nix-image.sh IMAGE_REF [OUT_DIR]

Pull IMAGE_REF, run nix-store --export inside the image, and import the exported
closure into the host Nix store.

IMAGE_REF must be a named image reference such as:
  ghcr.io/costinm/ssh-mesh-vm-cloud-profile:latest

Environment:
  ENGINE=podman|docker        Container engine. Auto-detected when unset.
  MAKE_CA=0|1                 Also rewrite roots to content-addressed paths.
                              Default: 1 when supported by local nix.
  STORE_PATHS_FILE=PATH       Path inside image with root store paths.
  ARTIFACTS_FILE=PATH         Path inside image with name<TAB>store-path rows.

Outputs in OUT_DIR, default ./target/nix-image-import:
  roots.txt                   Imported root store paths.
  artifacts.tsv               Image-provided artifact names and store paths.
  ca-paths.json               make-content-addressed JSON output, when enabled.
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

image_ref="${1:-}"
out_dir="${2:-target/nix-image-import}"

if [ -z "${image_ref}" ] || [ "${image_ref}" = "-h" ] || [ "${image_ref}" = "--help" ]; then
  usage
  exit 0
fi

case "${image_ref}" in
  *@sha256:*)
    die "pass a named image tag instead of a digest reference: ${image_ref}"
    ;;
esac

if [ -z "${ENGINE:-}" ]; then
  if command -v podman >/dev/null 2>&1; then
    ENGINE=podman
  elif command -v docker >/dev/null 2>&1; then
    ENGINE=docker
  else
    die "missing podman or docker"
  fi
fi

need "${ENGINE}"
need nix-store
need nix

mkdir -p "${out_dir}"
roots_out="${out_dir}/roots.txt"
artifacts_out="${out_dir}/artifacts.tsv"
ca_out="${out_dir}/ca-paths.json"

"${ENGINE}" pull "${image_ref}" >/dev/null

label_value() {
  local key="$1"
  local value
  value="$("${ENGINE}" image inspect \
    --format "{{ index .Config.Labels \"${key}\" }}" \
    "${image_ref}" 2>/dev/null || true)"
  if [ "${value}" = "<no value>" ]; then
    value=""
  fi
  printf '%s\n' "${value}"
}

store_paths_file="${STORE_PATHS_FILE:-$(label_value org.ssh-mesh.nix.store-paths-file)}"
artifacts_file="${ARTIFACTS_FILE:-$(label_value org.ssh-mesh.nix.artifacts-file)}"

: "${store_paths_file:=/nix-support/artifact-store-paths}"
: "${artifacts_file:=/nix-support/artifacts.tsv}"

run_in_image() {
  "${ENGINE}" run --rm --entrypoint /bin/bash "${image_ref}" -lc "$1" _ "${@:2}"
}

run_in_image '
  set -euo pipefail
  file="$1"
  test -r "$file"
  sed "/^[[:space:]]*$/d" "$file"
' "${store_paths_file}" > "${roots_out}"

run_in_image '
  set -euo pipefail
  file="$1"
  if [ -r "$file" ]; then
    cat "$file"
  fi
' "${artifacts_file}" > "${artifacts_out}"

run_in_image '
  set -euo pipefail
  file="$1"
  roots="$(sed "/^[[:space:]]*$/d" "$file")"
  nix-store -qR $roots | xargs -r nix-store --export
' "${store_paths_file}" | nix-store --import >/dev/null

if [ "${MAKE_CA:-1}" != "0" ]; then
  if nix store make-content-addressed --help >/dev/null 2>&1; then
    nix store make-content-addressed --json --stdin < "${roots_out}" > "${ca_out}"
  else
    echo "warning: local nix does not support 'nix store make-content-addressed'" >&2
  fi
fi

echo "roots=${roots_out}"
echo "artifacts=${artifacts_out}"
if [ -s "${ca_out}" ]; then
  echo "content_addressed=${ca_out}"
fi
