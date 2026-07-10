#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fragment_dir="${1:-${repo_root}/linux/fragments}"
kernel_config="${2:-${NIX_PROFILE:-${repo_root}/target/nix/profile}/opt/ssh-mesh-kernel/config}"

if [ ! -d "${fragment_dir}" ]; then
  echo "missing fragment directory: ${fragment_dir}" >&2
  exit 2
fi

if [ ! -r "${kernel_config}" ]; then
  cat >&2 <<EOF
missing readable kernel config: ${kernel_config}

Build/update the profile first:
  ${repo_root}/scripts/build.sh profile
EOF
  exit 2
fi

tmp_required="$(mktemp)"
tmp_kernel="$(mktemp)"
trap 'rm -f "${tmp_required}" "${tmp_kernel}"' EXIT

awk '
  /^[[:space:]]*CONFIG_[A-Za-z0-9_]+=/ {
    split($0, parts, "=")
    symbol = parts[1]
    value = substr($0, length(symbol) + 2)
    required[symbol] = value
  }
  END {
    for (symbol in required) {
      print symbol "=" required[symbol]
    }
  }
' "${fragment_dir}"/*.fragment | sort > "${tmp_required}"

awk '
  /^[[:space:]]*CONFIG_[A-Za-z0-9_]+=/ {
    split($0, parts, "=")
    symbol = parts[1]
    value = substr($0, length(symbol) + 2)
    kernel[symbol] = value
  }
  /^[[:space:]]*#[[:space:]]*CONFIG_[A-Za-z0-9_]+ is not set/ {
    symbol = $2
    kernel[symbol] = "n"
  }
  END {
    for (symbol in kernel) {
      print symbol "=" kernel[symbol]
    }
  }
' "${kernel_config}" | sort > "${tmp_kernel}"

echo "Comparing:"
echo "  required: ${fragment_dir}/*.fragment"
echo "  kernel:   ${kernel_config}"
echo

awk -F= '
  NR == FNR {
    kernel[$1] = $2
    next
  }
  {
    required = $2
    actual = (($1 in kernel) ? kernel[$1] : "missing")
    if (actual != required) {
      printf "%-42s required=%-24s actual=%s\n", $1, required, actual
      count++
    }
  }
  END {
    if (count == 0) {
      print "All fragment symbols match the Nix kernel config."
    } else {
      printf "\n%d fragment symbols differ from the Nix kernel config.\n", count
      exit 1
    }
  }
' "${tmp_kernel}" "${tmp_required}"
