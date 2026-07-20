#!/usr/bin/env bash
set -u

iw_bin="${IW:-iw}"
ip_bin="${IP:-ip}"
rfkill_bin="${RFKILL:-rfkill}"
wpa_supplicant_bin="${LMESH_WPA_SUPPLICANT:-wpa_supplicant}"
wpa_cli_bin="${WPA_CLI:-wpa_cli}"
iface="${LMESH_WIFI_IFACE:-wlan1}"
ctrl_dir="${LMESH_WPA_CTRL_DIR:-/run/mesh/wpa-supplicant-nan}"

section() {
  printf '\n== %s ==\n' "$1"
}

run_optional() {
  local label="$1"
  shift
  printf '\n-- %s: %s\n' "$label" "$*"
  if command -v "$1" >/dev/null 2>&1 || [ -x "$1" ]; then
    "$@" 2>&1 || true
  else
    printf 'missing: %s\n' "$1"
  fi
}

section "helpers"
for helper in "$iw_bin" "$ip_bin" "$rfkill_bin" "$wpa_supplicant_bin" "$wpa_cli_bin"; do
  if command -v "$helper" >/dev/null 2>&1 || [ -x "$helper" ]; then
    command -v "$helper" 2>/dev/null || printf '%s\n' "$helper"
  else
    printf 'missing: %s\n' "$helper"
  fi
done

section "process capabilities"
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/$$/status

section "interfaces"
run_optional "ip links" "$ip_bin" -o link show
run_optional "iw dev" "$iw_bin" dev

section "phys and NAN support"
if command -v "$iw_bin" >/dev/null 2>&1 || [ -x "$iw_bin" ]; then
  "$iw_bin" phy 2>&1 | awk '
    /^Wiphy / {
      if (phy != "") {
        printf "%s mentions_nan=%s nan_interface_mode=%s nan_frame_sections=%s\n", phy, mentions, mode, frames
      }
      phy=$2; mentions="no"; mode="no"; frames="no"
    }
    /NAN/ { mentions="yes" }
    /^[[:space:]]+\* NAN$/ { mode="yes" }
    /^[[:space:]]+\* NAN:/ { frames="yes" }
    /NAN function/ { frames="yes" }
    { print }
    END {
      if (phy != "") {
        printf "%s mentions_nan=%s nan_interface_mode=%s nan_frame_sections=%s\n", phy, mentions, mode, frames
      }
    }'
else
  printf 'missing: %s\n' "$iw_bin"
fi

section "rfkill"
run_optional "rfkill" "$rfkill_bin" list

section "wpa"
printf 'iface=%s\nctrl_dir=%s\n' "$iface" "$ctrl_dir"
client_dir="/tmp/lmesh-radio-preflight-$$"
mkdir -p "$client_dir"
run_optional "wpa_supplicant version" "$wpa_supplicant_bin" -v
run_optional "wpa status" "$wpa_cli_bin" -p "$ctrl_dir" -i "$iface" -s "$client_dir" STATUS
run_optional "wpa NAN_GET_CAPABILITY" "$wpa_cli_bin" -p "$ctrl_dir" -i "$iface" -s "$client_dir" NAN_GET_CAPABILITY
