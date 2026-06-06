#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -P "${SCRIPT_DIR}/.." && pwd -P)"
cd "${PROJECT_ROOT}"

OUT="${OUT:-${PROJECT_ROOT}/target/vm/echo-latency}"
LOG_DIR="${OUT}/logs"
RUNS="${RUNS:-3}"
mkdir -p "${LOG_DIR}"

tests=(
  "qemu-vrun"
  "cloud-hypervisor-vrun"
  "crosvm-vrun"
  "microvm-crosvm"
  "microvm-qemu"
  "microvm-cloud-hypervisor"
)

run_one() {
  local name="$1"
  local iter="$2"
  local log="${LOG_DIR}/${name}.${iter}.log"
  local start_ns
  local end_ns
  local status
  local elapsed_ms

  printf 'running %-26s' "${name}"
  start_ns="$(date +%s%N)"
  case "${name}" in
    qemu-vrun)
      TIMEOUT="${TIMEOUT:-90}" tests/test_vm_qemu_echo.sh >"${log}" 2>&1
      ;;
    cloud-hypervisor-vrun)
      TIMEOUT="${TIMEOUT:-90}" tests/test_vm_vrun_cloud_hypervisor_echo.sh >"${log}" 2>&1
      ;;
    crosvm-vrun)
      TIMEOUT="${TIMEOUT:-90}" tests/test_vm_vrun_crosvm_echo.sh >"${log}" 2>&1
      ;;
    microvm-crosvm)
      TIMEOUT="${TIMEOUT:-90}" MICROVM_HYPERVISOR=crosvm tests/test_vm_microvm_echo.sh >"${log}" 2>&1
      ;;
    microvm-qemu)
      TIMEOUT="${TIMEOUT:-90}" MICROVM_HYPERVISOR=qemu tests/test_vm_microvm_echo.sh >"${log}" 2>&1
      ;;
    microvm-cloud-hypervisor)
      TIMEOUT="${TIMEOUT:-90}" MICROVM_HYPERVISOR=cloud-hypervisor tests/test_vm_microvm_echo.sh >"${log}" 2>&1
      ;;
    *)
      echo "unknown test: ${name}" >&2
      return 2
      ;;
  esac
  status=$?
  end_ns="$(date +%s%N)"
  elapsed_ms=$(((end_ns - start_ns) / 1000000))

  if [[ "${status}" -eq 0 ]]; then
    printf ' ok %s ms\n' "${elapsed_ms}"
  else
    printf ' fail %s ms\n' "${elapsed_ms}"
  fi

  printf '%s\t%s\t%s\t%s\n' "${name}" "${status}" "${elapsed_ms}" "${log}" >> "${OUT}/results.tsv"
  return 0
}

rm -f "${OUT}/results.tsv"
printf 'name\tstatus\tms\tlog\n' > "${OUT}/results.tsv"

for name in "${tests[@]}"; do
  iter=1
  while [[ "${iter}" -le "${RUNS}" ]]; do
    run_one "${name}" "${iter}"
    iter=$((iter + 1))
  done
done

echo
printf '%-28s %5s %10s %10s %10s %s\n' "name" "pass" "avg_ms" "min_ms" "max_ms" "logs"
awk -F '\t' '
  NR == 1 { next }
  {
    seen[$1] = 1
    total[$1] += $3
    count[$1] += 1
    if ($2 == 0) {
      pass[$1] += 1
    }
    if (!($1 in min) || $3 < min[$1]) {
      min[$1] = $3
    }
    if (!($1 in max) || $3 > max[$1]) {
      max[$1] = $3
    }
  }
  END {
    order[1] = "qemu-vrun"
    order[2] = "cloud-hypervisor-vrun"
    order[3] = "crosvm-vrun"
    order[4] = "microvm-crosvm"
    order[5] = "microvm-qemu"
    order[6] = "microvm-cloud-hypervisor"
    for (i = 1; i <= 6; i++) {
      name = order[i]
      if (count[name] > 0) {
        printf "%-28s %2d/%-2d %10.0f %10d %10d %s/%s.*.log\n", name, pass[name], count[name], total[name] / count[name], min[name], max[name], log_dir, name
      }
    }
  }
' log_dir="${LOG_DIR}" "${OUT}/results.tsv"
