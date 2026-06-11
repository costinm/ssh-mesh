#!/usr/bin/env bash
set -euo pipefail

# Run `ls -l /dev` over SSH against each environment exposed by the host1 example.
# Start the examples first with:
#
#   docs/examples/start_all.sh

examples_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace_dir="$(cd "${examples_dir}/../.." 2>/dev/null && pwd)"
target_dir="${SSH_MESH_TARGET_DIR:-${workspace_dir}/target}"
root_dir="${SSH_MESH_EXAMPLE_ROOT:-${target_dir}/examples}"
log_dir="${root_dir}/logs/ssh-ls-dev"

ssh_config="${SSH_MESH_SSH_CONFIG:-${examples_dir}/ssh_config}"
host1_port="${SSH_MESH_HOST1_SSH_PORT:-18422}"
timeout_secs="${SSH_MESH_DEV_LS_TIMEOUT:-180}"
runs="${SSH_MESH_DEV_LS_RUNS:-2}"

targets="${SSH_MESH_DEV_LS_TARGETS:-host1 host2 app1-bwrap host3-vm app2-qemu app3-crosvm app4-ch}"

for f in "${ssh_config}" "${examples_dir}/host1/home/system/.ssh/id_ecdsa" "${examples_dir}/host1/home/system/.ssh/id_ecdsa-user-cert.pub"; do
  if [ ! -r "${f}" ]; then
    echo "missing SSH config/key/certificate: ${f}" >&2
    echo "regenerate with: ${examples_dir}/generate_keys.sh" >&2
    exit 2
  fi
done

mkdir -p "${log_dir}"

ssh_opts=(
  -F "${ssh_config}"
  -p "${host1_port}"
)

failed=0
summary="${log_dir}/summary.tsv"
first_run_summary="${log_dir}/first-run.tsv"
second_run_summary="${log_dir}/second-run.tsv"

now_ns() {
  date +%s%N
}

elapsed_ms() {
  start_ns="$1"
  end_ns="$2"
  echo $(((end_ns - start_ns) / 1000000))
}

printf 'target\trun\tstatus\telapsed_ms\tlog\n' >"${summary}"

for target in ${targets}; do
  echo "=== ${target} (ssh_config, host1 port ${host1_port}) ==="

  run=1
  while [ "${run}" -le "${runs}" ]; do
    log="${log_dir}/${target}.${run}.log"
    marker="__SSH_MESH_LS_DEV_DONE_${target}_${run}__"

    start_ns="$(now_ns)"
    set +e
    (
      cd "${examples_dir}"
      timeout --foreground "${timeout_secs}s" \
        ssh "${ssh_opts[@]}" "${target}" "echo ${marker}; ls -l /dev"
    ) >"${log}" 2>&1
    status=$?
    set -e
    end_ns="$(now_ns)"
    ms="$(elapsed_ms "${start_ns}" "${end_ns}")"

    sed "/${marker}/d" "${log}"

    if grep -q "${marker}" "${log}"; then
      result="ok"
    else
      result="failed"
      failed=1
    fi

    printf '%s\t%s\t%s\t%s\t%s\n' "${target}" "${run}" "${result}" "${ms}" "${log}" \
      >>"${summary}"
    echo "${result}: ${target} run ${run} (${ms} ms, ssh status ${status}, log ${log})"
    run=$((run + 1))
  done
  echo
done

echo "summary: ${summary}"
awk 'NR == 1 || $2 == "1"' "${summary}" >"${first_run_summary}"
awk 'NR == 1 || $2 == "2"' "${summary}" >"${second_run_summary}"
echo "first run: ${first_run_summary}"
echo "second run: ${second_run_summary}"

exit "${failed}"
