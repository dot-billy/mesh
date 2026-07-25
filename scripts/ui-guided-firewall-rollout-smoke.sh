#!/usr/bin/env bash

# Browser-authored two-node proof for a staged firewall canary, exact
# convergence gate, rollback, and promotion on the original Nebula processes.

set -Eeuo pipefail
umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
[[ -n "${script_dir}" && -d "${script_dir}" && ! -L "${script_dir}" ]] || {
  printf 'ERROR: could not resolve a real script directory\n' >&2
  exit 1
}

MESH_UI_GUIDED_SMOKE=1 MESH_FIREWALL_ROLLOUT_SMOKE=1 exec "${script_dir}/packet-smoke.sh"
