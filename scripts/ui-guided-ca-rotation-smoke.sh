#!/usr/bin/env bash

# Browser-authored zero-downtime CA rotation proof. The guided UI creates the
# real two-node network, then the staged control workflow rotates both agents
# and live Nebula processes while a continuous authenticated packet stream is
# measured for loss.

set -Eeuo pipefail
umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
[[ -n "${script_dir}" && -d "${script_dir}" && ! -L "${script_dir}" ]] || {
  printf 'ERROR: could not resolve a real script directory\n' >&2
  exit 1
}

MESH_UI_GUIDED_SMOKE=1 MESH_CA_ROTATION_SMOKE=1 exec "${script_dir}/packet-smoke.sh"
