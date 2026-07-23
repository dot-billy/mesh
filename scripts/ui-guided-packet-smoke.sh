#!/usr/bin/env bash

# Browser-authored variant of the real packet lifecycle proof. This proves the
# current UI path from sign-in through network/lighthouse/member creation and
# then delegates enrollment, signed convergence, and packet assertions to the
# hardened namespace harness.

set -Eeuo pipefail
umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
[[ -n "${script_dir}" && -d "${script_dir}" && ! -L "${script_dir}" ]] || {
  printf 'ERROR: could not resolve a real script directory\n' >&2
  exit 1
}

MESH_UI_GUIDED_SMOKE=1 exec "${script_dir}/packet-smoke.sh"
