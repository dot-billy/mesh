#!/usr/bin/env bash

# Browser-authored routed-subnet variant of the real packet lifecycle proof.
# The UI declares exact gateway ownership before enrollment; the namespace
# harness then proves the certificate, signed configs, OS route, forwarding
# gateway, and a non-Nebula destination as one fail-closed path.

set -Eeuo pipefail
umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
[[ -n "${script_dir}" && -d "${script_dir}" && ! -L "${script_dir}" ]] || {
  printf 'ERROR: could not resolve a real script directory\n' >&2
  exit 1
}

MESH_UI_GUIDED_SMOKE=1 MESH_UNSAFE_ROUTE_SMOKE=1 exec "${script_dir}/packet-smoke.sh"
