#!/usr/bin/env bash

# Browser-authored managed-relay variant of the real packet proof. The UI
# selects a relay, then two members are placed on disjoint point-to-point
# underlays that can each reach the relay but cannot route directly to one
# another. Bidirectional overlay ICMP therefore proves the Nebula relay path.

set -Eeuo pipefail
umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
[[ -n "${script_dir}" && -d "${script_dir}" && ! -L "${script_dir}" ]] || {
  printf 'ERROR: could not resolve a real script directory\n' >&2
  exit 1
}

MESH_UI_GUIDED_SMOKE=1 MESH_NETWORK_RELAY_SMOKE=1 exec "${script_dir}/packet-smoke.sh"
