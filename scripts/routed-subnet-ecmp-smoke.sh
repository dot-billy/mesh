#!/usr/bin/env bash

# API-driven weighted-ECMP variant of the real packet proof. Two active
# certificate owners share one exact routed prefix. Varying UDP port pairs
# prove distribution, fallback, recovery, and route-first member removal.

set -Eeuo pipefail
umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
[[ -n "${script_dir}" && -d "${script_dir}" && ! -L "${script_dir}" ]] || {
  printf 'ERROR: could not resolve a real script directory\n' >&2
  exit 1
}

MESH_UNSAFE_ROUTE_SMOKE=1 MESH_ROUTE_ECMP_SMOKE=1 \
  exec "${script_dir}/packet-smoke.sh"
