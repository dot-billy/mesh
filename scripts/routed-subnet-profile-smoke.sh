#!/usr/bin/env bash

# API-driven active-gateway route-profile variant of the real packet proof.
# One routed prefix is withdrawn route-first and restored certificate-first;
# real agents, certificates, signed configs, Nebula processes, and packets are
# checked at every convergence boundary.

set -Eeuo pipefail
umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
[[ -n "${script_dir}" && -d "${script_dir}" && ! -L "${script_dir}" ]] || {
  printf 'ERROR: could not resolve a real script directory\n' >&2
  exit 1
}

MESH_UNSAFE_ROUTE_SMOKE=1 MESH_ROUTE_PROFILE_SMOKE=1 \
  exec "${script_dir}/packet-smoke.sh"
