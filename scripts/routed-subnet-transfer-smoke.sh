#!/usr/bin/env bash

# API-driven routed-subnet ownership-transfer variant of the real packet proof.
# Three real Nebula nodes share an isolated routed LAN. The target installs its
# expanded certificate before promotion; the source later installs its cleaned
# certificate, and the final packet proof runs with source forwarding disabled.

set -Eeuo pipefail
umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
[[ -n "${script_dir}" && -d "${script_dir}" && ! -L "${script_dir}" ]] || {
  printf 'ERROR: could not resolve a real script directory\n' >&2
  exit 1
}

MESH_UNSAFE_ROUTE_SMOKE=1 MESH_ROUTE_TRANSFER_SMOKE=1 \
  exec "${script_dir}/packet-smoke.sh"
