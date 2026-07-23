#!/usr/bin/env bash

# Browser-authored managed-DNS variant of the real packet lifecycle proof.
# The UI enables a per-network resolver, then the namespace harness verifies
# the signed lighthouse-only listener and performs an exact UDP DNS query over
# the authenticated Nebula overlay.

set -Eeuo pipefail
umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
[[ -n "${script_dir}" && -d "${script_dir}" && ! -L "${script_dir}" ]] || {
  printf 'ERROR: could not resolve a real script directory\n' >&2
  exit 1
}

MESH_UI_GUIDED_SMOKE=1 MESH_NETWORK_DNS_SMOKE=1 exec "${script_dir}/packet-smoke.sh"
