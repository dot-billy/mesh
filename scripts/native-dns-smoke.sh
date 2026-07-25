#!/usr/bin/env bash

# Browser-authored native split-DNS variant of the real Nebula DNS packet
# proof. The namespace harness starts the production suffix adapter from the
# exact signed member config, resolves a suffixed certificate name through the
# lighthouse, and proves an unrelated public name is not recursively forwarded.

set -Eeuo pipefail
umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
[[ -n "${script_dir}" && -d "${script_dir}" && ! -L "${script_dir}" ]] || {
  printf 'ERROR: could not resolve a real script directory\n' >&2
  exit 1
}

MESH_UI_GUIDED_SMOKE=1 MESH_NETWORK_DNS_SMOKE=1 MESH_NATIVE_DNS_SMOKE=1 \
  exec "${script_dir}/packet-smoke.sh"
