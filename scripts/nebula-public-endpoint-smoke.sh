#!/usr/bin/env bash

# Runs the exact observer harness with routed, DNAT-backed public lighthouse
# endpoints, two members, two failure-domain lighthouses, and a site-edge loss.

set -Eeuo pipefail
umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

MESH_RUNTIME_OBSERVER_OUTAGE_SMOKE=0 \
MESH_RUNTIME_OBSERVER_MULTILIGHTHOUSE_SMOKE=1 \
MESH_RUNTIME_ACTIVE_PROBE_SMOKE=1 \
MESH_RUNTIME_MULTIMEMBER_SMOKE=1 \
MESH_RUNTIME_PUBLIC_ENDPOINT_SMOKE=1 \
  exec "${script_dir}/nebula-observer-overlay-smoke.sh"
