#!/usr/bin/env bash

# Runs the exact observer overlay harness in its focused multi-lighthouse mode.

set -Eeuo pipefail
umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

MESH_RUNTIME_OBSERVER_OUTAGE_SMOKE=0 \
MESH_RUNTIME_OBSERVER_MULTILIGHTHOUSE_SMOKE=1 \
  exec "${script_dir}/nebula-observer-overlay-smoke.sh"
