#!/usr/bin/env bash

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
export MESH_UI_GUIDED_PACKAGE_SMOKE=1
exec "${repo_root}/scripts/linux-install-smoke.sh" "$@"
