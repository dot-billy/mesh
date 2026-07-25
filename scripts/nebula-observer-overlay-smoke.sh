#!/usr/bin/env bash

# Builds the exact observer-locked Nebula stage, then runs the real two-node
# packet lifecycle with one private /run mount per Nebula process. Exit 77 is a
# local capability/prerequisite skip inherited from packet-smoke.sh.

set -Eeuo pipefail
umask 077

readonly script_name="${0##*/}"
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
active_probe_smoke="${MESH_RUNTIME_ACTIVE_PROBE_SMOKE:-0}"
if [[ -n "${MESH_RUNTIME_OBSERVER_OUTAGE_SMOKE+x}" ]]; then
  observer_outage_smoke="${MESH_RUNTIME_OBSERVER_OUTAGE_SMOKE}"
elif [[ "${active_probe_smoke}" == "1" ]]; then
  observer_outage_smoke=0
else
  observer_outage_smoke=1
fi
observer_multilighthouse_smoke="${MESH_RUNTIME_OBSERVER_MULTILIGHTHOUSE_SMOKE:-0}"
multimember_smoke="${MESH_RUNTIME_MULTIMEMBER_SMOKE:-0}"
public_endpoint_smoke="${MESH_RUNTIME_PUBLIC_ENDPOINT_SMOKE:-0}"
work_dir=""

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local status=$?

  trap - EXIT HUP INT TERM
  set +e
  if [[ -n "${work_dir}" && -d "${work_dir}" ]]; then
    case "${work_dir##*/}" in
      mesh-nebula-observer-overlay.*)
        if [[ -L "${work_dir}" ]]; then
          printf 'ERROR: refusing to remove linked observer-overlay workspace %s\n' "${work_dir}" >&2
          status=1
        else
          chmod -R u+w -- "${work_dir}" 2>/dev/null || status=1
          rm -rf -- "${work_dir}" || status=1
        fi
        ;;
      *)
        printf 'ERROR: refusing to remove unexpected observer-overlay workspace %s\n' "${work_dir}" >&2
        status=1
        ;;
    esac
  fi
  exit "${status}"
}

on_error() {
  local status=$?
  local line="${1:-unknown}"

  trap - ERR
  printf 'ERROR: %s failed at line %s; private diagnostics were removed\n' \
    "${script_name}" "${line}" >&2
  exit "${status}"
}

trap cleanup EXIT
trap 'on_error "${LINENO}"' ERR
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for prerequisite in go mktemp chmod rm; do
  command -v -- "${prerequisite}" >/dev/null 2>&1 ||
    die "required command is unavailable: ${prerequisite}"
done

case "${observer_outage_smoke}" in
  0 | 1) ;;
  *) die "MESH_RUNTIME_OBSERVER_OUTAGE_SMOKE must be exactly 0 or 1" ;;
esac
case "${active_probe_smoke}" in
  0 | 1) ;;
  *) die "MESH_RUNTIME_ACTIVE_PROBE_SMOKE must be exactly 0 or 1" ;;
esac
case "${observer_multilighthouse_smoke}" in
  0 | 1) ;;
  *) die "MESH_RUNTIME_OBSERVER_MULTILIGHTHOUSE_SMOKE must be exactly 0 or 1" ;;
esac
case "${multimember_smoke}" in
  0 | 1) ;;
  *) die "MESH_RUNTIME_MULTIMEMBER_SMOKE must be exactly 0 or 1" ;;
esac
case "${public_endpoint_smoke}" in
  0 | 1) ;;
  *) die "MESH_RUNTIME_PUBLIC_ENDPOINT_SMOKE must be exactly 0 or 1" ;;
esac
if [[ "${observer_multilighthouse_smoke}" == "1" && "${observer_outage_smoke}" == "1" ]]; then
  die "multi-lighthouse and single-lighthouse outage modes are mutually exclusive"
fi
if [[ "${active_probe_smoke}" == "1" && "${observer_outage_smoke}" == "1" ]]; then
  die "active-probe and underlay-outage modes are mutually exclusive"
fi
if [[ "${multimember_smoke}" == "1" && ( "${observer_multilighthouse_smoke}" != "1" || "${active_probe_smoke}" != "1" ) ]]; then
  die "multi-member mode requires multi-lighthouse observer and active-probe modes"
fi
if [[ "${public_endpoint_smoke}" == "1" && "${multimember_smoke}" != "1" ]]; then
  die "public-endpoint mode requires multi-member mode"
fi

architecture="$(go env GOARCH)"
case "${architecture}" in
  amd64 | arm64) ;;
  *) die "observer overlay smoke supports only amd64 or arm64 hosts" ;;
esac

temp_parent="${TMPDIR:-/tmp}"
[[ -d "${temp_parent}" ]] || die "temporary directory parent does not exist: ${temp_parent}"
work_dir="$(mktemp -d "${temp_parent%/}/mesh-nebula-observer-overlay.XXXXXX")"
[[ -d "${work_dir}" && ! -L "${work_dir}" ]] ||
  die "mktemp did not create a real private directory"
chmod 0700 "${work_dir}"
mkdir -p -- "${work_dir}/bin"

printf 'Building exact observer stage and isolated Mesh smoke tools\n'
(
  cd -- "${repo_root}"
  go build -trimpath -buildvcs=false -o "${work_dir}/bin/mesh-deps" ./cmd/mesh-deps
  go build -trimpath -buildvcs=false -o "${work_dir}/bin/mesh-server" ./cmd/mesh-server
  go build -trimpath -buildvcs=false -o "${work_dir}/bin/meshctl" ./cmd/meshctl
  go build -trimpath -buildvcs=false -o "${work_dir}/bin/runtime-observer-smokeclient" \
    ./internal/runtimeobserver/smokeclient
  if [[ "${active_probe_smoke}" == "1" ]]; then
    go build -trimpath -buildvcs=false -o "${work_dir}/bin/probecapture" \
      ./internal/nodeagent/probecapture
  fi
)

observer_stage="${work_dir}/observer-stage"
"${work_dir}/bin/mesh-deps" build-nebula-observer \
  --arch "${architecture}" \
  --output-dir "${observer_stage}"

if [[ "${public_endpoint_smoke}" == "1" ]]; then
  printf 'Running routed public-endpoint edge/site failure proof\n'
elif [[ "${multimember_smoke}" == "1" ]]; then
  printf 'Running multi-member, multi-site observer and active-probe proof\n'
elif [[ "${active_probe_smoke}" == "1" ]]; then
  printf 'Running active-probe namespace/TUN proof\n'
elif [[ "${observer_multilighthouse_smoke}" == "1" ]]; then
  printf 'Running multi-lighthouse observer overlay proof\n'
else
  printf 'Running two-node observer overlay lifecycle proof\n'
fi
if MESH_SERVER_BIN="${work_dir}/bin/mesh-server" \
  MESHCTL_BIN="${work_dir}/bin/meshctl" \
  NEBULA_BIN="${observer_stage}/nebula" \
  NEBULA_CERT_BIN="${observer_stage}/nebula-cert" \
  MESH_RUNTIME_OBSERVER_SMOKE=1 \
  MESH_RUNTIME_OBSERVER_OUTAGE_SMOKE="${observer_outage_smoke}" \
  MESH_RUNTIME_OBSERVER_MULTILIGHTHOUSE_SMOKE="${observer_multilighthouse_smoke}" \
  MESH_RUNTIME_MULTIMEMBER_SMOKE="${multimember_smoke}" \
  MESH_RUNTIME_PUBLIC_ENDPOINT_SMOKE="${public_endpoint_smoke}" \
  MESH_RUNTIME_OBSERVER_PROBE_BIN="${work_dir}/bin/runtime-observer-smokeclient" \
  MESH_RUNTIME_ACTIVE_PROBE_SMOKE="${active_probe_smoke}" \
  MESH_RUNTIME_ACTIVE_PROBE_CAPTURE_BIN="${work_dir}/bin/probecapture" \
    "${repo_root}/scripts/packet-smoke.sh"; then
  :
else
  exit "$?"
fi
