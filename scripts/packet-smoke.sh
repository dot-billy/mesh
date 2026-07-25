#!/usr/bin/env bash

# Linux-only, packet-level lifecycle smoke for Mesh and real Nebula.
#
# The control plane and meshctl run in the caller's network namespace. Each
# Nebula process runs in its own Linux network namespace, joined only by a
# point-to-point veth underlay. The test proves that ICMP traverses the Nebula
# overlay, revokes the member, synchronizes the signed blocklist to the
# lighthouse, restarts that peer from the new immutable bundle, and proves the
# overlay path is cut while both Nebula processes remain alive. An opt-in
# observer mode also gives every peer a private mount namespace and /run,
# allowing the fixed production Unix socket to be exercised on both peers.

set -Eeuo pipefail
umask 077

readonly skip_status=77
readonly script_name="${0##*/}"

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
mesh_server_candidate="${MESH_SERVER_BIN:-${repo_root}/bin/mesh-server}"
meshctl_candidate="${MESHCTL_BIN:-${repo_root}/bin/meshctl}"
nebula_candidate="${NEBULA_BIN:-nebula}"
nebula_cert_candidate="${NEBULA_CERT_BIN:-nebula-cert}"
observer_smoke="${MESH_RUNTIME_OBSERVER_SMOKE:-0}"
observer_outage_smoke="${MESH_RUNTIME_OBSERVER_OUTAGE_SMOKE:-0}"
observer_multilighthouse_smoke="${MESH_RUNTIME_OBSERVER_MULTILIGHTHOUSE_SMOKE:-0}"
multimember_smoke="${MESH_RUNTIME_MULTIMEMBER_SMOKE:-0}"
public_endpoint_smoke="${MESH_RUNTIME_PUBLIC_ENDPOINT_SMOKE:-0}"
observer_probe_candidate="${MESH_RUNTIME_OBSERVER_PROBE_BIN:-}"
active_probe_smoke="${MESH_RUNTIME_ACTIVE_PROBE_SMOKE:-0}"
active_probe_capture_candidate="${MESH_RUNTIME_ACTIVE_PROBE_CAPTURE_BIN:-}"
ui_guided_smoke="${MESH_UI_GUIDED_SMOKE:-0}"
unsafe_route_smoke="${MESH_UNSAFE_ROUTE_SMOKE:-0}"
route_transfer_smoke="${MESH_ROUTE_TRANSFER_SMOKE:-0}"
route_profile_smoke="${MESH_ROUTE_PROFILE_SMOKE:-0}"
route_ecmp_smoke="${MESH_ROUTE_ECMP_SMOKE:-0}"
keep_smoke="${KEEP_MESH_PACKET_SMOKE:-0}"
dns_smoke="${MESH_NETWORK_DNS_SMOKE:-0}"
native_dns_smoke="${MESH_NATIVE_DNS_SMOKE:-0}"
native_dns_domain="packet.mesh"
relay_smoke="${MESH_NETWORK_RELAY_SMOKE:-0}"
ca_rotation_smoke="${MESH_CA_ROTATION_SMOKE:-0}"
firewall_rollout_smoke="${MESH_FIREWALL_ROLLOUT_SMOKE:-0}"
second_member_smoke="0"
second_lighthouse_smoke="0"

work_dir=""
server_data=""
curl_config=""
server_url=""
server_pid=""
lighthouse_launcher_pid=""
second_lighthouse_launcher_pid=""
member_launcher_pid=""
second_member_launcher_pid=""
lighthouse_nebula_pid=""
second_lighthouse_nebula_pid=""
member_nebula_pid=""
second_member_nebula_pid=""
first_edge_ns=""
second_edge_ns=""
observer_probe=""
active_probe_capture=""
active_capture_pid=""
active_proxy_pid=""
ca_rotation_probe_launcher_pid=""
ca_rotation_probe_pid=""
ca_rotation_heartbeat_helper=""
ui_guided_started_epoch=0
native_dns_proxy_launcher_pid=""
native_dns_smoke_binary=""

probe_ns=""
lighthouse_ns=""
second_lighthouse_ns=""
member_ns=""
second_member_ns=""
routed_host_ns=""
probe_ns_created=0
lighthouse_ns_created=0
second_lighthouse_ns_created=0
member_ns_created=0
second_member_ns_created=0
routed_host_ns_created=0
first_edge_ns_created=0
second_edge_ns_created=0

suffix=""
probe_veth_a=""
probe_veth_b=""
lighthouse_veth=""
member_veth=""
second_lighthouse_veth=""
second_member_veth=""
routed_gateway_veth=""
routed_host_veth=""
routed_gateway_peer=""
routed_target_veth=""
routed_target_peer=""
routed_host_interface="uplink0"

readonly routed_subnet="172.31.250.0/24"
readonly routed_gateway_ip="172.31.250.1"
readonly routed_host_ip="172.31.250.2"
readonly routed_target_ip="172.31.250.3"

declare -a root_prefix=()
declare -a multimember_root_links=()
declare -a multimember_bridges=()

say() {
  printf '%s\n' "$*"
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

skip() {
  printf 'SKIP: %s\n' "$*" >&2
  exit "${skip_status}"
}

run_root() {
  "${root_prefix[@]}" "$@"
}

stop_server() {
  local pid="${server_pid}"
  local attempt

  server_pid=""
  if [[ -z "${pid}" || ! "${pid}" =~ ^[0-9]+$ || "${pid}" -le 1 ]]; then
    return
  fi
  if ! kill -0 "${pid}" 2>/dev/null; then
    wait "${pid}" 2>/dev/null || true
    return
  fi
  kill -TERM "${pid}" 2>/dev/null || true
  for attempt in {1..50}; do
    if ! kill -0 "${pid}" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  if kill -0 "${pid}" 2>/dev/null; then
    kill -KILL "${pid}" 2>/dev/null || true
  fi
  wait "${pid}" 2>/dev/null || true
}

stop_namespace_processes() {
  local namespace="$1"
  local attempt pid
  local -a pids=()

  [[ -n "${namespace}" ]] || return
  while IFS= read -r pid; do
    [[ "${pid}" =~ ^[0-9]+$ && "${pid}" -gt 1 ]] && pids+=("${pid}")
  done < <(run_root ip netns pids "${namespace}" 2>/dev/null || true)
  if (( ${#pids[@]} == 0 )); then
    return
  fi

  run_root kill -TERM -- "${pids[@]}" 2>/dev/null || true
  for attempt in {1..50}; do
    pids=()
    while IFS= read -r pid; do
      [[ "${pid}" =~ ^[0-9]+$ && "${pid}" -gt 1 ]] && pids+=("${pid}")
    done < <(run_root ip netns pids "${namespace}" 2>/dev/null || true)
    (( ${#pids[@]} == 0 )) && return
    sleep 0.1
  done
  run_root kill -KILL -- "${pids[@]}" 2>/dev/null || true
  for attempt in {1..20}; do
    if ! namespace_has_process "${namespace}"; then
      return
    fi
    sleep 0.1
  done
  return 1
}

delete_namespace() {
  local namespace="$1"

  [[ -n "${namespace}" ]] || return
  stop_namespace_processes "${namespace}"
  run_root ip netns del "${namespace}" >/dev/null 2>&1
}

cleanup() {
  local status=$?

  trap - ERR EXIT HUP INT TERM
  set +e

  if [[ "${routed_host_ns_created}" == "1" ]]; then
    if ! delete_namespace "${routed_host_ns}"; then
      printf 'ERROR: could not remove packet-smoke routed-host namespace\n' >&2
      status=1
    fi
    routed_host_ns_created=0
  fi

  if [[ "${second_lighthouse_ns_created}" == "1" ]]; then
    if ! delete_namespace "${second_lighthouse_ns}"; then
      printf 'ERROR: could not remove packet-smoke second lighthouse namespace\n' >&2
      status=1
    fi
    second_lighthouse_ns_created=0
  fi
  if [[ "${second_edge_ns_created}" == "1" ]]; then
    if ! delete_namespace "${second_edge_ns}"; then
      printf 'ERROR: could not remove packet-smoke second edge namespace\n' >&2
      status=1
    fi
    second_edge_ns_created=0
  fi
  if [[ "${first_edge_ns_created}" == "1" ]]; then
    if ! delete_namespace "${first_edge_ns}"; then
      printf 'ERROR: could not remove packet-smoke first edge namespace\n' >&2
      status=1
    fi
    first_edge_ns_created=0
  fi
  if [[ "${second_member_ns_created}" == "1" ]]; then
    if ! delete_namespace "${second_member_ns}"; then
      printf 'ERROR: could not remove packet-smoke second member namespace\n' >&2
      status=1
    fi
    second_member_ns_created=0
  fi
  if [[ "${member_ns_created}" == "1" ]]; then
    if ! delete_namespace "${member_ns}"; then
      printf 'ERROR: could not remove packet-smoke member namespace\n' >&2
      status=1
    fi
    member_ns_created=0
  fi
  if [[ "${lighthouse_ns_created}" == "1" ]]; then
    if ! delete_namespace "${lighthouse_ns}"; then
      printf 'ERROR: could not remove packet-smoke lighthouse namespace\n' >&2
      status=1
    fi
    lighthouse_ns_created=0
  fi
  if [[ "${probe_ns_created}" == "1" ]]; then
    if ! delete_namespace "${probe_ns}"; then
      printf 'ERROR: could not remove packet-smoke capability namespace\n' >&2
      status=1
    fi
    probe_ns_created=0
  fi

  local link
  for link in "${probe_veth_a}" "${probe_veth_b}" "${lighthouse_veth}" "${member_veth}" \
    "${second_lighthouse_veth}" "${second_member_veth}" "${routed_gateway_veth}" "${routed_host_veth}" \
    "${routed_gateway_peer}" "${routed_target_veth}" "${routed_target_peer}" \
    "${multimember_root_links[@]}"; do
    [[ -n "${link}" ]] || continue
    if run_root ip link show dev "${link}" >/dev/null 2>&1; then
      if ! run_root ip link del "${link}" >/dev/null 2>&1 ||
        run_root ip link show dev "${link}" >/dev/null 2>&1; then
        printf 'ERROR: could not remove packet-smoke veth %s\n' "${link}" >&2
        status=1
      fi
    fi
  done
  for link in "${multimember_bridges[@]}"; do
    [[ -n "${link}" ]] || continue
    if run_root ip link show dev "${link}" >/dev/null 2>&1; then
      if ! run_root ip link del "${link}" >/dev/null 2>&1 ||
        run_root ip link show dev "${link}" >/dev/null 2>&1; then
        printf 'ERROR: could not remove packet-smoke bridge %s\n' "${link}" >&2
        status=1
      fi
    fi
  done

  if [[ -n "${lighthouse_launcher_pid}" ]]; then
    wait "${lighthouse_launcher_pid}" 2>/dev/null || true
  fi
  if [[ -n "${second_lighthouse_launcher_pid}" ]]; then
    wait "${second_lighthouse_launcher_pid}" 2>/dev/null || true
  fi
  if [[ -n "${member_launcher_pid}" ]]; then
    wait "${member_launcher_pid}" 2>/dev/null || true
  fi
  if [[ -n "${second_member_launcher_pid}" ]]; then
    wait "${second_member_launcher_pid}" 2>/dev/null || true
  fi
  if [[ -n "${active_capture_pid}" ]]; then
    wait "${active_capture_pid}" 2>/dev/null || true
  fi
  if [[ -n "${active_proxy_pid}" ]]; then
    wait "${active_proxy_pid}" 2>/dev/null || true
  fi
  if [[ -n "${ca_rotation_probe_launcher_pid}" ]]; then
    wait "${ca_rotation_probe_launcher_pid}" 2>/dev/null || true
  fi
  if [[ -n "${native_dns_proxy_launcher_pid}" ]]; then
    wait "${native_dns_proxy_launcher_pid}" 2>/dev/null || true
  fi
  stop_server

  if [[ -n "${work_dir}" && -d "${work_dir}" ]]; then
    case "${work_dir##*/}" in
      mesh-packet-smoke.*)
        if [[ "${keep_smoke}" == "1" ]]; then
          printf 'Kept private packet-smoke workspace for diagnostics: %s\n' "${work_dir}" >&2
        else
          rm -rf -- "${work_dir}"
        fi
        ;;
      *)
        printf 'ERROR: refusing to remove unexpected packet-smoke path %s\n' "${work_dir}" >&2
        status=1
        ;;
    esac
  fi
  exit "${status}"
}

on_error() {
  local status=$?
  local line="${1:-unknown}"
  local disposition="were removed"

  trap - ERR
  [[ "${keep_smoke}" == "1" ]] && disposition="will be retained"
  printf 'ERROR: %s failed at line %s; private diagnostics %s\n' \
    "${script_name}" "${line}" "${disposition}" >&2
  exit "${status}"
}

trap cleanup EXIT
trap 'on_error "${LINENO}"' ERR
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

resolve_executable() {
  local candidate="$1"

  if [[ "${candidate}" == */* ]]; then
    [[ -f "${candidate}" && -x "${candidate}" ]] || return 1
    printf '%s\n' "${candidate}"
    return
  fi
  command -v -- "${candidate}"
}

nebula_version_pinned() {
  local output="$1"

  [[ "${output}" == "Version: 1.10.3" ]]
}

pick_loopback_port() {
  python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

start_server() {
  local attempt poll port ready
  local -a server_args

  mkdir -p -- "${server_data}"
  chmod 0700 "${server_data}"
  : >"${work_dir}/server.log"
  for attempt in {1..8}; do
    port="$(pick_loopback_port)"
    [[ "${port}" =~ ^[0-9]+$ && "${port}" -ge 1024 && "${port}" -le 65535 ]] ||
      die "kernel returned an invalid loopback port"
    server_url="http://127.0.0.1:${port}"

    server_args=(
      --dev
      --listen "127.0.0.1:${port}"
      --data-dir "${server_data}"
    )
    if [[ "${ui_guided_smoke}" == "1" ]]; then
      server_args+=(--linux-install-bundle-url "https://releases.example.invalid/channels/stable/bundle.json")
    fi
    NEBULA_CERT_BINARY="${nebula_cert}" \
      "${mesh_server}" "${server_args[@]}" \
      >>"${work_dir}/server.log" 2>&1 &
    server_pid=$!
    ready=0
    for poll in {1..100}; do
      if curl --silent --show-error --fail --noproxy '*' \
        --connect-timeout 1 --max-time 1 \
        --output /dev/null "${server_url}/healthz" 2>/dev/null; then
        ready=1
        break
      fi
      if ! kill -0 "${server_pid}" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    if [[ "${ready}" == "1" ]]; then
      return
    fi
    stop_server
  done
  die "could not start the development control plane on a free loopback port"
}

api_request() {
  local method="$1"
  local path="$2"
  local output="$3"
  local -a args

  args=(
    --config "${curl_config}"
    --request "${method}"
    --output "${output}"
    --noproxy '*'
  )
  if [[ $# -eq 4 ]]; then
    args+=(--data-binary "@$4")
  fi
  curl "${args[@]}" "${server_url}${path}"
}

assert_route_transfer_document() {
  local path="$1"
  local phase="$2"
  local revision="$3"
  local request_id="$4"
  local source_id="$5"
  local target_id="$6"
  local source_ready="$7"
  local target_ready="$8"
  local actions="$9"

  python3 - "${path}" "${phase}" "${revision}" "${request_id}" \
    "${source_id}" "${target_id}" "${source_ready}" "${target_ready}" "${actions}" \
    "${routed_subnet}" <<'PY'
import json
import pathlib
import re
import sys

(
    path, phase, revision, request_id, source_id, target_id,
    source_ready, target_ready, actions, routed_subnet,
) = sys.argv[1:]
document = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
expected_keys = {
    "schema", "network_id", "request_id", "phase", "routed_subnets",
    "config_revision", "started_at", "promoted_at", "finished_at",
    "source", "target", "available_actions",
}

node_keys = {
    "node_id", "name", "certificate_generation",
    "applied_certificate_generation", "applied_config_revision",
    "desired_certificate_generation", "ready",
}
if set(document) != expected_keys or document.get("schema") != "mesh-network-route-transfer-v1":
    raise SystemExit("route-transfer document schema is not exact")
if document.get("request_id") != request_id or document.get("phase") != phase:
    raise SystemExit("route-transfer document identity or phase changed")
if document.get("config_revision") != int(revision) or document.get("routed_subnets") != [routed_subnet]:
    raise SystemExit("route-transfer document revision or exact prefix changed")
for label, expected_id, ready in (
    ("source", source_id, source_ready == "1"),
    ("target", target_id, target_ready == "1"),
):
    node = document.get(label)
    if not isinstance(node, dict) or set(node) != node_keys or node.get("node_id") != expected_id:
        raise SystemExit(f"route-transfer {label} status is not exact")
    if node.get("ready") is not ready:
        raise SystemExit(f"route-transfer {label} readiness is not authoritative")
    for key in (
        "certificate_generation", "applied_certificate_generation",
        "applied_config_revision", "desired_certificate_generation",
    ):
        if not isinstance(node.get(key), int) or isinstance(node.get(key), bool) or node[key] < 0:
            raise SystemExit(f"route-transfer {label} generation metadata is invalid")
expected_actions = [] if actions == "-" else actions.split(",")
if document.get("available_actions") != expected_actions:
    raise SystemExit("route-transfer actions are not fail-closed")
timestamp = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
if not isinstance(document.get("started_at"), str) or timestamp.fullmatch(document["started_at"]) is None:
    raise SystemExit("route-transfer start time is not canonical UTC")
if phase == "preparing_target":
    if document.get("promoted_at") is not None or document.get("finished_at") is not None:
        raise SystemExit("prepare document fabricated transition times")
elif phase == "cleaning_source":
    if not isinstance(document.get("promoted_at"), str) or timestamp.fullmatch(document["promoted_at"]) is None or document.get("finished_at") is not None:
        raise SystemExit("promotion document has invalid transition times")
elif phase == "completed":
    if any(not isinstance(document.get(key), str) or timestamp.fullmatch(document[key]) is None for key in ("promoted_at", "finished_at")):
        raise SystemExit("completion document has invalid transition times")
else:
    raise SystemExit("unexpected route-transfer phase in packet proof")
PY
}

assert_route_profile_document() {
  local path="$1"
  local phase="$2"
  local revision="$3"
  local request_id="$4"
  local node_id="$5"
  local original_present="$6"
  local desired_present="$7"
  local ready="$8"
  local actions="$9"

  python3 - "${path}" "${phase}" "${revision}" "${request_id}" \
    "${node_id}" "${original_present}" "${desired_present}" "${ready}" \
    "${actions}" "${routed_subnet}" <<'PY'
import json
import pathlib
import re
import sys

(
    path, phase, revision, request_id, node_id, original_present,
    desired_present, ready, actions, routed_subnet,
) = sys.argv[1:]
document = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
expected_keys = {
    "schema", "network_id", "node_id", "request_id", "phase",
    "original_routed_subnets", "desired_routed_subnets", "additions",
    "removals", "config_revision", "started_at", "promoted_at",
    "finished_at", "owner", "available_actions",
}
node_keys = {
    "node_id", "name", "certificate_generation",
    "applied_certificate_generation", "applied_config_revision",
    "desired_certificate_generation", "ready",
}
if set(document) != expected_keys or document.get("schema") != "mesh-node-route-profile-edit-v1":
    raise SystemExit("route-profile document schema is not exact")
if document.get("node_id") != node_id or document.get("request_id") != request_id or document.get("phase") != phase:
    raise SystemExit("route-profile document identity or phase changed")
if document.get("config_revision") != int(revision):
    raise SystemExit("route-profile document revision changed")
original = [routed_subnet] if original_present == "1" else []
desired = [routed_subnet] if desired_present == "1" else []
additions = [routed_subnet] if desired_present == "1" and original_present == "0" else []
removals = [routed_subnet] if original_present == "1" and desired_present == "0" else []
if document.get("original_routed_subnets") != original or document.get("desired_routed_subnets") != desired:
    raise SystemExit("route-profile exact original or desired prefix set changed")
if document.get("additions") != additions or document.get("removals") != removals:
    raise SystemExit("route-profile prefix differences changed")
owner = document.get("owner")
if not isinstance(owner, dict) or set(owner) != node_keys or owner.get("node_id") != node_id:
    raise SystemExit("route-profile owner status is not exact")
if owner.get("ready") is not (ready == "1"):
    raise SystemExit("route-profile owner readiness is not authoritative")
for key in (
    "certificate_generation", "applied_certificate_generation",
    "applied_config_revision", "desired_certificate_generation",
):
    if not isinstance(owner.get(key), int) or isinstance(owner.get(key), bool) or owner[key] < 0:
        raise SystemExit("route-profile owner generation metadata is invalid")
expected_actions = [] if actions == "-" else actions.split(",")
if document.get("available_actions") != expected_actions:
    raise SystemExit("route-profile actions are not fail-closed")
timestamp = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
if not isinstance(document.get("started_at"), str) or timestamp.fullmatch(document["started_at"]) is None:
    raise SystemExit("route-profile start time is not canonical UTC")
if phase == "preparing_owner":
    if document.get("promoted_at") is not None or document.get("finished_at") is not None:
        raise SystemExit("route-profile prepare fabricated transition times")
elif phase == "cleaning_owner":
    if not isinstance(document.get("promoted_at"), str) or timestamp.fullmatch(document["promoted_at"]) is None or document.get("finished_at") is not None:
        raise SystemExit("route-profile cleanup has invalid transition times")
elif phase == "completed":
    if any(not isinstance(document.get(key), str) or timestamp.fullmatch(document[key]) is None for key in ("promoted_at", "finished_at")):
        raise SystemExit("route-profile completion has invalid transition times")
else:
    raise SystemExit("unexpected route-profile phase in packet proof")
PY
}

assert_ca_rotation_document() {
  local path="$1"
  local phase="$2"
  local revision="$3"
  local converged_nodes="$4"
  local actions="$5"
  local lighthouse_id="$6"
  local member_id="$7"

  python3 - "${path}" "${phase}" "${revision}" "${converged_nodes}" \
    "${actions}" "${lighthouse_id}" "${member_id}" <<'PY'
import json
import pathlib
import re
import sys

path, phase, revision, converged, actions, lighthouse_id, member_id = sys.argv[1:]
document = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
expected_keys = {
    "schema", "network_id", "phase", "current_trust_bundle_sha256",
    "previous_trust_bundle_sha256", "active_ca_certificate_sha256",
    "target_ca_certificate_sha256", "stage_config_revision", "config_revision",
    "config_updated_at", "started_at", "stage_started_at", "active_nodes",
    "converged_nodes", "pending_recovery_replays", "available_actions", "nodes",
}
if set(document) != expected_keys or document.get("schema") != "mesh-network-ca-rotation-v1":
    raise SystemExit("CA rotation document did not have its exact public schema")
if document.get("phase") != phase or document.get("config_revision") != int(revision):
    raise SystemExit("CA rotation document changed phase or revision")
if document.get("active_nodes") != 2 or document.get("converged_nodes") != int(converged):
    raise SystemExit(
        f"CA rotation convergence evidence is not exact for {path}: "
        f"active={document.get('active_nodes')} converged={document.get('converged_nodes')} "
        f"expected=2/{converged}"
    )
if document.get("pending_recovery_replays") != 0 or document.get("available_actions") != ([x for x in actions.split(",") if x]):
    raise SystemExit("CA rotation safety actions are not exact")
if re.fullmatch(r"[0-9a-f]{64}", document.get("current_trust_bundle_sha256", "")) is None:
    raise SystemExit("CA rotation document omitted its current trust digest")
nodes = document.get("nodes")
if not isinstance(nodes, list) or {node.get("node_id") for node in nodes} != {lighthouse_id, member_id}:
    raise SystemExit("CA rotation document omitted or fabricated active nodes")
node_keys = {
    "node_id", "name", "status", "certificate_authority_sha256",
    "certificate_generation", "applied_certificate_generation",
    "applied_config_revision", "converged",
}
if any(set(node) != node_keys or node.get("status") != "active" for node in nodes):
    raise SystemExit("CA rotation node evidence did not have its exact public schema")
PY
}

ca_rotation_action() {
  local action="$1"
  local expected_revision="$2"
  local output="$3"
  local request_path="${work_dir}/ca-rotation-${action}-request.json"

  printf '{"action":"%s","expected_config_revision":%s}\n' \
    "${action}" "${expected_revision}" >"${request_path}"
  api_request POST "/api/v1/networks/${network_id}/ca-rotation" "${output}" "${request_path}"
}

assert_firewall_rollout_document() {
	local path="$1"
	local phase="$2"
	local revision="$3"
	local canary_nodes="$4"
	local converged_canaries="$5"
	local actions="$6"
	local lighthouse_id="$7"
	local member_id="$8"

	python3 - "${path}" "${phase}" "${revision}" "${canary_nodes}" \
		"${converged_canaries}" "${actions}" "${lighthouse_id}" "${member_id}" <<'PY'
import json
import pathlib
import re
import sys

path, phase, revision, canaries, converged, actions, lighthouse_id, member_id = sys.argv[1:]
document = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
expected_keys = {
    "schema", "network_id", "phase", "config_revision", "config_updated_at",
    "stage_config_revision", "started_at", "paused_at", "current_policy_sha256",
    "target_policy_sha256", "target_policy", "active_nodes", "canary_nodes",
    "converged_canaries", "available_actions", "nodes", "last_transition",
    "automatic_rollback_guards",
}
if set(document) != expected_keys or document.get("schema") != "mesh-network-firewall-rollout-v5":
    raise SystemExit("firewall rollout document did not have its exact public schema")
if document.get("automatic_rollback_guards") != ["activation_failed", "target_runtime_stopped"]:
    raise SystemExit("firewall rollout automatic rollback guards are not exact")
if document.get("phase") != phase or document.get("config_revision") != int(revision):
    raise SystemExit("firewall rollout document changed phase or revision")
if document.get("active_nodes") != 2 or document.get("canary_nodes") != int(canaries) or document.get("converged_canaries") != int(converged):
    raise SystemExit("firewall rollout convergence totals are not exact")
if document.get("available_actions") != [value for value in actions.split(",") if value]:
    raise SystemExit("firewall rollout safety actions are not exact")
if re.fullmatch(r"[0-9a-f]{64}", document.get("current_policy_sha256", "")) is None:
    raise SystemExit("firewall rollout omitted the current policy digest")
nodes = document.get("nodes")
node_keys = {
    "node_id", "name", "ip", "role", "canary", "applied_config_revision",
    "applied_config_sha256", "desired_config_sha256", "certificate_generation",
    "applied_certificate_generation", "nebula_running", "agent_status", "converged",
}
if not isinstance(nodes, list) or {node.get("node_id") for node in nodes} != {lighthouse_id, member_id}:
    raise SystemExit("firewall rollout omitted or fabricated active nodes")
if any(set(node) != node_keys for node in nodes):
    raise SystemExit("firewall rollout node evidence did not have its exact public schema")
transition = document.get("last_transition")
if transition is not None and set(transition) != {"action", "at", "reason_code", "node_id"}:
    raise SystemExit("firewall rollout transition evidence did not have its exact public schema")
selected = [node for node in nodes if node.get("canary")]
if phase == "stable":
    if document.get("stage_config_revision") != 0 or document.get("started_at") is not None or document.get("paused_at") is not None or document.get("target_policy_sha256") or document.get("target_policy") is not None or selected:
        raise SystemExit("stable firewall rollout retained transition metadata")
else:
    if [node.get("node_id") for node in selected] != [member_id]:
        raise SystemExit("firewall rollout selected a node other than the exact member canary")
    if document.get("stage_config_revision", 0) < 1 or document.get("started_at") is None or document.get("target_policy_sha256") == document.get("current_policy_sha256"):
        raise SystemExit("firewall rollout transition metadata is invalid")
    target = document.get("target_policy")
    if not isinstance(target, dict) or set(target) != {
        "mode", "renderer_version", "inbound", "outbound", "rendered_firewall",
        "policy_sha256", "effective_nodes",
    }:
        raise SystemExit("firewall rollout target policy schema is not exact")
    if target.get("mode") != "managed" or target.get("renderer_version") != 2:
        raise SystemExit("firewall rollout target renderer is not current")
    if target.get("inbound") != [{"proto": "tcp", "port": "443", "group": "all"}] or target.get("outbound") != [{"proto": "tcp", "port": "443", "host": "any"}]:
        raise SystemExit("firewall rollout target is not the exact restrictive policy")
    if target.get("policy_sha256") != document.get("target_policy_sha256") or not target.get("rendered_firewall"):
        raise SystemExit("firewall rollout target policy digest or rendered policy is invalid")
    effective_nodes = target.get("effective_nodes")
    effective_node_keys = {
        "node_id", "name", "ip", "groups", "inbound", "outbound",
        "rendered_firewall", "sha256",
    }
    if (
        not isinstance(effective_nodes, list)
        or {node.get("node_id") for node in effective_nodes} != {lighthouse_id, member_id}
        or any(set(node) != effective_node_keys for node in effective_nodes)
        or any(node.get("inbound") != target.get("inbound") or node.get("outbound") != target.get("outbound") for node in effective_nodes)
        or any(node.get("rendered_firewall") != target.get("rendered_firewall") or node.get("sha256") != target.get("policy_sha256") for node in effective_nodes)
    ):
        raise SystemExit("firewall rollout target effective-node policy is not exact")
    if sum(node.get("converged") is True for node in selected) != int(converged):
        raise SystemExit("firewall rollout canary evidence does not match its total")
    if phase == "paused":
        if document.get("paused_at") is None or int(converged) != 0:
            raise SystemExit("paused firewall rollout did not clear convergence and record its boundary")
    elif document.get("paused_at") is not None:
        raise SystemExit("active canary retained paused metadata")
PY
}

assert_firewall_auto_rollback_transition() {
	local path="$1"
	local node_id="$2"
	python3 - "${path}" "${node_id}" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
transition = document.get("last_transition")
expected = {
    "action": "auto_rolled_back",
    "reason_code": "canary_config_activation_failed",
    "node_id": sys.argv[2],
}
if not isinstance(transition, dict) or any(transition.get(key) != value for key, value in expected.items()) or not isinstance(transition.get("at"), str):
    raise SystemExit("firewall automatic rollback did not expose exact bounded failure evidence")
PY
}

assert_firewall_runtime_stopped_transition() {
	local path="$1"
	local node_id="$2"
	python3 - "${path}" "${node_id}" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
transition = document.get("last_transition")
expected = {
    "action": "auto_rolled_back",
    "reason_code": "canary_target_runtime_stopped",
    "node_id": sys.argv[2],
}
if not isinstance(transition, dict) or any(transition.get(key) != value for key, value in expected.items()) or not isinstance(transition.get("at"), str):
    raise SystemExit("firewall stopped-runtime rollback did not expose exact bounded health evidence")
PY
}

firewall_rollout_node_field() {
	local path="$1"
	local node_id="$2"
	local field="$3"
	python3 - "${path}" "${node_id}" "${field}" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
matches = [node for node in document.get("nodes", []) if node.get("node_id") == sys.argv[2]]
if len(matches) != 1 or sys.argv[3] not in matches[0] or isinstance(matches[0][sys.argv[3]], (dict, list, bool)):
    raise SystemExit("firewall rollout node field is missing or invalid")
print(matches[0][sys.argv[3]])
PY
}

firewall_rollout_action() {
	local action="$1"
	local expected_revision="$2"
	local output="$3"
	local request_path="${work_dir}/firewall-rollout-${action}-request.json"

	printf '{"action":"%s","expected_config_revision":%s}\n' \
		"${action}" "${expected_revision}" >"${request_path}"
	api_request POST "/api/v1/networks/${network_id}/firewall-rollout" "${output}" "${request_path}"
}

json_field() {
  local path="$1"
  local field="$2"

  python3 - "${path}" "${field}" <<'PY'
import json
import pathlib
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
for part in sys.argv[2].split("."):
    if not isinstance(value, dict) or part not in value:
        raise SystemExit(f"missing JSON field: {sys.argv[2]}")
    value = value[part]
if value is None or isinstance(value, (dict, list, bool)):
    raise SystemExit(f"JSON field is not a scalar: {sys.argv[2]}")
print(value)
PY
}

network_field() {
  local path="$1"
  local network_name="$2"
  local field="$3"

  python3 - "${path}" "${network_name}" "${field}" <<'PY'
import json
import pathlib
import sys

networks = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
matches = [item for item in networks if item.get("name") == sys.argv[2]]
if len(matches) != 1:
    raise SystemExit(f"expected one network named {sys.argv[2]!r}, found {len(matches)}")
if sys.argv[3] not in matches[0]:
    raise SystemExit(f"network field {sys.argv[3]!r} is missing")
value = matches[0][sys.argv[3]]
if value is None or isinstance(value, (dict, list, bool)):
    raise SystemExit(f"network field {sys.argv[3]!r} is not a scalar")
print(value)
PY
}

require_bearer() {
  local value="$1"
  local label="$2"

  [[ "${value}" =~ ^[A-Za-z0-9_-]{43}$ ]] ||
    die "${label} was not a canonical 256-bit bearer"
}

require_id() {
  local value="$1"
  local label="$2"

  [[ "${value}" =~ ^[A-Za-z0-9_-]+$ ]] || die "${label} was not URL-safe"
}

require_positive_integer() {
  local value="$1"
  local label="$2"

  [[ "${value}" =~ ^[0-9]+$ && "${value}" -gt 0 ]] ||
    die "${label} was not a positive integer"
}

require_overlay_ipv4() {
  local value="$1"
  local expected_network="$2"
  local label="$3"

  python3 - "${value}" "${expected_network}" "${label}" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.IPv4Address(sys.argv[1])
    network = ipaddress.IPv4Network(sys.argv[2], strict=True)
except ValueError as exc:
    raise SystemExit(f"{sys.argv[3]} is invalid: {exc}")
if address not in network or address in (network.network_address, network.broadcast_address):
    raise SystemExit(f"{sys.argv[3]} is outside the usable overlay range")
PY
}

enroll_node() {
  local enrollment_token="$1"
  local state_path="$2"
  local output_dir="$3"
  local log_path="$4"

  mkdir -p -- "$(dirname -- "${state_path}")"
  chmod 0700 "$(dirname -- "${state_path}")"
  MESH_ENROLL_TOKEN="${enrollment_token}" \
    "${meshctl}" enroll \
    --server "${server_url}" \
    --state "${state_path}" \
    --output "${output_dir}" \
    --nebula "${nebula}" \
    --nebula-cert "${nebula_cert}" \
    >"${log_path}" 2>&1
}

validate_bundle() {
  local output_dir="$1"
  local label="$2"
  local current="${output_dir}/current"

  [[ -L "${current}" ]] || die "${label} current bundle is not an atomic symlink"
  python3 - "${output_dir}" <<'PY'
import os
import pathlib
import sys

output = pathlib.Path(sys.argv[1])
versions = (output / "versions").resolve(strict=True)
current = (output / "current").resolve(strict=True)
if os.path.commonpath((str(versions), str(current))) != str(versions) or current == versions:
    raise SystemExit("current bundle does not resolve inside immutable versions")
for name in ("ca.crt", "host.crt", "host.key", "host.pub", "config.yml", "config.signed.yml", "metadata.json"):
    path = current / name
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"managed bundle file is missing or unsafe: {name}")
PY
  "${nebula_cert}" verify \
    -ca "${current}/ca.crt" \
    -crt "${current}/host.crt" \
    >>"${work_dir}/bundle-validation.log" 2>&1
  "${nebula}" -test -config "${current}/config.yml" \
    >>"${work_dir}/bundle-validation.log" 2>&1
}

run_validation_agent() {
  local state_path="$1"
  local log_path="$2"
  local status

  # Runtime control is performed explicitly inside the isolated namespace.
  # This agent invocation validates and commits the signed immutable bundle;
  # --fail-open is explicit because --no-reload cannot acknowledge a runtime.
  if "${meshctl}" agent \
    --state "${state_path}" \
    --once \
    --no-reload \
    --fail-open \
    --nebula "${nebula}" \
    --nebula-cert "${nebula_cert}" \
    >"${log_path}" 2>&1; then
    return
  else
    status=$?
  fi
  python3 - "${log_path}" <<'PY' >&2
import pathlib
import re
import sys

lines = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace").splitlines()
message = lines[-1] if lines else "agent exited without a diagnostic"
message = re.sub(r"[A-Za-z0-9_-]{32,}", "[redacted]", message)
print(f"ERROR: validation agent failed: {message}")
PY
  return "${status}"
}

report_ca_rotation_heartbeat() {
  local state_path="$1"
  local log_path="$2"
  local status

	[[ ( "${ca_rotation_smoke}" == "1" || "${firewall_rollout_smoke}" == "1" || "${route_transfer_smoke}" == "1" || "${route_profile_smoke}" == "1" || "${route_ecmp_smoke}" == "1" ) && -x "${ca_rotation_heartbeat_helper}" ]] ||
		die "managed-transition heartbeat helper is unavailable"
  if run_root setpriv --reuid="$(id -u)" --regid="$(id -g)" --init-groups \
    --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all -- \
    "${ca_rotation_heartbeat_helper}" telemetry \
    --state "${state_path}" \
    --nebula "${nebula}" \
    --nebula-cert "${nebula_cert}" \
    >"${log_path}" 2>&1; then
    return
  else
    status=$?
  fi
  python3 - "${log_path}" <<'PY' >&2
import pathlib
import re
import sys

lines = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace").splitlines()
message = lines[-1] if lines else "heartbeat helper exited without a diagnostic"
message = re.sub(r"[A-Za-z0-9_-]{32,}", "[redacted]", message)
print(f"ERROR: managed-transition heartbeat failed: {message}")
PY
  return "${status}"
}

stop_active_probe_helpers() {
  local pid

  for pid in "${active_capture_pid}" "${active_proxy_pid}"; do
    [[ "${pid}" =~ ^[0-9]+$ && "${pid}" -gt 1 ]] || continue
    if kill -0 "${pid}" 2>/dev/null; then
      kill -TERM "${pid}" 2>/dev/null || true
    fi
    wait "${pid}" 2>/dev/null || true
  done
  active_capture_pid=""
  active_proxy_pid=""
}

wait_for_active_probe_helper() {
  local ready_path="$1"
  local pid="$2"
  local label="$3"
  local attempt

  for attempt in {1..100}; do
    if [[ -f "${ready_path}" ]]; then
      return
    fi
    if ! kill -0 "${pid}" 2>/dev/null; then
      wait "${pid}" 2>/dev/null || true
      stop_active_probe_helpers
      die "${label} exited before becoming ready"
    fi
    sleep 0.05
  done
  stop_active_probe_helpers
  die "${label} did not become ready"
}

run_active_probe_cycle() {
  local label="$1"
  local observer_access="$2"
  local probe_namespace="${3:-${member_ns}}"
  local probe_overlay_device="${4:-${member_overlay_device}}"
  local probe_source_ip="${5:-${member_ip}}"
  local probe_nebula_pid="${6:-${member_nebula_pid}}"
  local probe_state="${7:-${member_state}}"
  local capture_output="${work_dir}/active-probe-${label}-capture.json"
  local capture_log="${work_dir}/active-probe-${label}-capture.log"
  local capture_ready="${work_dir}/active-probe-${label}-capture.ready"
  local proxy_ready="${work_dir}/active-probe-${label}-proxy.ready"
  local proxy_log="${work_dir}/active-probe-${label}-proxy.log"
  local agent_log="${work_dir}/active-probe-${label}-agent.log"
  local server_port="${server_url##*:}"
  local agent_status=0
  local -a capture_targets=(--target "${lighthouse_ip}")

  [[ "${active_probe_smoke}" == "1" ]] || die "active probe cycle requested outside active-probe mode"
  [[ "${observer_access}" == "shared" || "${observer_access}" == "unavailable" ]] ||
    die "active probe cycle received an invalid observer mode"
  [[ "${server_port}" =~ ^[0-9]+$ && "${server_port}" -ge 1024 && "${server_port}" -le 65535 ]] ||
    die "active probe cycle could not resolve the control-plane port"
  stop_active_probe_helpers
  rm -f -- "${capture_output}" "${capture_ready}" "${proxy_ready}"
  if [[ "${observer_multilighthouse_smoke}" == "1" ]]; then
    capture_targets+=(--target "${second_lighthouse_ip}")
  fi

  run_root ip netns exec "${probe_namespace}" \
    "${active_probe_capture}" capture \
    --interface "${probe_overlay_device}" \
    --source "${probe_source_ip}" \
    "${capture_targets[@]}" \
    --duration 8s \
    --ready-file "${capture_ready}" \
    >"${capture_output}" 2>"${capture_log}" &
  active_capture_pid=$!

  run_root bash -c '
    set -Eeuo pipefail
    exec 3<>"/dev/tcp/127.0.0.1/${1}"
    exec ip netns exec "$2" "$3" proxy \
      --listen "127.0.0.1:${1}" --backend-fd 3 --ready-file "$4"
  ' mesh-active-proxy "${server_port}" "${probe_namespace}" "${active_probe_capture}" "${proxy_ready}" \
    >"${proxy_log}" 2>&1 &
  active_proxy_pid=$!

  wait_for_active_probe_helper "${capture_ready}" "${active_capture_pid}" "${label} TUN capture"
  wait_for_active_probe_helper "${proxy_ready}" "${active_proxy_pid}" "${label} namespace proxy"

  if [[ "${observer_access}" == "shared" ]]; then
    run_root nsenter --target "${probe_nebula_pid}" --net --mount -- \
      setpriv --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all -- \
      "${active_probe_capture}" telemetry \
      --state "${probe_state}" --nebula "${nebula}" --nebula-cert "${nebula_cert}" \
      >"${agent_log}" 2>&1 || agent_status=$?
  else
    run_root ip netns exec "${probe_namespace}" \
      setpriv --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all -- \
      "${active_probe_capture}" telemetry \
      --state "${probe_state}" --nebula "${nebula}" --nebula-cert "${nebula_cert}" \
      >"${agent_log}" 2>&1 || agent_status=$?
  fi

  if [[ "${agent_status}" != "0" ]]; then
    python3 - "${agent_log}" "${work_dir}" "${probe_source_ip}" "${lighthouse_ip}" "${server_url}" <<'PY' >&2
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
for private in sys.argv[2:]:
    if private:
        text = text.replace(private, "<private>")
text = re.sub(r"\b[A-Za-z0-9_-]{43}\b", "<redacted-bearer>", text)
lines = [line for line in text.splitlines() if line][-8:]
for line in lines:
    print(f"active-probe helper: {line}")
PY
    stop_active_probe_helpers
    die "${label} production telemetry cycle failed (${agent_log##*/})"
  fi
  if ! wait "${active_capture_pid}"; then
    active_capture_pid=""
    stop_active_probe_helpers
    die "${label} TUN capture failed (${capture_log##*/})"
  fi
  active_capture_pid=""
  if ! wait "${active_proxy_pid}"; then
    active_proxy_pid=""
    die "${label} namespace proxy failed (${proxy_log##*/})"
  fi
  active_proxy_pid=""
  # The control plane independently enforces a five-second lifecycle
  # heartbeat interval. The bounded eight-second capture also keeps following
  # proof cycles outside that independent lifecycle rate limit.
}

assert_active_probe_capture() {
  local label="$1"
  local comparison="$2"
  local expected="$3"

  python3 - "${work_dir}/active-probe-${label}-capture.json" "${comparison}" "${expected}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
capture = json.loads(path.read_text(encoding="utf-8"))
if set(capture) != {"echo_requests"} or type(capture["echo_requests"]) is not int or capture["echo_requests"] < 0:
    raise SystemExit("active-probe capture did not return its exact bounded count")
expected = int(sys.argv[3])
if sys.argv[2] == "exact" and capture["echo_requests"] != expected:
    raise SystemExit(f"captured {capture['echo_requests']} echo requests, want exactly {expected}")
if sys.argv[2] == "minimum" and capture["echo_requests"] < expected:
    raise SystemExit(f"captured {capture['echo_requests']} echo requests, want at least {expected}")
if sys.argv[2] not in {"exact", "minimum"}:
    raise SystemExit("invalid active-probe capture comparison")
PY
}

assert_active_probe_projection() {
  local label="$1"
  local expected_state="$2"
  local expected_observation="$3"
  local minimum_attempted="$4"
  local minimum_replied="$5"
  local minimum_sample_age="$6"
  local projected_node_id="${7:-${member_id}}"
  local fleet_path="${work_dir}/active-probe-${label}-fleet.json"
  local health_path="${work_dir}/active-probe-${label}-health.json"

  api_request GET "/api/v1/fleet/runtime-telemetry" "${fleet_path}"
  api_request GET "/api/v1/fleet/health" "${health_path}"
  python3 - \
    "${fleet_path}" "${health_path}" "${projected_node_id}" "${expected_state}" \
    "${expected_observation}" "${minimum_attempted}" "${minimum_replied}" "${minimum_sample_age}" <<'PY'
import json
import pathlib
import sys

fleet_path, health_path = map(pathlib.Path, sys.argv[1:3])
node_id, expected_state, expected_observation = sys.argv[3:6]
minimum_attempted, minimum_replied, minimum_sample_age = map(int, sys.argv[6:9])
fleet_raw = fleet_path.read_text(encoding="utf-8")
health_raw = health_path.read_text(encoding="utf-8")
fleet = json.loads(fleet_raw)
health = json.loads(health_raw)
if fleet.get("schema") != "mesh-runtime-telemetry-fleet-v4":
    raise SystemExit("fleet telemetry did not use schema v4")
records = [record for record in fleet.get("records", []) if record.get("node_id") == node_id]
if len(records) != 1:
    raise SystemExit("fleet telemetry did not contain exactly one member record")
record = records[0]
if expected_observation != "any" and record.get("state") != expected_observation:
    raise SystemExit(f"passive observation is {record.get('state')!r}, want {expected_observation!r}")
probe = record.get("active_probe")
if not isinstance(probe, dict) or set(probe) != {"version", "state", "sample_age_ms", "attempted", "replied", "duration_ms"}:
    raise SystemExit("fleet telemetry did not expose the exact fixed active-probe shape")
if probe.get("version") != 1 or probe.get("state") != expected_state:
    raise SystemExit(f"active-probe state is {probe!r}, want {expected_state!r}")
if probe.get("attempted", -1) < minimum_attempted or probe.get("replied", -1) < minimum_replied:
    raise SystemExit(f"active-probe counts are below the required proof: {probe!r}")
if minimum_sample_age >= 0 and (type(probe.get("sample_age_ms")) is not int or probe["sample_age_ms"] < minimum_sample_age):
    raise SystemExit(f"active-probe sample age did not advance: {probe!r}")
if expected_state in {"not_eligible", "capability_unavailable"} and (probe["attempted"] != 0 or probe["replied"] != 0):
    raise SystemExit(f"non-attempted active-probe state reported packet counts: {probe!r}")
if expected_state == "unavailable" and probe != {
    "version": 1, "state": "unavailable", "sample_age_ms": None,
    "attempted": 0, "replied": 0, "duration_ms": 0,
}:
    raise SystemExit(f"unavailable active-probe result is not exact: {probe!r}")
for forbidden in ("target_ip", "local_ip", "plan_sha256", "nonce", "packet", "socket_error", "process_instance_id"):
    if forbidden in fleet_raw:
        raise SystemExit(f"fleet telemetry exposed forbidden field {forbidden!r}")
nodes = [
    node for network in health.get("networks", [])
    for node in network.get("nodes", []) if node.get("id") == node_id
]
if len(nodes) != 1:
    raise SystemExit("fleet health did not contain exactly one member")
node = nodes[0]
if node.get("lifecycle_status") != "active" or node.get("agent_status") != "healthy" or node.get("nebula_running") is not True:
    raise SystemExit(f"active-probe evidence changed lifecycle state: {node!r}")
if node.get("operational") is not True or node.get("rollout_current") is not True:
    raise SystemExit(f"member lifecycle proof is not independently operational/current: {node!r}")
if node.get("heartbeat_sequence") != record.get("heartbeat_sequence"):
    raise SystemExit("fleet telemetry is not bound to the exact lifecycle heartbeat")
if '"active_probe"' in health_raw:
    raise SystemExit("active-probe evidence leaked into authoritative fleet health")
PY
}

assert_active_probe_sample_age_advanced() {
  local older_label="$1"
  local newer_label="$2"

  python3 - \
    "${work_dir}/active-probe-${older_label}-fleet.json" \
    "${work_dir}/active-probe-${newer_label}-fleet.json" "${member_id}" <<'PY'
import json
import pathlib
import sys

def sample_age(path, node_id):
    fleet = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    records = [record for record in fleet["records"] if record["node_id"] == node_id]
    if len(records) != 1:
        raise SystemExit("could not compare one member active-probe sample")
    return records[0]["active_probe"]["sample_age_ms"]

older = sample_age(sys.argv[1], sys.argv[3])
newer = sample_age(sys.argv[2], sys.argv[3])
if type(older) is not int or type(newer) is not int or newer <= older:
    raise SystemExit(f"cached active-probe sample age did not advance: {older!r} -> {newer!r}")
PY
}

wait_until_active_probe_due() {
  local state_path="${1:-${member_state}}"
  local journal="${state_path}.runtime-probe.json"
  local delay

  [[ -f "${journal}" ]] || return 0
  delay="$(python3 - "${journal}" <<'PY'
import datetime
import json
import pathlib
import sys

journal = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
reserved = datetime.datetime.fromisoformat(journal["reserved_at"].replace("Z", "+00:00"))
remaining = 30.25 - (datetime.datetime.now(datetime.timezone.utc) - reserved).total_seconds()
print(f"{max(0.0, remaining):.3f}")
PY
)"
  python3 - "${delay}" <<'PY'
import sys
delay = float(sys.argv[1])
if delay < 0 or delay > 30.5:
    raise SystemExit("active-probe cadence wait escaped its global bound")
PY
  if [[ "${delay}" != "0.000" ]]; then
    sleep "${delay}"
  fi
}

namespace_has_process() {
  local namespace="$1"
  local pid

  while IFS= read -r pid; do
    if [[ "${pid}" =~ ^[0-9]+$ && "${pid}" -gt 1 ]]; then
      return 0
    fi
  done < <(run_root ip netns pids "${namespace}" 2>/dev/null || true)
  return 1
}

namespace_contains_pid() {
  local namespace="$1"
  local expected_pid="$2"
  local pid

  while IFS= read -r pid; do
    if [[ "${pid}" == "${expected_pid}" ]]; then
      return 0
    fi
  done < <(run_root ip netns pids "${namespace}" 2>/dev/null || true)
  return 1
}

overlay_interface() {
  local namespace="$1"
  local overlay_ip="$2"
  local index interface family cidr remainder

  while read -r index interface family cidr remainder; do
    if [[ "${family}" == "inet" && "${cidr%/*}" == "${overlay_ip}" ]]; then
      interface="${interface%@*}"
      printf '%s\n' "${interface}"
      return 0
    fi
  done < <(run_root ip -n "${namespace}" -o -4 address show 2>/dev/null || true)
  return 1
}

start_nebula() {
  local namespace="$1"
  local config_path="$2"
  local log_path="$3"
  local pid_variable="$4"
	local process_pid_variable="${pid_variable%_launcher_pid}_nebula_pid"
	local process_pid_path="${work_dir}/${process_pid_variable}.pid"
	local attempt process_pid

  : >"${log_path}"
  if [[ "${observer_smoke}" == "1" ]]; then
    rm -f -- "${process_pid_path}"
    "${root_prefix[@]}" ip netns exec "${namespace}" \
      unshare --mount --propagation private -- \
      bash -c '
        set -Eeuo pipefail
        mount -t tmpfs -o mode=0755,nosuid,nodev,noexec tmpfs /run
        install -d -o 0 -g 0 -m 0700 /run/mesh-nebula
        printf "%s\n" "$$" >"$1"
        exec "$2" -config "$3"
      ' mesh-runtime-observer-launch "${process_pid_path}" "${nebula}" "${config_path}" \
      >"${log_path}" 2>&1 &
  else
    "${root_prefix[@]}" ip netns exec "${namespace}" \
      "${nebula}" -config "${config_path}" \
      >"${log_path}" 2>&1 &
  fi
  printf -v "${pid_variable}" '%s' "$!"

  if [[ "${observer_smoke}" != "1" ]]; then
    printf -v "${process_pid_variable}" '%s' ""
    return
  fi
  process_pid=""
  for attempt in {1..100}; do
    if run_root test -f "${process_pid_path}"; then
      process_pid="$(run_root cat -- "${process_pid_path}" 2>/dev/null || true)"
      if [[ "${process_pid}" =~ ^[0-9]+$ && "${process_pid}" -gt 1 ]] &&
        namespace_contains_pid "${namespace}" "${process_pid}"; then
        printf -v "${process_pid_variable}" '%s' "${process_pid}"
        return
      fi
    fi
    if ! run_root kill -0 "${!pid_variable}" 2>/dev/null; then
      break
    fi
    sleep 0.05
  done
  die "${namespace} Nebula did not enter its private runtime mount namespace"
}

single_namespace_process_pid() {
  local namespace="$1"
  local label="$2"
  local pid
  local -a pids=()

  while IFS= read -r pid; do
    [[ "${pid}" =~ ^[0-9]+$ && "${pid}" -gt 1 ]] && pids+=("${pid}")
  done < <(run_root ip netns pids "${namespace}" 2>/dev/null || true)
  (( ${#pids[@]} == 1 )) || die "${label} namespace did not contain exactly one Nebula process"
  printf '%s\n' "${pids[0]}"
}

reload_nebula_for_ca_rotation() {
  local namespace="$1"
  local process_pid="$2"
  local label="$3"
  local attempt

  namespace_contains_pid "${namespace}" "${process_pid}" ||
    die "${label} Nebula process identity changed before CA reload"
  run_root kill -HUP "${process_pid}"
  for attempt in {1..100}; do
    if namespace_contains_pid "${namespace}" "${process_pid}"; then
      sleep 0.05
      return
    fi
    sleep 0.05
  done
  die "${label} Nebula process exited while reloading CA trust"
}

start_ca_rotation_probe() {
  local namespace="$1"
  local nebula_pid="$2"
  local target="$3"
  local log_path="$4"
  local attempt pid

  : >"${log_path}"
  run_root ip netns exec "${namespace}" ping -n -i 0.05 -W 1 "${target}" \
    >"${log_path}" 2>&1 &
  ca_rotation_probe_launcher_pid=$!
  ca_rotation_probe_pid=""
  for attempt in {1..100}; do
    while IFS= read -r pid; do
      if [[ "${pid}" =~ ^[0-9]+$ && "${pid}" -gt 1 && "${pid}" != "${nebula_pid}" ]]; then
        ca_rotation_probe_pid="${pid}"
        return
      fi
    done < <(run_root ip netns pids "${namespace}" 2>/dev/null || true)
    if ! kill -0 "${ca_rotation_probe_launcher_pid}" 2>/dev/null; then
      break
    fi
    sleep 0.05
  done
  die "continuous CA rotation packet probe did not start"
}

stop_and_assert_ca_rotation_probe() {
  local log_path="$1"

  [[ "${ca_rotation_probe_pid}" =~ ^[0-9]+$ && "${ca_rotation_probe_pid}" -gt 1 ]] ||
    die "continuous CA rotation packet probe lost its process identity"
  run_root kill -INT "${ca_rotation_probe_pid}" 2>/dev/null || true
  if [[ -n "${ca_rotation_probe_launcher_pid}" ]]; then
    wait "${ca_rotation_probe_launcher_pid}" 2>/dev/null || true
  fi
  ca_rotation_probe_launcher_pid=""
  ca_rotation_probe_pid=""
  python3 - "${log_path}" <<'PY'
import pathlib
import re
import sys

content = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
match = re.search(r"(\d+) packets transmitted, (\d+) received,.*?([0-9.]+)% packet loss", content)
if match is None:
    raise SystemExit("continuous CA rotation packet probe omitted its summary")
sent, received, loss = int(match.group(1)), int(match.group(2)), float(match.group(3))
if sent < 20 or received != sent or loss != 0:
    raise SystemExit(f"CA rotation packet continuity failed: sent={sent} received={received} loss={loss}")
PY
}

capture_observer_snapshot() {
  local process_pid="$1"
  local network="$2"
  local output_path="$3"
  shift 3
  local lighthouse attempt
  local -a arguments=(--network "${network}")

  [[ "${observer_smoke}" == "1" ]] || die "observer capture was requested outside observer mode"
  [[ "${process_pid}" =~ ^[0-9]+$ && "${process_pid}" -gt 1 ]] ||
    die "observer capture has no live Nebula process identity"
  for lighthouse in "$@"; do
    arguments+=(--lighthouse "${lighthouse}")
  done
  rm -f -- "${output_path}" "${output_path}.tmp"
  for attempt in {1..50}; do
    if run_root nsenter --target "${process_pid}" --mount -- \
      "${observer_probe}" "${arguments[@]}" \
      >"${output_path}.tmp" 2>>"${work_dir}/runtime-observer-probe.log"; then
      mv -- "${output_path}.tmp" "${output_path}"
      return
    fi
    rm -f -- "${output_path}.tmp"
    if ! run_root kill -0 "${process_pid}" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  die "runtime observer did not return an accepted snapshot"
}

assert_initial_observer_snapshots() {
  local member_first="$1"
  local member_second="$2"
  local lighthouse_snapshot="$3"
  local expected_lighthouse="$4"

  python3 - "${member_first}" "${member_second}" "${lighthouse_snapshot}" "${expected_lighthouse}" <<'PY'
import json
import pathlib
import sys

member_first, member_second, lighthouse = [
    json.loads(pathlib.Path(path).read_text(encoding="utf-8")) for path in sys.argv[1:4]
]
expected_lighthouse = sys.argv[4]

def require_active_peer(snapshot, label):
    if snapshot["handshakes"]["completed_total"] < 1:
        raise SystemExit(f"{label} did not record a completed Noise handshake")
    if snapshot["handshakes"]["most_recent_completion_age_ms"] is None:
        raise SystemExit(f"{label} omitted its completed-handshake age")
    peers = snapshot["peers"]
    if peers["established"] != 1 or peers["authenticated_rx_within_2m"] != 1 or peers["authenticated_rx_within_5m"] != 1:
        raise SystemExit(f"{label} did not report its one authenticated, recently receiving peer")
    if peers["oldest_authenticated_rx_age_ms"] is None:
        raise SystemExit(f"{label} omitted authenticated receive freshness")

require_active_peer(member_first, "member observer")
require_active_peer(member_second, "member observer repeat")
require_active_peer(lighthouse, "lighthouse observer")
if member_second["process_instance_id"] != member_first["process_instance_id"]:
    raise SystemExit("two member samples from one process changed process_instance_id")
if member_second["sample_sequence"] != member_first["sample_sequence"] + 1:
    raise SystemExit("member sample_sequence did not advance by exactly one")
member_lighthouses = member_second["lighthouses"]
if (
    member_lighthouses["configured"] != 1
    or member_lighthouses["established"] != 1
    or member_lighthouses["authenticated_rx_within_2m"] != 1
    or member_lighthouses["authenticated_rx_within_5m"] != 1
    or member_lighthouses["most_recent_authenticated_rx_age_ms"] is None
    or member_lighthouses["overflow"] is not False
    or len(member_lighthouses["entries"]) != 1
):
    raise SystemExit("member observer did not report the exact configured lighthouse aggregate")
entry = member_lighthouses["entries"][0]
if (
    entry["vpn_ip"] != expected_lighthouse
    or entry["established"] is not True
    or entry["last_handshake_age_ms"] is None
    or entry["last_authenticated_rx_age_ms"] is None
):
    raise SystemExit("member observer lighthouse entry is incomplete or identifies the wrong peer")
if lighthouse["lighthouses"] != {
    "configured": 0,
    "established": 0,
    "authenticated_rx_within_2m": 0,
    "authenticated_rx_within_5m": 0,
    "most_recent_authenticated_rx_age_ms": None,
    "overflow": False,
    "entries": [],
}:
    raise SystemExit("lighthouse process unexpectedly reported a configured upstream lighthouse")
PY
}

assert_initial_multilighthouse_observer_snapshots() {
  local member_first="$1"
  local member_second="$2"
  local first_lighthouse="$3"
  local second_lighthouse="$4"

  python3 - "${member_first}" "${member_second}" "${first_lighthouse}" "${second_lighthouse}" <<'PY'
import ipaddress
import json
import pathlib
import sys

first, second = [json.loads(pathlib.Path(path).read_text(encoding="utf-8")) for path in sys.argv[1:3]]
expected = sorted(sys.argv[3:5], key=ipaddress.ip_address)

if first["process_instance_id"] != second["process_instance_id"]:
    raise SystemExit("two multi-lighthouse samples crossed a Nebula process boundary")
if second["sample_sequence"] != first["sample_sequence"] + 1:
    raise SystemExit("multi-lighthouse sample sequence did not advance by exactly one")
if second["process_uptime_ms"] < first["process_uptime_ms"]:
    raise SystemExit("multi-lighthouse process uptime moved backwards")
if second["handshakes"]["completed_total"] < 2 or second["handshakes"]["most_recent_completion_age_ms"] is None:
    raise SystemExit("member did not record both completed lighthouse handshakes")
peers = second["peers"]
if (
    peers["established"] != 2
    or peers["authenticated_rx_within_2m"] != 2
    or peers["authenticated_rx_within_5m"] != 2
    or peers["oldest_authenticated_rx_age_ms"] is None
):
    raise SystemExit("member did not report two authenticated, recently receiving peers")
lighthouses = second["lighthouses"]
if (
    lighthouses["configured"] != 2
    or lighthouses["established"] != 2
    or lighthouses["authenticated_rx_within_2m"] != 2
    or lighthouses["authenticated_rx_within_5m"] != 2
    or lighthouses["most_recent_authenticated_rx_age_ms"] is None
    or lighthouses["overflow"] is not False
    or len(lighthouses["entries"]) != 2
):
    raise SystemExit("member observer did not report the exact dual-lighthouse aggregate")
entries = lighthouses["entries"]
if [entry["vpn_ip"] for entry in entries] != expected:
    raise SystemExit("dual-lighthouse entries are not the exact canonical IPv4 order")
for entry in entries:
    if (
        entry["established"] is not True
        or entry["last_handshake_age_ms"] is None
        or entry["last_authenticated_rx_age_ms"] is None
    ):
        raise SystemExit("dual-lighthouse entry lacks authenticated current-tunnel evidence")
PY
}

assert_observer_process_discontinuity() {
  local previous_snapshot="$1"
  local restarted_snapshot="$2"

  python3 - "${previous_snapshot}" "${restarted_snapshot}" <<'PY'
import json
import pathlib
import sys

previous, restarted = [json.loads(pathlib.Path(path).read_text(encoding="utf-8")) for path in sys.argv[1:]]
if previous["process_instance_id"] == restarted["process_instance_id"]:
    raise SystemExit("restarted Nebula reused its observer process_instance_id")
if restarted["sample_sequence"] != 1:
    raise SystemExit("first sample from restarted Nebula did not begin a new sequence")
if restarted["handshakes"]["completed_total"] < 1:
    raise SystemExit("restarted Nebula did not record a fresh completed handshake")
if restarted["peers"]["established"] != 1 or restarted["peers"]["authenticated_rx_within_2m"] != 1:
    raise SystemExit("restarted Nebula did not observe fresh authenticated overlay traffic")
PY
}

observer_snapshot_has_timed_out_tunnel() {
  local snapshot_path="$1"

  python3 - "${snapshot_path}" <<'PY'
import json
import pathlib
import sys

snapshot = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
peers = snapshot["peers"]
lighthouses = snapshot["lighthouses"]
if (
    snapshot["handshakes"]["completed_total"] < 1
    or snapshot["handshakes"]["timed_out_total"] < 1
    or peers["established"] != 0
    or peers["authenticated_rx_within_2m"] != 0
    or peers["authenticated_rx_within_5m"] != 0
    or peers["oldest_authenticated_rx_age_ms"] is not None
    or lighthouses["configured"] != 1
    or lighthouses["established"] != 0
    or lighthouses["authenticated_rx_within_2m"] != 0
    or lighthouses["authenticated_rx_within_5m"] != 0
    or lighthouses["most_recent_authenticated_rx_age_ms"] is None
    or lighthouses["entries"] != []
):
    raise SystemExit(1)
PY
}

wait_for_observer_outage() {
  local process_pid="$1"
  local network="$2"
  local output_path="$3"
  local expected_lighthouse="$4"
  local attempt

  for attempt in {1..36}; do
    capture_observer_snapshot "${process_pid}" "${network}" "${output_path}" "${expected_lighthouse}"
    if observer_snapshot_has_timed_out_tunnel "${output_path}"; then
      return
    fi
    if (( attempt % 6 == 0 )); then
      python3 - "${output_path}" <<'PY'
import json
import pathlib
import sys

snapshot = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
summary = {
    "uptime_ms": snapshot["process_uptime_ms"],
    "handshakes": snapshot["handshakes"],
    "peers": snapshot["peers"],
    "lighthouses": snapshot["lighthouses"],
}
print("observer outage wait:", json.dumps(summary, separators=(",", ":"), sort_keys=True))
PY
    fi
    sleep 5
  done
  die "observer did not report tunnel eviction and a timed-out handshake during the underlay outage"
}

assert_observer_rehandshake_recovered() {
  local baseline_path="$1"
  local outage_path="$2"
  local recovered_path="$3"

  python3 - "${baseline_path}" "${outage_path}" "${recovered_path}" <<'PY'
import json
import pathlib
import sys

baseline, outage, recovered = [
    json.loads(pathlib.Path(path).read_text(encoding="utf-8")) for path in sys.argv[1:]
]
identities = {sample["process_instance_id"] for sample in (baseline, outage, recovered)}
if len(identities) != 1:
    raise SystemExit("outage/recovery samples crossed a Nebula process boundary")
if outage["sample_sequence"] <= baseline["sample_sequence"]:
    raise SystemExit("outage sample did not advance within the original process")
if recovered["sample_sequence"] != outage["sample_sequence"] + 1:
    raise SystemExit("recovery sample did not immediately follow the outage sample")
if recovered["process_uptime_ms"] < outage["process_uptime_ms"]:
    raise SystemExit("recovered sample moved process uptime backwards")
if recovered["handshakes"]["completed_total"] <= outage["handshakes"]["completed_total"]:
    raise SystemExit("recovery did not complete a fresh Noise handshake")
if recovered["handshakes"]["timed_out_total"] < outage["handshakes"]["timed_out_total"]:
    raise SystemExit("recovery moved the timed-out handshake counter backwards")
baseline_lighthouse_age = baseline["lighthouses"]["most_recent_authenticated_rx_age_ms"]
outage_lighthouse_age = outage["lighthouses"]["most_recent_authenticated_rx_age_ms"]
if baseline_lighthouse_age is None or outage_lighthouse_age is None or outage_lighthouse_age <= baseline_lighthouse_age:
    raise SystemExit("host-map eviction did not retain and advance lighthouse receive history")
peers = recovered["peers"]
lighthouses = recovered["lighthouses"]
if (
    peers["established"] != 1
    or peers["authenticated_rx_within_2m"] != 1
    or peers["authenticated_rx_within_5m"] != 1
    or peers["oldest_authenticated_rx_age_ms"] is None
    or peers["oldest_authenticated_rx_age_ms"] >= 10000
    or lighthouses["configured"] != 1
    or lighthouses["established"] != 1
    or lighthouses["authenticated_rx_within_2m"] != 1
    or lighthouses["authenticated_rx_within_5m"] != 1
    or lighthouses["most_recent_authenticated_rx_age_ms"] is None
    or lighthouses["most_recent_authenticated_rx_age_ms"] >= 10000
):
    raise SystemExit("authenticated overlay traffic did not recover the lighthouse freshness aggregate")
PY
}

multilighthouse_snapshot_is_degraded() {
  local snapshot_path="$1"
  local surviving_lighthouse="$2"

  python3 - "${snapshot_path}" "${surviving_lighthouse}" <<'PY'
import json
import pathlib
import sys

snapshot = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
survivor = sys.argv[2]
peers = snapshot["peers"]
lighthouses = snapshot["lighthouses"]
entries = lighthouses["entries"]
if (
    snapshot["handshakes"]["completed_total"] < 2
    or snapshot["handshakes"]["timed_out_total"] < 1
    or peers["established"] != 1
    or peers["authenticated_rx_within_2m"] != 1
    or peers["authenticated_rx_within_5m"] != 1
    or peers["oldest_authenticated_rx_age_ms"] is None
    or lighthouses["configured"] != 2
    or lighthouses["established"] != 1
    or lighthouses["authenticated_rx_within_2m"] != 1
    or lighthouses["authenticated_rx_within_5m"] != 1
    or lighthouses["most_recent_authenticated_rx_age_ms"] is None
    or lighthouses["overflow"] is not False
    or len(entries) != 1
    or entries[0]["vpn_ip"] != survivor
    or entries[0]["established"] is not True
    or entries[0]["last_handshake_age_ms"] is None
    or entries[0]["last_authenticated_rx_age_ms"] is None
):
    raise SystemExit(1)
PY
}

wait_for_multilighthouse_degraded() {
  local process_pid="$1"
  local network="$2"
  local output_path="$3"
  local failed_lighthouse="$4"
  local surviving_lighthouse="$5"
  local attempt

  for attempt in {1..36}; do
    prove_overlay_ping "${member_ns}" "${surviving_lighthouse}" \
      "${work_dir}/multi-surviving-lighthouse-proof.log"
    capture_observer_snapshot "${process_pid}" "${network}" "${output_path}" \
      "${failed_lighthouse}" "${surviving_lighthouse}"
    if multilighthouse_snapshot_is_degraded "${output_path}" "${surviving_lighthouse}"; then
      return
    fi
    if (( attempt % 6 == 0 )); then
      python3 - "${output_path}" <<'PY'
import json
import pathlib
import sys

snapshot = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
summary = {
    "uptime_ms": snapshot["process_uptime_ms"],
    "handshakes": snapshot["handshakes"],
    "peers": snapshot["peers"],
    "lighthouses": snapshot["lighthouses"],
}
print("multi-lighthouse degraded wait:", json.dumps(summary, separators=(",", ":"), sort_keys=True))
PY
    fi
    sleep 5
  done
  die "observer did not retain one active lighthouse while the other underlay was unavailable"
}

assert_multilighthouse_recovered() {
  local baseline_path="$1"
  local degraded_path="$2"
  local recovered_path="$3"
  local first_lighthouse="$4"
  local second_lighthouse="$5"

  python3 - "${baseline_path}" "${degraded_path}" "${recovered_path}" \
    "${first_lighthouse}" "${second_lighthouse}" <<'PY'
import ipaddress
import json
import pathlib
import sys

baseline, degraded, recovered = [
    json.loads(pathlib.Path(path).read_text(encoding="utf-8")) for path in sys.argv[1:4]
]
expected = sorted(sys.argv[4:6], key=ipaddress.ip_address)
if len({sample["process_instance_id"] for sample in (baseline, degraded, recovered)}) != 1:
    raise SystemExit("multi-lighthouse degradation/recovery crossed a process boundary")
if degraded["sample_sequence"] <= baseline["sample_sequence"]:
    raise SystemExit("degraded multi-lighthouse sample did not advance")
if recovered["sample_sequence"] != degraded["sample_sequence"] + 1:
    raise SystemExit("recovered multi-lighthouse sample was not immediately next")
if not (baseline["process_uptime_ms"] <= degraded["process_uptime_ms"] <= recovered["process_uptime_ms"]):
    raise SystemExit("multi-lighthouse process uptime moved backwards")
if recovered["handshakes"]["completed_total"] <= degraded["handshakes"]["completed_total"]:
    raise SystemExit("restored lighthouse did not complete a fresh handshake")
if recovered["handshakes"]["timed_out_total"] < degraded["handshakes"]["timed_out_total"]:
    raise SystemExit("multi-lighthouse timed-out counter moved backwards")
peers = recovered["peers"]
lighthouses = recovered["lighthouses"]
entries = lighthouses["entries"]
if (
    peers["established"] != 2
    or peers["authenticated_rx_within_2m"] != 2
    or peers["authenticated_rx_within_5m"] != 2
    or peers["oldest_authenticated_rx_age_ms"] is None
    or lighthouses["configured"] != 2
    or lighthouses["established"] != 2
    or lighthouses["authenticated_rx_within_2m"] != 2
    or lighthouses["authenticated_rx_within_5m"] != 2
    or lighthouses["most_recent_authenticated_rx_age_ms"] is None
    or lighthouses["most_recent_authenticated_rx_age_ms"] >= 10000
    or lighthouses["overflow"] is not False
    or [entry["vpn_ip"] for entry in entries] != expected
):
    raise SystemExit("restored member did not recover the exact dual-lighthouse aggregate")
PY
}

assert_multisite_topology_readiness() {
  local readiness_path="$1"

  python3 - "${readiness_path}" "${multimember_smoke}" \
    "${first_lighthouse_endpoint_ip}:4242" "${second_lighthouse_endpoint_ip}:4242" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
multimember = sys.argv[2] == "1"
if report.get("schema") != "mesh-network-readiness-v6":
    raise SystemExit("multi-site proof did not receive readiness schema v6")
topology = report.get("checks", {}).get("topology_diversity", {})
expected_topology = {
    "status": "pass",
    "evidence_source": "control_inventory",
    "configured_sites": 3,
    "active_sites": 3,
    "active_nodes": 4 if multimember else 3,
    "assigned_active_nodes": 4 if multimember else 3,
    "active_lighthouses": 2,
    "assigned_active_lighthouses": 2,
    "distinct_lighthouse_failure_domains": 2,
    "required_lighthouse_failure_domains": 2,
}
for key, expected in expected_topology.items():
    if topology.get(key) != expected:
        raise SystemExit(f"multi-site topology {key}={topology.get(key)!r}, expected {expected!r}")
expected_sites = {
    "packet-site-a": ((2, 2, 1, 1, ["packet-domain-a"]) if multimember else (1, 1, 0, 1, ["packet-domain-a"])),
    "packet-site-b": (1, 1, 0, 1, ["packet-domain-b"]),
    "packet-site-c": (1, 1, 1, 0, ["packet-domain-c"]),
}
sites = report.get("sites")
if not isinstance(sites, list) or [site.get("name") for site in sites] != sorted(expected_sites):
    raise SystemExit("multi-site readiness did not expose the exact canonical site groups")
for site in sites:
    expected = expected_sites[site["name"]]
    actual = (
        site.get("configured_nodes"),
        site.get("active_nodes"),
        site.get("active_members"),
        site.get("active_lighthouses"),
        site.get("failure_domains"),
    )
    if actual != expected:
        raise SystemExit(f"multi-site group {site['name']}={actual!r}, expected {expected!r}")
expected_lighthouses = {
    "packet-lighthouse": ("packet-site-a", "packet-domain-a", sys.argv[3]),
    "packet-lighthouse-b": ("packet-site-b", "packet-domain-b", sys.argv[4]),
}
lighthouses = report.get("lighthouses")
if not isinstance(lighthouses, list) or {item.get("name") for item in lighthouses} != set(expected_lighthouses):
    raise SystemExit("multi-site readiness did not expose the exact two lighthouses")
for lighthouse in lighthouses:
    actual = (lighthouse.get("site"), lighthouse.get("failure_domain"), lighthouse.get("public_endpoint"))
    if lighthouse.get("lifecycle_status") != "active" or actual != expected_lighthouses[lighthouse["name"]]:
        raise SystemExit(f"multi-site lighthouse projection changed: {lighthouse!r}")
PY
}

assert_multisite_udp_readiness() {
  local readiness_path="$1"

  assert_multisite_topology_readiness "${readiness_path}"
  python3 - "${readiness_path}" "${multimember_smoke}" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
required_members = 2 if sys.argv[2] == "1" else 1
udp = report.get("checks", {}).get("public_udp_reachability", {})
expected = {
    "status": "pass",
    "evidence_source": "authenticated_member_active_probe",
    "observed_members": required_members,
    "required_members": required_members,
    "verified_lighthouses": 2,
    "required_lighthouses": 2,
    "freshness_window_seconds": 30,
}
for key, value in expected.items():
    if udp.get(key) != value:
        raise SystemExit(f"multi-site public UDP {key}={udp.get(key)!r}, expected {value!r}")
if not isinstance(udp.get("evidence_at"), str):
    raise SystemExit("multi-site public UDP pass omitted its bounded evidence timestamp")
PY
}

assert_same_domain_topology_warning() {
  local readiness_path="$1"

  python3 - "${readiness_path}" "${multimember_smoke}" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
multimember = sys.argv[2] == "1"
if report.get("schema") != "mesh-network-readiness-v6":
    raise SystemExit("same-domain proof did not receive readiness schema v6")
topology = report.get("checks", {}).get("topology_diversity", {})
expected = {
    "status": "warning",
    "evidence_source": "control_inventory",
    "configured_sites": 3,
    "active_sites": 3,
    "active_nodes": 4 if multimember else 3,
    "assigned_active_nodes": 4 if multimember else 3,
    "active_lighthouses": 2,
    "assigned_active_lighthouses": 2,
    "distinct_lighthouse_failure_domains": 1,
    "required_lighthouse_failure_domains": 2,
}
for key, value in expected.items():
    if topology.get(key) != value:
        raise SystemExit(f"same-domain topology {key}={topology.get(key)!r}, expected {value!r}")
lighthouses = {item["name"]: item for item in report.get("lighthouses", [])}
if set(lighthouses) != {"packet-lighthouse", "packet-lighthouse-b"}:
    raise SystemExit("same-domain readiness did not expose the exact lighthouse pair")
if lighthouses["packet-lighthouse"].get("failure_domain") != "packet-domain-a" or lighthouses["packet-lighthouse-b"].get("failure_domain") != "packet-domain-a":
    raise SystemExit("same-domain readiness did not retain the deliberate shared label")
site_b = [site for site in report.get("sites", []) if site.get("name") == "packet-site-b"]
if len(site_b) != 1 or site_b[0].get("failure_domains") != ["packet-domain-a"]:
    raise SystemExit("same-domain site grouping did not expose the deliberate shared label")
PY
}

assert_multisite_failure_domain_loss() {
  local readiness_path="$1"
  local nodes_path="$2"
  local observer_path="$3"
  local failed_lighthouse="$4"
  local surviving_lighthouse="$5"

  assert_multisite_topology_readiness "${readiness_path}"
  python3 - "${readiness_path}" "${nodes_path}" "${observer_path}" \
    "${failed_lighthouse}" "${surviving_lighthouse}" <<'PY'
import json
import pathlib
import sys

readiness = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
nodes_document = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
snapshot = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
failed, survivor = sys.argv[4:6]
nodes = nodes_document if isinstance(nodes_document, list) else nodes_document.get("nodes")
if not isinstance(nodes, list):
    raise SystemExit("authenticated node inventory is not an array")
by_ip = {
    item["ip"]: (item["name"], item["site"], item["failure_domain"], item["status"])
    for item in nodes
}
if by_ip.get(failed) != ("packet-lighthouse", "packet-site-a", "packet-domain-a", "active"):
    raise SystemExit("failed lighthouse was not bound to packet-domain-a")
if by_ip.get(survivor) != ("packet-lighthouse-b", "packet-site-b", "packet-domain-b", "active"):
    raise SystemExit("surviving lighthouse was not bound to packet-domain-b")
projected = {item["name"]: (item["site"], item["failure_domain"]) for item in readiness["lighthouses"]}
if projected != {
    "packet-lighthouse": ("packet-site-a", "packet-domain-a"),
    "packet-lighthouse-b": ("packet-site-b", "packet-domain-b"),
}:
    raise SystemExit("readiness lighthouse placement drifted from authenticated node inventory")
lighthouses = snapshot["lighthouses"]
entries = lighthouses["entries"]
if (
    lighthouses["configured"] != 2
    or lighthouses["established"] != 1
    or lighthouses["authenticated_rx_within_2m"] != 1
    or len(entries) != 1
    or entries[0]["vpn_ip"] != survivor
    or entries[0]["established"] is not True
):
    raise SystemExit("observer did not isolate the declared packet-domain-a loss")
PY
}

multimember_snapshot_is_site_lost() {
  local snapshot_path="$1"

  python3 - "${snapshot_path}" <<'PY'
import json
import pathlib
import sys

snapshot = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
peers = snapshot["peers"]
lighthouses = snapshot["lighthouses"]
if (
    snapshot["handshakes"]["completed_total"] < 2
    or snapshot["handshakes"]["timed_out_total"] < 2
    or peers["established"] != 0
    or peers["authenticated_rx_within_2m"] != 0
    or peers["authenticated_rx_within_5m"] != 0
    or peers["oldest_authenticated_rx_age_ms"] is not None
    or lighthouses["configured"] != 2
    or lighthouses["established"] != 0
    or lighthouses["authenticated_rx_within_2m"] != 0
    or lighthouses["authenticated_rx_within_5m"] != 0
    or lighthouses["most_recent_authenticated_rx_age_ms"] is None
    or lighthouses["overflow"] is not False
    or lighthouses["entries"] != []
):
    raise SystemExit(1)
PY
}

wait_for_multimember_site_loss() {
  local process_pid="$1"
  local network="$2"
  local output_path="$3"
  local attempt

  for attempt in {1..36}; do
    capture_observer_snapshot "${process_pid}" "${network}" "${output_path}" \
      "${lighthouse_ip}" "${second_lighthouse_ip}"
    if multimember_snapshot_is_site_lost "${output_path}"; then
      return
    fi
    if (( attempt % 6 == 0 )); then
      python3 - "${output_path}" <<'PY'
import json
import pathlib
import sys

snapshot = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
summary = {
    "uptime_ms": snapshot["process_uptime_ms"],
    "handshakes": snapshot["handshakes"],
    "peers": snapshot["peers"],
    "lighthouses": snapshot["lighthouses"],
}
print("multi-member site-loss wait:", json.dumps(summary, separators=(",", ":"), sort_keys=True))
PY
    fi
    sleep 5
  done
  die "site-local member did not lose both lighthouse tunnels after its whole site was isolated"
}

assert_multimember_site_loss() {
  local readiness_path="$1"
  local nodes_path="$2"
  local surviving_observer_path="$3"
  local failed_observer_path="$4"

  assert_multisite_failure_domain_loss \
    "${readiness_path}" "${nodes_path}" "${surviving_observer_path}" \
    "${lighthouse_ip}" "${second_lighthouse_ip}"
  multimember_snapshot_is_site_lost "${failed_observer_path}"
  python3 - "${nodes_path}" "${second_member_ip}" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
nodes = document if isinstance(document, list) else document.get("nodes")
if not isinstance(nodes, list):
    raise SystemExit("authenticated node inventory is not an array")
site_a = {
    item["name"]: (item["ip"], item["failure_domain"], item["status"])
    for item in nodes if item.get("site") == "packet-site-a"
}
expected = {
    "packet-lighthouse": (next(item["ip"] for item in nodes if item.get("name") == "packet-lighthouse"), "packet-domain-a", "active"),
    "packet-member-b": (sys.argv[2], "packet-domain-a", "active"),
}
if site_a != expected:
    raise SystemExit(f"site-wide loss was not bound to the exact two-node packet-site-a inventory: {site_a!r}")
PY
}

assert_multimember_udp_unknown() {
  local readiness_path="$1"

  assert_multisite_topology_readiness "${readiness_path}"
  python3 - "${readiness_path}" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
udp = report.get("checks", {}).get("public_udp_reachability", {})
expected = {
    "status": "unknown",
    "evidence_source": "not_observed",
    "observed_members": 0,
    "required_members": 2,
    "verified_lighthouses": 0,
    "required_lighthouses": 2,
    "freshness_window_seconds": 30,
    "evidence_at": None,
}
for key, value in expected.items():
    if udp.get(key) != value:
        raise SystemExit(f"site-loss public UDP {key}={udp.get(key)!r}, expected {value!r}")
PY
}

assert_multilighthouse_overflow_snapshot() {
  local snapshot_path="$1"
  local first_lighthouse="$2"
  local second_lighthouse="$3"
  shift 3

  python3 - "${snapshot_path}" "${first_lighthouse}" "${second_lighthouse}" "$@" <<'PY'
import ipaddress
import json
import pathlib
import sys

snapshot = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
live = sorted(sys.argv[2:4], key=ipaddress.ip_address)
configured = set(sys.argv[2:])
if len(configured) != 9:
    raise SystemExit("overflow assertion did not receive nine unique lighthouse addresses")
peers = snapshot["peers"]
lighthouses = snapshot["lighthouses"]
entries = lighthouses["entries"]
if (
    peers["established"] != 2
    or peers["authenticated_rx_within_2m"] != 2
    or peers["authenticated_rx_within_5m"] != 2
    or peers["oldest_authenticated_rx_age_ms"] is None
    or lighthouses["configured"] != 9
    or lighthouses["established"] != 2
    or lighthouses["authenticated_rx_within_2m"] != 2
    or lighthouses["authenticated_rx_within_5m"] != 2
    or lighthouses["most_recent_authenticated_rx_age_ms"] is None
    or lighthouses["overflow"] is not True
    or [entry["vpn_ip"] for entry in entries] != live
):
    raise SystemExit("observer did not report the exact bounded nine-lighthouse overflow aggregate")
for entry in entries:
    if entry["vpn_ip"] not in configured or entry["established"] is not True:
        raise SystemExit("overflow snapshot synthesized or misclassified a lighthouse entry")
    if entry["last_handshake_age_ms"] is None or entry["last_authenticated_rx_age_ms"] is None:
        raise SystemExit("overflow live entry omitted authenticated tunnel evidence")
PY
}

assert_revoked_observer_snapshot() {
  local snapshot_path="$1"

  python3 - "${snapshot_path}" <<'PY'
import json
import pathlib
import sys

snapshot = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if snapshot["sample_sequence"] != 1:
    raise SystemExit("first post-revocation observer sample did not start a new sequence")
if snapshot["handshakes"]["completed_total"] != 0:
    raise SystemExit("blocklisted peer unexpectedly completed a fresh handshake")
if snapshot["peers"] != {
    "established": 0,
    "authenticated_rx_within_2m": 0,
    "authenticated_rx_within_5m": 0,
    "oldest_authenticated_rx_age_ms": None,
}:
    raise SystemExit("post-revocation lighthouse observer retained a peer")
PY
}

wait_for_overlay() {
  local namespace="$1"
  local overlay_ip="$2"
  local label="$3"
  local attempt interface

  for attempt in {1..150}; do
    if ! namespace_has_process "${namespace}"; then
      die "${label} Nebula exited before creating its overlay interface"
    fi
    if interface="$(overlay_interface "${namespace}" "${overlay_ip}")"; then
      [[ -n "${interface}" && "${interface}" != "lo" && "${interface}" != "underlay0" ]] ||
        die "${label} overlay address was assigned to an unsafe interface"
      printf '%s\n' "${interface}"
      return
    fi
    sleep 0.1
  done
  die "${label} Nebula did not create the expected overlay address"
}

assert_overlay_route() {
  local namespace="$1"
  local source_ip="$2"
  local target_ip="$3"
  local overlay_device="$4"
  local label="$5"
  local route_file="${work_dir}/route-${label}.txt"

  run_root ip -n "${namespace}" -o route get "${target_ip}" >"${route_file}" 2>&1
  python3 - "${route_file}" "${source_ip}" "${target_ip}" "${overlay_device}" <<'PY'
import pathlib
import sys

tokens = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace").split()
source, target, device = sys.argv[2:]
if not tokens or tokens[0] != target:
    raise SystemExit("route lookup did not return the requested overlay target")
try:
    actual_device = tokens[tokens.index("dev") + 1]
    actual_source = tokens[tokens.index("src") + 1]
except (ValueError, IndexError):
    raise SystemExit("route lookup omitted its device or source")
if actual_device != device or actual_source != source:
    raise SystemExit(
        f"overlay route used dev={actual_device!r} src={actual_source!r}, "
        f"expected dev={device!r} src={source!r}"
    )
PY
}

wait_for_overlay_ping() {
  local namespace="$1"
  local target_ip="$2"
  local log_path="$3"
  local attempt

  : >"${log_path}"
  for attempt in {1..120}; do
    if run_root ip netns exec "${namespace}" \
      ping -n -c 1 -W 1 "${target_ip}" >>"${log_path}" 2>&1; then
      return
    fi
    sleep 0.5
  done
  die "authenticated overlay ICMP did not establish before the deadline (${log_path##*/})"
}

prove_overlay_ping() {
  local namespace="$1"
  local target_ip="$2"
  local log_path="$3"
  local attempt

  : >"${log_path}"
  for attempt in {1..3}; do
    run_root ip netns exec "${namespace}" \
      ping -n -c 1 -W 1 -w 2 "${target_ip}" >>"${log_path}" 2>&1 ||
      die "established overlay ICMP did not deliver every proof packet"
  done
}

prove_nebula_dns() {
  local namespace="$1"
  local source_ip="$2"
  local server_ip="$3"
  local server_port="$4"
  local query_name="$5"
  local expected_ip="$6"
  local log_path="$7"

  if ! run_root ip netns exec "${namespace}" python3 - \
    "${source_ip}" "${server_ip}" "${server_port}" "${query_name}" "${expected_ip}" \
    >"${log_path}" 2>&1 <<'PY'
import ipaddress
import socket
import struct
import sys
import time

source_ip, server_ip, server_port_text, query_name, expected_ip = sys.argv[1:]
server_port = int(server_port_text)
source = ipaddress.IPv4Address(source_ip)
server = ipaddress.IPv4Address(server_ip)
expected = ipaddress.IPv4Address(expected_ip)
if not 1 <= server_port <= 65535:
    raise SystemExit("DNS proof received an invalid server port")
if not query_name.endswith("."):
    raise SystemExit("DNS proof requires a canonical absolute query name")


def encode_name(name):
    labels = name[:-1].split(".")
    if not labels or any(not label or len(label.encode("ascii")) > 63 for label in labels):
        raise ValueError("invalid DNS query name")
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"


def decode_name(message, offset):
    labels = []
    resume = None
    visited = set()
    while True:
        if offset >= len(message):
            raise ValueError("truncated DNS name")
        length = message[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                raise ValueError("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | message[offset + 1]
            if pointer >= len(message) or pointer in visited:
                raise ValueError("invalid DNS compression pointer")
            visited.add(pointer)
            if resume is None:
                resume = offset + 2
            offset = pointer
            continue
        if length & 0xC0:
            raise ValueError("invalid DNS label encoding")
        offset += 1
        if length == 0:
            return ".".join(labels).lower() + ".", resume if resume is not None else offset
        if length > 63 or offset + length > len(message):
            raise ValueError("invalid DNS label length")
        labels.append(message[offset:offset + length].decode("ascii"))
        offset += length


transaction_id = 0x4D53
question = encode_name(query_name.lower()) + struct.pack("!HH", 1, 1)
request = struct.pack("!HHHHHH", transaction_id, 0, 1, 0, 0, 0) + question
deadline = time.monotonic() + 12
attempts = 0
last_result = "no response"

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    client.bind((str(source), 0))
    client.settimeout(0.75)
    while time.monotonic() < deadline:
        attempts += 1
        client.sendto(request, (str(server), server_port))
        try:
            response, responder = client.recvfrom(4096)
        except TimeoutError:
            last_result = "timeout"
            time.sleep(0.15)
            continue
        if responder != (str(server), server_port):
            raise SystemExit(f"DNS response came from unexpected endpoint {responder!r}")
        if len(response) < 12:
            raise SystemExit("DNS response header was truncated")
        response_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", response[:12])
        if response_id != transaction_id or not flags & 0x8000 or flags & 0x7800:
            raise SystemExit("DNS response changed the transaction, QR bit, or opcode")
        if flags & 0x0200:
            raise SystemExit("DNS response was unexpectedly truncated")
        if qdcount != 1:
            raise SystemExit(f"DNS response returned {qdcount} questions instead of one")
        offset = 12
        returned_name, offset = decode_name(response, offset)
        if offset + 4 > len(response):
            raise SystemExit("DNS response question was truncated")
        returned_type, returned_class = struct.unpack("!HH", response[offset:offset + 4])
        offset += 4
        if returned_name != query_name.lower() or (returned_type, returned_class) != (1, 1):
            raise SystemExit("DNS response changed the exact A/IN question")
        answers = []
        for _ in range(ancount):
            answer_name, offset = decode_name(response, offset)
            if offset + 10 > len(response):
                raise SystemExit("DNS answer header was truncated")
            answer_type, answer_class, ttl, rdlength = struct.unpack("!HHIH", response[offset:offset + 10])
            offset += 10
            if offset + rdlength > len(response):
                raise SystemExit("DNS answer data was truncated")
            answer_data = response[offset:offset + rdlength]
            offset += rdlength
            if answer_name == query_name.lower() and answer_type == 1 and answer_class == 1 and rdlength == 4:
                answers.append(ipaddress.IPv4Address(answer_data))
        rcode = flags & 0x000F
        if rcode == 0 and ancount >= 1 and answers == [expected]:
            print(
                f"verified {query_name} A {expected} from {server}:{server_port} "
                f"using source {source} after {attempts} attempt(s)"
            )
            break
        if rcode in (0, 3) and not answers:
            last_result = f"rcode={rcode} answers={ancount}"
            time.sleep(0.15)
            continue
        raise SystemExit(
            f"DNS response was not the exact expected record: rcode={rcode} "
            f"ancount={ancount} A={answers!r} authority={nscount} additional={arcount}"
        )
    else:
        raise SystemExit(
            f"Nebula DNS did not return {query_name} A {expected} within 12 seconds; "
            f"last result: {last_result}"
        )
PY
  then
    sed -n '1,80p' "${log_path}" >&2 || true
    die "Nebula lighthouse DNS did not resolve the authenticated member certificate"
  fi
}

assert_public_edge_dnat() {
  local edge_namespace="$1"
  local public_ip="$2"
  local private_ip="$3"
  local label="$4"
  local rules_path="${work_dir}/public-edge-${label}-dnat.txt"

  run_root ip netns exec "${edge_namespace}" \
    nft list chain ip mesh_edge prerouting >"${rules_path}"
  python3 - "${rules_path}" "${public_ip}" "${private_ip}" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
if f"ip daddr {sys.argv[2]} udp dport 4242" not in text or f"dnat to {sys.argv[3]}:4242" not in text:
    raise SystemExit("public edge omitted the exact bounded UDP DNAT rule")
match = re.search(r"counter packets ([0-9]+) bytes ([0-9]+)", text)
if match is None or int(match.group(1)) < 1 or int(match.group(2)) < 1:
    raise SystemExit("public edge DNAT rule did not observe authenticated Nebula traffic")
PY
}

assert_overlay_ping_blocked() {
  local namespace="$1"
  local target_ip="$2"
  local log_path="$3"
  local attempt

  : >"${log_path}"
  for attempt in {1..10}; do
    if run_root ip netns exec "${namespace}" \
      ping -n -c 1 -W 1 -w 2 "${target_ip}" >>"${log_path}" 2>&1; then
      die "overlay ICMP unexpectedly succeeded while policy required it to be blocked (${log_path##*/})"
    fi
    sleep 0.5
  done
}

prove_overlay_tcp_443() {
  local server_namespace="$1"
  local server_ip="$2"
  local expected_client_ip="$3"
  local client_namespace="$4"
  local label="$5"
  local ready_path="${work_dir}/tcp-${label}.ready"
  local server_log="${work_dir}/tcp-${label}-server.log"
  local client_log="${work_dir}/tcp-${label}-client.log"
  local listener_pid attempt ready delivered

  rm -f -- "${ready_path}"
  : >"${server_log}"
  : >"${client_log}"
  run_root ip netns exec "${server_namespace}" \
    python3 - "${server_ip}" "${expected_client_ip}" "${ready_path}" "${label}" \
    >"${server_log}" 2>&1 <<'PY' &
import pathlib
import socket
import sys

server_ip, expected_client_ip, ready_path, label = sys.argv[1:]
request = ("mesh-policy-proof-v1:" + label).encode("ascii")
response = b"accepted:" + request
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((server_ip, 443))
    listener.listen(1)
    listener.settimeout(40)
    pathlib.Path(ready_path).write_text("ready\n", encoding="ascii")
    connection, address = listener.accept()
    with connection:
        connection.settimeout(5)
        if address[0] != expected_client_ip:
            raise SystemExit(f"unexpected overlay client address {address[0]!r}")
        received = connection.recv(4096)
        if received != request:
            raise SystemExit("TCP policy proof received an unexpected request")
        connection.sendall(response)
PY
  listener_pid=$!

  ready=0
  for attempt in {1..100}; do
    if [[ -s "${ready_path}" ]]; then
      ready=1
      break
    fi
    if ! kill -0 "${listener_pid}" 2>/dev/null; then
      wait "${listener_pid}" 2>/dev/null || true
      die "restrictive-policy TCP/443 listener failed before becoming ready (${server_log##*/})"
    fi
    sleep 0.1
  done
  [[ "${ready}" == "1" ]] || die "restrictive-policy TCP/443 listener did not become ready"

  delivered=0
  for attempt in {1..25}; do
    if run_root ip netns exec "${client_namespace}" \
      python3 - "${server_ip}" "${label}" >>"${client_log}" 2>&1 <<'PY'
import socket
import sys

server_ip, label = sys.argv[1:]
request = ("mesh-policy-proof-v1:" + label).encode("ascii")
expected = b"accepted:" + request
with socket.create_connection((server_ip, 443), timeout=1) as connection:
    connection.settimeout(3)
    connection.sendall(request)
    received = connection.recv(4096)
    if received != expected:
        raise SystemExit("TCP policy proof received an unexpected response")
PY
    then
      delivered=1
      break
    fi
    sleep 0.2
  done
  if [[ "${delivered}" != "1" ]]; then
    wait "${listener_pid}" 2>/dev/null || true
    die "restrictive policy did not deliver the explicitly allowed TCP/443 exchange (${client_log##*/})"
  fi
  wait "${listener_pid}" || die "restrictive-policy TCP/443 listener rejected the authenticated overlay peer"
  rm -f -- "${ready_path}"
}

if (( BASH_VERSINFO[0] < 4 )); then
  skip "Bash 4 or newer is required"
fi
if [[ "$(uname -s)" != "Linux" ]]; then
  skip "packet smoke requires Linux network namespaces and /dev/net/tun; no cross-platform packet claim is made"
fi
case "${observer_smoke}" in
  0 | 1) ;;
  *) die "MESH_RUNTIME_OBSERVER_SMOKE must be exactly 0 or 1" ;;
esac
case "${observer_outage_smoke}" in
  0 | 1) ;;
  *) die "MESH_RUNTIME_OBSERVER_OUTAGE_SMOKE must be exactly 0 or 1" ;;
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
case "${active_probe_smoke}" in
  0 | 1) ;;
  *) die "MESH_RUNTIME_ACTIVE_PROBE_SMOKE must be exactly 0 or 1" ;;
esac
case "${ui_guided_smoke}" in
  0 | 1) ;;
  *) die "MESH_UI_GUIDED_SMOKE must be exactly 0 or 1" ;;
esac
case "${unsafe_route_smoke}" in
  0 | 1) ;;
  *) die "MESH_UNSAFE_ROUTE_SMOKE must be exactly 0 or 1" ;;
esac
case "${route_transfer_smoke}" in
  0 | 1) ;;
  *) die "MESH_ROUTE_TRANSFER_SMOKE must be exactly 0 or 1" ;;
esac
case "${route_profile_smoke}" in
  0 | 1) ;;
  *) die "MESH_ROUTE_PROFILE_SMOKE must be exactly 0 or 1" ;;
esac
case "${route_ecmp_smoke}" in
  0 | 1) ;;
  *) die "MESH_ROUTE_ECMP_SMOKE must be exactly 0 or 1" ;;
esac
case "${keep_smoke}" in
  0 | 1) ;;
  *) die "KEEP_MESH_PACKET_SMOKE must be exactly 0 or 1" ;;
esac
case "${dns_smoke}" in
  0 | 1) ;;
  *) die "MESH_NETWORK_DNS_SMOKE must be exactly 0 or 1" ;;
esac
case "${native_dns_smoke}" in
  0 | 1) ;;
  *) die "MESH_NATIVE_DNS_SMOKE must be exactly 0 or 1" ;;
esac
case "${relay_smoke}" in
  0 | 1) ;;
  *) die "MESH_NETWORK_RELAY_SMOKE must be exactly 0 or 1" ;;
esac
case "${ca_rotation_smoke}" in
  0 | 1) ;;
  *) die "MESH_CA_ROTATION_SMOKE must be exactly 0 or 1" ;;
esac
case "${firewall_rollout_smoke}" in
	0 | 1) ;;
	*) die "MESH_FIREWALL_ROLLOUT_SMOKE must be exactly 0 or 1" ;;
esac
if [[ "${observer_outage_smoke}" == "1" && "${observer_smoke}" != "1" ]]; then
  die "MESH_RUNTIME_OBSERVER_OUTAGE_SMOKE requires MESH_RUNTIME_OBSERVER_SMOKE=1"
fi
if [[ "${native_dns_smoke}" == "1" && ( "${dns_smoke}" != "1" || "${ui_guided_smoke}" != "1" ) ]]; then
  die "native split-DNS packet proof requires UI-guided managed DNS"
fi
if [[ "${observer_multilighthouse_smoke}" == "1" && "${observer_smoke}" != "1" ]]; then
  die "MESH_RUNTIME_OBSERVER_MULTILIGHTHOUSE_SMOKE requires MESH_RUNTIME_OBSERVER_SMOKE=1"
fi
if [[ "${observer_multilighthouse_smoke}" == "1" && "${observer_outage_smoke}" == "1" ]]; then
  die "multi-lighthouse and single-lighthouse outage modes are mutually exclusive"
fi
if [[ "${multimember_smoke}" == "1" && ( "${observer_multilighthouse_smoke}" != "1" || "${active_probe_smoke}" != "1" ) ]]; then
  die "multi-member mode requires multi-lighthouse observer and active-probe modes"
fi
if [[ "${public_endpoint_smoke}" == "1" && "${multimember_smoke}" != "1" ]]; then
  die "public-endpoint mode requires multi-member mode"
fi
if [[ "${active_probe_smoke}" == "1" && "${observer_smoke}" != "1" ]]; then
  die "MESH_RUNTIME_ACTIVE_PROBE_SMOKE requires MESH_RUNTIME_OBSERVER_SMOKE=1"
fi
if [[ "${active_probe_smoke}" == "1" && "${observer_outage_smoke}" == "1" ]]; then
  die "active-probe and underlay-outage modes are mutually exclusive"
fi
if [[ "${ui_guided_smoke}" == "1" && "${observer_multilighthouse_smoke}" == "1" ]]; then
  die "UI-guided and multi-lighthouse observer modes are mutually exclusive"
fi
if [[ "${ui_guided_smoke}" == "1" && "${active_probe_smoke}" == "1" ]]; then
  die "UI-guided and active-probe modes are mutually exclusive"
fi
if [[ "${route_transfer_smoke}" == "1" && "${unsafe_route_smoke}" != "1" ]]; then
  die "routed-subnet transfer packet proof requires MESH_UNSAFE_ROUTE_SMOKE=1"
fi
if [[ "${route_transfer_smoke}" == "1" && ( "${ui_guided_smoke}" == "1" || "${observer_smoke}" == "1" || "${multimember_smoke}" == "1" || "${dns_smoke}" == "1" || "${relay_smoke}" == "1" || "${ca_rotation_smoke}" == "1" || "${firewall_rollout_smoke}" == "1" ) ]]; then
  die "routed-subnet transfer packet proof is an isolated API-driven mode"
fi
if [[ "${route_profile_smoke}" == "1" && "${unsafe_route_smoke}" != "1" ]]; then
  die "routed-subnet profile packet proof requires MESH_UNSAFE_ROUTE_SMOKE=1"
fi
if [[ "${route_profile_smoke}" == "1" && ( "${ui_guided_smoke}" == "1" || "${observer_smoke}" == "1" || "${multimember_smoke}" == "1" || "${dns_smoke}" == "1" || "${relay_smoke}" == "1" || "${ca_rotation_smoke}" == "1" || "${firewall_rollout_smoke}" == "1" || "${route_transfer_smoke}" == "1" ) ]]; then
  die "routed-subnet profile packet proof is an isolated API-driven mode"
fi
if [[ "${route_ecmp_smoke}" == "1" && "${unsafe_route_smoke}" != "1" ]]; then
  die "weighted-ECMP packet proof requires MESH_UNSAFE_ROUTE_SMOKE=1"
fi
if [[ "${route_ecmp_smoke}" == "1" && ( "${ui_guided_smoke}" == "1" || "${observer_smoke}" == "1" || "${multimember_smoke}" == "1" || "${dns_smoke}" == "1" || "${relay_smoke}" == "1" || "${ca_rotation_smoke}" == "1" || "${firewall_rollout_smoke}" == "1" || "${route_transfer_smoke}" == "1" || "${route_profile_smoke}" == "1" ) ]]; then
  die "weighted-ECMP packet proof is an isolated API-driven mode"
fi
if [[ "${relay_smoke}" == "1" && "${ui_guided_smoke}" != "1" ]]; then
  die "managed-relay packet proof requires MESH_UI_GUIDED_SMOKE=1"
fi
if [[ "${relay_smoke}" == "1" && ( "${observer_smoke}" == "1" || "${multimember_smoke}" == "1" || "${unsafe_route_smoke}" == "1" || "${dns_smoke}" == "1" ) ]]; then
  die "managed-relay packet proof is an isolated UI-guided mode"
fi
if [[ "${ca_rotation_smoke}" == "1" && "${ui_guided_smoke}" != "1" ]]; then
  die "managed CA rotation packet proof requires MESH_UI_GUIDED_SMOKE=1"
fi
if [[ "${ca_rotation_smoke}" == "1" && ( "${observer_smoke}" == "1" || "${multimember_smoke}" == "1" || "${unsafe_route_smoke}" == "1" || "${dns_smoke}" == "1" || "${relay_smoke}" == "1" ) ]]; then
  die "managed CA rotation packet proof is an isolated UI-guided mode"
fi
if [[ "${firewall_rollout_smoke}" == "1" && "${ui_guided_smoke}" != "1" ]]; then
	die "managed firewall rollout packet proof requires MESH_UI_GUIDED_SMOKE=1"
fi
if [[ "${firewall_rollout_smoke}" == "1" && ( "${observer_smoke}" == "1" || "${multimember_smoke}" == "1" || "${unsafe_route_smoke}" == "1" || "${dns_smoke}" == "1" || "${relay_smoke}" == "1" || "${ca_rotation_smoke}" == "1" ) ]]; then
	die "managed firewall rollout packet proof is an isolated UI-guided mode"
fi
if [[ "${multimember_smoke}" == "1" || "${relay_smoke}" == "1" ]]; then
  second_member_smoke="1"
fi
if [[ "${observer_multilighthouse_smoke}" == "1" || "${route_transfer_smoke}" == "1" || "${route_ecmp_smoke}" == "1" ]]; then
  second_lighthouse_smoke="1"
fi
for prerequisite in python3 curl mktemp chmod rm ip ping uname; do
  command -v -- "${prerequisite}" >/dev/null 2>&1 ||
    skip "required command is unavailable: ${prerequisite}"
done
if [[ "${ca_rotation_smoke}" == "1" || "${firewall_rollout_smoke}" == "1" || "${route_transfer_smoke}" == "1" || "${route_profile_smoke}" == "1" || "${route_ecmp_smoke}" == "1" || "${native_dns_smoke}" == "1" ]]; then
  for prerequisite in go setpriv; do
    command -v -- "${prerequisite}" >/dev/null 2>&1 ||
      skip "managed transition packet proof requires command: ${prerequisite}"
  done
fi
if [[ "${unsafe_route_smoke}" == "1" ]]; then
  command -v sysctl >/dev/null 2>&1 ||
    skip "routed-subnet packet proof requires sysctl"
fi
if [[ "${ui_guided_smoke}" == "1" ]]; then
  for prerequisite in firefox geckodriver; do
    command -v -- "${prerequisite}" >/dev/null 2>&1 ||
      skip "UI-guided packet proof requires command: ${prerequisite}"
  done
  [[ -f "${repo_root}/scripts/ui_guided_author.py" && ! -L "${repo_root}/scripts/ui_guided_author.py" ]] ||
    die "UI-guided browser author is missing or linked"
fi
[[ -c /dev/net/tun ]] ||
  skip "packet smoke requires a usable /dev/net/tun character device"

mesh_server="$(resolve_executable "${mesh_server_candidate}")" ||
  skip "mesh-server is unavailable; run 'make build' or set MESH_SERVER_BIN"
meshctl="$(resolve_executable "${meshctl_candidate}")" ||
  skip "meshctl is unavailable; run 'make build' or set MESHCTL_BIN"
nebula="$(resolve_executable "${nebula_candidate}")" ||
  skip "real nebula is unavailable; install the pinned Nebula 1.10.3 or set NEBULA_BIN"
nebula_cert="$(resolve_executable "${nebula_cert_candidate}")" ||
  skip "real nebula-cert is unavailable; install the pinned Nebula 1.10.3 or set NEBULA_CERT_BIN"
if [[ "${observer_smoke}" == "1" ]]; then
  for prerequisite in bash unshare mount install nsenter stat; do
    command -v -- "${prerequisite}" >/dev/null 2>&1 ||
      skip "runtime-observer packet proof requires command: ${prerequisite}"
  done
  [[ -n "${observer_probe_candidate}" ]] ||
    skip "runtime-observer packet proof requires MESH_RUNTIME_OBSERVER_PROBE_BIN"
  observer_probe="$(resolve_executable "${observer_probe_candidate}")" ||
    skip "runtime-observer smoke probe is unavailable"
fi
if [[ "${active_probe_smoke}" == "1" ]]; then
  for prerequisite in setpriv sysctl; do
    command -v -- "${prerequisite}" >/dev/null 2>&1 ||
      skip "active-probe packet proof requires command: ${prerequisite}"
  done
  [[ -n "${active_probe_capture_candidate}" ]] ||
    skip "active-probe packet proof requires MESH_RUNTIME_ACTIVE_PROBE_CAPTURE_BIN"
  active_probe_capture="$(resolve_executable "${active_probe_capture_candidate}")" ||
    skip "active-probe capture helper is unavailable"
fi
if [[ "${public_endpoint_smoke}" == "1" ]]; then
  command -v nft >/dev/null 2>&1 ||
    skip "public-endpoint packet proof requires nftables"
fi

nebula_version="$("${nebula}" -version 2>&1)" || skip "nebula -version failed"
nebula_version_pinned "${nebula_version}" || skip "packet proof requires exact Nebula 1.10.3"
nebula_cert_version="$("${nebula_cert}" -version 2>&1)" || skip "nebula-cert -version failed"
nebula_version_pinned "${nebula_cert_version}" || skip "packet proof requires exact nebula-cert 1.10.3"
unset nebula_version
unset nebula_cert_version

if (( EUID != 0 )); then
  if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    root_prefix=(sudo -n)
  else
    skip "network namespaces and TUN setup require root or working non-interactive sudo"
  fi
fi

if [[ "${active_probe_smoke}" == "1" && "${EUID}" -ne 0 ]]; then
  exec "${root_prefix[@]}" env \
    MESH_SERVER_BIN="${mesh_server}" \
    MESHCTL_BIN="${meshctl}" \
    NEBULA_BIN="${nebula}" \
    NEBULA_CERT_BIN="${nebula_cert}" \
    MESH_RUNTIME_OBSERVER_SMOKE=1 \
    MESH_RUNTIME_OBSERVER_OUTAGE_SMOKE=0 \
    MESH_RUNTIME_OBSERVER_MULTILIGHTHOUSE_SMOKE="${observer_multilighthouse_smoke}" \
    MESH_RUNTIME_MULTIMEMBER_SMOKE="${multimember_smoke}" \
    MESH_RUNTIME_PUBLIC_ENDPOINT_SMOKE="${public_endpoint_smoke}" \
    MESH_RUNTIME_OBSERVER_PROBE_BIN="${observer_probe}" \
    MESH_RUNTIME_ACTIVE_PROBE_SMOKE=1 \
    MESH_RUNTIME_ACTIVE_PROBE_CAPTURE_BIN="${active_probe_capture}" \
    MESH_UNSAFE_ROUTE_SMOKE="${unsafe_route_smoke}" \
    MESH_NETWORK_DNS_SMOKE="${dns_smoke}" \
    "${repo_root}/scripts/packet-smoke.sh"
fi
if [[ "${active_probe_smoke}" == "1" ]] && ! run_root "${active_probe_capture}" check; then
  skip "active-probe AF_PACKET capture is unavailable with the current root policy"
fi

temp_parent="${TMPDIR:-/tmp}"
[[ -d "${temp_parent}" ]] || die "temporary directory parent does not exist: ${temp_parent}"
work_dir="$(mktemp -d "${temp_parent%/}/mesh-packet-smoke.XXXXXX")"
[[ -d "${work_dir}" && ! -L "${work_dir}" ]] ||
  die "mktemp did not create a real private directory"
chmod 0700 "${work_dir}"
if [[ "${ca_rotation_smoke}" == "1" || "${firewall_rollout_smoke}" == "1" || "${route_transfer_smoke}" == "1" || "${route_profile_smoke}" == "1" || "${route_ecmp_smoke}" == "1" ]]; then
  ca_rotation_heartbeat_helper="${work_dir}/agent-heartbeat-smoke"
  go build -buildvcs=false -trimpath -o "${ca_rotation_heartbeat_helper}" \
    ./internal/nodeagent/probecapture
  chmod 0700 "${ca_rotation_heartbeat_helper}"
fi
if [[ "${native_dns_smoke}" == "1" ]]; then
  native_dns_smoke_binary="${work_dir}/native-dns-smoke.test"
  (
    cd -- "${repo_root}"
    go test -c -o "${native_dns_smoke_binary}" ./internal/nodeagent
  )
  chmod 0700 "${native_dns_smoke_binary}"
fi
if [[ "${active_probe_smoke}" == "1" ]]; then
  active_binary_dir="${work_dir}/active-bin"
  install -d -o 0 -g 0 -m 0700 "${active_binary_dir}"
  install -o 0 -g 0 -m 0755 -- "${nebula}" "${active_binary_dir}/nebula"
  install -o 0 -g 0 -m 0755 -- "${nebula_cert}" "${active_binary_dir}/nebula-cert"
  install -o 0 -g 0 -m 0755 -- "${active_probe_capture}" "${active_binary_dir}/probecapture"
  nebula="${active_binary_dir}/nebula"
  nebula_cert="${active_binary_dir}/nebula-cert"
  active_probe_capture="${active_binary_dir}/probecapture"
fi
server_data="${work_dir}/server"
curl_config="${work_dir}/admin.curlrc"

printf -v suffix '%x' "$$"
probe_ns="meshps-probe-${suffix}"
lighthouse_ns="meshps-lh-${suffix}"
second_lighthouse_ns="meshps-lh2-${suffix}"
member_ns="meshps-member-${suffix}"
second_member_ns="meshps-member2-${suffix}"
routed_host_ns="meshps-route-${suffix}"
first_edge_ns="meshps-edge1-${suffix}"
second_edge_ns="meshps-edge2-${suffix}"
probe_veth_a="mppa${suffix}"
probe_veth_b="mppb${suffix}"
lighthouse_veth="mpsl${suffix}"
member_veth="mpsm${suffix}"
second_lighthouse_veth="mps2l${suffix}"
second_member_veth="mps2m${suffix}"
routed_gateway_veth="mpsrg${suffix}"
routed_host_veth="mpsrh${suffix}"
routed_gateway_peer="mpsgp${suffix}"
routed_target_veth="mpsrt${suffix}"
routed_target_peer="mpstp${suffix}"

if ! run_root ip netns add "${probe_ns}" >"${work_dir}/capability-netns.log" 2>&1; then
  skip "Linux network namespace creation failed; CAP_SYS_ADMIN and a usable /run/netns mount are required"
fi
probe_ns_created=1
if ! run_root ip link add "${probe_veth_a}" type veth peer name "${probe_veth_b}" \
  >"${work_dir}/capability-veth.log" 2>&1; then
  skip "veth creation failed; CAP_NET_ADMIN with veth support is required"
fi
run_root ip link del "${probe_veth_a}" >/dev/null 2>&1
if ! run_root ip netns exec "${probe_ns}" \
  ip tuntap add dev meshptun mode tun >"${work_dir}/capability-tun.log" 2>&1; then
  skip "TUN creation inside a network namespace failed; CAP_NET_ADMIN and usable /dev/net/tun are required"
fi
run_root ip netns exec "${probe_ns}" ip tuntap del dev meshptun mode tun >/dev/null 2>&1
if [[ "${observer_smoke}" == "1" ]] && ! run_root ip netns exec "${probe_ns}" \
  unshare --mount --propagation private -- \
  bash -c 'set -Eeuo pipefail; mount -t tmpfs -o mode=0755,nosuid,nodev,noexec tmpfs /run; install -d -o 0 -g 0 -m 0700 /run/mesh-nebula; test "$(stat -c %u:%g:%a /run/mesh-nebula)" = 0:0:700' \
  >"${work_dir}/capability-runtime-mount.log" 2>&1; then
  skip "private runtime mount creation failed; runtime-observer packet proof requires CAP_SYS_ADMIN"
fi
delete_namespace "${probe_ns}"
probe_ns_created=0

first_lighthouse_endpoint_ip="192.0.2.1"
second_lighthouse_endpoint_ip="198.51.100.1"
if [[ "${public_endpoint_smoke}" == "1" ]]; then
  first_lighthouse_endpoint_ip="203.0.113.10"
  second_lighthouse_endpoint_ip="198.51.100.10"
fi

say "Creating isolated Linux underlay namespaces"
if [[ "${relay_smoke}" == "1" ]]; then
  run_root ip netns add "${lighthouse_ns}"
  lighthouse_ns_created=1
  run_root ip netns add "${member_ns}"
  member_ns_created=1
  run_root ip netns add "${second_member_ns}"
  second_member_ns_created=1
  run_root ip link add "${lighthouse_veth}" type veth peer name "${member_veth}"
  run_root ip link set "${lighthouse_veth}" netns "${lighthouse_ns}"
  run_root ip link set "${member_veth}" netns "${member_ns}"
  run_root ip -n "${lighthouse_ns}" link set "${lighthouse_veth}" name underlay0
  run_root ip -n "${member_ns}" link set "${member_veth}" name underlay0
  run_root ip link add "${second_lighthouse_veth}" type veth peer name "${second_member_veth}"
  run_root ip link set "${second_lighthouse_veth}" netns "${lighthouse_ns}"
  run_root ip link set "${second_member_veth}" netns "${second_member_ns}"
  run_root ip -n "${lighthouse_ns}" link set "${second_lighthouse_veth}" name underlay1
  run_root ip -n "${second_member_ns}" link set "${second_member_veth}" name underlay0
  for namespace in "${lighthouse_ns}" "${member_ns}" "${second_member_ns}"; do
    run_root ip -n "${namespace}" link set lo up
  done
  run_root ip -n "${lighthouse_ns}" address add 192.0.2.1 peer 192.0.2.2 dev underlay0
  run_root ip -n "${lighthouse_ns}" address add 192.0.2.1 peer 192.0.2.3 dev underlay1
  run_root ip -n "${member_ns}" address add 192.0.2.2 peer 192.0.2.1 dev underlay0
  run_root ip -n "${second_member_ns}" address add 192.0.2.3 peer 192.0.2.1 dev underlay0
  run_root ip netns exec "${lighthouse_ns}" sysctl -q -w net.ipv4.ip_forward=0
  for link_spec in "${lighthouse_ns}|underlay0" "${lighthouse_ns}|underlay1" "${member_ns}|underlay0" "${second_member_ns}|underlay0"; do
    IFS='|' read -r namespace interface <<<"${link_spec}"
    run_root ip -n "${namespace}" link set "${interface}" up
  done
  run_root ip netns exec "${member_ns}" ping -n -c 1 -W 2 "${first_lighthouse_endpoint_ip}" \
    >"${work_dir}/underlay-member-relay.log" 2>&1 ||
    die "primary member could not reach the relay underlay"
  run_root ip netns exec "${second_member_ns}" ping -n -c 1 -W 2 "${first_lighthouse_endpoint_ip}" \
    >"${work_dir}/underlay-second-member-relay.log" 2>&1 ||
    die "second member could not reach the relay underlay"
  if run_root ip netns exec "${member_ns}" ping -n -c 1 -W 1 192.0.2.3 \
    >"${work_dir}/forbidden-direct-underlay.log" 2>&1; then
    die "primary member unexpectedly reached the second member directly on the underlay"
  fi
  if run_root ip netns exec "${second_member_ns}" ping -n -c 1 -W 1 192.0.2.2 \
    >"${work_dir}/forbidden-reverse-underlay.log" 2>&1; then
    die "second member unexpectedly reached the primary member directly on the underlay"
  fi
  [[ "$(run_root ip netns exec "${lighthouse_ns}" sysctl -n net.ipv4.ip_forward)" == "0" ]] ||
    die "relay namespace unexpectedly permits IP forwarding"
elif [[ "${multimember_smoke}" == "1" ]]; then
  run_root ip netns add "${lighthouse_ns}"
  lighthouse_ns_created=1
  run_root ip netns add "${second_lighthouse_ns}"
  second_lighthouse_ns_created=1
  run_root ip netns add "${member_ns}"
  member_ns_created=1
  run_root ip netns add "${second_member_ns}"
  second_member_ns_created=1

  attach_multimember_underlay() {
    local first_namespace="$1"
    local first_interface="$2"
    local second_namespace="$3"
    local second_interface="$4"
    local first_link="$5"
    local second_link="$6"

    run_root ip link add "${first_link}" type veth peer name "${second_link}"
    run_root ip link set "${first_link}" netns "${first_namespace}"
    run_root ip link set "${second_link}" netns "${second_namespace}"
    run_root ip -n "${first_namespace}" link set "${first_link}" name "${first_interface}"
    run_root ip -n "${second_namespace}" link set "${second_link}" name "${second_interface}"
    run_root ip -n "${first_namespace}" link set "${first_interface}" up
    run_root ip -n "${second_namespace}" link set "${second_interface}" up
  }

  if [[ "${public_endpoint_smoke}" == "1" ]]; then
    run_root ip netns add "${first_edge_ns}"
    first_edge_ns_created=1
    run_root ip netns add "${second_edge_ns}"
    second_edge_ns_created=1
    attach_multimember_underlay \
      "${lighthouse_ns}" underlay0 "${first_edge_ns}" lan0 "mpal${suffix}" "mpea${suffix}"
    attach_multimember_underlay \
      "${first_edge_ns}" wan0 "${member_ns}" underlay0 "mpe1a${suffix}" "mpa1${suffix}"
    attach_multimember_underlay \
      "${first_edge_ns}" wan1 "${second_member_ns}" underlay0 "mpe2a${suffix}" "mpa2${suffix}"
    attach_multimember_underlay \
      "${second_lighthouse_ns}" underlay0 "${second_edge_ns}" lan0 "mpbl${suffix}" "mpeb${suffix}"
    attach_multimember_underlay \
      "${second_edge_ns}" wan0 "${member_ns}" underlay1 "mpe1b${suffix}" "mpb1${suffix}"
    attach_multimember_underlay \
      "${second_edge_ns}" wan1 "${second_member_ns}" underlay1 "mpe2b${suffix}" "mpb2${suffix}"
    for namespace in "${lighthouse_ns}" "${second_lighthouse_ns}" "${member_ns}" "${second_member_ns}" "${first_edge_ns}" "${second_edge_ns}"; do
      run_root ip -n "${namespace}" link set lo up
    done
    run_root ip -n "${lighthouse_ns}" address add 10.200.10.2 peer 10.200.10.1 dev underlay0
    run_root ip -n "${first_edge_ns}" address add 10.200.10.1 peer 10.200.10.2 dev lan0
    run_root ip -n "${first_edge_ns}" address add 203.0.113.10 peer 203.0.113.20 dev wan0
    run_root ip -n "${first_edge_ns}" address add 203.0.113.10 peer 203.0.113.21 dev wan1
    run_root ip -n "${member_ns}" address add 203.0.113.20 peer 203.0.113.10 dev underlay0
    run_root ip -n "${second_member_ns}" address add 203.0.113.21 peer 203.0.113.10 dev underlay0
    run_root ip -n "${second_lighthouse_ns}" address add 10.200.20.2 peer 10.200.20.1 dev underlay0
    run_root ip -n "${second_edge_ns}" address add 10.200.20.1 peer 10.200.20.2 dev lan0
    run_root ip -n "${second_edge_ns}" address add 198.51.100.10 peer 198.51.100.20 dev wan0
    run_root ip -n "${second_edge_ns}" address add 198.51.100.10 peer 198.51.100.21 dev wan1
    run_root ip -n "${member_ns}" address add 198.51.100.20 peer 198.51.100.10 dev underlay1
    run_root ip -n "${second_member_ns}" address add 198.51.100.21 peer 198.51.100.10 dev underlay1
    run_root ip -n "${lighthouse_ns}" route add default via 10.200.10.1 dev underlay0
    run_root ip -n "${second_lighthouse_ns}" route add default via 10.200.20.1 dev underlay0
    for edge_spec in \
      "${first_edge_ns}|203.0.113.10|10.200.10.2" \
      "${second_edge_ns}|198.51.100.10|10.200.20.2"; do
      IFS='|' read -r edge_namespace edge_public_ip edge_private_ip <<<"${edge_spec}"
      run_root ip netns exec "${edge_namespace}" sysctl -q -w net.ipv4.ip_forward=1
      run_root ip netns exec "${edge_namespace}" nft -f - <<EOF
table ip mesh_edge {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    ip daddr ${edge_public_ip} udp dport 4242 counter dnat to ${edge_private_ip}:4242
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state established,related accept
    ip daddr ${edge_private_ip} udp dport 4242 accept
    ip saddr ${edge_private_ip} meta l4proto udp accept
  }
}
EOF
    done
  else
    attach_multimember_underlay \
      "${lighthouse_ns}" underlay0 "${member_ns}" underlay0 "mpal${suffix}" "mpa1${suffix}"
    attach_multimember_underlay \
      "${lighthouse_ns}" underlay1 "${second_member_ns}" underlay0 "mpal2${suffix}" "mpa2${suffix}"
    attach_multimember_underlay \
      "${second_lighthouse_ns}" underlay0 "${member_ns}" underlay1 "mpbl${suffix}" "mpb1${suffix}"
    attach_multimember_underlay \
      "${second_lighthouse_ns}" underlay1 "${second_member_ns}" underlay1 "mpbl2${suffix}" "mpb2${suffix}"
    for namespace in "${lighthouse_ns}" "${second_lighthouse_ns}" "${member_ns}" "${second_member_ns}"; do
      run_root ip -n "${namespace}" link set lo up
    done
    run_root ip -n "${lighthouse_ns}" address add 192.0.2.1 peer 192.0.2.2 dev underlay0
    run_root ip -n "${lighthouse_ns}" address add 192.0.2.1 peer 192.0.2.3 dev underlay1
    run_root ip -n "${second_lighthouse_ns}" address add 198.51.100.1 peer 198.51.100.2 dev underlay0
    run_root ip -n "${second_lighthouse_ns}" address add 198.51.100.1 peer 198.51.100.3 dev underlay1
    run_root ip -n "${member_ns}" address add 192.0.2.2 peer 192.0.2.1 dev underlay0
    run_root ip -n "${member_ns}" address add 198.51.100.2 peer 198.51.100.1 dev underlay1
    run_root ip -n "${second_member_ns}" address add 192.0.2.3 peer 192.0.2.1 dev underlay0
    run_root ip -n "${second_member_ns}" address add 198.51.100.3 peer 198.51.100.1 dev underlay1
  fi
  run_root ip netns exec "${member_ns}" ping -n -c 1 -W 2 "${first_lighthouse_endpoint_ip}" \
    >"${work_dir}/underlay-member-first-lighthouse.log" 2>&1 ||
    die "primary member could not reach the first lighthouse underlay"
  run_root ip netns exec "${member_ns}" ping -n -c 1 -W 2 "${second_lighthouse_endpoint_ip}" \
    >"${work_dir}/underlay-member-second-lighthouse.log" 2>&1 ||
    die "primary member could not reach the second lighthouse underlay"
  run_root ip netns exec "${second_member_ns}" ping -n -c 1 -W 2 "${first_lighthouse_endpoint_ip}" \
    >"${work_dir}/underlay-second-member-first-lighthouse.log" 2>&1 ||
    die "second member could not reach the first lighthouse underlay"
  run_root ip netns exec "${second_member_ns}" ping -n -c 1 -W 2 "${second_lighthouse_endpoint_ip}" \
    >"${work_dir}/underlay-second-member-second-lighthouse.log" 2>&1 ||
    die "second member could not reach the second lighthouse underlay"
elif [[ "${second_lighthouse_smoke}" == "1" ]]; then
  run_root ip netns add "${lighthouse_ns}"
  lighthouse_ns_created=1
  run_root ip netns add "${member_ns}"
  member_ns_created=1
  run_root ip link add "${lighthouse_veth}" type veth peer name "${member_veth}"
  run_root ip link set "${lighthouse_veth}" netns "${lighthouse_ns}"
  run_root ip link set "${member_veth}" netns "${member_ns}"
  run_root ip -n "${lighthouse_ns}" link set "${lighthouse_veth}" name underlay0
  run_root ip -n "${member_ns}" link set "${member_veth}" name underlay0
  run_root ip -n "${lighthouse_ns}" address add 192.0.2.1/30 dev underlay0
  run_root ip -n "${member_ns}" address add 192.0.2.2/30 dev underlay0
  run_root ip -n "${lighthouse_ns}" link set lo up
  run_root ip -n "${member_ns}" link set lo up
  run_root ip -n "${lighthouse_ns}" link set underlay0 up
  run_root ip -n "${member_ns}" link set underlay0 up
  run_root ip netns add "${second_lighthouse_ns}"
  second_lighthouse_ns_created=1
  run_root ip link add "${second_lighthouse_veth}" type veth peer name "${second_member_veth}"
  run_root ip link set "${second_lighthouse_veth}" netns "${second_lighthouse_ns}"
  run_root ip link set "${second_member_veth}" netns "${member_ns}"
  run_root ip -n "${second_lighthouse_ns}" link set "${second_lighthouse_veth}" name underlay0
  run_root ip -n "${member_ns}" link set "${second_member_veth}" name underlay1
  run_root ip -n "${second_lighthouse_ns}" address add 198.51.100.1/30 dev underlay0
  run_root ip -n "${member_ns}" address add 198.51.100.2/30 dev underlay1
  run_root ip -n "${second_lighthouse_ns}" link set lo up
  run_root ip -n "${second_lighthouse_ns}" link set underlay0 up
  run_root ip -n "${member_ns}" link set underlay1 up
else
  run_root ip netns add "${lighthouse_ns}"
  lighthouse_ns_created=1
  run_root ip netns add "${member_ns}"
  member_ns_created=1
  run_root ip link add "${lighthouse_veth}" type veth peer name "${member_veth}"
  run_root ip link set "${lighthouse_veth}" netns "${lighthouse_ns}"
  run_root ip link set "${member_veth}" netns "${member_ns}"
  run_root ip -n "${lighthouse_ns}" link set "${lighthouse_veth}" name underlay0
  run_root ip -n "${member_ns}" link set "${member_veth}" name underlay0
  run_root ip -n "${lighthouse_ns}" address add 192.0.2.1/30 dev underlay0
  run_root ip -n "${member_ns}" address add 192.0.2.2/30 dev underlay0
  run_root ip -n "${lighthouse_ns}" link set lo up
  run_root ip -n "${member_ns}" link set lo up
  run_root ip -n "${lighthouse_ns}" link set underlay0 up
  run_root ip -n "${member_ns}" link set underlay0 up
fi

if [[ "${unsafe_route_smoke}" == "1" ]]; then
  say "Creating a non-Nebula routed host and isolated gateway LAN"
  run_root ip netns add "${routed_host_ns}"
  routed_host_ns_created=1
  if [[ "${route_transfer_smoke}" == "1" || "${route_ecmp_smoke}" == "1" ]]; then
    routed_host_interface="lan0"
    run_root ip -n "${routed_host_ns}" link add "${routed_host_interface}" type bridge
    run_root ip -n "${routed_host_ns}" link set "${routed_host_interface}" up
    for routed_link in \
      "${routed_gateway_veth}|${routed_gateway_peer}|${lighthouse_ns}|source0" \
      "${routed_target_veth}|${routed_target_peer}|${second_lighthouse_ns}|target0"; do
      IFS='|' read -r gateway_link lan_link gateway_namespace lan_interface <<<"${routed_link}"
      run_root ip link add "${gateway_link}" type veth peer name "${lan_link}"
      run_root ip link set "${gateway_link}" netns "${gateway_namespace}"
      run_root ip link set "${lan_link}" netns "${routed_host_ns}"
      run_root ip -n "${gateway_namespace}" link set "${gateway_link}" name routed0
      run_root ip -n "${gateway_namespace}" link set routed0 up
      run_root ip -n "${routed_host_ns}" link set "${lan_link}" name "${lan_interface}"
      run_root ip -n "${routed_host_ns}" link set "${lan_interface}" master "${routed_host_interface}"
      run_root ip -n "${routed_host_ns}" link set "${lan_interface}" up
    done
    run_root ip netns exec "${second_lighthouse_ns}" sysctl -q -w net.ipv4.ip_forward=0
    run_root ip netns exec "${second_lighthouse_ns}" sysctl -q -w net.ipv4.conf.all.rp_filter=0
    run_root ip netns exec "${second_lighthouse_ns}" sysctl -q -w net.ipv4.conf.routed0.rp_filter=0
  else
    run_root ip link add "${routed_gateway_veth}" type veth peer name "${routed_host_veth}"
    run_root ip link set "${routed_gateway_veth}" netns "${lighthouse_ns}"
    run_root ip link set "${routed_host_veth}" netns "${routed_host_ns}"
    run_root ip -n "${lighthouse_ns}" link set "${routed_gateway_veth}" name routed0
    run_root ip -n "${routed_host_ns}" link set "${routed_host_veth}" name uplink0
    run_root ip -n "${lighthouse_ns}" link set routed0 up
    run_root ip -n "${routed_host_ns}" link set uplink0 up
  fi
  run_root ip -n "${lighthouse_ns}" address add "${routed_gateway_ip}/24" dev routed0
  run_root ip -n "${routed_host_ns}" address add "${routed_host_ip}/24" dev "${routed_host_interface}"
  run_root ip -n "${routed_host_ns}" link set lo up
  run_root ip -n "${routed_host_ns}" route add 10.88.0.0/24 via "${routed_gateway_ip}" dev "${routed_host_interface}"
  run_root ip netns exec "${lighthouse_ns}" sysctl -q -w net.ipv4.ip_forward=1
  run_root ip netns exec "${lighthouse_ns}" sysctl -q -w net.ipv4.conf.all.rp_filter=0
  run_root ip netns exec "${lighthouse_ns}" sysctl -q -w net.ipv4.conf.routed0.rp_filter=0
fi

say "Starting isolated Mesh control plane"
start_server

admin_token_file="${server_data}/admin.token"
[[ -f "${admin_token_file}" && ! -L "${admin_token_file}" ]] ||
  die "development admin token file was not created safely"
IFS= read -r admin_token <"${admin_token_file}"
require_bearer "${admin_token}" "development admin token"
{
  printf 'silent\n'
  printf 'show-error\n'
  printf 'fail\n'
  printf 'connect-timeout = 2\n'
  printf 'max-time = 30\n'
  printf 'header = "Authorization: Bearer %s"\n' "${admin_token}"
  printf 'header = "Content-Type: application/json"\n'
} >"${curl_config}"
chmod 0600 "${curl_config}"

network_name="packet-smoke"
overlay_cidr="10.88.0.0/24"
dns_port=5353
if [[ "${ui_guided_smoke}" == "1" ]]; then
  say "Authoring the network, lighthouse, and member through the real browser UI"
  ui_guided_started_epoch="$(date -u '+%s')"
  ui_routed_args=()
  if [[ "${unsafe_route_smoke}" == "1" ]]; then
    ui_routed_args=(--lighthouse-routed-subnet "${routed_subnet}")
  fi
  ui_dns_args=()
  if [[ "${dns_smoke}" == "1" ]]; then
    ui_dns_args=(--enable-network-dns --dns-listen-port "${dns_port}")
    if [[ "${native_dns_smoke}" == "1" ]]; then
      ui_dns_args+=(--enable-native-dns --dns-search-domain "${native_dns_domain}")
    fi
  fi
  ui_relay_args=()
  if [[ "${relay_smoke}" == "1" ]]; then
    ui_relay_args=(--enable-network-relays --relay-node-name packet-lighthouse)
  fi
  python3 "${repo_root}/scripts/ui_guided_author.py" \
    --server-url "${server_url}" \
    --admin-token-file "${admin_token_file}" \
    --output-dir "${work_dir}" \
    --network-name "${network_name}" \
    --cidr "${overlay_cidr}" \
    --lighthouse-name packet-lighthouse \
    --lighthouse-endpoint 192.0.2.1:4242 \
    "${ui_routed_args[@]}" \
    "${ui_dns_args[@]}" \
    "${ui_relay_args[@]}" \
    --member-name packet-member \
    --exercise-redundancy-remediation \
    --backup-lighthouse-name packet-lighthouse-backup \
    --backup-lighthouse-endpoint 192.0.2.2:4242 \
    --backup-lighthouse-site packet-site-b \
    --backup-lighthouse-failure-domain packet-domain-b
  unset admin_token
else
  MESH_ADMIN_TOKEN="${admin_token}" \
    "${meshctl}" create-network \
    --server "${server_url}" \
    --name "${network_name}" \
    --cidr "${overlay_cidr}" \
    >"${work_dir}/create-network.log" 2>&1
  unset admin_token
  api_request GET "/api/v1/networks" "${work_dir}/networks.json"
fi

network_id="$(network_field "${work_dir}/networks.json" "${network_name}" id)"
require_id "${network_id}" "network ID"

if [[ "${dns_smoke}" == "1" && "${ui_guided_smoke}" != "1" ]]; then
  dns_initial_revision="$(network_field "${work_dir}/networks.json" "${network_name}" config_revision)"
  require_positive_integer "${dns_initial_revision}" "initial DNS network revision"
  printf '{"expected_config_revision":%s,"enabled":true,"listen_port":%s,"native_resolver":false,"search_domain":""}\n' \
    "${dns_initial_revision}" "${dns_port}" >"${work_dir}/network-dns-update.json"
  api_request PUT "/api/v1/networks/${network_id}/dns" \
    "${work_dir}/network-dns-update-result.json" "${work_dir}/network-dns-update.json"
fi
if [[ "${dns_smoke}" == "1" ]]; then
  api_request GET "/api/v1/networks/${network_id}/dns" \
    "${work_dir}/network-dns-control.json"
  python3 - "${work_dir}/network-dns-control.json" "${network_id}" "${overlay_cidr}" "${dns_port}" "${native_dns_smoke}" "${native_dns_domain}" <<'PY'
import json
import pathlib
import sys

path, network_id, cidr, port, native, domain = sys.argv[1:]
document = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
expected_keys = {
    "schema", "network_id", "network_cidr", "enabled", "listen_port",
    "native_resolver", "search_domain", "firewall_ready", "resolvers",
    "config_revision", "config_updated_at",
}
if set(document) != expected_keys or document.get("schema") != "mesh-network-dns-v1":
    raise SystemExit("network DNS document schema is not exact")
if document.get("network_id") != network_id or document.get("network_cidr") != cidr:
    raise SystemExit("network DNS document identity changed")
if document.get("enabled") is not True or document.get("listen_port") != int(port) or document.get("firewall_ready") is not True:
    raise SystemExit("network DNS was not enabled with complete firewall access")
if document.get("native_resolver") is not (native == "1") or document.get("search_domain") != (domain if native == "1" else ""):
    raise SystemExit("network DNS native resolver state changed")
if document.get("resolvers") != []:
    raise SystemExit("pending network DNS fabricated an active resolver")
PY
fi

if [[ "${ui_guided_smoke}" != "1" ]]; then
  if [[ "${unsafe_route_smoke}" == "1" ]]; then
    printf '{"name":"packet-lighthouse","site":"packet-site-a","failure_domain":"packet-domain-a","role":"lighthouse","public_endpoint":"%s:4242","routed_subnets":["%s"]}\n' \
      "${first_lighthouse_endpoint_ip}" "${routed_subnet}" \
      >"${work_dir}/lighthouse-create.json"
  else
    printf '{"name":"packet-lighthouse","site":"packet-site-a","failure_domain":"packet-domain-a","role":"lighthouse","public_endpoint":"%s:4242"}\n' \
      "${first_lighthouse_endpoint_ip}" \
      >"${work_dir}/lighthouse-create.json"
  fi
fi
if [[ "${second_lighthouse_smoke}" == "1" ]]; then
  printf '{"name":"packet-lighthouse-b","site":"packet-site-b","failure_domain":"packet-domain-b","role":"lighthouse","public_endpoint":"%s:4242"}\n' \
    "${second_lighthouse_endpoint_ip}" \
    >"${work_dir}/second-lighthouse-create.json"
fi
if [[ "${ui_guided_smoke}" != "1" ]]; then
  printf '%s\n' \
    '{"name":"packet-member","site":"packet-site-c","failure_domain":"packet-domain-c","role":"member"}' \
    >"${work_dir}/member-create.json"
fi
if [[ "${second_member_smoke}" == "1" ]]; then
  printf '%s\n' \
    '{"name":"packet-member-b","site":"packet-site-a","failure_domain":"packet-domain-a","role":"member"}' \
    >"${work_dir}/second-member-create.json"
fi

say "Creating and enrolling lighthouse and member identities"
if [[ "${ui_guided_smoke}" != "1" ]]; then
  api_request POST "/api/v1/networks/${network_id}/nodes" \
    "${work_dir}/lighthouse-created.json" "${work_dir}/lighthouse-create.json"
fi
if [[ "${second_lighthouse_smoke}" == "1" ]]; then
  api_request POST "/api/v1/networks/${network_id}/nodes" \
    "${work_dir}/second-lighthouse-created.json" "${work_dir}/second-lighthouse-create.json"
fi
if [[ "${ui_guided_smoke}" != "1" ]]; then
  api_request POST "/api/v1/networks/${network_id}/nodes" \
    "${work_dir}/member-created.json" "${work_dir}/member-create.json"
fi
if [[ "${second_member_smoke}" == "1" ]]; then
  api_request POST "/api/v1/networks/${network_id}/nodes" \
    "${work_dir}/second-member-created.json" "${work_dir}/second-member-create.json"
fi

lighthouse_id="$(json_field "${work_dir}/lighthouse-created.json" node.id)"
member_id="$(json_field "${work_dir}/member-created.json" node.id)"
lighthouse_ip="$(json_field "${work_dir}/lighthouse-created.json" node.ip)"
member_ip="$(json_field "${work_dir}/member-created.json" node.ip)"
lighthouse_enrollment_token="$(json_field "${work_dir}/lighthouse-created.json" enrollment_token)"
member_enrollment_token="$(json_field "${work_dir}/member-created.json" enrollment_token)"
second_lighthouse_id=""
second_lighthouse_ip=""
second_lighthouse_enrollment_token=""
if [[ "${second_lighthouse_smoke}" == "1" ]]; then
  second_lighthouse_id="$(json_field "${work_dir}/second-lighthouse-created.json" node.id)"
  second_lighthouse_ip="$(json_field "${work_dir}/second-lighthouse-created.json" node.ip)"
  second_lighthouse_enrollment_token="$(json_field "${work_dir}/second-lighthouse-created.json" enrollment_token)"
fi
second_member_id=""
second_member_ip=""
second_member_enrollment_token=""
if [[ "${second_member_smoke}" == "1" ]]; then
  second_member_id="$(json_field "${work_dir}/second-member-created.json" node.id)"
  second_member_ip="$(json_field "${work_dir}/second-member-created.json" node.ip)"
  second_member_enrollment_token="$(json_field "${work_dir}/second-member-created.json" enrollment_token)"
fi
require_id "${lighthouse_id}" "lighthouse ID"
require_id "${member_id}" "member ID"
require_overlay_ipv4 "${lighthouse_ip}" "${overlay_cidr}" "lighthouse overlay IP"
require_overlay_ipv4 "${member_ip}" "${overlay_cidr}" "member overlay IP"
require_bearer "${lighthouse_enrollment_token}" "lighthouse enrollment token"
require_bearer "${member_enrollment_token}" "member enrollment token"
[[ "${lighthouse_id}" != "${member_id}" && "${lighthouse_ip}" != "${member_ip}" ]] ||
  die "control plane returned duplicate node identity or address"
if [[ "${second_lighthouse_smoke}" == "1" ]]; then
  require_id "${second_lighthouse_id}" "second lighthouse ID"
  require_overlay_ipv4 "${second_lighthouse_ip}" "${overlay_cidr}" "second lighthouse overlay IP"
  require_bearer "${second_lighthouse_enrollment_token}" "second lighthouse enrollment token"
  [[ "${second_lighthouse_id}" != "${lighthouse_id}" && \
    "${second_lighthouse_id}" != "${member_id}" && \
    "${second_lighthouse_ip}" != "${lighthouse_ip}" && \
    "${second_lighthouse_ip}" != "${member_ip}" ]] ||
    die "control plane returned duplicate multi-lighthouse identity or address"
fi
if [[ "${second_member_smoke}" == "1" ]]; then
  require_id "${second_member_id}" "second member ID"
  require_overlay_ipv4 "${second_member_ip}" "${overlay_cidr}" "second member overlay IP"
  require_bearer "${second_member_enrollment_token}" "second member enrollment token"
  for existing_id in "${lighthouse_id}" "${second_lighthouse_id}" "${member_id}"; do
    [[ "${second_member_id}" != "${existing_id}" ]] ||
      die "control plane reused the second member identity"
  done
  for existing_ip in "${lighthouse_ip}" "${second_lighthouse_ip}" "${member_ip}"; do
    [[ "${second_member_ip}" != "${existing_ip}" ]] ||
      die "control plane reused the second member overlay address"
  done
fi

lighthouse_root="${work_dir}/nodes/lighthouse"
second_lighthouse_root="${work_dir}/nodes/second-lighthouse"
member_root="${work_dir}/nodes/member"
second_member_root="${work_dir}/nodes/second-member"
lighthouse_state="${lighthouse_root}/state.json"
second_lighthouse_state="${second_lighthouse_root}/state.json"
member_state="${member_root}/state.json"
second_member_state="${second_member_root}/state.json"
lighthouse_output="${lighthouse_root}/nebula"
second_lighthouse_output="${second_lighthouse_root}/nebula"
member_output="${member_root}/nebula"
second_member_output="${second_member_root}/nebula"

enroll_node "${lighthouse_enrollment_token}" "${lighthouse_state}" "${lighthouse_output}" \
  "${work_dir}/lighthouse-enroll.log"
unset lighthouse_enrollment_token
if [[ "${second_lighthouse_smoke}" == "1" ]]; then
  enroll_node "${second_lighthouse_enrollment_token}" "${second_lighthouse_state}" "${second_lighthouse_output}" \
    "${work_dir}/second-lighthouse-enroll.log"
  unset second_lighthouse_enrollment_token
fi
enroll_node "${member_enrollment_token}" "${member_state}" "${member_output}" \
  "${work_dir}/member-enroll.log"
unset member_enrollment_token
if [[ "${second_member_smoke}" == "1" ]]; then
  enroll_node "${second_member_enrollment_token}" "${second_member_state}" "${second_member_output}" \
    "${work_dir}/second-member-enroll.log"
  unset second_member_enrollment_token
fi

validate_bundle "${lighthouse_output}" "lighthouse"
if [[ "${second_lighthouse_smoke}" == "1" ]]; then
  validate_bundle "${second_lighthouse_output}" "second lighthouse"
fi
validate_bundle "${member_output}" "member"
if [[ "${second_member_smoke}" == "1" ]]; then
  validate_bundle "${second_member_output}" "second member"
fi
run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-initial.log"
if [[ "${second_lighthouse_smoke}" == "1" ]]; then
  run_validation_agent "${second_lighthouse_state}" "${work_dir}/second-lighthouse-agent-initial.log"
fi
run_validation_agent "${member_state}" "${work_dir}/member-agent-initial.log"
if [[ "${second_member_smoke}" == "1" ]]; then
  run_validation_agent "${second_member_state}" "${work_dir}/second-member-agent-initial.log"
fi
initial_lighthouse_revision="$(json_field "${lighthouse_state}" applied_config_revision)"
initial_second_lighthouse_revision=""
if [[ "${second_lighthouse_smoke}" == "1" ]]; then
  initial_second_lighthouse_revision="$(json_field "${second_lighthouse_state}" applied_config_revision)"
fi
initial_member_revision="$(json_field "${member_state}" applied_config_revision)"
initial_second_member_revision=""
if [[ "${second_member_smoke}" == "1" ]]; then
  initial_second_member_revision="$(json_field "${second_member_state}" applied_config_revision)"
fi
require_positive_integer "${initial_lighthouse_revision}" "initial lighthouse revision"
require_positive_integer "${initial_member_revision}" "initial member revision"
[[ "${initial_lighthouse_revision}" == "${initial_member_revision}" ]] ||
  die "nodes did not converge on the same signed pre-revocation revision"
if [[ "${second_member_smoke}" == "1" ]]; then
  require_positive_integer "${initial_second_member_revision}" "initial second member revision"
  [[ "${initial_second_member_revision}" == "${initial_member_revision}" ]] ||
    die "both members did not converge on one signed revision"
fi
if [[ "${second_lighthouse_smoke}" == "1" ]]; then
  require_positive_integer "${initial_second_lighthouse_revision}" "initial second lighthouse revision"
  [[ "${initial_second_lighthouse_revision}" == "${initial_member_revision}" ]] ||
    die "multi-lighthouse nodes did not converge on one signed revision"
fi
if [[ "${observer_multilighthouse_smoke}" == "1" ]]; then
  api_request GET "/api/v1/networks/${network_id}/readiness" \
    "${work_dir}/multisite-readiness-initial.json"
  assert_multisite_topology_readiness "${work_dir}/multisite-readiness-initial.json"
fi
if [[ "${dns_smoke}" == "1" ]]; then
  api_request GET "/api/v1/networks/${network_id}/dns" \
    "${work_dir}/network-dns-active.json"
  python3 - \
    "${work_dir}/network-dns-active.json" \
    "${lighthouse_output}/current/config.yml" \
    "${member_output}/current/config.yml" \
    "${network_id}" "${lighthouse_id}" "${lighthouse_ip}" "${dns_port}" "${native_dns_smoke}" "${native_dns_domain}" <<'PY'
import json
import pathlib
import sys

document_path, lighthouse_config_path, member_config_path, network_id, lighthouse_id, lighthouse_ip, port, native, domain = sys.argv[1:]
document = json.loads(pathlib.Path(document_path).read_text(encoding="utf-8"))
expected_resolver = {"node_id": lighthouse_id, "name": "packet-lighthouse", "ip": lighthouse_ip}
if document.get("network_id") != network_id or document.get("enabled") is not True or document.get("listen_port") != int(port):
    raise SystemExit("active network DNS document changed identity or settings")
if document.get("native_resolver") is not (native == "1") or document.get("search_domain") != (domain if native == "1" else ""):
    raise SystemExit("active network DNS changed native resolver state")
if document.get("firewall_ready") is not True or document.get("resolvers") != [expected_resolver]:
    raise SystemExit("active network DNS document omitted or fabricated its resolver")
lighthouse_config = pathlib.Path(lighthouse_config_path).read_text(encoding="utf-8")
member_config = pathlib.Path(member_config_path).read_text(encoding="utf-8")
expected_listener = f'  serve_dns: true\n  dns:\n    host: "{lighthouse_ip}"\n    port: {port}\n'
if expected_listener not in lighthouse_config:
    raise SystemExit("lighthouse signed config omitted the exact overlay-only DNS listener")
if "serve_dns:" in member_config or "\n  dns:\n" in member_config:
    raise SystemExit("member signed config was allowed to serve DNS")
PY
fi
if [[ "${relay_smoke}" == "1" ]]; then
  api_request GET "/api/v1/networks/${network_id}/relays" \
    "${work_dir}/network-relays-active.json"
  python3 - \
    "${work_dir}/network-relays-active.json" \
    "${lighthouse_output}/current/config.yml" \
    "${member_output}/current/config.yml" \
    "${second_member_output}/current/config.yml" \
    "${network_id}" "${lighthouse_id}" "${lighthouse_ip}" <<'PY'
import json
import pathlib
import sys

document_path, relay_config_path, member_config_path, second_member_config_path, network_id, relay_id, relay_ip = sys.argv[1:]
document = json.loads(pathlib.Path(document_path).read_text(encoding="utf-8"))
expected_keys = {
    "schema", "network_id", "network_cidr", "enabled", "relay_node_ids",
    "active_relays", "max_relay_nodes", "config_revision", "config_updated_at",
}
expected_active = [{"node_id": relay_id, "name": "packet-lighthouse", "ip": relay_ip, "role": "lighthouse"}]
if set(document) != expected_keys or document.get("schema") != "mesh-network-relays-v1":
    raise SystemExit("network relay document schema is not exact")
if document.get("network_id") != network_id or document.get("enabled") is not True:
    raise SystemExit("active network relay document changed identity or enabled state")
if document.get("relay_node_ids") != [relay_id] or document.get("active_relays") != expected_active or document.get("max_relay_nodes") != 8:
    raise SystemExit("active network relay document omitted or fabricated its selected relay")
relay_config = pathlib.Path(relay_config_path).read_text(encoding="utf-8")
member_configs = [
    pathlib.Path(member_config_path).read_text(encoding="utf-8"),
    pathlib.Path(second_member_config_path).read_text(encoding="utf-8"),
]
if "relay:\n  am_relay: true\n  use_relays: false\n" not in relay_config or "\n  relays:\n" in relay_config:
    raise SystemExit("selected relay config does not have the exact server-only relay policy")
expected_client = f'relay:\n  relays:\n    - "{relay_ip}"\n  am_relay: false\n  use_relays: true\n'
if any(expected_client not in config or "am_relay: true" in config for config in member_configs):
    raise SystemExit("member config does not advertise the exact active relay client policy")
PY
fi
if [[ "${unsafe_route_smoke}" == "1" ]]; then
  "${nebula_cert}" print -json -path "${lighthouse_output}/current/host.crt" \
    >"${work_dir}/routed-gateway-certificate.json"
  python3 - \
    "${work_dir}/routed-gateway-certificate.json" \
    "${lighthouse_output}/current/config.yml" \
    "${member_output}/current/config.yml" \
    "${routed_subnet}" "${lighthouse_ip}" <<'PY'
import json
import pathlib
import sys

certificate_path, gateway_config_path, member_config_path, routed_subnet, gateway_ip = sys.argv[1:]
certificate = json.loads(pathlib.Path(certificate_path).read_text(encoding="utf-8"))
if not isinstance(certificate, list) or len(certificate) != 1:
    raise SystemExit("gateway certificate print did not return exactly one certificate")
if certificate[0].get("details", {}).get("unsafeNetworks") != [routed_subnet]:
    raise SystemExit("gateway certificate does not bind the exact routed subnet")
gateway_config = pathlib.Path(gateway_config_path).read_text(encoding="utf-8")
member_config = pathlib.Path(member_config_path).read_text(encoding="utf-8")
if "unsafe_routes:" in gateway_config or f"local_cidr: {routed_subnet}" not in gateway_config:
    raise SystemExit("gateway config routes to itself or omits explicit routed-destination policy")
route = f'    - route: "{routed_subnet}"\n      via: "{gateway_ip}"\n'
if route not in member_config or f"local_cidr: {routed_subnet}" in member_config:
    raise SystemExit("member config does not carry the exact remote gateway route")
PY
fi

say "Starting real Nebula peers in separate network namespaces"
start_nebula "${lighthouse_ns}" "${lighthouse_output}/current/config.yml" \
  "${work_dir}/lighthouse-nebula.log" lighthouse_launcher_pid
lighthouse_overlay_device="$(wait_for_overlay "${lighthouse_ns}" "${lighthouse_ip}" lighthouse)"
second_lighthouse_overlay_device=""
if [[ "${second_lighthouse_smoke}" == "1" ]]; then
  start_nebula "${second_lighthouse_ns}" "${second_lighthouse_output}/current/config.yml" \
    "${work_dir}/second-lighthouse-nebula.log" second_lighthouse_launcher_pid
  second_lighthouse_overlay_device="$(wait_for_overlay "${second_lighthouse_ns}" "${second_lighthouse_ip}" second-lighthouse)"
fi
start_nebula "${member_ns}" "${member_output}/current/config.yml" \
  "${work_dir}/member-nebula.log" member_launcher_pid
member_overlay_device="$(wait_for_overlay "${member_ns}" "${member_ip}" member)"
second_member_overlay_device=""
if [[ "${second_member_smoke}" == "1" ]]; then
  start_nebula "${second_member_ns}" "${second_member_output}/current/config.yml" \
    "${work_dir}/second-member-nebula.log" second_member_launcher_pid
  second_member_overlay_device="$(wait_for_overlay "${second_member_ns}" "${second_member_ip}" second-member)"
fi

assert_overlay_route "${member_ns}" "${member_ip}" "${lighthouse_ip}" \
  "${member_overlay_device}" member-to-lighthouse-before
assert_overlay_route "${lighthouse_ns}" "${lighthouse_ip}" "${member_ip}" \
  "${lighthouse_overlay_device}" lighthouse-to-member-before
if [[ "${second_lighthouse_smoke}" == "1" ]]; then
  assert_overlay_route "${member_ns}" "${member_ip}" "${second_lighthouse_ip}" \
    "${member_overlay_device}" member-to-second-lighthouse-before
  assert_overlay_route "${second_lighthouse_ns}" "${second_lighthouse_ip}" "${member_ip}" \
    "${second_lighthouse_overlay_device}" second-lighthouse-to-member-before
fi
if [[ "${relay_smoke}" == "1" ]]; then
  assert_overlay_route "${second_member_ns}" "${second_member_ip}" "${lighthouse_ip}" \
    "${second_member_overlay_device}" second-member-to-relay-before
  assert_overlay_route "${lighthouse_ns}" "${lighthouse_ip}" "${second_member_ip}" \
    "${lighthouse_overlay_device}" relay-to-second-member-before
elif [[ "${multimember_smoke}" == "1" ]]; then
  assert_overlay_route "${second_member_ns}" "${second_member_ip}" "${lighthouse_ip}" \
    "${second_member_overlay_device}" second-member-to-lighthouse-before
  assert_overlay_route "${second_member_ns}" "${second_member_ip}" "${second_lighthouse_ip}" \
    "${second_member_overlay_device}" second-member-to-second-lighthouse-before
  assert_overlay_route "${lighthouse_ns}" "${lighthouse_ip}" "${second_member_ip}" \
    "${lighthouse_overlay_device}" lighthouse-to-second-member-before
  assert_overlay_route "${second_lighthouse_ns}" "${second_lighthouse_ip}" "${second_member_ip}" \
    "${second_lighthouse_overlay_device}" second-lighthouse-to-second-member-before
fi
wait_for_overlay_ping "${member_ns}" "${lighthouse_ip}" "${work_dir}/overlay-establish.log"
prove_overlay_ping "${member_ns}" "${lighthouse_ip}" "${work_dir}/overlay-proof.log"
if [[ "${relay_smoke}" == "1" ]]; then
  wait_for_overlay_ping "${second_member_ns}" "${lighthouse_ip}" \
    "${work_dir}/second-member-relay-establish.log"
  prove_overlay_ping "${second_member_ns}" "${lighthouse_ip}" \
    "${work_dir}/second-member-relay-proof.log"
  wait_for_overlay_ping "${member_ns}" "${second_member_ip}" \
    "${work_dir}/forced-relay-forward-establish.log"
  prove_overlay_ping "${member_ns}" "${second_member_ip}" \
    "${work_dir}/forced-relay-forward-proof.log"
  prove_overlay_ping "${second_member_ns}" "${member_ip}" \
    "${work_dir}/forced-relay-reverse-proof.log"
  namespace_has_process "${lighthouse_ns}" || die "relay Nebula exited during forced-relay proof"
  namespace_has_process "${member_ns}" || die "primary member Nebula exited during forced-relay proof"
  namespace_has_process "${second_member_ns}" || die "second member Nebula exited during forced-relay proof"
  say "PASS: browser-managed Nebula relay carried bidirectional member traffic across an underlay with no direct member route"
fi
if [[ "${dns_smoke}" == "1" ]]; then
  prove_nebula_dns "${member_ns}" "${member_ip}" "${lighthouse_ip}" "${dns_port}" \
    "packet-member." "${member_ip}" "${work_dir}/network-dns-proof.log"
  if [[ "${native_dns_smoke}" == "1" ]]; then
    run_root ip netns exec "${member_ns}" env \
      MESH_NATIVE_DNS_SMOKE_PROCESS=1 \
      MESH_NATIVE_DNS_SIGNED_CONFIG="${member_output}/current/config.signed.yml" \
      "${native_dns_smoke_binary}" -test.v -test.run '^TestNativeDNSSmokeProcess$' \
      >"${work_dir}/native-dns-adapter.log" 2>&1 &
    native_dns_proxy_launcher_pid=$!
    native_dns_adapter=""
    for poll in {1..100}; do
      native_dns_adapter="$(sed -n 's/^MESH_NATIVE_DNS_READY=//p' "${work_dir}/native-dns-adapter.log" | tail -n 1)"
      [[ -n "${native_dns_adapter}" ]] && break
      kill -0 "${native_dns_proxy_launcher_pid}" 2>/dev/null || break
      sleep 0.1
    done
    [[ "${native_dns_adapter}" =~ ^${member_ip}:([0-9]+)$ ]] || {
      sed -n '1,120p' "${work_dir}/native-dns-adapter.log" >&2
      die "signed native DNS adapter did not start on the member overlay address"
    }
    native_dns_adapter_port="${BASH_REMATCH[1]}"
    prove_nebula_dns "${member_ns}" "${member_ip}" "${member_ip}" "${native_dns_adapter_port}" \
      "packet-member.${native_dns_domain}." "${member_ip}" "${work_dir}/native-dns-suffix-proof.log"
    run_root ip netns exec "${member_ns}" python3 - \
      "${member_ip}" "${native_dns_adapter_port}" >"${work_dir}/native-dns-isolation-proof.log" <<'PY'
import random
import socket
import struct
import sys

server, port = sys.argv[1], int(sys.argv[2])
transaction = random.SystemRandom().randrange(1, 65536)
name = b"\x07example\x03com\x00"
packet = struct.pack("!HHHHHH", transaction, 0, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    client.bind((server, 0))
    client.settimeout(2)
    client.sendto(packet, (server, port))
    response, responder = client.recvfrom(1232)
if responder != (server, port) or len(response) < 12:
    raise SystemExit("native DNS isolation response endpoint or header is invalid")
identifier, flags, questions, answers, authority, additional = struct.unpack("!HHHHHH", response[:12])
if identifier != transaction or flags & 0x8000 == 0 or flags & 0xF != 2 or questions != 1 or answers != 0:
    raise SystemExit("native DNS adapter did not reject an unrelated public name with SERVFAIL")
print("unrelated DNS name rejected without recursive forwarding")
PY
    say "PASS: signed native split DNS translated the search suffix over Nebula and rejected unrelated recursive traffic"
  fi
  namespace_has_process "${lighthouse_ns}" || die "lighthouse Nebula exited during DNS proof"
  namespace_has_process "${member_ns}" || die "member Nebula exited during DNS proof"
  say "PASS: browser-managed lighthouse DNS returned the authenticated member's exact overlay address"
fi
if [[ "${unsafe_route_smoke}" == "1" ]]; then
  assert_overlay_route "${member_ns}" "${member_ip}" "${routed_host_ip}" \
    "${member_overlay_device}" member-to-routed-host
  wait_for_overlay_ping "${member_ns}" "${routed_host_ip}" \
    "${work_dir}/routed-host-establish.log"
  prove_overlay_ping "${member_ns}" "${routed_host_ip}" \
    "${work_dir}/routed-host-proof.log"
  namespace_has_process "${lighthouse_ns}" || die "gateway Nebula exited during routed-host proof"
  namespace_has_process "${member_ns}" || die "member Nebula exited during routed-host proof"
  say "PASS: certificate-authorized ${routed_subnet} ownership delivered packets through the gateway to a non-Nebula host"
fi
if [[ "${route_ecmp_smoke}" == "1" ]]; then
  say "Proving weighted ECMP, unavailable-gateway fallback, recovery, and route-first leave"
  source_ecmp_pid="$(single_namespace_process_pid "${lighthouse_ns}" ecmp-source)"
  target_ecmp_pid="$(single_namespace_process_pid "${second_lighthouse_ns}" ecmp-target)"
  member_ecmp_pid="$(single_namespace_process_pid "${member_ns}" ecmp-member)"

  run_root ip -n "${second_lighthouse_ns}" address add "${routed_target_ip}/24" dev routed0
  run_root ip netns exec "${second_lighthouse_ns}" sysctl -q -w net.ipv4.ip_forward=1

  ecmp_join_request_id="ecmp-join-packet-${suffix}"
  printf \
    '{"routed_subnets":["%s"],"expected_config_revision":%s,"request_id":"%s"}\n' \
    "${routed_subnet}" "${initial_member_revision}" "${ecmp_join_request_id}" \
    >"${work_dir}/ecmp-join-request.json"
  api_request POST "/api/v1/nodes/${second_lighthouse_id}/route-profile" \
    "${work_dir}/ecmp-join-preparing.json" "${work_dir}/ecmp-join-request.json"
  ecmp_prepare_revision="$(json_field "${work_dir}/ecmp-join-preparing.json" config_revision)"
  (( ecmp_prepare_revision == initial_member_revision + 1 )) ||
    die "ECMP join prepare did not advance exactly one signed revision"
  assert_route_profile_document "${work_dir}/ecmp-join-preparing.json" preparing_owner \
    "${ecmp_prepare_revision}" "${ecmp_join_request_id}" \
    "${second_lighthouse_id}" 0 1 0 cancel

  run_validation_agent "${second_lighthouse_state}" "${work_dir}/ecmp-target-agent-prepare.log"
  run_validation_agent "${lighthouse_state}" "${work_dir}/ecmp-source-agent-prepare.log"
  run_validation_agent "${member_state}" "${work_dir}/ecmp-member-agent-prepare.log"
  validate_bundle "${second_lighthouse_output}" "ECMP prepared target"
  python3 - \
    "${second_lighthouse_output}/current/config.yml" \
    "${member_output}/current/config.yml" \
    "${routed_subnet}" "${lighthouse_ip}" <<'PY'
import pathlib
import sys

target_path, member_path, prefix, source_ip = sys.argv[1:]
target = pathlib.Path(target_path).read_text(encoding="utf-8")
member = pathlib.Path(member_path).read_text(encoding="utf-8")
source_route = f'    - route: "{prefix}"\n      via: "{source_ip}"\n'
if f"local_cidr: {prefix}" not in target or f'route: "{prefix}"' in target:
    raise SystemExit("ECMP target prepare omitted local authorization or installed a loopable peer route")
if source_route not in member or "gateway:" in member:
    raise SystemExit("ECMP target prepare changed the member route before promotion")
PY
  reload_nebula_for_ca_rotation "${second_lighthouse_ns}" "${target_ecmp_pid}" ecmp-target-prepared
  reload_nebula_for_ca_rotation "${lighthouse_ns}" "${source_ecmp_pid}" ecmp-source-prepare
  reload_nebula_for_ca_rotation "${member_ns}" "${member_ecmp_pid}" ecmp-member-unpromoted
  prove_overlay_ping "${second_lighthouse_ns}" "${routed_host_ip}" \
    "${work_dir}/ecmp-target-lan-after-certificate-prepare.log"
  prove_overlay_ping "${member_ns}" "${routed_host_ip}" \
    "${work_dir}/ecmp-source-during-prepare.log"
  sleep 5.1
  report_ca_rotation_heartbeat "${second_lighthouse_state}" \
    "${work_dir}/ecmp-target-heartbeat-prepare.log"
  api_request GET "/api/v1/nodes/${second_lighthouse_id}/route-profile" \
    "${work_dir}/ecmp-join-ready.json"
  assert_route_profile_document "${work_dir}/ecmp-join-ready.json" preparing_owner \
    "${ecmp_prepare_revision}" "${ecmp_join_request_id}" \
    "${second_lighthouse_id}" 0 1 1 advance,cancel

  printf '{"expected_config_revision":%s,"request_id":"%s"}\n' \
    "${ecmp_prepare_revision}" "${ecmp_join_request_id}" \
    >"${work_dir}/ecmp-join-promote-request.json"
  api_request POST "/api/v1/nodes/${second_lighthouse_id}/route-profile/advance" \
    "${work_dir}/ecmp-joined.json" "${work_dir}/ecmp-join-promote-request.json"
  ecmp_joined_revision="$(json_field "${work_dir}/ecmp-joined.json" config_revision)"
  (( ecmp_joined_revision == ecmp_prepare_revision + 1 )) ||
    die "ECMP join promotion did not advance exactly one signed revision"
  assert_route_profile_document "${work_dir}/ecmp-joined.json" completed \
    "${ecmp_joined_revision}" "${ecmp_join_request_id}" \
    "${second_lighthouse_id}" 0 1 0 start

  run_validation_agent "${second_lighthouse_state}" "${work_dir}/ecmp-target-agent-joined.log"
  run_validation_agent "${lighthouse_state}" "${work_dir}/ecmp-source-agent-joined.log"
  run_validation_agent "${member_state}" "${work_dir}/ecmp-member-agent-joined.log"
  reload_nebula_for_ca_rotation "${second_lighthouse_ns}" "${target_ecmp_pid}" ecmp-target-joined
  reload_nebula_for_ca_rotation "${lighthouse_ns}" "${source_ecmp_pid}" ecmp-source-joined
  reload_nebula_for_ca_rotation "${member_ns}" "${member_ecmp_pid}" ecmp-member-joined

  api_request GET "/api/v1/networks/${network_id}/route-policies" \
    "${work_dir}/ecmp-derived-policy.json"
  python3 - \
    "${work_dir}/ecmp-derived-policy.json" "${network_id}" "${routed_subnet}" \
    "${lighthouse_id}" "${second_lighthouse_id}" "${ecmp_joined_revision}" <<'PY'
import json
import pathlib
import sys

path, network_id, prefix, source_id, target_id, revision = sys.argv[1:]
document = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
if set(document) != {"schema", "network_id", "config_revision", "policies", "available_actions"}:
    raise SystemExit("derived route-policy document keys are not exact")
if document.get("schema") != "mesh-network-route-policies-v1" or document.get("network_id") != network_id:
    raise SystemExit("derived route-policy document identity changed")
if document.get("config_revision") != int(revision) or document.get("available_actions") != ["update"]:
    raise SystemExit("derived route-policy revision or actions changed")
policies = document.get("policies")
if not isinstance(policies, list) or len(policies) != 1:
    raise SystemExit("derived route-policy document omitted the exact prefix")
policy = policies[0]
expected_keys = {"prefix", "gateways", "mtu", "metric", "install", "last_request_id", "policy_revision", "updated_at", "available_actions"}
if set(policy) != expected_keys or policy.get("prefix") != prefix or policy.get("install") is not True:
    raise SystemExit("derived route policy is not exact")
if policy.get("mtu") != 0 or policy.get("metric") != 0 or policy.get("last_request_id") != "" or policy.get("policy_revision") != 0 or policy.get("updated_at") is not None:
    raise SystemExit("derived route policy fabricated persisted controls")
if {gateway.get("node_id"): gateway.get("weight") for gateway in policy.get("gateways", [])} != {source_id: 1, target_id: 1}:
    raise SystemExit("derived route policy did not expose both equal-weight owners")
PY

  ecmp_policy_request_id="ecmp-policy-packet-${suffix}"
  printf \
    '{"prefix":"%s","gateways":[{"node_id":"%s","weight":3},{"node_id":"%s","weight":1}],"mtu":1300,"metric":42,"expected_config_revision":%s,"request_id":"%s"}\n' \
    "${routed_subnet}" "${lighthouse_id}" "${second_lighthouse_id}" \
    "${ecmp_joined_revision}" "${ecmp_policy_request_id}" \
    >"${work_dir}/ecmp-policy-update-request.json"
  api_request POST "/api/v1/networks/${network_id}/route-policies" \
    "${work_dir}/ecmp-policy-updated.json" "${work_dir}/ecmp-policy-update-request.json"
  ecmp_policy_revision="$(json_field "${work_dir}/ecmp-policy-updated.json" config_revision)"
  (( ecmp_policy_revision == ecmp_joined_revision + 1 )) ||
    die "ECMP policy update did not advance exactly one signed revision"
  api_request POST "/api/v1/networks/${network_id}/route-policies" \
    "${work_dir}/ecmp-policy-replayed.json" "${work_dir}/ecmp-policy-update-request.json"
  cmp -s "${work_dir}/ecmp-policy-updated.json" "${work_dir}/ecmp-policy-replayed.json" ||
    die "exact ECMP policy response-loss replay changed its authoritative receipt"
  python3 - \
    "${work_dir}/ecmp-policy-updated.json" "${routed_subnet}" \
    "${lighthouse_id}" "${second_lighthouse_id}" "${ecmp_policy_revision}" \
    "${ecmp_policy_request_id}" <<'PY'
import json
import pathlib
import re
import sys

path, prefix, source_id, target_id, revision, request_id = sys.argv[1:]
document = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
policies = document.get("policies")
if document.get("config_revision") != int(revision) or not isinstance(policies, list) or len(policies) != 1:
    raise SystemExit("updated route policy changed revision or prefix cardinality")
policy = policies[0]
if policy.get("prefix") != prefix or policy.get("mtu") != 1300 or policy.get("metric") != 42 or policy.get("install") is not True:
    raise SystemExit("updated route policy omitted exact controls")
if policy.get("last_request_id") != request_id or policy.get("policy_revision") != int(revision):
    raise SystemExit("updated route policy omitted its bound receipt")
if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", policy.get("updated_at", "")) is None:
    raise SystemExit("updated route policy timestamp is not canonical UTC")
if {gateway.get("node_id"): gateway.get("weight") for gateway in policy.get("gateways", [])} != {source_id: 3, target_id: 1}:
    raise SystemExit("updated route policy changed exact owner weights")
PY

  run_validation_agent "${second_lighthouse_state}" "${work_dir}/ecmp-target-agent-policy.log"
  run_validation_agent "${lighthouse_state}" "${work_dir}/ecmp-source-agent-policy.log"
  run_validation_agent "${member_state}" "${work_dir}/ecmp-member-agent-policy.log"
  validate_bundle "${second_lighthouse_output}" "ECMP weighted target"
  validate_bundle "${lighthouse_output}" "ECMP weighted source"
  validate_bundle "${member_output}" "ECMP weighted member"
  python3 - \
    "${lighthouse_output}/current/config.yml" \
    "${second_lighthouse_output}/current/config.yml" \
    "${member_output}/current/config.yml" \
    "${routed_subnet}" "${lighthouse_ip}" "${second_lighthouse_ip}" <<'PY'
import pathlib
import sys

source_path, target_path, member_path, prefix, source_ip, target_ip = sys.argv[1:]
source = pathlib.Path(source_path).read_text(encoding="utf-8")
target = pathlib.Path(target_path).read_text(encoding="utf-8")
member = pathlib.Path(member_path).read_text(encoding="utf-8")
if any(f'route: "{prefix}"' in config for config in (source, target)):
    raise SystemExit("an ECMP owner received its own prefix as an unsafe route")
if member.count(f'route: "{prefix}"') != 1 or member.count("gateway:") != 2:
    raise SystemExit("member did not receive exactly one two-gateway route")
for gateway, weight in ((source_ip, 3), (target_ip, 1)):
    if f'        - gateway: "{gateway}"\n          weight: {weight}\n' not in member:
        raise SystemExit("member weighted route omitted an exact gateway")
if "      mtu: 1300\n      metric: 42\n" not in member:
    raise SystemExit("member weighted route omitted MTU or metric controls")
PY
  reload_nebula_for_ca_rotation "${second_lighthouse_ns}" "${target_ecmp_pid}" ecmp-target-weighted
  reload_nebula_for_ca_rotation "${lighthouse_ns}" "${source_ecmp_pid}" ecmp-source-weighted
  reload_nebula_for_ca_rotation "${member_ns}" "${member_ecmp_pid}" ecmp-member-weighted

  install -m 0600 /dev/null "${work_dir}/ecmp-udp-receipts.log"
  run_root ip netns exec "${routed_host_ns}" \
    python3 "${repo_root}/scripts/udp-flow-smoke.py" server \
      --bind "${routed_host_ip}" --port 18080 --receipt "${work_dir}/ecmp-udp-receipts.log" \
      >"${work_dir}/ecmp-udp-server.log" 2>&1 &
  ecmp_udp_server_launcher_pid=$!
  ecmp_receipt_count() {
    python3 - "${work_dir}/ecmp-udp-receipts.log" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
print(sum(1 for _ in path.open(encoding="utf-8")) if path.exists() else 0)
PY
  }
  ecmp_wait_for_receipts() {
    local expected="$1"
    local label="$2"
    local observed poll
    for poll in {1..100}; do
      observed="$(ecmp_receipt_count)"
      (( observed >= expected )) && return
      sleep 0.05
    done
    die "${label} delivered $(ecmp_receipt_count) receipts; expected at least ${expected}"
  }
  ecmp_udp_ready=0
  for poll in {1..50}; do
    if run_root ip netns exec "${member_ns}" \
      python3 "${repo_root}/scripts/udp-flow-smoke.py" client \
        --source "${member_ip}" --target "${routed_host_ip}" --port 18080 \
        --count 1 --first-source-port "$(( 20000 + poll ))" --send-only \
        >"${work_dir}/ecmp-udp-ready.json" 2>/dev/null &&
      (( $(ecmp_receipt_count) >= 1 )); then
      ecmp_udp_ready=1
      break
    fi
    sleep 0.1
  done
  [[ "${ecmp_udp_ready}" == "1" ]] || die "ECMP routed-host UDP echo service did not become reachable"

  ecmp_link_tx_packets() {
    local namespace="$1"
    run_root ip netns exec "${namespace}" python3 - <<'PY'
import pathlib
print(pathlib.Path("/sys/class/net/routed0/statistics/tx_packets").read_text(encoding="ascii").strip())
PY
  }

  ecmp_source_before="$(ecmp_link_tx_packets "${lighthouse_ns}")"
  ecmp_target_before="$(ecmp_link_tx_packets "${second_lighthouse_ns}")"
  ecmp_receipts_before="$(ecmp_receipt_count)"
  run_root ip netns exec "${member_ns}" \
    python3 "${repo_root}/scripts/udp-flow-smoke.py" client \
      --source "${member_ip}" --target "${routed_host_ip}" --port 18080 \
      --count 160 --first-source-port 20100 --send-only --interval 0.002 \
      >"${work_dir}/ecmp-weighted-flows.json"
  ecmp_wait_for_receipts "$(( ecmp_receipts_before + 160 ))" "weighted ECMP sample"
  ecmp_source_after="$(ecmp_link_tx_packets "${lighthouse_ns}")"
  ecmp_target_after="$(ecmp_link_tx_packets "${second_lighthouse_ns}")"
  python3 - \
    "${ecmp_source_before}" "${ecmp_source_after}" \
    "${ecmp_target_before}" "${ecmp_target_after}" 160 \
    >"${work_dir}/ecmp-weighted-distribution.json" <<'PY'
import json
import sys

source_before, source_after, target_before, target_after, attempted = map(int, sys.argv[1:])
source = source_after - source_before
target = target_after - target_before
total = source + target
if source <= 0 or target <= 0 or total < attempted or total > attempted + 8:
    raise SystemExit(f"weighted ECMP did not deliver bounded traffic through both gateways: source={source} target={target}")
share = source / total
if not 0.60 <= share <= 0.90:
    raise SystemExit(f"3:1 ECMP source share is outside the bounded sample: {share:.3f}")
print(json.dumps({"schema":"mesh-ecmp-distribution-v1","source_packets":source,"target_packets":target,"source_share":share}, separators=(",", ":"), sort_keys=True))
PY

  say "Making the lower-weight gateway unavailable while preserving its Nebula process"
  run_root ip -n "${second_lighthouse_ns}" link set underlay0 down
  run_root ip netns exec "${member_ns}" \
    python3 "${repo_root}/scripts/udp-flow-smoke.py" client \
      --source "${member_ip}" --target "${routed_host_ip}" --port 18080 \
      --count 160 --first-source-port 20400 --send-only --interval 0.002 \
      >"${work_dir}/ecmp-failure-detection-churn.json"
  sleep 16
  ecmp_source_before="$(ecmp_link_tx_packets "${lighthouse_ns}")"
  ecmp_target_before="$(ecmp_link_tx_packets "${second_lighthouse_ns}")"
  ecmp_receipts_before="$(ecmp_receipt_count)"
  run_root ip netns exec "${member_ns}" \
    python3 "${repo_root}/scripts/udp-flow-smoke.py" client \
      --source "${member_ip}" --target "${routed_host_ip}" --port 18080 \
      --count 80 --first-source-port 20700 --send-only --interval 0.002 \
      >"${work_dir}/ecmp-fallback-flows.json"
  ecmp_wait_for_receipts "$(( ecmp_receipts_before + 80 ))" "unavailable-gateway fallback sample"
  ecmp_source_after="$(ecmp_link_tx_packets "${lighthouse_ns}")"
  ecmp_target_after="$(ecmp_link_tx_packets "${second_lighthouse_ns}")"
  python3 - \
    "${ecmp_source_before}" "${ecmp_source_after}" \
    "${ecmp_target_before}" "${ecmp_target_after}" 80 \
    >"${work_dir}/ecmp-fallback-distribution.json" <<'PY'
import json
import sys

source_before, source_after, target_before, target_after, attempted = map(int, sys.argv[1:])
source = source_after - source_before
target = target_after - target_before
if source < attempted or source > attempted + 8 or target != 0:
    raise SystemExit(f"ECMP fallback was not isolated to the surviving gateway: source={source} target={target}")
print(json.dumps({"schema":"mesh-ecmp-fallback-v1","source_packets":source,"target_packets":target}, separators=(",", ":"), sort_keys=True))
PY
  namespace_contains_pid "${second_lighthouse_ns}" "${target_ecmp_pid}" ||
    die "unavailable ECMP gateway process exited during fallback"

  say "Restoring the lower-weight gateway and re-establishing its overlay tunnel"
  run_root ip -n "${second_lighthouse_ns}" link set underlay0 up
  wait_for_overlay_ping "${member_ns}" "${second_lighthouse_ip}" \
    "${work_dir}/ecmp-target-reestablish.log"
  ecmp_source_before="$(ecmp_link_tx_packets "${lighthouse_ns}")"
  ecmp_target_before="$(ecmp_link_tx_packets "${second_lighthouse_ns}")"
  ecmp_receipts_before="$(ecmp_receipt_count)"
  run_root ip netns exec "${member_ns}" \
    python3 "${repo_root}/scripts/udp-flow-smoke.py" client \
      --source "${member_ip}" --target "${routed_host_ip}" --port 18080 \
      --count 160 --first-source-port 21000 --send-only --interval 0.002 \
      >"${work_dir}/ecmp-restored-flows.json"
  ecmp_wait_for_receipts "$(( ecmp_receipts_before + 160 ))" "restored weighted ECMP sample"
  ecmp_source_after="$(ecmp_link_tx_packets "${lighthouse_ns}")"
  ecmp_target_after="$(ecmp_link_tx_packets "${second_lighthouse_ns}")"
  python3 - \
    "${ecmp_source_before}" "${ecmp_source_after}" \
    "${ecmp_target_before}" "${ecmp_target_after}" 160 \
    >"${work_dir}/ecmp-restored-distribution.json" <<'PY'
import json
import sys

source_before, source_after, target_before, target_after, attempted = map(int, sys.argv[1:])
source = source_after - source_before
target = target_after - target_before
total = source + target
if source <= 0 or target <= 0 or total < attempted or total > attempted + 8 or not 0.60 <= source / total <= 0.90:
    raise SystemExit(f"restored ECMP did not resume bounded 3:1 selection: source={source} target={target}")
print(json.dumps({"schema":"mesh-ecmp-restored-v1","source_packets":source,"target_packets":target,"source_share":source/total}, separators=(",", ":"), sort_keys=True))
PY

  ecmp_leave_request_id="ecmp-leave-packet-${suffix}"
  printf '{"routed_subnets":[],"expected_config_revision":%s,"request_id":"%s"}\n' \
    "${ecmp_policy_revision}" "${ecmp_leave_request_id}" \
    >"${work_dir}/ecmp-leave-request.json"
  api_request POST "/api/v1/nodes/${second_lighthouse_id}/route-profile" \
    "${work_dir}/ecmp-leaving.json" "${work_dir}/ecmp-leave-request.json"
  ecmp_leave_revision="$(json_field "${work_dir}/ecmp-leaving.json" config_revision)"
  (( ecmp_leave_revision == ecmp_policy_revision + 1 )) ||
    die "ECMP leave did not advance exactly one signed revision"
  assert_route_profile_document "${work_dir}/ecmp-leaving.json" cleaning_owner \
    "${ecmp_leave_revision}" "${ecmp_leave_request_id}" \
    "${second_lighthouse_id}" 1 0 0 -

  run_validation_agent "${second_lighthouse_state}" "${work_dir}/ecmp-target-agent-leave.log"
  run_validation_agent "${lighthouse_state}" "${work_dir}/ecmp-source-agent-leave.log"
  run_validation_agent "${member_state}" "${work_dir}/ecmp-member-agent-leave.log"
  reload_nebula_for_ca_rotation "${second_lighthouse_ns}" "${target_ecmp_pid}" ecmp-target-cleaning
  reload_nebula_for_ca_rotation "${lighthouse_ns}" "${source_ecmp_pid}" ecmp-source-surviving
  reload_nebula_for_ca_rotation "${member_ns}" "${member_ecmp_pid}" ecmp-member-single-route
  python3 - \
    "${member_output}/current/config.yml" "${routed_subnet}" "${lighthouse_ip}" <<'PY'
import pathlib
import sys

path, prefix, source_ip = sys.argv[1:]
config = pathlib.Path(path).read_text(encoding="utf-8")
route = f'    - route: "{prefix}"\n      via: "{source_ip}"\n      mtu: 1300\n      metric: 42\n'
if config.count(f'route: "{prefix}"') != 1 or route not in config or "gateway:" in config:
    raise SystemExit("route-first ECMP leave did not publish the exact surviving scalar route and controls")
PY
  ecmp_source_before="$(ecmp_link_tx_packets "${lighthouse_ns}")"
  ecmp_target_before="$(ecmp_link_tx_packets "${second_lighthouse_ns}")"
  ecmp_receipts_before="$(ecmp_receipt_count)"
  run_root ip netns exec "${member_ns}" \
    python3 "${repo_root}/scripts/udp-flow-smoke.py" client \
      --source "${member_ip}" --target "${routed_host_ip}" --port 18080 \
      --count 80 --first-source-port 21400 --send-only --interval 0.002 \
      >"${work_dir}/ecmp-route-first-leave-flows.json"
  ecmp_wait_for_receipts "$(( ecmp_receipts_before + 80 ))" "route-first ECMP leave sample"
  ecmp_source_after="$(ecmp_link_tx_packets "${lighthouse_ns}")"
  ecmp_target_after="$(ecmp_link_tx_packets "${second_lighthouse_ns}")"
  python3 - \
    "${ecmp_source_before}" "${ecmp_source_after}" \
    "${ecmp_target_before}" "${ecmp_target_after}" 80 <<'PY'
import sys

source_before, source_after, target_before, target_after, attempted = map(int, sys.argv[1:])
source = source_after - source_before
target = target_after - target_before
if source < attempted or source > attempted + 8 or target != 0:
    raise SystemExit(f"route-first ECMP leave did not keep traffic on the surviving gateway: source={source} target={target}")
PY

  sleep 5.1
  report_ca_rotation_heartbeat "${second_lighthouse_state}" \
    "${work_dir}/ecmp-target-heartbeat-cleaned.log"
  api_request GET "/api/v1/nodes/${second_lighthouse_id}/route-profile" \
    "${work_dir}/ecmp-leave-ready.json"
  assert_route_profile_document "${work_dir}/ecmp-leave-ready.json" cleaning_owner \
    "${ecmp_leave_revision}" "${ecmp_leave_request_id}" \
    "${second_lighthouse_id}" 1 0 1 advance
  printf '{"expected_config_revision":%s,"request_id":"%s"}\n' \
    "${ecmp_leave_revision}" "${ecmp_leave_request_id}" \
    >"${work_dir}/ecmp-leave-complete-request.json"
  api_request POST "/api/v1/nodes/${second_lighthouse_id}/route-profile/advance" \
    "${work_dir}/ecmp-left.json" "${work_dir}/ecmp-leave-complete-request.json"
  assert_route_profile_document "${work_dir}/ecmp-left.json" completed \
    "${ecmp_leave_revision}" "${ecmp_leave_request_id}" \
    "${second_lighthouse_id}" 1 0 0 start
  api_request POST "/api/v1/nodes/${second_lighthouse_id}/route-profile/advance" \
    "${work_dir}/ecmp-left-replay.json" "${work_dir}/ecmp-leave-complete-request.json"
  cmp -s "${work_dir}/ecmp-left.json" "${work_dir}/ecmp-left-replay.json" ||
    die "completed ECMP leave replay changed its authoritative receipt"

  for process_spec in \
    "${lighthouse_ns}|${source_ecmp_pid}|source" \
    "${second_lighthouse_ns}|${target_ecmp_pid}|target" \
    "${member_ns}|${member_ecmp_pid}|member"; do
    IFS='|' read -r namespace pid label <<<"${process_spec}"
    namespace_contains_pid "${namespace}" "${pid}" ||
      die "${label} Nebula process changed during the ECMP lifecycle"
  done
  kill -0 "${ecmp_udp_server_launcher_pid}" 2>/dev/null ||
    die "routed-host UDP receiver exited during the ECMP lifecycle"

  say "PASS: 3:1 weighted UDP port pairs traversed both active certificate owners"
  say "PASS: unavailable-gateway detection fell back to the surviving gateway and restoration resumed weighted selection"
  say "PASS: route-first membership removal kept packets flowing while the departing certificate was cleaned"
  say "Scope: isolated Linux namespaces, one exact IPv4 prefix, two gateways, and Nebula 1.10.3 passive/active tunnel detection; this is not a production router health SLA."
  exit 0
fi
if [[ "${route_profile_smoke}" == "1" ]]; then
  say "Proving route-first removal and certificate-first restoration through real agents and Nebula packets"
  route_profile_gateway_pid="$(single_namespace_process_pid "${lighthouse_ns}" route-profile-gateway)"
  route_profile_member_pid="$(single_namespace_process_pid "${member_ns}" route-profile-member)"
  route_profile_remove_request_id="route-profile-remove-packet-${suffix}"

  printf \
    '{"routed_subnets":[],"expected_config_revision":%s,"request_id":"%s"}\n' \
    "${initial_member_revision}" "${route_profile_remove_request_id}" \
    >"${work_dir}/route-profile-remove-request.json"
  api_request POST "/api/v1/nodes/${lighthouse_id}/route-profile" \
    "${work_dir}/route-profile-removing.json" "${work_dir}/route-profile-remove-request.json"
  route_profile_remove_revision="$(json_field "${work_dir}/route-profile-removing.json" config_revision)"
  (( route_profile_remove_revision == initial_member_revision + 1 )) ||
    die "route-profile removal did not advance exactly one signed revision"
  assert_route_profile_document "${work_dir}/route-profile-removing.json" cleaning_owner \
    "${route_profile_remove_revision}" "${route_profile_remove_request_id}" \
    "${lighthouse_id}" 1 0 0 -

  run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-route-profile-remove.log"
  run_validation_agent "${member_state}" "${work_dir}/member-agent-route-profile-remove.log"
  validate_bundle "${lighthouse_output}" "route-profile cleaned gateway"
  validate_bundle "${member_output}" "route-profile withdrawn member"
  "${nebula_cert}" print -json -path "${lighthouse_output}/current/host.crt" \
    >"${work_dir}/route-profile-removed-certificate.json"
  python3 - \
    "${work_dir}/route-profile-removed-certificate.json" \
    "${lighthouse_output}/current/config.yml" \
    "${member_output}/current/config.yml" \
    "${routed_subnet}" "${lighthouse_ip}" <<'PY'
import json
import pathlib
import sys

certificate_path, gateway_config_path, member_config_path, routed_subnet, gateway_ip = sys.argv[1:]
certificate = json.loads(pathlib.Path(certificate_path).read_text(encoding="utf-8"))
if not isinstance(certificate, list) or len(certificate) != 1 or (certificate[0].get("details", {}).get("unsafeNetworks") or []) != []:
    raise SystemExit("route-profile removal certificate retained routed authorization")
gateway_config = pathlib.Path(gateway_config_path).read_text(encoding="utf-8")
member_config = pathlib.Path(member_config_path).read_text(encoding="utf-8")
route = f'    - route: "{routed_subnet}"\n      via: "{gateway_ip}"\n'
if f"local_cidr: {routed_subnet}" in gateway_config or route in member_config:
    raise SystemExit("route-profile removal retained local policy or a peer route")
PY
  reload_nebula_for_ca_rotation "${lighthouse_ns}" "${route_profile_gateway_pid}" route-profile-gateway-removed
  reload_nebula_for_ca_rotation "${member_ns}" "${route_profile_member_pid}" route-profile-member-withdrawn
  assert_overlay_ping_blocked "${member_ns}" "${routed_host_ip}" \
    "${work_dir}/route-profile-withdrawn-packet.log"
  sleep 5.1
  report_ca_rotation_heartbeat "${lighthouse_state}" \
    "${work_dir}/lighthouse-heartbeat-route-profile-removed.log"
  api_request GET "/api/v1/nodes/${lighthouse_id}/route-profile" \
    "${work_dir}/route-profile-remove-ready.json"
  assert_route_profile_document "${work_dir}/route-profile-remove-ready.json" cleaning_owner \
    "${route_profile_remove_revision}" "${route_profile_remove_request_id}" \
    "${lighthouse_id}" 1 0 1 advance

  printf '{"expected_config_revision":%s,"request_id":"%s"}\n' \
    "${route_profile_remove_revision}" "${route_profile_remove_request_id}" \
    >"${work_dir}/route-profile-remove-complete-request.json"
  api_request POST "/api/v1/nodes/${lighthouse_id}/route-profile/advance" \
    "${work_dir}/route-profile-removed.json" "${work_dir}/route-profile-remove-complete-request.json"
  assert_route_profile_document "${work_dir}/route-profile-removed.json" completed \
    "${route_profile_remove_revision}" "${route_profile_remove_request_id}" \
    "${lighthouse_id}" 1 0 0 start
  api_request POST "/api/v1/nodes/${lighthouse_id}/route-profile/advance" \
    "${work_dir}/route-profile-removed-replay.json" "${work_dir}/route-profile-remove-complete-request.json"
  cmp -s "${work_dir}/route-profile-removed.json" "${work_dir}/route-profile-removed-replay.json" ||
    die "completed route-profile removal replay changed its authoritative receipt"

  route_profile_add_request_id="route-profile-add-packet-${suffix}"
  printf \
    '{"routed_subnets":["%s"],"expected_config_revision":%s,"request_id":"%s"}\n' \
    "${routed_subnet}" "${route_profile_remove_revision}" "${route_profile_add_request_id}" \
    >"${work_dir}/route-profile-add-request.json"
  api_request POST "/api/v1/nodes/${lighthouse_id}/route-profile" \
    "${work_dir}/route-profile-preparing.json" "${work_dir}/route-profile-add-request.json"
  route_profile_prepare_revision="$(json_field "${work_dir}/route-profile-preparing.json" config_revision)"
  (( route_profile_prepare_revision == route_profile_remove_revision + 1 )) ||
    die "route-profile addition prepare did not advance exactly one signed revision"
  assert_route_profile_document "${work_dir}/route-profile-preparing.json" preparing_owner \
    "${route_profile_prepare_revision}" "${route_profile_add_request_id}" \
    "${lighthouse_id}" 0 1 0 cancel

  run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-route-profile-prepare.log"
  run_validation_agent "${member_state}" "${work_dir}/member-agent-route-profile-prepare.log"
  validate_bundle "${lighthouse_output}" "route-profile prepared gateway"
  validate_bundle "${member_output}" "route-profile unpromoted member"
  "${nebula_cert}" print -json -path "${lighthouse_output}/current/host.crt" \
    >"${work_dir}/route-profile-prepared-certificate.json"
  python3 - \
    "${work_dir}/route-profile-prepared-certificate.json" \
    "${lighthouse_output}/current/config.yml" \
    "${member_output}/current/config.yml" \
    "${routed_subnet}" "${lighthouse_ip}" <<'PY'
import json
import pathlib
import sys

certificate_path, gateway_config_path, member_config_path, routed_subnet, gateway_ip = sys.argv[1:]
certificate = json.loads(pathlib.Path(certificate_path).read_text(encoding="utf-8"))
if not isinstance(certificate, list) or len(certificate) != 1 or certificate[0].get("details", {}).get("unsafeNetworks") != [routed_subnet]:
    raise SystemExit("route-profile prepared certificate omitted routed authorization")
gateway_config = pathlib.Path(gateway_config_path).read_text(encoding="utf-8")
member_config = pathlib.Path(member_config_path).read_text(encoding="utf-8")
route = f'    - route: "{routed_subnet}"\n      via: "{gateway_ip}"\n'
if f"local_cidr: {routed_subnet}" not in gateway_config or route in member_config:
    raise SystemExit("route-profile prepare published the peer route before promotion")
PY
  reload_nebula_for_ca_rotation "${lighthouse_ns}" "${route_profile_gateway_pid}" route-profile-gateway-prepared
  reload_nebula_for_ca_rotation "${member_ns}" "${route_profile_member_pid}" route-profile-member-unpromoted
  assert_overlay_ping_blocked "${member_ns}" "${routed_host_ip}" \
    "${work_dir}/route-profile-prepared-unpublished-packet.log"
  sleep 5.1
  report_ca_rotation_heartbeat "${lighthouse_state}" \
    "${work_dir}/lighthouse-heartbeat-route-profile-prepared.log"
  api_request GET "/api/v1/nodes/${lighthouse_id}/route-profile" \
    "${work_dir}/route-profile-prepare-ready.json"
  assert_route_profile_document "${work_dir}/route-profile-prepare-ready.json" preparing_owner \
    "${route_profile_prepare_revision}" "${route_profile_add_request_id}" \
    "${lighthouse_id}" 0 1 1 advance,cancel

  printf '{"expected_config_revision":%s,"request_id":"%s"}\n' \
    "${route_profile_prepare_revision}" "${route_profile_add_request_id}" \
    >"${work_dir}/route-profile-promote-request.json"
  api_request POST "/api/v1/nodes/${lighthouse_id}/route-profile/advance" \
    "${work_dir}/route-profile-restored.json" "${work_dir}/route-profile-promote-request.json"
  route_profile_restored_revision="$(json_field "${work_dir}/route-profile-restored.json" config_revision)"
  (( route_profile_restored_revision == route_profile_prepare_revision + 1 )) ||
    die "route-profile addition promotion did not advance exactly one signed revision"
  assert_route_profile_document "${work_dir}/route-profile-restored.json" completed \
    "${route_profile_restored_revision}" "${route_profile_add_request_id}" \
    "${lighthouse_id}" 0 1 0 start

  run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-route-profile-restored.log"
  run_validation_agent "${member_state}" "${work_dir}/member-agent-route-profile-restored.log"
  validate_bundle "${lighthouse_output}" "route-profile restored gateway"
  validate_bundle "${member_output}" "route-profile restored member"
  reload_nebula_for_ca_rotation "${lighthouse_ns}" "${route_profile_gateway_pid}" route-profile-gateway-restored
  reload_nebula_for_ca_rotation "${member_ns}" "${route_profile_member_pid}" route-profile-member-restored
  assert_overlay_route "${member_ns}" "${member_ip}" "${routed_host_ip}" \
    "${member_overlay_device}" member-to-routed-host-after-profile-restore
  wait_for_overlay_ping "${member_ns}" "${routed_host_ip}" \
    "${work_dir}/route-profile-restored-establish.log"
  prove_overlay_ping "${member_ns}" "${routed_host_ip}" \
    "${work_dir}/route-profile-restored-proof.log"
  namespace_contains_pid "${lighthouse_ns}" "${route_profile_gateway_pid}" ||
    die "gateway Nebula process changed during route-profile edits"
  namespace_contains_pid "${member_ns}" "${route_profile_member_pid}" ||
    die "member Nebula process changed during route-profile edits"
  api_request POST "/api/v1/nodes/${lighthouse_id}/route-profile/advance" \
    "${work_dir}/route-profile-restored-replay.json" "${work_dir}/route-profile-promote-request.json"
  cmp -s "${work_dir}/route-profile-restored.json" "${work_dir}/route-profile-restored-replay.json" ||
    die "completed route-profile addition replay changed its authoritative receipt"

  say "PASS: route-first removal withdrew packets before certificate cleanup completion"
  say "PASS: certificate-first addition stayed unpublished until exact gateway convergence"
  say "PASS: promotion restored the signed peer route and real routed-host packets without replacing either Nebula process"
  say "Scope: isolated Linux namespaces, one exact IPv4 subnet, and one active gateway; no overlapping-prefix transition claim is made."
  exit 0
fi
if [[ "${route_transfer_smoke}" == "1" ]]; then
  say "Proving staged routed-subnet ownership transfer through real agents and Nebula packets"
  source_transfer_pid="$(single_namespace_process_pid "${lighthouse_ns}" route-transfer-source)"
  target_transfer_pid="$(single_namespace_process_pid "${second_lighthouse_ns}" route-transfer-target)"
  member_transfer_pid="$(single_namespace_process_pid "${member_ns}" route-transfer-member)"
  route_transfer_request_id="route-transfer-packet-${suffix}"

  printf \
    '{"source_node_id":"%s","target_node_id":"%s","routed_subnets":["%s"],"expected_config_revision":%s,"request_id":"%s"}\n' \
    "${lighthouse_id}" "${second_lighthouse_id}" "${routed_subnet}" \
    "${initial_member_revision}" "${route_transfer_request_id}" \
    >"${work_dir}/route-transfer-start-request.json"
  api_request POST "/api/v1/networks/${network_id}/route-transfer" \
    "${work_dir}/route-transfer-started.json" "${work_dir}/route-transfer-start-request.json"
  route_transfer_prepare_revision="$(json_field "${work_dir}/route-transfer-started.json" config_revision)"
  (( route_transfer_prepare_revision == initial_member_revision + 1 )) ||
    die "route-transfer prepare did not advance exactly one signed revision"
  assert_route_transfer_document "${work_dir}/route-transfer-started.json" preparing_target \
    "${route_transfer_prepare_revision}" "${route_transfer_request_id}" \
    "${lighthouse_id}" "${second_lighthouse_id}" 0 0 cancel

  run_validation_agent "${second_lighthouse_state}" \
    "${work_dir}/second-lighthouse-agent-route-transfer-prepare.log"
  validate_bundle "${second_lighthouse_output}" "route-transfer prepared target"
  "${nebula_cert}" print -json -path "${second_lighthouse_output}/current/host.crt" \
    >"${work_dir}/route-transfer-target-prepared-certificate.json"
  python3 - \
    "${work_dir}/route-transfer-target-prepared-certificate.json" \
    "${second_lighthouse_output}/current/config.yml" \
    "${member_output}/current/config.yml" \
    "${routed_subnet}" "${lighthouse_ip}" <<'PY'
import json
import pathlib
import sys

certificate_path, target_config_path, member_config_path, routed_subnet, source_ip = sys.argv[1:]
certificate = json.loads(pathlib.Path(certificate_path).read_text(encoding="utf-8"))
if not isinstance(certificate, list) or len(certificate) != 1:
    raise SystemExit("prepared target certificate print did not return exactly one certificate")
if certificate[0].get("details", {}).get("unsafeNetworks", []) != [routed_subnet]:
    raise SystemExit("prepared target certificate does not authorize the exact transferred subnet")
target_config = pathlib.Path(target_config_path).read_text(encoding="utf-8")
member_config = pathlib.Path(member_config_path).read_text(encoding="utf-8")
if "unsafe_routes:" in target_config or f"local_cidr: {routed_subnet}" not in target_config:
    raise SystemExit("prepared target config can loop the transferred subnet or omits local policy")
source_route = f'    - route: "{routed_subnet}"\n      via: "{source_ip}"\n'
if source_route not in member_config:
    raise SystemExit("prepare changed the existing member route before promotion")
PY
  reload_nebula_for_ca_rotation "${second_lighthouse_ns}" "${target_transfer_pid}" route-transfer-target-prepare
  run_root ip -n "${second_lighthouse_ns}" address add "${routed_target_ip}/24" dev routed0
  prove_overlay_ping "${second_lighthouse_ns}" "${routed_host_ip}" \
    "${work_dir}/route-transfer-target-prepare-lan-proof.log"
  sleep 5.1
  report_ca_rotation_heartbeat "${second_lighthouse_state}" \
    "${work_dir}/second-lighthouse-heartbeat-route-transfer-prepare.log"
  api_request GET "/api/v1/networks/${network_id}/route-transfer" \
    "${work_dir}/route-transfer-target-ready.json"
  assert_route_transfer_document "${work_dir}/route-transfer-target-ready.json" preparing_target \
    "${route_transfer_prepare_revision}" "${route_transfer_request_id}" \
    "${lighthouse_id}" "${second_lighthouse_id}" 0 1 advance,cancel
  prove_overlay_ping "${member_ns}" "${routed_host_ip}" \
    "${work_dir}/routed-host-during-prepare-proof.log"

  printf '{"expected_config_revision":%s,"request_id":"%s"}\n' \
    "${route_transfer_prepare_revision}" "${route_transfer_request_id}" \
    >"${work_dir}/route-transfer-promote-request.json"
  api_request POST "/api/v1/networks/${network_id}/route-transfer/advance" \
    "${work_dir}/route-transfer-promoted.json" "${work_dir}/route-transfer-promote-request.json"
  route_transfer_promoted_revision="$(json_field "${work_dir}/route-transfer-promoted.json" config_revision)"
  (( route_transfer_promoted_revision == route_transfer_prepare_revision + 1 )) ||
    die "route-transfer promotion did not advance exactly one signed revision"
  assert_route_transfer_document "${work_dir}/route-transfer-promoted.json" cleaning_source \
    "${route_transfer_promoted_revision}" "${route_transfer_request_id}" \
    "${lighthouse_id}" "${second_lighthouse_id}" 0 0 -

  run_validation_agent "${second_lighthouse_state}" \
    "${work_dir}/second-lighthouse-agent-route-transfer-promoted.log"
  run_validation_agent "${member_state}" "${work_dir}/member-agent-route-transfer-promoted.log"
  run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-route-transfer-cleanup.log"
  validate_bundle "${second_lighthouse_output}" "route-transfer promoted target"
  validate_bundle "${member_output}" "route-transfer promoted member"
  validate_bundle "${lighthouse_output}" "route-transfer cleaned source"

  reload_nebula_for_ca_rotation "${second_lighthouse_ns}" "${target_transfer_pid}" route-transfer-target-promoted
  run_root ip netns exec "${second_lighthouse_ns}" sysctl -q -w net.ipv4.ip_forward=1
  reload_nebula_for_ca_rotation "${member_ns}" "${member_transfer_pid}" route-transfer-member-promoted
  run_root ip -n "${routed_host_ns}" route replace 10.88.0.0/24 via "${routed_target_ip}" dev "${routed_host_interface}"
  reload_nebula_for_ca_rotation "${lighthouse_ns}" "${source_transfer_pid}" route-transfer-source-cleaned
  run_root ip netns exec "${lighthouse_ns}" sysctl -q -w net.ipv4.ip_forward=0

  sleep 5.1
  report_ca_rotation_heartbeat "${second_lighthouse_state}" \
    "${work_dir}/second-lighthouse-heartbeat-route-transfer-promoted.log"
  report_ca_rotation_heartbeat "${member_state}" \
    "${work_dir}/member-heartbeat-route-transfer-promoted.log"
  report_ca_rotation_heartbeat "${lighthouse_state}" \
    "${work_dir}/lighthouse-heartbeat-route-transfer-cleaned.log"
  api_request GET "/api/v1/networks/${network_id}/route-transfer" \
    "${work_dir}/route-transfer-source-ready.json"
  assert_route_transfer_document "${work_dir}/route-transfer-source-ready.json" cleaning_source \
    "${route_transfer_promoted_revision}" "${route_transfer_request_id}" \
    "${lighthouse_id}" "${second_lighthouse_id}" 1 1 advance

  "${nebula_cert}" print -json -path "${lighthouse_output}/current/host.crt" \
    >"${work_dir}/route-transfer-source-clean-certificate.json"
  "${nebula_cert}" print -json -path "${second_lighthouse_output}/current/host.crt" \
    >"${work_dir}/route-transfer-target-final-certificate.json"
  python3 - \
    "${work_dir}/route-transfer-source-clean-certificate.json" \
    "${work_dir}/route-transfer-target-final-certificate.json" \
    "${lighthouse_output}/current/config.yml" \
    "${second_lighthouse_output}/current/config.yml" \
    "${member_output}/current/config.yml" \
    "${routed_subnet}" "${second_lighthouse_ip}" <<'PY'
import json
import pathlib
import sys

source_cert_path, target_cert_path, source_config_path, target_config_path, member_config_path, routed_subnet, target_ip = sys.argv[1:]
source_cert = json.loads(pathlib.Path(source_cert_path).read_text(encoding="utf-8"))
target_cert = json.loads(pathlib.Path(target_cert_path).read_text(encoding="utf-8"))
if not isinstance(source_cert, list) or len(source_cert) != 1 or not isinstance(target_cert, list) or len(target_cert) != 1:
    raise SystemExit("final gateway certificate print did not return exact certificates")
if (source_cert[0].get("details", {}).get("unsafeNetworks") or []) != []:
    raise SystemExit("source certificate retained the transferred subnet")
if target_cert[0].get("details", {}).get("unsafeNetworks", []) != [routed_subnet]:
    raise SystemExit("target certificate lost the transferred subnet")
source_config = pathlib.Path(source_config_path).read_text(encoding="utf-8")
target_config = pathlib.Path(target_config_path).read_text(encoding="utf-8")
member_config = pathlib.Path(member_config_path).read_text(encoding="utf-8")
target_route = f'    - route: "{routed_subnet}"\n      via: "{target_ip}"\n'
if f"local_cidr: {routed_subnet}" in source_config or target_route not in source_config:
    raise SystemExit("source config did not become an ordinary peer of the target gateway")
if "unsafe_routes:" in target_config or f"local_cidr: {routed_subnet}" not in target_config:
    raise SystemExit("target config did not become the sole local gateway")
if target_route not in member_config or f"local_cidr: {routed_subnet}" in member_config:
    raise SystemExit("member config did not cut over to the target gateway")
PY

  assert_overlay_route "${member_ns}" "${member_ip}" "${routed_host_ip}" \
    "${member_overlay_device}" member-to-routed-host-after-transfer
  [[ "$(run_root ip netns exec "${second_lighthouse_ns}" sysctl -n net.ipv4.ip_forward)" == "1" ]] ||
    die "target forwarding was not enabled for the post-cutover proof"
  prove_overlay_ping "${second_lighthouse_ns}" "${routed_host_ip}" \
    "${work_dir}/route-transfer-target-lan-proof.log"
  prove_overlay_ping "${routed_host_ns}" "${routed_target_ip}" \
    "${work_dir}/route-transfer-host-target-proof.log"
  prove_overlay_ping "${member_ns}" "${routed_host_ip}" \
    "${work_dir}/routed-host-after-transfer-proof.log"
  [[ "$(run_root ip netns exec "${lighthouse_ns}" sysctl -n net.ipv4.ip_forward)" == "0" ]] ||
    die "source forwarding was not disabled for the post-cutover proof"
  namespace_contains_pid "${lighthouse_ns}" "${source_transfer_pid}" ||
    die "source Nebula process changed during route transfer"
  namespace_contains_pid "${second_lighthouse_ns}" "${target_transfer_pid}" ||
    die "target Nebula process changed during route transfer"
  namespace_contains_pid "${member_ns}" "${member_transfer_pid}" ||
    die "member Nebula process changed during route transfer"

  printf '{"expected_config_revision":%s,"request_id":"%s"}\n' \
    "${route_transfer_promoted_revision}" "${route_transfer_request_id}" \
    >"${work_dir}/route-transfer-complete-request.json"
  api_request POST "/api/v1/networks/${network_id}/route-transfer/advance" \
    "${work_dir}/route-transfer-completed.json" "${work_dir}/route-transfer-complete-request.json"
  assert_route_transfer_document "${work_dir}/route-transfer-completed.json" completed \
    "${route_transfer_promoted_revision}" "${route_transfer_request_id}" \
    "${lighthouse_id}" "${second_lighthouse_id}" 1 1 start
  api_request POST "/api/v1/networks/${network_id}/route-transfer/advance" \
    "${work_dir}/route-transfer-completed-replay.json" "${work_dir}/route-transfer-complete-request.json"
  cmp -s "${work_dir}/route-transfer-completed.json" "${work_dir}/route-transfer-completed-replay.json" ||
    die "completed route-transfer replay changed its authoritative receipt"

  say "PASS: target certificate convergence preserved source-routed packets before promotion"
  say "PASS: promotion moved the exact signed route and packets survived with source forwarding disabled"
  say "PASS: source certificate cleanup gated one write-free completed transfer receipt"
  say "Scope: isolated Linux namespaces, one exact IPv4 subnet, and one active gateway at a time; no ECMP claim is made."
  exit 0
fi
if [[ "${ui_guided_smoke}" == "1" ]]; then
  ui_guided_elapsed_seconds="$(( $(date -u '+%s') - ui_guided_started_epoch ))"
  (( ui_guided_started_epoch > 0 && ui_guided_elapsed_seconds >= 0 && ui_guided_elapsed_seconds <= 300 )) ||
    die "UI-guided authoring through authenticated overlay traffic exceeded five minutes"
  say "PASS: the browser-authored network reached authenticated lighthouse/member overlay traffic in ${ui_guided_elapsed_seconds} seconds"
fi
if [[ "${firewall_rollout_smoke}" == "1" ]]; then
	say "Proving canary firewall rollout, rollback, convergence-gated promotion, and unchanged Nebula processes"
	lighthouse_rollout_pid="$(single_namespace_process_pid "${lighthouse_ns}" lighthouse)"
	member_rollout_pid="$(single_namespace_process_pid "${member_ns}" member)"

	api_request GET "/api/v1/networks/${network_id}/firewall-rollout" \
		"${work_dir}/firewall-rollout-stable.json"
	assert_firewall_rollout_document "${work_dir}/firewall-rollout-stable.json" stable \
		"${initial_member_revision}" 0 0 start "${lighthouse_id}" "${member_id}"
	printf \
		'{"action":"start","expected_config_revision":%s,"canary_node_ids":["%s"],"inbound":[{"proto":"tcp","port":"443","group":"all"}],"outbound":[{"proto":"tcp","port":"443","host":"any"}]}\n' \
		"${initial_member_revision}" "${member_id}" >"${work_dir}/firewall-rollout-start-request.json"
	api_request POST "/api/v1/networks/${network_id}/firewall-rollout" \
		"${work_dir}/firewall-rollout-started.json" "${work_dir}/firewall-rollout-start-request.json"
	canary_revision="$(json_field "${work_dir}/firewall-rollout-started.json" config_revision)"
	(( canary_revision == initial_member_revision + 1 )) ||
		die "firewall canary start did not advance exactly one revision"
	assert_firewall_rollout_document "${work_dir}/firewall-rollout-started.json" canary \
		"${canary_revision}" 1 0 pause,rollback "${lighthouse_id}" "${member_id}"

	# The helper is an unprivileged managed agent using the member's persisted
	# bearer. It reports only the exact signed target identity; the server
	# independently re-renders that node before accepting the failure.
	failed_canary_digest="$(firewall_rollout_node_field "${work_dir}/firewall-rollout-started.json" "${member_id}" desired_config_sha256)"
	if ! run_root setpriv --reuid="$(id -u)" --regid="$(id -g)" --init-groups \
		--no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all -- \
		"${ca_rotation_heartbeat_helper}" config-failure \
		--state "${member_state}" --revision "${canary_revision}" --digest "${failed_canary_digest}" \
		>"${work_dir}/firewall-rollout-activation-failure.log" 2>&1; then
		die "authenticated member canary could not report exact activation failure"
	fi
	api_request GET "/api/v1/networks/${network_id}/firewall-rollout" \
		"${work_dir}/firewall-rollout-auto-rolled-back.json"
	auto_rollback_revision="$(json_field "${work_dir}/firewall-rollout-auto-rolled-back.json" config_revision)"
	(( auto_rollback_revision == canary_revision + 1 )) ||
		die "automatic firewall rollback did not advance exactly one revision"
	assert_firewall_rollout_document "${work_dir}/firewall-rollout-auto-rolled-back.json" stable \
		"${auto_rollback_revision}" 0 0 start "${lighthouse_id}" "${member_id}"
	assert_firewall_auto_rollback_transition "${work_dir}/firewall-rollout-auto-rolled-back.json" "${member_id}"
	namespace_contains_pid "${lighthouse_ns}" "${lighthouse_rollout_pid}" ||
		die "lighthouse Nebula process changed during automatic firewall rollback"
	namespace_contains_pid "${member_ns}" "${member_rollout_pid}" ||
		die "member Nebula process changed during automatic firewall rollback"
	prove_overlay_ping "${member_ns}" "${lighthouse_ip}" \
		"${work_dir}/firewall-auto-rollback-known-good-proof.log"
	run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-firewall-auto-rollback.log"
	run_validation_agent "${member_state}" "${work_dir}/member-agent-firewall-auto-rollback.log"
	reload_nebula_for_ca_rotation "${lighthouse_ns}" "${lighthouse_rollout_pid}" lighthouse
	reload_nebula_for_ca_rotation "${member_ns}" "${member_rollout_pid}" member
	prove_overlay_ping "${member_ns}" "${lighthouse_ip}" \
		"${work_dir}/firewall-auto-rollback-signed-known-good-proof.log"
	say "PASS: exact authenticated canary activation failure auto-rolled back while the known-good overlay and both Nebula processes remained intact"

	printf \
		'{"action":"start","expected_config_revision":%s,"canary_node_ids":["%s"],"inbound":[{"proto":"tcp","port":"443","group":"all"}],"outbound":[{"proto":"tcp","port":"443","host":"any"}]}\n' \
		"${auto_rollback_revision}" "${member_id}" >"${work_dir}/firewall-rollout-post-failure-start-request.json"
	api_request POST "/api/v1/networks/${network_id}/firewall-rollout" \
		"${work_dir}/firewall-rollout-post-failure-started.json" "${work_dir}/firewall-rollout-post-failure-start-request.json"
	canary_revision="$(json_field "${work_dir}/firewall-rollout-post-failure-started.json" config_revision)"
	(( canary_revision == auto_rollback_revision + 1 )) ||
		die "firewall canary restart after automatic rollback did not advance exactly one revision"
	assert_firewall_rollout_document "${work_dir}/firewall-rollout-post-failure-started.json" canary \
		"${canary_revision}" 1 0 pause,rollback "${lighthouse_id}" "${member_id}"

	run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-firewall-canary.log"
	run_validation_agent "${member_state}" "${work_dir}/member-agent-firewall-canary.log"
	[[ "$(json_field "${lighthouse_state}" applied_config_revision)" == "${canary_revision}" && \
		"$(json_field "${member_state}" applied_config_revision)" == "${canary_revision}" ]] ||
		die "both agents did not apply the canary revision metadata"
	validate_bundle "${lighthouse_output}" "firewall-canary lighthouse"
	validate_bundle "${member_output}" "firewall-canary member"
	python3 - "${lighthouse_output}/current/config.yml" "${member_output}/current/config.yml" <<'PY'
import pathlib
import sys

lighthouse = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
member = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
restrictive = (
    "firewall:\n"
    "  outbound:\n"
    "    - port: 443\n"
    "      proto: tcp\n"
    "      host: any\n"
    "  inbound:\n"
    "    - port: 443\n"
    "      proto: tcp\n"
    "      group: \"all\"\n"
)
full_mesh = (
    "firewall:\n"
    "  outbound:\n"
    "    - port: any\n"
    "      proto: any\n"
    "      host: any\n"
    "  inbound:\n"
    "    - port: any\n"
    "      proto: any\n"
    "      group: \"all\"\n"
)
if restrictive not in member or full_mesh not in lighthouse or restrictive in lighthouse:
    raise SystemExit("canary revision did not isolate the target firewall to the selected member")
PY
	reload_nebula_for_ca_rotation "${lighthouse_ns}" "${lighthouse_rollout_pid}" lighthouse
	reload_nebula_for_ca_rotation "${member_ns}" "${member_rollout_pid}" member
	prove_overlay_tcp_443 "${lighthouse_ns}" "${lighthouse_ip}" "${member_ip}" \
		"${member_ns}" firewall-canary-member-to-lighthouse
	assert_overlay_ping_blocked "${member_ns}" "${lighthouse_ip}" \
		"${work_dir}/firewall-canary-icmp-blocked.log"
	if ! run_root setpriv --reuid="$(id -u)" --regid="$(id -g)" --init-groups \
		--no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all -- \
		"${ca_rotation_heartbeat_helper}" runtime-stopped \
		--state "${member_state}" --nebula "${nebula}" --nebula-cert "${nebula_cert}" \
		>"${work_dir}/firewall-rollout-runtime-stopped.log" 2>&1; then
		die "authenticated member canary could not report exact stopped-target health evidence"
	fi
	api_request GET "/api/v1/networks/${network_id}/firewall-rollout" \
		"${work_dir}/firewall-rollout-runtime-auto-rolled-back.json"
	runtime_rollback_revision="$(json_field "${work_dir}/firewall-rollout-runtime-auto-rolled-back.json" config_revision)"
	(( runtime_rollback_revision == canary_revision + 1 )) ||
		die "stopped-runtime firewall rollback did not advance exactly one revision"
	assert_firewall_rollout_document "${work_dir}/firewall-rollout-runtime-auto-rolled-back.json" stable \
		"${runtime_rollback_revision}" 0 0 start "${lighthouse_id}" "${member_id}"
	assert_firewall_runtime_stopped_transition "${work_dir}/firewall-rollout-runtime-auto-rolled-back.json" "${member_id}"
	namespace_contains_pid "${lighthouse_ns}" "${lighthouse_rollout_pid}" ||
		die "lighthouse Nebula process changed during stopped-runtime automatic rollback"
	namespace_contains_pid "${member_ns}" "${member_rollout_pid}" ||
		die "member Nebula process changed during stopped-runtime automatic rollback"
	run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-firewall-runtime-rollback.log"
	run_validation_agent "${member_state}" "${work_dir}/member-agent-firewall-runtime-rollback.log"
	reload_nebula_for_ca_rotation "${lighthouse_ns}" "${lighthouse_rollout_pid}" lighthouse
	reload_nebula_for_ca_rotation "${member_ns}" "${member_rollout_pid}" member
	wait_for_overlay_ping "${member_ns}" "${lighthouse_ip}" \
		"${work_dir}/firewall-runtime-rollback-overlay-establish.log"
	prove_overlay_ping "${member_ns}" "${lighthouse_ip}" \
		"${work_dir}/firewall-runtime-rollback-overlay-proof.log"
	say "PASS: exact fresh stopped-target heartbeat auto-rolled back while missing, stale, and generic degradation remained non-destructive"

	printf \
		'{"action":"start","expected_config_revision":%s,"canary_node_ids":["%s"],"inbound":[{"proto":"tcp","port":"443","group":"all"}],"outbound":[{"proto":"tcp","port":"443","host":"any"}]}\n' \
		"${runtime_rollback_revision}" "${member_id}" >"${work_dir}/firewall-rollout-post-runtime-start-request.json"
	api_request POST "/api/v1/networks/${network_id}/firewall-rollout" \
		"${work_dir}/firewall-rollout-post-runtime-started.json" "${work_dir}/firewall-rollout-post-runtime-start-request.json"
	canary_revision="$(json_field "${work_dir}/firewall-rollout-post-runtime-started.json" config_revision)"
	(( canary_revision == runtime_rollback_revision + 1 )) ||
		die "firewall canary restart after stopped-runtime rollback did not advance exactly one revision"
	assert_firewall_rollout_document "${work_dir}/firewall-rollout-post-runtime-started.json" canary \
		"${canary_revision}" 1 0 pause,rollback "${lighthouse_id}" "${member_id}"
	run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-firewall-post-runtime.log"
	run_validation_agent "${member_state}" "${work_dir}/member-agent-firewall-post-runtime.log"
	reload_nebula_for_ca_rotation "${lighthouse_ns}" "${lighthouse_rollout_pid}" lighthouse
	reload_nebula_for_ca_rotation "${member_ns}" "${member_rollout_pid}" member
	prove_overlay_tcp_443 "${lighthouse_ns}" "${lighthouse_ip}" "${member_ip}" \
		"${member_ns}" firewall-post-runtime-member-to-lighthouse
	assert_overlay_ping_blocked "${member_ns}" "${lighthouse_ip}" \
		"${work_dir}/firewall-post-runtime-icmp-blocked.log"
	sleep 5.1
	report_ca_rotation_heartbeat "${lighthouse_state}" "${work_dir}/lighthouse-heartbeat-firewall-canary.log"
	report_ca_rotation_heartbeat "${member_state}" "${work_dir}/member-heartbeat-firewall-canary.log"
	api_request GET "/api/v1/networks/${network_id}/firewall-rollout" \
		"${work_dir}/firewall-rollout-canary-converged.json"
	assert_firewall_rollout_document "${work_dir}/firewall-rollout-canary-converged.json" canary \
		"${canary_revision}" 1 1 promote,pause,rollback "${lighthouse_id}" "${member_id}"

	firewall_rollout_action pause "${canary_revision}" \
		"${work_dir}/firewall-rollout-paused.json"
	paused_revision="$(json_field "${work_dir}/firewall-rollout-paused.json" config_revision)"
	(( paused_revision == canary_revision + 1 )) ||
		die "firewall pause did not advance exactly one revision"
	assert_firewall_rollout_document "${work_dir}/firewall-rollout-paused.json" paused \
		"${paused_revision}" 1 0 resume,rollback "${lighthouse_id}" "${member_id}"
	run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-firewall-paused.log"
	run_validation_agent "${member_state}" "${work_dir}/member-agent-firewall-paused.log"
	[[ "$(json_field "${lighthouse_state}" applied_config_revision)" == "${paused_revision}" && \
		"$(json_field "${member_state}" applied_config_revision)" == "${paused_revision}" ]] ||
		die "both agents did not apply the paused retained-policy revision"
	python3 - "${lighthouse_output}/current/config.yml" "${member_output}/current/config.yml" <<'PY'
import pathlib
import sys

full_mesh = (
    "firewall:\n"
    "  outbound:\n"
    "    - port: any\n"
    "      proto: any\n"
    "      host: any\n"
    "  inbound:\n"
    "    - port: any\n"
    "      proto: any\n"
    "      group: \"all\"\n"
)
for path in sys.argv[1:]:
    if full_mesh not in pathlib.Path(path).read_text(encoding="utf-8"):
        raise SystemExit("paused rollout did not return every selected canary to the retained policy")
PY
	reload_nebula_for_ca_rotation "${lighthouse_ns}" "${lighthouse_rollout_pid}" lighthouse
	reload_nebula_for_ca_rotation "${member_ns}" "${member_rollout_pid}" member
	wait_for_overlay_ping "${member_ns}" "${lighthouse_ip}" \
		"${work_dir}/firewall-pause-overlay-establish.log"
	prove_overlay_ping "${member_ns}" "${lighthouse_ip}" \
		"${work_dir}/firewall-pause-overlay-proof.log"

	firewall_rollout_action resume "${paused_revision}" \
		"${work_dir}/firewall-rollout-resumed.json"
	resumed_revision="$(json_field "${work_dir}/firewall-rollout-resumed.json" config_revision)"
	(( resumed_revision == paused_revision + 1 )) ||
		die "firewall resume did not advance exactly one revision"
	assert_firewall_rollout_document "${work_dir}/firewall-rollout-resumed.json" canary \
		"${resumed_revision}" 1 0 pause,rollback "${lighthouse_id}" "${member_id}"
	run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-firewall-resumed.log"
	run_validation_agent "${member_state}" "${work_dir}/member-agent-firewall-resumed.log"
	reload_nebula_for_ca_rotation "${lighthouse_ns}" "${lighthouse_rollout_pid}" lighthouse
	reload_nebula_for_ca_rotation "${member_ns}" "${member_rollout_pid}" member
	prove_overlay_tcp_443 "${lighthouse_ns}" "${lighthouse_ip}" "${member_ip}" \
		"${member_ns}" firewall-resumed-member-to-lighthouse
	assert_overlay_ping_blocked "${member_ns}" "${lighthouse_ip}" \
		"${work_dir}/firewall-resumed-icmp-blocked.log"
	report_ca_rotation_heartbeat "${lighthouse_state}" "${work_dir}/lighthouse-heartbeat-firewall-resumed.log"
	report_ca_rotation_heartbeat "${member_state}" "${work_dir}/member-heartbeat-firewall-resumed.log"
	api_request GET "/api/v1/networks/${network_id}/firewall-rollout" \
		"${work_dir}/firewall-rollout-resumed-converged.json"
	assert_firewall_rollout_document "${work_dir}/firewall-rollout-resumed-converged.json" canary \
		"${resumed_revision}" 1 1 promote,pause,rollback "${lighthouse_id}" "${member_id}"
	say "PASS: firewall pause restored the retained policy and ICMP; resume required a fresh signed revision and exact convergence"

	firewall_rollout_action rollback "${resumed_revision}" \
		"${work_dir}/firewall-rollout-rolled-back.json"
	rollback_revision="$(json_field "${work_dir}/firewall-rollout-rolled-back.json" config_revision)"
	(( rollback_revision == resumed_revision + 1 )) ||
		die "firewall rollback did not advance exactly one revision"
	assert_firewall_rollout_document "${work_dir}/firewall-rollout-rolled-back.json" stable \
		"${rollback_revision}" 0 0 start "${lighthouse_id}" "${member_id}"
	run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-firewall-rollback.log"
	run_validation_agent "${member_state}" "${work_dir}/member-agent-firewall-rollback.log"
	reload_nebula_for_ca_rotation "${lighthouse_ns}" "${lighthouse_rollout_pid}" lighthouse
	reload_nebula_for_ca_rotation "${member_ns}" "${member_rollout_pid}" member
	sleep 5.1
	report_ca_rotation_heartbeat "${lighthouse_state}" "${work_dir}/lighthouse-heartbeat-firewall-rollback.log"
	report_ca_rotation_heartbeat "${member_state}" "${work_dir}/member-heartbeat-firewall-rollback.log"
	wait_for_overlay_ping "${member_ns}" "${lighthouse_ip}" \
		"${work_dir}/firewall-rollback-overlay-establish.log"
	prove_overlay_ping "${member_ns}" "${lighthouse_ip}" \
		"${work_dir}/firewall-rollback-overlay-proof.log"

	printf \
		'{"action":"start","expected_config_revision":%s,"canary_node_ids":["%s"],"inbound":[{"proto":"tcp","port":"443","group":"all"}],"outbound":[{"proto":"tcp","port":"443","host":"any"}]}\n' \
		"${rollback_revision}" "${member_id}" >"${work_dir}/firewall-rollout-restart-request.json"
	api_request POST "/api/v1/networks/${network_id}/firewall-rollout" \
		"${work_dir}/firewall-rollout-restarted.json" "${work_dir}/firewall-rollout-restart-request.json"
	second_canary_revision="$(json_field "${work_dir}/firewall-rollout-restarted.json" config_revision)"
	(( second_canary_revision == rollback_revision + 1 )) ||
		die "second firewall canary start did not advance exactly one revision"
	run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-firewall-second-canary.log"
	run_validation_agent "${member_state}" "${work_dir}/member-agent-firewall-second-canary.log"
	reload_nebula_for_ca_rotation "${lighthouse_ns}" "${lighthouse_rollout_pid}" lighthouse
	reload_nebula_for_ca_rotation "${member_ns}" "${member_rollout_pid}" member
	sleep 5.1
	report_ca_rotation_heartbeat "${lighthouse_state}" "${work_dir}/lighthouse-heartbeat-firewall-second-canary.log"
	report_ca_rotation_heartbeat "${member_state}" "${work_dir}/member-heartbeat-firewall-second-canary.log"
	api_request GET "/api/v1/networks/${network_id}/firewall-rollout" \
		"${work_dir}/firewall-rollout-second-converged.json"
	assert_firewall_rollout_document "${work_dir}/firewall-rollout-second-converged.json" canary \
		"${second_canary_revision}" 1 1 promote,pause,rollback "${lighthouse_id}" "${member_id}"

	firewall_rollout_action promote "${second_canary_revision}" \
		"${work_dir}/firewall-rollout-promoted.json"
	promoted_revision="$(json_field "${work_dir}/firewall-rollout-promoted.json" config_revision)"
	(( promoted_revision == second_canary_revision + 1 )) ||
		die "firewall promotion did not advance exactly one revision"
	assert_firewall_rollout_document "${work_dir}/firewall-rollout-promoted.json" stable \
		"${promoted_revision}" 0 0 start "${lighthouse_id}" "${member_id}"
	run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-firewall-promoted.log"
	run_validation_agent "${member_state}" "${work_dir}/member-agent-firewall-promoted.log"
	[[ "$(json_field "${lighthouse_state}" applied_config_revision)" == "${promoted_revision}" && \
		"$(json_field "${member_state}" applied_config_revision)" == "${promoted_revision}" ]] ||
		die "both agents did not apply the promoted firewall revision"
	reload_nebula_for_ca_rotation "${lighthouse_ns}" "${lighthouse_rollout_pid}" lighthouse
	reload_nebula_for_ca_rotation "${member_ns}" "${member_rollout_pid}" member
	sleep 5.1
	report_ca_rotation_heartbeat "${lighthouse_state}" "${work_dir}/lighthouse-heartbeat-firewall-promoted.log"
	report_ca_rotation_heartbeat "${member_state}" "${work_dir}/member-heartbeat-firewall-promoted.log"
	prove_overlay_tcp_443 "${lighthouse_ns}" "${lighthouse_ip}" "${member_ip}" \
		"${member_ns}" firewall-promoted-member-to-lighthouse
	assert_overlay_ping_blocked "${member_ns}" "${lighthouse_ip}" \
		"${work_dir}/firewall-promoted-icmp-blocked.log"
	namespace_contains_pid "${lighthouse_ns}" "${lighthouse_rollout_pid}" ||
		die "lighthouse Nebula process restarted during firewall rollout"
	namespace_contains_pid "${member_ns}" "${member_rollout_pid}" ||
		die "member Nebula process restarted during firewall rollout"
	say "PASS: selected member canary received the restrictive policy while its lighthouse peer retained the known-good policy"
	say "PASS: exact signed convergence gated promotion, rollback restored ICMP, and promoted TCP-only policy blocked ICMP on both original Nebula processes"
	exit 0
fi
if [[ "${ca_rotation_smoke}" == "1" ]]; then
  say "Proving staged CA rotation with uninterrupted authenticated overlay traffic"
  lighthouse_rotation_pid="$(single_namespace_process_pid "${lighthouse_ns}" lighthouse)"
  member_rotation_pid="$(single_namespace_process_pid "${member_ns}" member)"
  initial_lighthouse_generation="$(json_field "${lighthouse_state}" certificate_generation)"
  initial_member_generation="$(json_field "${member_state}" certificate_generation)"
  require_positive_integer "${initial_lighthouse_generation}" "initial lighthouse certificate generation"
  require_positive_integer "${initial_member_generation}" "initial member certificate generation"
  "${nebula_cert}" print -json -path "${lighthouse_output}/current/ca.crt" \
    >"${work_dir}/ca-rotation-initial-ca.json"
  "${nebula_cert}" print -json -path "${lighthouse_output}/current/host.crt" \
    >"${work_dir}/ca-rotation-initial-lighthouse-host.json"
  "${nebula_cert}" print -json -path "${member_output}/current/host.crt" \
    >"${work_dir}/ca-rotation-initial-member-host.json"

  api_request GET "/api/v1/networks/${network_id}/ca-rotation" \
    "${work_dir}/ca-rotation-stable.json"
  assert_ca_rotation_document "${work_dir}/ca-rotation-stable.json" stable \
    "${initial_member_revision}" 2 prepare "${lighthouse_id}" "${member_id}"
  old_ca_digest="$(json_field "${work_dir}/ca-rotation-stable.json" active_ca_certificate_sha256)"

  start_ca_rotation_probe "${member_ns}" "${member_rotation_pid}" "${lighthouse_ip}" \
    "${work_dir}/ca-rotation-continuous-ping.log"
  sleep 0.25

  ca_rotation_action prepare "${initial_member_revision}" \
    "${work_dir}/ca-rotation-prepared.json"
  prepared_revision="$(json_field "${work_dir}/ca-rotation-prepared.json" config_revision)"
  require_positive_integer "${prepared_revision}" "prepared CA rotation revision"
  (( prepared_revision == initial_member_revision + 1 )) ||
    die "prepared CA rotation did not advance exactly one revision"
  assert_ca_rotation_document "${work_dir}/ca-rotation-prepared.json" prepared \
    "${prepared_revision}" 0 abort "${lighthouse_id}" "${member_id}"
  dual_trust_digest="$(json_field "${work_dir}/ca-rotation-prepared.json" current_trust_bundle_sha256)"
  target_ca_digest="$(json_field "${work_dir}/ca-rotation-prepared.json" target_ca_certificate_sha256)"
  [[ "${dual_trust_digest}" != "${old_ca_digest}" && "${target_ca_digest}" != "${old_ca_digest}" ]] ||
    die "prepared CA rotation did not create a distinct dual-trust transition"

  run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-ca-prepared.log"
  validate_bundle "${lighthouse_output}" "prepared CA lighthouse"
  reload_nebula_for_ca_rotation "${lighthouse_ns}" "${lighthouse_rotation_pid}" lighthouse
  prove_overlay_ping "${member_ns}" "${lighthouse_ip}" \
    "${work_dir}/ca-rotation-prepared-lighthouse-reload.log"
  report_ca_rotation_heartbeat "${lighthouse_state}" \
    "${work_dir}/lighthouse-heartbeat-ca-prepared.log"
  run_validation_agent "${member_state}" "${work_dir}/member-agent-ca-prepared.log"
  validate_bundle "${member_output}" "prepared CA member"
  reload_nebula_for_ca_rotation "${member_ns}" "${member_rotation_pid}" member
  prove_overlay_ping "${member_ns}" "${lighthouse_ip}" \
    "${work_dir}/ca-rotation-prepared-member-reload.log"
  report_ca_rotation_heartbeat "${member_state}" \
    "${work_dir}/member-heartbeat-ca-prepared.log"
  [[ "$(json_field "${lighthouse_state}" ca_certificate_sha256)" == "${dual_trust_digest}" && \
    "$(json_field "${member_state}" ca_certificate_sha256)" == "${dual_trust_digest}" ]] ||
    die "agents did not pin the prepared dual-trust bundle"
  "${nebula_cert}" print -json -path "${lighthouse_output}/current/ca.crt" \
    >"${work_dir}/ca-rotation-prepared-lighthouse-ca.json"
  "${nebula_cert}" print -json -path "${member_output}/current/ca.crt" \
    >"${work_dir}/ca-rotation-prepared-member-ca.json"
  api_request GET "/api/v1/networks/${network_id}/ca-rotation" \
    "${work_dir}/ca-rotation-prepared-converged.json"
  assert_ca_rotation_document "${work_dir}/ca-rotation-prepared-converged.json" prepared \
    "${prepared_revision}" 2 activate,abort "${lighthouse_id}" "${member_id}"

  ca_rotation_action activate "${prepared_revision}" \
    "${work_dir}/ca-rotation-activated.json"
  activated_revision="$(json_field "${work_dir}/ca-rotation-activated.json" config_revision)"
  (( activated_revision == prepared_revision + 1 )) ||
    die "activated CA rotation did not advance exactly one revision"
  assert_ca_rotation_document "${work_dir}/ca-rotation-activated.json" rotating \
    "${activated_revision}" 0 "" "${lighthouse_id}" "${member_id}"
  sleep 5.1

  run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-ca-rotating.log"
  validate_bundle "${lighthouse_output}" "rotating CA lighthouse"
  reload_nebula_for_ca_rotation "${lighthouse_ns}" "${lighthouse_rotation_pid}" lighthouse
  wait_for_overlay_ping "${member_ns}" "${lighthouse_ip}" \
    "${work_dir}/ca-rotation-mixed-cert-establish.log"
  prove_overlay_ping "${member_ns}" "${lighthouse_ip}" \
    "${work_dir}/ca-rotation-mixed-cert-proof.log"
  report_ca_rotation_heartbeat "${lighthouse_state}" \
    "${work_dir}/lighthouse-heartbeat-ca-rotating.log"
  run_validation_agent "${member_state}" "${work_dir}/member-agent-ca-rotating.log"
  validate_bundle "${member_output}" "rotating CA member"
  reload_nebula_for_ca_rotation "${member_ns}" "${member_rotation_pid}" member
  prove_overlay_ping "${member_ns}" "${lighthouse_ip}" \
    "${work_dir}/ca-rotation-new-cert-proof.log"
  report_ca_rotation_heartbeat "${member_state}" \
    "${work_dir}/member-heartbeat-ca-rotating.log"
  "${nebula_cert}" print -json -path "${lighthouse_output}/current/host.crt" \
    >"${work_dir}/ca-rotation-new-lighthouse-host.json"
  "${nebula_cert}" print -json -path "${member_output}/current/host.crt" \
    >"${work_dir}/ca-rotation-new-member-host.json"
  api_request GET "/api/v1/networks/${network_id}/ca-rotation" \
    "${work_dir}/ca-rotation-rotating-converged.json"
  assert_ca_rotation_document "${work_dir}/ca-rotation-rotating-converged.json" rotating \
    "${activated_revision}" 2 finalize "${lighthouse_id}" "${member_id}"

  ca_rotation_action finalize "${activated_revision}" \
    "${work_dir}/ca-rotation-finalizing.json"
  finalizing_revision="$(json_field "${work_dir}/ca-rotation-finalizing.json" config_revision)"
  (( finalizing_revision == activated_revision + 1 )) ||
    die "finalized CA rotation did not advance exactly one revision"
  assert_ca_rotation_document "${work_dir}/ca-rotation-finalizing.json" finalizing \
    "${finalizing_revision}" 0 "" "${lighthouse_id}" "${member_id}"
  sleep 5.1

  run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-ca-finalizing.log"
  validate_bundle "${lighthouse_output}" "finalizing CA lighthouse"
  reload_nebula_for_ca_rotation "${lighthouse_ns}" "${lighthouse_rotation_pid}" lighthouse
  prove_overlay_ping "${member_ns}" "${lighthouse_ip}" \
    "${work_dir}/ca-rotation-finalizing-lighthouse-reload.log"
  report_ca_rotation_heartbeat "${lighthouse_state}" \
    "${work_dir}/lighthouse-heartbeat-ca-finalizing.log"
  run_validation_agent "${member_state}" "${work_dir}/member-agent-ca-finalizing.log"
  validate_bundle "${member_output}" "finalizing CA member"
  reload_nebula_for_ca_rotation "${member_ns}" "${member_rotation_pid}" member
  prove_overlay_ping "${member_ns}" "${lighthouse_ip}" \
    "${work_dir}/ca-rotation-finalizing-member-reload.log"
  report_ca_rotation_heartbeat "${member_state}" \
    "${work_dir}/member-heartbeat-ca-finalizing.log"
  "${nebula_cert}" print -json -path "${lighthouse_output}/current/ca.crt" \
    >"${work_dir}/ca-rotation-final-lighthouse-ca.json"
  "${nebula_cert}" print -json -path "${member_output}/current/ca.crt" \
    >"${work_dir}/ca-rotation-final-member-ca.json"
  api_request GET "/api/v1/networks/${network_id}/ca-rotation" \
    "${work_dir}/ca-rotation-finalizing-converged.json"
  assert_ca_rotation_document "${work_dir}/ca-rotation-finalizing-converged.json" finalizing \
    "${finalizing_revision}" 2 complete "${lighthouse_id}" "${member_id}"

  ca_rotation_action complete "${finalizing_revision}" \
    "${work_dir}/ca-rotation-completed.json"
  completed_revision="$(json_field "${work_dir}/ca-rotation-completed.json" config_revision)"
  (( completed_revision == finalizing_revision + 1 )) ||
    die "completed CA rotation did not advance exactly one revision"
  assert_ca_rotation_document "${work_dir}/ca-rotation-completed.json" stable \
    "${completed_revision}" 2 prepare "${lighthouse_id}" "${member_id}"
  sleep 5.1
  run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-ca-completed.log"
  reload_nebula_for_ca_rotation "${lighthouse_ns}" "${lighthouse_rotation_pid}" lighthouse
  prove_overlay_ping "${member_ns}" "${lighthouse_ip}" \
    "${work_dir}/ca-rotation-completed-lighthouse-reload.log"
  report_ca_rotation_heartbeat "${lighthouse_state}" \
    "${work_dir}/lighthouse-heartbeat-ca-completed.log"
  run_validation_agent "${member_state}" "${work_dir}/member-agent-ca-completed.log"
  reload_nebula_for_ca_rotation "${member_ns}" "${member_rotation_pid}" member
  prove_overlay_ping "${member_ns}" "${lighthouse_ip}" \
    "${work_dir}/ca-rotation-completed-proof.log"
  report_ca_rotation_heartbeat "${member_state}" \
    "${work_dir}/member-heartbeat-ca-completed.log"
  api_request GET "/api/v1/networks/${network_id}/ca-rotation" \
    "${work_dir}/ca-rotation-stable-final.json"
  assert_ca_rotation_document "${work_dir}/ca-rotation-stable-final.json" stable \
    "${completed_revision}" 2 prepare "${lighthouse_id}" "${member_id}"
  stop_and_assert_ca_rotation_probe "${work_dir}/ca-rotation-continuous-ping.log"

  python3 - \
    "${work_dir}/ca-rotation-stable.json" \
    "${work_dir}/ca-rotation-prepared.json" \
    "${work_dir}/ca-rotation-activated.json" \
    "${work_dir}/ca-rotation-finalizing.json" \
    "${work_dir}/ca-rotation-stable-final.json" \
    "${work_dir}/ca-rotation-initial-ca.json" \
    "${work_dir}/ca-rotation-prepared-lighthouse-ca.json" \
    "${work_dir}/ca-rotation-prepared-member-ca.json" \
    "${work_dir}/ca-rotation-final-lighthouse-ca.json" \
    "${work_dir}/ca-rotation-final-member-ca.json" \
    "${work_dir}/ca-rotation-initial-lighthouse-host.json" \
    "${work_dir}/ca-rotation-initial-member-host.json" \
    "${work_dir}/ca-rotation-new-lighthouse-host.json" \
    "${work_dir}/ca-rotation-new-member-host.json" \
    "${lighthouse_state}" "${member_state}" \
    "${initial_lighthouse_generation}" "${initial_member_generation}" \
    "${completed_revision}" <<'PY'
import json
import pathlib
import sys

paths = sys.argv[1:17]
(
    stable, prepared, activated, finalizing, completed,
    initial_ca, prepared_lighthouse_ca, prepared_member_ca,
    final_lighthouse_ca, final_member_ca,
    initial_lighthouse_host, initial_member_host,
    new_lighthouse_host, new_member_host,
    lighthouse_state, member_state,
) = [json.loads(pathlib.Path(path).read_text(encoding="utf-8")) for path in paths]
initial_lighthouse_generation = int(sys.argv[17])
initial_member_generation = int(sys.argv[18])
completed_revision = int(sys.argv[19])

old_digest = stable["active_ca_certificate_sha256"]
target_digest = prepared["target_ca_certificate_sha256"]
dual_digest = prepared["current_trust_bundle_sha256"]
if stable["current_trust_bundle_sha256"] != old_digest or stable["previous_trust_bundle_sha256"] or stable["target_ca_certificate_sha256"]:
    raise SystemExit("stable pre-rotation trust evidence is inconsistent")
if prepared["active_ca_certificate_sha256"] != old_digest or prepared["previous_trust_bundle_sha256"] != old_digest or target_digest == old_digest or dual_digest in (old_digest, target_digest):
    raise SystemExit("prepared dual-trust evidence is inconsistent")
if activated["current_trust_bundle_sha256"] != dual_digest or activated["target_ca_certificate_sha256"] != target_digest:
    raise SystemExit("activated CA evidence changed the prepared trust bundle")
if finalizing["active_ca_certificate_sha256"] != target_digest or finalizing["current_trust_bundle_sha256"] != target_digest or finalizing["previous_trust_bundle_sha256"] != dual_digest:
    raise SystemExit("finalizing CA evidence did not remove the old root")
if completed["active_ca_certificate_sha256"] != target_digest or completed["current_trust_bundle_sha256"] != target_digest or completed["previous_trust_bundle_sha256"] or completed["target_ca_certificate_sha256"]:
    raise SystemExit("completed CA evidence retained transition metadata")

def one(items, label):
    if not isinstance(items, list) or len(items) != 1:
        raise SystemExit(f"{label} did not contain exactly one certificate")
    return items[0]

old_ca = one(initial_ca, "initial CA")
if len(prepared_lighthouse_ca) != 2 or len(prepared_member_ca) != 2:
    raise SystemExit("prepared agents did not install exactly two trusted CAs")
if [item["fingerprint"] for item in prepared_lighthouse_ca] != [item["fingerprint"] for item in prepared_member_ca]:
    raise SystemExit("prepared agents installed different CA trust order")
if prepared_lighthouse_ca[0]["fingerprint"] != old_ca["fingerprint"]:
    raise SystemExit("prepared trust bundle did not preserve the old CA first")
new_ca = one(final_lighthouse_ca, "final lighthouse CA")
if one(final_member_ca, "final member CA")["fingerprint"] != new_ca["fingerprint"] or new_ca["fingerprint"] == old_ca["fingerprint"]:
    raise SystemExit("final agents did not converge on one distinct replacement CA")
for initial_host in (initial_lighthouse_host, initial_member_host):
    if one(initial_host, "initial host certificate")["details"]["issuer"] != old_ca["fingerprint"]:
        raise SystemExit("initial host certificate was not issued by the old CA")
for new_host in (new_lighthouse_host, new_member_host):
    if one(new_host, "replacement host certificate")["details"]["issuer"] != new_ca["fingerprint"]:
        raise SystemExit("replacement host certificate was not issued by the new CA")
for state, initial_generation, label in (
    (lighthouse_state, initial_lighthouse_generation, "lighthouse"),
    (member_state, initial_member_generation, "member"),
):
    if state["certificate_generation"] != initial_generation + 1:
        raise SystemExit(f"{label} did not install exactly one replacement certificate")
    if state["ca_certificate_sha256"] != target_digest or state["applied_config_revision"] != completed_revision:
        raise SystemExit(f"{label} did not persist completed CA trust and revision")
PY
  namespace_contains_pid "${lighthouse_ns}" "${lighthouse_rotation_pid}" ||
    die "lighthouse Nebula process restarted during CA rotation"
  namespace_contains_pid "${member_ns}" "${member_rotation_pid}" ||
    die "member Nebula process restarted during CA rotation"
  say "PASS: prepare, activate, finalize, and complete converged both real agents on one replacement CA"
  say "PASS: one continuous authenticated ICMP stream lost zero packets while both original Nebula processes reloaded every trust stage"
  exit 0
fi
if [[ "${relay_smoke}" == "1" ]]; then
  exit 0
fi
if [[ "${observer_multilighthouse_smoke}" == "1" ]]; then
  wait_for_overlay_ping "${member_ns}" "${second_lighthouse_ip}" \
    "${work_dir}/second-lighthouse-overlay-establish.log"
  prove_overlay_ping "${member_ns}" "${second_lighthouse_ip}" \
    "${work_dir}/second-lighthouse-overlay-proof.log"
  namespace_has_process "${second_lighthouse_ns}" || die "second lighthouse Nebula exited after packet proof"
fi
if [[ "${multimember_smoke}" == "1" ]]; then
  wait_for_overlay_ping "${second_member_ns}" "${lighthouse_ip}" \
    "${work_dir}/second-member-first-lighthouse-establish.log"
  prove_overlay_ping "${second_member_ns}" "${lighthouse_ip}" \
    "${work_dir}/second-member-first-lighthouse-proof.log"
  wait_for_overlay_ping "${second_member_ns}" "${second_lighthouse_ip}" \
    "${work_dir}/second-member-second-lighthouse-establish.log"
  prove_overlay_ping "${second_member_ns}" "${second_lighthouse_ip}" \
    "${work_dir}/second-member-second-lighthouse-proof.log"
  namespace_has_process "${second_member_ns}" || die "second member Nebula exited after packet proof"
fi
if [[ "${public_endpoint_smoke}" == "1" ]]; then
  assert_public_edge_dnat "${first_edge_ns}" "${first_lighthouse_endpoint_ip}" 10.200.10.2 first
  assert_public_edge_dnat "${second_edge_ns}" "${second_lighthouse_endpoint_ip}" 10.200.20.2 second
  say "PASS: both public UDP endpoints forwarded authenticated Nebula traffic through independent edge DNAT rules"
fi
namespace_has_process "${lighthouse_ns}" || die "lighthouse Nebula exited after packet proof"
namespace_has_process "${member_ns}" || die "member Nebula exited after packet proof"
if [[ "${observer_smoke}" == "1" ]]; then
  say "Proving observer handshake, authenticated-RX, topology, and sequence evidence"
  if [[ "${observer_multilighthouse_smoke}" == "1" ]]; then
    capture_observer_snapshot "${member_nebula_pid}" "${overlay_cidr}" \
      "${work_dir}/observer-member-initial-1.json" "${lighthouse_ip}" "${second_lighthouse_ip}"
    capture_observer_snapshot "${member_nebula_pid}" "${overlay_cidr}" \
      "${work_dir}/observer-member-initial-2.json" "${lighthouse_ip}" "${second_lighthouse_ip}"
    assert_initial_multilighthouse_observer_snapshots \
      "${work_dir}/observer-member-initial-1.json" \
      "${work_dir}/observer-member-initial-2.json" \
      "${lighthouse_ip}" "${second_lighthouse_ip}"
    if [[ "${multimember_smoke}" == "1" ]]; then
      capture_observer_snapshot "${second_member_nebula_pid}" "${overlay_cidr}" \
        "${work_dir}/observer-second-member-initial-1.json" "${lighthouse_ip}" "${second_lighthouse_ip}"
      capture_observer_snapshot "${second_member_nebula_pid}" "${overlay_cidr}" \
        "${work_dir}/observer-second-member-initial-2.json" "${lighthouse_ip}" "${second_lighthouse_ip}"
      assert_initial_multilighthouse_observer_snapshots \
        "${work_dir}/observer-second-member-initial-1.json" \
        "${work_dir}/observer-second-member-initial-2.json" \
        "${lighthouse_ip}" "${second_lighthouse_ip}"
    fi

    say "Proving a same-domain placement mistake warns without changing signed state or live tunnels"
    api_request GET "/api/v1/networks" "${work_dir}/multisite-networks-before-placement.json"
    placement_revision="$(network_field "${work_dir}/multisite-networks-before-placement.json" "${network_name}" config_revision)"
    require_positive_integer "${placement_revision}" "pre-placement network revision"
    printf '%s\n' \
      '{"site":"packet-site-b","failure_domain":"packet-domain-a"}' \
      >"${work_dir}/second-lighthouse-topology-shared.json"
    api_request PUT "/api/v1/nodes/${second_lighthouse_id}/topology" \
      "${work_dir}/second-lighthouse-topology-shared-result.json" \
      "${work_dir}/second-lighthouse-topology-shared.json"
    [[ "$(json_field "${work_dir}/second-lighthouse-topology-shared-result.json" failure_domain)" == "packet-domain-a" ]] ||
      die "second lighthouse did not enter the deliberate shared failure domain"
    api_request GET "/api/v1/networks/${network_id}/readiness" \
      "${work_dir}/multisite-readiness-shared-domain.json"
    assert_same_domain_topology_warning "${work_dir}/multisite-readiness-shared-domain.json"
    api_request GET "/api/v1/networks" "${work_dir}/multisite-networks-shared-domain.json"
    [[ "$(network_field "${work_dir}/multisite-networks-shared-domain.json" "${network_name}" config_revision)" == "${placement_revision}" ]] ||
      die "topology-only update changed the signed network revision"
    prove_overlay_ping "${member_ns}" "${lighthouse_ip}" \
      "${work_dir}/same-domain-first-lighthouse-proof.log"
    prove_overlay_ping "${member_ns}" "${second_lighthouse_ip}" \
      "${work_dir}/same-domain-second-lighthouse-proof.log"
    if [[ "${multimember_smoke}" == "1" ]]; then
      prove_overlay_ping "${second_member_ns}" "${lighthouse_ip}" \
        "${work_dir}/same-domain-second-member-first-lighthouse-proof.log"
      prove_overlay_ping "${second_member_ns}" "${second_lighthouse_ip}" \
        "${work_dir}/same-domain-second-member-second-lighthouse-proof.log"
    fi
    capture_observer_snapshot "${member_nebula_pid}" "${overlay_cidr}" \
      "${work_dir}/observer-member-same-domain.json" \
      "${lighthouse_ip}" "${second_lighthouse_ip}"
    assert_initial_multilighthouse_observer_snapshots \
      "${work_dir}/observer-member-initial-2.json" \
      "${work_dir}/observer-member-same-domain.json" \
      "${lighthouse_ip}" "${second_lighthouse_ip}"
    if [[ "${multimember_smoke}" == "1" ]]; then
      capture_observer_snapshot "${second_member_nebula_pid}" "${overlay_cidr}" \
        "${work_dir}/observer-second-member-same-domain.json" \
        "${lighthouse_ip}" "${second_lighthouse_ip}"
      assert_initial_multilighthouse_observer_snapshots \
        "${work_dir}/observer-second-member-initial-2.json" \
        "${work_dir}/observer-second-member-same-domain.json" \
        "${lighthouse_ip}" "${second_lighthouse_ip}"
    fi

    printf '%s\n' \
      '{"site":"packet-site-b","failure_domain":"packet-domain-b"}' \
      >"${work_dir}/second-lighthouse-topology-restored.json"
    api_request PUT "/api/v1/nodes/${second_lighthouse_id}/topology" \
      "${work_dir}/second-lighthouse-topology-restored-result.json" \
      "${work_dir}/second-lighthouse-topology-restored.json"
    [[ "$(json_field "${work_dir}/second-lighthouse-topology-restored-result.json" failure_domain)" == "packet-domain-b" ]] ||
      die "second lighthouse did not restore its independent failure domain"
    api_request GET "/api/v1/networks/${network_id}/readiness" \
      "${work_dir}/multisite-readiness-domain-restored.json"
    assert_multisite_topology_readiness "${work_dir}/multisite-readiness-domain-restored.json"
    api_request GET "/api/v1/networks" "${work_dir}/multisite-networks-domain-restored.json"
    [[ "$(network_field "${work_dir}/multisite-networks-domain-restored.json" "${network_name}" config_revision)" == "${placement_revision}" ]] ||
      die "restoring topology changed the signed network revision"
    capture_observer_snapshot "${member_nebula_pid}" "${overlay_cidr}" \
      "${work_dir}/observer-member-domain-restored.json" \
      "${lighthouse_ip}" "${second_lighthouse_ip}"
    assert_initial_multilighthouse_observer_snapshots \
      "${work_dir}/observer-member-same-domain.json" \
      "${work_dir}/observer-member-domain-restored.json" \
      "${lighthouse_ip}" "${second_lighthouse_ip}"
    if [[ "${multimember_smoke}" == "1" ]]; then
      capture_observer_snapshot "${second_member_nebula_pid}" "${overlay_cidr}" \
        "${work_dir}/observer-second-member-domain-restored.json" \
        "${lighthouse_ip}" "${second_lighthouse_ip}"
      assert_initial_multilighthouse_observer_snapshots \
        "${work_dir}/observer-second-member-same-domain.json" \
        "${work_dir}/observer-second-member-domain-restored.json" \
        "${lighthouse_ip}" "${second_lighthouse_ip}"
    fi
    say "PASS: same-domain placement warned, independent placement recovered, and neither update changed signed state or tunnel continuity"

    if [[ "${active_probe_smoke}" == "1" ]]; then
      say "Proving every zero-capability member receives authenticated replies from both failure-domain lighthouses"
      run_root ip netns exec "${member_ns}" \
        sysctl -q -w "net.ipv4.ping_group_range=0 2147483647"
      run_active_probe_cycle multisite-member-a shared
      assert_active_probe_projection multisite-member-a attempted observed 2 2 0
      assert_active_probe_capture multisite-member-a minimum 2
      if [[ "${multimember_smoke}" == "1" ]]; then
        run_root ip netns exec "${second_member_ns}" \
          sysctl -q -w "net.ipv4.ping_group_range=0 2147483647"
        run_active_probe_cycle multisite-member-b shared \
          "${second_member_ns}" "${second_member_overlay_device}" "${second_member_ip}" \
          "${second_member_nebula_pid}" "${second_member_state}"
        assert_active_probe_projection multisite-member-b attempted observed 2 2 0 "${second_member_id}"
        assert_active_probe_capture multisite-member-b minimum 2
      fi
      api_request GET "/api/v1/networks/${network_id}/readiness" \
        "${work_dir}/multisite-readiness-public-udp.json"
      assert_multisite_udp_readiness "${work_dir}/multisite-readiness-public-udp.json"
      say "PASS: every current member published fresh authenticated replies from both active lighthouse failure domains"
    fi

    if [[ "${multimember_smoke}" == "1" ]]; then
      if [[ "${public_endpoint_smoke}" == "1" ]]; then
        say "Isolating packet-site-a behind its public edge while continuously proving packet-site-c through packet-site-b"
        run_root ip -n "${first_edge_ns}" link set lan0 down
      else
        say "Isolating both packet-site-a nodes while continuously proving packet-site-c through packet-site-b"
        run_root ip -n "${lighthouse_ns}" link set underlay0 down
      fi
      run_root ip -n "${second_member_ns}" link set underlay0 down
      run_root ip -n "${second_member_ns}" link set underlay1 down
    else
      say "Severing one lighthouse underlay while continuously proving the other"
      run_root ip -n "${member_ns}" link set underlay0 down
    fi
    wait_for_multilighthouse_degraded "${member_nebula_pid}" "${overlay_cidr}" \
      "${work_dir}/observer-member-multi-degraded.json" \
      "${lighthouse_ip}" "${second_lighthouse_ip}"
    member_degraded_recovery_path="${work_dir}/observer-member-multi-degraded.json"
    if [[ "${multimember_smoke}" == "1" ]]; then
      wait_for_multimember_site_loss "${second_member_nebula_pid}" "${overlay_cidr}" \
        "${work_dir}/observer-second-member-site-lost.json"
    fi
    api_request GET "/api/v1/networks/${network_id}/readiness" \
      "${work_dir}/multisite-readiness-degraded.json"
    api_request GET "/api/v1/networks/${network_id}/nodes" \
      "${work_dir}/multisite-nodes-degraded.json"
    if [[ "${multimember_smoke}" == "1" ]]; then
      assert_multimember_site_loss \
        "${work_dir}/multisite-readiness-degraded.json" \
        "${work_dir}/multisite-nodes-degraded.json" \
        "${work_dir}/observer-member-multi-degraded.json" \
        "${work_dir}/observer-second-member-site-lost.json"
      wait_until_active_probe_due "${member_state}"
      run_active_probe_cycle multisite-site-loss shared
      assert_active_probe_projection multisite-site-loss attempted observed 2 1 0
      assert_active_probe_capture multisite-site-loss minimum 2
      api_request GET "/api/v1/networks/${network_id}/readiness" \
        "${work_dir}/multisite-readiness-site-loss-udp.json"
      assert_multimember_udp_unknown "${work_dir}/multisite-readiness-site-loss-udp.json"
      capture_observer_snapshot "${member_nebula_pid}" "${overlay_cidr}" \
        "${work_dir}/observer-member-site-loss-post-probe.json" \
        "${lighthouse_ip}" "${second_lighthouse_ip}"
      multilighthouse_snapshot_is_degraded \
        "${work_dir}/observer-member-site-loss-post-probe.json" "${second_lighthouse_ip}" ||
        die "unaffected member did not remain on only packet-site-b after its degraded active probe"
      member_degraded_recovery_path="${work_dir}/observer-member-site-loss-post-probe.json"
    else
      assert_multisite_failure_domain_loss \
        "${work_dir}/multisite-readiness-degraded.json" \
        "${work_dir}/multisite-nodes-degraded.json" \
        "${work_dir}/observer-member-multi-degraded.json" \
        "${lighthouse_ip}" "${second_lighthouse_ip}"
    fi
    namespace_has_process "${lighthouse_ns}" || die "first lighthouse Nebula exited during isolated underlay loss"
    namespace_has_process "${second_lighthouse_ns}" || die "second lighthouse Nebula exited during isolated underlay loss"
    namespace_has_process "${member_ns}" || die "member Nebula exited during isolated underlay loss"
    if [[ "${multimember_smoke}" == "1" ]]; then
      namespace_has_process "${second_member_ns}" || die "second member Nebula exited during site-wide underlay loss"
    fi

    if [[ "${multimember_smoke}" == "1" ]]; then
      if [[ "${public_endpoint_smoke}" == "1" ]]; then
        say "Restoring packet-site-a behind the same public edge without restarting either Nebula process"
        run_root ip -n "${first_edge_ns}" link set lan0 up
      else
        say "Restoring both packet-site-a nodes without restarting either Nebula process"
        run_root ip -n "${lighthouse_ns}" link set underlay0 up
      fi
      run_root ip -n "${second_member_ns}" link set underlay0 up
      run_root ip -n "${second_member_ns}" link set underlay1 up
    else
      say "Restoring the failed lighthouse underlay in the same member process"
      run_root ip -n "${member_ns}" link set underlay0 up
    fi
    if [[ "${multimember_smoke}" == "1" ]]; then
      run_root ip netns exec "${member_ns}" ping -n -c 1 -W 2 "${first_lighthouse_endpoint_ip}" \
        >"${work_dir}/underlay-recovered-member-first-lighthouse.log" 2>&1 ||
        die "packet-site-c did not regain the first lighthouse underlay"
      run_root ip netns exec "${second_member_ns}" ping -n -c 1 -W 2 "${first_lighthouse_endpoint_ip}" \
        >"${work_dir}/underlay-recovered-second-member-first-lighthouse.log" 2>&1 ||
        die "packet-site-a member did not regain its local lighthouse underlay"
      run_root ip netns exec "${second_member_ns}" ping -n -c 1 -W 2 "${second_lighthouse_endpoint_ip}" \
        >"${work_dir}/underlay-recovered-second-member-second-lighthouse.log" 2>&1 ||
        die "packet-site-a member did not regain the remote lighthouse underlay"
    fi
    wait_for_overlay_ping "${member_ns}" "${lighthouse_ip}" \
      "${work_dir}/multi-first-lighthouse-recovery-establish.log"
    prove_overlay_ping "${member_ns}" "${lighthouse_ip}" \
      "${work_dir}/multi-first-lighthouse-recovery-proof.log"
    prove_overlay_ping "${member_ns}" "${second_lighthouse_ip}" \
      "${work_dir}/multi-second-lighthouse-recovery-proof.log"
    if [[ "${multimember_smoke}" == "1" ]]; then
      wait_for_overlay_ping "${second_member_ns}" "${lighthouse_ip}" \
        "${work_dir}/second-member-first-lighthouse-recovery-establish.log"
      prove_overlay_ping "${second_member_ns}" "${lighthouse_ip}" \
        "${work_dir}/second-member-first-lighthouse-recovery-proof.log"
      wait_for_overlay_ping "${second_member_ns}" "${second_lighthouse_ip}" \
        "${work_dir}/second-member-second-lighthouse-recovery-establish.log"
      prove_overlay_ping "${second_member_ns}" "${second_lighthouse_ip}" \
        "${work_dir}/second-member-second-lighthouse-recovery-proof.log"
    fi
    capture_observer_snapshot "${member_nebula_pid}" "${overlay_cidr}" \
      "${work_dir}/observer-member-multi-recovered.json" \
      "${lighthouse_ip}" "${second_lighthouse_ip}"
    assert_multilighthouse_recovered \
      "${work_dir}/observer-member-initial-2.json" \
      "${member_degraded_recovery_path}" \
      "${work_dir}/observer-member-multi-recovered.json" \
      "${lighthouse_ip}" "${second_lighthouse_ip}"
    if [[ "${multimember_smoke}" == "1" ]]; then
      capture_observer_snapshot "${second_member_nebula_pid}" "${overlay_cidr}" \
        "${work_dir}/observer-second-member-site-recovered.json" \
        "${lighthouse_ip}" "${second_lighthouse_ip}"
      assert_multilighthouse_recovered \
        "${work_dir}/observer-second-member-domain-restored.json" \
        "${work_dir}/observer-second-member-site-lost.json" \
        "${work_dir}/observer-second-member-site-recovered.json" \
        "${lighthouse_ip}" "${second_lighthouse_ip}"
      wait_until_active_probe_due "${member_state}"
      run_active_probe_cycle multisite-recovered-member-a shared
      assert_active_probe_projection multisite-recovered-member-a attempted observed 2 2 0
      assert_active_probe_capture multisite-recovered-member-a minimum 2
      wait_until_active_probe_due "${second_member_state}"
      run_active_probe_cycle multisite-recovered-member-b shared \
        "${second_member_ns}" "${second_member_overlay_device}" "${second_member_ip}" \
        "${second_member_nebula_pid}" "${second_member_state}"
      assert_active_probe_projection multisite-recovered-member-b attempted observed 2 2 0 "${second_member_id}"
      assert_active_probe_capture multisite-recovered-member-b minimum 2
    fi
    api_request GET "/api/v1/networks/${network_id}/readiness" \
      "${work_dir}/multisite-readiness-recovered.json"
    if [[ "${multimember_smoke}" == "1" ]]; then
      assert_multisite_udp_readiness "${work_dir}/multisite-readiness-recovered.json"
      say "PASS: the two-node packet-site-a loss isolated its member, packet-site-c retained packet-site-b, and both unchanged member processes recovered all tunnels and readiness"
    else
      assert_multisite_topology_readiness "${work_dir}/multisite-readiness-recovered.json"
      say "PASS: readiness-v6 declared two independent lighthouse failure domains, observer evidence isolated packet-domain-a loss, and the same member process recovered both tunnels"
    fi

    say "Activating seven additional non-running lighthouses for bounded overflow proof"
    declare -a overflow_lighthouse_ips=("${lighthouse_ip}" "${second_lighthouse_ip}")
    for overflow_index in {3..9}; do
      printf '{"name":"packet-lighthouse-%d","site":"packet-overflow","failure_domain":"packet-overflow-%d","role":"lighthouse","public_endpoint":"203.0.113.%d:4242"}\n' \
        "${overflow_index}" "${overflow_index}" "${overflow_index}" \
        >"${work_dir}/overflow-lighthouse-${overflow_index}-create.json"
      api_request POST "/api/v1/networks/${network_id}/nodes" \
        "${work_dir}/overflow-lighthouse-${overflow_index}-created.json" \
        "${work_dir}/overflow-lighthouse-${overflow_index}-create.json"
      overflow_lighthouse_id="$(json_field "${work_dir}/overflow-lighthouse-${overflow_index}-created.json" node.id)"
      overflow_lighthouse_ip="$(json_field "${work_dir}/overflow-lighthouse-${overflow_index}-created.json" node.ip)"
      overflow_lighthouse_enrollment_token="$(json_field \
        "${work_dir}/overflow-lighthouse-${overflow_index}-created.json" enrollment_token)"
      require_id "${overflow_lighthouse_id}" "overflow lighthouse ${overflow_index} ID"
      require_overlay_ipv4 "${overflow_lighthouse_ip}" "${overlay_cidr}" \
        "overflow lighthouse ${overflow_index} overlay IP"
      require_bearer "${overflow_lighthouse_enrollment_token}" \
        "overflow lighthouse ${overflow_index} enrollment token"
      for existing_lighthouse_ip in "${overflow_lighthouse_ips[@]}"; do
        [[ "${overflow_lighthouse_ip}" != "${existing_lighthouse_ip}" ]] ||
          die "control plane reused an overflow lighthouse overlay address"
      done
      overflow_lighthouse_root="${work_dir}/nodes/overflow-lighthouse-${overflow_index}"
      overflow_lighthouse_state="${overflow_lighthouse_root}/state.json"
      overflow_lighthouse_output="${overflow_lighthouse_root}/nebula"
      enroll_node "${overflow_lighthouse_enrollment_token}" \
        "${overflow_lighthouse_state}" "${overflow_lighthouse_output}" \
        "${work_dir}/overflow-lighthouse-${overflow_index}-enroll.log"
      validate_bundle "${overflow_lighthouse_output}" "overflow lighthouse ${overflow_index}"
      overflow_lighthouse_ips+=("${overflow_lighthouse_ip}")
      unset overflow_lighthouse_enrollment_token
    done

    run_validation_agent "${member_state}" "${work_dir}/member-agent-overflow.log"
    overflow_member_revision="$(json_field "${member_state}" applied_config_revision)"
    require_positive_integer "${overflow_member_revision}" "overflow member revision"
    (( overflow_member_revision > initial_member_revision )) ||
      die "member did not advance to the nine-lighthouse signed revision"
    python3 - "${member_output}/current/config.yml" "${overflow_lighthouse_ips[@]}" <<'PY'
import json
import pathlib
import re
import sys

config_path = pathlib.Path(sys.argv[1])
expected = set(sys.argv[2:])
if len(expected) != 9:
    raise SystemExit("overflow config assertion did not receive nine unique lighthouse addresses")
lines = config_path.read_text(encoding="utf-8").splitlines()
try:
    static_start = lines.index("static_host_map:")
    lighthouse_start = lines.index("lighthouse:")
    listen_start = lines.index("listen:")
except ValueError as exc:
    raise SystemExit(f"signed member config omitted a required section: {exc}")
if not (static_start < lighthouse_start < listen_start):
    raise SystemExit("signed member config sections are not canonically ordered")
static_pattern = re.compile(r'^  ("[^"]+"): \["[^"]+"\]$')
static_hosts = []
for line in lines[static_start + 1:lighthouse_start]:
    match = static_pattern.fullmatch(line)
    if match is None:
        raise SystemExit("signed member config has a noncanonical static-host-map entry")
    static_hosts.append(json.loads(match.group(1)))
try:
    hosts_start = lines.index("  hosts:", lighthouse_start + 1, listen_start)
except ValueError:
    raise SystemExit("signed member config omitted lighthouse.hosts")
host_pattern = re.compile(r'^    - ("[^"]+")$')
lighthouse_hosts = []
for line in lines[hosts_start + 1:listen_start]:
    match = host_pattern.fullmatch(line)
    if match is None:
        raise SystemExit("signed member config has a noncanonical lighthouse.hosts entry")
    lighthouse_hosts.append(json.loads(match.group(1)))
if len(static_hosts) != 9 or len(set(static_hosts)) != 9 or set(static_hosts) != expected:
    raise SystemExit("signed member config does not contain the exact nine static lighthouse maps")
if len(lighthouse_hosts) != 9 or len(set(lighthouse_hosts)) != 9 or set(lighthouse_hosts) != expected:
    raise SystemExit("signed member config does not contain the exact nine lighthouse hosts")
PY

    say "Restarting only the member on the signed nine-lighthouse revision"
    stop_namespace_processes "${member_ns}"
    namespace_has_process "${member_ns}" && die "member Nebula survived the overflow restart boundary"
    if [[ -n "${member_launcher_pid}" ]]; then
      wait "${member_launcher_pid}" 2>/dev/null || true
      member_launcher_pid=""
    fi
    member_nebula_pid=""
    start_nebula "${member_ns}" "${member_output}/current/config.yml" \
      "${work_dir}/member-nebula-overflow.log" member_launcher_pid
    member_overlay_device="$(wait_for_overlay "${member_ns}" "${member_ip}" overflow-member)"
    assert_overlay_route "${member_ns}" "${member_ip}" "${lighthouse_ip}" \
      "${member_overlay_device}" overflow-member-to-first-lighthouse
    assert_overlay_route "${member_ns}" "${member_ip}" "${second_lighthouse_ip}" \
      "${member_overlay_device}" overflow-member-to-second-lighthouse
    wait_for_overlay_ping "${member_ns}" "${lighthouse_ip}" \
      "${work_dir}/overflow-first-lighthouse-establish.log"
    prove_overlay_ping "${member_ns}" "${lighthouse_ip}" \
      "${work_dir}/overflow-first-lighthouse-proof.log"
    wait_for_overlay_ping "${member_ns}" "${second_lighthouse_ip}" \
      "${work_dir}/overflow-second-lighthouse-establish.log"
    prove_overlay_ping "${member_ns}" "${second_lighthouse_ip}" \
      "${work_dir}/overflow-second-lighthouse-proof.log"
    capture_observer_snapshot "${member_nebula_pid}" "${overlay_cidr}" \
      "${work_dir}/observer-member-overflow.json" "${overflow_lighthouse_ips[@]}"
    assert_multilighthouse_overflow_snapshot \
      "${work_dir}/observer-member-overflow.json" \
      "${lighthouse_ip}" "${second_lighthouse_ip}" "${overflow_lighthouse_ips[@]:2}"
    namespace_has_process "${lighthouse_ns}" || die "first lighthouse exited during overflow proof"
    namespace_has_process "${second_lighthouse_ns}" || die "second lighthouse exited during overflow proof"
    namespace_has_process "${member_ns}" || die "member exited during overflow proof"

    say "PASS: two active lighthouses produced exact authenticated observer aggregates"
    if [[ "${multimember_smoke}" == "1" ]]; then
      say "PASS: a two-node site failed and recovered while the unaffected member stayed authenticated through the other site"
    else
      say "PASS: one lighthouse underlay failed and recovered while the other stayed authenticated"
    fi
    say "PASS: nine configured lighthouses produced bounded overflow with only two live entries"
    exit 0
  else
    capture_observer_snapshot "${member_nebula_pid}" "${overlay_cidr}" \
      "${work_dir}/observer-member-initial-1.json" "${lighthouse_ip}"
    capture_observer_snapshot "${member_nebula_pid}" "${overlay_cidr}" \
      "${work_dir}/observer-member-initial-2.json" "${lighthouse_ip}"
    capture_observer_snapshot "${lighthouse_nebula_pid}" "${overlay_cidr}" \
      "${work_dir}/observer-lighthouse-initial.json"
    assert_initial_observer_snapshots \
      "${work_dir}/observer-member-initial-1.json" \
      "${work_dir}/observer-member-initial-2.json" \
      "${work_dir}/observer-lighthouse-initial.json" \
      "${lighthouse_ip}"
  fi
  if [[ "${observer_outage_smoke}" == "1" ]]; then
    say "Severing only the underlay until Nebula evicts the tunnel and a handshake times out"
    run_root ip -n "${member_ns}" link set underlay0 down
    wait_for_observer_outage "${member_nebula_pid}" "${overlay_cidr}" \
      "${work_dir}/observer-member-outage.json" "${lighthouse_ip}"
    namespace_has_process "${lighthouse_ns}" || die "lighthouse Nebula exited during underlay-outage proof"
    namespace_has_process "${member_ns}" || die "member Nebula exited during underlay-outage proof"
    say "Restoring the underlay and proving a fresh handshake plus authenticated-RX recovery"
    run_root ip -n "${member_ns}" link set underlay0 up
    wait_for_overlay_ping "${member_ns}" "${lighthouse_ip}" \
      "${work_dir}/observer-recovery-establish.log"
    prove_overlay_ping "${member_ns}" "${lighthouse_ip}" \
      "${work_dir}/observer-recovery-proof.log"
    capture_observer_snapshot "${member_nebula_pid}" "${overlay_cidr}" \
      "${work_dir}/observer-member-recovered.json" "${lighthouse_ip}"
    assert_observer_rehandshake_recovered \
      "${work_dir}/observer-member-initial-2.json" \
      "${work_dir}/observer-member-outage.json" \
      "${work_dir}/observer-member-recovered.json"
  fi
fi

say "Previewing and deploying a signed least-privilege policy"
restrictive_dns_rule=""
if [[ "${dns_smoke}" == "1" ]]; then
  restrictive_dns_rule=",{\"proto\":\"udp\",\"port\":\"${dns_port}\",\"group\":\"all\"}"
fi
if [[ "${active_probe_smoke}" == "1" ]]; then
  printf '{"inbound":[{"proto":"tcp","port":"443","group":"all"}%s],"outbound":[{"proto":"tcp","port":"443","host":"any"}]}\n' \
    "${restrictive_dns_rule}" \
    >"${work_dir}/policy-restrictive-preview.json"
else
  printf '{"inbound":[{"proto":"tcp","port":"443","group":"all"}%s],"outbound":[{"proto":"any","port":"any","host":"any"}]}\n' \
    "${restrictive_dns_rule}" \
    >"${work_dir}/policy-restrictive-preview.json"
fi
api_request PUT "/api/v1/networks/${network_id}/firewall/preview" \
  "${work_dir}/policy-restrictive-previewed.json" "${work_dir}/policy-restrictive-preview.json"
restrictive_revision="$(json_field "${work_dir}/policy-restrictive-previewed.json" proposed_config_revision)"
require_positive_integer "${restrictive_revision}" "restrictive policy revision"
python3 - \
  "${work_dir}/policy-restrictive-previewed.json" \
  "${initial_lighthouse_revision}" \
  "${restrictive_revision}" \
  "${active_probe_smoke}" \
  "${dns_smoke}" \
  "${dns_port}" <<'PY'
import json
import pathlib
import sys

preview = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
current = int(sys.argv[2])
proposed = int(sys.argv[3])
active_probe = sys.argv[4] == "1"
dns_enabled = sys.argv[5] == "1"
dns_port = int(sys.argv[6])
expected = (
    "firewall:\n"
    "  outbound:\n"
    f"    - port: {'443' if active_probe else 'any'}\n"
    f"      proto: {'tcp' if active_probe else 'any'}\n"
    "      host: any\n"
    "  inbound:\n"
    "    - port: 443\n"
    "      proto: tcp\n"
    "      group: \"all\"\n"
)
if dns_enabled:
    expected += (
        f"    - port: {dns_port}\n"
        "      proto: udp\n"
        "      group: \"all\"\n"
    )
if preview.get("would_change") is not True:
    raise SystemExit("restrictive policy preview did not report a change")
if preview.get("config_revision") != current or proposed != current + 1:
    raise SystemExit("restrictive policy preview returned an invalid revision transition")
if preview.get("rendered_firewall") != expected:
    raise SystemExit("restrictive policy preview did not return the canonical Nebula firewall")
PY
if [[ "${active_probe_smoke}" == "1" ]]; then
  printf \
    '{"expected_config_revision":%s,"inbound":[{"proto":"tcp","port":"443","group":"all"}%s],"outbound":[{"proto":"tcp","port":"443","host":"any"}]}\n' \
    "${initial_lighthouse_revision}" "${restrictive_dns_rule}" >"${work_dir}/policy-restrictive-update.json"
else
  printf \
    '{"expected_config_revision":%s,"inbound":[{"proto":"tcp","port":"443","group":"all"}%s],"outbound":[{"proto":"any","port":"any","host":"any"}]}\n' \
    "${initial_lighthouse_revision}" "${restrictive_dns_rule}" >"${work_dir}/policy-restrictive-update.json"
fi
api_request PUT "/api/v1/networks/${network_id}/firewall" \
  "${work_dir}/policy-restrictive-updated.json" "${work_dir}/policy-restrictive-update.json"
[[ "$(json_field "${work_dir}/policy-restrictive-updated.json" config_revision)" == "${restrictive_revision}" ]] ||
  die "restrictive policy update did not commit the previewed revision"

run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-restrictive-policy.log"
run_validation_agent "${member_state}" "${work_dir}/member-agent-restrictive-policy.log"
[[ "$(json_field "${lighthouse_state}" applied_config_revision)" == "${restrictive_revision}" ]] ||
  die "lighthouse did not apply the restrictive policy revision"
[[ "$(json_field "${member_state}" applied_config_revision)" == "${restrictive_revision}" ]] ||
  die "member did not apply the restrictive policy revision"
validate_bundle "${lighthouse_output}" "restrictive-policy lighthouse"
validate_bundle "${member_output}" "restrictive-policy member"
python3 - \
  "${lighthouse_output}/current/config.yml" \
  "${member_output}/current/config.yml" \
  "${active_probe_smoke}" \
  "${dns_smoke}" \
  "${dns_port}" <<'PY'
import pathlib
import sys

active_probe = sys.argv[3] == "1"
dns_enabled = sys.argv[4] == "1"
dns_port = int(sys.argv[5])
expected = (
    "firewall:\n"
    "  outbound:\n"
    f"    - port: {'443' if active_probe else 'any'}\n"
    f"      proto: {'tcp' if active_probe else 'any'}\n"
    "      host: any\n"
    "  inbound:\n"
    "    - port: 443\n"
    "      proto: tcp\n"
    "      group: \"all\"\n"
)
if dns_enabled:
    expected += (
        f"    - port: {dns_port}\n"
        "      proto: udp\n"
        "      group: \"all\"\n"
    )
for raw in sys.argv[1:3]:
    content = pathlib.Path(raw).read_text(encoding="utf-8")
    if content.count("firewall:\n") != 1 or expected not in content:
        raise SystemExit(f"restrictive policy is not the one exact firewall in {raw}")
PY

stop_namespace_processes "${lighthouse_ns}"
stop_namespace_processes "${member_ns}"
if namespace_has_process "${lighthouse_ns}" || namespace_has_process "${member_ns}"; then
  die "old Nebula process survived restrictive-policy quarantine"
fi
if [[ -n "${lighthouse_launcher_pid}" ]]; then
  wait "${lighthouse_launcher_pid}" 2>/dev/null || true
  lighthouse_launcher_pid=""
fi
if [[ -n "${member_launcher_pid}" ]]; then
  wait "${member_launcher_pid}" 2>/dev/null || true
  member_launcher_pid=""
fi
start_nebula "${lighthouse_ns}" "${lighthouse_output}/current/config.yml" \
  "${work_dir}/lighthouse-nebula-restrictive-policy.log" lighthouse_launcher_pid
lighthouse_overlay_device="$(wait_for_overlay "${lighthouse_ns}" "${lighthouse_ip}" restrictive-policy-lighthouse)"
start_nebula "${member_ns}" "${member_output}/current/config.yml" \
  "${work_dir}/member-nebula-restrictive-policy.log" member_launcher_pid
member_overlay_device="$(wait_for_overlay "${member_ns}" "${member_ip}" restrictive-policy-member)"
assert_overlay_route "${member_ns}" "${member_ip}" "${lighthouse_ip}" \
  "${member_overlay_device}" member-to-lighthouse-restrictive-policy
assert_overlay_route "${lighthouse_ns}" "${lighthouse_ip}" "${member_ip}" \
  "${lighthouse_overlay_device}" lighthouse-to-member-restrictive-policy
prove_overlay_tcp_443 "${lighthouse_ns}" "${lighthouse_ip}" "${member_ip}" \
  "${member_ns}" member-to-lighthouse-restrictive-policy
if [[ "${observer_smoke}" == "1" ]]; then
  capture_observer_snapshot "${member_nebula_pid}" "${overlay_cidr}" \
    "${work_dir}/observer-member-restarted.json" "${lighthouse_ip}"
  assert_observer_process_discontinuity \
    "${work_dir}/observer-member-initial-2.json" \
    "${work_dir}/observer-member-restarted.json"
fi
assert_overlay_ping_blocked "${member_ns}" "${lighthouse_ip}" \
  "${work_dir}/restrictive-member-to-lighthouse.log"

# Nebula is stateful: the member's denied outbound echo probes still create
# local conntrack entries, so a subsequent reverse-direction echo can look
# like reply traffic. Restart both exact restrictive-policy processes before
# testing the other inbound direction so each assertion starts with an empty
# userspace conntrack table.
stop_namespace_processes "${lighthouse_ns}"
stop_namespace_processes "${member_ns}"
if [[ -n "${lighthouse_launcher_pid}" ]]; then
  wait "${lighthouse_launcher_pid}" 2>/dev/null || true
  lighthouse_launcher_pid=""
fi
if [[ -n "${member_launcher_pid}" ]]; then
  wait "${member_launcher_pid}" 2>/dev/null || true
  member_launcher_pid=""
fi
start_nebula "${lighthouse_ns}" "${lighthouse_output}/current/config.yml" \
  "${work_dir}/lighthouse-nebula-restrictive-policy-reverse.log" lighthouse_launcher_pid
lighthouse_overlay_device="$(wait_for_overlay "${lighthouse_ns}" "${lighthouse_ip}" restrictive-policy-reverse-lighthouse)"
start_nebula "${member_ns}" "${member_output}/current/config.yml" \
  "${work_dir}/member-nebula-restrictive-policy-reverse.log" member_launcher_pid
member_overlay_device="$(wait_for_overlay "${member_ns}" "${member_ip}" restrictive-policy-reverse-member)"
assert_overlay_route "${lighthouse_ns}" "${lighthouse_ip}" "${member_ip}" \
  "${lighthouse_overlay_device}" lighthouse-to-member-restrictive-policy-clean
prove_overlay_tcp_443 "${member_ns}" "${member_ip}" "${lighthouse_ip}" \
  "${lighthouse_ns}" lighthouse-to-member-restrictive-policy
assert_overlay_ping_blocked "${lighthouse_ns}" "${member_ip}" \
  "${work_dir}/restrictive-lighthouse-to-member.log"
namespace_has_process "${lighthouse_ns}" || die "lighthouse Nebula exited during restrictive-policy proof"
namespace_has_process "${member_ns}" || die "member Nebula exited during restrictive-policy proof"
if [[ "${active_probe_smoke}" == "1" ]]; then
  say "Proving signed ICMP denial suppresses the production active probe"
  run_active_probe_cycle denial shared
  assert_active_probe_capture denial exact 0
  assert_active_probe_projection denial not_eligible observed 0 0 0
  [[ ! -e "${member_state}.runtime-probe.json" ]] ||
    die "not-eligible active probe unexpectedly touched the packet cadence journal"
  say "PASS: signed TCP-only policy produced not-eligible evidence and no TUN echo request"
fi

say "Rolling the signed firewall policy back to authenticated full-mesh connectivity"
printf '%s\n' \
  '{"inbound":[{"proto":"any","port":"any","group":"all"}],"outbound":[{"proto":"any","port":"any","host":"any"}]}' \
  >"${work_dir}/policy-default-preview.json"
api_request PUT "/api/v1/networks/${network_id}/firewall/preview" \
  "${work_dir}/policy-default-previewed.json" "${work_dir}/policy-default-preview.json"
restored_revision="$(json_field "${work_dir}/policy-default-previewed.json" proposed_config_revision)"
require_positive_integer "${restored_revision}" "restored policy revision"
python3 - \
  "${work_dir}/policy-default-previewed.json" \
  "${restrictive_revision}" \
  "${restored_revision}" <<'PY'
import json
import pathlib
import sys

preview = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
current = int(sys.argv[2])
proposed = int(sys.argv[3])
if preview.get("would_change") is not True:
    raise SystemExit("default policy restoration preview did not report a change")
if preview.get("config_revision") != current or proposed != current + 1:
    raise SystemExit("default policy restoration returned an invalid revision transition")
PY
printf \
  '{"expected_config_revision":%s,"inbound":[{"proto":"any","port":"any","group":"all"}],"outbound":[{"proto":"any","port":"any","host":"any"}]}\n' \
  "${restrictive_revision}" >"${work_dir}/policy-default-update.json"
api_request PUT "/api/v1/networks/${network_id}/firewall" \
  "${work_dir}/policy-default-updated.json" "${work_dir}/policy-default-update.json"
[[ "$(json_field "${work_dir}/policy-default-updated.json" config_revision)" == "${restored_revision}" ]] ||
  die "default policy restoration did not commit the previewed revision"

run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-restored-policy.log"
run_validation_agent "${member_state}" "${work_dir}/member-agent-restored-policy.log"
[[ "$(json_field "${lighthouse_state}" applied_config_revision)" == "${restored_revision}" ]] ||
  die "lighthouse did not apply the restored policy revision"
[[ "$(json_field "${member_state}" applied_config_revision)" == "${restored_revision}" ]] ||
  die "member did not apply the restored policy revision"
validate_bundle "${lighthouse_output}" "restored-policy lighthouse"
validate_bundle "${member_output}" "restored-policy member"

stop_namespace_processes "${lighthouse_ns}"
stop_namespace_processes "${member_ns}"
if [[ -n "${lighthouse_launcher_pid}" ]]; then
  wait "${lighthouse_launcher_pid}" 2>/dev/null || true
  lighthouse_launcher_pid=""
fi
if [[ -n "${member_launcher_pid}" ]]; then
  wait "${member_launcher_pid}" 2>/dev/null || true
  member_launcher_pid=""
fi
start_nebula "${lighthouse_ns}" "${lighthouse_output}/current/config.yml" \
  "${work_dir}/lighthouse-nebula-restored-policy.log" lighthouse_launcher_pid
lighthouse_overlay_device="$(wait_for_overlay "${lighthouse_ns}" "${lighthouse_ip}" restored-policy-lighthouse)"
start_nebula "${member_ns}" "${member_output}/current/config.yml" \
  "${work_dir}/member-nebula-restored-policy.log" member_launcher_pid
member_overlay_device="$(wait_for_overlay "${member_ns}" "${member_ip}" restored-policy-member)"
wait_for_overlay_ping "${member_ns}" "${lighthouse_ip}" "${work_dir}/restored-policy-establish.log"
prove_overlay_ping "${member_ns}" "${lighthouse_ip}" "${work_dir}/restored-policy-proof.log"
namespace_has_process "${lighthouse_ns}" || die "lighthouse Nebula exited after policy restoration"
namespace_has_process "${member_ns}" || die "member Nebula exited after policy restoration"

if [[ "${active_probe_smoke}" == "1" ]]; then
  say "Proving an allowed zero-capability ping socket receives a validated lighthouse reply"
  run_root ip netns exec "${member_ns}" \
    sysctl -q -w "net.ipv4.ping_group_range=0 2147483647"
  wait_until_active_probe_due
  run_active_probe_cycle allowed shared
  assert_active_probe_projection allowed attempted observed 1 1 0
  assert_active_probe_capture allowed minimum 1

  say "Proving an immediate restart reuses durable cadence evidence without another packet"
  sleep 0.05
  run_active_probe_cycle cadence shared
  assert_active_probe_capture cadence exact 0
  assert_active_probe_projection cadence attempted observed 1 1 1
  assert_active_probe_sample_age_advanced allowed cadence

  say "Changing to a different eligible signed lighthouse plan inside the global packet window"
  printf '%s\n' \
    '{"name":"active-probe-plan-change","role":"lighthouse","public_endpoint":"203.0.113.1:4242"}' \
    >"${work_dir}/active-probe-second-lighthouse-create.json"
  api_request POST "/api/v1/networks/${network_id}/nodes" \
    "${work_dir}/active-probe-second-lighthouse-created.json" \
    "${work_dir}/active-probe-second-lighthouse-create.json"
  active_second_lighthouse_id="$(json_field "${work_dir}/active-probe-second-lighthouse-created.json" node.id)"
  active_second_lighthouse_ip="$(json_field "${work_dir}/active-probe-second-lighthouse-created.json" node.ip)"
  active_second_lighthouse_token="$(json_field "${work_dir}/active-probe-second-lighthouse-created.json" enrollment_token)"
  require_id "${active_second_lighthouse_id}" "active-probe plan-change lighthouse ID"
  require_overlay_ipv4 "${active_second_lighthouse_ip}" "${overlay_cidr}" "active-probe plan-change lighthouse IP"
  require_bearer "${active_second_lighthouse_token}" "active-probe plan-change enrollment token"
  active_second_lighthouse_root="${work_dir}/nodes/active-probe-second-lighthouse"
  enroll_node "${active_second_lighthouse_token}" \
    "${active_second_lighthouse_root}/state.json" \
    "${active_second_lighthouse_root}/nebula" \
    "${work_dir}/active-probe-second-lighthouse-enroll.log"
  unset active_second_lighthouse_token
  run_validation_agent "${member_state}" "${work_dir}/member-agent-active-probe-plan-change.log"
  grep -F -- "\"${active_second_lighthouse_ip}\"" "${member_output}/current/config.signed.yml" >/dev/null ||
    die "changed eligible lighthouse was absent from the member's verified signed plan"

  stop_namespace_processes "${member_ns}"
  if [[ -n "${member_launcher_pid}" ]]; then
    wait "${member_launcher_pid}" 2>/dev/null || true
    member_launcher_pid=""
  fi
  start_nebula "${member_ns}" "${member_output}/current/config.yml" \
    "${work_dir}/member-nebula-active-probe-plan-change.log" member_launcher_pid
  member_overlay_device="$(wait_for_overlay "${member_ns}" "${member_ip}" active-probe-plan-change-member)"
  wait_for_overlay_ping "${member_ns}" "${lighthouse_ip}" \
    "${work_dir}/active-probe-plan-change-establish.log"
  run_active_probe_cycle changed-plan shared
  assert_active_probe_capture changed-plan exact 0
  assert_active_probe_projection changed-plan unavailable observed 0 0 -1

  say "Restoring the original eligible plan before capability and independence proofs"
  api_request POST "/api/v1/nodes/${active_second_lighthouse_id}/revoke" \
    "${work_dir}/active-probe-second-lighthouse-revoked.json"
  [[ "$(json_field "${work_dir}/active-probe-second-lighthouse-revoked.json" status)" == "revoked" ]] ||
    die "active-probe plan-change lighthouse did not revoke"
  run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-active-probe-plan-restored.log"
  run_validation_agent "${member_state}" "${work_dir}/member-agent-active-probe-plan-restored.log"
  if grep -F -- "\"${active_second_lighthouse_ip}\"" "${member_output}/current/config.signed.yml" >/dev/null; then
    die "revoked plan-change lighthouse remained in the member's active signed plan"
  fi

  stop_namespace_processes "${lighthouse_ns}"
  stop_namespace_processes "${member_ns}"
  if [[ -n "${lighthouse_launcher_pid}" ]]; then
    wait "${lighthouse_launcher_pid}" 2>/dev/null || true
    lighthouse_launcher_pid=""
  fi
  if [[ -n "${member_launcher_pid}" ]]; then
    wait "${member_launcher_pid}" 2>/dev/null || true
    member_launcher_pid=""
  fi
  start_nebula "${lighthouse_ns}" "${lighthouse_output}/current/config.yml" \
    "${work_dir}/lighthouse-nebula-active-probe-plan-restored.log" lighthouse_launcher_pid
  lighthouse_overlay_device="$(wait_for_overlay "${lighthouse_ns}" "${lighthouse_ip}" active-probe-plan-restored-lighthouse)"
  start_nebula "${member_ns}" "${member_output}/current/config.yml" \
    "${work_dir}/member-nebula-active-probe-plan-restored.log" member_launcher_pid
  member_overlay_device="$(wait_for_overlay "${member_ns}" "${member_ip}" active-probe-plan-restored-member)"
  wait_for_overlay_ping "${member_ns}" "${lighthouse_ip}" \
    "${work_dir}/active-probe-plan-restored-establish.log"

  say "Proving ping-socket policy denial leaves passive observation intact"
  wait_until_active_probe_due
  run_root ip netns exec "${member_ns}" sysctl -q -w "net.ipv4.ping_group_range=1 1"
  run_active_probe_cycle capability shared
  assert_active_probe_capture capability exact 0
  assert_active_probe_projection capability capability_unavailable observed 0 0 0
  run_root ip netns exec "${member_ns}" \
    sysctl -q -w "net.ipv4.ping_group_range=0 2147483647"

  say "Proving observer failure leaves independently sound active-probe evidence intact"
  wait_until_active_probe_due
  run_active_probe_cycle observer-unavailable unavailable
  assert_active_probe_capture observer-unavailable minimum 1
  assert_active_probe_projection observer-unavailable attempted unknown 1 1 0

  say "PASS: allowed lighthouse ICMP produced a validated zero-capability reply"
  say "PASS: restart cadence reused the prior sample and a changed eligible plan sent no packet"
  say "PASS: ping-socket denial preserved passive evidence and observer failure preserved active evidence"
  exit 0
fi

say "Revoking the member and applying the signed blocklist to its peer"
api_request POST "/api/v1/nodes/${member_id}/revoke" "${work_dir}/member-revoked.json"
[[ "$(json_field "${work_dir}/member-revoked.json" id)" == "${member_id}" ]] ||
  die "revocation response returned the wrong node"
[[ "$(json_field "${work_dir}/member-revoked.json" status)" == "revoked" ]] ||
  die "member did not reach revoked status"

api_request GET "/api/v1/networks" "${work_dir}/networks-after-revoke.json"
revocation_revision="$(network_field "${work_dir}/networks-after-revoke.json" "${network_name}" config_revision)"
require_positive_integer "${revocation_revision}" "revocation revision"
(( revocation_revision > restored_revision )) ||
  die "revocation did not advance the signed network revision"

run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-revocation.log"
applied_revocation_revision="$(json_field "${lighthouse_state}" applied_config_revision)"
[[ "${applied_revocation_revision}" == "${revocation_revision}" ]] ||
  die "lighthouse did not apply the control plane's signed revocation revision"
validate_bundle "${lighthouse_output}" "post-revocation lighthouse"

python3 - "${member_state}" "${lighthouse_output}/current/config.yml" <<'PY'
import json
import pathlib
import re
import sys

state = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
fingerprint = state.get("certificate_fingerprint", "")
if re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
    raise SystemExit("revoked member has no canonical certificate fingerprint")
config = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
if "  blocklist:\n" not in config or f'    - "{fingerprint}"\n' not in config:
    raise SystemExit("signed lighthouse config omitted the revoked member fingerprint")
PY

stop_namespace_processes "${lighthouse_ns}"
if [[ -n "${lighthouse_launcher_pid}" ]]; then
  wait "${lighthouse_launcher_pid}" 2>/dev/null || true
  lighthouse_launcher_pid=""
fi
start_nebula "${lighthouse_ns}" "${lighthouse_output}/current/config.yml" \
  "${work_dir}/lighthouse-nebula-revocation.log" lighthouse_launcher_pid
lighthouse_overlay_device="$(wait_for_overlay "${lighthouse_ns}" "${lighthouse_ip}" post-revocation-lighthouse)"

assert_overlay_route "${member_ns}" "${member_ip}" "${lighthouse_ip}" \
  "${member_overlay_device}" member-to-lighthouse-after
assert_overlay_route "${lighthouse_ns}" "${lighthouse_ip}" "${member_ip}" \
  "${lighthouse_overlay_device}" lighthouse-to-member-after
assert_overlay_ping_blocked "${member_ns}" "${lighthouse_ip}" \
  "${work_dir}/revoked-member-to-lighthouse.log"
assert_overlay_ping_blocked "${lighthouse_ns}" "${member_ip}" \
  "${work_dir}/lighthouse-to-revoked-member.log"
namespace_has_process "${lighthouse_ns}" ||
  die "lighthouse Nebula exited during post-revocation proof"
namespace_has_process "${member_ns}" ||
  die "member Nebula exited during post-revocation proof"
if [[ "${observer_smoke}" == "1" ]]; then
  capture_observer_snapshot "${lighthouse_nebula_pid}" "${overlay_cidr}" \
    "${work_dir}/observer-lighthouse-revoked.json"
  assert_revoked_observer_snapshot "${work_dir}/observer-lighthouse-revoked.json"
fi

say "PASS: authenticated Nebula overlay ICMP crossed isolated namespaces before revocation"
say "PASS: signed least-privilege policy revision ${restrictive_revision} blocked ICMP and revision ${restored_revision} restored it"
say "PASS: signed peer blocklist revision ${revocation_revision} cut bidirectional overlay ICMP while both peers stayed running"
if [[ "${observer_smoke}" == "1" ]]; then
  say "PASS: root-private observer snapshots proved handshake/RX evidence, sequence continuity, restart discontinuity, and revoked-peer exclusion"
fi
if [[ "${observer_outage_smoke}" == "1" ]]; then
  say "PASS: an underlay-only outage evicted the dead tunnel, recorded a timed-out handshake, and recovered through a fresh handshake plus authenticated RX in the same process"
fi
say "Scope: Linux network namespaces and TUN only; no cross-platform packet coverage is claimed."
