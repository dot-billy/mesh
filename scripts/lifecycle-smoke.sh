#!/usr/bin/env bash

# Rerunnable clean-room lifecycle smoke for the Mesh control plane.
#
# This exercises certificate/config lifecycle behavior with real Nebula tools.
# It deliberately does not start a Nebula tunnel or claim packet connectivity.

set -Eeuo pipefail
umask 077

readonly skip_status=77
readonly script_name="${0##*/}"
readonly keep_smoke="${KEEP_MESH_SMOKE:-0}"

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
mesh_server_candidate="${MESH_SERVER_BIN:-${repo_root}/bin/mesh-server}"
meshctl_candidate="${MESHCTL_BIN:-${repo_root}/bin/meshctl}"
nebula_candidate="${NEBULA_BIN:-nebula}"
nebula_cert_candidate="${NEBULA_CERT_BIN:-nebula-cert}"

work_dir=""
server_pid=""
server_url=""
server_data=""
curl_config=""

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

cleanup() {
  local status=$?

  trap - ERR EXIT HUP INT TERM
  set +e
  stop_server
  if [[ -n "${work_dir}" && -d "${work_dir}" ]]; then
    if [[ "${keep_smoke}" == "1" ]]; then
      printf 'Kept private smoke workspace for debugging: %s\n' "${work_dir}" >&2
      printf 'It contains live test credentials; remove it when finished.\n' >&2
    else
      case "${work_dir##*/}" in
        mesh-lifecycle-smoke.*)
          rm -rf -- "${work_dir}"
          ;;
        *)
          printf 'ERROR: refusing to remove unexpected smoke path %s\n' "${work_dir}" >&2
          status=1
          ;;
      esac
    fi
  fi
  exit "${status}"
}

on_error() {
  local status=$?
  local line="${1:-unknown}"

  trap - ERR
  printf 'ERROR: %s failed at line %s (use KEEP_MESH_SMOKE=1 to retain private diagnostics)\n' \
    "${script_name}" "${line}" >&2
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

nebula_version_supported() {
  local output="$1"
  local major minor patch

  if [[ ! "${output}" =~ ([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
    return 1
  fi
  major="${BASH_REMATCH[1]}"
  minor="${BASH_REMATCH[2]}"
  patch="${BASH_REMATCH[3]}"
  (( major > 1 )) ||
    (( major == 1 && minor > 10 )) ||
    (( major == 1 && minor == 10 && patch >= 3 ))
}

pick_loopback_port() {
  # The server does not accept an inherited listener. Ask the kernel for an
  # ephemeral loopback port, close it immediately before launch, and retry the
  # complete launch if another local process wins that narrow race.
  python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

start_server() {
  local attempt poll port
  local ready

  mkdir -p -- "${server_data}"
  chmod 0700 "${server_data}"
  : >"${work_dir}/server.log"

  for attempt in {1..8}; do
    port="$(pick_loopback_port)"
    [[ "${port}" =~ ^[0-9]+$ && "${port}" -ge 1024 && "${port}" -le 65535 ]] ||
      die "kernel returned an invalid loopback port"
    server_url="http://127.0.0.1:${port}"

    NEBULA_CERT_BINARY="${nebula_cert}" \
      "${mesh_server}" \
      --dev \
      --listen "127.0.0.1:${port}" \
      --data-dir "${server_data}" \
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

  # --no-reload cannot prove runtime quarantine, so the fail-open choice is
  # explicit and bounded to this one-shot bundle-validation process.
  "${meshctl}" agent \
    --state "${state_path}" \
    --once \
    --no-reload \
    --fail-open \
    --nebula "${nebula}" \
    --nebula-cert "${nebula_cert}" \
    >"${log_path}" 2>&1
}

if [[ "${keep_smoke}" != "0" && "${keep_smoke}" != "1" ]]; then
  die "KEEP_MESH_SMOKE must be 0 or 1"
fi
if (( BASH_VERSINFO[0] < 4 )); then
  skip "Bash 4 or newer is required"
fi
for prerequisite in python3 curl mktemp chmod rm; do
  command -v -- "${prerequisite}" >/dev/null 2>&1 ||
    skip "required command is unavailable: ${prerequisite}"
done

mesh_server="$(resolve_executable "${mesh_server_candidate}")" ||
  skip "mesh-server is unavailable; run 'make build' or set MESH_SERVER_BIN"
meshctl="$(resolve_executable "${meshctl_candidate}")" ||
  skip "meshctl is unavailable; run 'make build' or set MESHCTL_BIN"
nebula="$(resolve_executable "${nebula_candidate}")" ||
  skip "real nebula is unavailable; install Nebula 1.10.3 or newer or set NEBULA_BIN"
nebula_cert="$(resolve_executable "${nebula_cert_candidate}")" ||
  skip "real nebula-cert is unavailable; install Nebula 1.10.3 or newer or set NEBULA_CERT_BIN"

nebula_version="$(${nebula} -version 2>&1)" || skip "nebula -version failed"
nebula_version_supported "${nebula_version}" || skip "Nebula 1.10.3 or newer is required"
"${nebula_cert}" -version >/dev/null 2>&1 || skip "nebula-cert -version failed"
unset nebula_version

temp_parent="${TMPDIR:-/tmp}"
[[ -d "${temp_parent}" ]] || die "temporary directory parent does not exist: ${temp_parent}"
work_dir="$(mktemp -d "${temp_parent%/}/mesh-lifecycle-smoke.XXXXXX")"
[[ -d "${work_dir}" && ! -L "${work_dir}" ]] || die "mktemp did not create a real private directory"
chmod 0700 "${work_dir}"
server_data="${work_dir}/server"
curl_config="${work_dir}/admin.curlrc"

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

network_name="lifecycle-smoke"
MESH_ADMIN_TOKEN="${admin_token}" \
  "${meshctl}" create-network \
  --server "${server_url}" \
  --name "${network_name}" \
  --cidr "10.77.0.0/24" \
  >"${work_dir}/create-network.log" 2>&1
unset admin_token

api_request GET "/api/v1/networks" "${work_dir}/networks.json"
network_id="$(network_field "${work_dir}/networks.json" "${network_name}" id)"
require_id "${network_id}" "network ID"

printf '%s\n' \
  '{"name":"smoke-lighthouse","role":"lighthouse","public_endpoint":"127.0.0.1:4242"}' \
  >"${work_dir}/lighthouse-create.json"
printf '%s\n' \
  '{"name":"smoke-member","role":"member"}' \
  >"${work_dir}/member-create.json"

say "Creating and enrolling isolated lighthouse and member nodes"
api_request POST "/api/v1/networks/${network_id}/nodes" \
  "${work_dir}/lighthouse-created.json" "${work_dir}/lighthouse-create.json"
api_request POST "/api/v1/networks/${network_id}/nodes" \
  "${work_dir}/member-created.json" "${work_dir}/member-create.json"

lighthouse_id="$(json_field "${work_dir}/lighthouse-created.json" node.id)"
member_id="$(json_field "${work_dir}/member-created.json" node.id)"
lighthouse_enrollment_token="$(json_field "${work_dir}/lighthouse-created.json" enrollment_token)"
member_enrollment_token="$(json_field "${work_dir}/member-created.json" enrollment_token)"
require_id "${lighthouse_id}" "lighthouse ID"
require_id "${member_id}" "member ID"
require_bearer "${lighthouse_enrollment_token}" "lighthouse enrollment token"
require_bearer "${member_enrollment_token}" "member enrollment token"
[[ "${lighthouse_id}" != "${member_id}" ]] || die "control plane returned duplicate node IDs"
[[ "${lighthouse_enrollment_token}" != "${member_enrollment_token}" ]] ||
  die "control plane returned duplicate enrollment tokens"

lighthouse_root="${work_dir}/nodes/lighthouse"
member_root="${work_dir}/nodes/member"
lighthouse_state="${lighthouse_root}/state.json"
member_state="${member_root}/state.json"
lighthouse_output="${lighthouse_root}/nebula"
member_output="${member_root}/nebula"

enroll_node "${lighthouse_enrollment_token}" "${lighthouse_state}" "${lighthouse_output}" \
  "${work_dir}/lighthouse-enroll.log"
unset lighthouse_enrollment_token
enroll_node "${member_enrollment_token}" "${member_state}" "${member_output}" \
  "${work_dir}/member-enroll.log"
unset member_enrollment_token

[[ ! -e "${lighthouse_state}.enrollment.json" && ! -L "${lighthouse_state}.enrollment.json" ]] ||
  die "lighthouse provisional enrollment journal survived successful enrollment"
[[ ! -e "${member_state}.enrollment.json" && ! -L "${member_state}.enrollment.json" ]] ||
  die "member provisional enrollment journal survived successful enrollment"
[[ "$(json_field "${lighthouse_state}" node_id)" == "${lighthouse_id}" ]] ||
  die "lighthouse state identity does not match its API record"
[[ "$(json_field "${member_state}" node_id)" == "${member_id}" ]] ||
  die "member state identity does not match its API record"

validate_bundle "${lighthouse_output}" "lighthouse"
validate_bundle "${member_output}" "member"

say "Synchronizing signed bundles in one-shot validation-only mode"
run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-initial.log"
run_validation_agent "${member_state}" "${work_dir}/member-agent-initial.log"
initial_lighthouse_revision="$(json_field "${lighthouse_state}" applied_config_revision)"
initial_member_revision="$(json_field "${member_state}" applied_config_revision)"
require_positive_integer "${initial_lighthouse_revision}" "initial lighthouse revision"
require_positive_integer "${initial_member_revision}" "initial member revision"
[[ "${initial_lighthouse_revision}" == "${initial_member_revision}" ]] ||
  die "nodes did not converge on the same pre-revocation revision"

say "Recovering the active member agent credential with a one-time admin token"
member_old_bearer_file="${work_dir}/member-old-agent-bearer"
python3 - "${member_state}" "${member_old_bearer_file}" <<'PY'
import datetime
import json
import pathlib
import re
import sys

state = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
bearer = state.get("bearer", "")
if re.fullmatch(r"[A-Za-z0-9_-]{43}", bearer) is None:
    raise SystemExit("pre-recovery member bearer is missing or malformed")
pathlib.Path(sys.argv[2]).write_text(bearer + "\n", encoding="utf-8")
PY
chmod 0600 "${member_old_bearer_file}"
pre_recovery_generation="$(json_field "${member_state}" agent_credential_generation)"
require_positive_integer "${pre_recovery_generation}" "pre-recovery agent credential generation"

# First prove that an unknown but canonical token is journaled durably and
# rejected by the server. The subsequent real token may replace this journal
# only after the CLI proves the pending bearer is authoritatively unauthorized.
unknown_recovery_token_file="${work_dir}/member-unknown-recovery-token"
python3 - "${unknown_recovery_token_file}" <<'PY'
import base64
import pathlib
import secrets
import sys

token = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
pathlib.Path(sys.argv[1]).write_text(token + "\n", encoding="utf-8")
PY
chmod 0600 "${unknown_recovery_token_file}"
IFS= read -r unknown_recovery_token <"${unknown_recovery_token_file}"
require_bearer "${unknown_recovery_token}" "unknown member recovery token"
if MESH_AGENT_RECOVERY_TOKEN="${unknown_recovery_token}" \
  "${meshctl}" recover-agent \
  --state "${member_state}" \
  --no-reload \
  --fail-open \
  --nebula "${nebula}" \
  --nebula-cert "${nebula_cert}" \
  >"${work_dir}/member-recover-agent-unknown.log" 2>&1; then
  unknown_recovery_status=0
else
  unknown_recovery_status=$?
fi
unset unknown_recovery_token
[[ "${unknown_recovery_status}" -ne 0 ]] ||
  die "server-unknown recovery token unexpectedly succeeded"
python3 - \
  "${work_dir}/member-recover-agent-unknown.log" \
  "${member_state}" \
  "${unknown_recovery_token_file}" \
  "${work_dir}/member-unknown-pending-bearer" <<'PY'
import json
import pathlib
import re
import sys

message = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace").casefold()
state = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
unknown = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8").strip()
if "unauthorized" not in message:
    raise SystemExit("unknown recovery failure was not an authorization rejection")
if state.get("pending_recovery_token") != unknown:
    raise SystemExit("unknown recovery token was not retained in the crash journal")
pending = state.get("pending_bearer", "")
if re.fullmatch(r"[A-Za-z0-9_-]{43}", pending) is None or pending == state.get("bearer"):
    raise SystemExit("unknown recovery did not journal a distinct pending bearer")
pathlib.Path(sys.argv[4]).write_text(pending + "\n", encoding="utf-8")
PY
chmod 0600 "${work_dir}/member-unknown-pending-bearer"

api_request POST "/api/v1/nodes/${member_id}/agent-recovery" \
  "${work_dir}/member-recovery-issued.json"
member_recovery_token="$(json_field "${work_dir}/member-recovery-issued.json" recovery_token)"
require_bearer "${member_recovery_token}" "member agent recovery token"
MESH_AGENT_RECOVERY_TOKEN="${member_recovery_token}" \
  "${meshctl}" recover-agent \
  --state "${member_state}" \
  --no-reload \
  --fail-open \
  --nebula "${nebula}" \
  --nebula-cert "${nebula_cert}" \
  >"${work_dir}/member-recover-agent.log" 2>&1
unset member_recovery_token

post_recovery_generation="$(json_field "${member_state}" agent_credential_generation)"
require_positive_integer "${post_recovery_generation}" "post-recovery agent credential generation"
(( post_recovery_generation == pre_recovery_generation + 1 )) ||
  die "agent recovery did not advance the credential generation exactly once"
python3 - \
  "${member_state}" \
  "${member_old_bearer_file}" \
  "${work_dir}/member-unknown-pending-bearer" <<'PY'
import json
import pathlib
import re
import sys

state = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
old = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").strip()
unknown_pending = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8").strip()
current = state.get("bearer", "")
if re.fullmatch(r"[A-Za-z0-9_-]{43}", current) is None:
    raise SystemExit("recovered member bearer is missing or malformed")
if current == old:
    raise SystemExit("agent recovery did not replace the old bearer")
if current == unknown_pending:
    raise SystemExit("real recovery reused the unauthorized pending bearer")
if state.get("pending_bearer", "") or state.get("pending_recovery_token", "") or state.get("pending_recovery_allows_generation_advance", False):
    raise SystemExit("successful recovery retained pending credential material")
PY
validate_bundle "${member_output}" "recovered member"

# Issuing a newer unused token must retain the committed result above so a
# client that lost the first response can still exact-replay it.
api_request POST "/api/v1/nodes/${member_id}/agent-recovery" \
  "${work_dir}/member-recovery-replacement-issued.json"
replacement_recovery_token="$(json_field "${work_dir}/member-recovery-replacement-issued.json" recovery_token)"
require_bearer "${replacement_recovery_token}" "replacement member recovery token"
unset replacement_recovery_token

# Keep agent bearers out of argv and command output. These private curl config
# files are removed with the smoke workspace.
python3 - "${member_old_bearer_file}" "${work_dir}/old-member-agent.curlrc" <<'PY'
import pathlib
import re
import sys

bearer = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").strip()
if re.fullmatch(r"[A-Za-z0-9_-]{43}", bearer) is None:
    raise SystemExit("old member bearer is malformed")
pathlib.Path(sys.argv[2]).write_text(
    "silent\nshow-error\nconnect-timeout = 2\nmax-time = 30\n"
    f'header = "Authorization: Bearer {bearer}"\n',
    encoding="utf-8",
)
PY
chmod 0600 "${work_dir}/old-member-agent.curlrc"
old_bearer_status="$(curl \
  --config "${work_dir}/old-member-agent.curlrc" \
  --output "${work_dir}/old-member-bootstrap-error.json" \
  --write-out '%{http_code}' \
  --noproxy '*' \
  "${server_url}/api/v1/agent/bootstrap")"
[[ "${old_bearer_status}" == "401" ]] ||
  die "pre-recovery agent bearer was not rejected after recovery"

python3 - "${member_state}" "${work_dir}/recovered-member-agent.curlrc" <<'PY'
import json
import pathlib
import re
import sys

state = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
bearer = state.get("bearer", "")
if re.fullmatch(r"[A-Za-z0-9_-]{43}", bearer) is None:
    raise SystemExit("recovered member bearer is malformed")
pathlib.Path(sys.argv[2]).write_text(
    "silent\nshow-error\nfail\nconnect-timeout = 2\nmax-time = 30\n"
    f'header = "Authorization: Bearer {bearer}"\n',
    encoding="utf-8",
)
PY
chmod 0600 "${work_dir}/recovered-member-agent.curlrc"
curl \
  --config "${work_dir}/recovered-member-agent.curlrc" \
  --output "${work_dir}/recovered-member-bootstrap.json" \
  --noproxy '*' \
  "${server_url}/api/v1/agent/bootstrap"
[[ "$(json_field "${work_dir}/recovered-member-bootstrap.json" node_id)" == "${member_id}" ]] ||
  die "recovered bearer bootstrapped the wrong node identity"
[[ "$(json_field "${work_dir}/recovered-member-bootstrap.json" agent_credential_generation)" == "${post_recovery_generation}" ]] ||
  die "recovered bearer bootstrap returned the wrong credential generation"

# Reconstruct the byte-for-byte bound request from private artifacts. The
# exact retry must return the persisted signed recovery result, while changing
# only the proposed bearer hash must be rejected.
python3 - \
  "${work_dir}/member-recovery-issued.json" \
  "${member_state}" \
  "${member_output}/current/host.pub" \
  "${work_dir}/member-recovery-retry.json" \
  "${work_dir}/member-recovery-changed.json" <<'PY'
import base64
import hashlib
import json
import pathlib
import sys

issued = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
state = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
public_key = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8").strip() + "\n"

def token_hash(value: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest()).rstrip(b"=").decode()

request = {
    "recovery_token": issued["recovery_token"],
    "public_key": public_key,
    "new_agent_token_hash": token_hash(state["bearer"]),
}
pathlib.Path(sys.argv[4]).write_text(json.dumps(request), encoding="utf-8")
changed = dict(request)
changed["new_agent_token_hash"] = token_hash("deliberately-changed-recovery-retry")
pathlib.Path(sys.argv[5]).write_text(json.dumps(changed), encoding="utf-8")
PY
chmod 0600 \
  "${work_dir}/member-recovery-retry.json" \
  "${work_dir}/member-recovery-changed.json"
curl \
  --silent --show-error --fail --noproxy '*' \
  --connect-timeout 2 --max-time 30 \
  --header 'Content-Type: application/json' \
  --data-binary "@${work_dir}/member-recovery-retry.json" \
  --output "${work_dir}/member-recovery-retry-response.json" \
  "${server_url}/api/v1/agent/recover"
changed_retry_status="$(curl \
  --silent --show-error --noproxy '*' \
  --connect-timeout 2 --max-time 30 \
  --header 'Content-Type: application/json' \
  --data-binary "@${work_dir}/member-recovery-changed.json" \
  --output "${work_dir}/member-recovery-changed-error.json" \
  --write-out '%{http_code}' \
  "${server_url}/api/v1/agent/recover")"
[[ "${changed_retry_status}" == "401" ]] ||
  die "used recovery token accepted a changed retry request"

python3 - \
  "${server_data}/state.json" \
  "${work_dir}/member-recovery-retry-response.json" \
  "${member_state}" \
  "${member_id}" \
  "${work_dir}/member-recovery-issued.json" \
  "${work_dir}/member-recovery-replacement-issued.json" <<'PY'
import base64
import hashlib
import json
import pathlib
import sys

server = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
response = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
state = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
committed_issuance = json.loads(pathlib.Path(sys.argv[5]).read_text(encoding="utf-8"))
replacement_issuance = json.loads(pathlib.Path(sys.argv[6]).read_text(encoding="utf-8"))
matches = [item for item in server.get("agent_recoveries", []) if item.get("node_id") == sys.argv[4]]
used = [item for item in matches if item.get("used_at") and isinstance(item.get("result"), dict)]
unused = [item for item in matches if not item.get("used_at") and item.get("result") is None]
if len(matches) != 2 or len(used) != 1 or len(unused) != 1:
    raise SystemExit("replacement issuance did not retain one used result plus one unused token")

def token_hash(value: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest()).rstrip(b"=").decode()

if used[0].get("token_hash") != token_hash(committed_issuance["recovery_token"]):
    raise SystemExit("server did not retain the committed recovery record")
if unused[0].get("token_hash") != token_hash(replacement_issuance["recovery_token"]):
    raise SystemExit("server did not retain the newly issued unused replacement")
if response != used[0]["result"]:
    raise SystemExit("exact recovery retry did not return the persisted signed result")
receipt = response.get("recovery_receipt", {})
expected_hash = token_hash(state["bearer"])
if receipt.get("new_agent_token_hash") != expected_hash:
    raise SystemExit("recovery receipt does not bind the recovered bearer")
if response.get("agent_credential_generation") != state.get("agent_credential_generation"):
    raise SystemExit("recovery retry changed or misreported the credential generation")
PY

run_validation_agent "${member_state}" "${work_dir}/member-agent-recovered.log"
[[ "$(json_field "${member_state}" applied_config_revision)" == "${initial_member_revision}" ]] ||
  die "recovered member did not synchronize the current signed revision"
validate_bundle "${member_output}" "recovered and synchronized member"

say "Replacing the member's lost-key identity and distributing its blocklist entry"
api_request GET "/api/v1/networks" "${work_dir}/networks-before-identity-replacement.json"
replacement_expected_revision="$(network_field "${work_dir}/networks-before-identity-replacement.json" "${network_name}" config_revision)"
require_positive_integer "${replacement_expected_revision}" "identity replacement expected revision"
printf '{"expected_config_revision":%s}\n' "${replacement_expected_revision}" \
  >"${work_dir}/member-identity-replace.json"
api_request POST "/api/v1/nodes/${member_id}/replace" \
  "${work_dir}/member-identity-replaced.json" "${work_dir}/member-identity-replace.json"

replacement_id="$(json_field "${work_dir}/member-identity-replaced.json" node.id)"
replacement_enrollment_token="$(json_field "${work_dir}/member-identity-replaced.json" enrollment_token)"
replacement_revision="$(json_field "${work_dir}/member-identity-replaced.json" config_revision)"
require_id "${replacement_id}" "replacement member ID"
require_bearer "${replacement_enrollment_token}" "replacement member enrollment token"
require_positive_integer "${replacement_revision}" "identity replacement config revision"
[[ "${replacement_id}" != "${member_id}" ]] || die "identity replacement reused the revoked node ID"
[[ "$(json_field "${work_dir}/member-identity-replaced.json" revoked_node_id)" == "${member_id}" ]] ||
  die "identity replacement response revoked the wrong node"
(( replacement_revision == replacement_expected_revision + 1 )) ||
  die "identity replacement did not advance the network revision exactly once"

python3 - \
  "${work_dir}/member-created.json" \
  "${work_dir}/member-identity-replaced.json" <<'PY'
import json
import pathlib
import sys

source = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["node"]
response = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
replacement = response["node"]
if replacement.get("status") != "pending":
    raise SystemExit("identity replacement did not create a pending node")
if replacement.get("ip") == source.get("ip"):
    raise SystemExit("identity replacement reused the revoked overlay address")
for field in ("network_id", "name", "role", "groups", "site", "failure_domain", "public_endpoint", "routed_subnets"):
    if replacement.get(field) != source.get(field):
        raise SystemExit(f"identity replacement did not preserve {field}")
PY

# A response-loss retry must conflict because the source is now revoked, not
# create a second pending identity. The supported recovery path is enrollment
# reissue on the already-committed pending replacement.
printf '{"expected_config_revision":%s}\n' "${replacement_revision}" \
  >"${work_dir}/member-identity-replace-repeat.json"
repeat_replace_status="$(curl \
  --config "${curl_config}" \
  --no-fail \
  --request POST \
  --data-binary "@${work_dir}/member-identity-replace-repeat.json" \
  --output "${work_dir}/member-identity-replace-repeat-error.json" \
  --write-out '%{http_code}' \
  --noproxy '*' \
  "${server_url}/api/v1/nodes/${member_id}/replace")"
[[ "${repeat_replace_status}" == "409" ]] ||
  die "response-loss identity replacement retry did not conflict"

api_request POST "/api/v1/nodes/${replacement_id}/enrollment/reissue" \
  "${work_dir}/member-identity-enrollment-reissued.json"
replacement_reissued_token="$(json_field "${work_dir}/member-identity-enrollment-reissued.json" enrollment_token)"
require_bearer "${replacement_reissued_token}" "reissued replacement enrollment token"
[[ "${replacement_reissued_token}" != "${replacement_enrollment_token}" ]] ||
  die "identity replacement enrollment reissue reused its first token"
python3 - \
  "${work_dir}/member-identity-replaced.json" \
  "${work_dir}/replacement-original-preflight.json" <<'PY'
import json
import pathlib
import sys

response = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
pathlib.Path(sys.argv[2]).write_text(json.dumps({"token": response["enrollment_token"]}), encoding="utf-8")
PY
original_replacement_token_status="$(curl \
  --silent --show-error --noproxy '*' \
  --connect-timeout 2 --max-time 30 \
  --header 'Content-Type: application/json' \
  --data-binary "@${work_dir}/replacement-original-preflight.json" \
  --output "${work_dir}/replacement-original-preflight-error.json" \
  --write-out '%{http_code}' \
  "${server_url}/api/v1/enroll/preflight")"
[[ "${original_replacement_token_status}" == "401" ]] ||
  die "reissued replacement left its first enrollment token usable"
unset replacement_enrollment_token

replacement_root="${work_dir}/nodes/member-replacement"
replacement_state="${replacement_root}/state.json"
replacement_output="${replacement_root}/nebula"
enroll_node "${replacement_reissued_token}" "${replacement_state}" "${replacement_output}" \
  "${work_dir}/member-identity-replacement-enroll.log"
unset replacement_reissued_token
[[ ! -e "${replacement_state}.enrollment.json" && ! -L "${replacement_state}.enrollment.json" ]] ||
  die "replacement provisional enrollment journal survived successful enrollment"
[[ "$(json_field "${replacement_state}" node_id)" == "${replacement_id}" ]] ||
  die "replacement state identity does not match its API record"
validate_bundle "${replacement_output}" "replacement member"

api_request GET "/api/v1/networks/${network_id}/nodes" "${work_dir}/nodes-after-identity-replacement.json"
python3 - \
  "${work_dir}/nodes-after-identity-replacement.json" \
  "${member_id}" \
  "${replacement_id}" <<'PY'
import json
import pathlib
import sys

nodes = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
source = [node for node in nodes if node.get("id") == sys.argv[2]]
replacement = [node for node in nodes if node.get("id") == sys.argv[3]]
if len(source) != 1 or source[0].get("status") != "revoked":
    raise SystemExit("source member is not uniquely revoked")
if len(replacement) != 1 or replacement[0].get("status") != "active":
    raise SystemExit("replacement member is not uniquely active")
if len([node for node in nodes if node.get("name") == source[0].get("name") and node.get("status") == "pending"]) != 0:
    raise SystemExit("identity replacement left an extra pending identity")
PY

api_request GET "/api/v1/networks" "${work_dir}/networks-after-identity-replacement.json"
current_replacement_revision="$(network_field "${work_dir}/networks-after-identity-replacement.json" "${network_name}" config_revision)"
[[ "${current_replacement_revision}" == "${replacement_revision}" ]] ||
  die "member replacement enrollment unexpectedly changed the signed network revision"

run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-identity-replacement.log"
run_validation_agent "${replacement_state}" "${work_dir}/member-replacement-agent.log"
[[ "$(json_field "${lighthouse_state}" applied_config_revision)" == "${replacement_revision}" ]] ||
  die "lighthouse did not apply the identity-replacement blocklist revision"
[[ "$(json_field "${replacement_state}" applied_config_revision)" == "${replacement_revision}" ]] ||
  die "replacement member did not apply the current signed revision"
validate_bundle "${lighthouse_output}" "post-replacement lighthouse"
validate_bundle "${replacement_output}" "synchronized replacement member"

python3 - \
  "${member_state}" \
  "${replacement_state}" \
  "${lighthouse_output}/current/config.yml" \
  "${replacement_output}/current/config.yml" <<'PY'
import json
import pathlib
import re
import sys

source = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
replacement = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
fingerprint = source.get("certificate_fingerprint", "")
if re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
    raise SystemExit("source member state has no valid certificate fingerprint")
if replacement.get("certificate_fingerprint") == fingerprint:
    raise SystemExit("identity replacement reused the revoked certificate fingerprint")
for path in sys.argv[3:]:
    config = pathlib.Path(path).read_text(encoding="utf-8")
    if "  blocklist:\n" not in config or f'    - "{fingerprint}"\n' not in config:
        raise SystemExit(f"signed config does not contain the revoked member fingerprint: {path}")
PY

if "${meshctl}" agent \
  --state "${member_state}" \
  --once \
  --no-reload \
  --fail-open \
  --nebula "${nebula}" \
  --nebula-cert "${nebula_cert}" \
  >"${work_dir}/member-agent-revoked.log" 2>&1; then
  revoked_agent_status=0
else
  revoked_agent_status=$?
fi
[[ "${revoked_agent_status}" -ne 0 ]] || die "revoked member agent was still authorized"
python3 - "${work_dir}/member-agent-revoked.log" <<'PY'
import pathlib
import sys

message = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace").casefold()
if "unauthorized" not in message:
    raise SystemExit("revoked member failure was not an authorization rejection")
PY

say "Rotating an active host certificate with exact response-loss replay"
api_request POST "/api/v1/nodes/${replacement_id}/agent-recovery" \
  "${work_dir}/certificate-rotation-recovery-issued.json"
rotation_recovery_token="$(json_field "${work_dir}/certificate-rotation-recovery-issued.json" recovery_token)"
require_bearer "${rotation_recovery_token}" "certificate-rotation recovery token"
unset rotation_recovery_token

api_request GET "/api/v1/networks" "${work_dir}/networks-before-certificate-rotation.json"
rotation_expected_revision="$(network_field "${work_dir}/networks-before-certificate-rotation.json" "${network_name}" config_revision)"
rotation_previous_generation="$(json_field "${replacement_state}" certificate_generation)"
rotation_previous_expiry="$(json_field "${replacement_state}" certificate_expires_at)"
rotation_previous_fingerprint="$(json_field "${replacement_state}" certificate_fingerprint)"
rotation_node_name="$(json_field "${work_dir}/member-identity-replaced.json" node.name)"
require_positive_integer "${rotation_expected_revision}" "certificate rotation expected revision"
require_positive_integer "${rotation_previous_generation}" "pre-rotation certificate generation"
[[ "${rotation_previous_fingerprint}" =~ ^[0-9a-f]{64}$ ]] ||
  die "pre-rotation certificate fingerprint was not canonical"
cp -- "${replacement_output}/current/host.pub" "${work_dir}/certificate-rotation-host.pub"
python3 - \
  "${work_dir}/certificate-rotation-request.json" \
  "${rotation_expected_revision}" \
  "${rotation_node_name}" <<'PY'
import json
import pathlib
import sys

request = {
    "expected_config_revision": int(sys.argv[2]),
    "confirmation_name": sys.argv[3],
    "request_id": "lifecycle-certificate-rotation-0001",
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(request, separators=(",", ":")) + "\n", encoding="utf-8")
PY
api_request POST "/api/v1/nodes/${replacement_id}/certificate/rotate" \
  "${work_dir}/certificate-rotation-receipt.json" \
  "${work_dir}/certificate-rotation-request.json"
cp -- "${server_data}/state.json" "${work_dir}/state-after-certificate-rotation.json"

# Replaying the exact idempotency key after a lost success response must return
# the durable receipt without signing again, advancing state, or writing bytes.
api_request POST "/api/v1/nodes/${replacement_id}/certificate/rotate" \
  "${work_dir}/certificate-rotation-replay.json" \
  "${work_dir}/certificate-rotation-request.json"
cmp -- "${work_dir}/certificate-rotation-receipt.json" \
  "${work_dir}/certificate-rotation-replay.json" >/dev/null ||
  die "certificate rotation replay did not return the exact persisted receipt"
cmp -- "${work_dir}/state-after-certificate-rotation.json" \
  "${server_data}/state.json" >/dev/null ||
  die "certificate rotation replay rewrote control state"

python3 - \
  "${work_dir}/certificate-rotation-receipt.json" \
  "${work_dir}/member-identity-replaced.json" \
  "${server_data}/state.json" \
  "${replacement_id}" \
  "${network_id}" \
  "${rotation_expected_revision}" \
  "${rotation_previous_generation}" \
  "${rotation_previous_expiry}" \
  "${rotation_previous_fingerprint}" <<'PY'
import datetime
import json
import pathlib
import re
import sys

receipt = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
replacement = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))["node"]
state = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
expected_keys = {
    "request_id", "node_id", "network_id", "name", "ip", "role", "rotated_at",
    "previous_certificate_expires_at", "certificate_expires_at", "certificate_renew_after",
    "previous_certificate_generation", "certificate_generation",
    "agent_recovery_records_invalidated", "certificate_issuances_added",
    "blocklist_entries_added", "previous_certificate_blocklisted", "config_revision",
}
if set(receipt) != expected_keys:
    raise SystemExit("certificate rotation response is not the exact receipt schema")
expected_identity = {
    "request_id": "lifecycle-certificate-rotation-0001",
    "node_id": sys.argv[4], "network_id": sys.argv[5], "name": replacement["name"],
    "ip": replacement["ip"], "role": replacement["role"],
}
for key, value in expected_identity.items():
    if receipt.get(key) != value:
        raise SystemExit(f"certificate rotation receipt mismatched {key}")
expected_revision = int(sys.argv[6])
previous_generation = int(sys.argv[7])
if receipt.get("previous_certificate_generation") != previous_generation or receipt.get("certificate_generation") != previous_generation + 1:
    raise SystemExit("certificate rotation did not advance generation exactly once")
if receipt.get("config_revision") != expected_revision + 1:
    raise SystemExit("certificate rotation did not advance revision exactly once")
if receipt.get("agent_recovery_records_invalidated") != 1 or receipt.get("certificate_issuances_added") != 1 or receipt.get("blocklist_entries_added") != 1 or receipt.get("previous_certificate_blocklisted") is not True:
    raise SystemExit("certificate rotation receipt lacks recovery, issuance, or blocklist evidence")

def instant(value: str) -> datetime.datetime:
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})", value) is None:
        raise ValueError(value)
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))

if instant(receipt["previous_certificate_expires_at"]) != instant(sys.argv[8]):
    raise SystemExit("certificate rotation did not bind the prior certificate expiry instant")
rotated = instant(receipt["rotated_at"])
renew = instant(receipt["certificate_renew_after"])
expires = instant(receipt["certificate_expires_at"])
if not rotated < renew < expires:
    raise SystemExit("certificate rotation lifecycle timestamps are inconsistent")
revocations = [item for item in state.get("revocations", []) if item.get("fingerprint") == sys.argv[9]]
if len(revocations) != 1 or revocations[0].get("node_id") != sys.argv[4] or revocations[0].get("network_id") != sys.argv[5] or revocations[0].get("reason") != "certificate rotated by administrator" or instant(revocations[0].get("expires_at", "")) != instant(sys.argv[8]):
    raise SystemExit("prior certificate is not blocklisted through its exact expiry")
if any(item.get("node_id") == sys.argv[4] for item in state.get("agent_recoveries", [])):
    raise SystemExit("certificate rotation retained an agent recovery record")
PY

# The one-time recovery credential existed before rotation. It must now be
# unauthorized, even though its body otherwise satisfies the recovery schema.
python3 - \
  "${work_dir}/certificate-rotation-recovery-issued.json" \
  "${replacement_output}/current/host.pub" \
  "${work_dir}/certificate-rotation-invalidated-recovery.json" <<'PY'
import base64
import hashlib
import json
import pathlib
import sys

issued = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
public_key = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").strip() + "\n"
new_token_hash = base64.urlsafe_b64encode(hashlib.sha256(b"certificate-rotation-unused-bearer").digest()).rstrip(b"=").decode()
request = {"recovery_token": issued["recovery_token"], "public_key": public_key, "new_agent_token_hash": new_token_hash}
pathlib.Path(sys.argv[3]).write_text(json.dumps(request, separators=(",", ":")), encoding="utf-8")
PY
rotation_recovery_status="$(curl \
  --silent --show-error --noproxy '*' \
  --connect-timeout 2 --max-time 30 \
  --header 'Content-Type: application/json' \
  --data-binary "@${work_dir}/certificate-rotation-invalidated-recovery.json" \
  --output "${work_dir}/certificate-rotation-invalidated-recovery-error.json" \
  --write-out '%{http_code}' \
  "${server_url}/api/v1/agent/recover")"
[[ "${rotation_recovery_status}" == "401" ]] ||
  die "certificate rotation left its preexisting recovery token authorized"

rotation_revision="$(json_field "${work_dir}/certificate-rotation-receipt.json" config_revision)"
rotation_generation="$(json_field "${work_dir}/certificate-rotation-receipt.json" certificate_generation)"
run_validation_agent "${replacement_state}" "${work_dir}/member-agent-certificate-rotation.log"
run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-certificate-rotation.log"
[[ "$(json_field "${replacement_state}" applied_config_revision)" == "${rotation_revision}" ]] ||
  die "rotated member did not apply the certificate-rotation revision"
[[ "$(json_field "${replacement_state}" certificate_generation)" == "${rotation_generation}" ]] ||
  die "rotated member did not install the replacement certificate generation"
[[ "$(json_field "${lighthouse_state}" applied_config_revision)" == "${rotation_revision}" ]] ||
  die "lighthouse did not apply the certificate-rotation blocklist revision"
validate_bundle "${replacement_output}" "certificate-rotated member"
validate_bundle "${lighthouse_output}" "post-certificate-rotation lighthouse"
cmp -- "${work_dir}/certificate-rotation-host.pub" \
  "${replacement_output}/current/host.pub" >/dev/null ||
  die "certificate rotation replaced the pinned host public key"
python3 - \
  "${replacement_state}" \
  "${work_dir}/certificate-rotation-receipt.json" \
  "${rotation_previous_fingerprint}" \
  "${lighthouse_output}/current/config.yml" \
  "${replacement_output}/current/config.yml" <<'PY'
import datetime
import json
import pathlib
import re
import sys

state = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
receipt = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
previous_fingerprint = sys.argv[3]
current_fingerprint = state.get("certificate_fingerprint", "")
if re.fullmatch(r"[0-9a-f]{64}", current_fingerprint) is None or current_fingerprint == previous_fingerprint:
    raise SystemExit("certificate rotation did not install a distinct certificate")
def instant(value: str) -> datetime.datetime:
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})", value) is None:
        raise ValueError(value)
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))

if state.get("certificate_generation") != receipt.get("certificate_generation") or instant(state.get("certificate_expires_at", "")) != instant(receipt.get("certificate_expires_at", "")) or instant(state.get("certificate_renew_after", "")) != instant(receipt.get("certificate_renew_after", "")):
    raise SystemExit("certificate rotation agent state does not match its receipt")
for path in sys.argv[4:]:
    config = pathlib.Path(path).read_text(encoding="utf-8")
    if "  blocklist:\n" not in config or f'    - "{previous_fingerprint}"\n' not in config:
        raise SystemExit(f"signed config does not contain the rotated certificate fingerprint: {path}")
PY

say "Cancelling an abandoned pending enrollment and invalidating its credential"
api_request GET "/api/v1/networks" "${work_dir}/networks-before-pending-cancel.json"
pending_cancel_revision="$(network_field "${work_dir}/networks-before-pending-cancel.json" "${network_name}" config_revision)"
require_positive_integer "${pending_cancel_revision}" "pending cancellation config revision"
printf '%s\n' '{"name":"abandoned-pending","role":"member"}' >"${work_dir}/pending-cancel-create.json"
api_request POST "/api/v1/networks/${network_id}/nodes" \
  "${work_dir}/pending-cancel-created.json" "${work_dir}/pending-cancel-create.json"
pending_cancel_id="$(json_field "${work_dir}/pending-cancel-created.json" node.id)"
pending_cancel_token="$(json_field "${work_dir}/pending-cancel-created.json" enrollment_token)"
require_id "${pending_cancel_id}" "pending cancellation node ID"
require_bearer "${pending_cancel_token}" "pending cancellation enrollment token"
printf '{"token":"%s"}\n' "${pending_cancel_token}" >"${work_dir}/pending-cancel-preflight.json"
unset pending_cancel_token
printf '%s\n' '{"confirmation_name":"abandoned-pending"}' >"${work_dir}/pending-cancel.json"
api_request POST "/api/v1/nodes/${pending_cancel_id}/enrollment/cancel" \
  "${work_dir}/pending-cancelled.json" "${work_dir}/pending-cancel.json"

api_request GET "/api/v1/networks/${network_id}/nodes" "${work_dir}/nodes-after-pending-cancel.json"
api_request GET "/api/v1/networks" "${work_dir}/networks-after-pending-cancel.json"
python3 - \
  "${work_dir}/pending-cancel-created.json" \
  "${work_dir}/pending-cancelled.json" \
  "${work_dir}/nodes-after-pending-cancel.json" \
  "${work_dir}/networks-after-pending-cancel.json" \
  "${network_name}" \
  "${pending_cancel_revision}" <<'PY'
import datetime
import json
import pathlib
import sys

created = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
receipt = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
nodes = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
networks = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
node = created["node"]
revision = int(sys.argv[6])
expected_keys = {
    "node_id", "network_id", "name", "ip", "role", "cancelled_at",
    "enrollment_records_invalidated", "relay_assignment_removed",
    "routed_subnet_reservations_released", "config_revision",
}
if set(receipt) != expected_keys:
    raise SystemExit("pending cancellation response is not the exact receipt schema")
for receipt_key, node_key in (("node_id", "id"), ("network_id", "network_id"), ("name", "name"), ("ip", "ip"), ("role", "role")):
    if receipt.get(receipt_key) != node.get(node_key):
        raise SystemExit(f"pending cancellation receipt mismatched {receipt_key}")
if receipt.get("enrollment_records_invalidated") != 1 or receipt.get("relay_assignment_removed") is not False or receipt.get("routed_subnet_reservations_released") != 0 or receipt.get("config_revision") != revision:
    raise SystemExit("pending cancellation receipt has invalid cleanup evidence")
try:
    datetime.datetime.fromisoformat(receipt["cancelled_at"].replace("Z", "+00:00"))
except (KeyError, TypeError, ValueError) as error:
    raise SystemExit("pending cancellation receipt has invalid time") from error
if any(item.get("id") == node.get("id") for item in nodes):
    raise SystemExit("cancelled pending node remains in authoritative inventory")
matches = [item for item in networks if item.get("name") == sys.argv[5]]
if len(matches) != 1 or matches[0].get("config_revision") != revision:
    raise SystemExit("unassigned pending cancellation changed signed network revision")
PY

pending_cancel_token_status="$(curl \
  --silent --show-error --noproxy '*' \
  --connect-timeout 2 --max-time 30 \
  --header 'Content-Type: application/json' \
  --data-binary "@${work_dir}/pending-cancel-preflight.json" \
  --output "${work_dir}/pending-cancel-preflight-error.json" \
  --write-out '%{http_code}' \
  "${server_url}/api/v1/enroll/preflight")"
[[ "${pending_cancel_token_status}" == "401" ]] || die "cancelled pending enrollment token remained authorized"

say "Archiving a never-enrolled revoked record without weakening a certificate blocklist"
printf '%s\n' '{"name":"archived-pending","role":"member","routed_subnets":["192.168.79.0/24"]}' >"${work_dir}/archival-create.json"
api_request POST "/api/v1/networks/${network_id}/nodes" \
  "${work_dir}/archival-created.json" "${work_dir}/archival-create.json"
archival_id="$(json_field "${work_dir}/archival-created.json" node.id)"
archival_token="$(json_field "${work_dir}/archival-created.json" enrollment_token)"
require_id "${archival_id}" "archival node ID"
require_bearer "${archival_token}" "archival enrollment token"
printf '{"token":"%s"}\n' "${archival_token}" >"${work_dir}/archival-preflight.json"
unset archival_token
api_request POST "/api/v1/nodes/${archival_id}/revoke" "${work_dir}/archival-revoked.json"
api_request GET "/api/v1/networks" "${work_dir}/networks-before-archival.json"
archival_revision="$(network_field "${work_dir}/networks-before-archival.json" "${network_name}" config_revision)"
require_positive_integer "${archival_revision}" "node archival expected revision"
printf '{"expected_config_revision":%s,"confirmation_name":"archived-pending"}\n' \
  "${archival_revision}" >"${work_dir}/node-archive.json"
api_request POST "/api/v1/nodes/${archival_id}/archive" \
  "${work_dir}/node-archived.json" "${work_dir}/node-archive.json"
api_request GET "/api/v1/networks/${network_id}/nodes" "${work_dir}/nodes-after-archival.json"
api_request GET "/api/v1/networks" "${work_dir}/networks-after-archival.json"

python3 - \
  "${work_dir}/archival-created.json" \
  "${work_dir}/node-archived.json" \
  "${work_dir}/nodes-after-archival.json" \
  "${work_dir}/networks-after-archival.json" \
  "${server_data}/state.json" \
  "${network_name}" \
  "${archival_revision}" <<'PY'
import datetime
import json
import pathlib
import sys

created = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
receipt = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
nodes = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
networks = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
state = json.loads(pathlib.Path(sys.argv[5]).read_text(encoding="utf-8"))
network_name = sys.argv[6]
revision = int(sys.argv[7])
node = created["node"]
expected_keys = {
    "node_id", "network_id", "name", "ip", "role", "revoked_at", "archived_at",
    "enrollment_records_removed", "agent_recovery_records_removed",
    "certificate_issuances_removed", "revocations_removed", "blocklist_entries_removed",
    "routed_subnet_reservations_released", "config_revision",
    "runtime_telemetry_record_removed", "runtime_telemetry_cleanup_complete",
}
if set(receipt) != expected_keys:
    raise SystemExit("never-enrolled archival response is not the exact receipt schema")
for receipt_key, node_key in (("node_id", "id"), ("network_id", "network_id"), ("name", "name"), ("ip", "ip"), ("role", "role")):
    if receipt.get(receipt_key) != node.get(node_key):
        raise SystemExit(f"node archival receipt mismatched {receipt_key}")
for key in ("revoked_at", "archived_at"):
    try:
        datetime.datetime.fromisoformat(receipt[key].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as error:
        raise SystemExit(f"node archival receipt has invalid {key}") from error
expected_counts = {
    "enrollment_records_removed": 1,
    "agent_recovery_records_removed": 0,
    "certificate_issuances_removed": 0,
    "revocations_removed": 0,
    "blocklist_entries_removed": 0,
    "routed_subnet_reservations_released": 1,
    "config_revision": revision,
    "runtime_telemetry_record_removed": False,
    "runtime_telemetry_cleanup_complete": True,
}
for key, expected in expected_counts.items():
    if receipt.get(key) != expected:
        raise SystemExit(f"node archival receipt {key}={receipt.get(key)!r}, want {expected!r}")
if any(item.get("id") == node.get("id") for item in nodes):
    raise SystemExit("archived node remains in authoritative inventory")
matches = [item for item in networks if item.get("name") == network_name]
if len(matches) != 1 or matches[0].get("config_revision") != revision:
    raise SystemExit("never-enrolled archival changed the signed revision")
if any(item.get("id") == node.get("id") for item in state.get("nodes", [])):
    raise SystemExit("archived node remains in persisted inventory")
if any(item.get("node_id") == node.get("id") for item in state.get("enrollments", [])):
    raise SystemExit("archived node enrollment record remains persisted")
events = [item for item in state.get("audit", []) if item.get("action") == "node.archived" and item.get("resource_id") == node.get("id")]
if len(events) != 1 or events[0].get("resource") != "node":
    raise SystemExit("exactly one node archival tombstone was not persisted")
details = events[0].get("details", {})
for key, expected in {
    "network_id": node.get("network_id"), "name": node.get("name"), "ip": node.get("ip"), "role": node.get("role"),
    "enrolled": False, "last_certificate_expired_at": "", "enrollment_records_removed": 1,
    "agent_recovery_records_removed": 0, "certificate_issuances_removed": 0, "revocations_removed": 0,
    "blocklist_entries_removed": 0, "routed_subnet_reservations_released": 1, "config_revision": revision,
    "certificate_material_removed": True, "agent_credentials_invalidated": True, "all_certificate_records_expired": True,
}.items():
    if details.get(key) != expected:
        raise SystemExit(f"node archival tombstone has invalid {key}")
PY

archival_token_status="$(curl \
  --silent --show-error --noproxy '*' \
  --connect-timeout 2 --max-time 30 \
  --header 'Content-Type: application/json' \
  --data-binary "@${work_dir}/archival-preflight.json" \
  --output "${work_dir}/archival-preflight-error.json" \
  --write-out '%{http_code}' \
  "${server_url}/api/v1/enroll/preflight")"
[[ "${archival_token_status}" == "401" ]] || die "archived node enrollment token remained authorized"

repeat_archive_status="$(curl \
  --config "${curl_config}" --no-fail --request POST \
  --data-binary "@${work_dir}/node-archive.json" \
  --output "${work_dir}/node-archive-repeat-error.json" \
  --write-out '%{http_code}' --noproxy '*' \
  "${server_url}/api/v1/nodes/${archival_id}/archive")"
[[ "${repeat_archive_status}" == "404" ]] || die "repeated node archival was not rejected as absent"

say "Revoking an active real-Nebula node with exact response-loss replay"
printf '%s\n' '{"name":"safe-revocation-target","role":"member"}' >"${work_dir}/safe-revocation-create.json"
api_request POST "/api/v1/networks/${network_id}/nodes" \
  "${work_dir}/safe-revocation-created.json" "${work_dir}/safe-revocation-create.json"
safe_revocation_id="$(json_field "${work_dir}/safe-revocation-created.json" node.id)"
safe_revocation_enrollment_token="$(json_field "${work_dir}/safe-revocation-created.json" enrollment_token)"
require_id "${safe_revocation_id}" "safe revocation node ID"
require_bearer "${safe_revocation_enrollment_token}" "safe revocation enrollment token"
safe_revocation_root="${work_dir}/nodes/safe-revocation-target"
safe_revocation_state="${safe_revocation_root}/state.json"
safe_revocation_output="${safe_revocation_root}/nebula"
enroll_node "${safe_revocation_enrollment_token}" "${safe_revocation_state}" "${safe_revocation_output}" \
  "${work_dir}/safe-revocation-enroll.log"
unset safe_revocation_enrollment_token
validate_bundle "${safe_revocation_output}" "safe revocation target"
run_validation_agent "${safe_revocation_state}" "${work_dir}/safe-revocation-agent-initial.log"
safe_revocation_fingerprint="$(json_field "${safe_revocation_state}" certificate_fingerprint)"
[[ "${safe_revocation_fingerprint}" =~ ^[0-9a-f]{64}$ ]] || die "safe revocation fingerprint was not canonical"
api_request POST "/api/v1/nodes/${safe_revocation_id}/agent-recovery" \
  "${work_dir}/safe-revocation-recovery-issued.json"
safe_revocation_recovery_token="$(json_field "${work_dir}/safe-revocation-recovery-issued.json" recovery_token)"
require_bearer "${safe_revocation_recovery_token}" "safe revocation recovery token"
unset safe_revocation_recovery_token
api_request GET "/api/v1/networks" "${work_dir}/networks-before-safe-revocation.json"
safe_revocation_expected_revision="$(network_field "${work_dir}/networks-before-safe-revocation.json" "${network_name}" config_revision)"
require_positive_integer "${safe_revocation_expected_revision}" "safe revocation expected revision"
printf '{"expected_config_revision":%s,"confirmation_name":"safe-revocation-target","request_id":"lifecycle-node-revocation-0001"}\n' \
  "${safe_revocation_expected_revision}" >"${work_dir}/safe-revocation-request.json"
api_request POST "/api/v1/nodes/${safe_revocation_id}/revocation" \
  "${work_dir}/safe-revocation-receipt.json" "${work_dir}/safe-revocation-request.json"
cp -- "${server_data}/state.json" "${work_dir}/state-after-safe-revocation.json"
api_request POST "/api/v1/nodes/${safe_revocation_id}/revocation" \
  "${work_dir}/safe-revocation-replay.json" "${work_dir}/safe-revocation-request.json"
cmp -- "${work_dir}/safe-revocation-receipt.json" "${work_dir}/safe-revocation-replay.json" >/dev/null ||
  die "safe revocation replay did not return the exact persisted receipt"
cmp -- "${work_dir}/state-after-safe-revocation.json" "${server_data}/state.json" >/dev/null ||
  die "safe revocation replay rewrote control state"
python3 - \
  "${work_dir}/safe-revocation-created.json" \
  "${work_dir}/safe-revocation-receipt.json" \
  "${server_data}/state.json" \
  "${safe_revocation_expected_revision}" \
  "${safe_revocation_fingerprint}" <<'PY'
import datetime
import json
import pathlib
import sys

created = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["node"]
receipt = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
state = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
expected_revision = int(sys.argv[4])
expected_keys = {
    "request_id", "node_id", "network_id", "name", "ip", "role", "revoked_at", "was_enrolled",
    "enrollment_records_invalidated", "agent_recovery_records_invalidated", "blocklist_entries_added",
    "relay_assignment_removed", "firewall_canary_removed", "firewall_rollout_auto_rolled_back",
    "credentials_invalidated", "routed_subnet_reservations_released", "config_revision",
}
if set(receipt) != expected_keys:
    raise SystemExit("safe revocation response is not the exact receipt schema")
for receipt_key, node_key in (("node_id", "id"), ("network_id", "network_id"), ("name", "name"), ("ip", "ip"), ("role", "role")):
    if receipt.get(receipt_key) != created.get(node_key):
        raise SystemExit(f"safe revocation receipt mismatched {receipt_key}")
if receipt.get("request_id") != "lifecycle-node-revocation-0001" or receipt.get("was_enrolled") is not True or receipt.get("enrollment_records_invalidated") != 1 or receipt.get("agent_recovery_records_invalidated") != 1 or receipt.get("blocklist_entries_added") != 1 or receipt.get("relay_assignment_removed") is not False or receipt.get("firewall_canary_removed") is not False or receipt.get("firewall_rollout_auto_rolled_back") is not False or receipt.get("credentials_invalidated") is not True or receipt.get("routed_subnet_reservations_released") != 0 or receipt.get("config_revision") != expected_revision + 1:
    raise SystemExit("safe revocation receipt has invalid trust-cutoff evidence")
try:
    datetime.datetime.fromisoformat(receipt["revoked_at"].replace("Z", "+00:00"))
except (KeyError, TypeError, ValueError) as error:
    raise SystemExit("safe revocation receipt has invalid time") from error
nodes = [item for item in state.get("nodes", []) if item.get("id") == created.get("id")]
if len(nodes) != 1 or nodes[0].get("status") != "revoked":
    raise SystemExit("safe revocation target is not authoritatively revoked")
if any(item.get("node_id") == created.get("id") for item in state.get("enrollments", [])) or any(item.get("node_id") == created.get("id") for item in state.get("agent_recoveries", [])):
    raise SystemExit("safe revocation retained an enrollment or recovery record")
revocations = [item for item in state.get("revocations", []) if item.get("fingerprint") == sys.argv[5]]
if len(revocations) != 1 or revocations[0].get("node_id") != created.get("id"):
    raise SystemExit("safe revocation did not persist the target certificate blocklist")
PY

safe_revocation_revision="$(json_field "${work_dir}/safe-revocation-receipt.json" config_revision)"
run_validation_agent "${lighthouse_state}" "${work_dir}/lighthouse-agent-safe-revocation.log"
run_validation_agent "${replacement_state}" "${work_dir}/member-agent-safe-revocation.log"
[[ "$(json_field "${lighthouse_state}" applied_config_revision)" == "${safe_revocation_revision}" ]] ||
  die "lighthouse did not apply the safe-revocation blocklist revision"
[[ "$(json_field "${replacement_state}" applied_config_revision)" == "${safe_revocation_revision}" ]] ||
  die "member did not apply the safe-revocation blocklist revision"
python3 - "${safe_revocation_fingerprint}" "${lighthouse_output}/current/config.yml" "${replacement_output}/current/config.yml" <<'PY'
import pathlib
import sys

for value in sys.argv[2:]:
    config = pathlib.Path(value).read_text(encoding="utf-8")
    if f'    - "{sys.argv[1]}"\n' not in config:
        raise SystemExit(f"safe-revocation fingerprint is missing from signed config: {value}")
PY
if run_validation_agent "${safe_revocation_state}" "${work_dir}/safe-revocation-agent-rejected.log"; then
  die "safely revoked node agent remained authorized"
fi
python3 - "${work_dir}/safe-revocation-agent-rejected.log" <<'PY'
import pathlib
import sys

if "unauthorized" not in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace").casefold():
    raise SystemExit("safe revocation agent failure was not an authorization rejection")
PY

python3 - \
  "${server_data}/state.json" \
  "${work_dir}/lighthouse-created.json" \
  "${work_dir}/member-created.json" \
  "${lighthouse_state}" \
  "${member_state}" \
  "${member_old_bearer_file}" \
  "${work_dir}/member-recovery-issued.json" \
  "${unknown_recovery_token_file}" \
  "${work_dir}/member-unknown-pending-bearer" \
  "${work_dir}/member-recovery-replacement-issued.json" \
  "${work_dir}/member-identity-replaced.json" \
  "${work_dir}/member-identity-enrollment-reissued.json" \
  "${replacement_state}" \
  "${work_dir}/pending-cancel-created.json" \
  "${work_dir}/archival-created.json" \
  "${work_dir}/certificate-rotation-recovery-issued.json" \
  "${work_dir}/safe-revocation-created.json" \
  "${safe_revocation_state}" \
  "${work_dir}/safe-revocation-recovery-issued.json" \
  "${member_id}" \
  "${replacement_id}" <<'PY'
import json
import pathlib
import re
import sys

server_state = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
server = json.loads(server_state)
lighthouse_created = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
member_created = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
lighthouse_state = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
member_state = json.loads(pathlib.Path(sys.argv[5]).read_text(encoding="utf-8"))
old_member_bearer = pathlib.Path(sys.argv[6]).read_text(encoding="utf-8").strip()
recovery_issued = json.loads(pathlib.Path(sys.argv[7]).read_text(encoding="utf-8"))
unknown_recovery_token = pathlib.Path(sys.argv[8]).read_text(encoding="utf-8").strip()
unknown_pending_bearer = pathlib.Path(sys.argv[9]).read_text(encoding="utf-8").strip()
replacement_issued = json.loads(pathlib.Path(sys.argv[10]).read_text(encoding="utf-8"))
identity_replaced = json.loads(pathlib.Path(sys.argv[11]).read_text(encoding="utf-8"))
identity_reissued = json.loads(pathlib.Path(sys.argv[12]).read_text(encoding="utf-8"))
replacement_state = json.loads(pathlib.Path(sys.argv[13]).read_text(encoding="utf-8"))
pending_cancel_created = json.loads(pathlib.Path(sys.argv[14]).read_text(encoding="utf-8"))
archival_created = json.loads(pathlib.Path(sys.argv[15]).read_text(encoding="utf-8"))
rotation_recovery_issued = json.loads(pathlib.Path(sys.argv[16]).read_text(encoding="utf-8"))
safe_revocation_created = json.loads(pathlib.Path(sys.argv[17]).read_text(encoding="utf-8"))
safe_revocation_state = json.loads(pathlib.Path(sys.argv[18]).read_text(encoding="utf-8"))
safe_revocation_recovery = json.loads(pathlib.Path(sys.argv[19]).read_text(encoding="utf-8"))
secrets = {
    "lighthouse enrollment token": lighthouse_created.get("enrollment_token", ""),
    "member enrollment token": member_created.get("enrollment_token", ""),
    "lighthouse agent bearer": lighthouse_state.get("bearer", ""),
    "pre-recovery member agent bearer": old_member_bearer,
    "recovered member agent bearer": member_state.get("bearer", ""),
    "server-unknown member recovery token": unknown_recovery_token,
    "unauthorized pending member bearer": unknown_pending_bearer,
    "member agent recovery token": recovery_issued.get("recovery_token", ""),
    "unused replacement recovery token": replacement_issued.get("recovery_token", ""),
    "original identity-replacement enrollment token": identity_replaced.get("enrollment_token", ""),
    "reissued identity-replacement enrollment token": identity_reissued.get("enrollment_token", ""),
    "replacement member agent bearer": replacement_state.get("bearer", ""),
    "cancelled pending enrollment token": pending_cancel_created.get("enrollment_token", ""),
    "archived node enrollment token": archival_created.get("enrollment_token", ""),
    "invalidated certificate-rotation recovery token": rotation_recovery_issued.get("recovery_token", ""),
    "safe revocation enrollment token": safe_revocation_created.get("enrollment_token", ""),
    "safe revocation agent bearer": safe_revocation_state.get("bearer", ""),
    "safe revocation recovery token": safe_revocation_recovery.get("recovery_token", ""),
}
for label, secret in secrets.items():
    if re.fullmatch(r"[A-Za-z0-9_-]{43}", secret) is None:
        raise SystemExit(f"{label} is missing or malformed")
    if secret in server_state:
        raise SystemExit(f"raw {label} was persisted in server state")
if len(set(secrets.values())) != len(secrets):
    raise SystemExit("node credentials were unexpectedly reused")
if any(item.get("node_id") == sys.argv[20] for item in server.get("agent_recoveries", [])):
    raise SystemExit("identity replacement retained a recovery record for the revoked source")
if any(item.get("node_id") == sys.argv[21] for item in server.get("agent_recoveries", [])):
    raise SystemExit("certificate rotation retained a recovery record for the active replacement")
PY

say "Retiring the complete network and proving permanent trust-domain reservation"
printf '%s\n' '{"name":"retirement-pending","role":"member"}' >"${work_dir}/retirement-pending-create.json"
api_request POST "/api/v1/networks/${network_id}/nodes" \
  "${work_dir}/retirement-pending-created.json" "${work_dir}/retirement-pending-create.json"
retirement_pending_id="$(json_field "${work_dir}/retirement-pending-created.json" node.id)"
retirement_pending_token="$(json_field "${work_dir}/retirement-pending-created.json" enrollment_token)"
require_id "${retirement_pending_id}" "retirement pending node ID"
require_bearer "${retirement_pending_token}" "retirement pending enrollment token"
printf '{"token":"%s"}\n' "${retirement_pending_token}" >"${work_dir}/retirement-pending-preflight.json"
unset retirement_pending_token

api_request GET "/api/v1/networks" "${work_dir}/networks-before-retirement.json"
retirement_revision="$(network_field "${work_dir}/networks-before-retirement.json" "${network_name}" config_revision)"
require_positive_integer "${retirement_revision}" "network retirement expected revision"
cp -- "${server_data}/state.json" "${work_dir}/state-before-retirement.json"
cp -- "${server_data}/runtime-telemetry.json" "${work_dir}/telemetry-before-retirement.json"
printf '{"expected_config_revision":%s,"confirmation_name":"%s"}\n' \
  "${retirement_revision}" "${network_name}" >"${work_dir}/network-retire.json"
api_request POST "/api/v1/networks/${network_id}/retire" \
  "${work_dir}/network-retired.json" "${work_dir}/network-retire.json"

python3 - \
  "${work_dir}/state-before-retirement.json" \
  "${server_data}/state.json" \
  "${work_dir}/telemetry-before-retirement.json" \
  "${server_data}/runtime-telemetry.json" \
  "${work_dir}/network-retired.json" \
  "${work_dir}/retirement-pending-created.json" \
  "${network_id}" \
  "${network_name}" \
  "${retirement_revision}" <<'PY'
import json
import pathlib
import sys

before_path, after_path, telemetry_before_path, telemetry_after_path, receipt_path, pending_path = map(pathlib.Path, sys.argv[1:7])
before_raw = before_path.read_text(encoding="utf-8")
after_raw = after_path.read_text(encoding="utf-8")
before = json.loads(before_raw)
after = json.loads(after_raw)
telemetry_before = json.loads(telemetry_before_path.read_text(encoding="utf-8"))
telemetry_after = json.loads(telemetry_after_path.read_text(encoding="utf-8"))
receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
pending = json.loads(pending_path.read_text(encoding="utf-8"))
network_id, network_name, revision_text = sys.argv[7:10]
revision = int(revision_text)

def collection(document, key):
    value = document.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        raise SystemExit(f"persisted {key} is not a collection")
    return value

target_networks = [item for item in collection(before, "networks") if item.get("id") == network_id]
if len(target_networks) != 1:
    raise SystemExit("pre-retirement state does not contain exactly one target network")
target = target_networks[0]
if target.get("name") != network_name or target.get("config_revision") != revision:
    raise SystemExit("retirement input was not bound to the snapshotted target revision")
target_nodes = [item for item in collection(before, "nodes") if item.get("network_id") == network_id]
target_node_ids = {item.get("id") for item in target_nodes}
if None in target_node_ids or not target_node_ids:
    raise SystemExit("pre-retirement target node inventory is invalid")
status_counts = {status: sum(item.get("status") == status for item in target_nodes) for status in ("pending", "active", "revoked")}
if sum(status_counts.values()) != len(target_nodes):
    raise SystemExit("pre-retirement target node statuses are incomplete")
expected_telemetry = sum(item.get("node_id") in target_node_ids for item in collection(telemetry_before, "records"))

expected_receipt_keys = {
    "network_id", "name", "cidr", "config_revision", "retired_at", "node_count",
    "pending_nodes", "active_nodes", "revoked_nodes", "credentials_invalidated",
    "encrypted_key_material_removed", "name_cidr_permanently_reserved",
    "runtime_telemetry_records_removed", "runtime_telemetry_cleanup_complete",
}
if set(receipt) != expected_receipt_keys:
    raise SystemExit("retirement response is not the exact receipt schema")
if receipt.get("network_id") != network_id or receipt.get("name") != network_name or receipt.get("cidr") != target.get("cidr") or receipt.get("config_revision") != revision:
    raise SystemExit("retirement receipt identifies the wrong trust domain")
expected_counts = {
    "node_count": len(target_nodes),
    "pending_nodes": status_counts["pending"],
    "active_nodes": status_counts["active"],
    "revoked_nodes": status_counts["revoked"],
    "runtime_telemetry_records_removed": expected_telemetry,
}
for key, value in expected_counts.items():
    if receipt.get(key) != value:
        raise SystemExit(f"retirement receipt {key}={receipt.get(key)!r}, want {value}")
for key in ("credentials_invalidated", "encrypted_key_material_removed", "name_cidr_permanently_reserved", "runtime_telemetry_cleanup_complete"):
    if receipt.get(key) is not True:
        raise SystemExit(f"retirement receipt did not prove {key}")

if any(item.get("id") == network_id for item in collection(after, "networks")):
    raise SystemExit("retired network remains in control state")
if any(item.get("network_id") == network_id for item in collection(after, "nodes")):
    raise SystemExit("retired network nodes remain in control state")
if any(item.get("node_id") in target_node_ids for item in collection(after, "enrollments")):
    raise SystemExit("retired network enrollment records remain in control state")
if any(item.get("node_id") in target_node_ids for item in collection(after, "agent_recoveries")):
    raise SystemExit("retired network recovery records remain in control state")
if any(item.get("network_id") == network_id for item in collection(after, "issuances")):
    raise SystemExit("retired network certificate issuances remain in control state")
if any(item.get("network_id") == network_id for item in collection(after, "revocations")):
    raise SystemExit("retired network revocations remain in control state")
if any(item.get("node_id") in target_node_ids for item in collection(telemetry_after, "records")):
    raise SystemExit("retired network runtime telemetry remains in its separate store")

trust_material = []
for key in ("ca_certificate", "encrypted_ca_key", "config_signing_public_key", "encrypted_config_signing_key"):
    value = target.get(key)
    if isinstance(value, str) and value:
        trust_material.append((key, value))
rotation = target.get("ca_rotation", {})
if isinstance(rotation, dict):
    for key, value in rotation.items():
        if isinstance(value, str) and value and ("key" in key or "certificate" in key):
            trust_material.append((f"ca_rotation.{key}", value))
if len(trust_material) < 4:
    raise SystemExit("pre-retirement state did not expose the complete encrypted trust material")
for key, value in trust_material:
    if value in after_raw:
        raise SystemExit(f"retired {key} remains persisted")
pending_token = pending.get("enrollment_token", "")
if not pending_token or pending_token in after_raw:
    raise SystemExit("pending retirement credential is missing or remains persisted raw")

events = [item for item in collection(after, "audit") if item.get("action") == "network.retired" and item.get("resource_id") == network_id]
if len(events) != 1:
    raise SystemExit("exactly one retirement tombstone was not persisted")
details = events[0].get("details", {})
for key, value in {
    "name": network_name, "cidr": target.get("cidr"), "config_revision": revision,
    "node_count": len(target_nodes), "pending_nodes": status_counts["pending"],
    "active_nodes": status_counts["active"], "revoked_nodes": status_counts["revoked"],
    "credentials_invalidated": True, "encrypted_key_material_removed": True,
    "name_cidr_permanently_reserved": True,
}.items():
    if details.get(key) != value:
        raise SystemExit(f"retirement tombstone has invalid {key}")
PY

for retired_agent_spec in \
  "${lighthouse_state}:${work_dir}/lighthouse-agent-retired.log:lighthouse" \
  "${replacement_state}:${work_dir}/member-replacement-agent-retired.log:replacement member"; do
  IFS=: read -r retired_state retired_log retired_label <<<"${retired_agent_spec}"
  if run_validation_agent "${retired_state}" "${retired_log}"; then
    die "retired ${retired_label} agent was still authorized"
  fi
  python3 - "${retired_log}" "${retired_label}" <<'PY'
import pathlib
import sys

message = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace").casefold()
if "unauthorized" not in message:
    raise SystemExit(f"retired {sys.argv[2]} failure was not an authorization rejection")
PY
done

retired_pending_status="$(curl \
  --silent --show-error --noproxy '*' \
  --connect-timeout 2 --max-time 30 \
  --header 'Content-Type: application/json' \
  --data-binary "@${work_dir}/retirement-pending-preflight.json" \
  --output "${work_dir}/retirement-pending-preflight-error.json" \
  --write-out '%{http_code}' \
  "${server_url}/api/v1/enroll/preflight")"
[[ "${retired_pending_status}" == "401" ]] || die "retired network pending enrollment token remained authorized"

repeat_retire_status="$(curl \
  --config "${curl_config}" --no-fail --request POST \
  --data-binary "@${work_dir}/network-retire.json" \
  --output "${work_dir}/network-retire-repeat-error.json" \
  --write-out '%{http_code}' --noproxy '*' \
  "${server_url}/api/v1/networks/${network_id}/retire")"
[[ "${repeat_retire_status}" == "404" ]] || die "repeated network retirement was not rejected as absent"

printf '%s\n' '{"name":"lifecycle-smoke","cidr":"10.78.0.0/24"}' >"${work_dir}/retired-name-reuse.json"
retired_name_status="$(curl \
  --config "${curl_config}" --no-fail --request POST \
  --data-binary "@${work_dir}/retired-name-reuse.json" \
  --output "${work_dir}/retired-name-reuse-error.json" \
  --write-out '%{http_code}' --noproxy '*' \
  "${server_url}/api/v1/networks")"
[[ "${retired_name_status}" == "409" ]] || die "retired network name was reusable"

printf '%s\n' '{"name":"retired-overlap","cidr":"10.77.0.128/25"}' >"${work_dir}/retired-cidr-overlap.json"
retired_cidr_status="$(curl \
  --config "${curl_config}" --no-fail --request POST \
  --data-binary "@${work_dir}/retired-cidr-overlap.json" \
  --output "${work_dir}/retired-cidr-overlap-error.json" \
  --write-out '%{http_code}' --noproxy '*' \
  "${server_url}/api/v1/networks")"
[[ "${retired_cidr_status}" == "409" ]] || die "CIDR overlapping a retired network was reusable"

printf '%s\n' '{"name":"retirement-unrelated","cidr":"10.78.0.0/24"}' >"${work_dir}/retirement-unrelated.json"
fresh_network_status="$(curl \
  --config "${curl_config}" --no-fail --request POST \
  --data-binary "@${work_dir}/retirement-unrelated.json" \
  --output "${work_dir}/retirement-unrelated-created.json" \
  --write-out '%{http_code}' --noproxy '*' \
  "${server_url}/api/v1/networks")"
[[ "${fresh_network_status}" == "201" ]] || die "retirement reservation blocked an unrelated network"

api_request GET "/api/v1/networks" "${work_dir}/networks-after-retirement.json"
python3 - "${work_dir}/networks-after-retirement.json" "${network_id}" <<'PY'
import json
import pathlib
import sys

networks = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if any(item.get("id") == sys.argv[2] for item in networks):
    raise SystemExit("retired network remains in authoritative inventory")
if len([item for item in networks if item.get("name") == "retirement-unrelated"]) != 1:
    raise SystemExit("unrelated post-retirement network is missing")
PY

say "PASS: enrollment, pending cancellation, safe revoked-node archival, signed sync, agent recovery, atomic identity replacement, immediate same-key certificate rotation, idempotent active-node revocation, network retirement, permanent trust-domain reservation, response-loss recovery, blocklist propagation, and credential non-persistence verified"
say "Real Nebula validated each bundle; packet-level connectivity was not tested."
