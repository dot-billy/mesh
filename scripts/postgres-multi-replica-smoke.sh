#!/usr/bin/env bash

# Disposable application-level proof that two independent mesh-server
# processes can share one imported PostgreSQL control/identity state. This is
# intentionally not a PostgreSQL failover or PITR test: the database remains a
# single, local postgres:17-alpine container for the complete run.

set -Eeuo pipefail
umask 077

readonly skip_status=77
readonly script_name="${0##*/}"
readonly keep_smoke="${KEEP_MESH_SMOKE:-0}"
readonly postgres_image="postgres:17-alpine"
readonly nebula_cert="/usr/local/bin/nebula-cert"

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
work_parent=""
work_dir=""
run_id=""
container_name=""
container_id=""
container_started=0

mesh_server=""
mesh_storage=""
mesh_backup=""

source_pid=""
replica_one_pid=""
replica_two_pid=""
source_port=""
replica_one_port=""
replica_two_port=""
source_url=""
replica_one_url=""
replica_two_url=""
public_origin=""

admin_token=""
master_key=""
postgres_password=""

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

valid_child_pid() {
  local pid="$1"
  local expected_executable="$2"
  local observed_parent observed_executable

  [[ "${pid}" =~ ^[0-9]+$ && "${pid}" -gt 1 ]] || return 1
  kill -0 "${pid}" 2>/dev/null || return 1
  observed_parent="$(ps -o ppid= -p "${pid}" 2>/dev/null | tr -d '[:space:]')"
  [[ "${observed_parent}" == "$$" ]] || return 1
  observed_executable="$(readlink -f -- "/proc/${pid}/exe" 2>/dev/null || true)"
  [[ -n "${observed_executable}" && "${observed_executable}" == "${expected_executable}" ]]
}

stop_child() {
  local pid="$1"
  local expected_executable="$2"
  local attempt

  if [[ -z "${pid}" || ! "${pid}" =~ ^[0-9]+$ || "${pid}" -le 1 ]]; then
    return 0
  fi
  if ! kill -0 "${pid}" 2>/dev/null; then
    wait "${pid}" 2>/dev/null || true
    return 0
  fi
  if ! valid_child_pid "${pid}" "${expected_executable}"; then
    printf 'ERROR: refusing to signal unverified process %s\n' "${pid}" >&2
    return 1
  fi
  kill -TERM "${pid}" 2>/dev/null || true
  for attempt in {1..100}; do
    if ! kill -0 "${pid}" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  if kill -0 "${pid}" 2>/dev/null; then
    if ! valid_child_pid "${pid}" "${expected_executable}"; then
      printf 'ERROR: refusing to force-stop unverified process %s\n' "${pid}" >&2
      return 1
    fi
    kill -KILL "${pid}" 2>/dev/null || true
  fi
  wait "${pid}" 2>/dev/null || true
}

container_matches_run() {
  local observed_name observed_label observed_id

  [[ "${container_started}" == "1" ]] || return 1
  [[ "${container_name}" =~ ^mesh-postgres-multi-replica-smoke-[0-9a-f]{16}$ ]] || return 1
  [[ -z "${container_id}" || "${container_id}" =~ ^[0-9a-f]{64}$ ]] || return 1
  observed_name="$(docker inspect --format '{{.Name}}' "${container_name}" 2>/dev/null || true)"
  observed_label="$(docker inspect --format '{{ index .Config.Labels "io.mesh.smoke.instance" }}' "${container_name}" 2>/dev/null || true)"
  observed_id="$(docker inspect --format '{{.Id}}' "${container_name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "/${container_name}" && "${observed_label}" == "${run_id}" &&
     "${observed_id}" =~ ^[0-9a-f]{64}$ && ( -z "${container_id}" || "${observed_id}" == "${container_id}" ) ]]
}

cleanup() {
  local status=$?
  local base parent

  trap - ERR EXIT HUP INT TERM
  set +e

  if [[ -n "${replica_one_pid}" ]]; then
    stop_child "${replica_one_pid}" "${mesh_server}" || status=1
    replica_one_pid=""
  fi
  if [[ -n "${replica_two_pid}" ]]; then
    stop_child "${replica_two_pid}" "${mesh_server}" || status=1
    replica_two_pid=""
  fi
  if [[ -n "${source_pid}" ]]; then
    stop_child "${source_pid}" "${mesh_server}" || status=1
    source_pid=""
  fi

  # Forget shell-held credentials before any diagnostic message is emitted.
  admin_token=""
  master_key=""
  postgres_password=""

  if [[ "${container_started}" == "1" ]]; then
    if container_matches_run; then
      if [[ "${keep_smoke}" == "1" ]]; then
        printf 'Kept exact disposable PostgreSQL container for debugging: %s\n' "${container_name}" >&2
      else
        docker rm --force -- "${container_name}" >/dev/null 2>&1 || status=1
        container_started=0
      fi
    elif docker inspect "${container_name}" >/dev/null 2>&1; then
      printf 'ERROR: refusing to remove a PostgreSQL container whose exact identity or label changed\n' >&2
      status=1
    else
      container_started=0
    fi
  fi

  if [[ -n "${work_dir}" && -d "${work_dir}" ]]; then
    if [[ "${keep_smoke}" == "1" ]]; then
      printf 'Kept private PostgreSQL smoke workspace for debugging: %s\n' "${work_dir}" >&2
      printf 'It contains live disposable credentials; remove it with the retained container.\n' >&2
    else
      base="${work_dir##*/}"
      parent="$(cd -- "$(dirname -- "${work_dir}")" 2>/dev/null && pwd -P)"
      if [[ "${base}" == mesh-postgres-multi-replica-smoke.* && -n "${work_parent}" && "${parent}" == "${work_parent}" && ! -L "${work_dir}" ]]; then
        rm -rf -- "${work_dir}"
      else
        printf 'ERROR: refusing to remove unexpected smoke workspace %s\n' "${work_dir}" >&2
        status=1
      fi
    fi
  fi
  exit "${status}"
}

on_error() {
  local status=$?
  local line="${1:-unknown}"

  trap - ERR
  printf 'ERROR: %s failed at line %s (set KEEP_MESH_SMOKE=1 to retain private diagnostics)\n' \
    "${script_name}" "${line}" >&2
  exit "${status}"
}

trap cleanup EXIT
trap 'on_error "${LINENO}"' ERR
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

pick_loopback_port() {
  python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

nebula_version_exact() {
  local output="$1"
  local major minor patch

  [[ "${output}" =~ ([0-9]+)\.([0-9]+)\.([0-9]+) ]] || return 1
  major="${BASH_REMATCH[1]}"
  minor="${BASH_REMATCH[2]}"
  patch="${BASH_REMATCH[3]}"
  (( major == 1 && minor == 10 && patch == 3 ))
}

json_scalar() {
  local path="$1"
  local field="$2"

  python3 - "${path}" "${field}" <<'PY'
import json
import pathlib
import sys

def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON name: {key}")
        value[key] = item
    return value

raw = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
decoder = json.JSONDecoder(object_pairs_hook=reject_duplicates)
value, end = decoder.raw_decode(raw)
if raw[end:].strip():
    raise SystemExit("JSON document has trailing data")
for part in sys.argv[2].split("."):
    if not isinstance(value, dict) or part not in value:
        raise SystemExit(f"missing JSON field: {sys.argv[2]}")
    value = value[part]
if value is None or isinstance(value, (dict, list, bool)) or not isinstance(value, (str, int)):
    raise SystemExit(f"JSON field is not a string or integer: {sys.argv[2]}")
print(value)
PY
}

read_private_line() {
  local path="$1"
  local label="$2"

  python3 - "${path}" "${label}" <<'PY'
import os
import stat
import sys

path, label = sys.argv[1], sys.argv[2]
if not os.path.isabs(path) or os.path.normpath(path) != path:
    raise SystemExit(f"{label} path is not clean and absolute")
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(path, flags)
try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
        raise SystemExit(f"{label} is not an owner-controlled single-link regular file")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise SystemExit(f"{label} grants group or other permissions")
    if info.st_size < 2 or info.st_size > 4096:
        raise SystemExit(f"{label} has an invalid size")
    raw = os.read(fd, 4097)
    if len(raw) != info.st_size:
        raise SystemExit(f"{label} changed during its private read")
finally:
    os.close(fd)
try:
    text = raw.decode("utf-8")
except UnicodeDecodeError as error:
    raise SystemExit(f"{label} is not UTF-8") from error
if "\x00" in text or not text.endswith("\n") or "\n" in text[:-1] or "\r" in text:
    raise SystemExit(f"{label} is not one canonical line")
print(text[:-1], end="")
PY
}

require_bearer() {
  local value="$1"
  local label="$2"

  [[ "${value}" =~ ^[A-Za-z0-9_-]{43}$ ]] || die "${label} is not a canonical 256-bit bearer"
}

require_record_id() {
  local value="$1"
  local label="$2"

  [[ "${value}" =~ ^[A-Za-z0-9_-]{1,128}$ ]] || die "${label} is not a canonical record ID"
}

require_backup_id() {
  local value="$1"

  [[ "${value}" =~ ^[0-9a-f]{32}$ ]] || die "backup command did not return a canonical authenticated backup ID"
}

wait_for_server() {
  local pid="$1"
  local url="$2"
  local label="$3"
  local poll health_ready=0 application_ready=0

  for poll in {1..300}; do
    if curl --silent --show-error --fail --noproxy '*' --connect-timeout 1 --max-time 1 \
      --output /dev/null "${url}/healthz" 2>/dev/null; then
      health_ready=1
    fi
    if curl --silent --show-error --fail --noproxy '*' --connect-timeout 1 --max-time 1 \
      --output /dev/null "${url}/readyz" 2>/dev/null; then
      application_ready=1
    fi
    if [[ "${health_ready}" == "1" && "${application_ready}" == "1" ]]; then
      return 0
    fi
    if ! kill -0 "${pid}" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  die "${label} did not reach both liveness and application readiness"
}

start_source_server() {
  : >"${work_dir}/source-server.log"
  MESH_MASTER_KEY= MESH_ADMIN_TOKEN= NEBULA_CERT_BINARY="${nebula_cert}" \
    "${mesh_server}" \
    --dev \
    --listen "127.0.0.1:${source_port}" \
    --data-dir "${work_dir}/source" \
    >>"${work_dir}/source-server.log" 2>&1 &
  source_pid=$!
  wait_for_server "${source_pid}" "${source_url}" "JSON source server"
}

start_replica_one() {
  : >"${work_dir}/replica-one.log"
  MESH_MASTER_KEY="${master_key}" MESH_ADMIN_TOKEN="${admin_token}" NEBULA_CERT_BINARY="${nebula_cert}" \
    "${mesh_server}" \
    --storage-backend=postgres \
    --postgres-dsn-file="${work_dir}/postgres.dsn" \
    --allow-local-plaintext-postgres \
    --listen "127.0.0.1:${replica_one_port}" \
    --public-url "${public_origin}" \
    >>"${work_dir}/replica-one.log" 2>&1 &
  replica_one_pid=$!
  wait_for_server "${replica_one_pid}" "${replica_one_url}" "PostgreSQL replica one"
}

start_replica_two() {
  : >"${work_dir}/replica-two.log"
  MESH_MASTER_KEY="${master_key}" MESH_ADMIN_TOKEN="${admin_token}" NEBULA_CERT_BINARY="${nebula_cert}" \
    "${mesh_server}" \
    --storage-backend=postgres \
    --postgres-dsn-file="${work_dir}/postgres.dsn" \
    --allow-local-plaintext-postgres \
    --listen "127.0.0.1:${replica_two_port}" \
    --public-url "${public_origin}" \
    >>"${work_dir}/replica-two.log" 2>&1 &
  replica_two_pid=$!
  wait_for_server "${replica_two_pid}" "${replica_two_url}" "PostgreSQL replica two"
}

api_request() {
  local base_url="$1"
  local method="$2"
  local path="$3"
  local output="$4"
  local -a arguments

  arguments=(
    --silent --show-error --fail --noproxy '*'
    --connect-timeout 2 --max-time 60
    --config "${work_dir}/admin.curlrc"
    --request "${method}"
    --output "${output}"
  )
  if [[ $# -eq 5 ]]; then
    arguments+=(--data-binary "@$5")
  fi
  curl "${arguments[@]}" "${base_url}${path}"
}

wait_pair() {
  local first_pid="$1"
  local second_pid="$2"
  local label="$3"
  local first_status=0 second_status=0

  wait "${first_pid}" || first_status=$?
  wait "${second_pid}" || second_status=$?
  if [[ "${first_status}" -ne 0 || "${second_status}" -ne 0 ]]; then
    die "${label} did not complete successfully on both replicas"
  fi
}

browser_login() {
  local base_url="$1"
  local cookie_jar="$2"
  local output="$3"

  MESH_SMOKE_LOGIN_TOKEN="${admin_token}" python3 - <<'PY' |
import json
import os
import sys

token = os.environ.get("MESH_SMOKE_LOGIN_TOKEN", "")
if len(token) != 43:
    raise SystemExit("development login token is not canonical")
json.dump({"token": token}, sys.stdout, separators=(",", ":"))
PY
    curl --silent --show-error --fail --noproxy '*' \
      --connect-timeout 2 --max-time 30 \
      --request POST \
      --header 'Content-Type: application/json' \
      --header "Origin: ${public_origin}" \
      --header 'Sec-Fetch-Site: same-origin' \
      --cookie-jar "${cookie_jar}" \
      --data-binary @- \
      --output "${output}" \
      "${base_url}/api/v1/session"
  chmod 0600 "${cookie_jar}"
}

browser_session_get() {
  local base_url="$1"
  local cookie_jar="$2"
  local output="$3"

  curl --silent --show-error --fail --noproxy '*' \
    --connect-timeout 2 --max-time 30 \
    --request GET \
    --header "Origin: ${public_origin}" \
    --header 'Sec-Fetch-Site: same-origin' \
    --cookie "${cookie_jar}" \
    --cookie-jar "${cookie_jar}" \
    --output "${output}" \
    "${base_url}/api/v1/session"
}

csrf_from_cookie_jar() {
  local cookie_jar="$1"

  python3 - "${cookie_jar}" <<'PY'
import pathlib
import re
import sys

matches = []
for raw in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    line = raw
    if line.startswith("#HttpOnly_"):
        line = line[len("#HttpOnly_"):]
    elif line.startswith("#") or not line:
        continue
    fields = line.split("\t")
    if len(fields) == 7 and fields[5] == "mesh_csrf":
        matches.append(fields[6])
if len(matches) != 1 or not re.fullmatch(r"[A-Za-z0-9_-]{43}", matches[0]):
    raise SystemExit("cookie jar does not contain one canonical CSRF token")
print(matches[0])
PY
}

revoke_session_with_browser() {
  local base_url="$1"
  local actor_cookie_jar="$2"
  local target_session_id="$3"
  local output="$4"
  local csrf_token status

  csrf_token="$(csrf_from_cookie_jar "${actor_cookie_jar}")"
  {
    printf 'silent\n'
    printf 'show-error\n'
    printf 'connect-timeout = 2\n'
    printf 'max-time = 30\n'
    printf 'header = "Origin: %s"\n' "${public_origin}"
    printf 'header = "Sec-Fetch-Site: same-origin"\n'
    printf 'header = "X-Mesh-CSRF: %s"\n' "${csrf_token}"
  } >"${work_dir}/browser-csrf.curlrc"
  chmod 0600 "${work_dir}/browser-csrf.curlrc"
  csrf_token=""

  status="$(curl --silent --show-error --noproxy '*' \
    --config "${work_dir}/browser-csrf.curlrc" \
    --request DELETE \
    --cookie "${actor_cookie_jar}" \
    --cookie-jar "${actor_cookie_jar}" \
    --output "${output}" \
    --write-out '%{http_code}' \
    "${base_url}/api/v1/sessions/${target_session_id}")"
  [[ "${status}" == "204" ]] || die "cross-replica browser session revocation did not return HTTP 204"
}

assert_revoked_cookie() {
  local base_url="$1"
  local cookie_jar="$2"
  local output="$3"
  local status

  status="$(curl --silent --show-error --noproxy '*' \
    --connect-timeout 2 --max-time 30 \
    --request GET \
    --header "Origin: ${public_origin}" \
    --header 'Sec-Fetch-Site: same-origin' \
    --cookie "${cookie_jar}" \
    --output "${output}" \
    --write-out '%{http_code}' \
    "${base_url}/api/v1/session")"
  [[ "${status}" == "401" ]] || die "revoked cross-replica browser cookie remained authorized"
}

assert_shared_inventory() {
  local expected_continuity="$1"
  local networks_one="$2"
  local networks_two="$3"
  local nodes_one="$4"
  local nodes_two="$5"
  local audits_one="$6"
  local audits_two="$7"
  local session_id="${8:-}"

  python3 - \
    "${expected_continuity}" \
    "${networks_one}" "${networks_two}" \
    "${nodes_one}" "${nodes_two}" \
    "${audits_one}" "${audits_two}" \
    "${session_id}" <<'PY'
import json
import pathlib
import sys

def load(path):
    def reject_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON name: {key}")
            value[key] = item
        return value
    return json.loads(
        pathlib.Path(path).read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicates,
    )

continuity = sys.argv[1] == "1"
networks_one, networks_two = load(sys.argv[2]), load(sys.argv[3])
nodes_one, nodes_two = load(sys.argv[4]), load(sys.argv[5])
audits_one, audits_two = load(sys.argv[6]), load(sys.argv[7])
session_id = sys.argv[8]

if networks_one != networks_two:
    raise SystemExit("replicas returned different authoritative network inventories")
if nodes_one != nodes_two:
    raise SystemExit("replicas returned different authoritative node inventories")
if audits_one != audits_two:
    raise SystemExit("replicas returned different authoritative audit histories")

network_names = {item.get("name") for item in networks_one}
expected_networks = {"postgres-source", "replica-one-network", "replica-two-network"}
if network_names != expected_networks or len(networks_one) != len(expected_networks):
    raise SystemExit("a concurrent network mutation was lost or an unexpected network appeared")

expected_nodes = {"replica-one-node", "replica-two-node"}
if continuity:
    expected_nodes.add("continuity-node")
node_names = {item.get("name") for item in nodes_one}
if node_names != expected_nodes:
    raise SystemExit("a concurrent or continuity node mutation was lost")
node_ids = [item.get("id") for item in nodes_one]
node_ips = [item.get("ip") for item in nodes_one]
if len(set(node_ids)) != len(node_ids) or len(set(node_ips)) != len(node_ips):
    raise SystemExit("concurrent node allocation returned a duplicate ID or address")

network_audits = {
    event.get("details", {}).get("name")
    for event in audits_one
    if event.get("action") == "network.created"
}
if not expected_networks.issubset(network_audits):
    raise SystemExit("concurrent network audit history is incomplete")
node_audits = {
    event.get("details", {}).get("name")
    for event in audits_one
    if event.get("action") == "node.created"
}
if not expected_nodes.issubset(node_audits):
    raise SystemExit("concurrent node audit history is incomplete")
if session_id:
    created = [event for event in audits_one if event.get("action") == "session.created"]
    revoked = [
        event for event in audits_one
        if event.get("action") == "session.revoked" and event.get("target_session_id") == session_id
    ]
    if len(created) < 2 or len(revoked) != 1:
        raise SystemExit("shared identity audit history does not prove creation and revocation")
PY
}

collect_and_assert() {
  local stage="$1"
  local expected_continuity="$2"
  local session_id="${3:-}"

  api_request "${replica_one_url}" GET /api/v1/networks "${work_dir}/${stage}-networks-one.json"
  api_request "${replica_two_url}" GET /api/v1/networks "${work_dir}/${stage}-networks-two.json"
  api_request "${replica_one_url}" GET "/api/v1/networks/${source_network_id}/nodes" "${work_dir}/${stage}-nodes-one.json"
  api_request "${replica_two_url}" GET "/api/v1/networks/${source_network_id}/nodes" "${work_dir}/${stage}-nodes-two.json"
  api_request "${replica_one_url}" GET /api/v1/audit "${work_dir}/${stage}-audit-one.json"
  api_request "${replica_two_url}" GET /api/v1/audit "${work_dir}/${stage}-audit-two.json"
  assert_shared_inventory \
    "${expected_continuity}" \
    "${work_dir}/${stage}-networks-one.json" "${work_dir}/${stage}-networks-two.json" \
    "${work_dir}/${stage}-nodes-one.json" "${work_dir}/${stage}-nodes-two.json" \
    "${work_dir}/${stage}-audit-one.json" "${work_dir}/${stage}-audit-two.json" \
    "${session_id}"
}

if [[ "${keep_smoke}" != "0" && "${keep_smoke}" != "1" ]]; then
  die "KEEP_MESH_SMOKE must be 0 or 1"
fi
if (( BASH_VERSINFO[0] < 4 )); then
  skip "Bash 4 or newer is required"
fi
if [[ "$(uname -s 2>/dev/null || true)" != "Linux" ]]; then
  skip "the secure backup importer and this smoke require Linux"
fi
for prerequisite in go python3 curl docker mktemp chmod mkdir rm ps readlink sleep tr uname; do
  command -v -- "${prerequisite}" >/dev/null 2>&1 || skip "required command is unavailable: ${prerequisite}"
done
[[ -x "${nebula_cert}" && -f "${nebula_cert}" && ! -L "${nebula_cert}" ]] || \
  skip "real /usr/local/bin/nebula-cert is unavailable"
nebula_cert_version="$(${nebula_cert} -version 2>&1)" || skip "nebula-cert -version failed"
nebula_version_exact "${nebula_cert_version}" || skip "exact nebula-cert 1.10.3 is required"
unset nebula_cert_version
docker info >/dev/null 2>&1 || skip "Docker daemon access is unavailable"
docker image inspect "${postgres_image}" >/dev/null 2>&1 || skip "cached postgres:17-alpine image is unavailable"

temporary_parent="${TMPDIR:-/tmp}"
[[ -d "${temporary_parent}" && ! -L "${temporary_parent}" ]] || skip "private temporary directory parent is unavailable"
work_parent="$(cd -- "${temporary_parent}" && pwd -P)"
work_dir="$(mktemp -d "${work_parent%/}/mesh-postgres-multi-replica-smoke.XXXXXX")"
[[ -d "${work_dir}" && ! -L "${work_dir}" ]] || die "mktemp did not create a real private workspace"
chmod 0700 "${work_dir}"
mkdir -- "${work_dir}/bin" "${work_dir}/source"
chmod 0700 "${work_dir}/bin" "${work_dir}/source"
cd -- "${repo_root}"

say "Building isolated Mesh server, storage, and backup executables"
go build -buildvcs=false -trimpath -o "${work_dir}/bin/mesh-server" ./cmd/mesh-server \
  >"${work_dir}/build-server.log" 2>&1
go build -buildvcs=false -trimpath -o "${work_dir}/bin/mesh-storage" ./cmd/mesh-storage \
  >"${work_dir}/build-storage.log" 2>&1
go build -buildvcs=false -trimpath -o "${work_dir}/bin/mesh-backup" ./cmd/mesh-backup \
  >"${work_dir}/build-backup.log" 2>&1
mesh_server="$(readlink -f -- "${work_dir}/bin/mesh-server")"
mesh_storage="$(readlink -f -- "${work_dir}/bin/mesh-storage")"
mesh_backup="$(readlink -f -- "${work_dir}/bin/mesh-backup")"

source_port="$(pick_loopback_port)"
[[ "${source_port}" =~ ^[0-9]+$ && "${source_port}" -ge 1024 && "${source_port}" -le 65535 ]] || \
  die "kernel returned an invalid source loopback port"
source_url="http://127.0.0.1:${source_port}"

say "Creating one current control-v5 JSON source network and authenticated encrypted backup"
start_source_server
admin_token="$(read_private_line "${work_dir}/source/admin.token" "development administrator token")"
master_key="$(read_private_line "${work_dir}/source/master.key" "development master key")"
require_bearer "${admin_token}" "development administrator token"
require_bearer "${master_key}" "development master key"
{
  printf 'silent\n'
  printf 'show-error\n'
  printf 'fail\n'
  printf 'connect-timeout = 2\n'
  printf 'max-time = 60\n'
  printf 'header = "Authorization: Bearer %s"\n' "${admin_token}"
  printf 'header = "Content-Type: application/json"\n'
  printf 'header = "Accept: application/json"\n'
} >"${work_dir}/admin.curlrc"
chmod 0600 "${work_dir}/admin.curlrc"

printf '%s\n' '{"name":"postgres-source","cidr":"10.91.0.0/24"}' >"${work_dir}/source-network-request.json"
api_request "${source_url}" POST /api/v1/networks "${work_dir}/source-network.json" "${work_dir}/source-network-request.json"
source_network_id="$(json_scalar "${work_dir}/source-network.json" id)"
require_record_id "${source_network_id}" "source network ID"

stop_child "${source_pid}" "${mesh_server}"
source_pid=""

"${mesh_backup}" keygen --output "${work_dir}/backup.key" \
  >"${work_dir}/backup-keygen.json" 2>"${work_dir}/backup-keygen.stderr"
MESH_MASTER_KEY="${master_key}" MESH_ADMIN_TOKEN="${admin_token}" \
  "${mesh_backup}" create \
    --data-dir "${work_dir}/source" \
    --key-file "${work_dir}/backup.key" \
    --output "${work_dir}/source.meshbackup" \
    >"${work_dir}/backup-create.json" 2>"${work_dir}/backup-create.stderr"
backup_id="$(json_scalar "${work_dir}/backup-create.json" backup_id)"
require_backup_id "${backup_id}"
"${mesh_backup}" verify \
  --key-file "${work_dir}/backup.key" \
  --archive "${work_dir}/source.meshbackup" \
  >"${work_dir}/backup-verify.json" 2>"${work_dir}/backup-verify.stderr"
[[ "$(json_scalar "${work_dir}/backup-verify.json" backup_id)" == "${backup_id}" ]] || \
  die "backup verification returned a different authenticated backup ID"

run_id="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(8))
PY
)"
[[ "${run_id}" =~ ^[0-9a-f]{16}$ ]] || die "could not generate a canonical disposable run identifier"
container_name="mesh-postgres-multi-replica-smoke-${run_id}"
postgres_password="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
require_bearer "${postgres_password}" "disposable PostgreSQL password"
{
  printf 'POSTGRES_USER=mesh\n'
  printf 'POSTGRES_DB=mesh\n'
  printf 'POSTGRES_PASSWORD=%s\n' "${postgres_password}"
} >"${work_dir}/postgres.env"
chmod 0600 "${work_dir}/postgres.env"

say "Starting one exact disposable PostgreSQL 17 target"
docker run --detach \
  --name "${container_name}" \
  --label "io.mesh.smoke.instance=${run_id}" \
  --env-file "${work_dir}/postgres.env" \
  --publish '127.0.0.1::5432' \
  "${postgres_image}" \
  >"${work_dir}/container.id" 2>"${work_dir}/docker-run.stderr"
container_started=1
reported_container_id="$(tr -d '\r\n' <"${work_dir}/container.id")"
observed_container_id="$(docker inspect --format '{{.Id}}' "${container_name}" 2>/dev/null || true)"
[[ "${reported_container_id}" =~ ^[0-9a-f]{64}$ &&
   "${observed_container_id}" =~ ^[0-9a-f]{64}$ &&
   "${reported_container_id}" == "${observed_container_id}" ]] || die "Docker did not return one exact canonical container ID"
container_id="${observed_container_id}"
container_matches_run || die "disposable PostgreSQL container identity did not match its exact label and ID"

postgres_ready=0
for poll in {1..300}; do
  # The image briefly starts a Unix-socket-only bootstrap postmaster before it
  # creates the requested database. Requiring the final TCP listener avoids a
  # false-ready handoff during that initialization window.
  if docker exec "${container_name}" pg_isready --quiet --host 127.0.0.1 --port 5432 --username mesh --dbname mesh \
    >"${work_dir}/pg-isready.stdout" 2>"${work_dir}/pg-isready.stderr"; then
    postgres_ready=1
    break
  fi
  sleep 0.1
done
[[ "${postgres_ready}" == "1" ]] || die "disposable PostgreSQL did not become ready"

port_mapping="$(docker port "${container_name}" 5432/tcp 2>/dev/null)"
if [[ ! "${port_mapping}" =~ ^127\.0\.0\.1:([0-9]+)$ ]]; then
  die "Docker did not publish PostgreSQL on one numeric IPv4 loopback port"
fi
postgres_port="${BASH_REMATCH[1]}"
[[ "${postgres_port}" -ge 1024 && "${postgres_port}" -le 65535 ]] || \
  die "Docker returned an invalid PostgreSQL host port"
printf 'postgres://mesh:%s@127.0.0.1:%s/mesh?sslmode=disable&target_session_attrs=read-write&connect_timeout=5&pool_max_conns=8\n' \
  "${postgres_password}" "${postgres_port}" >"${work_dir}/postgres.dsn"
chmod 0600 "${work_dir}/postgres.dsn"

say "Migrating, importing the exact selected backup, and rereading it cryptographically"
"${mesh_storage}" migrate \
  --postgres-dsn-file "${work_dir}/postgres.dsn" \
  --allow-local-plaintext-postgres \
  >"${work_dir}/storage-migrate.json" 2>"${work_dir}/storage-migrate.stderr"
[[ "$(json_scalar "${work_dir}/storage-migrate.json" status)" == "migrated" ]] || \
  die "PostgreSQL migration did not report success"
"${mesh_storage}" import-backup \
  --postgres-dsn-file "${work_dir}/postgres.dsn" \
  --backup-key-file "${work_dir}/backup.key" \
  --backup-archive "${work_dir}/source.meshbackup" \
  --expect-backup-id "${backup_id}" \
  --allow-local-plaintext-postgres \
  >"${work_dir}/storage-import.json" 2>"${work_dir}/storage-import.stderr"
[[ "$(json_scalar "${work_dir}/storage-import.json" status)" == "imported" ]] || \
  die "PostgreSQL import did not report success"
[[ "$(json_scalar "${work_dir}/storage-import.json" backup_id)" == "${backup_id}" ]] || \
  die "PostgreSQL import provenance has the wrong authenticated backup ID"
"${mesh_storage}" verify \
  --postgres-dsn-file "${work_dir}/postgres.dsn" \
  --backup-key-file "${work_dir}/backup.key" \
  --backup-archive "${work_dir}/source.meshbackup" \
  --expect-backup-id "${backup_id}" \
  --allow-local-plaintext-postgres \
  >"${work_dir}/storage-verify.json" 2>"${work_dir}/storage-verify.stderr"
[[ "$(json_scalar "${work_dir}/storage-verify.json" status)" == "verified" ]] || \
  die "PostgreSQL exact-document verification did not report success"

replica_one_port="$(pick_loopback_port)"
replica_two_port="$(pick_loopback_port)"
[[ "${replica_one_port}" =~ ^[0-9]+$ && "${replica_two_port}" =~ ^[0-9]+$ && \
   "${replica_one_port}" -ge 1024 && "${replica_one_port}" -le 65535 && \
   "${replica_two_port}" -ge 1024 && "${replica_two_port}" -le 65535 && \
   "${replica_one_port}" != "${replica_two_port}" ]] || die "kernel returned invalid or duplicate replica ports"
replica_one_url="http://127.0.0.1:${replica_one_port}"
replica_two_url="http://127.0.0.1:${replica_two_port}"
# Both processes model backends behind one browser origin. Direct loopback
# ports are used only to prove that each backend independently serves state.
public_origin="${replica_one_url}"

say "Launching two independent PostgreSQL-backed application replicas"
start_replica_one
start_replica_two

printf '%s\n' '{"name":"replica-one-network","cidr":"10.92.0.0/24"}' >"${work_dir}/network-one-request.json"
printf '%s\n' '{"name":"replica-two-network","cidr":"10.93.0.0/24"}' >"${work_dir}/network-two-request.json"
api_request "${replica_one_url}" POST /api/v1/networks \
  "${work_dir}/network-one-response.json" "${work_dir}/network-one-request.json" &
network_one_request_pid=$!
api_request "${replica_two_url}" POST /api/v1/networks \
  "${work_dir}/network-two-response.json" "${work_dir}/network-two-request.json" &
network_two_request_pid=$!
wait_pair "${network_one_request_pid}" "${network_two_request_pid}" "concurrent network creation"

printf '%s\n' '{"name":"replica-one-node","role":"member"}' >"${work_dir}/node-one-request.json"
printf '%s\n' '{"name":"replica-two-node","role":"member"}' >"${work_dir}/node-two-request.json"
api_request "${replica_one_url}" POST "/api/v1/networks/${source_network_id}/nodes" \
  "${work_dir}/node-one-response.json" "${work_dir}/node-one-request.json" &
node_one_request_pid=$!
api_request "${replica_two_url}" POST "/api/v1/networks/${source_network_id}/nodes" \
  "${work_dir}/node-two-response.json" "${work_dir}/node-two-request.json" &
node_two_request_pid=$!
wait_pair "${node_one_request_pid}" "${node_two_request_pid}" "concurrent node creation"

node_one_id="$(json_scalar "${work_dir}/node-one-response.json" node.id)"
node_two_id="$(json_scalar "${work_dir}/node-two-response.json" node.id)"
require_record_id "${node_one_id}" "replica one node ID"
require_record_id "${node_two_id}" "replica two node ID"
[[ "${node_one_id}" != "${node_two_id}" ]] || die "concurrent replicas returned the same node ID"

say "Proving shared browser sessions and cross-replica CSRF-protected revocation"
browser_login "${replica_one_url}" "${work_dir}/browser-one.cookies" "${work_dir}/browser-one-login.json"
browser_one_session_id="$(json_scalar "${work_dir}/browser-one-login.json" session_id)"
require_record_id "${browser_one_session_id}" "first browser session ID"
browser_session_get "${replica_two_url}" "${work_dir}/browser-one.cookies" "${work_dir}/browser-one-via-two.json"
[[ "$(json_scalar "${work_dir}/browser-one-via-two.json" session_id)" == "${browser_one_session_id}" ]] || \
  die "replica two did not observe the session created through replica one"
browser_login "${replica_two_url}" "${work_dir}/browser-two.cookies" "${work_dir}/browser-two-login.json"
browser_two_session_id="$(json_scalar "${work_dir}/browser-two-login.json" session_id)"
require_record_id "${browser_two_session_id}" "second browser session ID"
[[ "${browser_one_session_id}" != "${browser_two_session_id}" ]] || die "browser logins returned duplicate session IDs"
revoke_session_with_browser \
  "${replica_two_url}" "${work_dir}/browser-two.cookies" "${browser_one_session_id}" "${work_dir}/browser-revoke.json"
assert_revoked_cookie "${replica_one_url}" "${work_dir}/browser-one.cookies" "${work_dir}/browser-one-revoked.json"

collect_and_assert before-restart 0 "${browser_one_session_id}"

say "Hard-stopping one application replica while the other remains ready"
replica_one_to_kill="${replica_one_pid}"
if ! valid_child_pid "${replica_one_to_kill}" "${mesh_server}"; then
  die "replica one process identity could not be verified before forced termination"
fi
kill -KILL "${replica_one_to_kill}"
wait "${replica_one_to_kill}" 2>/dev/null || true
replica_one_pid=""
curl --silent --show-error --fail --noproxy '*' --connect-timeout 2 --max-time 5 \
  --output /dev/null "${replica_two_url}/readyz"

printf '%s\n' '{"name":"continuity-node","role":"member"}' >"${work_dir}/continuity-node-request.json"
api_request "${replica_two_url}" POST "/api/v1/networks/${source_network_id}/nodes" \
  "${work_dir}/continuity-node-response.json" "${work_dir}/continuity-node-request.json"
continuity_node_id="$(json_scalar "${work_dir}/continuity-node-response.json" node.id)"
require_record_id "${continuity_node_id}" "continuity node ID"

say "Restarting the stopped replica and proving convergence without fallback state"
start_replica_one
collect_and_assert after-restart 1 "${browser_one_session_id}"

say "PASS: two application replicas shared imported control and identity state without lost concurrent updates"
say "PASS: a session crossed replicas, was revoked through CSRF on the peer, and stayed revoked after restart"
say "PASS: the surviving replica remained ready and accepted a mutation while its peer was stopped"
say "LIMIT: this proves application multi-replica correctness against one PostgreSQL container; it does not prove database failover or PITR"
