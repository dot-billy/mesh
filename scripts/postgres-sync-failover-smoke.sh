#!/usr/bin/env bash

# Disposable local proof that an acknowledged Mesh control/identity timeline
# survives promotion of a synchronous PostgreSQL 17 physical standby. This is
# intentionally a bounded failover smoke, not a PITR, ambiguous-commit, TLS,
# least-privilege-role, load, or soak proof.

set -Eeuo pipefail
umask 077

readonly skip_status=77
readonly script_name="${0##*/}"
readonly keep_smoke="${KEEP_MESH_SMOKE:-0}"
readonly postgres_image="postgres:17-alpine"
readonly nebula_cert="/usr/local/bin/nebula-cert"
readonly smoke_label="io.mesh.smoke.instance"
readonly smoke_kind_label="io.mesh.smoke.kind"

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
work_parent=""
work_dir=""
run_id=""
network_name=""
network_id=""
primary_volume=""
standby_volume=""
primary_container=""
standby_bootstrap_container=""
standby_container=""

declare -A container_ids=()
declare -A volume_ids=()

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
source_network_id=""

admin_token=""
master_key=""
postgres_password=""
replication_password=""

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
  local name="$1"
  local expected_id="${container_ids[${name}]:-}"
  local observed_name observed_id observed_run observed_kind

  [[ -n "${run_id}" && "${run_id}" =~ ^[0-9a-f]{16}$ ]] || return 1
  [[ "${name}" =~ ^mesh-postgres-sync-failover-smoke-[0-9a-f]{16}-(primary|standby-bootstrap|standby)$ ]] || return 1
  [[ "${expected_id}" =~ ^[0-9a-f]{64}$ ]] || return 1
  observed_name="$(docker inspect --format '{{.Name}}' "${name}" 2>/dev/null || true)"
  observed_id="$(docker inspect --format '{{.Id}}' "${name}" 2>/dev/null || true)"
  observed_run="$(docker inspect --format '{{ index .Config.Labels "io.mesh.smoke.instance" }}' "${name}" 2>/dev/null || true)"
  observed_kind="$(docker inspect --format '{{ index .Config.Labels "io.mesh.smoke.kind" }}' "${name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "/${name}" && "${observed_id}" == "${expected_id}" &&
     "${observed_run}" == "${run_id}" && "${observed_kind}" == "postgres-sync-failover" ]]
}

network_matches_run() {
  local observed_name observed_id observed_run observed_kind

  [[ -n "${network_name}" && "${network_name}" =~ ^mesh-postgres-sync-failover-smoke-[0-9a-f]{16}-network$ ]] || return 1
  [[ "${network_id}" =~ ^[0-9a-f]{64}$ ]] || return 1
  observed_name="$(docker network inspect --format '{{.Name}}' "${network_name}" 2>/dev/null || true)"
  observed_id="$(docker network inspect --format '{{.Id}}' "${network_name}" 2>/dev/null || true)"
  observed_run="$(docker network inspect --format '{{ index .Labels "io.mesh.smoke.instance" }}' "${network_name}" 2>/dev/null || true)"
  observed_kind="$(docker network inspect --format '{{ index .Labels "io.mesh.smoke.kind" }}' "${network_name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "${network_name}" && "${observed_id}" == "${network_id}" &&
     "${observed_run}" == "${run_id}" && "${observed_kind}" == "postgres-sync-failover" ]]
}

volume_matches_run() {
  local name="$1"
  local expected_name="${volume_ids[${name}]:-}"
  local observed_name observed_run observed_kind

  [[ "${name}" =~ ^mesh-postgres-sync-failover-smoke-[0-9a-f]{16}-(primary|standby)-data$ ]] || return 1
  [[ "${expected_name}" == "${name}" ]] || return 1
  observed_name="$(docker volume inspect --format '{{.Name}}' "${name}" 2>/dev/null || true)"
  observed_run="$(docker volume inspect --format '{{ index .Labels "io.mesh.smoke.instance" }}' "${name}" 2>/dev/null || true)"
  observed_kind="$(docker volume inspect --format '{{ index .Labels "io.mesh.smoke.kind" }}' "${name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "${name}" && "${observed_run}" == "${run_id}" &&
     "${observed_kind}" == "postgres-sync-failover" ]]
}

adopt_container_for_cleanup() {
  local name="$1"
  local observed_name observed_id observed_run observed_kind

  [[ -n "${run_id}" && "${run_id}" =~ ^[0-9a-f]{16}$ ]] || return 1
  [[ "${name}" =~ ^mesh-postgres-sync-failover-smoke-${run_id}-(primary|standby-bootstrap|standby)$ ]] || return 1
  observed_name="$(docker inspect --format '{{.Name}}' "${name}" 2>/dev/null || true)"
  observed_id="$(docker inspect --format '{{.Id}}' "${name}" 2>/dev/null || true)"
  observed_run="$(docker inspect --format '{{ index .Config.Labels "io.mesh.smoke.instance" }}' "${name}" 2>/dev/null || true)"
  observed_kind="$(docker inspect --format '{{ index .Config.Labels "io.mesh.smoke.kind" }}' "${name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "/${name}" && "${observed_id}" =~ ^[0-9a-f]{64}$ &&
     "${observed_run}" == "${run_id}" && "${observed_kind}" == "postgres-sync-failover" ]] || return 1
  container_ids["${name}"]="${observed_id}"
}

adopt_network_for_cleanup() {
  local observed_name observed_id observed_run observed_kind

  [[ -n "${run_id}" && "${network_name}" == "mesh-postgres-sync-failover-smoke-${run_id}-network" ]] || return 1
  observed_name="$(docker network inspect --format '{{.Name}}' "${network_name}" 2>/dev/null || true)"
  observed_id="$(docker network inspect --format '{{.Id}}' "${network_name}" 2>/dev/null || true)"
  observed_run="$(docker network inspect --format '{{ index .Labels "io.mesh.smoke.instance" }}' "${network_name}" 2>/dev/null || true)"
  observed_kind="$(docker network inspect --format '{{ index .Labels "io.mesh.smoke.kind" }}' "${network_name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "${network_name}" && "${observed_id}" =~ ^[0-9a-f]{64}$ &&
     "${observed_run}" == "${run_id}" && "${observed_kind}" == "postgres-sync-failover" ]] || return 1
  network_id="${observed_id}"
}

adopt_volume_for_cleanup() {
  local name="$1"
  local observed_name observed_run observed_kind

  [[ -n "${run_id}" && "${name}" =~ ^mesh-postgres-sync-failover-smoke-${run_id}-(primary|standby)-data$ ]] || return 1
  observed_name="$(docker volume inspect --format '{{.Name}}' "${name}" 2>/dev/null || true)"
  observed_run="$(docker volume inspect --format '{{ index .Labels "io.mesh.smoke.instance" }}' "${name}" 2>/dev/null || true)"
  observed_kind="$(docker volume inspect --format '{{ index .Labels "io.mesh.smoke.kind" }}' "${name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "${name}" && "${observed_run}" == "${run_id}" &&
     "${observed_kind}" == "postgres-sync-failover" ]] || return 1
  volume_ids["${name}"]="${name}"
}

remove_container_exact() {
  local name="$1"

  if [[ -z "${container_ids[${name}]:-}" ]]; then
    if ! docker inspect "${name}" >/dev/null 2>&1; then
      return 0
    fi
    adopt_container_for_cleanup "${name}" || {
      printf 'ERROR: refusing to adopt unexpected container %s for cleanup\n' "${name}" >&2
      return 1
    }
  fi
  if container_matches_run "${name}"; then
    docker rm --force -- "${name}" >/dev/null
    unset 'container_ids[$name]'
  elif docker inspect "${name}" >/dev/null 2>&1; then
    printf 'ERROR: refusing to remove container %s because its exact identity or labels changed\n' "${name}" >&2
    return 1
  else
    unset 'container_ids[$name]'
  fi
}

cleanup() {
  local status=$?
  local name base parent

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

  admin_token=""
  master_key=""
  postgres_password=""
  replication_password=""

  if [[ "${keep_smoke}" == "1" ]]; then
    if (( ${#container_ids[@]} > 0 )); then
      printf 'Kept exact labeled PostgreSQL failover containers for debugging.\n' >&2
    fi
  else
    for name in "${standby_bootstrap_container}" "${standby_container}" "${primary_container}"; do
      [[ -n "${name}" ]] || continue
      remove_container_exact "${name}" || status=1
    done
    if [[ -z "${network_id}" && -n "${network_name}" ]] && docker network inspect "${network_name}" >/dev/null 2>&1; then
      adopt_network_for_cleanup || {
        printf 'ERROR: refusing to adopt unexpected Docker network for cleanup\n' >&2
        status=1
      }
    fi
    if [[ -n "${network_id}" ]]; then
      if network_matches_run; then
        docker network rm -- "${network_name}" >/dev/null 2>&1 || status=1
        network_id=""
      elif docker network inspect "${network_name}" >/dev/null 2>&1; then
        printf 'ERROR: refusing to remove Docker network whose exact identity or labels changed\n' >&2
        status=1
      else
        network_id=""
      fi
    fi
    for name in "${standby_volume}" "${primary_volume}"; do
      [[ -n "${name}" ]] || continue
      if [[ -z "${volume_ids[${name}]:-}" ]] && docker volume inspect "${name}" >/dev/null 2>&1; then
        adopt_volume_for_cleanup "${name}" || {
          printf 'ERROR: refusing to adopt unexpected Docker volume %s for cleanup\n' "${name}" >&2
          status=1
        }
      fi
      if [[ -n "${volume_ids[${name}]:-}" ]]; then
        if volume_matches_run "${name}"; then
          docker volume rm -- "${name}" >/dev/null 2>&1 || status=1
          unset 'volume_ids[$name]'
        elif docker volume inspect "${name}" >/dev/null 2>&1; then
          printf 'ERROR: refusing to remove Docker volume %s because its exact labels changed\n' "${name}" >&2
          status=1
        else
          unset 'volume_ids[$name]'
        fi
      fi
    done
  fi

  if [[ -n "${work_dir}" && -d "${work_dir}" ]]; then
    if [[ "${keep_smoke}" == "1" ]]; then
      printf 'Kept private failover workspace: %s\n' "${work_dir}" >&2
      printf 'It contains disposable credentials that also exist in the retained database volumes.\n' >&2
    else
      base="${work_dir##*/}"
      parent="$(cd -- "$(dirname -- "${work_dir}")" 2>/dev/null && pwd -P)"
      if [[ "${base}" == mesh-postgres-sync-failover-smoke.* && -n "${work_parent}" &&
            "${parent}" == "${work_parent}" && ! -L "${work_dir}" ]]; then
        rm -rf -- "${work_dir}"
      else
        printf 'ERROR: refusing to remove unexpected failover workspace %s\n' "${work_dir}" >&2
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
  printf 'ERROR: %s failed at line %s (set KEEP_MESH_SMOKE=1 to retain exact private diagnostics)\n' \
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
text = raw.decode("utf-8")
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

  for poll in {1..600}; do
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
  wait_for_server "${replica_one_pid}" "${replica_one_url}" "PostgreSQL application replica one"
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
  wait_for_server "${replica_two_pid}" "${replica_two_url}" "PostgreSQL application replica two"
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

register_container() {
  local name="$1"
  local id_file="$2"
  local reported observed

  reported="$(tr -d '\r\n' <"${id_file}")"
  observed="$(docker inspect --format '{{.Id}}' "${name}" 2>/dev/null || true)"
  [[ "${reported}" =~ ^[0-9a-f]{64}$ && "${observed}" =~ ^[0-9a-f]{64}$ &&
     "${reported}" == "${observed}" ]] || die "Docker did not return one exact canonical ID for ${name}"
  container_ids["${name}"]="${observed}"
  container_matches_run "${name}" || die "container ${name} did not match its exact name, ID, and smoke labels"
}

container_port() {
  local name="$1"
  local mapping

  container_matches_run "${name}" || die "refusing to inspect an unverified container port"
  mapping="$(docker port "${name}" 5432/tcp 2>/dev/null)"
  if [[ ! "${mapping}" =~ ^127\.0\.0\.1:([0-9]+)$ ]]; then
    die "Docker did not publish ${name} PostgreSQL on one numeric IPv4 loopback port"
  fi
  [[ "${BASH_REMATCH[1]}" -ge 1024 && "${BASH_REMATCH[1]}" -le 65535 ]] || \
    die "Docker returned an invalid PostgreSQL host port"
  printf '%s\n' "${BASH_REMATCH[1]}"
}

wait_postgres_ready() {
  local name="$1"
  local label="$2"
  local poll

  for poll in {1..600}; do
    container_matches_run "${name}" || die "${label} container identity changed while waiting for readiness"
    if docker exec --user postgres "${name}" \
      pg_isready --quiet --host 127.0.0.1 --port 5432 --username mesh --dbname mesh \
      >"${work_dir}/${label}-pg-isready.stdout" 2>"${work_dir}/${label}-pg-isready.stderr"; then
      return 0
    fi
    sleep 0.1
  done
  die "${label} did not become PostgreSQL-ready"
}

postgres_scalar() {
  local name="$1"
  local query="$2"

  container_matches_run "${name}" || die "refusing a PostgreSQL query against an unverified container"
  docker exec --user postgres "${name}" \
    psql -X --no-psqlrc --set=ON_ERROR_STOP=1 --tuples-only --no-align \
      --username mesh --dbname mesh --command "${query}" | tr -d '\r\n'
}

postgres_script() {
  local name="$1"
  local output="$2"

  container_matches_run "${name}" || die "refusing PostgreSQL input against an unverified container"
  docker exec --interactive --user postgres "${name}" \
    psql -X --no-psqlrc --set=ON_ERROR_STOP=1 --username mesh --dbname mesh \
    >"${output}"
}

wait_standby_streaming() {
  local poll status

  for poll in {1..600}; do
    status="$(postgres_scalar "${primary_container}" \
      "SELECT application_name || '|' || state || '|' || sync_state || '|' ||
              (replay_lsn >= pg_current_wal_flush_lsn())::text
         FROM pg_catalog.pg_stat_replication
        WHERE application_name = 'mesh_standby';")"
    if [[ "${status}" == "mesh_standby|streaming|sync|true" ]]; then
      return 0
    fi
    sleep 0.1
  done
  die "named physical standby did not reach synchronous streaming replay"
}

wait_promoted_writable() {
  local poll recovery read_only

  for poll in {1..600}; do
    recovery="$(postgres_scalar "${standby_container}" "SELECT pg_catalog.pg_is_in_recovery();" 2>/dev/null || true)"
    read_only="$(postgres_scalar "${standby_container}" "SHOW transaction_read_only;" 2>/dev/null || true)"
    if [[ "${recovery}" == "f" && "${read_only}" == "off" ]]; then
      return 0
    fi
    sleep 0.1
  done
  die "promoted standby did not become the writable authority"
}

capture_database_manifest() {
  local name="$1"
  local output="$2"

  {
    printf '%s\n' '\pset format unaligned'
    printf '%s\n' '\pset tuples_only on'
    printf '%s\n' "\\pset fieldsep '|'"
    printf '%s\n' 'BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;'
    printf '%s\n' "SELECT 'document', document_key, revision, pg_catalog.encode(document_sha256, 'hex'), last_write_receipt::text, pg_catalog.octet_length(document_bytes) FROM mesh.mesh_state_documents ORDER BY document_key;"
    printf '%s\n' "SELECT 'receipt', r.receipt_id::text, r.operation_class, pg_catalog.to_char(r.committed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'), d.document_key, d.base_revision, d.committed_revision, pg_catalog.encode(d.document_sha256, 'hex') FROM mesh.mesh_write_receipts AS r JOIN mesh.mesh_write_receipt_documents AS d ON d.receipt_id = r.receipt_id ORDER BY r.committed_at, r.receipt_id, d.document_key;"
    printf '%s\n' "SELECT 'import', import_id::text, import_receipt::text, source_backup_id, pg_catalog.encode(source_control_sha256, 'hex'), pg_catalog.encode(source_identity_sha256, 'hex') FROM mesh.mesh_import_metadata;"
    printf '%s\n' 'COMMIT;'
  } | postgres_script "${name}" "${output}"
}

assert_acknowledged_revisions() {
  local name="$1"
  local control identity

  control="$(postgres_scalar "${name}" "SELECT revision || '|' || last_write_receipt::text FROM mesh.mesh_state_documents WHERE document_key = 'control';")"
  identity="$(postgres_scalar "${name}" "SELECT revision || '|' || last_write_receipt::text FROM mesh.mesh_state_documents WHERE document_key = 'identity';")"
  [[ "${control}" =~ ^3\|[0-9a-f-]{36}$ ]] || die "acknowledged control revision/receipt was not exact revision 3"
  [[ "${identity}" =~ ^2\|[0-9a-f-]{36}$ ]] || die "acknowledged identity revision/receipt was not exact revision 2"
  [[ "${control#*|}" != "${identity#*|}" ]] || die "control and identity mutations unexpectedly shared one receipt"
}

assert_api_snapshot_equal() {
  local expected_prefix="$1"
  local actual_prefix="$2"
  local session_id="$3"

  python3 - "${expected_prefix}" "${actual_prefix}" "${session_id}" <<'PY'
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
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)

expected_prefix, actual_prefix, session_id = sys.argv[1:]
expected_networks = load(expected_prefix + "-networks.json")
actual_networks = load(actual_prefix + "-networks.json")
expected_nodes = load(expected_prefix + "-nodes.json")
actual_nodes = load(actual_prefix + "-nodes.json")
expected_audit = load(expected_prefix + "-audit.json")
actual_audit = load(actual_prefix + "-audit.json")
if expected_networks != actual_networks:
    raise SystemExit("network inventory changed across synchronous promotion")
if expected_nodes != actual_nodes:
    raise SystemExit("node inventory changed across synchronous promotion")
if expected_audit != actual_audit:
    raise SystemExit("control/identity audit history changed across synchronous promotion")
network_names = {item.get("name") for item in actual_networks}
if network_names != {"postgres-source", "before-failover-network"}:
    raise SystemExit("acknowledged network mutation is absent after promotion")
node_names = {item.get("name") for item in actual_nodes}
if node_names != {"before-failover-node"}:
    raise SystemExit("acknowledged node mutation is absent after promotion")
session_events = [
    item for item in actual_audit
    if item.get("action") == "session.created" and item.get("target_session_id") == session_id
]
if len(session_events) != 1:
    raise SystemExit("acknowledged browser session audit is absent after promotion")
PY
}

collect_api_snapshot() {
  local base_url="$1"
  local prefix="$2"

  api_request "${base_url}" GET /api/v1/networks "${prefix}-networks.json"
  api_request "${base_url}" GET "/api/v1/networks/${source_network_id}/nodes" "${prefix}-nodes.json"
  api_request "${base_url}" GET /api/v1/audit "${prefix}-audit.json"
}

assert_final_convergence() {
  local first_prefix="$1"
  local second_prefix="$2"
  local original_session_id="$3"
  local fresh_session_id="$4"

  python3 - "${first_prefix}" "${second_prefix}" "${original_session_id}" "${fresh_session_id}" <<'PY'
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
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)

first, second, original_session, fresh_session = sys.argv[1:]
for suffix in ("networks", "nodes", "audit"):
    if load(f"{first}-{suffix}.json") != load(f"{second}-{suffix}.json"):
        raise SystemExit(f"application replicas diverged after failover: {suffix}")
networks = load(f"{first}-networks.json")
nodes = load(f"{first}-nodes.json")
audit = load(f"{first}-audit.json")
if {item.get("name") for item in networks} != {
    "postgres-source", "before-failover-network", "after-failover-network"
}:
    raise SystemExit("final network inventory does not contain the exact pre/post-failover mutations")
if {item.get("name") for item in nodes} != {"before-failover-node"}:
    raise SystemExit("final node inventory is incomplete")
created_sessions = {
    item.get("target_session_id")
    for item in audit
    if item.get("action") == "session.created"
}
if not {original_session, fresh_session}.issubset(created_sessions):
    raise SystemExit("final identity audit is missing a pre/post-failover session mutation")
PY
}

if [[ "${keep_smoke}" != "0" && "${keep_smoke}" != "1" ]]; then
  die "KEEP_MESH_SMOKE must be 0 or 1"
fi
if (( BASH_VERSINFO[0] < 4 )); then
  skip "Bash 4 or newer is required"
fi
if [[ "$(uname -s 2>/dev/null || true)" != "Linux" ]]; then
  skip "the secure backup importer and this failover smoke require Linux"
fi
for prerequisite in go python3 curl docker mktemp chmod mkdir rm ps readlink sleep tr uname cmp; do
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
work_dir="$(mktemp -d "${work_parent%/}/mesh-postgres-sync-failover-smoke.XXXXXX")"
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

say "Creating one current control-v5 JSON source and authenticated encrypted backup"
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

printf '%s\n' '{"name":"postgres-source","cidr":"10.94.0.0/24"}' >"${work_dir}/source-network-request.json"
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
network_name="mesh-postgres-sync-failover-smoke-${run_id}-network"
primary_volume="mesh-postgres-sync-failover-smoke-${run_id}-primary-data"
standby_volume="mesh-postgres-sync-failover-smoke-${run_id}-standby-data"
primary_container="mesh-postgres-sync-failover-smoke-${run_id}-primary"
standby_bootstrap_container="mesh-postgres-sync-failover-smoke-${run_id}-standby-bootstrap"
standby_container="mesh-postgres-sync-failover-smoke-${run_id}-standby"
postgres_password="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
require_bearer "${postgres_password}" "disposable PostgreSQL password"
replication_password="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"
[[ "${replication_password}" =~ ^[0-9a-f]{64}$ ]] || die "could not generate a canonical replication password"

say "Creating exact labeled Docker network and two database volumes"
docker network create \
  --label "${smoke_label}=${run_id}" \
  --label "${smoke_kind_label}=postgres-sync-failover" \
  "${network_name}" >"${work_dir}/network.id"
network_id="$(tr -d '\r\n' <"${work_dir}/network.id")"
[[ "${network_id}" =~ ^[0-9a-f]{64}$ ]] || die "Docker did not return one canonical network ID"
network_matches_run || die "disposable network identity or labels did not match"
for volume in "${primary_volume}" "${standby_volume}"; do
  docker volume create \
    --label "${smoke_label}=${run_id}" \
    --label "${smoke_kind_label}=postgres-sync-failover" \
    "${volume}" >"${work_dir}/${volume##*-}.volume"
  volume_ids["${volume}"]="${volume}"
  volume_matches_run "${volume}" || die "disposable volume ${volume} identity or labels did not match"
done

{
  printf 'POSTGRES_USER=mesh\n'
  printf 'POSTGRES_DB=mesh\n'
  printf 'POSTGRES_PASSWORD=%s\n' "${postgres_password}"
  printf 'POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=trust\n'
} >"${work_dir}/postgres.env"
chmod 0600 "${work_dir}/postgres.env"

say "Initializing the exact PostgreSQL 17 primary with physical-replication capability"
docker run --detach \
  --name "${primary_container}" \
  --label "${smoke_label}=${run_id}" \
  --label "${smoke_kind_label}=postgres-sync-failover" \
  --network "${network_name}" \
  --network-alias mesh-primary \
  --volume "${primary_volume}:/var/lib/postgresql/data" \
  --env-file "${work_dir}/postgres.env" \
  --publish '127.0.0.1::5432' \
  "${postgres_image}" \
  postgres \
    -c wal_level=replica \
    -c max_wal_senders=5 \
    -c max_replication_slots=5 \
    -c wal_keep_size=64MB \
    -c password_encryption=scram-sha-256 \
  >"${work_dir}/primary.id" 2>"${work_dir}/primary-docker-run.stderr"
register_container "${primary_container}" "${work_dir}/primary.id"
wait_postgres_ready "${primary_container}" primary

say "Creating a dedicated replication login and exact physical slot"
printf '%s\n' 'host replication mesh_repl samenet scram-sha-256' | \
  docker exec --interactive --user postgres "${primary_container}" \
    sh -c 'cat >> /var/lib/postgresql/data/pg_hba.conf'
docker exec --user postgres "${primary_container}" \
  pg_ctl reload --pgdata /var/lib/postgresql/data \
  >"${work_dir}/primary-reload.stdout" 2>"${work_dir}/primary-reload.stderr"
{
  printf "CREATE ROLE mesh_repl WITH LOGIN REPLICATION PASSWORD '%s';\n" "${replication_password}"
  printf "%s\n" "SELECT slot_name FROM pg_catalog.pg_create_physical_replication_slot('mesh_standby_slot');"
} | postgres_script "${primary_container}" "${work_dir}/primary-replication-setup.txt"

say "Taking an exact base backup into the new standby volume"
docker run --detach \
  --name "${standby_bootstrap_container}" \
  --label "${smoke_label}=${run_id}" \
  --label "${smoke_kind_label}=postgres-sync-failover" \
  --network "${network_name}" \
  --volume "${standby_volume}:/var/lib/postgresql/data" \
  --entrypoint /bin/sh \
  "${postgres_image}" \
  -c 'trap "exit 0" TERM INT; while :; do sleep 3600 & wait $!; done' \
  >"${work_dir}/standby-bootstrap.id" 2>"${work_dir}/standby-bootstrap-docker-run.stderr"
register_container "${standby_bootstrap_container}" "${work_dir}/standby-bootstrap.id"
docker exec --user root "${standby_bootstrap_container}" sh -c \
  'set -eu; test -d /var/lib/postgresql/data; test -z "$(find /var/lib/postgresql/data -mindepth 1 -print -quit)"; chown postgres:postgres /var/lib/postgresql/data; chmod 0700 /var/lib/postgresql/data'
printf 'mesh-primary:5432:*:mesh_repl:%s\n' "${replication_password}" | \
  docker exec --interactive --user root "${standby_bootstrap_container}" sh -c \
    'umask 077; cat > /tmp/mesh-repl.pgpass; chown postgres:postgres /tmp/mesh-repl.pgpass; chmod 0600 /tmp/mesh-repl.pgpass'
docker exec --user postgres --env PGPASSFILE=/tmp/mesh-repl.pgpass "${standby_bootstrap_container}" \
  pg_basebackup \
    --host mesh-primary \
    --port 5432 \
    --username mesh_repl \
    --pgdata /var/lib/postgresql/data \
    --format plain \
    --wal-method stream \
    --write-recovery-conf \
    --slot mesh_standby_slot \
    --checkpoint fast \
    >"${work_dir}/pg-basebackup.stdout" 2>"${work_dir}/pg-basebackup.stderr"
printf "primary_conninfo = 'host=mesh-primary port=5432 user=mesh_repl password=%s application_name=mesh_standby connect_timeout=5'\n" \
  "${replication_password}" | \
  docker exec --interactive --user postgres "${standby_bootstrap_container}" sh -c \
    'cat >> /var/lib/postgresql/data/postgresql.auto.conf'
docker exec --user root "${standby_bootstrap_container}" sh -c \
  'set -eu; rm -f /tmp/mesh-repl.pgpass; test -f /var/lib/postgresql/data/standby.signal; test -f /var/lib/postgresql/data/postgresql.auto.conf; test "$(stat -c %U /var/lib/postgresql/data/postgresql.auto.conf)" = postgres'
remove_container_exact "${standby_bootstrap_container}"

say "Starting the exact physical standby"
docker run --detach \
  --name "${standby_container}" \
  --label "${smoke_label}=${run_id}" \
  --label "${smoke_kind_label}=postgres-sync-failover" \
  --network "${network_name}" \
  --network-alias mesh-standby \
  --volume "${standby_volume}:/var/lib/postgresql/data" \
  --publish '127.0.0.1::5432' \
  "${postgres_image}" \
  postgres \
    -c synchronous_commit=remote_apply \
    -c synchronous_standby_names= \
  >"${work_dir}/standby.id" 2>"${work_dir}/standby-docker-run.stderr"
register_container "${standby_container}" "${work_dir}/standby.id"
wait_postgres_ready "${standby_container}" standby
[[ "$(postgres_scalar "${standby_container}" 'SELECT pg_catalog.pg_is_in_recovery();')" == "t" ]] || \
  die "standby was not in physical recovery before synchronous configuration"

say "Enabling remote_apply with one exact named synchronous standby"
{
  printf "%s\n" "ALTER SYSTEM SET synchronous_commit = 'remote_apply';"
  printf "%s\n" "ALTER SYSTEM SET synchronous_standby_names = 'FIRST 1 (mesh_standby)';"
  printf '%s\n' 'SELECT pg_catalog.pg_reload_conf();'
} | postgres_script "${primary_container}" "${work_dir}/primary-synchronous-settings.txt"
wait_standby_streaming
primary_sync_settings="$(postgres_scalar "${primary_container}" \
  "SELECT current_setting('synchronous_commit') || '|' || current_setting('synchronous_standby_names');")"
[[ "${primary_sync_settings}" == "remote_apply|FIRST 1 (mesh_standby)" ]] || \
  die "primary did not expose the exact remote_apply/named-standby settings"
say "Synchronous streaming and replay are proven before the first Mesh PostgreSQL write"

primary_port="$(container_port "${primary_container}")"
standby_port="$(container_port "${standby_container}")"
[[ "${primary_port}" != "${standby_port}" ]] || die "primary and standby were published on the same host port"
printf 'postgres://mesh:%s@127.0.0.1:%s,127.0.0.1:%s/mesh?sslmode=disable&target_session_attrs=read-write&connect_timeout=3&pool_max_conns=8&pool_min_conns=0\n' \
  "${postgres_password}" "${primary_port}" "${standby_port}" >"${work_dir}/postgres.dsn"
chmod 0600 "${work_dir}/postgres.dsn"

say "Migrating, importing, and cryptographically verifying through the multi-host DSN"
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
wait_standby_streaming

replica_one_port="$(pick_loopback_port)"
replica_two_port="$(pick_loopback_port)"
[[ "${replica_one_port}" =~ ^[0-9]+$ && "${replica_two_port}" =~ ^[0-9]+$ &&
   "${replica_one_port}" -ge 1024 && "${replica_one_port}" -le 65535 &&
   "${replica_two_port}" -ge 1024 && "${replica_two_port}" -le 65535 &&
   "${replica_one_port}" != "${replica_two_port}" ]] || die "kernel returned invalid or duplicate replica ports"
replica_one_url="http://127.0.0.1:${replica_one_port}"
replica_two_url="http://127.0.0.1:${replica_two_port}"
public_origin="${replica_one_url}"

say "Launching two Mesh application replicas through read-write target routing"
start_replica_one
start_replica_two

printf '%s\n' '{"name":"before-failover-network","cidr":"10.95.0.0/24"}' >"${work_dir}/before-network-request.json"
api_request "${replica_one_url}" POST /api/v1/networks \
  "${work_dir}/before-network-response.json" "${work_dir}/before-network-request.json"
printf '%s\n' '{"name":"before-failover-node","role":"member"}' >"${work_dir}/before-node-request.json"
api_request "${replica_two_url}" POST "/api/v1/networks/${source_network_id}/nodes" \
  "${work_dir}/before-node-response.json" "${work_dir}/before-node-request.json"
before_node_id="$(json_scalar "${work_dir}/before-node-response.json" node.id)"
require_record_id "${before_node_id}" "pre-failover node ID"
browser_login "${replica_one_url}" "${work_dir}/original-session.cookies" "${work_dir}/original-session-login.json"
original_session_id="$(json_scalar "${work_dir}/original-session-login.json" session_id)"
require_record_id "${original_session_id}" "pre-failover browser session ID"
browser_session_get "${replica_two_url}" "${work_dir}/original-session.cookies" "${work_dir}/original-session-via-two.json"
[[ "$(json_scalar "${work_dir}/original-session-via-two.json" session_id)" == "${original_session_id}" ]] || \
  die "second application replica did not observe the acknowledged session"

wait_standby_streaming
assert_acknowledged_revisions "${primary_container}"
collect_api_snapshot "${replica_one_url}" "${work_dir}/before-failover"
capture_database_manifest "${primary_container}" "${work_dir}/before-failover-database.txt"
capture_database_manifest "${standby_container}" "${work_dir}/before-failover-standby-database.txt"
cmp --silent "${work_dir}/before-failover-database.txt" "${work_dir}/before-failover-standby-database.txt" || \
  die "standby ledger did not exactly match the acknowledged primary ledger before termination"

say "Stopping one app replica, then hard-terminating the exact primary"
stop_child "${replica_one_pid}" "${mesh_server}"
replica_one_pid=""
container_matches_run "${primary_container}" || die "primary identity changed before forced termination"
docker kill --signal KILL -- "${primary_container}" >"${work_dir}/primary-kill.stdout"
[[ "$(tr -d '\r\n' <"${work_dir}/primary-kill.stdout")" == "${primary_container}" ]] || \
  die "Docker did not report termination of the exact primary"
[[ "$(docker inspect --format '{{.State.Running}}' "${primary_container}")" == "false" ]] || \
  die "exact primary remained running after forced termination"

say "Promoting the exact standby and waiting for writable authority"
container_matches_run "${standby_container}" || die "standby identity changed before promotion"
[[ "$(postgres_scalar "${standby_container}" 'SELECT pg_catalog.pg_promote(true, 60);')" == "t" ]] || \
  die "exact standby did not acknowledge promotion"
wait_promoted_writable
wait_for_server "${replica_two_pid}" "${replica_two_url}" "surviving application replica after database promotion"

say "Proving every acknowledged application state, session, audit, revision, and receipt survived"
collect_api_snapshot "${replica_two_url}" "${work_dir}/after-promotion"
assert_api_snapshot_equal "${work_dir}/before-failover" "${work_dir}/after-promotion" "${original_session_id}"
browser_session_get "${replica_two_url}" "${work_dir}/original-session.cookies" "${work_dir}/original-session-after-promotion.json"
[[ "$(json_scalar "${work_dir}/original-session-after-promotion.json" session_id)" == "${original_session_id}" ]] || \
  die "pre-failover browser session did not survive promotion"
capture_database_manifest "${standby_container}" "${work_dir}/after-promotion-database.txt"
cmp --silent "${work_dir}/before-failover-database.txt" "${work_dir}/after-promotion-database.txt" || \
  die "acknowledged revision/receipt ledger changed or was lost across promotion"
assert_acknowledged_revisions "${standby_container}"

say "Committing fresh control and identity mutations on the promoted authority"
printf '%s\n' '{"name":"after-failover-network","cidr":"10.96.0.0/24"}' >"${work_dir}/after-network-request.json"
api_request "${replica_two_url}" POST /api/v1/networks \
  "${work_dir}/after-network-response.json" "${work_dir}/after-network-request.json"
browser_login "${replica_two_url}" "${work_dir}/fresh-session.cookies" "${work_dir}/fresh-session-login.json"
fresh_session_id="$(json_scalar "${work_dir}/fresh-session-login.json" session_id)"
require_record_id "${fresh_session_id}" "post-failover browser session ID"
[[ "${fresh_session_id}" != "${original_session_id}" ]] || die "pre/post-failover logins returned one session ID"
final_revisions="$(postgres_scalar "${standby_container}" \
  "SELECT pg_catalog.string_agg(document_key || ':' || revision, ',' ORDER BY document_key) FROM mesh.mesh_state_documents;")"
[[ "${final_revisions}" == "control:4,identity:3,runtime_telemetry:1" ]] || \
  die "fresh post-promotion writes did not advance both authoritative revisions exactly once while telemetry remained stable"

say "Restarting the stopped app replica and proving two-replica convergence on the promoted timeline"
start_replica_one
browser_session_get "${replica_one_url}" "${work_dir}/original-session.cookies" "${work_dir}/original-session-via-restarted.json"
[[ "$(json_scalar "${work_dir}/original-session-via-restarted.json" session_id)" == "${original_session_id}" ]] || \
  die "restarted replica did not authenticate the pre-failover session"
browser_session_get "${replica_one_url}" "${work_dir}/fresh-session.cookies" "${work_dir}/fresh-session-via-restarted.json"
[[ "$(json_scalar "${work_dir}/fresh-session-via-restarted.json" session_id)" == "${fresh_session_id}" ]] || \
  die "restarted replica did not authenticate the post-failover session"
collect_api_snapshot "${replica_one_url}" "${work_dir}/final-one"
collect_api_snapshot "${replica_two_url}" "${work_dir}/final-two"
assert_final_convergence "${work_dir}/final-one" "${work_dir}/final-two" "${original_session_id}" "${fresh_session_id}"

say "PASS: PostgreSQL 17 remote_apply acknowledged the exact Mesh control and identity timeline only after the named standby replayed it"
say "PASS: hard primary termination plus exact standby promotion preserved every acknowledged revision, receipt, session, inventory item, and audit event"
say "PASS: the promoted authority accepted fresh control and identity mutations, and a restarted app replica converged through the multi-host read-write DSN"
say "LIMIT: this bounded local smoke does not inject ambiguous commits, prove PITR, use production TLS/roles, or establish load and soak budgets"
