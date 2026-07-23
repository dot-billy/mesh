#!/usr/bin/env bash

# Disposable local proof that PostgreSQL 17 can restore the exact Mesh
# control/identity document pair and immutable write-receipt ledger from one
# base backup plus archived WAL at explicitly selected named recovery points.
# This is a bounded recovery drill, not a production PITR claim.

set -Eeuo pipefail
umask 077

readonly skip_status=77
readonly script_name="${0##*/}"
readonly keep_smoke="${KEEP_MESH_SMOKE:-0}"
readonly postgres_image="postgres:17-alpine"
readonly nebula="/usr/local/bin/nebula"
readonly nebula_cert="/usr/local/bin/nebula-cert"
readonly smoke_label="io.mesh.smoke.instance"
readonly smoke_kind_label="io.mesh.smoke.kind"
readonly smoke_kind="postgres-pitr"

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
work_parent=""
work_dir=""
run_id=""
network_name=""
network_id=""
primary_container=""
archive_init_container=""
basebackup_container=""
early_clone_container=""
early_container=""
late_clone_container=""
late_container=""
primary_volume=""
archive_volume=""
base_volume=""
early_volume=""
late_volume=""

declare -A container_ids=()
declare -A volume_names=()

mesh_server=""
mesh_storage=""
mesh_backup=""
meshctl=""
source_pid=""
app_pid=""
source_port=""
primary_app_port=""
source_url=""
app_url=""
public_origin=""
source_network_id=""
current_dsn_file=""

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

container_name_valid() {
  local name="$1"

  [[ -n "${run_id}" && "${run_id}" =~ ^[0-9a-f]{16}$ ]] || return 1
  [[ "${name}" =~ ^mesh-postgres-pitr-smoke-${run_id}-(primary|archive-init|basebackup|early-clone|early|late-clone|late)$ ]]
}

container_matches_run() {
  local name="$1"
  local expected_id="${container_ids[${name}]:-}"
  local observed_name observed_id observed_run observed_kind

  container_name_valid "${name}" || return 1
  [[ "${expected_id}" =~ ^[0-9a-f]{64}$ ]] || return 1
  observed_name="$(docker inspect --format '{{.Name}}' "${name}" 2>/dev/null || true)"
  observed_id="$(docker inspect --format '{{.Id}}' "${name}" 2>/dev/null || true)"
  observed_run="$(docker inspect --format '{{ index .Config.Labels "io.mesh.smoke.instance" }}' "${name}" 2>/dev/null || true)"
  observed_kind="$(docker inspect --format '{{ index .Config.Labels "io.mesh.smoke.kind" }}' "${name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "/${name}" && "${observed_id}" == "${expected_id}" &&
     "${observed_run}" == "${run_id}" && "${observed_kind}" == "${smoke_kind}" ]]
}

network_matches_run() {
  local observed_name observed_id observed_run observed_kind

  [[ -n "${run_id}" && "${network_name}" == "mesh-postgres-pitr-smoke-${run_id}-network" ]] || return 1
  [[ "${network_id}" =~ ^[0-9a-f]{64}$ ]] || return 1
  observed_name="$(docker network inspect --format '{{.Name}}' "${network_name}" 2>/dev/null || true)"
  observed_id="$(docker network inspect --format '{{.Id}}' "${network_name}" 2>/dev/null || true)"
  observed_run="$(docker network inspect --format '{{ index .Labels "io.mesh.smoke.instance" }}' "${network_name}" 2>/dev/null || true)"
  observed_kind="$(docker network inspect --format '{{ index .Labels "io.mesh.smoke.kind" }}' "${network_name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "${network_name}" && "${observed_id}" == "${network_id}" &&
     "${observed_run}" == "${run_id}" && "${observed_kind}" == "${smoke_kind}" ]]
}

volume_name_valid() {
  local name="$1"

  [[ -n "${run_id}" && "${run_id}" =~ ^[0-9a-f]{16}$ ]] || return 1
  [[ "${name}" =~ ^mesh-postgres-pitr-smoke-${run_id}-(primary|archive|base|early|late)-data$ ]]
}

volume_matches_run() {
  local name="$1"
  local observed_name observed_run observed_kind

  volume_name_valid "${name}" || return 1
  [[ "${volume_names[${name}]:-}" == "${name}" ]] || return 1
  observed_name="$(docker volume inspect --format '{{.Name}}' "${name}" 2>/dev/null || true)"
  observed_run="$(docker volume inspect --format '{{ index .Labels "io.mesh.smoke.instance" }}' "${name}" 2>/dev/null || true)"
  observed_kind="$(docker volume inspect --format '{{ index .Labels "io.mesh.smoke.kind" }}' "${name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "${name}" && "${observed_run}" == "${run_id}" &&
     "${observed_kind}" == "${smoke_kind}" ]]
}

adopt_container_for_cleanup() {
  local name="$1"
  local observed_name observed_id observed_run observed_kind

  container_name_valid "${name}" || return 1
  observed_name="$(docker inspect --format '{{.Name}}' "${name}" 2>/dev/null || true)"
  observed_id="$(docker inspect --format '{{.Id}}' "${name}" 2>/dev/null || true)"
  observed_run="$(docker inspect --format '{{ index .Config.Labels "io.mesh.smoke.instance" }}' "${name}" 2>/dev/null || true)"
  observed_kind="$(docker inspect --format '{{ index .Config.Labels "io.mesh.smoke.kind" }}' "${name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "/${name}" && "${observed_id}" =~ ^[0-9a-f]{64}$ &&
     "${observed_run}" == "${run_id}" && "${observed_kind}" == "${smoke_kind}" ]] || return 1
  container_ids["${name}"]="${observed_id}"
}

adopt_network_for_cleanup() {
  local observed_name observed_id observed_run observed_kind

  [[ -n "${run_id}" && "${network_name}" == "mesh-postgres-pitr-smoke-${run_id}-network" ]] || return 1
  observed_name="$(docker network inspect --format '{{.Name}}' "${network_name}" 2>/dev/null || true)"
  observed_id="$(docker network inspect --format '{{.Id}}' "${network_name}" 2>/dev/null || true)"
  observed_run="$(docker network inspect --format '{{ index .Labels "io.mesh.smoke.instance" }}' "${network_name}" 2>/dev/null || true)"
  observed_kind="$(docker network inspect --format '{{ index .Labels "io.mesh.smoke.kind" }}' "${network_name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "${network_name}" && "${observed_id}" =~ ^[0-9a-f]{64}$ &&
     "${observed_run}" == "${run_id}" && "${observed_kind}" == "${smoke_kind}" ]] || return 1
  network_id="${observed_id}"
}

adopt_volume_for_cleanup() {
  local name="$1"
  local observed_name observed_run observed_kind

  volume_name_valid "${name}" || return 1
  observed_name="$(docker volume inspect --format '{{.Name}}' "${name}" 2>/dev/null || true)"
  observed_run="$(docker volume inspect --format '{{ index .Labels "io.mesh.smoke.instance" }}' "${name}" 2>/dev/null || true)"
  observed_kind="$(docker volume inspect --format '{{ index .Labels "io.mesh.smoke.kind" }}' "${name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "${name}" && "${observed_run}" == "${run_id}" &&
     "${observed_kind}" == "${smoke_kind}" ]] || return 1
  volume_names["${name}"]="${name}"
}

remove_container_exact() {
  local name="$1"

  [[ -n "${name}" ]] || return 0
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

  if [[ -n "${app_pid}" ]]; then
    stop_child "${app_pid}" "${mesh_server}" || status=1
    app_pid=""
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
      printf 'Kept exact labeled PostgreSQL PITR containers for debugging.\n' >&2
    fi
  else
    for name in "${late_clone_container}" "${late_container}" "${early_clone_container}" \
      "${early_container}" "${basebackup_container}" "${archive_init_container}" "${primary_container}"; do
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

    for name in "${late_volume}" "${early_volume}" "${base_volume}" "${archive_volume}" "${primary_volume}"; do
      [[ -n "${name}" ]] || continue
      if [[ -z "${volume_names[${name}]:-}" ]] && docker volume inspect "${name}" >/dev/null 2>&1; then
        adopt_volume_for_cleanup "${name}" || {
          printf 'ERROR: refusing to adopt unexpected Docker volume %s for cleanup\n' "${name}" >&2
          status=1
        }
      fi
      if [[ -n "${volume_names[${name}]:-}" ]]; then
        if volume_matches_run "${name}"; then
          docker volume rm -- "${name}" >/dev/null 2>&1 || status=1
          unset 'volume_names[$name]'
        elif docker volume inspect "${name}" >/dev/null 2>&1; then
          printf 'ERROR: refusing to remove Docker volume %s because its exact labels changed\n' "${name}" >&2
          status=1
        else
          unset 'volume_names[$name]'
        fi
      fi
    done
  fi

  if [[ -n "${work_dir}" && -d "${work_dir}" ]]; then
    if [[ "${keep_smoke}" == "1" ]]; then
      printf 'Kept private PITR workspace: %s\n' "${work_dir}" >&2
      printf 'It contains disposable credentials that also exist in retained database volumes.\n' >&2
    else
      base="${work_dir##*/}"
      parent="$(cd -- "$(dirname -- "${work_dir}")" 2>/dev/null && pwd -P)"
      if [[ "${base}" == mesh-postgres-pitr-smoke.* && -n "${work_parent}" &&
            "${parent}" == "${work_parent}" && ! -L "${work_dir}" ]]; then
        rm -rf -- "${work_dir}"
      else
        printf 'ERROR: refusing to remove unexpected PITR workspace %s\n' "${work_dir}" >&2
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

start_app() {
  local dsn_file="$1"
  local port="$2"
  local label="$3"
  local log_slug="$4"

  [[ -z "${app_pid}" ]] || die "refusing to launch a second application process"
  current_dsn_file="${dsn_file}"
  app_url="http://127.0.0.1:${port}"
  : >"${work_dir}/${log_slug}-server.log"
  MESH_MASTER_KEY="${master_key}" MESH_ADMIN_TOKEN="${admin_token}" NEBULA_CERT_BINARY="${nebula_cert}" \
    "${mesh_server}" \
    --storage-backend=postgres \
    --postgres-dsn-file="${dsn_file}" \
    --allow-local-plaintext-postgres \
    --listen "127.0.0.1:${port}" \
    --public-url "${public_origin}" \
    >>"${work_dir}/${log_slug}-server.log" 2>&1 &
  app_pid=$!
  wait_for_server "${app_pid}" "${app_url}" "${label}"
}

stop_app() {
  if [[ -n "${app_pid}" ]]; then
    stop_child "${app_pid}" "${mesh_server}"
    app_pid=""
  fi
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
    --output "${output}" \
    "${base_url}/api/v1/session"
}

assert_session_rejected() {
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
  [[ "${status}" == "401" ]] || die "session expected to be absent returned HTTP ${status}"
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

  container_matches_run "${name}" || die "refusing to inspect a port on an unverified container"
  mapping="$(docker port "${name}" 5432/tcp 2>/dev/null | tr -d '\r')"
  [[ "${mapping}" =~ ^127\.0\.0\.1:([0-9]+)$ ]] || die "${name} has no exact numeric loopback PostgreSQL mapping"
  [[ "${BASH_REMATCH[1]}" -ge 1024 && "${BASH_REMATCH[1]}" -le 65535 ]] || die "${name} returned an invalid PostgreSQL port"
  printf '%s\n' "${BASH_REMATCH[1]}"
}

wait_postgres_ready() {
  local name="$1"
  local label="$2"
  local poll

  container_matches_run "${name}" || die "refusing readiness against an unverified container"
  for poll in {1..900}; do
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

wait_recovered_writable() {
  local name="$1"
  local label="$2"
  local poll recovery read_only

  for poll in {1..900}; do
    recovery="$(postgres_scalar "${name}" 'SELECT pg_catalog.pg_is_in_recovery();' 2>/dev/null || true)"
    read_only="$(postgres_scalar "${name}" 'SHOW transaction_read_only;' 2>/dev/null || true)"
    if [[ "${recovery}" == "f" && "${read_only}" == "off" ]]; then
      return 0
    fi
    sleep 0.1
  done
  die "${label} did not promote to a writable recovered authority"
}

capture_database_manifest() {
  local name="$1"
  local output="$2"

  {
    printf '%s\n' '\pset format unaligned'
    printf '%s\n' '\pset tuples_only on'
    printf '%s\n' "\pset fieldsep '|'"
    printf '%s\n' 'BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;'
    printf '%s\n' "SELECT 'document', document_key, revision, pg_catalog.encode(document_sha256, 'hex'), last_write_receipt::text, pg_catalog.octet_length(document_bytes), pg_catalog.to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') FROM mesh.mesh_state_documents ORDER BY document_key;"
    printf '%s\n' "SELECT 'receipt', r.receipt_id::text, r.operation_class, pg_catalog.to_char(r.committed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'), d.document_key, d.base_revision, d.committed_revision, pg_catalog.encode(d.document_sha256, 'hex') FROM mesh.mesh_write_receipts AS r JOIN mesh.mesh_write_receipt_documents AS d ON d.receipt_id = r.receipt_id ORDER BY r.committed_at, r.receipt_id, d.document_key;"
    printf '%s\n' "SELECT 'import', singleton, import_id::text, import_receipt::text, pg_catalog.encode(pg_catalog.convert_to(source_format, 'UTF8'), 'hex'), pg_catalog.encode(source_control_sha256, 'hex'), pg_catalog.encode(source_identity_sha256, 'hex'), source_control_bytes, source_identity_bytes, source_control_version, pg_catalog.encode(pg_catalog.convert_to(source_identity_schema, 'UTF8'), 'hex'), source_backup_id, pg_catalog.to_char(imported_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'), pg_catalog.encode(pg_catalog.convert_to(importer_build, 'UTF8'), 'hex') FROM mesh.mesh_import_metadata;"
    printf '%s\n' 'COMMIT;'
  } | postgres_script "${name}" "${output}"
}

assert_revisions() {
  local name="$1"
  local expected_control="$2"
  local expected_identity="$3"
  local actual

  actual="$(postgres_scalar "${name}" \
    "SELECT pg_catalog.string_agg(document_key || ':' || revision, ',' ORDER BY document_key) FROM mesh.mesh_state_documents;")"
  [[ "${actual}" == "control:${expected_control},identity:${expected_identity},runtime_telemetry:1" ]] || \
	    die "document revisions were ${actual}, expected control:${expected_control},identity:${expected_identity},runtime_telemetry:1"
}

collect_api_snapshot() {
  local base_url="$1"
  local prefix="$2"

  api_request "${base_url}" GET /api/v1/networks "${prefix}-networks.json"
  api_request "${base_url}" GET "/api/v1/networks/${source_network_id}/nodes" "${prefix}-nodes.json"
  api_request "${base_url}" GET /api/v1/audit "${prefix}-audit.json"
}

assert_point_inventory() {
  local prefix="$1"
  local stage="$2"
  local sessions_csv="$3"

  python3 - "${prefix}" "${stage}" "${sessions_csv}" <<'PY'
import json
import pathlib
import sys

prefix, stage, sessions_csv = sys.argv[1:]
networks = json.loads(pathlib.Path(prefix + "-networks.json").read_text(encoding="utf-8"))
nodes = json.loads(pathlib.Path(prefix + "-nodes.json").read_text(encoding="utf-8"))
audit = json.loads(pathlib.Path(prefix + "-audit.json").read_text(encoding="utf-8"))
expected_networks = {"pitr-source", "pitr-early-network"}
if stage in {"late", "after"}:
    expected_networks.add("pitr-late-network")
if stage == "after":
    expected_networks.add("pitr-after-network")
if {item.get("name") for item in networks if isinstance(item, dict)} != expected_networks:
    raise SystemExit(f"{stage} point has an unexpected network inventory")
if nodes != []:
    raise SystemExit(f"{stage} point unexpectedly has a node before recovered lifecycle validation")
expected_sessions = set(sessions_csv.split(","))
actual_sessions = {
    item.get("target_session_id")
    for item in audit
    if isinstance(item, dict) and item.get("action") == "session.created"
}
if actual_sessions != expected_sessions:
    raise SystemExit(f"{stage} point has an unexpected acknowledged-session inventory")
PY
}

assert_api_snapshot_equal() {
  local expected_prefix="$1"
  local actual_prefix="$2"
  local label="$3"

  python3 - "${expected_prefix}" "${actual_prefix}" "${label}" <<'PY'
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

def load(path):
    raw = pathlib.Path(path).read_text(encoding="utf-8")
    decoder = json.JSONDecoder(object_pairs_hook=reject_duplicates)
    value, end = decoder.raw_decode(raw)
    if raw[end:].strip():
        raise SystemExit(f"trailing JSON data in {path}")
    return value

expected, actual, label = sys.argv[1:]
for suffix in ("networks", "nodes", "audit"):
    if load(f"{expected}-{suffix}.json") != load(f"{actual}-{suffix}.json"):
        raise SystemExit(f"{label} API {suffix} differs from its externally recorded recovery point")
PY
}

create_recovery_point() {
  local point_name="$1"
  local output="$2"
  local lsn segment switch_lsn poll size wal_sha256 archive_status

  [[ "${point_name}" =~ ^mesh_(early|late|after)_[0-9a-f]{16}$ ]] || die "recovery point name is not canonical"
  lsn="$(postgres_scalar "${primary_container}" \
    "SELECT pg_catalog.pg_create_restore_point('${point_name}');")"
  [[ "${lsn}" =~ ^[0-9A-F]+/[0-9A-F]+$ ]] || die "PostgreSQL returned a noncanonical restore-point LSN"
  segment="$(postgres_scalar "${primary_container}" \
    "SELECT pg_catalog.pg_walfile_name('${lsn}'::pg_catalog.pg_lsn);")"
  [[ "${segment}" =~ ^[0-9A-F]{24}$ ]] || die "PostgreSQL returned a noncanonical restore-point WAL segment"
  switch_lsn="$(postgres_scalar "${primary_container}" 'SELECT pg_catalog.pg_switch_wal();')"
  [[ "${switch_lsn}" =~ ^[0-9A-F]+/[0-9A-F]+$ ]] || die "PostgreSQL returned a noncanonical WAL-switch LSN"

  for poll in {1..900}; do
    container_matches_run "${primary_container}" || die "primary identity changed while waiting for archived WAL"
    size="$(docker exec --user postgres "${primary_container}" \
      sh -c 'test -f "/archive/$1" && stat -c %s "/archive/$1"' _ "${segment}" 2>/dev/null || true)"
    if [[ "${size}" == "16777216" ]]; then
      break
    fi
    sleep 0.1
  done
  [[ "${size:-}" == "16777216" ]] || die "restore-point WAL segment ${segment} was not durably published to the archive"
  wal_sha256="$(docker exec --user postgres "${primary_container}" \
    sha256sum "/archive/${segment}" | awk '{print $1}')"
  [[ "${wal_sha256}" =~ ^[0-9a-f]{64}$ ]] || die "archived restore-point WAL digest is not canonical"
  archive_status="$(postgres_scalar "${primary_container}" \
    "SELECT archived_count || '|' || failed_count || '|' || COALESCE(last_failed_wal, '') FROM pg_catalog.pg_stat_archiver;")"
  [[ "${archive_status}" =~ ^[1-9][0-9]*\|0\|$ ]] || die "WAL archiver did not report a clean success-only history"
  printf '%s|%s|%s|%s|%s\n' "${point_name}" "${lsn}" "${segment}" "${size}" "${wal_sha256}" >"${output}"
  chmod 0600 "${output}"
}

write_recovery_evidence() {
  local point_file="$1"
  local manifest="$2"
  local api_prefix="$3"
  local output="$4"
  local system_identifier timeline

  system_identifier="$(postgres_scalar "${primary_container}" \
    'SELECT system_identifier FROM pg_catalog.pg_control_system();')"
  timeline="$(postgres_scalar "${primary_container}" \
    'SELECT timeline_id FROM pg_catalog.pg_control_checkpoint();')"
  [[ "${system_identifier}" =~ ^[0-9]{18,22}$ ]] || die "primary system identifier is not canonical"
  [[ "${timeline}" == "1" ]] || die "PITR source unexpectedly left timeline 1"
  python3 - "${point_file}" "${manifest}" "${api_prefix}" "${output}" \
    "${system_identifier}" "${timeline}" "${work_dir}/base-backup.sha256" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import sys

point_path, manifest_path, api_prefix, output_path, system_identifier, timeline, base_digest_path = sys.argv[1:]
point_raw = pathlib.Path(point_path).read_text(encoding="ascii")
if not point_raw.endswith("\n") or point_raw.count("\n") != 1:
    raise SystemExit("restore-point record is not one canonical line")
parts = point_raw[:-1].split("|")
if len(parts) != 5:
    raise SystemExit("restore-point record shape is invalid")
name, lsn, segment, segment_size, segment_sha256 = parts
if re.fullmatch(r"mesh_(early|late|after)_[0-9a-f]{16}", name) is None:
    raise SystemExit("restore-point name is invalid")
if re.fullmatch(r"[0-9A-F]+/[0-9A-F]+", lsn) is None or re.fullmatch(r"[0-9A-F]{24}", segment) is None:
    raise SystemExit("restore-point WAL identity is invalid")
if segment_size != "16777216" or re.fullmatch(r"[0-9a-f]{64}", segment_sha256) is None:
    raise SystemExit("restore-point WAL size or digest is invalid")
base_digest_parts = pathlib.Path(base_digest_path).read_text(encoding="ascii").split()
if len(base_digest_parts) != 2 or re.fullmatch(r"[0-9a-f]{64}", base_digest_parts[0]) is None:
    raise SystemExit("base-backup digest record is invalid")
paths = {
    "database_manifest": pathlib.Path(manifest_path),
    "api_networks": pathlib.Path(api_prefix + "-networks.json"),
    "api_nodes": pathlib.Path(api_prefix + "-nodes.json"),
    "api_audit": pathlib.Path(api_prefix + "-audit.json"),
}
for path in (pathlib.Path(point_path), pathlib.Path(base_digest_path), *paths.values()):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
digests = {label: hashlib.sha256(path.read_bytes()).hexdigest() for label, path in paths.items()}
document = {
    "version": 1,
    "source_system_identifier": system_identifier,
    "source_timeline": int(timeline),
    "base_backup_sha256": base_digest_parts[0],
    "restore_point": name,
    "restore_lsn": lsn,
    "wal_segment": segment,
    "wal_segment_size": int(segment_size),
    "wal_segment_sha256": segment_sha256,
    "sha256": digests,
}
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(output_path, flags, 0o600)
try:
    os.write(fd, (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))
    os.fsync(fd)
finally:
    os.close(fd)
directory_fd = os.open(str(pathlib.Path(output_path).parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY
}

assert_recovery_evidence() {
  local evidence="$1"
  local expected_manifest="$2"
  local expected_api_prefix="$3"
  local actual_manifest="$4"
  local actual_api_prefix="$5"
  local recovered_container="$6"
  local expected_point="$7"
  local current_base_snapshot="$8"
  local recovered_system_identifier recovered_timeline recovered_timeline_hex evidence_lsn evidence_segment
  local observed_wal_size observed_wal_sha256 replay_reached

  container_matches_run "${recovered_container}" || die "refusing evidence validation through an unverified recovery container"
  recovered_system_identifier="$(postgres_scalar "${recovered_container}" \
    'SELECT system_identifier FROM pg_catalog.pg_control_system();')"
  recovered_timeline_hex="$(postgres_scalar "${recovered_container}" \
    "SELECT pg_catalog.substr(pg_catalog.pg_walfile_name(pg_catalog.pg_current_wal_lsn()), 1, 8);")"
  [[ "${recovered_timeline_hex}" =~ ^[0-9A-F]{8}$ ]] || die "recovered authority returned a noncanonical timeline"
  recovered_timeline=$((16#${recovered_timeline_hex}))
  [[ "${recovered_timeline}" =~ ^[0-9]+$ && "${recovered_timeline}" -gt 1 ]] || \
    die "recovered authority did not advance beyond source timeline 1"
  evidence_lsn="$(json_scalar "${evidence}" restore_lsn)"
  evidence_segment="$(json_scalar "${evidence}" wal_segment)"
  [[ "${evidence_lsn}" =~ ^[0-9A-F]+/[0-9A-F]+$ ]] || die "recovery evidence LSN is not canonical"
  [[ "${evidence_segment}" =~ ^[0-9A-F]{24}$ ]] || die "recovery evidence WAL segment is not canonical"
  replay_reached="$(postgres_scalar "${recovered_container}" \
    "SELECT pg_catalog.pg_last_wal_replay_lsn() >= '${evidence_lsn}'::pg_catalog.pg_lsn;")"
  [[ "${replay_reached}" == "t" ]] || die "recovered authority did not replay through the recorded target LSN"
  observed_wal_size="$(docker exec --user postgres "${recovered_container}" \
    stat -c %s "/archive/${evidence_segment}")"
  observed_wal_sha256="$(docker exec --user postgres "${recovered_container}" \
    sha256sum "/archive/${evidence_segment}" | awk '{print $1}')"
  python3 - "${evidence}" "${expected_manifest}" "${expected_api_prefix}" \
    "${actual_manifest}" "${actual_api_prefix}" "${recovered_system_identifier}" "${expected_point}" \
    "${work_dir}/base-backup.sha256" "${current_base_snapshot}" "${observed_wal_size}" \
    "${observed_wal_sha256}" "${recovered_timeline}" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

def strict_load(path):
    raw = pathlib.Path(path).read_text(encoding="utf-8")
    def reject_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON name: {key}")
            value[key] = item
        return value
    decoder = json.JSONDecoder(object_pairs_hook=reject_duplicates)
    value, end = decoder.raw_decode(raw)
    if raw[end:].strip():
        raise SystemExit(f"trailing JSON data in {path}")
    return value

evidence_path, expected_manifest, expected_api, actual_manifest, actual_api, system_identifier, expected_point, base_record, current_base_record, observed_wal_size, observed_wal_sha256, recovered_timeline = sys.argv[1:]
evidence = strict_load(evidence_path)
if set(evidence) != {"version", "source_system_identifier", "source_timeline", "base_backup_sha256", "restore_point", "restore_lsn", "wal_segment", "wal_segment_size", "wal_segment_sha256", "sha256"}:
    raise SystemExit("create-only recovery evidence has an invalid shape")
if evidence["version"] != 1 or evidence["source_timeline"] != 1:
    raise SystemExit("create-only recovery evidence has the wrong version or source timeline")
if evidence["source_system_identifier"] != system_identifier:
    raise SystemExit("recovered cluster has a different PostgreSQL system identifier")
if evidence["restore_point"] != expected_point:
    raise SystemExit("create-only evidence identifies a different selected recovery point")
if re.fullmatch(r"[0-9A-F]+/[0-9A-F]+", evidence["restore_lsn"]) is None:
    raise SystemExit("create-only evidence has an invalid restore LSN")
if re.fullmatch(r"[0-9A-F]{24}", evidence["wal_segment"]) is None:
    raise SystemExit("create-only evidence has an invalid WAL segment")
if int(recovered_timeline) <= evidence["source_timeline"]:
    raise SystemExit("recovered authority did not advance to a new timeline")
base_values = pathlib.Path(base_record).read_text(encoding="ascii").split()
current_base_values = pathlib.Path(current_base_record).read_text(encoding="ascii").split()
if len(base_values) != 2 or len(current_base_values) != 2 or evidence["base_backup_sha256"] != base_values[0] or base_values[0] != current_base_values[0]:
    raise SystemExit("base-backup input digest differs from create-only recovery evidence")
if evidence["wal_segment_size"] != 16777216 or str(evidence["wal_segment_size"]) != observed_wal_size:
    raise SystemExit("read-only archived WAL segment size differs from recovery evidence")
if re.fullmatch(r"[0-9a-f]{64}", evidence["wal_segment_sha256"]) is None or evidence["wal_segment_sha256"] != observed_wal_sha256:
    raise SystemExit("read-only archived WAL segment digest differs from recovery evidence")
expected_paths = {
    "database_manifest": pathlib.Path(expected_manifest),
    "api_networks": pathlib.Path(expected_api + "-networks.json"),
    "api_nodes": pathlib.Path(expected_api + "-nodes.json"),
    "api_audit": pathlib.Path(expected_api + "-audit.json"),
}
actual_paths = {
    "database_manifest": pathlib.Path(actual_manifest),
    "api_networks": pathlib.Path(actual_api + "-networks.json"),
    "api_nodes": pathlib.Path(actual_api + "-nodes.json"),
    "api_audit": pathlib.Path(actual_api + "-audit.json"),
}
if set(evidence["sha256"]) != set(expected_paths):
    raise SystemExit("create-only evidence digest set is invalid")
for label, path in expected_paths.items():
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if evidence["sha256"].get(label) != digest:
        raise SystemExit(f"create-only recovery evidence digest changed: {label}")
    if path.read_bytes() != actual_paths[label].read_bytes():
        raise SystemExit(f"recovered point differs from create-only evidence: {label}")
PY
}

snapshot_base_volume() {
  local container="$1"
  local output="$2"

  container_matches_run "${container}" || die "refusing to hash a base backup through an unverified helper"
  docker exec --user root "${container}" sh -c \
    'set -eu; cd /base; tar -cf - .' | sha256sum >"${output}"
  [[ "$(awk '{print $1}' "${output}")" =~ ^[0-9a-f]{64}$ ]] || die "base-backup snapshot digest is not canonical"
}

clone_base_for_recovery() {
  local clone_container="$1"
  local target_volume="$2"
  local slug="$3"

  docker run --detach \
    --name "${clone_container}" \
    --label "${smoke_label}=${run_id}" \
    --label "${smoke_kind_label}=${smoke_kind}" \
    --network "${network_name}" \
    --volume "${base_volume}:/base:ro" \
    --volume "${target_volume}:/target" \
    --entrypoint /bin/sh \
    "${postgres_image}" \
    -c 'trap "exit 0" TERM INT; while :; do sleep 3600 & wait $!; done' \
    >"${work_dir}/${slug}-clone.id" 2>"${work_dir}/${slug}-clone-docker-run.stderr"
  register_container "${clone_container}" "${work_dir}/${slug}-clone.id"
  [[ "$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/base"}}{{.RW}}{{end}}{{end}}' "${clone_container}")" == "false" ]] || \
    die "${slug} clone did not mount the immutable base backup read-only"
  snapshot_base_volume "${clone_container}" "${work_dir}/${slug}-base-before.sha256"
  cmp --silent "${work_dir}/base-backup.sha256" "${work_dir}/${slug}-base-before.sha256" || \
    die "immutable base-backup volume changed before the ${slug} clone"
  docker exec --user root "${clone_container}" sh -c \
    'set -eu; test -z "$(find /target -mindepth 1 -print -quit)"; cp -a /base/. /target/; rm -f /target/postmaster.pid /target/standby.signal; : > /target/recovery.signal; chown -R postgres:postgres /target; chmod 0700 /target; chmod 0600 /target/recovery.signal; test -f /target/PG_VERSION; test -f /target/backup_label'
  snapshot_base_volume "${clone_container}" "${work_dir}/${slug}-base-after.sha256"
  cmp --silent "${work_dir}/base-backup.sha256" "${work_dir}/${slug}-base-after.sha256" || \
    die "immutable base-backup volume changed while creating the ${slug} clone"
  remove_container_exact "${clone_container}"
}

recovery_port=""

start_recovery_container() {
  local name="$1"
  local volume="$2"
  local point_name="$3"
  local slug="$4"

  [[ "${point_name}" =~ ^mesh_(early|late)_[0-9a-f]{16}$ ]] || die "selected recovery target is not canonical"
  docker run --detach \
    --name "${name}" \
    --label "${smoke_label}=${run_id}" \
    --label "${smoke_kind_label}=${smoke_kind}" \
    --network "${network_name}" \
    --volume "${volume}:/var/lib/postgresql/data" \
    --volume "${archive_volume}:/archive:ro" \
    --publish '127.0.0.1::5432' \
    "${postgres_image}" \
    postgres \
      -c "restore_command=cp /archive/%f %p" \
      -c "recovery_target_name=${point_name}" \
      -c recovery_target_action=promote \
      -c recovery_target_timeline=1 \
    >"${work_dir}/${slug}.id" 2>"${work_dir}/${slug}-docker-run.stderr"
  register_container "${name}" "${work_dir}/${slug}.id"
  [[ "$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/archive"}}{{.RW}}{{end}}{{end}}' "${name}")" == "false" ]] || \
    die "${slug} recovery did not mount the archived WAL input read-only"
  wait_postgres_ready "${name}" "${slug}"
  wait_recovered_writable "${name}" "${slug} recovery"
  recovery_port="$(container_port "${name}")"
  docker logs "${name}" >"${work_dir}/${slug}-postgres.log" 2>&1
  grep -F "recovery stopping at restore point \"${point_name}\"" "${work_dir}/${slug}-postgres.log" >/dev/null || \
    die "${slug} PostgreSQL log did not identify the selected named recovery point"
}

capture_pending_node() {
  local payload="$1"
  local token_path="$2"
  local sanitized_path="$3"
  local private_response="${sanitized_path}.private-response"

  api_request "${app_url}" POST "/api/v1/networks/${source_network_id}/nodes" "${private_response}" "${payload}"
  python3 - "${private_response}" "${token_path}" "${sanitized_path}" <<'PY'
import json
import os
import pathlib
import re
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
created, end = decoder.raw_decode(raw)
if raw[end:].strip() or not isinstance(created, dict):
    raise SystemExit("node response is not one strict JSON object")
token = created.pop("enrollment_token", None)
if not isinstance(token, str) or re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is None:
    raise SystemExit("node response omitted its canonical one-time enrollment token")
node = created.get("node")
if not isinstance(node, dict) or node.get("role") != "member" or node.get("status") != "pending":
    raise SystemExit("node response is not one pending member")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
for path, body in (
    (sys.argv[2], token.encode("ascii") + b"\n"),
    (sys.argv[3], (json.dumps(created, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")),
):
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, body)
        os.fsync(fd)
    finally:
        os.close(fd)
PY
  rm -- "${private_response}"
}

validate_bundle() {
  local output_dir="$1"
  local validation_log="$2"
  local current="${output_dir}/current"

  [[ -L "${current}" ]] || die "recovered enrollment did not publish an atomic current symlink"
  python3 - "${output_dir}" <<'PY'
import os
import pathlib
import sys

output = pathlib.Path(sys.argv[1])
versions = (output / "versions").resolve(strict=True)
current = (output / "current").resolve(strict=True)
if os.path.commonpath((str(versions), str(current))) != str(versions) or current == versions:
    raise SystemExit("current bundle does not resolve inside immutable versions")
required = {"ca.crt", "host.crt", "host.key", "host.pub", "config.yml", "config.signed.yml", "metadata.json"}
if {item.name for item in current.iterdir()} != required:
    raise SystemExit("managed bundle is incomplete or contains unexpected files")
for name in required:
    path = current / name
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"managed bundle file is missing or unsafe: {name}")
PY
  "${nebula_cert}" verify -ca "${current}/ca.crt" -crt "${current}/host.crt" \
    >>"${validation_log}" 2>&1
  "${nebula}" -test -config "${current}/config.yml" >>"${validation_log}" 2>&1
}

assert_lifecycle_node() {
  local nodes_path="$1"
  local audit_path="$2"
  local state_path="$3"
  local node_id="$4"
  local expected_status="$5"

  python3 - "${nodes_path}" "${audit_path}" "${state_path}" "${node_id}" "${source_network_id}" "${expected_status}" <<'PY'
import json
import pathlib
import re
import sys

def load(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))

nodes, audit, state = map(load, sys.argv[1:4])
node_id, network_id, expected_status = sys.argv[4:]
matches = [item for item in nodes if isinstance(item, dict) and item.get("id") == node_id]
if len(matches) != 1:
    raise SystemExit("recovered lifecycle node was not returned exactly once")
node = matches[0]
for field, expected in {
    "network_id": network_id,
    "name": "pitr-recovered-member",
    "role": "member",
    "status": expected_status,
}.items():
    if node.get(field) != expected:
        raise SystemExit(f"recovered lifecycle node field changed: {field}")
fingerprint = node.get("certificate_fingerprint")
if re.fullmatch(r"[0-9a-f]{64}", fingerprint or "") is None:
    raise SystemExit("recovered lifecycle node has no signed certificate fingerprint")
if state.get("node_id") != node_id or state.get("network_id") != network_id:
    raise SystemExit("enrolled agent state disagrees with recovered authority identity")
events = {(item.get("action"), item.get("resource_id")) for item in audit if isinstance(item, dict)}
required = {("node.created", node_id), ("node.enrolled", node_id)}
if expected_status == "revoked":
    required.add(("node.revoked", node_id))
if not required.issubset(events):
    raise SystemExit("recovered lifecycle audit is missing create/enroll/revoke evidence")
PY
}

exercise_recovered_lifecycle() {
  local token_file="${work_dir}/recovered-member.enrollment-token"
  local state_path="${work_dir}/recovered-member/agent/state.json"
  local output_dir="${work_dir}/recovered-member/nebula"
  local node_id

  printf '%s\n' '{"name":"pitr-recovered-member","role":"member"}' >"${work_dir}/recovered-member-create-request.json"
  capture_pending_node "${work_dir}/recovered-member-create-request.json" "${token_file}" \
    "${work_dir}/recovered-member-created.json"
  node_id="$(json_scalar "${work_dir}/recovered-member-created.json" node.id)"
  require_record_id "${node_id}" "recovered lifecycle node ID"
  mkdir -p -- "${work_dir}/recovered-member/agent"
  chmod 0700 "${work_dir}/recovered-member" "${work_dir}/recovered-member/agent"
  MESH_ENROLL_TOKEN= "${meshctl}" enroll \
    --server "${app_url}" \
    --token-file "${token_file}" \
    --state "${state_path}" \
    --output "${output_dir}" \
    --nebula "${nebula}" \
    --nebula-cert "${nebula_cert}" \
    >"${work_dir}/recovered-member-enroll.log" 2>&1
  [[ "$(json_scalar "${state_path}" node_id)" == "${node_id}" ]] || die "enrolled node state has the wrong node ID"
  [[ "$(json_scalar "${state_path}" network_id)" == "${source_network_id}" ]] || die "enrolled node state has the wrong network ID"
  validate_bundle "${output_dir}" "${work_dir}/recovered-member-bundle-validation.log"
  api_request "${app_url}" GET "/api/v1/networks/${source_network_id}/nodes" "${work_dir}/recovered-member-active-nodes.json"
  api_request "${app_url}" GET /api/v1/audit "${work_dir}/recovered-member-active-audit.json"
  assert_lifecycle_node "${work_dir}/recovered-member-active-nodes.json" \
    "${work_dir}/recovered-member-active-audit.json" "${state_path}" "${node_id}" active

  api_request "${app_url}" POST "/api/v1/nodes/${node_id}/revoke" "${work_dir}/recovered-member-revoked.json"
  [[ "$(json_scalar "${work_dir}/recovered-member-revoked.json" id)" == "${node_id}" ]] || die "revocation returned the wrong node"
  [[ "$(json_scalar "${work_dir}/recovered-member-revoked.json" status)" == "revoked" ]] || die "recovered node did not reach revoked status"
  api_request "${app_url}" GET "/api/v1/networks/${source_network_id}/nodes" "${work_dir}/recovered-member-revoked-nodes.json"
  api_request "${app_url}" GET /api/v1/audit "${work_dir}/recovered-member-revoked-audit.json"
  assert_lifecycle_node "${work_dir}/recovered-member-revoked-nodes.json" \
    "${work_dir}/recovered-member-revoked-audit.json" "${state_path}" "${node_id}" revoked
}

assert_no_secret_logging() {
  python3 - "${work_dir}" \
    "${work_dir}/source/admin.token" \
    "${work_dir}/source/master.key" \
    "${work_dir}/backup.key" \
    "${work_dir}/replication.password" \
    "${work_dir}/postgres.env" \
    "${work_dir}/early-session.cookies" \
    "${work_dir}/late-session.cookies" \
    "${work_dir}/after-session.cookies" \
    "${work_dir}/recovered-member.enrollment-token" \
    "${work_dir}/recovered-member/agent/state.json" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
secrets = []
for index, raw_path in enumerate(sys.argv[2:], start=2):
    path = pathlib.Path(raw_path)
    raw = path.read_bytes()
    if path.name == "postgres.env":
        secrets.extend(line.split(b"=", 1)[1] for line in raw.splitlines() if b"=" in line)
    elif path.suffix == ".cookies":
        for line in raw.splitlines():
            fields = line.split(b"\t")
            if len(fields) == 7:
                secrets.append(fields[6])
    elif path.name == "state.json" and "recovered-member" in str(path):
        state = json.loads(raw)
        bearer = state.get("bearer")
        if isinstance(bearer, str):
            secrets.append(bearer.encode("ascii"))
    else:
        secrets.append(raw.strip())
secrets = [value for value in secrets if len(value) >= 16]
diagnostic_suffixes = {".log", ".stderr", ".stdout", ".txt", ".json"}
for path in root.iterdir():
    if not path.is_file() or path.suffix not in diagnostic_suffixes:
        continue
    raw = path.read_bytes()
    for secret in secrets:
        if secret in raw:
            raise SystemExit(f"known disposable credential leaked into diagnostic file: {path.name}")
PY
}

if [[ "${keep_smoke}" != "0" && "${keep_smoke}" != "1" ]]; then
  die "KEEP_MESH_SMOKE must be 0 or 1"
fi
if (( BASH_VERSINFO[0] < 4 )); then
  skip "Bash 4 or newer is required"
fi
if [[ "$(uname -s 2>/dev/null || true)" != "Linux" ]]; then
  skip "the secure backup importer and this PITR smoke require Linux"
fi
for prerequisite in go python3 curl docker mktemp chmod mkdir rm ps readlink sleep tr uname cmp \
  grep sha256sum awk stat; do
  command -v -- "${prerequisite}" >/dev/null 2>&1 || skip "required command is unavailable: ${prerequisite}"
done
for binary in "${nebula}" "${nebula_cert}"; do
  [[ -x "${binary}" && -f "${binary}" && ! -L "${binary}" ]] || skip "real ${binary} is unavailable"
done
nebula_version="$(${nebula} -version 2>&1)" || skip "nebula -version failed"
nebula_cert_version="$(${nebula_cert} -version 2>&1)" || skip "nebula-cert -version failed"
nebula_version_exact "${nebula_version}" || skip "exact Nebula 1.10.3 is required"
nebula_version_exact "${nebula_cert_version}" || skip "exact nebula-cert 1.10.3 is required"
unset nebula_version nebula_cert_version
docker info >/dev/null 2>&1 || skip "Docker daemon access is unavailable"
docker image inspect "${postgres_image}" >/dev/null 2>&1 || skip "cached postgres:17-alpine image is unavailable"

temporary_parent="${TMPDIR:-/tmp}"
[[ -d "${temporary_parent}" && ! -L "${temporary_parent}" ]] || skip "private temporary directory parent is unavailable"
work_parent="$(cd -- "${temporary_parent}" && pwd -P)"
work_dir="$(mktemp -d "${work_parent%/}/mesh-postgres-pitr-smoke.XXXXXX")"
[[ -d "${work_dir}" && ! -L "${work_dir}" ]] || die "mktemp did not create a real private workspace"
chmod 0700 "${work_dir}"
mkdir -- "${work_dir}/bin" "${work_dir}/source"
chmod 0700 "${work_dir}/bin" "${work_dir}/source"
cd -- "${repo_root}"

say "Building isolated Mesh server, storage, backup, and lifecycle executables"
go build -buildvcs=false -trimpath -o "${work_dir}/bin/mesh-server" ./cmd/mesh-server \
  >"${work_dir}/build-server.log" 2>&1
go build -buildvcs=false -trimpath -o "${work_dir}/bin/mesh-storage" ./cmd/mesh-storage \
  >"${work_dir}/build-storage.log" 2>&1
go build -buildvcs=false -trimpath -o "${work_dir}/bin/mesh-backup" ./cmd/mesh-backup \
  >"${work_dir}/build-backup.log" 2>&1
go build -buildvcs=false -trimpath -o "${work_dir}/bin/meshctl" ./cmd/meshctl \
  >"${work_dir}/build-meshctl.log" 2>&1
mesh_server="$(readlink -f -- "${work_dir}/bin/mesh-server")"
mesh_storage="$(readlink -f -- "${work_dir}/bin/mesh-storage")"
mesh_backup="$(readlink -f -- "${work_dir}/bin/mesh-backup")"
meshctl="$(readlink -f -- "${work_dir}/bin/meshctl")"

source_port="$(pick_loopback_port)"
[[ "${source_port}" =~ ^[0-9]+$ && "${source_port}" -ge 1024 && "${source_port}" -le 65535 ]] || \
  die "kernel returned an invalid source loopback port"
source_url="http://127.0.0.1:${source_port}"

say "Creating an authenticated current control-v5 JSON source and encrypted import archive"
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

printf '%s\n' '{"name":"pitr-source","cidr":"10.97.0.0/24"}' >"${work_dir}/source-network-request.json"
api_request "${source_url}" POST /api/v1/networks "${work_dir}/source-network.json" \
  "${work_dir}/source-network-request.json"
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
network_name="mesh-postgres-pitr-smoke-${run_id}-network"
primary_container="mesh-postgres-pitr-smoke-${run_id}-primary"
archive_init_container="mesh-postgres-pitr-smoke-${run_id}-archive-init"
basebackup_container="mesh-postgres-pitr-smoke-${run_id}-basebackup"
early_clone_container="mesh-postgres-pitr-smoke-${run_id}-early-clone"
early_container="mesh-postgres-pitr-smoke-${run_id}-early"
late_clone_container="mesh-postgres-pitr-smoke-${run_id}-late-clone"
late_container="mesh-postgres-pitr-smoke-${run_id}-late"
primary_volume="mesh-postgres-pitr-smoke-${run_id}-primary-data"
archive_volume="mesh-postgres-pitr-smoke-${run_id}-archive-data"
base_volume="mesh-postgres-pitr-smoke-${run_id}-base-data"
early_volume="mesh-postgres-pitr-smoke-${run_id}-early-data"
late_volume="mesh-postgres-pitr-smoke-${run_id}-late-data"

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
printf '%s\n' "${replication_password}" >"${work_dir}/replication.password"
chmod 0600 "${work_dir}/replication.password"

say "Creating one exact labeled Docker network and five purpose-specific volumes"
docker network create \
  --label "${smoke_label}=${run_id}" \
  --label "${smoke_kind_label}=${smoke_kind}" \
  "${network_name}" >"${work_dir}/network.id"
network_id="$(tr -d '\r\n' <"${work_dir}/network.id")"
[[ "${network_id}" =~ ^[0-9a-f]{64}$ ]] || die "Docker did not return one canonical network ID"
network_matches_run || die "disposable network identity or labels did not match"
for volume in "${primary_volume}" "${archive_volume}" "${base_volume}" "${early_volume}" "${late_volume}"; do
  docker volume create \
    --label "${smoke_label}=${run_id}" \
    --label "${smoke_kind_label}=${smoke_kind}" \
    "${volume}" >"${work_dir}/${volume##*-}.volume"
  volume_names["${volume}"]="${volume}"
  volume_matches_run "${volume}" || die "disposable volume ${volume} identity or labels did not match"
done

say "Preparing the private WAL archive volume"
docker run --detach \
  --name "${archive_init_container}" \
  --label "${smoke_label}=${run_id}" \
  --label "${smoke_kind_label}=${smoke_kind}" \
  --network "${network_name}" \
  --volume "${archive_volume}:/archive" \
  --entrypoint /bin/sh \
  "${postgres_image}" \
  -c 'trap "exit 0" TERM INT; while :; do sleep 3600 & wait $!; done' \
  >"${work_dir}/archive-init.id" 2>"${work_dir}/archive-init-docker-run.stderr"
register_container "${archive_init_container}" "${work_dir}/archive-init.id"
docker exec --user root "${archive_init_container}" sh -c \
  'set -eu; test -z "$(find /archive -mindepth 1 -print -quit)"; chown postgres:postgres /archive; chmod 0700 /archive; test "$(stat -c %U /archive)" = postgres'
remove_container_exact "${archive_init_container}"

{
  printf 'POSTGRES_USER=mesh\n'
  printf 'POSTGRES_DB=mesh\n'
  printf 'POSTGRES_PASSWORD=%s\n' "${postgres_password}"
  printf 'POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=trust\n'
} >"${work_dir}/postgres.env"
chmod 0600 "${work_dir}/postgres.env"

say "Starting the exact PostgreSQL 17 primary with continuous archived WAL"
docker run --detach \
  --name "${primary_container}" \
  --label "${smoke_label}=${run_id}" \
  --label "${smoke_kind_label}=${smoke_kind}" \
  --network "${network_name}" \
  --network-alias mesh-pitr-primary \
  --volume "${primary_volume}:/var/lib/postgresql/data" \
  --volume "${archive_volume}:/archive" \
  --env-file "${work_dir}/postgres.env" \
  --publish '127.0.0.1::5432' \
  "${postgres_image}" \
  postgres \
    -c wal_level=replica \
    -c max_wal_senders=4 \
    -c archive_mode=on \
    -c 'archive_command=test -f /archive/%f || (cp %p /archive/%f.partial && sync /archive/%f.partial && mv /archive/%f.partial /archive/%f && sync /archive)' \
    -c archive_timeout=2s \
    -c password_encryption=scram-sha-256 \
  >"${work_dir}/primary.id" 2>"${work_dir}/primary-docker-run.stderr"
register_container "${primary_container}" "${work_dir}/primary.id"
wait_postgres_ready "${primary_container}" primary
[[ "$(postgres_scalar "${primary_container}" 'SHOW server_version;')" =~ ^17\. ]] || \
  die "primary is not PostgreSQL 17"
[[ "$(postgres_scalar "${primary_container}" \
  "SELECT current_setting('archive_mode') || '|' || current_setting('wal_level');")" == "on|replica" ]] || \
  die "primary did not enable the exact archive/WAL boundary"

say "Creating a dedicated base-backup replication login"
printf '%s\n' 'host replication mesh_repl samenet scram-sha-256' | \
  docker exec --interactive --user postgres "${primary_container}" \
    sh -c 'cat >> /var/lib/postgresql/data/pg_hba.conf'
docker exec --user postgres "${primary_container}" \
  pg_ctl reload --pgdata /var/lib/postgresql/data \
  >"${work_dir}/primary-reload.stdout" 2>"${work_dir}/primary-reload.stderr"
printf "CREATE ROLE mesh_repl WITH LOGIN REPLICATION PASSWORD '%s';\n" "${replication_password}" | \
  postgres_script "${primary_container}" "${work_dir}/primary-replication-setup.txt"

primary_port="$(container_port "${primary_container}")"
printf 'postgres://mesh:%s@127.0.0.1:%s/mesh?sslmode=disable&target_session_attrs=read-write&connect_timeout=3&pool_max_conns=8&pool_min_conns=0\n' \
  "${postgres_password}" "${primary_port}" >"${work_dir}/primary.dsn"
chmod 0600 "${work_dir}/primary.dsn"

say "Migrating, importing, and verifying the authenticated control-v5 pair"
"${mesh_storage}" migrate \
  --postgres-dsn-file "${work_dir}/primary.dsn" \
  --allow-local-plaintext-postgres \
  >"${work_dir}/storage-migrate.json" 2>"${work_dir}/storage-migrate.stderr"
[[ "$(json_scalar "${work_dir}/storage-migrate.json" status)" == "migrated" ]] || \
  die "PostgreSQL migration did not report success"
"${mesh_storage}" import-backup \
  --postgres-dsn-file "${work_dir}/primary.dsn" \
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
  --postgres-dsn-file "${work_dir}/primary.dsn" \
  --backup-key-file "${work_dir}/backup.key" \
  --backup-archive "${work_dir}/source.meshbackup" \
  --expect-backup-id "${backup_id}" \
  --allow-local-plaintext-postgres \
  >"${work_dir}/storage-verify.json" 2>"${work_dir}/storage-verify.stderr"
[[ "$(json_scalar "${work_dir}/storage-verify.json" status)" == "verified" ]] || \
  die "PostgreSQL exact-document verification did not report success"
assert_revisions "${primary_container}" 1 1

say "Taking one immutable physical base backup before application mutations"
docker run --detach \
  --name "${basebackup_container}" \
  --label "${smoke_label}=${run_id}" \
  --label "${smoke_kind_label}=${smoke_kind}" \
  --network "${network_name}" \
  --volume "${base_volume}:/base" \
  --entrypoint /bin/sh \
  "${postgres_image}" \
  -c 'trap "exit 0" TERM INT; while :; do sleep 3600 & wait $!; done' \
  >"${work_dir}/basebackup.id" 2>"${work_dir}/basebackup-docker-run.stderr"
register_container "${basebackup_container}" "${work_dir}/basebackup.id"
docker exec --user root "${basebackup_container}" sh -c \
  'set -eu; test -z "$(find /base -mindepth 1 -print -quit)"; chown postgres:postgres /base; chmod 0700 /base'
printf 'mesh-pitr-primary:5432:*:mesh_repl:%s\n' "${replication_password}" | \
  docker exec --interactive --user root "${basebackup_container}" sh -c \
    'umask 077; cat > /tmp/mesh-repl.pgpass; chown postgres:postgres /tmp/mesh-repl.pgpass; chmod 0600 /tmp/mesh-repl.pgpass'
docker exec --user postgres --env PGPASSFILE=/tmp/mesh-repl.pgpass "${basebackup_container}" \
  pg_basebackup \
    --host mesh-pitr-primary \
    --port 5432 \
    --username mesh_repl \
    --pgdata /base \
    --format plain \
    --wal-method stream \
    --checkpoint fast \
    >"${work_dir}/pg-basebackup.stdout" 2>"${work_dir}/pg-basebackup.stderr"
docker exec --user root "${basebackup_container}" sh -c \
  'set -eu; rm -f /tmp/mesh-repl.pgpass; test -f /base/PG_VERSION; test -f /base/backup_label; test ! -e /base/recovery.signal; test ! -e /base/standby.signal; test "$(stat -c %U /base)" = postgres'
snapshot_base_volume "${basebackup_container}" "${work_dir}/base-backup.sha256"
remove_container_exact "${basebackup_container}"

primary_app_port="$(pick_loopback_port)"
[[ "${primary_app_port}" =~ ^[0-9]+$ && "${primary_app_port}" -ge 1024 && "${primary_app_port}" -le 65535 ]] || \
  die "kernel returned an invalid application loopback port"
public_origin="http://127.0.0.1:${primary_app_port}"
early_point="mesh_early_${run_id}"
late_point="mesh_late_${run_id}"
after_point="mesh_after_${run_id}"

say "Committing acknowledged control and identity mutations before the early point"
start_app "${work_dir}/primary.dsn" "${primary_app_port}" "primary application" primary
printf '%s\n' '{"name":"pitr-early-network","cidr":"10.98.0.0/24"}' >"${work_dir}/early-network-request.json"
api_request "${app_url}" POST /api/v1/networks "${work_dir}/early-network-response.json" \
  "${work_dir}/early-network-request.json"
browser_login "${app_url}" "${work_dir}/early-session.cookies" "${work_dir}/early-session-login.json"
early_session_id="$(json_scalar "${work_dir}/early-session-login.json" session_id)"
require_record_id "${early_session_id}" "early-point browser session ID"
assert_revisions "${primary_container}" 2 2
collect_api_snapshot "${app_url}" "${work_dir}/early-expected"
assert_point_inventory "${work_dir}/early-expected" early "${early_session_id}"
stop_app
capture_database_manifest "${primary_container}" "${work_dir}/early-before-point-database.txt"
create_recovery_point "${early_point}" "${work_dir}/early-point.txt"
capture_database_manifest "${primary_container}" "${work_dir}/early-expected-database.txt"
cmp --silent "${work_dir}/early-before-point-database.txt" "${work_dir}/early-expected-database.txt" || \
  die "Mesh database ledger changed while the sole app writer was stopped for the early point"
write_recovery_evidence "${work_dir}/early-point.txt" "${work_dir}/early-expected-database.txt" \
  "${work_dir}/early-expected" "${work_dir}/early-evidence.json"

say "Committing another acknowledged control and identity pair before the later point"
start_app "${work_dir}/primary.dsn" "${primary_app_port}" "primary application after early point" primary-after-early
printf '%s\n' '{"name":"pitr-late-network","cidr":"10.99.0.0/24"}' >"${work_dir}/late-network-request.json"
api_request "${app_url}" POST /api/v1/networks "${work_dir}/late-network-response.json" \
  "${work_dir}/late-network-request.json"
browser_login "${app_url}" "${work_dir}/late-session.cookies" "${work_dir}/late-session-login.json"
late_session_id="$(json_scalar "${work_dir}/late-session-login.json" session_id)"
require_record_id "${late_session_id}" "later-point browser session ID"
[[ "${late_session_id}" != "${early_session_id}" ]] || die "early/later logins returned one session ID"
assert_revisions "${primary_container}" 3 3
collect_api_snapshot "${app_url}" "${work_dir}/late-expected"
assert_point_inventory "${work_dir}/late-expected" late "${early_session_id},${late_session_id}"
stop_app
capture_database_manifest "${primary_container}" "${work_dir}/late-before-point-database.txt"
create_recovery_point "${late_point}" "${work_dir}/late-point.txt"
capture_database_manifest "${primary_container}" "${work_dir}/late-expected-database.txt"
cmp --silent "${work_dir}/late-before-point-database.txt" "${work_dir}/late-expected-database.txt" || \
  die "Mesh database ledger changed while the sole app writer was stopped for the later point"
write_recovery_evidence "${work_dir}/late-point.txt" "${work_dir}/late-expected-database.txt" \
  "${work_dir}/late-expected" "${work_dir}/late-evidence.json"

say "Archiving a third acknowledged control/identity pair after the selected later point"
start_app "${work_dir}/primary.dsn" "${primary_app_port}" "primary application after later point" primary-after-late
printf '%s\n' '{"name":"pitr-after-network","cidr":"10.100.0.0/24"}' >"${work_dir}/after-network-request.json"
api_request "${app_url}" POST /api/v1/networks "${work_dir}/after-network-response.json" \
  "${work_dir}/after-network-request.json"
browser_login "${app_url}" "${work_dir}/after-session.cookies" "${work_dir}/after-session-login.json"
after_session_id="$(json_scalar "${work_dir}/after-session-login.json" session_id)"
require_record_id "${after_session_id}" "post-later browser session ID"
[[ "${after_session_id}" != "${early_session_id}" && "${after_session_id}" != "${late_session_id}" ]] || \
  die "three acknowledged logins did not return distinct sessions"
assert_revisions "${primary_container}" 4 4
collect_api_snapshot "${app_url}" "${work_dir}/after-expected"
assert_point_inventory "${work_dir}/after-expected" after \
  "${early_session_id},${late_session_id},${after_session_id}"
stop_app
capture_database_manifest "${primary_container}" "${work_dir}/after-before-point-database.txt"
create_recovery_point "${after_point}" "${work_dir}/after-point.txt"
capture_database_manifest "${primary_container}" "${work_dir}/after-expected-database.txt"
cmp --silent "${work_dir}/after-before-point-database.txt" "${work_dir}/after-expected-database.txt" || \
  die "Mesh database ledger changed while the sole app writer was stopped for the post-later point"
write_recovery_evidence "${work_dir}/after-point.txt" "${work_dir}/after-expected-database.txt" \
  "${work_dir}/after-expected" "${work_dir}/after-evidence.json"

say "Hard-terminating the exact primary after all selected and later WAL is archived"
container_matches_run "${primary_container}" || die "primary identity changed before forced termination"
docker kill --signal KILL -- "${primary_container}" >"${work_dir}/primary-kill.stdout"
[[ "$(tr -d '\r\n' <"${work_dir}/primary-kill.stdout")" == "${primary_container}" ]] || \
  die "Docker did not report termination of the exact primary"
[[ "$(docker inspect --format '{{.State.Running}}' "${primary_container}")" == "false" ]] || \
  die "exact primary remained running after forced termination"

say "Restoring the immutable base backup to the create-only recorded early point"
clone_base_for_recovery "${early_clone_container}" "${early_volume}" early
start_recovery_container "${early_container}" "${early_volume}" "${early_point}" early
capture_database_manifest "${early_container}" "${work_dir}/early-actual-database.txt"
cmp --silent "${work_dir}/early-expected-database.txt" "${work_dir}/early-actual-database.txt" || \
  die "early recovered revision/receipt ledger differs from the selected point"
assert_revisions "${early_container}" 2 2
printf 'postgres://mesh:%s@127.0.0.1:%s/mesh?sslmode=disable&target_session_attrs=read-write&connect_timeout=3&pool_max_conns=8&pool_min_conns=0\n' \
  "${postgres_password}" "${recovery_port}" >"${work_dir}/early.dsn"
chmod 0600 "${work_dir}/early.dsn"
early_app_port="$(pick_loopback_port)"
start_app "${work_dir}/early.dsn" "${early_app_port}" "early recovered application" early-recovered
collect_api_snapshot "${app_url}" "${work_dir}/early-actual"
assert_api_snapshot_equal "${work_dir}/early-expected" "${work_dir}/early-actual" "early recovered point"
assert_recovery_evidence "${work_dir}/early-evidence.json" \
  "${work_dir}/early-expected-database.txt" "${work_dir}/early-expected" \
  "${work_dir}/early-actual-database.txt" "${work_dir}/early-actual" \
  "${early_container}" "${early_point}" "${work_dir}/early-base-after.sha256"
browser_session_get "${app_url}" "${work_dir}/early-session.cookies" "${work_dir}/early-session-restored.json"
[[ "$(json_scalar "${work_dir}/early-session-restored.json" session_id)" == "${early_session_id}" ]] || \
  die "early selected session was not authenticated after early recovery"
assert_session_rejected "${app_url}" "${work_dir}/late-session.cookies" "${work_dir}/late-session-absent-early.json"
assert_session_rejected "${app_url}" "${work_dir}/after-session.cookies" "${work_dir}/after-session-absent-early.json"

say "Exercising fresh create/enroll/sign/verify/revoke lifecycle only after exact early-point validation"
exercise_recovered_lifecycle
assert_revisions "${early_container}" 6 2
stop_app
remove_container_exact "${early_container}"

say "Independently restoring the same base backup to the create-only recorded later point"
clone_base_for_recovery "${late_clone_container}" "${late_volume}" late
start_recovery_container "${late_container}" "${late_volume}" "${late_point}" late
capture_database_manifest "${late_container}" "${work_dir}/late-actual-database.txt"
cmp --silent "${work_dir}/late-expected-database.txt" "${work_dir}/late-actual-database.txt" || \
  die "later recovered revision/receipt ledger differs from the selected point"
assert_revisions "${late_container}" 3 3
printf 'postgres://mesh:%s@127.0.0.1:%s/mesh?sslmode=disable&target_session_attrs=read-write&connect_timeout=3&pool_max_conns=8&pool_min_conns=0\n' \
  "${postgres_password}" "${recovery_port}" >"${work_dir}/late.dsn"
chmod 0600 "${work_dir}/late.dsn"
late_app_port="$(pick_loopback_port)"
start_app "${work_dir}/late.dsn" "${late_app_port}" "later recovered application" late-recovered
collect_api_snapshot "${app_url}" "${work_dir}/late-actual"
assert_api_snapshot_equal "${work_dir}/late-expected" "${work_dir}/late-actual" "later recovered point"
assert_recovery_evidence "${work_dir}/late-evidence.json" \
  "${work_dir}/late-expected-database.txt" "${work_dir}/late-expected" \
  "${work_dir}/late-actual-database.txt" "${work_dir}/late-actual" \
  "${late_container}" "${late_point}" "${work_dir}/late-base-after.sha256"
browser_session_get "${app_url}" "${work_dir}/early-session.cookies" "${work_dir}/early-session-restored-late.json"
[[ "$(json_scalar "${work_dir}/early-session-restored-late.json" session_id)" == "${early_session_id}" ]] || \
  die "early session was not retained at the later recovery point"
browser_session_get "${app_url}" "${work_dir}/late-session.cookies" "${work_dir}/late-session-restored.json"
[[ "$(json_scalar "${work_dir}/late-session-restored.json" session_id)" == "${late_session_id}" ]] || \
  die "later selected session was not authenticated at the later recovery point"
assert_session_rejected "${app_url}" "${work_dir}/after-session.cookies" "${work_dir}/after-session-absent-late.json"

assert_no_secret_logging

say "PASS: PostgreSQL 17 restored one immutable base backup plus continuously archived WAL to two create-only recorded named points on source timeline 1"
say "PASS: each recovered authority exactly matched its create-only fsynced point evidence, base/WAL digests, API state, two-document revisions, and full receipt/import ledger before fresh writes"
say "PASS: early recovery excluded later mutations and sessions; later recovery included its selected mutation/session but excluded the archived post-point pair"
say "PASS: the validated early authority accepted a fresh real Nebula create, enrollment, CA-signed bundle verification, and revocation lifecycle"
say "LIMIT: this bounded local drill does not provide external catalog custody, WAL retention/timeline-history operations, concurrent-write/failover fault injection, production TLS/roles, or load/soak budgets"
