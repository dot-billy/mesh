#!/usr/bin/env bash

# Disposable Linux mechanism proof for the documented PostgreSQL role and TLS
# boundary. One PostgreSQL 17 container provides the database and one Ubuntu
# 24.04 container runs the real Mesh binaries against an isolated system trust
# store. This is not a deployment-platform, managed-database, or HA proof.

set -Eeuo pipefail
umask 077

readonly skip_status=77
readonly script_name="${0##*/}"
readonly keep_smoke="${KEEP_MESH_SMOKE:-0}"
readonly postgres_image="postgres:17-alpine"
readonly client_image="ubuntu:24.04"
readonly nebula_cert_source="/usr/local/bin/nebula-cert"
readonly resource_prefix="mesh-postgres-roles-tls-smoke"
readonly smoke_kind="postgres-roles-tls"

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
work_parent=""
work_dir=""
run_id=""
network_name=""
network_id=""
network_created=0
pgdata_volume=""
tls_volume=""
pgdata_created=0
tls_created=0
postgres_container=""
postgres_id=""
postgres_started=0
client_container=""
client_id=""
client_started=0
helper_container=""
helper_id=""
helper_started=0

mesh_server=""
mesh_storage=""
mesh_backup=""
source_pid=""
runtime_pid=""
source_port=""
source_url=""
client_port=""
client_url=""
public_origin="https://mesh.roles-tls.invalid"

admin_token=""
master_key=""
backup_id=""
postgres_admin_password=""
migrate_password=""
import_password=""
runtime_old_password=""
runtime_new_password=""

primary_host=""
fallback_host=""
unavailable_host=""
unverified_host=""

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

  [[ -n "${pid}" && "${pid}" =~ ^[0-9]+$ && "${pid}" -gt 1 ]] || return 0
  if ! kill -0 "${pid}" 2>/dev/null; then
    wait "${pid}" 2>/dev/null || true
    return 0
  fi
  valid_child_pid "${pid}" "${expected_executable}" || {
    printf 'ERROR: refusing to signal unverified process %s\n' "${pid}" >&2
    return 1
  }
  kill -TERM "${pid}" 2>/dev/null || true
  for attempt in {1..100}; do
    kill -0 "${pid}" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "${pid}" 2>/dev/null; then
    valid_child_pid "${pid}" "${expected_executable}" || return 1
    kill -KILL "${pid}" 2>/dev/null || true
  fi
  wait "${pid}" 2>/dev/null || true
}

container_matches() {
  local name="$1"
  local expected_id="$2"
  local role="$3"
  local observed_name observed_id observed_instance observed_kind observed_role

  [[ "${name}" =~ ^${resource_prefix}-[0-9a-f]{16}-(postgres|client|tls-init)$ ]] || return 1
  [[ -z "${expected_id}" || "${expected_id}" =~ ^[0-9a-f]{64}$ ]] || return 1
  observed_name="$(docker inspect --format '{{.Name}}' "${name}" 2>/dev/null || true)"
  observed_id="$(docker inspect --format '{{.Id}}' "${name}" 2>/dev/null || true)"
  observed_instance="$(docker inspect --format '{{ index .Config.Labels "io.mesh.smoke.instance" }}' "${name}" 2>/dev/null || true)"
  observed_kind="$(docker inspect --format '{{ index .Config.Labels "io.mesh.smoke.kind" }}' "${name}" 2>/dev/null || true)"
  observed_role="$(docker inspect --format '{{ index .Config.Labels "io.mesh.smoke.role" }}' "${name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "/${name}" && "${observed_id}" =~ ^[0-9a-f]{64}$ &&
     ( -z "${expected_id}" || "${observed_id}" == "${expected_id}" ) &&
     "${observed_instance}" == "${run_id}" && "${observed_kind}" == "${smoke_kind}" &&
     "${observed_role}" == "${role}" ]]
}

network_matches() {
  local observed_name observed_id observed_instance observed_kind

  [[ "${network_name}" =~ ^${resource_prefix}-[0-9a-f]{16}-network$ ]] || return 1
  observed_name="$(docker network inspect --format '{{.Name}}' "${network_name}" 2>/dev/null || true)"
  observed_id="$(docker network inspect --format '{{.Id}}' "${network_name}" 2>/dev/null || true)"
  observed_instance="$(docker network inspect --format '{{ index .Labels "io.mesh.smoke.instance" }}' "${network_name}" 2>/dev/null || true)"
  observed_kind="$(docker network inspect --format '{{ index .Labels "io.mesh.smoke.kind" }}' "${network_name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "${network_name}" && "${observed_id}" =~ ^[0-9a-f]{64}$ &&
     ( -z "${network_id}" || "${observed_id}" == "${network_id}" ) &&
     "${observed_instance}" == "${run_id}" && "${observed_kind}" == "${smoke_kind}" ]]
}

volume_matches() {
  local name="$1"
  local role="$2"
  local observed_name observed_instance observed_kind observed_role

  [[ "${name}" =~ ^${resource_prefix}-[0-9a-f]{16}-(pgdata|tls)$ ]] || return 1
  observed_name="$(docker volume inspect --format '{{.Name}}' "${name}" 2>/dev/null || true)"
  observed_instance="$(docker volume inspect --format '{{ index .Labels "io.mesh.smoke.instance" }}' "${name}" 2>/dev/null || true)"
  observed_kind="$(docker volume inspect --format '{{ index .Labels "io.mesh.smoke.kind" }}' "${name}" 2>/dev/null || true)"
  observed_role="$(docker volume inspect --format '{{ index .Labels "io.mesh.smoke.role" }}' "${name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "${name}" && "${observed_instance}" == "${run_id}" &&
     "${observed_kind}" == "${smoke_kind}" && "${observed_role}" == "${role}" ]]
}

remove_exact_container() {
  local started="$1"
  local name="$2"
  local id="$3"
  local role="$4"

  [[ "${started}" == "1" ]] || return 0
  if container_matches "${name}" "${id}" "${role}"; then
    docker rm --force -- "${name}" >/dev/null 2>&1
  elif docker inspect "${name}" >/dev/null 2>&1; then
    printf 'ERROR: refusing to remove container with changed identity: %s\n' "${name}" >&2
    return 1
  fi
}

cleanup() {
  local status=$?
  local base parent

  trap - ERR EXIT HUP INT TERM
  set +e

  if [[ -n "${source_pid}" ]]; then
    stop_child "${source_pid}" "${mesh_server}" || status=1
    source_pid=""
  fi

  postgres_admin_password=""
  migrate_password=""
  import_password=""
  runtime_old_password=""
  runtime_new_password=""
  admin_token=""
  master_key=""

  if [[ "${keep_smoke}" == "1" ]]; then
    printf 'Kept exact private roles/TLS smoke resources for debugging (run %s).\n' "${run_id:-unassigned}" >&2
    printf 'The retained workspace and resources contain disposable live credentials.\n' >&2
  else
    remove_exact_container "${client_started}" "${client_container}" "${client_id}" client || status=1
    client_started=0
    remove_exact_container "${postgres_started}" "${postgres_container}" "${postgres_id}" postgres || status=1
    postgres_started=0
    remove_exact_container "${helper_started}" "${helper_container}" "${helper_id}" tls-init || status=1
    helper_started=0

    if [[ "${pgdata_created}" == "1" ]]; then
      if volume_matches "${pgdata_volume}" pgdata; then
        docker volume rm -- "${pgdata_volume}" >/dev/null 2>&1 || status=1
      elif docker volume inspect "${pgdata_volume}" >/dev/null 2>&1; then
        printf 'ERROR: refusing to remove volume with changed labels: %s\n' "${pgdata_volume}" >&2
        status=1
      fi
      pgdata_created=0
    fi
    if [[ "${tls_created}" == "1" ]]; then
      if volume_matches "${tls_volume}" tls; then
        docker volume rm -- "${tls_volume}" >/dev/null 2>&1 || status=1
      elif docker volume inspect "${tls_volume}" >/dev/null 2>&1; then
        printf 'ERROR: refusing to remove volume with changed labels: %s\n' "${tls_volume}" >&2
        status=1
      fi
      tls_created=0
    fi
    if [[ "${network_created}" == "1" ]]; then
      if network_matches; then
        docker network rm -- "${network_name}" >/dev/null 2>&1 || status=1
      elif docker network inspect "${network_name}" >/dev/null 2>&1; then
        printf 'ERROR: refusing to remove network with changed identity: %s\n' "${network_name}" >&2
        status=1
      fi
      network_created=0
    fi
    if [[ -n "${work_dir}" && -d "${work_dir}" ]]; then
      base="${work_dir##*/}"
      parent="$(cd -- "$(dirname -- "${work_dir}")" 2>/dev/null && pwd -P)"
      if [[ "${base}" == ${resource_prefix}.* && -n "${work_parent}" && "${parent}" == "${work_parent}" && ! -L "${work_dir}" ]]; then
        rm -rf -- "${work_dir}"
      else
        printf 'ERROR: refusing to remove unexpected workspace: %s\n' "${work_dir}" >&2
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
  printf 'ERROR: %s failed at line %s (set KEEP_MESH_SMOKE=1 for private diagnostics)\n' \
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

random_bearer() {
  python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
}

json_scalar() {
  local path="$1"
  local field="$2"
  python3 - "${path}" "${field}" <<'PY'
import json, pathlib, sys
def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON name")
        result[key] = value
    return result
raw = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
decoder = json.JSONDecoder(object_pairs_hook=unique)
value, end = decoder.raw_decode(raw)
if raw[end:].strip():
    raise SystemExit("trailing JSON data")
for part in sys.argv[2].split("."):
    value = value[part]
if isinstance(value, (dict, list, bool)) or value is None:
    raise SystemExit("field is not scalar")
print(value)
PY
}

read_private_line() {
  local path="$1"
  python3 - "${path}" <<'PY'
import os, stat, sys
path = sys.argv[1]
fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
try:
    info = os.fstat(fd)
    raw = os.read(fd, 4097)
finally:
    os.close(fd)
if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
    raise SystemExit("private file ownership changed")
if stat.S_IMODE(info.st_mode) not in (0o400, 0o600) or len(raw) != info.st_size:
    raise SystemExit("private file mode or size is invalid")
text = raw.decode("utf-8")
if "\x00" in text or not text.endswith("\n") or "\n" in text[:-1] or "\r" in text:
    raise SystemExit("private file is not canonical")
print(text[:-1], end="")
PY
}

wait_for_url() {
  local url="$1"
  local label="$2"
  local poll
  local -a tls_args=()
  [[ "${url}" == https://* ]] && tls_args+=(--insecure)
  for poll in {1..300}; do
    if curl --silent --show-error --fail --noproxy '*' --connect-timeout 1 --max-time 1 \
      "${tls_args[@]}" --output /dev/null "${url}/healthz" 2>/dev/null &&
       curl --silent --show-error --fail --noproxy '*' --connect-timeout 1 --max-time 1 \
      "${tls_args[@]}" --output /dev/null "${url}/readyz" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  die "${label} did not reach liveness and readiness"
}

wait_for_readiness_status() {
  local expected="$1"
  local label="$2"
  local poll status
  for poll in {1..200}; do
    status="$(curl --silent --show-error --noproxy '*' --insecure \
      --connect-timeout 1 --max-time 2 --output /dev/null --write-out '%{http_code}' \
      "${client_url}/readyz" 2>/dev/null || true)"
    if [[ "${status}" == "${expected}" ]]; then
      return 0
    fi
    sleep 0.1
  done
  die "${label} did not reach HTTP ${expected} readiness status"
}

api_request() {
  local method="$1"
  local path="$2"
  local output="$3"
  local body="${4:-}"
  local -a args=(
    --silent --show-error --fail --noproxy '*'
    --insecure
    --connect-timeout 2 --max-time 60
    --config "${work_dir}/client/admin.curlrc"
    --request "${method}" --output "${output}"
  )
  [[ -z "${body}" ]] || args+=(--data-binary "@${body}")
  curl "${args[@]}" "${client_url}${path}"
}

psql_as() {
  local service="$1"
  local sql_file="$2"
  local stdout_file="$3"
  local stderr_file="$4"
  docker exec --user 1000:1000 --env HOME=/role-client "${postgres_container}" \
    psql "service=${service}" --no-psqlrc --set ON_ERROR_STOP=1 --file "${sql_file}" \
    >"${stdout_file}" 2>"${stderr_file}"
}

expect_sql_denied() {
  local service="$1"
  local sql_file="$2"
  local label="$3"
  local stem="${sql_file##*/}"
  local status=0
  psql_as "${service}" "${sql_file}" \
    "${work_dir}/results/${stem}.stdout" "${work_dir}/results/${stem}.stderr" || status=$?
  [[ "${status}" -ne 0 ]] || die "${label} unexpectedly succeeded"
  grep -Eiq 'permission denied|must be owner|not owner' "${work_dir}/results/${stem}.stderr" || \
    die "${label} failed for a reason other than authorization"
}

run_mesh_storage() {
  docker exec --user 1000:1000 "${client_container}" \
    "${work_dir}/client/bin/mesh-storage" "$@"
}

postgres_application_row_count() {
  docker exec "${postgres_container}" psql --no-psqlrc --tuples-only --no-align \
    --username mesh_admin --dbname mesh --command '
SELECT
    (SELECT pg_catalog.count(*) FROM mesh.mesh_write_receipts)
  + (SELECT pg_catalog.count(*) FROM mesh.mesh_state_documents)
  + (SELECT pg_catalog.count(*) FROM mesh.mesh_write_receipt_documents)
  + (SELECT pg_catalog.count(*) FROM mesh.mesh_import_metadata)'
}

start_runtime() {
  local dsn_name="$1"
  local log_name="$2"
  docker exec --detach --user 1000:1000 "${client_container}" \
    "${work_dir}/client/start-runtime.sh" "${dsn_name}" "${log_name}"
  for poll in {1..100}; do
    if [[ -s "${work_dir}/client/runtime.pid" ]]; then
      runtime_pid="$(tr -d '\r\n' <"${work_dir}/client/runtime.pid")"
      [[ "${runtime_pid}" =~ ^[0-9]+$ && "${runtime_pid}" -gt 1 ]] && break
    fi
    sleep 0.1
  done
  [[ "${runtime_pid}" =~ ^[0-9]+$ && "${runtime_pid}" -gt 1 ]] || die "runtime PID was not recorded"
  docker exec "${client_container}" sh -c \
    'test "$(readlink -f "/proc/$1/exe")" = "$2"' sh "${runtime_pid}" "${work_dir}/client/bin/mesh-server" || \
    die "runtime process identity did not match the isolated Mesh binary"
  wait_for_url "${client_url}" "PostgreSQL-backed Mesh runtime"
}

stop_runtime() {
  local poll
  [[ -n "${runtime_pid}" ]] || return 0
  docker exec "${client_container}" sh -c 'kill -TERM "$1"' sh "${runtime_pid}"
  for poll in {1..100}; do
    if ! docker exec "${client_container}" sh -c 'kill -0 "$1" 2>/dev/null' sh "${runtime_pid}"; then
      runtime_pid=""
      rm -f -- "${work_dir}/client/runtime.pid"
      return 0
    fi
    sleep 0.1
  done
  die "isolated Mesh runtime did not stop"
}

assert_no_db_secret_leaks() {
  local secret path
  local -a secrets=(
    "${postgres_admin_password}" "${migrate_password}" "${import_password}"
    "${runtime_old_password}" "${runtime_new_password}"
  )
  local -a paths=(
    "${work_dir}/results" "${work_dir}/client/source-server.log"
    "${work_dir}/client/runtime-old.log" "${work_dir}/client/runtime-new.log"
    "${work_dir}/postgres.log" "${work_dir}/client-process.txt"
    "${work_dir}/client-inspect.txt"
  )
  for secret in "${secrets[@]}"; do
    [[ "${secret}" =~ ^[A-Za-z0-9_-]{43}$ ]] || die "disposable database credential lost canonical form"
    for path in "${paths[@]}"; do
      [[ -e "${path}" ]] || continue
      if grep -R -F -q -- "${secret}" "${path}"; then
        die "a disposable database password leaked into diagnostics"
      fi
    done
  done
  if grep -R -E -q 'postgres(ql)?://[^[:space:]]+:[^@[:space:]]+@' "${work_dir}/results" \
      "${work_dir}/client/source-server.log" "${work_dir}/client/runtime-old.log" \
      "${work_dir}/client/runtime-new.log" "${work_dir}/postgres.log" \
      "${work_dir}/client-process.txt" "${work_dir}/client-inspect.txt"; then
    die "a PostgreSQL DSN leaked into diagnostics"
  fi
}

if [[ "${keep_smoke}" != "0" && "${keep_smoke}" != "1" ]]; then
  die "KEEP_MESH_SMOKE must be 0 or 1"
fi
if (( BASH_VERSINFO[0] < 4 )); then
  skip "Bash 4 or newer is required"
fi
[[ "$(uname -s 2>/dev/null || true)" == "Linux" ]] || skip "this bounded OS-trust-store proof requires Linux"
for prerequisite in go python3 curl docker openssl mktemp chmod mkdir rm ps readlink sleep grep sha256sum; do
  command -v -- "${prerequisite}" >/dev/null 2>&1 || skip "required command is unavailable: ${prerequisite}"
done
[[ -x "${nebula_cert_source}" && -f "${nebula_cert_source}" && ! -L "${nebula_cert_source}" ]] || \
  skip "real /usr/local/bin/nebula-cert is unavailable"
"${nebula_cert_source}" -version 2>&1 | grep -Eq '1\.10\.3' || skip "exact nebula-cert 1.10.3 is required"
docker info >/dev/null 2>&1 || skip "Docker daemon access is unavailable"
docker image inspect "${postgres_image}" >/dev/null 2>&1 || skip "cached postgres:17-alpine image is unavailable"
docker image inspect "${client_image}" >/dev/null 2>&1 || skip "cached ubuntu:24.04 image is unavailable"

temporary_parent="${TMPDIR:-/tmp}"
[[ -d "${temporary_parent}" && ! -L "${temporary_parent}" ]] || skip "private temporary parent is unavailable"
work_parent="$(cd -- "${temporary_parent}" && pwd -P)"
work_dir="$(mktemp -d "${work_parent%/}/${resource_prefix}.XXXXXX")"
[[ -d "${work_dir}" && ! -L "${work_dir}" ]] || die "mktemp did not create a private workspace"
chmod 0700 "${work_dir}"
mkdir -- "${work_dir}/client" "${work_dir}/client/bin" "${work_dir}/client/source" \
  "${work_dir}/client-trust" "${work_dir}/local-ca" "${work_dir}/server-tls" \
  "${work_dir}/role-client" "${work_dir}/role-client/queries" "${work_dir}/results"
chmod 0700 "${work_dir}/client" "${work_dir}/client/bin" "${work_dir}/client/source" \
  "${work_dir}/server-tls" "${work_dir}/role-client" "${work_dir}/role-client/queries" "${work_dir}/results"
chmod 0755 "${work_dir}/client-trust" "${work_dir}/local-ca"

run_id="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(8))
PY
)"
[[ "${run_id}" =~ ^[0-9a-f]{16}$ ]] || die "could not generate a canonical run ID"
network_name="${resource_prefix}-${run_id}-network"
pgdata_volume="${resource_prefix}-${run_id}-pgdata"
tls_volume="${resource_prefix}-${run_id}-tls"
postgres_container="${resource_prefix}-${run_id}-postgres"
client_container="${resource_prefix}-${run_id}-client"
helper_container="${resource_prefix}-${run_id}-tls-init"
primary_host="mesh-postgres-primary-${run_id}.mesh-smoke.internal"
fallback_host="mesh-postgres-fallback-${run_id}.mesh-smoke.internal"
unavailable_host="mesh-postgres-unavailable-${run_id}.mesh-smoke.internal"
unverified_host="mesh-postgres-unverified-${run_id}.mesh-smoke.internal"

postgres_admin_password="$(random_bearer)"
migrate_password="$(random_bearer)"
import_password="$(random_bearer)"
runtime_old_password="$(random_bearer)"
runtime_new_password="$(random_bearer)"
[[ "${postgres_admin_password}" != "${migrate_password}" && "${migrate_password}" != "${import_password}" &&
   "${import_password}" != "${runtime_old_password}" && "${runtime_old_password}" != "${runtime_new_password}" ]] || \
  die "random role credentials collided"

cd -- "${repo_root}"
say "Building static clean-room Mesh executables"
CGO_ENABLED=0 go build -buildvcs=false -trimpath -o "${work_dir}/client/bin/mesh-server" ./cmd/mesh-server \
  >"${work_dir}/results/build-server.log" 2>&1
CGO_ENABLED=0 go build -buildvcs=false -trimpath -o "${work_dir}/client/bin/mesh-storage" ./cmd/mesh-storage \
  >"${work_dir}/results/build-storage.log" 2>&1
CGO_ENABLED=0 go build -buildvcs=false -trimpath -o "${work_dir}/client/bin/mesh-backup" ./cmd/mesh-backup \
  >"${work_dir}/results/build-backup.log" 2>&1
cp -- "${nebula_cert_source}" "${work_dir}/client/bin/nebula-cert"
chmod 0500 "${work_dir}/client/bin/"*
mesh_server="$(readlink -f -- "${work_dir}/client/bin/mesh-server")"
mesh_storage="$(readlink -f -- "${work_dir}/client/bin/mesh-storage")"
mesh_backup="$(readlink -f -- "${work_dir}/client/bin/mesh-backup")"

say "Creating one current control-v5 JSON source and authenticated backup"
source_port="$(pick_loopback_port)"
source_url="http://127.0.0.1:${source_port}"
: >"${work_dir}/client/source-server.log"
MESH_MASTER_KEY= MESH_ADMIN_TOKEN= NEBULA_CERT_BINARY="${work_dir}/client/bin/nebula-cert" \
  "${mesh_server}" --dev --listen "127.0.0.1:${source_port}" --data-dir "${work_dir}/client/source" \
  >>"${work_dir}/client/source-server.log" 2>&1 &
source_pid=$!
wait_for_url "${source_url}" "JSON source server"
admin_token="$(read_private_line "${work_dir}/client/source/admin.token")"
master_key="$(read_private_line "${work_dir}/client/source/master.key")"
[[ "${admin_token}" =~ ^[A-Za-z0-9_-]{43}$ && "${master_key}" =~ ^[A-Za-z0-9_-]{43}$ ]] || \
  die "development credentials were not canonical"
{
  printf 'silent\nshow-error\nfail\nconnect-timeout = 2\nmax-time = 60\n'
  printf 'header = "Authorization: Bearer %s"\n' "${admin_token}"
  printf 'header = "Content-Type: application/json"\nheader = "Accept: application/json"\n'
} >"${work_dir}/client/admin.curlrc"
chmod 0600 "${work_dir}/client/admin.curlrc"
printf '%s\n' '{"name":"roles-tls-source","cidr":"10.111.0.0/24"}' >"${work_dir}/client/source-network-request.json"
curl --silent --show-error --fail --noproxy '*' --config "${work_dir}/client/admin.curlrc" \
  --request POST --data-binary "@${work_dir}/client/source-network-request.json" \
  --output "${work_dir}/client/source-network.json" "${source_url}/api/v1/networks"
stop_child "${source_pid}" "${mesh_server}"
source_pid=""
"${mesh_backup}" keygen --output "${work_dir}/client/backup.key" \
  >"${work_dir}/results/backup-keygen.json" 2>"${work_dir}/results/backup-keygen.stderr"
MESH_MASTER_KEY="${master_key}" MESH_ADMIN_TOKEN="${admin_token}" \
  "${mesh_backup}" create --data-dir "${work_dir}/client/source" \
  --key-file "${work_dir}/client/backup.key" --output "${work_dir}/client/source.meshbackup" \
  >"${work_dir}/results/backup-create.json" 2>"${work_dir}/results/backup-create.stderr"
backup_id="$(json_scalar "${work_dir}/results/backup-create.json" backup_id)"
[[ "${backup_id}" =~ ^[0-9a-f]{32}$ ]] || die "backup ID was not canonical"
"${mesh_backup}" verify --key-file "${work_dir}/client/backup.key" \
  --archive "${work_dir}/client/source.meshbackup" \
  >"${work_dir}/results/backup-verify.json" 2>"${work_dir}/results/backup-verify.stderr"

say "Generating an ephemeral private CA and hostname-bound PostgreSQL server certificate"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${work_dir}/server-tls/ca.key" \
  >"${work_dir}/results/openssl-ca-key.stdout" 2>"${work_dir}/results/openssl-ca-key.stderr"
openssl req -x509 -new -sha256 -days 2 -key "${work_dir}/server-tls/ca.key" \
  -subj "/CN=Mesh PostgreSQL roles TLS smoke ${run_id}" -out "${work_dir}/server-tls/ca.crt" \
  >"${work_dir}/results/openssl-ca.stdout" 2>"${work_dir}/results/openssl-ca.stderr"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${work_dir}/server-tls/server.key" \
  >"${work_dir}/results/openssl-server-key.stdout" 2>"${work_dir}/results/openssl-server-key.stderr"
openssl req -new -sha256 -key "${work_dir}/server-tls/server.key" \
  -subj "/CN=${primary_host}" -out "${work_dir}/server-tls/server.csr" \
  >"${work_dir}/results/openssl-server-csr.stdout" 2>"${work_dir}/results/openssl-server-csr.stderr"
cat >"${work_dir}/server-tls/server.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${primary_host},DNS:${fallback_host}
EOF
openssl x509 -req -sha256 -days 2 -in "${work_dir}/server-tls/server.csr" \
  -CA "${work_dir}/server-tls/ca.crt" -CAkey "${work_dir}/server-tls/ca.key" -CAcreateserial \
  -extfile "${work_dir}/server-tls/server.ext" -out "${work_dir}/server-tls/server.crt" \
  >"${work_dir}/results/openssl-sign.stdout" 2>"${work_dir}/results/openssl-sign.stderr"
openssl verify -CAfile "${work_dir}/server-tls/ca.crt" "${work_dir}/server-tls/server.crt" \
  >"${work_dir}/results/openssl-verify.stdout" 2>"${work_dir}/results/openssl-verify.stderr"
openssl x509 -in "${work_dir}/server-tls/server.crt" -noout -checkhost "${primary_host}" >/dev/null
openssl x509 -in "${work_dir}/server-tls/server.crt" -noout -checkhost "${fallback_host}" >/dev/null
if openssl x509 -in "${work_dir}/server-tls/server.crt" -noout -checkhost "${unverified_host}" >/dev/null 2>&1; then
  die "server certificate unexpectedly covered the unverified hostname"
fi
cp -- "${work_dir}/server-tls/ca.crt" "${work_dir}/client-trust/ca-certificates.crt"
cp -- "${work_dir}/server-tls/ca.crt" "${work_dir}/local-ca/mesh-postgres-smoke-ca.crt"
chmod 0444 "${work_dir}/client-trust/ca-certificates.crt" "${work_dir}/local-ca/mesh-postgres-smoke-ca.crt"

cat >"${work_dir}/pg_hba.conf" <<'EOF'
local   all             mesh_admin                              trust
local   all             all                                     reject
hostnossl all           all             0.0.0.0/0               reject
hostnossl all           all             ::/0                    reject
hostssl all             all             0.0.0.0/0               scram-sha-256
hostssl all             all             ::/0                    scram-sha-256
EOF
chmod 0444 "${work_dir}/pg_hba.conf"
printf '%s\n' "${postgres_admin_password}" >"${work_dir}/postgres-admin-password"
chmod 0400 "${work_dir}/postgres-admin-password"

say "Creating exact labeled Docker network and volumes without image pulls"
network_id="$(docker network create \
  --label "io.mesh.smoke.instance=${run_id}" --label "io.mesh.smoke.kind=${smoke_kind}" \
  "${network_name}")"
network_created=1
network_matches || die "created Docker network identity did not match"
docker volume create --label "io.mesh.smoke.instance=${run_id}" --label "io.mesh.smoke.kind=${smoke_kind}" \
  --label 'io.mesh.smoke.role=pgdata' "${pgdata_volume}" >/dev/null
pgdata_created=1
volume_matches "${pgdata_volume}" pgdata || die "created pgdata volume labels did not match"
docker volume create --label "io.mesh.smoke.instance=${run_id}" --label "io.mesh.smoke.kind=${smoke_kind}" \
  --label 'io.mesh.smoke.role=tls' "${tls_volume}" >/dev/null
tls_created=1
volume_matches "${tls_volume}" tls || die "created TLS volume labels did not match"

say "Installing only the server certificate and key into the private PostgreSQL TLS volume"
helper_id="$(docker create --pull=never --name "${helper_container}" \
  --label "io.mesh.smoke.instance=${run_id}" --label "io.mesh.smoke.kind=${smoke_kind}" \
  --label 'io.mesh.smoke.role=tls-init' --network none --entrypoint /bin/sh \
  --mount "type=bind,src=${work_dir}/server-tls,dst=/source,readonly" \
  --mount "type=volume,src=${tls_volume},dst=/target" "${postgres_image}" \
  -c 'set -eu; cp /source/server.crt /target/server.crt; cp /source/server.key /target/server.key; chown postgres:postgres /target/server.crt /target/server.key; chmod 0600 /target/server.key; chmod 0644 /target/server.crt')"
helper_started=1
container_matches "${helper_container}" "${helper_id}" tls-init || die "TLS helper identity did not match"
docker start --attach "${helper_container}" >"${work_dir}/results/tls-init.stdout" 2>"${work_dir}/results/tls-init.stderr"
docker rm -- "${helper_container}" >/dev/null
helper_started=0
helper_id=""

cat >"${work_dir}/provision.sql" <<EOF
CREATE ROLE mesh_migrate LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${migrate_password}';
CREATE ROLE mesh_import LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${import_password}';
CREATE ROLE mesh_runtime LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${runtime_old_password}';
CREATE DATABASE mesh OWNER mesh_migrate TEMPLATE template0;
REVOKE ALL ON DATABASE mesh FROM PUBLIC;
GRANT CONNECT ON DATABASE mesh TO mesh_migrate, mesh_import, mesh_runtime;
EOF
chmod 0400 "${work_dir}/provision.sql"

say "Starting hostname-authenticated, hostssl-only PostgreSQL 17"
postgres_id="$(docker run --detach --pull=never --name "${postgres_container}" \
  --label "io.mesh.smoke.instance=${run_id}" --label "io.mesh.smoke.kind=${smoke_kind}" \
  --label 'io.mesh.smoke.role=postgres' --network "${network_name}" \
  --network-alias "${primary_host}" --network-alias "${fallback_host}" --network-alias "${unverified_host}" \
  --env POSTGRES_USER=mesh_admin --env POSTGRES_DB=postgres \
  --env POSTGRES_PASSWORD_FILE=/run/secrets/postgres-admin-password \
  --env POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256\ --auth-local=trust \
  --mount "type=bind,src=${work_dir}/postgres-admin-password,dst=/run/secrets/postgres-admin-password,readonly" \
  --mount "type=bind,src=${work_dir}/pg_hba.conf,dst=/etc/postgresql/mesh-pg_hba.conf,readonly" \
  --mount "type=bind,src=${work_dir}/role-client,dst=/role-client,readonly" \
  --mount "type=bind,src=${work_dir}/client-trust,dst=/etc/ssl/certs,readonly" \
  --mount "type=volume,src=${pgdata_volume},dst=/var/lib/postgresql/data" \
  --mount "type=volume,src=${tls_volume},dst=/var/lib/postgresql/mesh-tls,readonly" \
  "${postgres_image}" postgres \
  -c hba_file=/etc/postgresql/mesh-pg_hba.conf \
  -c ssl=on -c ssl_cert_file=/var/lib/postgresql/mesh-tls/server.crt \
  -c ssl_key_file=/var/lib/postgresql/mesh-tls/server.key \
  -c ssl_min_protocol_version=TLSv1.2 -c password_encryption=scram-sha-256 \
  -c log_connections=on -c log_disconnections=on -c log_hostname=off \
  -c 'log_line_prefix=%m [%p] %q%u@%d ' )"
postgres_started=1
container_matches "${postgres_container}" "${postgres_id}" postgres || die "PostgreSQL container identity did not match"
postgres_ready=0
for poll in {1..300}; do
  # The image briefly runs a Unix-socket-only bootstrap postmaster. Requiring
  # the final TCP listener prevents handing provisioning to that transient
  # process.
  if docker exec "${postgres_container}" pg_isready --quiet --host 127.0.0.1 --port 5432 --username mesh_admin --dbname postgres; then
    postgres_ready=1
    break
  fi
  sleep 0.1
done
[[ "${postgres_ready}" == "1" ]] || die "PostgreSQL did not become ready"
docker exec --interactive "${postgres_container}" psql --no-psqlrc --set ON_ERROR_STOP=1 \
  --username mesh_admin --dbname postgres <"${work_dir}/provision.sql" \
  >"${work_dir}/results/provision.stdout" 2>"${work_dir}/results/provision.stderr"

cat >"${work_dir}/role-client/.pgpass" <<EOF
${primary_host}:5432:mesh:mesh_migrate:${migrate_password}
${fallback_host}:5432:mesh:mesh_migrate:${migrate_password}
${primary_host}:5432:mesh:mesh_import:${import_password}
${fallback_host}:5432:mesh:mesh_import:${import_password}
${primary_host}:5432:mesh:mesh_runtime:${runtime_old_password}
${fallback_host}:5432:mesh:mesh_runtime:${runtime_old_password}
EOF
cat >"${work_dir}/role-client/.pg_service.conf" <<EOF
[mesh_migrate]
host=${primary_host}
port=5432
dbname=mesh
user=mesh_migrate
sslmode=verify-full
sslrootcert=system
target_session_attrs=read-write
connect_timeout=5

[mesh_import]
host=${primary_host}
port=5432
dbname=mesh
user=mesh_import
sslmode=verify-full
sslrootcert=system
target_session_attrs=read-write
connect_timeout=5

[mesh_runtime]
host=${fallback_host}
port=5432
dbname=mesh
user=mesh_runtime
sslmode=verify-full
sslrootcert=system
target_session_attrs=read-write
connect_timeout=5

[mesh_runtime_plaintext]
host=${fallback_host}
port=5432
dbname=mesh
user=mesh_runtime
sslmode=disable
target_session_attrs=read-write
connect_timeout=5
EOF
chmod 0600 "${work_dir}/role-client/.pgpass" "${work_dir}/role-client/.pg_service.conf"

dsn_suffix='sslmode=verify-full&sslrootcert=system&target_session_attrs=read-write&connect_timeout=3&pool_max_conns=4&pool_min_conns=1'
printf 'postgres://mesh_migrate:%s@%s:5432/mesh?%s\n' \
  "${migrate_password}" "${primary_host}" "${dsn_suffix}" >"${work_dir}/client/migrate.dsn"
printf 'postgres://mesh_import:%s@%s:5432/mesh?%s\n' \
  "${import_password}" "${primary_host}" "${dsn_suffix}" >"${work_dir}/client/import.dsn"
printf 'postgres://mesh_runtime:%s@%s:5432,%s:5432/mesh?%s\n' \
  "${runtime_old_password}" "${unavailable_host}" "${fallback_host}" "${dsn_suffix}" >"${work_dir}/client/runtime-old.dsn"
printf 'postgres://mesh_runtime:%s@%s:5432,%s:5432/mesh?%s\n' \
  "${runtime_new_password}" "${unavailable_host}" "${fallback_host}" "${dsn_suffix}" >"${work_dir}/client/runtime-new.dsn"
printf 'postgres://mesh_migrate:%s@%s:5432/mesh?%s\n' \
  "${migrate_password}" "${unverified_host}" "${dsn_suffix}" >"${work_dir}/client/unverified-host.dsn"
chmod 0600 "${work_dir}/client/"*.dsn

cat >"${work_dir}/client/start-runtime.sh" <<EOF
#!/bin/bash
set -Eeuo pipefail
umask 077
dsn_name="\${1:?dsn file name required}"
log_name="\${2:?log file name required}"
case "\${dsn_name}" in runtime-old.dsn|runtime-new.dsn) ;; *) exit 64 ;; esac
case "\${log_name}" in runtime-old.log|runtime-new.log) ;; *) exit 64 ;; esac
IFS= read -r MESH_MASTER_KEY <"${work_dir}/client/source/master.key"
IFS= read -r MESH_ADMIN_TOKEN <"${work_dir}/client/source/admin.token"
export MESH_MASTER_KEY MESH_ADMIN_TOKEN
export NEBULA_CERT_BINARY="${work_dir}/client/bin/nebula-cert"
printf '%s\n' "\$\$" >"${work_dir}/client/runtime.pid"
exec "${work_dir}/client/bin/mesh-server" \
  --storage-backend=postgres --postgres-dsn-file="${work_dir}/client/\${dsn_name}" \
  --listen 0.0.0.0:8080 --public-url "${public_origin}" \
  --tls-cert "${work_dir}/client/runtime-tls.crt" --tls-key "${work_dir}/client/runtime-tls.key" \
  >>"${work_dir}/client/\${log_name}" 2>&1
EOF
chmod 0500 "${work_dir}/client/start-runtime.sh"

# The HTTP proof port crosses the Docker namespace, so the Mesh listener uses
# its own unrelated disposable TLS identity. PostgreSQL trust still contains
# only the database CA above.
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
  -subj '/CN=mesh.roles-tls.invalid' \
  -addext 'subjectAltName=DNS:mesh.roles-tls.invalid,IP:127.0.0.1' \
  -keyout "${work_dir}/client/runtime-tls.key" -out "${work_dir}/client/runtime-tls.crt" \
  >"${work_dir}/results/openssl-runtime-tls.stdout" \
  2>"${work_dir}/results/openssl-runtime-tls.stderr"
chmod 0400 "${work_dir}/client/runtime-tls.key"
chmod 0444 "${work_dir}/client/runtime-tls.crt"

say "Starting isolated Ubuntu 24.04 Mesh client with only the ephemeral CA in its OS trust paths"
client_id="$(docker run --detach --pull=never --name "${client_container}" \
  --label "io.mesh.smoke.instance=${run_id}" --label "io.mesh.smoke.kind=${smoke_kind}" \
  --label 'io.mesh.smoke.role=client' --network "${network_name}" \
  --add-host "${unavailable_host}:127.0.0.2" --publish '127.0.0.1::8080' \
  --user 1000:1000 --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,noexec,size=67108864,mode=1777 \
  --mount "type=bind,src=${work_dir}/client,dst=${work_dir}/client" \
  --mount "type=bind,src=${work_dir}/client-trust,dst=/etc/ssl/certs,readonly" \
  --mount "type=bind,src=${work_dir}/local-ca,dst=/usr/local/share/ca-certificates,readonly" \
  "${client_image}" sleep infinity)"
client_started=1
container_matches "${client_container}" "${client_id}" client || die "Ubuntu client identity did not match"
port_mapping="$(docker port "${client_container}" 8080/tcp)"
[[ "${port_mapping}" =~ ^127\.0\.0\.1:([0-9]+)$ ]] || die "client port was not loopback-published"
client_port="${BASH_REMATCH[1]}"
client_url="https://127.0.0.1:${client_port}"
docker exec "${client_container}" sh -c \
  'test "$(find /etc/ssl/certs -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 1 && test -r /etc/ssl/certs/ca-certificates.crt && test -r /usr/local/share/ca-certificates/mesh-postgres-smoke-ca.crt'
docker exec "${client_container}" sh -c 'env | grep -E "^(PG|SSL_CERT_FILE=|SSL_CERT_DIR=)" >/dev/null && exit 1 || exit 0'

say "Rejecting a reachable PostgreSQL route whose hostname is absent from the certificate"
status=0
run_mesh_storage migrate --postgres-dsn-file "${work_dir}/client/unverified-host.dsn" \
  >"${work_dir}/results/unverified-host.stdout" 2>"${work_dir}/results/unverified-host.stderr" || status=$?
[[ "${status}" -ne 0 ]] || die "verify-full accepted an unverified PostgreSQL hostname"
grep -Fxq 'mesh-storage: ping PostgreSQL pool failed' "${work_dir}/results/unverified-host.stderr" || \
  die "hostname rejection did not remain a sanitized connection error"

say "Running migration as mesh_migrate over primary-host verify-full TLS"
run_mesh_storage migrate --postgres-dsn-file "${work_dir}/client/migrate.dsn" \
  >"${work_dir}/results/migrate.json" 2>"${work_dir}/results/migrate.stderr"
[[ "$(json_scalar "${work_dir}/results/migrate.json" status)" == "migrated" ]] || die "migration did not report success"

say "Proving base schema readiness permits transfer staging while import fails before any write"
rows_before_transfer="$(postgres_application_row_count | tr -d '[:space:]')"
[[ "${rows_before_transfer}" == "0" ]] || die "fresh migrated schema unexpectedly contained application rows"
status=0
run_mesh_storage import-backup --postgres-dsn-file "${work_dir}/client/migrate.dsn" \
  --backup-key-file "${work_dir}/client/backup.key" --backup-archive "${work_dir}/client/source.meshbackup" \
  --expect-backup-id "${backup_id}" >"${work_dir}/results/pre-transfer-import.stdout" \
  2>"${work_dir}/results/pre-transfer-import.stderr" || status=$?
[[ "${status}" -ne 0 ]] || die "import succeeded before the pgcrypto ownership/ACL ceremony"
grep -q 'operational pgcrypto function security invariant failed' \
  "${work_dir}/results/pre-transfer-import.stderr" || \
  die "pre-transfer import failed outside the operational function-security gate"
rows_after_transfer_rejection="$(postgres_application_row_count | tr -d '[:space:]')"
[[ "${rows_after_transfer_rejection}" == "${rows_before_transfer}" ]] || \
  die "pre-transfer import changed an application table"

# pgcrypto is a PostgreSQL trusted extension. Its extension object is owned by
# the role that runs CREATE EXTENSION, but its member functions are initially
# owned by the bootstrap superuser. Transfer just those dedicated-schema
# functions through the already-required cluster-administration channel so
# mesh_migrate can actually revoke and grant EXECUTE below. Without this step,
# PostgreSQL only emits warnings and PUBLIC retains its default EXECUTE access.
cat >"${work_dir}/own-extension-functions.sql" <<'EOF'
\connect mesh
DO $ownership$
DECLARE
  function_signature pg_catalog.regprocedure;
  transferred integer := 0;
BEGIN
  FOR function_signature IN
    SELECT p.oid::pg_catalog.regprocedure
    FROM pg_catalog.pg_proc AS p
    JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
    JOIN pg_catalog.pg_depend AS dependency
      ON dependency.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass
     AND dependency.objid = p.oid
     AND dependency.deptype = 'e'
    JOIN pg_catalog.pg_extension AS extension
      ON extension.oid = dependency.refobjid
     AND dependency.refclassid = 'pg_catalog.pg_extension'::pg_catalog.regclass
    WHERE n.nspname = 'mesh'
      AND p.prokind = 'f'
      AND extension.extname = 'pgcrypto'
    ORDER BY p.oid
  LOOP
    EXECUTE pg_catalog.format('ALTER FUNCTION %s OWNER TO mesh_migrate', function_signature);
    transferred := transferred + 1;
  END LOOP;
  IF transferred = 0 THEN
    RAISE EXCEPTION 'pgcrypto extension has no function members in schema mesh';
  END IF;
END
$ownership$;
EOF
chmod 0444 "${work_dir}/own-extension-functions.sql"
docker exec --interactive "${postgres_container}" psql --no-psqlrc --set ON_ERROR_STOP=1 \
  --username mesh_admin --dbname postgres <"${work_dir}/own-extension-functions.sql" \
  >"${work_dir}/results/own-extension-functions.stdout" \
  2>"${work_dir}/results/own-extension-functions.stderr"

cat >"${work_dir}/role-client/queries/grants.sql" <<'EOF'
REVOKE ALL ON SCHEMA mesh FROM PUBLIC, mesh_import, mesh_runtime;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA mesh FROM PUBLIC, mesh_import, mesh_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE mesh_migrate IN SCHEMA mesh REVOKE ALL ON TABLES FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA mesh FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE mesh_migrate IN SCHEMA mesh REVOKE ALL ON FUNCTIONS FROM PUBLIC;
GRANT USAGE ON SCHEMA mesh TO mesh_import, mesh_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA mesh TO mesh_import, mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh.digest(bytea, text) TO mesh_import, mesh_runtime;
GRANT INSERT ON mesh.mesh_write_receipts, mesh.mesh_state_documents,
  mesh.mesh_write_receipt_documents, mesh.mesh_import_metadata TO mesh_import;
GRANT INSERT ON mesh.mesh_write_receipts, mesh.mesh_write_receipt_documents TO mesh_runtime;
GRANT UPDATE (revision, document_bytes, document_sha256, last_write_receipt, updated_at)
  ON mesh.mesh_state_documents TO mesh_runtime;
EOF
chmod 0444 "${work_dir}/role-client/queries/grants.sql"
psql_as mesh_migrate /role-client/queries/grants.sql \
  "${work_dir}/results/grants.stdout" "${work_dir}/results/grants.stderr"

cat >"${work_dir}/acl-proof.sql" <<'EOF'
\connect mesh
DO $proof$
DECLARE
  role_name text;
BEGIN
  FOREACH role_name IN ARRAY ARRAY['mesh_migrate','mesh_import','mesh_runtime'] LOOP
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=role_name AND
      (rolsuper OR rolinherit OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR NOT rolcanlogin)) THEN
      RAISE EXCEPTION 'unsafe role attributes: %', role_name;
    END IF;
  END LOOP;
  IF NOT pg_catalog.has_schema_privilege('mesh_import','mesh','USAGE') OR
     pg_catalog.has_schema_privilege('mesh_import','mesh','CREATE') OR
     NOT pg_catalog.has_schema_privilege('mesh_runtime','mesh','USAGE') OR
     pg_catalog.has_schema_privilege('mesh_runtime','mesh','CREATE') THEN
    RAISE EXCEPTION 'schema role ACL mismatch';
  END IF;
  IF NOT pg_catalog.has_table_privilege('mesh_import','mesh.mesh_state_documents','SELECT') OR
     NOT pg_catalog.has_table_privilege('mesh_import','mesh.mesh_state_documents','INSERT') OR
     pg_catalog.has_table_privilege('mesh_import','mesh.mesh_state_documents','UPDATE') OR
     pg_catalog.has_table_privilege('mesh_import','mesh.mesh_state_documents','DELETE') OR
     pg_catalog.has_table_privilege('mesh_import','mesh.mesh_state_documents','TRUNCATE') OR
     pg_catalog.has_table_privilege('mesh_import','mesh.mesh_schema_migrations','INSERT') OR
     pg_catalog.has_table_privilege('mesh_import','mesh.mesh_schema_migrations','UPDATE') OR
     pg_catalog.has_table_privilege('mesh_import','mesh.mesh_schema_migrations','DELETE') THEN
    RAISE EXCEPTION 'import table ACL mismatch';
  END IF;
  IF NOT pg_catalog.has_table_privilege('mesh_runtime','mesh.mesh_write_receipts','SELECT') OR
     NOT pg_catalog.has_table_privilege('mesh_runtime','mesh.mesh_write_receipts','INSERT') OR
     NOT pg_catalog.has_table_privilege('mesh_runtime','mesh.mesh_write_receipt_documents','SELECT') OR
     NOT pg_catalog.has_table_privilege('mesh_runtime','mesh.mesh_write_receipt_documents','INSERT') OR
     pg_catalog.has_table_privilege('mesh_runtime','mesh.mesh_state_documents','INSERT') OR
     pg_catalog.has_table_privilege('mesh_runtime','mesh.mesh_state_documents','DELETE') OR
     pg_catalog.has_table_privilege('mesh_runtime','mesh.mesh_state_documents','TRUNCATE') OR
     pg_catalog.has_table_privilege('mesh_runtime','mesh.mesh_import_metadata','INSERT') OR
     pg_catalog.has_table_privilege('mesh_runtime','mesh.mesh_import_metadata','UPDATE') OR
     pg_catalog.has_table_privilege('mesh_runtime','mesh.mesh_import_metadata','DELETE') THEN
    RAISE EXCEPTION 'runtime table ACL mismatch';
  END IF;
  IF NOT pg_catalog.has_column_privilege('mesh_runtime','mesh.mesh_state_documents','revision','UPDATE') OR
     NOT pg_catalog.has_column_privilege('mesh_runtime','mesh.mesh_state_documents','document_bytes','UPDATE') OR
     NOT pg_catalog.has_column_privilege('mesh_runtime','mesh.mesh_state_documents','document_sha256','UPDATE') OR
     NOT pg_catalog.has_column_privilege('mesh_runtime','mesh.mesh_state_documents','last_write_receipt','UPDATE') OR
     NOT pg_catalog.has_column_privilege('mesh_runtime','mesh.mesh_state_documents','updated_at','UPDATE') OR
     pg_catalog.has_column_privilege('mesh_runtime','mesh.mesh_state_documents','document_key','UPDATE') THEN
    RAISE EXCEPTION 'runtime column ACL mismatch';
  END IF;
  IF NOT pg_catalog.has_function_privilege('mesh_import','mesh.digest(bytea,text)','EXECUTE') OR
     NOT pg_catalog.has_function_privilege('mesh_runtime','mesh.digest(bytea,text)','EXECUTE') THEN
    RAISE EXCEPTION 'digest execute ACL mismatch';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS p
    JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
    JOIN pg_catalog.pg_depend AS dependency
      ON dependency.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass
     AND dependency.objid = p.oid
     AND dependency.deptype = 'e'
    JOIN pg_catalog.pg_extension AS extension
      ON extension.oid = dependency.refobjid
     AND dependency.refclassid = 'pg_catalog.pg_extension'::pg_catalog.regclass
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = p.proowner,
    LATERAL pg_catalog.aclexplode(
      COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))
    ) AS acl
    WHERE n.nspname = 'mesh'
      AND extension.extname = 'pgcrypto'
      AND (owner.rolname <> 'mesh_migrate' OR
           (acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'))
  ) THEN
    RAISE EXCEPTION 'extension function ownership or PUBLIC ACL mismatch';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS p
    JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
    JOIN pg_catalog.pg_depend AS dependency
      ON dependency.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass
     AND dependency.objid = p.oid
     AND dependency.deptype = 'e'
    JOIN pg_catalog.pg_extension AS extension
      ON extension.oid = dependency.refobjid
     AND dependency.refclassid = 'pg_catalog.pg_extension'::pg_catalog.regclass,
    LATERAL pg_catalog.aclexplode(
      COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))
    ) AS acl
    WHERE n.nspname = 'mesh'
      AND extension.extname = 'pgcrypto'
      AND acl.grantee IN (
        (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'mesh_import'),
        (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'mesh_runtime')
      )
      AND p.oid <> 'mesh.digest(bytea,text)'::pg_catalog.regprocedure
  ) THEN
    RAISE EXCEPTION 'import/runtime can execute a non-digest pgcrypto function';
  END IF;
END
$proof$;
EOF
chmod 0444 "${work_dir}/acl-proof.sql"
docker exec --interactive "${postgres_container}" psql --no-psqlrc --set ON_ERROR_STOP=1 \
  --username mesh_admin --dbname postgres <"${work_dir}/acl-proof.sql" \
  >"${work_dir}/results/acl-proof.stdout" 2>"${work_dir}/results/acl-proof.stderr"

say "Importing and offline-verifying the authenticated archive as mesh_import"
run_mesh_storage import-backup --postgres-dsn-file "${work_dir}/client/import.dsn" \
  --backup-key-file "${work_dir}/client/backup.key" --backup-archive "${work_dir}/client/source.meshbackup" \
  --expect-backup-id "${backup_id}" >"${work_dir}/results/import.json" 2>"${work_dir}/results/import.stderr"
[[ "$(json_scalar "${work_dir}/results/import.json" status)" == "imported" ]] || die "import did not report success"
run_mesh_storage verify --postgres-dsn-file "${work_dir}/client/import.dsn" \
  --backup-key-file "${work_dir}/client/backup.key" --backup-archive "${work_dir}/client/source.meshbackup" \
  --expect-backup-id "${backup_id}" >"${work_dir}/results/verify.json" 2>"${work_dir}/results/verify.stderr"
[[ "$(json_scalar "${work_dir}/results/verify.json" status)" == "verified" ]] || die "offline verification did not report success"

cat >"${work_dir}/role-client/queries/import-select.sql" <<'EOF'
SELECT current_user, pg_catalog.count(*) FROM mesh.mesh_state_documents GROUP BY current_user;
EOF
cat >"${work_dir}/role-client/queries/import-update.sql" <<'EOF'
UPDATE mesh.mesh_state_documents SET revision=revision WHERE false;
EOF
cat >"${work_dir}/role-client/queries/import-delete.sql" <<'EOF'
DELETE FROM mesh.mesh_write_receipts WHERE false;
EOF
cat >"${work_dir}/role-client/queries/import-ddl.sql" <<'EOF'
CREATE TABLE mesh.import_forbidden_probe (id integer);
EOF
cat >"${work_dir}/role-client/queries/import-grant.sql" <<'EOF'
GRANT mesh_runtime TO mesh_import;
EOF
cat >"${work_dir}/role-client/queries/import-forbidden-insert.sql" <<'EOF'
INSERT INTO mesh.mesh_schema_migrations DEFAULT VALUES;
EOF
chmod 0444 "${work_dir}/role-client/queries/"*.sql
psql_as mesh_import /role-client/queries/import-select.sql \
  "${work_dir}/results/import-select.stdout" "${work_dir}/results/import-select.stderr"
grep -q 'mesh_import' "${work_dir}/results/import-select.stdout" || die "import SELECT did not use mesh_import"
expect_sql_denied mesh_import /role-client/queries/import-update.sql "import UPDATE"
expect_sql_denied mesh_import /role-client/queries/import-delete.sql "import DELETE"
expect_sql_denied mesh_import /role-client/queries/import-ddl.sql "import DDL"
expect_sql_denied mesh_import /role-client/queries/import-grant.sql "import privilege grant"
expect_sql_denied mesh_import /role-client/queries/import-forbidden-insert.sql "import migration-ledger INSERT"

say "Disabling mesh_import LOGIN after the verified cutover"
printf '%s\n' 'ALTER ROLE mesh_import NOLOGIN;' >"${work_dir}/disable-import.sql"
docker exec --interactive "${postgres_container}" psql --no-psqlrc --set ON_ERROR_STOP=1 \
  --username mesh_admin --dbname postgres <"${work_dir}/disable-import.sql" \
  >"${work_dir}/results/disable-import.stdout" 2>"${work_dir}/results/disable-import.stderr"
status=0
run_mesh_storage verify --postgres-dsn-file "${work_dir}/client/import.dsn" \
  --backup-key-file "${work_dir}/client/backup.key" --backup-archive "${work_dir}/client/source.meshbackup" \
  --expect-backup-id "${backup_id}" >"${work_dir}/results/import-disabled.stdout" \
  2>"${work_dir}/results/import-disabled.stderr" || status=$?
[[ "${status}" -ne 0 ]] || die "disabled import role still opened a new application connection"
grep -Fxq 'mesh-storage: ping PostgreSQL pool failed' "${work_dir}/results/import-disabled.stderr" || \
  die "disabled import login did not fail through the sanitized connection boundary"

say "Starting mesh-server as mesh_runtime through the unavailable-first, verified fallback route"
: >"${work_dir}/client/runtime-old.log"
start_runtime runtime-old.dsn runtime-old.log

say "Failing runtime readiness on pgcrypto ACL/ownership corruption and recovering after repair"
cat >"${work_dir}/role-client/queries/grant-runtime-crypt.sql" <<'EOF'
GRANT EXECUTE ON FUNCTION mesh.crypt(text, text) TO mesh_runtime;
EOF
cat >"${work_dir}/role-client/queries/revoke-runtime-crypt.sql" <<'EOF'
REVOKE ALL ON FUNCTION mesh.crypt(text, text) FROM mesh_runtime;
EOF
cat >"${work_dir}/role-client/queries/grant-public-digest.sql" <<'EOF'
GRANT EXECUTE ON FUNCTION mesh.digest(bytea, text) TO PUBLIC;
EOF
cat >"${work_dir}/role-client/queries/revoke-public-digest.sql" <<'EOF'
REVOKE ALL ON FUNCTION mesh.digest(bytea, text) FROM PUBLIC;
EOF
chmod 0444 "${work_dir}/role-client/queries/"{grant-runtime-crypt,revoke-runtime-crypt,grant-public-digest,revoke-public-digest}.sql
psql_as mesh_migrate /role-client/queries/grant-runtime-crypt.sql \
  "${work_dir}/results/grant-runtime-crypt.stdout" "${work_dir}/results/grant-runtime-crypt.stderr"
wait_for_readiness_status 503 "runtime with broad pgcrypto execution"
psql_as mesh_migrate /role-client/queries/revoke-runtime-crypt.sql \
  "${work_dir}/results/revoke-runtime-crypt.stdout" "${work_dir}/results/revoke-runtime-crypt.stderr"
wait_for_readiness_status 200 "runtime after broad execution repair"
psql_as mesh_migrate /role-client/queries/grant-public-digest.sql \
  "${work_dir}/results/grant-public-digest.stdout" "${work_dir}/results/grant-public-digest.stderr"
wait_for_readiness_status 503 "runtime with PUBLIC digest execution"
psql_as mesh_migrate /role-client/queries/revoke-public-digest.sql \
  "${work_dir}/results/revoke-public-digest.stdout" "${work_dir}/results/revoke-public-digest.stderr"
wait_for_readiness_status 200 "runtime after PUBLIC execution repair"
printf '%s\n' 'ALTER FUNCTION mesh.crypt(text, text) OWNER TO mesh_admin;' >"${work_dir}/corrupt-function-owner.sql"
docker exec --interactive "${postgres_container}" psql --no-psqlrc --set ON_ERROR_STOP=1 \
  --username mesh_admin --dbname mesh <"${work_dir}/corrupt-function-owner.sql" \
  >"${work_dir}/results/corrupt-function-owner.stdout" \
  2>"${work_dir}/results/corrupt-function-owner.stderr"
wait_for_readiness_status 503 "runtime with pgcrypto member owner drift"
printf '%s\n' 'ALTER FUNCTION mesh.crypt(text, text) OWNER TO mesh_migrate;' >"${work_dir}/repair-function-owner.sql"
docker exec --interactive "${postgres_container}" psql --no-psqlrc --set ON_ERROR_STOP=1 \
  --username mesh_admin --dbname mesh <"${work_dir}/repair-function-owner.sql" \
  >"${work_dir}/results/repair-function-owner.stdout" \
  2>"${work_dir}/results/repair-function-owner.stderr"
wait_for_readiness_status 200 "runtime after pgcrypto member owner repair"

printf '%s\n' '{"name":"roles-tls-runtime-old","cidr":"10.112.0.0/24"}' >"${work_dir}/client/runtime-old-request.json"
api_request POST /api/v1/networks "${work_dir}/results/runtime-old-network.json" \
  "${work_dir}/client/runtime-old-request.json"

cat >"${work_dir}/role-client/queries/runtime-select.sql" <<'EOF'
SELECT current_user, pg_catalog.count(*) FROM mesh.mesh_state_documents GROUP BY current_user;
EOF
cat >"${work_dir}/role-client/queries/runtime-insert-state.sql" <<'EOF'
INSERT INTO mesh.mesh_state_documents DEFAULT VALUES;
EOF
cat >"${work_dir}/role-client/queries/runtime-insert-import.sql" <<'EOF'
INSERT INTO mesh.mesh_import_metadata DEFAULT VALUES;
EOF
cat >"${work_dir}/role-client/queries/runtime-update-key.sql" <<'EOF'
UPDATE mesh.mesh_state_documents SET document_key=document_key WHERE false;
EOF
cat >"${work_dir}/role-client/queries/runtime-update-import.sql" <<'EOF'
UPDATE mesh.mesh_import_metadata SET importer_build=importer_build WHERE false;
EOF
cat >"${work_dir}/role-client/queries/runtime-delete.sql" <<'EOF'
DELETE FROM mesh.mesh_write_receipts WHERE false;
EOF
cat >"${work_dir}/role-client/queries/runtime-ddl.sql" <<'EOF'
CREATE TABLE mesh.runtime_forbidden_probe (id integer);
EOF
cat >"${work_dir}/role-client/queries/runtime-grant.sql" <<'EOF'
GRANT mesh_import TO mesh_runtime;
EOF
chmod 0444 "${work_dir}/role-client/queries/"runtime-*.sql
psql_as mesh_runtime /role-client/queries/runtime-select.sql \
  "${work_dir}/results/runtime-select.stdout" "${work_dir}/results/runtime-select.stderr"
grep -q 'mesh_runtime' "${work_dir}/results/runtime-select.stdout" || die "runtime SELECT did not use mesh_runtime"
expect_sql_denied mesh_runtime /role-client/queries/runtime-insert-state.sql "runtime state INSERT"
expect_sql_denied mesh_runtime /role-client/queries/runtime-insert-import.sql "runtime import-metadata INSERT"
expect_sql_denied mesh_runtime /role-client/queries/runtime-update-key.sql "runtime forbidden-column UPDATE"
expect_sql_denied mesh_runtime /role-client/queries/runtime-update-import.sql "runtime import-metadata UPDATE"
expect_sql_denied mesh_runtime /role-client/queries/runtime-delete.sql "runtime DELETE"
expect_sql_denied mesh_runtime /role-client/queries/runtime-ddl.sql "runtime DDL"
expect_sql_denied mesh_runtime /role-client/queries/runtime-grant.sql "runtime privilege grant"
status=0
psql_as mesh_runtime_plaintext /role-client/queries/runtime-select.sql \
  "${work_dir}/results/runtime-plaintext.stdout" "${work_dir}/results/runtime-plaintext.stderr" || status=$?
[[ "${status}" -ne 0 ]] || die "hostnossl unexpectedly allowed runtime authentication"
grep -Eiq 'no encryption|pg_hba.conf rejects connection' "${work_dir}/results/runtime-plaintext.stderr" || \
  die "plaintext probe failed for a reason other than hostnossl rejection"

docker exec "${client_container}" sh -c \
  'tr "\000" "\n" </proc/$1/cmdline; tr "\000" "\n" </proc/$1/environ' sh "${runtime_pid}" \
  >"${work_dir}/client-process.txt"
if grep -E '^PG[A-Z_]*=' "${work_dir}/client-process.txt" >/dev/null; then
  die "runtime inherited ambient PG settings"
fi
docker inspect --format '{{json .Config.Env}} {{json .Config.Cmd}}' "${client_container}" >"${work_dir}/client-inspect.txt"

say "Rotating the runtime password and rejecting the old credential on a fresh connection"
stop_runtime
cat >"${work_dir}/rotate-runtime.sql" <<EOF
ALTER ROLE mesh_runtime PASSWORD '${runtime_new_password}';
EOF
chmod 0400 "${work_dir}/rotate-runtime.sql"
docker exec --interactive "${postgres_container}" psql --no-psqlrc --set ON_ERROR_STOP=1 \
  --username mesh_admin --dbname postgres <"${work_dir}/rotate-runtime.sql" \
  >"${work_dir}/results/rotate-runtime.stdout" 2>"${work_dir}/results/rotate-runtime.stderr"
status=0
run_mesh_storage verify --postgres-dsn-file "${work_dir}/client/runtime-old.dsn" \
  --backup-key-file "${work_dir}/client/backup.key" --backup-archive "${work_dir}/client/source.meshbackup" \
  --expect-backup-id "${backup_id}" >"${work_dir}/results/runtime-old-rejected.stdout" \
  2>"${work_dir}/results/runtime-old-rejected.stderr" || status=$?
[[ "${status}" -ne 0 ]] || die "old runtime password remained valid for a fresh connection"
grep -Fxq 'mesh-storage: ping PostgreSQL pool failed' "${work_dir}/results/runtime-old-rejected.stderr" || \
  die "old runtime password rejection was not sanitized"

say "Restarting mesh-server with the new runtime password and proving a fresh write"
: >"${work_dir}/client/runtime-new.log"
start_runtime runtime-new.dsn runtime-new.log
docker exec "${client_container}" sh -c \
  'tr "\000" "\n" </proc/$1/cmdline; tr "\000" "\n" </proc/$1/environ' sh "${runtime_pid}" \
  >>"${work_dir}/client-process.txt"
if grep -E '^PG[A-Z_]*=' "${work_dir}/client-process.txt" >/dev/null; then
  die "rotated runtime inherited ambient PG settings"
fi
printf '%s\n' '{"name":"roles-tls-runtime-new","cidr":"10.113.0.0/24"}' >"${work_dir}/client/runtime-new-request.json"
api_request POST /api/v1/networks "${work_dir}/results/runtime-new-network.json" \
  "${work_dir}/client/runtime-new-request.json"
api_request GET /api/v1/networks "${work_dir}/results/runtime-networks.json"
python3 - "${work_dir}/results/runtime-networks.json" <<'PY'
import json, pathlib, sys
items = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
names = {item.get("name") for item in items}
expected = {"roles-tls-source", "roles-tls-runtime-old", "roles-tls-runtime-new"}
if names != expected:
    raise SystemExit(f"runtime inventory mismatch: {sorted(names)!r}")
PY
curl --silent --show-error --fail --noproxy '*' --connect-timeout 2 --max-time 5 \
  --insecure --output /dev/null "${client_url}/readyz"

docker logs "${postgres_container}" >"${work_dir}/postgres.log" 2>&1
for role in mesh_migrate mesh_import mesh_runtime; do
  grep -E "${role}@mesh .*SSL enabled \(protocol=TLSv1\.[23].*cipher=" "${work_dir}/postgres.log" >/dev/null || \
    die "PostgreSQL logs did not prove TLS for ${role}"
  grep -E "${role}@mesh .*method=scram-sha-256" "${work_dir}/postgres.log" >/dev/null || \
    die "PostgreSQL logs did not prove SCRAM for ${role}"
done

assert_no_db_secret_leaks
stop_runtime

say "PASS: isolated mesh_migrate, mesh_import, and mesh_runtime roles completed their exact permitted lifecycle"
say "PASS: import/runtime DDL, privilege, delete, forbidden insert/update, and forbidden-column probes were denied"
say "PASS: import wrote nothing before function hardening, and runtime readiness rejected member-owner, PUBLIC, and broad-role execution drift"
say "PASS: Ubuntu system roots authenticated primary and unavailable-first fallback hostnames; an uncovered hostname and plaintext were rejected"
say "PASS: import LOGIN was disabled, runtime password rotation rejected the old secret, and the new secret completed a fresh mutation"
say "PASS: Mesh arguments, ambient PG state, logs, and saved failure diagnostics contained no database DSN or password"
say "LIMIT: this is a bounded local Linux/Docker/PostgreSQL 17 mechanism proof, not a managed-service, HA, OS-distribution, load, or production deployment claim"
