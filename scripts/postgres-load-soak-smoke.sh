#!/usr/bin/env bash

# Bounded intended-workload/micro-soak proof for one PostgreSQL 17 primary and
# two real mesh-server replicas. This is intentionally a fixed-count local gate,
# not a maximum-document, long-retention, failover, TLS, or managed-service test.

set -Eeuo pipefail
umask 077

readonly skip_status=77
readonly script_name="${0##*/}"
readonly keep_smoke="${KEEP_MESH_SMOKE:-0}"
readonly postgres_image="postgres:17-alpine"
readonly nebula_cert="/usr/local/bin/nebula-cert"
readonly application_rss_budget=$((192 * 1024 * 1024))
readonly postgres_memory_budget=$((384 * 1024 * 1024))

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
load_driver=""
source_pid=""
replica_one_pid=""
replica_two_pid=""
driver_pid=""

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
backup_key=""
postgres_password=""
postgres_role=""
postgres_database=""
postgres_dsn=""

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
  local observed_name observed_instance observed_kind observed_id

  [[ "${container_started}" == "1" ]] || return 1
  [[ "${container_name}" =~ ^mesh-postgres-load-soak-smoke-[0-9a-f]{16}$ ]] || return 1
  [[ -z "${container_id}" || "${container_id}" =~ ^[0-9a-f]{64}$ ]] || return 1
  observed_name="$(docker inspect --format '{{.Name}}' "${container_name}" 2>/dev/null || true)"
  observed_instance="$(docker inspect --format '{{ index .Config.Labels "io.mesh.smoke.instance" }}' "${container_name}" 2>/dev/null || true)"
  observed_kind="$(docker inspect --format '{{ index .Config.Labels "io.mesh.smoke.kind" }}' "${container_name}" 2>/dev/null || true)"
  observed_id="$(docker inspect --format '{{.Id}}' "${container_name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "/${container_name}" && "${observed_instance}" == "${run_id}" &&
     "${observed_kind}" == "postgres-load-soak" && "${observed_id}" =~ ^[0-9a-f]{64}$ &&
     ( -z "${container_id}" || "${observed_id}" == "${container_id}" ) ]]
}

cleanup() {
  local status=$?
  local base parent

  trap - ERR EXIT HUP INT TERM
  set +e
  if [[ -n "${driver_pid}" ]]; then
    stop_child "${driver_pid}" "${load_driver}" || status=1
    driver_pid=""
  fi
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
  backup_key=""
  postgres_password=""
  postgres_role=""
  postgres_database=""
  postgres_dsn=""

  if [[ "${container_started}" == "1" ]]; then
    if container_matches_run; then
      if [[ "${keep_smoke}" == "1" ]]; then
        printf 'Kept exact disposable PostgreSQL container for debugging: %s\n' "${container_name}" >&2
      else
        docker rm --force -- "${container_name}" >/dev/null 2>&1 || status=1
        container_started=0
      fi
    elif docker inspect "${container_name}" >/dev/null 2>&1; then
      printf 'ERROR: refusing to remove a PostgreSQL container whose exact identity or labels changed\n' >&2
      status=1
    else
      container_started=0
    fi
  fi

  if [[ -n "${work_dir}" && -d "${work_dir}" ]]; then
    if [[ "${keep_smoke}" == "1" ]]; then
      printf 'Kept private PostgreSQL load workspace for debugging: %s\n' "${work_dir}" >&2
      printf 'It contains live disposable credentials; remove it with the retained container.\n' >&2
    else
      base="${work_dir##*/}"
      parent="$(cd -- "$(dirname -- "${work_dir}")" 2>/dev/null && pwd -P)"
      if [[ "${base}" == mesh-postgres-load-soak-smoke.* && -n "${work_parent}" && "${parent}" == "${work_parent}" && ! -L "${work_dir}" ]]; then
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
fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
        raise SystemExit(f"{label} is not an owner-controlled single-link regular file")
    if stat.S_IMODE(info.st_mode) & 0o077 or info.st_size < 2 or info.st_size > 16384:
        raise SystemExit(f"{label} has invalid metadata")
    raw = os.read(fd, info.st_size + 1)
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

wait_for_server() {
  local pid="$1"
  local url="$2"
  local label="$3"
  local poll

  for poll in {1..300}; do
    if curl --silent --show-error --fail --noproxy '*' --connect-timeout 1 --max-time 1 \
      --output /dev/null "${url}/healthz" 2>/dev/null && \
      curl --silent --show-error --fail --noproxy '*' --connect-timeout 1 --max-time 1 \
      --output /dev/null "${url}/readyz" 2>/dev/null; then
      return 0
    fi
    if ! kill -0 "${pid}" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  die "${label} did not reach liveness and application readiness"
}

start_source_server() {
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

process_rss_bytes() {
  local pid="$1"
  python3 - "${pid}" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path("/proc") / sys.argv[1] / "status"
try:
    text = path.read_text(encoding="utf-8")
except (FileNotFoundError, PermissionError):
    print(0)
    raise SystemExit
match = re.search(r"^VmRSS:\s+([0-9]+)\s+kB$", text, re.MULTILINE)
print(int(match.group(1)) * 1024 if match else 0)
PY
}

container_memory_bytes() {
  local usage
  usage="$(docker stats --no-stream --format '{{.MemUsage}}' "${container_name}" 2>/dev/null || true)"
  python3 - "${usage}" <<'PY'
import re
import sys

value = sys.argv[1].split("/", 1)[0].strip()
match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(B|KiB|MiB|GiB)", value)
if not match:
    print(0)
    raise SystemExit
scale = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3}[match.group(2)]
print(int(float(match.group(1)) * scale))
PY
}

record_process_arguments() {
  local output="$1"
  shift
  python3 - "${output}" "$@" <<'PY'
import pathlib
import sys

output = pathlib.Path(sys.argv[1])
lines = []
for raw_pid in sys.argv[2:]:
    raw = (pathlib.Path("/proc") / raw_pid / "cmdline").read_bytes()
    values = [part.decode("utf-8", "strict") for part in raw.split(b"\0") if part]
    lines.append(" ".join(values))
output.write_text("\n".join(lines) + "\n", encoding="utf-8")
output.chmod(0o600)
PY
}

validate_load_report() {
  python3 - "${work_dir}/load-report.json" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if report.get("schema") != "mesh-postgres-load-soak-v1" or report.get("passed") is not True:
    raise SystemExit("load report did not pass")
records = report.get("operations")
if not isinstance(records, list):
    raise SystemExit("load report has no operation ledger")
ids = [item.get("id") for item in records]
if len(ids) != len(set(ids)) or any(item.get("attempts") != 1 for item in records):
    raise SystemExit("load report repeated or retried a logical operation")
workload = [item for item in records if item.get("stage") in {"load", "soak"}]
if len(workload) != 364 or sum(bool(item.get("write")) for item in workload) != 256:
    raise SystemExit("load report workload cardinality is not exact")
if any(item.get("error") or item.get("status") != item.get("expected_status") for item in workload):
    raise SystemExit("load report contains an unsuccessful workload response")
delta = report.get("delta", {})
if (delta.get("control_revision"), delta.get("identity_revision"), delta.get("control_audit"), delta.get("identity_audit"), delta.get("receipt_headers"), delta.get("receipt_documents")) != (120, 136, 120, 136, 256, 256):
    raise SystemExit("load report state deltas are not exact")
PY
}

validate_secret_capture() {
  python3 - "${work_dir}/captured-secrets.tsv" <<'PY'
import collections
import pathlib
import sys

records = []
for line in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    fields = line.split("\t")
    if len(fields) != 2 or not fields[0] or not fields[1]:
        raise SystemExit("captured-secret record is invalid")
    records.append(tuple(fields))
counts = collections.Counter(kind for kind, _ in records)
expected = {"enrollment": 48, "reissue_enrollment": 48, "session_cookie": 68, "csrf_cookie": 68}
for kind, count in expected.items():
    if counts[kind] != count:
        raise SystemExit(f"captured {kind} count={counts[kind]}, want {count}")
generated = [value for kind, value in records if kind in expected]
if len(generated) != len(set(generated)):
    raise SystemExit("generated workload credentials were not globally unique")
PY
}

scan_diagnostics_for_secrets() {
  python3 - "${work_dir}/captured-secrets.tsv" "${work_dir}/diagnostic-files.list" <<'PY'
import pathlib
import sys

secret_file, list_file = map(pathlib.Path, sys.argv[1:])
secrets = []
for line in secret_file.read_text(encoding="utf-8").splitlines():
    kind, value = line.split("\t")
    secrets.append((kind, value.encode("utf-8")))
for raw_path in list_file.read_text(encoding="utf-8").splitlines():
    path = pathlib.Path(raw_path)
    data = path.read_bytes()
    for kind, value in secrets:
        if value in data:
            raise SystemExit(f"diagnostic secret leak: kind={kind} file={path.name}")
PY
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
for prerequisite in go python3 curl docker mktemp chmod find mkdir rm ps readlink sleep sort touch tr uname; do
  command -v -- "${prerequisite}" >/dev/null 2>&1 || skip "required command is unavailable: ${prerequisite}"
done
[[ -x "${nebula_cert}" && -f "${nebula_cert}" && ! -L "${nebula_cert}" ]] || skip "real /usr/local/bin/nebula-cert is unavailable"
nebula_output="$(${nebula_cert} -version 2>&1)" || skip "nebula-cert -version failed"
nebula_version_exact "${nebula_output}" || skip "exact nebula-cert 1.10.3 is required"
unset nebula_output
docker info >/dev/null 2>&1 || skip "Docker daemon access is unavailable"
docker image inspect "${postgres_image}" >/dev/null 2>&1 || skip "cached postgres:17-alpine image is unavailable"

for postgres_environment in \
  PGHOST PGPORT PGDATABASE PGUSER PGPASSWORD PGPASSFILE PGSERVICE PGSERVICEFILE \
  PGSSLMODE PGSSLCERT PGSSLKEY PGSSLROOTCERT PGSSLPASSWORD PGSSLSNI PGSSLNEGOTIATION \
  PGAPPNAME PGCONNECT_TIMEOUT PGTARGETSESSIONATTRS PGTZ PGOPTIONS PGMINPROTOCOLVERSION \
  PGMAXPROTOCOLVERSION PGCHANNELBINDING PGREQUIREAUTH; do
  unset "${postgres_environment}"
done
unset postgres_environment

temporary_parent="${TMPDIR:-/tmp}"
[[ -d "${temporary_parent}" && ! -L "${temporary_parent}" ]] || skip "private temporary directory parent is unavailable"
work_parent="$(cd -- "${temporary_parent}" && pwd -P)"
work_dir="$(mktemp -d "${work_parent%/}/mesh-postgres-load-soak-smoke.XXXXXX")"
[[ -d "${work_dir}" && ! -L "${work_dir}" ]] || die "mktemp did not create a real private workspace"
chmod 0700 "${work_dir}"
mkdir -- "${work_dir}/bin" "${work_dir}/source"
chmod 0700 "${work_dir}/bin" "${work_dir}/source"
touch "${work_dir}/source-server.log" "${work_dir}/replica-one.log" "${work_dir}/replica-two.log"
chmod 0600 "${work_dir}"/*.log
cd -- "${repo_root}"

say "Building isolated Mesh server, storage, backup, and load-gate executables"
go build -buildvcs=false -trimpath -o "${work_dir}/bin/mesh-server" ./cmd/mesh-server >"${work_dir}/build-server.log" 2>&1
go build -buildvcs=false -trimpath -o "${work_dir}/bin/mesh-storage" ./cmd/mesh-storage >"${work_dir}/build-storage.log" 2>&1
go build -buildvcs=false -trimpath -o "${work_dir}/bin/mesh-backup" ./cmd/mesh-backup >"${work_dir}/build-backup.log" 2>&1
go build -buildvcs=false -trimpath -o "${work_dir}/bin/mesh-postgres-load-smoke" ./cmd/mesh-postgres-load-smoke >"${work_dir}/build-load-driver.log" 2>&1
mesh_server="$(readlink -f -- "${work_dir}/bin/mesh-server")"
mesh_storage="$(readlink -f -- "${work_dir}/bin/mesh-storage")"
mesh_backup="$(readlink -f -- "${work_dir}/bin/mesh-backup")"
load_driver="$(readlink -f -- "${work_dir}/bin/mesh-postgres-load-smoke")"

source_port="$(pick_loopback_port)"
source_url="http://127.0.0.1:${source_port}"
[[ "${source_port}" =~ ^[0-9]+$ && "${source_port}" -ge 1024 && "${source_port}" -le 65535 ]] || die "kernel returned an invalid source port"

say "Creating one current control-v5 JSON source network and authenticated backup"
start_source_server
admin_token="$(read_private_line "${work_dir}/source/admin.token" "development administrator token")"
master_key="$(read_private_line "${work_dir}/source/master.key" "development master key")"
require_bearer "${admin_token}" "development administrator token"
require_bearer "${master_key}" "development master key"
{
  printf 'silent\nshow-error\nfail\nconnect-timeout = 2\nmax-time = 60\n'
  printf 'header = "Authorization: Bearer %s"\n' "${admin_token}"
  printf 'header = "Content-Type: application/json"\nheader = "Accept: application/json"\n'
} >"${work_dir}/admin.curlrc"
chmod 0600 "${work_dir}/admin.curlrc"
printf '%s\n' '{"name":"postgres-load-source","cidr":"10.94.0.0/24"}' >"${work_dir}/source-network-request.json"
api_request "${source_url}" POST /api/v1/networks "${work_dir}/source-network.json" "${work_dir}/source-network-request.json"
source_network_id="$(json_scalar "${work_dir}/source-network.json" id)"
require_record_id "${source_network_id}" "source network ID"
stop_child "${source_pid}" "${mesh_server}"
source_pid=""

"${mesh_backup}" keygen --output "${work_dir}/backup.key" >"${work_dir}/backup-keygen.json" 2>"${work_dir}/backup-keygen.stderr"
MESH_MASTER_KEY="${master_key}" MESH_ADMIN_TOKEN="${admin_token}" \
  "${mesh_backup}" create --data-dir "${work_dir}/source" --key-file "${work_dir}/backup.key" --output "${work_dir}/source.meshbackup" \
  >"${work_dir}/backup-create.json" 2>"${work_dir}/backup-create.stderr"
backup_id="$(json_scalar "${work_dir}/backup-create.json" backup_id)"
[[ "${backup_id}" =~ ^[0-9a-f]{32}$ ]] || die "backup command returned an invalid backup ID"
"${mesh_backup}" verify --key-file "${work_dir}/backup.key" --archive "${work_dir}/source.meshbackup" \
  >"${work_dir}/backup-verify.json" 2>"${work_dir}/backup-verify.stderr"
[[ "$(json_scalar "${work_dir}/backup-verify.json" backup_id)" == "${backup_id}" ]] || die "backup verification changed the backup ID"
backup_key="$(read_private_line "${work_dir}/backup.key" "backup key")"
require_bearer "${backup_key}" "backup key"

run_id="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(8))
PY
)"
[[ "${run_id}" =~ ^[0-9a-f]{16}$ ]] || die "could not generate a canonical run ID"
container_name="mesh-postgres-load-soak-smoke-${run_id}"
postgres_role="meshload_r_${run_id}"
postgres_database="meshload_d_${run_id}"
postgres_password="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
require_bearer "${postgres_password}" "disposable PostgreSQL password"
{
  printf 'POSTGRES_USER=%s\n' "${postgres_role}"
  printf 'POSTGRES_DB=%s\n' "${postgres_database}"
  printf 'POSTGRES_PASSWORD=%s\n' "${postgres_password}"
} >"${work_dir}/postgres.env"
chmod 0600 "${work_dir}/postgres.env"

say "Starting one exact 2-CPU/512-MiB disposable PostgreSQL 17 target"
docker run --detach \
  --name "${container_name}" \
  --label "io.mesh.smoke.instance=${run_id}" \
  --label 'io.mesh.smoke.kind=postgres-load-soak' \
  --memory 512m --memory-swap 512m --cpus 2 \
  --env-file "${work_dir}/postgres.env" \
  --publish '127.0.0.1::5432' \
  "${postgres_image}" \
  >"${work_dir}/container.id" 2>"${work_dir}/docker-run.stderr"
container_started=1
reported_container_id="$(tr -d '\r\n' <"${work_dir}/container.id")"
container_id="$(docker inspect --format '{{.Id}}' "${container_name}" 2>/dev/null || true)"
[[ "${reported_container_id}" =~ ^[0-9a-f]{64}$ && "${container_id}" == "${reported_container_id}" ]] || die "Docker did not return one exact container ID"
container_matches_run || die "disposable PostgreSQL identity did not match its exact labels and ID"
postgres_ready=0
for poll in {1..300}; do
  if docker exec "${container_name}" pg_isready --quiet --host 127.0.0.1 --port 5432 --username "${postgres_role}" --dbname "${postgres_database}" \
    >"${work_dir}/pg-isready.stdout" 2>"${work_dir}/pg-isready.stderr"; then
    postgres_ready=1
    break
  fi
  sleep 0.1
done
[[ "${postgres_ready}" == "1" ]] || die "disposable PostgreSQL did not become ready"
port_mapping="$(docker port "${container_name}" 5432/tcp 2>/dev/null)"
[[ "${port_mapping}" =~ ^127\.0\.0\.1:([0-9]+)$ ]] || die "Docker did not publish one PostgreSQL loopback port"
postgres_port="${BASH_REMATCH[1]}"
postgres_dsn="postgres://${postgres_role}:${postgres_password}@127.0.0.1:${postgres_port}/${postgres_database}?sslmode=disable&target_session_attrs=read-write&connect_timeout=5&pool_max_conns=8"
printf '%s\n' "${postgres_dsn}" >"${work_dir}/postgres.dsn"
chmod 0600 "${work_dir}/postgres.dsn"

say "Migrating, importing the authenticated backup, and verifying exact source bytes"
"${mesh_storage}" migrate --postgres-dsn-file "${work_dir}/postgres.dsn" --allow-local-plaintext-postgres \
  >"${work_dir}/storage-migrate.json" 2>"${work_dir}/storage-migrate.stderr"
[[ "$(json_scalar "${work_dir}/storage-migrate.json" status)" == "migrated" ]] || die "migration did not report success"
"${mesh_storage}" import-backup \
  --postgres-dsn-file "${work_dir}/postgres.dsn" \
  --backup-key-file "${work_dir}/backup.key" \
  --backup-archive "${work_dir}/source.meshbackup" \
  --expect-backup-id "${backup_id}" \
  --allow-local-plaintext-postgres \
  >"${work_dir}/storage-import.json" 2>"${work_dir}/storage-import.stderr"
[[ "$(json_scalar "${work_dir}/storage-import.json" status)" == "imported" ]] || die "import did not report success"
"${mesh_storage}" verify \
  --postgres-dsn-file "${work_dir}/postgres.dsn" \
  --backup-key-file "${work_dir}/backup.key" \
  --backup-archive "${work_dir}/source.meshbackup" \
  --expect-backup-id "${backup_id}" \
  --allow-local-plaintext-postgres \
  >"${work_dir}/storage-verify.json" 2>"${work_dir}/storage-verify.stderr"
[[ "$(json_scalar "${work_dir}/storage-verify.json" status)" == "verified" ]] || die "storage verification did not report success"

replica_one_port="$(pick_loopback_port)"
replica_two_port="$(pick_loopback_port)"
[[ "${replica_one_port}" =~ ^[0-9]+$ && "${replica_two_port}" =~ ^[0-9]+$ && "${replica_one_port}" != "${replica_two_port}" ]] || die "kernel returned invalid replica ports"
replica_one_url="http://127.0.0.1:${replica_one_port}"
replica_two_url="http://127.0.0.1:${replica_two_port}"
public_origin="${replica_one_url}"

say "Launching two independent real PostgreSQL-backed application replicas"
start_replica_one
start_replica_two

say "Running the fixed 256-write dependency load and 30-second paced mixed micro-soak"
"${load_driver}" run \
  --replica-one "${replica_one_url}" \
  --replica-two "${replica_two_url}" \
  --public-origin "${public_origin}" \
  --network-id "${source_network_id}" \
  --admin-token-file "${work_dir}/source/admin.token" \
  --postgres-dsn-file "${work_dir}/postgres.dsn" \
  --generated-secrets-file "${work_dir}/captured-secrets.tsv" \
  --report "${work_dir}/load-report.json" \
  >"${work_dir}/load-driver.stdout" 2>"${work_dir}/load-driver.stderr" &
driver_pid=$!
peak_replica_one=0
peak_replica_two=0
peak_postgres=0
resource_samples=0
while kill -0 "${driver_pid}" 2>/dev/null; do
  replica_one_rss="$(process_rss_bytes "${replica_one_pid}")"
  replica_two_rss="$(process_rss_bytes "${replica_two_pid}")"
  postgres_memory="$(container_memory_bytes)"
  (( replica_one_rss > peak_replica_one )) && peak_replica_one="${replica_one_rss}"
  (( replica_two_rss > peak_replica_two )) && peak_replica_two="${replica_two_rss}"
  (( postgres_memory > peak_postgres )) && peak_postgres="${postgres_memory}"
  resource_samples=$((resource_samples + 1))
  sleep 0.25
done
driver_status=0
wait "${driver_pid}" || driver_status=$?
driver_pid=""
if [[ "${driver_status}" != "0" ]]; then
  python3 "${repo_root}/scripts/postgres-load-failure-summary.py" \
    --report "${work_dir}/load-report.json" \
    --stderr "${work_dir}/load-driver.stderr" \
    --secret-file "${work_dir}/source/admin.token" \
    --secret-file "${work_dir}/source/master.key" \
    --secret-file "${work_dir}/backup.key" \
    --secret-file "${work_dir}/postgres.dsn" \
    --secret-file "${work_dir}/postgres.env" \
    --optional-secret-file "${work_dir}/captured-secrets.tsv" || true
  die "bounded PostgreSQL load driver failed"
fi
validate_load_report
(( resource_samples > 0 )) || die "resource sampler captured no observations"
(( peak_replica_one > 0 )) || die "replica one RSS sampler returned no valid value"
(( peak_replica_two > 0 )) || die "replica two RSS sampler returned no valid value"
(( peak_postgres > 0 )) || die "PostgreSQL memory sampler returned no valid value"
(( peak_replica_one <= application_rss_budget )) || die "replica one RSS exceeded 192 MiB"
(( peak_replica_two <= application_rss_budget )) || die "replica two RSS exceeded 192 MiB"
(( peak_postgres <= postgres_memory_budget )) || die "PostgreSQL memory exceeded 384 MiB"
python3 - \
  "${peak_replica_one}" "${peak_replica_two}" "${peak_postgres}" "${resource_samples}" \
  "${application_rss_budget}" "${postgres_memory_budget}" >"${work_dir}/resource-report.json" <<'PY'
import json
import sys

one, two, postgres, samples, app_budget, postgres_budget = map(int, sys.argv[1:])
json.dump({
    "schema": "mesh-postgres-load-resource-v1",
    "passed": 0 < one <= app_budget and 0 < two <= app_budget and 0 < postgres <= postgres_budget and samples > 0,
    "samples": samples,
    "replica_one_peak_rss_bytes": one,
    "replica_two_peak_rss_bytes": two,
    "postgres_peak_memory_bytes": postgres,
    "application_rss_budget_bytes": app_budget,
    "postgres_memory_budget_bytes": postgres_budget,
    "postgres_container_memory_cap_bytes": 512 * 1024 * 1024,
    "postgres_container_cpu_cap": 2,
}, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
PY
chmod 0600 "${work_dir}/resource-report.json"

say "Restarting both application replicas and proving exact state/receipt readiness"
record_process_arguments "${work_dir}/process-arguments-before-restart.txt" "${replica_one_pid}" "${replica_two_pid}"
stop_child "${replica_one_pid}" "${mesh_server}"
replica_one_pid=""
stop_child "${replica_two_pid}" "${mesh_server}"
replica_two_pid=""
start_replica_one
start_replica_two
"${load_driver}" verify \
  --replica-one "${replica_one_url}" \
  --replica-two "${replica_two_url}" \
  --public-origin "${public_origin}" \
  --network-id "${source_network_id}" \
  --admin-token-file "${work_dir}/source/admin.token" \
  --postgres-dsn-file "${work_dir}/postgres.dsn" \
  --generated-secrets-file "${work_dir}/captured-secrets.tsv" \
  --expected-report "${work_dir}/load-report.json" \
  --report "${work_dir}/restart-verification.json" \
  >"${work_dir}/restart-driver.stdout" 2>"${work_dir}/restart-driver.stderr"
python3 - "${work_dir}/restart-verification.json" <<'PY'
import json
import pathlib
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if value.get("schema") != "mesh-postgres-load-soak-v1-restart-verification" or value.get("passed") is not True:
    raise SystemExit("restart verification did not pass")
PY
record_process_arguments "${work_dir}/process-arguments-after-restart.txt" "${replica_one_pid}" "${replica_two_pid}"

say "Capturing and scanning private diagnostics for every workload and infrastructure credential"
{
  printf 'admin_token\t%s\n' "${admin_token}"
  printf 'master_key\t%s\n' "${master_key}"
  printf 'backup_key\t%s\n' "${backup_key}"
  printf 'postgres_password\t%s\n' "${postgres_password}"
  printf 'postgres_role\t%s\n' "${postgres_role}"
  printf 'postgres_database\t%s\n' "${postgres_database}"
  printf 'postgres_dsn\t%s\n' "${postgres_dsn}"
} >>"${work_dir}/captured-secrets.tsv"
chmod 0600 "${work_dir}/captured-secrets.tsv"
validate_secret_capture
docker logs "${container_name}" >"${work_dir}/postgres-container.log" 2>"${work_dir}/postgres-container-log.stderr"
find "${work_dir}" -maxdepth 1 -type f \
  \( -name '*.log' -o -name '*.stderr' -o -name '*.stdout' -o -name '*report.json' -o -name 'storage-*.json' -o -name 'backup-*.json' -o -name 'process-arguments-*.txt' \) \
  ! -name 'captured-secrets.tsv' -print | sort >"${work_dir}/diagnostic-files.list"
chmod 0600 "${work_dir}/diagnostic-files.list"
scan_diagnostics_for_secrets

say "PASS: 256 one-attempt mixed writes and 108 paced reads met explicit latency, throughput, WAL, database, vacuum, and resource budgets"
say "PASS: post-import deltas proved 120 control and 136 identity revisions/audits/receipts with exact terminal inventory and no PostgreSQL errors"
say "PASS: both real application replicas restarted ready with byte-identical documents, complete receipt history, and no diagnostic credential disclosure"
say "LIMIT: this bounded single-primary local micro-soak does not test failover, TLS/roles, maximum-size documents, long-duration receipt retention, or production autovacuum tuning"
