#!/usr/bin/env bash

# Exact-boundary PostgreSQL 17 proof for validator-created 64 MiB control and
# 8 MiB identity documents. This is intentionally separate from the fixed
# intended-workload micro-soak and is destructive only to exact labeled
# disposable resources created by this invocation.

set -Eeuo pipefail
umask 077

readonly skip_status=77
readonly postgres_image="postgres:17-alpine"
readonly smoke_kind="postgres-max-document"
readonly resource_prefix="mesh-postgres-max-document-smoke"
readonly application_rss_budget=$((1536 * 1024 * 1024))
readonly postgres_memory_budget=$((1024 * 1024 * 1024))
readonly postgres_disk_budget=$((512 * 1024 * 1024))
readonly database_budget=$((256 * 1024 * 1024))
readonly wal_budget=$((256 * 1024 * 1024))
readonly workspace_budget=$((2 * 1024 * 1024 * 1024))
readonly duration_budget=900
readonly keep_smoke="${KEEP_MESH_SMOKE:-0}"
readonly docker_command_timeout=10
readonly docker_probe_timeout=2
readonly docker_cleanup_timeout=3

# Put the entire inner gate under one wall-clock supervisor while leaving the
# inner shell in charge of exact PID/container/volume/workspace cleanup. The
# marker is valid only for the child of the exact compatible timeout binary;
# an inherited caller-controlled value cannot bypass the supervisor.
timeout_candidate="$(type -P timeout 2>/dev/null || true)"
[[ -n "${timeout_candidate}" ]] || { printf '%s\n' 'SKIP: required command is unavailable: timeout' >&2; exit 77; }
timeout_executable="$(readlink -f -- "${timeout_candidate}" 2>/dev/null || true)"
[[ -n "${timeout_executable}" && -f "${timeout_executable}" && -x "${timeout_executable}" ]] || { printf '%s\n' 'SKIP: timeout executable identity is invalid' >&2; exit 77; }
timeout_version="$("${timeout_executable}" --version 2>/dev/null || true)"
[[ "${timeout_version}" == *"GNU coreutils"* || "${timeout_version}" == *"uutils coreutils"* ]] || { printf '%s\n' 'SKIP: compatible GNU or uutils timeout is required' >&2; exit 77; }
timeout_probe_status=0
"${timeout_executable}" --signal=TERM --kill-after=1s 0.1s "${BASH}" --noprofile --norc -c 'trap "exit 0" TERM; while :; do :; done' >/dev/null 2>&1 || timeout_probe_status=$?
[[ "${timeout_probe_status}" == "124" ]] || { printf '%s\n' 'SKIP: timeout failed the required TERM/kill-after wall-clock probe' >&2; exit 77; }
unset timeout_candidate timeout_version timeout_probe_status

watchdog_valid=0
watchdog_marker="${MESH_POSTGRES_MAX_DOCUMENT_WATCHDOG:-}"
if [[ "${watchdog_marker}" =~ ^armed-v2:([0-9]+):(.+)$ ]]; then
  watchdog_parent_pid="${BASH_REMATCH[1]}"
  watchdog_parent_executable="${BASH_REMATCH[2]}"
  observed_watchdog_executable="$(readlink -f -- "/proc/${PPID}/exe" 2>/dev/null || true)"
  if [[ "${watchdog_parent_pid}" == "${PPID}" && "${watchdog_parent_executable}" == "${timeout_executable}" && "${observed_watchdog_executable}" == "${timeout_executable}" ]]; then
    watchdog_valid=1
  fi
fi
if [[ "${watchdog_valid}" != "1" ]]; then
  export MESH_POSTGRES_MAX_DOCUMENT_WATCHDOG="armed-v2:${BASHPID}:${timeout_executable}"
  exec "${timeout_executable}" --signal=TERM --kill-after=30s "${duration_budget}s" "$0" "$@"
fi
unset MESH_POSTGRES_MAX_DOCUMENT_WATCHDOG watchdog_valid watchdog_marker watchdog_parent_pid watchdog_parent_executable observed_watchdog_executable
readonly timeout_executable
(( $# == 0 )) || { printf '%s\n' 'ERROR: postgres maximum-document smoke accepts no arguments' >&2; exit 1; }

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
work_parent=""
work_dir=""
run_id=""
resource_id=""
container_name=""
container_id=""
postgres_image_id=""
volume_name=""
volume_created=0
container_started=0
server_pid=""
server_executable=""
active_pid=""
active_executable=""
peak_process_rss=0
peak_postgres_memory=0
resource_samples=0
started_seconds="${SECONDS}"

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
skip() { printf 'SKIP: %s\n' "$*" >&2; exit "${skip_status}"; }

run_bounded() {
  local seconds="$1"
  shift
  "${timeout_executable}" --signal=TERM --kill-after=1s "${seconds}s" "$@"
}

docker_command() { run_bounded "${docker_command_timeout}" docker "$@"; }
docker_probe() { run_bounded "${docker_probe_timeout}" docker "$@"; }
docker_cleanup() { run_bounded "${docker_cleanup_timeout}" docker "$@"; }

json_scalar() {
  python3 - "$1" "$2" <<'PY'
import json
import pathlib
import sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
for part in sys.argv[2].split("."):
    value = value[part]
if isinstance(value, bool):
    print("true" if value else "false")
elif isinstance(value, (str, int)):
    print(value)
else:
    raise SystemExit("requested JSON value is not scalar")
PY
}

read_private_line() {
  python3 - "$1" <<'PY'
import os
import pathlib
import stat
import sys
path = pathlib.Path(sys.argv[1])
info = path.lstat()
if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) not in (0o400, 0o600) or info.st_uid != os.geteuid() or info.st_nlink != 1:
    raise SystemExit("private file metadata is invalid")
raw = path.read_bytes()
if not raw.endswith(b"\n") or raw.count(b"\n") != 1 or b"\r" in raw:
    raise SystemExit("private file is not one canonical line")
print(raw[:-1].decode("ascii", "strict"))
PY
}

pick_loopback_port() {
  python3 - <<'PY'
import socket
sock = socket.socket()
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
}

valid_child_pid() {
  local pid="$1" expected="$2" parent executable
  [[ "${pid}" =~ ^[0-9]+$ && "${pid}" -gt 1 ]] || return 1
  kill -0 "${pid}" 2>/dev/null || return 1
  parent="$(ps -o ppid= -p "${pid}" 2>/dev/null | tr -d '[:space:]')"
  executable="$(readlink -f -- "/proc/${pid}/exe" 2>/dev/null || true)"
  [[ "${parent}" == "$$" && "${executable}" == "${expected}" ]]
}

stop_child() {
  local pid="$1" expected="$2" attempt
  [[ -n "${pid}" ]] || return 0
  if ! kill -0 "${pid}" 2>/dev/null; then
    wait "${pid}" 2>/dev/null || true
    return 0
  fi
  valid_child_pid "${pid}" "${expected}" || { printf 'ERROR: refusing to signal unverified PID %s\n' "${pid}" >&2; return 1; }
  kill -TERM "${pid}" 2>/dev/null || true
  for attempt in {1..50}; do
    kill -0 "${pid}" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "${pid}" 2>/dev/null; then
    valid_child_pid "${pid}" "${expected}" || return 1
    kill -KILL "${pid}" 2>/dev/null || true
  fi
  wait "${pid}" 2>/dev/null || true
}

container_matches() {
  local observed observed_id observed_name observed_kind observed_instance observed_role observed_image
  [[ "${container_started}" == "1" && "${container_name}" == "${resource_prefix}-${run_id}" && "${container_id}" =~ ^[0-9a-f]{64}$ && "${postgres_image_id}" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  observed="$(docker_probe inspect --format '{{.Id}}|{{.Name}}|{{index .Config.Labels "io.mesh.smoke.kind"}}|{{index .Config.Labels "io.mesh.smoke.instance"}}|{{index .Config.Labels "io.mesh.smoke.role"}}|{{.Image}}' "${container_id}" 2>/dev/null || true)"
  IFS='|' read -r observed_id observed_name observed_kind observed_instance observed_role observed_image <<<"${observed}"
  observed_name="${observed_name#/}"
  [[ "${observed_id}" == "${container_id}" && "${observed_name}" == "${container_name}" && "${observed_kind}" == "${smoke_kind}" && "${observed_instance}" == "${resource_id}" && "${observed_role}" == "postgres" && "${observed_image}" == "${postgres_image_id}" ]]
}

volume_matches() {
  local observed observed_name observed_kind observed_instance observed_role
  [[ "${volume_created}" == "1" && "${volume_name}" == "${resource_prefix}-${run_id}-pgdata" ]] || return 1
  observed="$(docker_probe volume inspect --format '{{.Name}}|{{index .Labels "io.mesh.smoke.kind"}}|{{index .Labels "io.mesh.smoke.instance"}}|{{index .Labels "io.mesh.smoke.role"}}' "${volume_name}" 2>/dev/null || true)"
  IFS='|' read -r observed_name observed_kind observed_instance observed_role <<<"${observed}"
  [[ "${observed_name}" == "${volume_name}" && "${observed_kind}" == "${smoke_kind}" && "${observed_instance}" == "${resource_id}" && "${observed_role}" == "pgdata" ]]
}

process_rss_bytes() {
  python3 - "$1" <<'PY'
import pathlib
import re
import sys
try:
    text = (pathlib.Path("/proc") / sys.argv[1] / "status").read_text(encoding="utf-8")
except (FileNotFoundError, PermissionError):
    print(0)
    raise SystemExit
match = re.search(r"^VmRSS:\s+([0-9]+)\s+kB$", text, re.MULTILINE)
print(int(match.group(1)) * 1024 if match else 0)
PY
}

process_hwm_bytes() {
  python3 - "$1" <<'PY'
import pathlib
import re
import sys
text = (pathlib.Path("/proc") / sys.argv[1] / "status").read_text(encoding="utf-8")
match = re.search(r"^VmHWM:\s+([0-9]+)\s+kB$", text, re.MULTILINE)
print(int(match.group(1)) * 1024 if match else 0)
PY
}

container_memory_bytes() {
  local usage
  usage="$(docker_probe stats --no-stream --format '{{.MemUsage}}' "${container_id}" 2>/dev/null || true)"
  python3 - "${usage}" <<'PY'
import re
import sys
value = sys.argv[1].split("/", 1)[0].strip()
match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(B|KiB|MiB|GiB)", value)
if not match:
    print(0)
    raise SystemExit
scales = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3}
print(int(float(match.group(1)) * scales[match.group(2)]))
PY
}

workspace_size_bytes() {
  local value
  value="$(du -sb -- "${work_dir}" | tr '\t' ' ' | sed 's/ .*//')"
  [[ "${value}" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "${value}"
}

sample_process() {
  local pid="$1" expected="$2" status=0 rss server_rss postgres_memory workspace_sample verified=0 attempt
  active_pid="${pid}"
  active_executable="${expected}"
  for attempt in {1..100}; do
    if valid_child_pid "${pid}" "${expected}"; then
      verified=1
      break
    fi
    kill -0 "${pid}" 2>/dev/null || break
    sleep 0.01
  done
  if [[ "${verified}" != "1" ]]; then
    wait "${pid}" || status=$?
    active_pid=""
    active_executable=""
    (( status == 0 )) && status=1
    return "${status}"
  fi
  while kill -0 "${pid}" 2>/dev/null; do
    rss="$(process_rss_bytes "${pid}")"
    (( rss > peak_process_rss )) && peak_process_rss="${rss}"
    if (( rss > application_rss_budget )); then
      printf 'ERROR: measured application RSS exceeded 1.5 GiB for PID %s\n' "${pid}" >&2
      stop_child "${pid}" "${expected}" || true
      active_pid=""
      active_executable=""
      return 1
    fi
    if [[ -n "${server_pid}" ]] && kill -0 "${server_pid}" 2>/dev/null; then
      server_rss="$(process_rss_bytes "${server_pid}")"
      (( server_rss > peak_process_rss )) && peak_process_rss="${server_rss}"
      if (( server_rss > application_rss_budget )); then
        printf 'ERROR: measured server RSS exceeded 1.5 GiB for PID %s\n' "${server_pid}" >&2
        stop_child "${pid}" "${expected}" || true
        active_pid=""
        active_executable=""
        return 1
      fi
    fi
    if [[ "${container_started}" == "1" ]]; then
      postgres_memory="$(container_memory_bytes)"
      (( postgres_memory > peak_postgres_memory )) && peak_postgres_memory="${postgres_memory}"
      if (( postgres_memory > postgres_memory_budget )); then
        printf '%s\n' 'ERROR: measured PostgreSQL memory exceeded 1 GiB' >&2
        stop_child "${pid}" "${expected}" || true
        active_pid=""
        active_executable=""
        return 1
      fi
    fi
    resource_samples=$((resource_samples + 1))
    if (( resource_samples % 10 == 0 )); then
      workspace_sample="$(workspace_size_bytes)"
      if (( workspace_sample > workspace_budget )); then
        printf '%s\n' 'ERROR: measured maximum-document workspace exceeded 2 GiB' >&2
        stop_child "${pid}" "${expected}" || true
        active_pid=""
        active_executable=""
        return 1
      fi
    fi
    sleep 0.1
  done
  wait "${pid}" || status=$?
  active_pid=""
  active_executable=""
  return "${status}"
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "${active_pid}" ]]; then
    stop_child "${active_pid}" "${active_executable}" || status=1
    active_pid=""
    active_executable=""
  fi
  if [[ -n "${server_pid}" ]]; then
    stop_child "${server_pid}" "${server_executable}" || status=1
    server_pid=""
  fi
  if [[ "${container_started}" == "1" ]]; then
    if container_matches; then
      docker_cleanup rm --force --volumes "${container_id}" >/dev/null 2>&1 || status=1
    else
      printf 'ERROR: refusing to remove PostgreSQL container with mismatched identity\n' >&2
      status=1
    fi
    container_started=0
  fi
  if [[ "${volume_created}" == "1" ]]; then
    if volume_matches; then
      docker_cleanup volume rm "${volume_name}" >/dev/null 2>&1 || status=1
    else
      printf 'ERROR: refusing to remove PostgreSQL volume with mismatched identity\n' >&2
      status=1
    fi
    volume_created=0
  fi
  if [[ -n "${work_dir}" && -n "${work_parent}" ]]; then
    local parent base
    parent="$(dirname -- "${work_dir}")"
    base="$(basename -- "${work_dir}")"
    if [[ "${parent}" == "${work_parent}" && "${base}" == ${resource_prefix}.* && -d "${work_dir}" && ! -L "${work_dir}" ]]; then
      if [[ "${keep_smoke}" == "1" ]]; then
        printf 'WARNING: retained private smoke workspace %s; it contains disposable credentials\n' "${work_dir}" >&2
      else
        rm -rf -- "${work_dir}" || status=1
      fi
    else
      printf 'ERROR: refusing to remove unverified smoke workspace %s\n' "${work_dir}" >&2
      status=1
    fi
  fi
  exit "${status}"
}
trap 'exit 130' INT
trap 'exit 143' TERM
trap cleanup EXIT

if [[ "${keep_smoke}" != "0" && "${keep_smoke}" != "1" ]]; then
  die "KEEP_MESH_SMOKE must be 0 or 1"
fi
(( BASH_VERSINFO[0] >= 4 )) || skip "Bash 4 or newer is required"
[[ "$(uname -s 2>/dev/null || true)" == "Linux" ]] || skip "this secure import gate requires Linux"
for prerequisite in go python3 curl docker mktemp chmod find mkdir ps readlink sleep sort tr du sed sha256sum; do
  command -v -- "${prerequisite}" >/dev/null 2>&1 || skip "required command is unavailable: ${prerequisite}"
done
docker_command info >/dev/null 2>&1 || skip "Docker daemon access is unavailable"
postgres_image_id="$(docker_command image inspect --format '{{.Id}}' "${postgres_image}" 2>/dev/null || true)"
[[ "${postgres_image_id}" =~ ^sha256:[0-9a-f]{64}$ ]] || skip "cached ${postgres_image} image has no exact content identity"
[[ -x /usr/local/bin/nebula-cert && -f /usr/local/bin/nebula-cert && ! -L /usr/local/bin/nebula-cert ]] || skip "real /usr/local/bin/nebula-cert is unavailable"

for postgres_environment in PGHOST PGPORT PGDATABASE PGUSER PGPASSWORD PGPASSFILE PGSERVICE PGSERVICEFILE PGSSLMODE PGSSLCERT PGSSLKEY PGSSLROOTCERT PGSSLPASSWORD PGSSNI PGAPPNAME PGCONNECT_TIMEOUT PGTARGETSESSIONATTRS PGTZ PGOPTIONS PGCHANNELBINDING PGREQUIREAUTH; do
  unset "${postgres_environment}"
done
unset postgres_environment

temporary_parent="${TMPDIR:-/tmp}"
[[ -d "${temporary_parent}" && ! -L "${temporary_parent}" ]] || skip "private temporary directory parent is unavailable"
work_parent="$(cd -- "${temporary_parent}" && pwd -P)"
work_dir="$(mktemp -d "${work_parent%/}/${resource_prefix}.XXXXXX")"
[[ -d "${work_dir}" && ! -L "${work_dir}" ]] || die "mktemp did not create a real workspace"
chmod 0700 "${work_dir}"
mkdir -- "${work_dir}/bin" "${work_dir}/fixture" "${work_dir}/results" "${work_dir}/diagnostics"
chmod 0700 "${work_dir}/bin" "${work_dir}/fixture" "${work_dir}/results" "${work_dir}/diagnostics"
printf '%s\n' "${postgres_image_id}" >"${work_dir}/results/postgres-image.id"
cd -- "${repo_root}"

say "Running tagged static tests before allocating maximum-size documents or Docker resources"
go test -buildvcs=false -tags postgresmaxdocgate -count=1 \
  ./internal/control ./internal/identity ./internal/backup ./internal/backupio \
  ./internal/postgresstore ./internal/postgresmaxdocgate ./cmd/mesh-storage \
  >"${work_dir}/diagnostics/static-tests.log" 2>&1

say "Building isolated release binaries and the tagged test-only maximum-document driver"
CGO_ENABLED=0 go build -buildvcs=false -trimpath -o "${work_dir}/bin/mesh-server" ./cmd/mesh-server >"${work_dir}/diagnostics/build-server.log" 2>&1
CGO_ENABLED=0 go build -buildvcs=false -trimpath -o "${work_dir}/bin/mesh-storage" ./cmd/mesh-storage >"${work_dir}/diagnostics/build-storage.log" 2>&1
CGO_ENABLED=0 go build -buildvcs=false -trimpath -o "${work_dir}/bin/mesh-backup" ./cmd/mesh-backup >"${work_dir}/diagnostics/build-backup.log" 2>&1
CGO_ENABLED=0 go build -buildvcs=false -trimpath -tags postgresmaxdocgate -o "${work_dir}/bin/mesh-postgres-max-document-smoke" ./cmd/mesh-postgres-max-document-smoke >"${work_dir}/diagnostics/build-driver.log" 2>&1
mesh_server="$(readlink -f -- "${work_dir}/bin/mesh-server")"
mesh_storage="$(readlink -f -- "${work_dir}/bin/mesh-storage")"
mesh_backup="$(readlink -f -- "${work_dir}/bin/mesh-backup")"
max_driver="$(readlink -f -- "${work_dir}/bin/mesh-postgres-max-document-smoke")"
server_executable="${mesh_server}"

say "Generating and fully validating production-shaped canonical state plus exact JSON boundaries"
"${max_driver}" generate --output-dir "${work_dir}/fixture" >"${work_dir}/results/fixture.json" 2>"${work_dir}/diagnostics/generate.stderr" &
generate_pid=$!
sample_process "${generate_pid}" "${max_driver}" || die "maximum-document fixture generation failed"
python3 - "${work_dir}/fixture/fixture-metadata.json" <<'PY'
import hashlib
import json
import pathlib
import sys
metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert metadata["schema"] == "mesh-postgres-maximum-document-v1"
assert 62 * 1024**2 <= metadata["control"]["canonical_bytes"] <= 63 * 1024**2
assert metadata["control"]["exact_bytes"] == 64 * 1024**2
assert metadata["control"]["network_count"] == 1
assert metadata["control"]["network_cidr"] == "10.240.0.0/16"
assert metadata["control"]["group_count"] == 64
assert metadata["control"]["inbound_rule_count"] == 128
assert metadata["control"]["outbound_rule_count"] == 128
assert 7 * 1024**2 <= metadata["identity"]["canonical_bytes"] <= int(7.5 * 1024**2)
assert metadata["identity"]["exact_bytes"] == 8 * 1024**2
assert 0 < metadata["identity"]["oidc_claims_bytes"] <= 64 * 1024
assert metadata["identity"]["oidc_group_count"] == 64
assert metadata["identity"]["login_attempt_count"] == 1
assert metadata["control"]["node_count"] == metadata["control"]["enrollment_count"]
assert metadata["control"]["audit_count"] == metadata["control"]["node_count"] + 4
assert metadata["identity"]["audit_count"] == metadata["identity"]["session_count"]
for domain in ("control", "identity"):
    path = pathlib.Path(metadata["paths"][domain + "_state"])
    body = path.read_bytes()
    assert len(body) == metadata[domain]["exact_bytes"]
    assert hashlib.sha256(body).hexdigest() == metadata[domain]["sha256"]
    assert body[-1:] == b" "
PY
control_canonical_bytes="$(json_scalar "${work_dir}/fixture/fixture-metadata.json" control.canonical_bytes)"
control_exact_bytes="$(json_scalar "${work_dir}/fixture/fixture-metadata.json" control.exact_bytes)"
control_padding_bytes="$(json_scalar "${work_dir}/fixture/fixture-metadata.json" control.padding_bytes)"
control_node_count="$(json_scalar "${work_dir}/fixture/fixture-metadata.json" control.node_count)"
control_sha256="$(json_scalar "${work_dir}/fixture/fixture-metadata.json" control.sha256)"
identity_canonical_bytes="$(json_scalar "${work_dir}/fixture/fixture-metadata.json" identity.canonical_bytes)"
identity_exact_bytes="$(json_scalar "${work_dir}/fixture/fixture-metadata.json" identity.exact_bytes)"
identity_padding_bytes="$(json_scalar "${work_dir}/fixture/fixture-metadata.json" identity.padding_bytes)"
identity_oidc_claims_bytes="$(json_scalar "${work_dir}/fixture/fixture-metadata.json" identity.oidc_claims_bytes)"
identity_oidc_group_count="$(json_scalar "${work_dir}/fixture/fixture-metadata.json" identity.oidc_group_count)"
identity_login_attempt_count="$(json_scalar "${work_dir}/fixture/fixture-metadata.json" identity.login_attempt_count)"
identity_session_count="$(json_scalar "${work_dir}/fixture/fixture-metadata.json" identity.session_count)"
identity_sha256="$(json_scalar "${work_dir}/fixture/fixture-metadata.json" identity.sha256)"
say "FIXTURE: control canonical=${control_canonical_bytes} exact=${control_exact_bytes} padding=${control_padding_bytes} nodes=${control_node_count}; identity canonical=${identity_canonical_bytes} exact=${identity_exact_bytes} padding=${identity_padding_bytes} oidc_claims=${identity_oidc_claims_bytes} oidc_groups=${identity_oidc_group_count} login_attempts=${identity_login_attempt_count} sessions=${identity_session_count}"
say "FIXTURE-SHA256: control=${control_sha256} identity=${identity_sha256}"

master_key="$(read_private_line "${work_dir}/fixture/secrets/master.key")"
admin_token="$(read_private_line "${work_dir}/fixture/secrets/admin.token")"
"${mesh_backup}" keygen --output "${work_dir}/fixture/secrets/backup.key" >"${work_dir}/results/backup-keygen.json" 2>"${work_dir}/diagnostics/backup-keygen.stderr"
say "Creating and reopening the authenticated exact-document backup before PostgreSQL exists"
MESH_MASTER_KEY="${master_key}" MESH_ADMIN_TOKEN="${admin_token}" \
  "${mesh_backup}" create --data-dir "${work_dir}/fixture/source" --key-file "${work_dir}/fixture/secrets/backup.key" --output "${work_dir}/fixture/source.meshbackup" \
  >"${work_dir}/results/backup-create.json" 2>"${work_dir}/diagnostics/backup-create.stderr" &
backup_pid=$!
sample_process "${backup_pid}" "${mesh_backup}" || die "authenticated maximum-document backup creation failed"
backup_id="$(json_scalar "${work_dir}/results/backup-create.json" backup_id)"
[[ "${backup_id}" =~ ^[0-9a-f]{32}$ ]] || die "backup command returned an invalid backup ID"
"${mesh_backup}" verify --key-file "${work_dir}/fixture/secrets/backup.key" --archive "${work_dir}/fixture/source.meshbackup" >"${work_dir}/results/backup-verify.json" 2>"${work_dir}/diagnostics/backup-verify.stderr" &
backup_verify_pid=$!
sample_process "${backup_verify_pid}" "${mesh_backup}" || die "authenticated maximum-document backup verification failed"
[[ "$(json_scalar "${work_dir}/results/backup-verify.json" backup_id)" == "${backup_id}" ]] || die "backup verification changed the backup ID"

run_id="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(8))
PY
)"
resource_id="$(python3 - "${run_id}" <<'PY'
import hashlib
import sys
print(hashlib.sha256(("mesh-postgres-max-document:" + sys.argv[1]).encode()).hexdigest())
PY
)"
[[ "${run_id}" =~ ^[0-9a-f]{16}$ && "${resource_id}" =~ ^[0-9a-f]{64}$ ]] || die "could not create canonical disposable resource identifiers"
container_name="${resource_prefix}-${run_id}"
volume_name="${resource_prefix}-${run_id}-pgdata"
postgres_role="meshmax_${run_id}"
postgres_database="meshmax_${run_id}"
postgres_password="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
printf '%s\n' "${postgres_password}" >"${work_dir}/fixture/secrets/postgres.password"
chmod 0400 "${work_dir}/fixture/secrets/postgres.password"

say "Creating exact labeled PostgreSQL volume and 1-GiB-capped PostgreSQL 17 container"
docker_command volume create --label "io.mesh.smoke.kind=${smoke_kind}" --label "io.mesh.smoke.instance=${resource_id}" --label 'io.mesh.smoke.role=pgdata' "${volume_name}" >/dev/null
volume_created=1
volume_matches || die "created PostgreSQL volume identity did not match"
container_id="$(docker_command create --pull=never \
  --name "${container_name}" \
  --label "io.mesh.smoke.kind=${smoke_kind}" --label "io.mesh.smoke.instance=${resource_id}" --label 'io.mesh.smoke.role=postgres' \
  --memory 1024m --memory-swap 1024m --cpus 2 --pids-limit 256 --shm-size 128m \
  --security-opt no-new-privileges \
  --env "POSTGRES_USER=${postgres_role}" --env "POSTGRES_DB=${postgres_database}" \
  --env POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password \
  --mount "type=bind,src=${work_dir}/fixture/secrets/postgres.password,dst=/run/secrets/postgres-password,readonly" \
  --mount "type=volume,src=${volume_name},dst=/var/lib/postgresql/data" \
  --publish '127.0.0.1::5432' "${postgres_image_id}" \
  2>"${work_dir}/diagnostics/docker-create.stderr")"
[[ "${container_id}" =~ ^[0-9a-f]{64}$ ]] || die "Docker did not return one exact created container ID"
container_started=1
container_matches || die "disposable PostgreSQL container identity did not match"
printf '%s\n' "${container_id}" >"${work_dir}/results/container.id"
started_container_id="$(docker_command start "${container_id}" 2>"${work_dir}/diagnostics/docker-start.stderr")"
[[ "${started_container_id}" == "${container_name}" || "${started_container_id}" == "${container_id}" ]] || die "Docker did not start the exact created container"
container_matches || die "disposable PostgreSQL container identity changed during start"
postgres_ready=0
postgres_ready_deadline=$((SECONDS + 60))
while (( SECONDS < postgres_ready_deadline )); do
  if docker_probe exec "${container_id}" pg_isready --quiet --host 127.0.0.1 --port 5432 --username "${postgres_role}" --dbname "${postgres_database}"; then
    postgres_ready=1
    break
  fi
  sleep 0.1
done
[[ "${postgres_ready}" == "1" ]] || die "disposable PostgreSQL did not become ready"
container_matches || die "PostgreSQL container identity changed before version validation"
postgres_version_num="$(docker_command exec "${container_id}" psql --no-psqlrc --tuples-only --no-align --username "${postgres_role}" --dbname "${postgres_database}" --command 'SHOW server_version_num')"
[[ "${postgres_version_num}" =~ ^17[0-9]{4}$ ]] || die "disposable database is not PostgreSQL major version 17"
port_mapping="$(docker_command port "${container_id}" 5432/tcp 2>/dev/null)"
[[ "${port_mapping}" =~ ^127\.0\.0\.1:([0-9]+)$ ]] || die "Docker did not publish one loopback PostgreSQL port"
postgres_port="${BASH_REMATCH[1]}"
postgres_dsn="postgres://${postgres_role}:${postgres_password}@127.0.0.1:${postgres_port}/${postgres_database}?sslmode=disable&target_session_attrs=read-write&connect_timeout=5&pool_max_conns=4"
printf '%s\n' "${postgres_dsn}" >"${work_dir}/fixture/secrets/postgres.dsn"
chmod 0400 "${work_dir}/fixture/secrets/postgres.dsn"

say "Migrating, validated-importing, and offline-verifying the exact authenticated pair"
container_matches || die "PostgreSQL container identity changed before migration"
"${mesh_storage}" migrate --postgres-dsn-file "${work_dir}/fixture/secrets/postgres.dsn" --allow-local-plaintext-postgres >"${work_dir}/results/storage-migrate.json" 2>"${work_dir}/diagnostics/storage-migrate.stderr"
container_matches || die "PostgreSQL container identity changed before authenticated import"
baseline_metrics="$(docker_command exec "${container_id}" psql --no-psqlrc --tuples-only --no-align --field-separator='|' --username "${postgres_role}" --dbname "${postgres_database}" --command "SELECT pg_database_size(current_database()), wal_bytes::bigint FROM pg_stat_wal")"
IFS='|' read -r baseline_database_bytes baseline_wal_bytes <<<"${baseline_metrics}"
[[ "${baseline_database_bytes}" =~ ^[0-9]+$ && "${baseline_wal_bytes}" =~ ^[0-9]+$ ]] || die "could not capture pre-import PostgreSQL metrics"
"${mesh_storage}" import-backup --postgres-dsn-file "${work_dir}/fixture/secrets/postgres.dsn" --backup-key-file "${work_dir}/fixture/secrets/backup.key" --backup-archive "${work_dir}/fixture/source.meshbackup" --expect-backup-id "${backup_id}" --allow-local-plaintext-postgres >"${work_dir}/results/storage-import.json" 2>"${work_dir}/diagnostics/storage-import.stderr" &
import_pid=$!
sample_process "${import_pid}" "${mesh_storage}" || die "validated maximum-document import failed"
container_matches || die "PostgreSQL container identity changed during authenticated import"
"${mesh_storage}" verify --postgres-dsn-file "${work_dir}/fixture/secrets/postgres.dsn" --backup-key-file "${work_dir}/fixture/secrets/backup.key" --backup-archive "${work_dir}/fixture/source.meshbackup" --expect-backup-id "${backup_id}" --allow-local-plaintext-postgres >"${work_dir}/results/storage-verify.json" 2>"${work_dir}/diagnostics/storage-verify.stderr" &
storage_verify_pid=$!
sample_process "${storage_verify_pid}" "${mesh_storage}" || die "offline maximum-document storage verification failed"

"${max_driver}" verify --postgres-dsn-file "${work_dir}/fixture/secrets/postgres.dsn" --metadata "${work_dir}/fixture/fixture-metadata.json" --backup-id "${backup_id}" --phase initial --allow-local-plaintext-postgres >"${work_dir}/results/initial.json" 2>"${work_dir}/diagnostics/initial.stderr" &
verify_pid=$!
sample_process "${verify_pid}" "${max_driver}" || die "initial maximum-document database verification failed"

server_port="$(pick_loopback_port)"
[[ "${server_port}" =~ ^[0-9]+$ && "${server_port}" -ge 1024 && "${server_port}" -le 65535 ]] || die "kernel returned an invalid server port"
server_url="http://127.0.0.1:${server_port}"

start_server() {
  container_matches || die "PostgreSQL container identity changed before server start"
  MESH_MASTER_KEY="${master_key}" MESH_ADMIN_TOKEN="${admin_token}" NEBULA_CERT_BINARY=/usr/local/bin/nebula-cert \
    "${mesh_server}" --storage-backend=postgres --postgres-dsn-file="${work_dir}/fixture/secrets/postgres.dsn" --allow-local-plaintext-postgres \
    --listen "127.0.0.1:${server_port}" --public-url "${server_url}" \
    >>"${work_dir}/diagnostics/server.log" 2>&1 &
  server_pid=$!
  local ready=0 ready_deadline=$((SECONDS + 60)) server_rss
  while (( SECONDS < ready_deadline )); do
    if curl --silent --show-error --fail --noproxy '*' --connect-timeout 1 --max-time 2 --output /dev/null "${server_url}/healthz" 2>/dev/null && \
       curl --silent --show-error --fail --noproxy '*' --connect-timeout 1 --max-time 15 --output /dev/null "${server_url}/readyz" 2>/dev/null; then
      ready=1
      break
    fi
    kill -0 "${server_pid}" 2>/dev/null || break
    server_rss="$(process_rss_bytes "${server_pid}")"
    (( server_rss > peak_process_rss )) && peak_process_rss="${server_rss}"
    (( server_rss <= application_rss_budget )) || die "measured server RSS exceeded 1.5 GiB during startup"
    sleep 0.1
  done
  [[ "${ready}" == "1" ]] || die "real maximum-document server did not become ready"
}

say "Starting one real server and executing the shrink-first business mutations"
start_server
python3 - "${server_pid}" "${work_dir}/diagnostics/server-cmdline.txt" <<'PY'
import pathlib
import sys
raw = (pathlib.Path("/proc") / sys.argv[1] / "cmdline").read_bytes()
pathlib.Path(sys.argv[2]).write_text(" ".join(v.decode("utf-8") for v in raw.split(b"\0") if v) + "\n", encoding="utf-8")
PY
"${max_driver}" mutate --postgres-dsn-file "${work_dir}/fixture/secrets/postgres.dsn" --metadata "${work_dir}/fixture/fixture-metadata.json" --backup-id "${backup_id}" --server-url "${server_url}" --allow-local-plaintext-postgres >"${work_dir}/results/mutation.json" 2>"${work_dir}/diagnostics/mutation.stderr" &
mutation_pid=$!
sample_process "${mutation_pid}" "${max_driver}" || die "maximum-document shrink-first mutation sequence failed"
[[ "$(json_scalar "${work_dir}/results/mutation.json" cleanup_login_attempts)" == "1" ]] || die "maximum-document cleanup did not remove the one sealed login attempt"
[[ "$(json_scalar "${work_dir}/results/mutation.json" cleanup_sessions)" == "1" ]] || die "maximum-document cleanup did not remove the one expired session"
[[ "$(json_scalar "${work_dir}/results/mutation.json" cleanup_revision)" == "2" ]] || die "maximum-document cleanup did not prove identity revision 2"
cleanup_sha256="$(json_scalar "${work_dir}/results/mutation.json" cleanup_sha256)"
cleanup_write_id="$(json_scalar "${work_dir}/results/mutation.json" cleanup_write_id)"
[[ "${cleanup_sha256}" =~ ^[0-9a-f]{64}$ ]] || die "maximum-document cleanup did not report its bound SHA-256"
[[ "${cleanup_write_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || die "maximum-document cleanup did not report its canonical write ID"
[[ "$(json_scalar "${work_dir}/results/mutation.json" cleanup_receipt_operation)" == "identity.state.update" ]] || die "maximum-document cleanup receipt operation changed"
[[ "$(json_scalar "${work_dir}/results/mutation.json" cleanup_receipt_base_revision)" == "1" && "$(json_scalar "${work_dir}/results/mutation.json" cleanup_receipt_committed_revision)" == "2" ]] || die "maximum-document cleanup receipt revision pair changed"
server_hwm="$(process_hwm_bytes "${server_pid}")"
(( server_hwm > peak_process_rss )) && peak_process_rss="${server_hwm}"

say "Restarting the real server and repeating readiness plus terminal database verification"
stop_child "${server_pid}" "${server_executable}"
server_pid=""
start_server
"${max_driver}" verify --postgres-dsn-file "${work_dir}/fixture/secrets/postgres.dsn" --metadata "${work_dir}/fixture/fixture-metadata.json" --backup-id "${backup_id}" --phase terminal --allow-local-plaintext-postgres >"${work_dir}/results/restart.json" 2>"${work_dir}/diagnostics/restart.stderr" &
restart_pid=$!
sample_process "${restart_pid}" "${max_driver}" || die "restarted maximum-document database verification failed"
restart_hwm="$(process_hwm_bytes "${server_pid}")"
(( restart_hwm > peak_process_rss )) && peak_process_rss="${restart_hwm}"

container_matches || die "PostgreSQL container identity changed before terminal diagnostics"
docker_command logs "${container_id}" >"${work_dir}/diagnostics/postgres.log" 2>"${work_dir}/diagnostics/postgres-log.stderr"
terminal_wal_bytes="$(json_scalar "${work_dir}/results/restart.json" wal_bytes)"
terminal_database_bytes="$(json_scalar "${work_dir}/results/restart.json" database_bytes)"
wal_delta=$((terminal_wal_bytes - baseline_wal_bytes))
container_matches || die "PostgreSQL container identity changed before physical disk measurement"
postgres_disk_usage="$(docker_command exec "${container_id}" du -sk /var/lib/postgresql/data)"
read -r postgres_disk_kib _ <<<"${postgres_disk_usage}"
[[ "${postgres_disk_kib}" =~ ^[0-9]+$ ]] || die "could not capture PostgreSQL physical disk usage"
postgres_disk_bytes=$((postgres_disk_kib * 1024))
(( resource_samples > 0 && peak_process_rss > 0 && peak_postgres_memory > 0 )) || die "resource sampling returned no observations"
(( peak_process_rss <= application_rss_budget )) || die "maximum-document process RSS exceeded 1.5 GiB"
(( peak_postgres_memory <= postgres_memory_budget )) || die "PostgreSQL memory exceeded 1 GiB"
(( postgres_disk_bytes <= postgres_disk_budget )) || die "PostgreSQL physical data directory exceeded 512 MiB"
(( terminal_database_bytes <= database_budget )) || die "PostgreSQL database exceeded 256 MiB"
(( wal_delta >= 0 && wal_delta <= wal_budget )) || die "PostgreSQL WAL delta exceeded 256 MiB"

say "Scanning bounded diagnostics for every disposable credential"
find "${work_dir}/diagnostics" "${work_dir}/results" -type f -print | sort >"${work_dir}/diagnostic-files.list"
python3 - "${work_dir}/diagnostic-files.list" \
  "${work_dir}/fixture/secrets/master.key" "${work_dir}/fixture/secrets/admin.token" \
  "${work_dir}/fixture/secrets/backup.key" "${work_dir}/fixture/secrets/postgres.password" \
  "${work_dir}/fixture/secrets/postgres.dsn" <<'PY'
import pathlib
import sys
diagnostics = [pathlib.Path(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines() if line]
secrets = []
for name in sys.argv[2:]:
    raw = pathlib.Path(name).read_bytes().strip()
    if len(raw) >= 8:
        secrets.append(raw)
for path in diagnostics:
    raw = path.read_bytes()
    for secret in secrets:
        if secret in raw:
            raise SystemExit(f"credential leaked into diagnostic {path}")
PY

workspace_bytes="$(workspace_size_bytes)"
elapsed=$((SECONDS - started_seconds))
(( workspace_bytes <= workspace_budget )) || die "maximum-document workspace exceeded 2 GiB"
(( elapsed <= duration_budget )) || die "maximum-document gate exceeded 15 minutes"
python3 - "${peak_process_rss}" "${peak_postgres_memory}" "${postgres_disk_bytes}" "${terminal_database_bytes}" "${wal_delta}" "${workspace_bytes}" "${elapsed}" "${resource_samples}" >"${work_dir}/results/resources.json" <<'PY'
import json
import sys
process, postgres, postgres_disk, database, wal, workspace, elapsed, samples = map(int, sys.argv[1:])
json.dump({
    "schema": "mesh-postgres-maximum-document-resource-v1",
    "passed": True,
    "peak_process_rss_bytes": process,
    "peak_postgres_memory_bytes": postgres,
    "postgres_disk_bytes": postgres_disk,
    "database_bytes": database,
    "wal_delta_bytes": wal,
    "workspace_bytes": workspace,
    "elapsed_seconds": elapsed,
    "samples": samples,
    "budgets": {"process_rss_bytes": 1536 * 1024**2, "postgres_memory_bytes": 1024**3, "postgres_disk_bytes": 512 * 1024**2, "database_bytes": 256 * 1024**2, "wal_bytes": 256 * 1024**2, "workspace_bytes": 2 * 1024**3, "elapsed_seconds": 900},
}, sys.stdout, sort_keys=True)
sys.stdout.write("\n")
PY

say "RESOURCES: app_peak_rss=${peak_process_rss} postgres_peak_memory=${peak_postgres_memory} postgres_disk=${postgres_disk_bytes} database=${terminal_database_bytes} wal_delta=${wal_delta} workspace=${workspace_bytes} elapsed_seconds=${elapsed} samples=${resource_samples}"
say "PASS: imported and reread exact 67,108,864-byte control and 8,388,608-byte identity documents with authenticated provenance and revision-one receipts"
say "PASS: full graph/recovery readiness including purpose-sealed OIDC payloads, shrink-first control and identity mutations, canonical rewrites, receipt sequences, restart readiness, and bounded resources all passed"
say "LIMIT: this gate proves maximum valid document mechanics, not sustained load, retention, failover, production roles/TLS, or managed-service behavior"
