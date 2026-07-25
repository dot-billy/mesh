#!/usr/bin/env bash

# Disposable local proof of Mesh's strict PostgreSQL commit-outcome contract.
# A package-internal harness injects deterministic transaction-boundary errors
# around real PostgreSQL commits. One exact matching receipt is resolved only
# after hard primary termination and synchronous-standby promotion; a changed
# writable authority with a missing receipt fails closed. This is not a load,
# soak, PITR, production TLS/role, or automated failover proof.

set -Eeuo pipefail
umask 077

readonly skip_status=77
readonly script_name="${0##*/}"
readonly keep_smoke="${KEEP_MESH_SMOKE:-0}"
readonly postgres_image="postgres:17-alpine"
readonly smoke_label="io.mesh.smoke.instance"
readonly smoke_kind_label="io.mesh.smoke.kind"
readonly smoke_kind="postgres-ambiguous-commit"

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
work_parent=""
work_dir=""
run_id=""
network_name=""
network_id=""
primary_volume=""
standby_volume=""
divergent_volume=""
primary_container=""
standby_bootstrap_container=""
standby_container=""
divergent_container=""
primary_port=""
standby_port=""
divergent_port=""
test_pid=""
go_executable=""

declare -A container_ids=()
declare -A volume_names=()

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

stop_test_process() {
  local attempt

  [[ -n "${test_pid}" ]] || return 0
  if ! kill -0 "${test_pid}" 2>/dev/null; then
    wait "${test_pid}" 2>/dev/null || true
    test_pid=""
    return 0
  fi
  if ! valid_child_pid "${test_pid}" "${go_executable}"; then
    printf 'ERROR: refusing to signal unverified test process %s\n' "${test_pid}" >&2
    return 1
  fi
  kill -TERM "${test_pid}" 2>/dev/null || true
  for attempt in {1..100}; do
    kill -0 "${test_pid}" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "${test_pid}" 2>/dev/null; then
    valid_child_pid "${test_pid}" "${go_executable}" || {
      printf 'ERROR: refusing to force-stop changed test process %s\n' "${test_pid}" >&2
      return 1
    }
    kill -KILL "${test_pid}" 2>/dev/null || true
  fi
  wait "${test_pid}" 2>/dev/null || true
  test_pid=""
}

container_matches_run() {
  local name="$1"
  local expected_id="${container_ids[${name}]:-}"
  local observed_name observed_id observed_run observed_kind

  [[ -n "${run_id}" && "${run_id}" =~ ^[0-9a-f]{16}$ ]] || return 1
  [[ "${name}" =~ ^mesh-postgres-ambiguous-commit-smoke-${run_id}-(primary|standby-bootstrap|standby|divergent)$ ]] || return 1
  [[ "${expected_id}" =~ ^[0-9a-f]{64}$ ]] || return 1
  observed_name="$(docker inspect --format '{{.Name}}' "${name}" 2>/dev/null || true)"
  observed_id="$(docker inspect --format '{{.Id}}' "${name}" 2>/dev/null || true)"
  observed_run="$(docker inspect --format '{{ index .Config.Labels "io.mesh.smoke.instance" }}' "${name}" 2>/dev/null || true)"
  observed_kind="$(docker inspect --format '{{ index .Config.Labels "io.mesh.smoke.kind" }}' "${name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "/${name}" && "${observed_id}" == "${expected_id}" &&
     "${observed_run}" == "${run_id}" && "${observed_kind}" == "${smoke_kind}" ]]
}

adopt_container_for_cleanup() {
  local name="$1"
  local observed_name observed_id observed_run observed_kind

  [[ -n "${run_id}" ]] || return 1
  [[ "${name}" =~ ^mesh-postgres-ambiguous-commit-smoke-${run_id}-(primary|standby-bootstrap|standby|divergent)$ ]] || return 1
  observed_name="$(docker inspect --format '{{.Name}}' "${name}" 2>/dev/null || true)"
  observed_id="$(docker inspect --format '{{.Id}}' "${name}" 2>/dev/null || true)"
  observed_run="$(docker inspect --format '{{ index .Config.Labels "io.mesh.smoke.instance" }}' "${name}" 2>/dev/null || true)"
  observed_kind="$(docker inspect --format '{{ index .Config.Labels "io.mesh.smoke.kind" }}' "${name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "/${name}" && "${observed_id}" =~ ^[0-9a-f]{64}$ &&
     "${observed_run}" == "${run_id}" && "${observed_kind}" == "${smoke_kind}" ]] || return 1
  container_ids["${name}"]="${observed_id}"
}

remove_container_exact() {
  local name="$1"

  [[ -n "${name}" ]] || return 0
  if [[ -z "${container_ids[${name}]:-}" ]]; then
    docker inspect "${name}" >/dev/null 2>&1 || return 0
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

network_matches_run() {
  local observed_name observed_id observed_run observed_kind

  [[ "${network_name}" == "mesh-postgres-ambiguous-commit-smoke-${run_id}-network" ]] || return 1
  [[ "${network_id}" =~ ^[0-9a-f]{64}$ ]] || return 1
  observed_name="$(docker network inspect --format '{{.Name}}' "${network_name}" 2>/dev/null || true)"
  observed_id="$(docker network inspect --format '{{.Id}}' "${network_name}" 2>/dev/null || true)"
  observed_run="$(docker network inspect --format '{{ index .Labels "io.mesh.smoke.instance" }}' "${network_name}" 2>/dev/null || true)"
  observed_kind="$(docker network inspect --format '{{ index .Labels "io.mesh.smoke.kind" }}' "${network_name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "${network_name}" && "${observed_id}" == "${network_id}" &&
     "${observed_run}" == "${run_id}" && "${observed_kind}" == "${smoke_kind}" ]]
}

adopt_network_for_cleanup() {
  local observed_name observed_id observed_run observed_kind

  [[ "${network_name}" == "mesh-postgres-ambiguous-commit-smoke-${run_id}-network" ]] || return 1
  observed_name="$(docker network inspect --format '{{.Name}}' "${network_name}" 2>/dev/null || true)"
  observed_id="$(docker network inspect --format '{{.Id}}' "${network_name}" 2>/dev/null || true)"
  observed_run="$(docker network inspect --format '{{ index .Labels "io.mesh.smoke.instance" }}' "${network_name}" 2>/dev/null || true)"
  observed_kind="$(docker network inspect --format '{{ index .Labels "io.mesh.smoke.kind" }}' "${network_name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "${network_name}" && "${observed_id}" =~ ^[0-9a-f]{64}$ &&
     "${observed_run}" == "${run_id}" && "${observed_kind}" == "${smoke_kind}" ]] || return 1
  network_id="${observed_id}"
}

volume_matches_run() {
  local name="$1"
  local observed_name observed_run observed_kind

  [[ "${name}" =~ ^mesh-postgres-ambiguous-commit-smoke-${run_id}-(primary|standby|divergent)-data$ ]] || return 1
  [[ "${volume_names[${name}]:-}" == "${name}" ]] || return 1
  observed_name="$(docker volume inspect --format '{{.Name}}' "${name}" 2>/dev/null || true)"
  observed_run="$(docker volume inspect --format '{{ index .Labels "io.mesh.smoke.instance" }}' "${name}" 2>/dev/null || true)"
  observed_kind="$(docker volume inspect --format '{{ index .Labels "io.mesh.smoke.kind" }}' "${name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "${name}" && "${observed_run}" == "${run_id}" &&
     "${observed_kind}" == "${smoke_kind}" ]]
}

adopt_volume_for_cleanup() {
  local name="$1"
  local observed_name observed_run observed_kind

  [[ "${name}" =~ ^mesh-postgres-ambiguous-commit-smoke-${run_id}-(primary|standby|divergent)-data$ ]] || return 1
  observed_name="$(docker volume inspect --format '{{.Name}}' "${name}" 2>/dev/null || true)"
  observed_run="$(docker volume inspect --format '{{ index .Labels "io.mesh.smoke.instance" }}' "${name}" 2>/dev/null || true)"
  observed_kind="$(docker volume inspect --format '{{ index .Labels "io.mesh.smoke.kind" }}' "${name}" 2>/dev/null || true)"
  [[ "${observed_name}" == "${name}" && "${observed_run}" == "${run_id}" &&
     "${observed_kind}" == "${smoke_kind}" ]] || return 1
  volume_names["${name}"]="${name}"
}

cleanup() {
  local status=$?
  local name base parent

  trap - ERR EXIT HUP INT TERM
  set +e
  stop_test_process || status=1

  if [[ "${keep_smoke}" == "1" ]]; then
    if (( ${#container_ids[@]} > 0 )); then
      printf 'Kept exact labeled ambiguous-commit PostgreSQL resources for debugging.\n' >&2
    fi
  else
    for name in "${standby_bootstrap_container}" "${standby_container}" "${primary_container}" "${divergent_container}"; do
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

    for name in "${standby_volume}" "${primary_volume}" "${divergent_volume}"; do
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
      printf 'Kept private ambiguous-commit workspace: %s\n' "${work_dir}" >&2
      printf 'It contains disposable credentials that also exist in the retained database volumes.\n' >&2
    else
      base="${work_dir##*/}"
      parent="$(cd -- "$(dirname -- "${work_dir}")" 2>/dev/null && pwd -P)"
      if [[ "${base}" == mesh-postgres-ambiguous-commit-smoke.* && -n "${work_parent}" &&
            "${parent}" == "${work_parent}" && ! -L "${work_dir}" ]]; then
        rm -rf -- "${work_dir}"
      else
        printf 'ERROR: refusing to remove unexpected ambiguous-commit workspace %s\n' "${work_dir}" >&2
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

register_container() {
  local name="$1"
  local id_file="$2"
  local reported observed

  reported="$(tr -d '\r\n' <"${id_file}")"
  observed="$(docker inspect --format '{{.Id}}' "${name}" 2>/dev/null || true)"
  [[ "${reported}" =~ ^[0-9a-f]{64}$ && "${observed}" == "${reported}" ]] ||
    die "Docker did not return one exact canonical ID for ${name}"
  container_ids["${name}"]="${observed}"
  container_matches_run "${name}" || die "container ${name} did not match its exact name, ID, and smoke labels"
}

container_port() {
  local name="$1"
  local mapping

  container_matches_run "${name}" || die "refusing to inspect an unverified container port"
  mapping="$(docker port "${name}" 5432/tcp 2>/dev/null)"
  [[ "${mapping}" =~ ^127\.0\.0\.1:([0-9]+)$ ]] ||
    die "Docker did not publish ${name} PostgreSQL on one IPv4 loopback port"
  [[ "${BASH_REMATCH[1]}" -ge 1024 && "${BASH_REMATCH[1]}" -le 65535 ]] ||
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
      pg_isready --quiet --host 127.0.0.1 --port 5432 --username mesh_admin --dbname mesh \
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
      --username mesh_admin --dbname mesh --command "${query}" | tr -d '\r\n'
}

postgres_script() {
  local name="$1"
  local output="$2"

  container_matches_run "${name}" || die "refusing PostgreSQL input against an unverified container"
  docker exec --interactive --user postgres "${name}" \
    psql -X --no-psqlrc --set=ON_ERROR_STOP=1 --username mesh_admin --dbname mesh \
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
    recovery="$(postgres_scalar "${standby_container}" 'SELECT pg_catalog.pg_is_in_recovery();' 2>/dev/null || true)"
    read_only="$(postgres_scalar "${standby_container}" 'SHOW transaction_read_only;' 2>/dev/null || true)"
    if [[ "${recovery}" == "f" && "${read_only}" == "off" ]]; then
      return 0
    fi
    sleep 0.1
  done
  die "promoted standby did not become the writable authority"
}

write_dsn_file() {
  local output="$1"
  local port="$2"

  python3 - "${work_dir}/secrets/postgres-password" "${output}" "${port}" <<'PY'
import os
import pathlib
import re
import sys
import urllib.parse

secret_path, output_path, port = sys.argv[1:]
password = pathlib.Path(secret_path).read_text(encoding="ascii").rstrip("\n")
if not re.fullmatch(r"[A-Za-z0-9_-]{43}", password):
    raise SystemExit("disposable PostgreSQL password is not canonical")
if not port.isdigit() or not (1024 <= int(port) <= 65535):
    raise SystemExit("PostgreSQL port is invalid")
dsn = (
    "postgresql://mesh_admin:"
    + urllib.parse.quote(password, safe="")
    + f"@127.0.0.1:{port}/mesh"
    + "?sslmode=disable&target_session_attrs=read-write&connect_timeout=3"
    + "&pool_max_conns=4&pool_min_conns=0&pool_min_idle_conns=0\n"
)
fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(fd, dsn.encode("ascii"))
    os.fsync(fd)
finally:
    os.close(fd)
PY
}

write_resume_file() {
  local output="$1"

  python3 - "${output}" <<'PY'
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
temporary = path.with_name(path.name + ".publishing")
fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(fd, b"promoted_writable\n")
    os.fsync(fd)
finally:
    os.close(fd)
directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(directory)
    os.link(temporary, path)
    os.fsync(directory)
    os.unlink(temporary)
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

capture_container_diagnostics() {
  local name="$1"
  local label="$2"

  container_matches_run "${name}" || die "refusing diagnostics from an unverified ${label} container"
  docker inspect -- "${name}" >"${work_dir}/${label}-docker-inspect.json"
  docker logs --timestamps -- "${name}" \
    >"${work_dir}/${label}-docker.log" 2>"${work_dir}/${label}-docker-log.stderr"
}

scan_for_secret_leaks() {
  python3 - "${work_dir}" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
secrets = [
    (root / "secrets" / "postgres-password").read_bytes().rstrip(b"\n"),
    (root / "secrets" / "replication-password").read_bytes().rstrip(b"\n"),
]
if any(len(secret) < 32 for secret in secrets):
    raise SystemExit("disposable secret length is invalid")

scanned = 0
for path in sorted(root.rglob("*")):
    if not path.is_file() or path.is_symlink():
        continue
    relative = path.relative_to(root)
    if relative.parts[0] == "secrets" or path.suffix == ".dsn":
        continue
    size = path.stat().st_size
    if size > 16 * 1024 * 1024:
        raise SystemExit(f"diagnostic exceeds leak-scan bound: {relative}")
    scanned += size
    if scanned > 64 * 1024 * 1024:
        raise SystemExit("diagnostics exceed aggregate leak-scan bound")
    data = path.read_bytes()
    if any(secret in data for secret in secrets):
        raise SystemExit(f"disposable PostgreSQL secret leaked into diagnostic: {relative}")
PY
}

if [[ "${keep_smoke}" != "0" && "${keep_smoke}" != "1" ]]; then
  die "KEEP_MESH_SMOKE must be 0 or 1"
fi
if (( BASH_VERSINFO[0] < 4 )); then
  skip "Bash 4 or newer is required"
fi
if [[ "$(uname -s 2>/dev/null || true)" != "Linux" ]]; then
  skip "this PostgreSQL fault-injection smoke requires Linux"
fi
for prerequisite in go python3 docker mktemp chmod mkdir rm ps readlink sleep tr uname stat id sed env; do
  command -v -- "${prerequisite}" >/dev/null 2>&1 || skip "required command is unavailable: ${prerequisite}"
done
go_executable="$(readlink -f -- "$(command -v go)")"
[[ -x "${go_executable}" && -f "${go_executable}" ]] || skip "the Go executable is unavailable"
docker info >/dev/null 2>&1 || skip "Docker daemon access is unavailable"
docker image inspect "${postgres_image}" >/dev/null 2>&1 || skip "cached postgres:17-alpine image is unavailable"

temporary_parent="${TMPDIR:-/tmp}"
[[ -d "${temporary_parent}" && ! -L "${temporary_parent}" ]] || skip "private temporary directory parent is unavailable"
work_parent="$(cd -- "${temporary_parent}" && pwd -P)"
work_dir="$(mktemp -d "${work_parent%/}/mesh-postgres-ambiguous-commit-smoke.XXXXXX")"
[[ -d "${work_dir}" && ! -L "${work_dir}" ]] || die "mktemp did not create a real private workspace"
chmod 0700 "${work_dir}"
mkdir -- "${work_dir}/secrets"
chmod 0700 "${work_dir}/secrets"
cd -- "${repo_root}"

run_id="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(8))
PY
)"
[[ "${run_id}" =~ ^[0-9a-f]{16}$ ]] || die "could not generate a canonical disposable run identifier"

network_name="mesh-postgres-ambiguous-commit-smoke-${run_id}-network"
primary_volume="mesh-postgres-ambiguous-commit-smoke-${run_id}-primary-data"
standby_volume="mesh-postgres-ambiguous-commit-smoke-${run_id}-standby-data"
divergent_volume="mesh-postgres-ambiguous-commit-smoke-${run_id}-divergent-data"
primary_container="mesh-postgres-ambiguous-commit-smoke-${run_id}-primary"
standby_bootstrap_container="mesh-postgres-ambiguous-commit-smoke-${run_id}-standby-bootstrap"
standby_container="mesh-postgres-ambiguous-commit-smoke-${run_id}-standby"
divergent_container="mesh-postgres-ambiguous-commit-smoke-${run_id}-divergent"

python3 - "${work_dir}/secrets/postgres-password" "${work_dir}/secrets/replication-password" <<'PY'
import os
import secrets
import sys

for path, value in (
    (sys.argv[1], secrets.token_urlsafe(32)),
    (sys.argv[2], secrets.token_hex(32)),
):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, (value + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
PY

{
  printf '%s\n' 'POSTGRES_USER=mesh_admin'
  printf '%s\n' 'POSTGRES_DB=mesh'
  printf '%s\n' 'POSTGRES_PASSWORD_FILE=/run/mesh-secrets/postgres-password'
  printf '%s\n' 'POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=trust'
} >"${work_dir}/postgres.env"
chmod 0600 "${work_dir}/postgres.env"

say "Creating one exact labeled network and three disposable database volumes"
docker network create \
  --label "${smoke_label}=${run_id}" \
  --label "${smoke_kind_label}=${smoke_kind}" \
  "${network_name}" >"${work_dir}/network.id"
network_id="$(tr -d '\r\n' <"${work_dir}/network.id")"
[[ "${network_id}" =~ ^[0-9a-f]{64}$ ]] || die "Docker did not return one canonical network ID"
network_matches_run || die "disposable network identity or labels did not match"
for volume in "${primary_volume}" "${standby_volume}" "${divergent_volume}"; do
  docker volume create \
    --label "${smoke_label}=${run_id}" \
    --label "${smoke_kind_label}=${smoke_kind}" \
    "${volume}" >"${work_dir}/${volume##*-${run_id}-}.volume"
  volume_names["${volume}"]="${volume}"
  volume_matches_run "${volume}" || die "disposable volume ${volume} identity or labels did not match"
done

say "Starting the exact PostgreSQL 17 primary and independent divergent authority"
docker run --detach \
  --name "${primary_container}" \
  --label "${smoke_label}=${run_id}" \
  --label "${smoke_kind_label}=${smoke_kind}" \
  --network "${network_name}" \
  --network-alias mesh-primary \
  --volume "${primary_volume}:/var/lib/postgresql/data" \
  --mount "type=bind,src=${work_dir}/secrets,dst=/run/mesh-secrets,readonly" \
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

docker run --detach \
  --name "${divergent_container}" \
  --label "${smoke_label}=${run_id}" \
  --label "${smoke_kind_label}=${smoke_kind}" \
  --network "${network_name}" \
  --network-alias mesh-divergent \
  --volume "${divergent_volume}:/var/lib/postgresql/data" \
  --mount "type=bind,src=${work_dir}/secrets,dst=/run/mesh-secrets,readonly" \
  --env-file "${work_dir}/postgres.env" \
  --publish '127.0.0.1::5432' \
  "${postgres_image}" \
  postgres -c password_encryption=scram-sha-256 \
  >"${work_dir}/divergent.id" 2>"${work_dir}/divergent-docker-run.stderr"
register_container "${divergent_container}" "${work_dir}/divergent.id"

wait_postgres_ready "${primary_container}" primary
wait_postgres_ready "${divergent_container}" divergent

say "Creating the dedicated replication login and exact physical slot without exposing its secret in argv"
printf '%s\n' 'host replication mesh_repl samenet scram-sha-256' | \
  docker exec --interactive --user postgres "${primary_container}" \
    sh -c 'cat >> /var/lib/postgresql/data/pg_hba.conf'
docker exec --user postgres "${primary_container}" \
  pg_ctl reload --pgdata /var/lib/postgresql/data \
  >"${work_dir}/primary-reload.stdout" 2>"${work_dir}/primary-reload.stderr"
python3 - "${work_dir}/secrets/replication-password" <<'PY' | \
  postgres_script "${primary_container}" "${work_dir}/primary-replication-setup.txt"
import pathlib
import re
import sys

password = pathlib.Path(sys.argv[1]).read_text(encoding="ascii").rstrip("\n")
if not re.fullmatch(r"[0-9a-f]{64}", password):
    raise SystemExit("replication password is not canonical")
print("CREATE ROLE mesh_repl WITH LOGIN REPLICATION PASSWORD '" + password + "';")
print("SELECT slot_name FROM pg_catalog.pg_create_physical_replication_slot('mesh_standby_slot');")
PY

say "Taking one exact physical base backup into the standby volume"
docker run --detach \
  --name "${standby_bootstrap_container}" \
  --label "${smoke_label}=${run_id}" \
  --label "${smoke_kind_label}=${smoke_kind}" \
  --network "${network_name}" \
  --volume "${standby_volume}:/var/lib/postgresql/data" \
  --mount "type=bind,src=${work_dir}/secrets,dst=/run/mesh-secrets,readonly" \
  --entrypoint /bin/sh \
  "${postgres_image}" \
  -c 'trap "exit 0" TERM INT; while :; do sleep 3600 & wait $!; done' \
  >"${work_dir}/standby-bootstrap.id" 2>"${work_dir}/standby-bootstrap-docker-run.stderr"
register_container "${standby_bootstrap_container}" "${work_dir}/standby-bootstrap.id"
docker exec --user root "${standby_bootstrap_container}" sh -c \
  'set -eu; test -d /var/lib/postgresql/data; test -z "$(find /var/lib/postgresql/data -mindepth 1 -print -quit)"; chown postgres:postgres /var/lib/postgresql/data; chmod 0700 /var/lib/postgresql/data; umask 077; pw="$(tr -d "\n" < /run/mesh-secrets/replication-password)"; printf "mesh-primary:5432:*:mesh_repl:%s\n" "$pw" > /tmp/mesh-repl.pgpass; chown postgres:postgres /tmp/mesh-repl.pgpass; chmod 0600 /tmp/mesh-repl.pgpass'
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
docker exec --user root "${standby_bootstrap_container}" sh -c \
  'set -eu; install -o postgres -g postgres -m 0600 /tmp/mesh-repl.pgpass /var/lib/postgresql/data/.mesh-repl.pgpass; rm -f /tmp/mesh-repl.pgpass'
printf '%s\n' "primary_conninfo = 'host=mesh-primary port=5432 user=mesh_repl passfile=/var/lib/postgresql/data/.mesh-repl.pgpass application_name=mesh_standby connect_timeout=5'" | \
  docker exec --interactive --user postgres "${standby_bootstrap_container}" \
    sh -c 'cat >> /var/lib/postgresql/data/postgresql.auto.conf'
docker exec --user root "${standby_bootstrap_container}" sh -c \
  'set -eu; test -f /var/lib/postgresql/data/standby.signal; test -f /var/lib/postgresql/data/.mesh-repl.pgpass; test "$(stat -c %a /var/lib/postgresql/data/.mesh-repl.pgpass)" = 600'
capture_container_diagnostics "${standby_bootstrap_container}" standby-bootstrap
remove_container_exact "${standby_bootstrap_container}"

say "Starting the exact physical standby and requiring remote_apply before Mesh writes"
docker run --detach \
  --name "${standby_container}" \
  --label "${smoke_label}=${run_id}" \
  --label "${smoke_kind_label}=${smoke_kind}" \
  --network "${network_name}" \
  --network-alias mesh-standby \
  --volume "${standby_volume}:/var/lib/postgresql/data" \
  --publish '127.0.0.1::5432' \
  "${postgres_image}" \
  postgres -c synchronous_commit=remote_apply -c synchronous_standby_names= \
  >"${work_dir}/standby.id" 2>"${work_dir}/standby-docker-run.stderr"
register_container "${standby_container}" "${work_dir}/standby.id"
wait_postgres_ready "${standby_container}" standby
[[ "$(postgres_scalar "${standby_container}" 'SELECT pg_catalog.pg_is_in_recovery();')" == "t" ]] ||
  die "standby was not in physical recovery before synchronous configuration"

{
  printf "%s\n" "ALTER SYSTEM SET synchronous_commit = 'remote_apply';"
  printf "%s\n" "ALTER SYSTEM SET synchronous_standby_names = 'FIRST 1 (mesh_standby)';"
  printf '%s\n' 'SELECT pg_catalog.pg_reload_conf();'
} | postgres_script "${primary_container}" "${work_dir}/primary-synchronous-settings.txt"
wait_standby_streaming
primary_sync_settings="$(postgres_scalar "${primary_container}" \
  "SELECT current_setting('synchronous_commit') || '|' || current_setting('synchronous_standby_names');")"
[[ "${primary_sync_settings}" == "remote_apply|FIRST 1 (mesh_standby)" ]] ||
  die "primary synchronous settings were not exact"

primary_port="$(container_port "${primary_container}")"
standby_port="$(container_port "${standby_container}")"
divergent_port="$(container_port "${divergent_container}")"
[[ "${primary_port}" != "${standby_port}" && "${primary_port}" != "${divergent_port}" &&
   "${standby_port}" != "${divergent_port}" ]] || die "PostgreSQL authorities shared one host port"
write_dsn_file "${work_dir}/primary.dsn" "${primary_port}"
write_dsn_file "${work_dir}/standby.dsn" "${standby_port}"
write_dsn_file "${work_dir}/divergent.dsn" "${divergent_port}"

phase_file="${work_dir}/remote-apply-committed.phase"
resume_file="${work_dir}/promoted-writable.resume"

say "Running deterministic pre-commit, lost-acknowledgment, and changed-authority cases"
env \
  -u PGHOST -u PGPORT -u PGDATABASE -u PGUSER -u PGPASSWORD -u PGPASSFILE \
  -u PGSERVICE -u PGSERVICEFILE -u PGSSLMODE -u PGSSLCERT -u PGSSLKEY \
  -u PGSSLROOTCERT -u PGSSLPASSWORD -u PGSSLSNI -u PGSSLNEGOTIATION \
  -u PGAPPNAME -u PGCONNECT_TIMEOUT -u PGTARGETSESSIONATTRS -u PGTZ -u PGOPTIONS \
  -u PGMINPROTOCOLVERSION -u PGMAXPROTOCOLVERSION -u PGCHANNELBINDING -u PGREQUIREAUTH \
  MESH_POSTGRES_AMBIGUOUS_PRIMARY_DSN_FILE="${work_dir}/primary.dsn" \
  MESH_POSTGRES_AMBIGUOUS_STANDBY_DSN_FILE="${work_dir}/standby.dsn" \
  MESH_POSTGRES_AMBIGUOUS_DIVERGENT_DSN_FILE="${work_dir}/divergent.dsn" \
  MESH_POSTGRES_AMBIGUOUS_PHASE_FILE="${phase_file}" \
  MESH_POSTGRES_AMBIGUOUS_RESUME_FILE="${resume_file}" \
  go test -buildvcs=false -count=1 -run '^TestPostgresAmbiguousCommitIntegration$' -v ./internal/postgresstore \
  >"${work_dir}/go-test.log" 2>&1 &
test_pid=$!
sleep 0.1
if kill -0 "${test_pid}" 2>/dev/null; then
  valid_child_pid "${test_pid}" "${go_executable}" || die "fault-injection test process identity changed"
fi

phase_seen=0
for poll in {1..1800}; do
  if [[ -f "${phase_file}" ]]; then
    phase_metadata="$(stat -c '%a|%u|%h|%s' "${phase_file}")"
    expected_phase_metadata="600|$(id -u)|1|28"
    if [[ ! -L "${phase_file}" && "${phase_metadata}" == "600|$(id -u)|2|28" ]]; then
      sleep 0.05
      continue
    fi
    [[ ! -L "${phase_file}" && "${phase_metadata}" == "${expected_phase_metadata}" ]] ||
      die "promotion phase file metadata was not exact"
    [[ "$(<"${phase_file}")" == "remote_apply_commit_durable" ]] || die "promotion phase file value was not exact"
    phase_seen=1
    break
  fi
  if ! kill -0 "${test_pid}" 2>/dev/null; then
    sed -n '1,240p' "${work_dir}/go-test.log" >&2
    die "fault-injection test exited before the durable-commit phase"
  fi
  sleep 0.05
done
[[ "${phase_seen}" == "1" ]] || die "timed out waiting for the durable remote_apply commit phase"

say "Hard-terminating the exact primary and explicitly promoting its synchronous standby"
container_matches_run "${primary_container}" || die "primary identity changed before hard termination"
docker kill --signal KILL -- "${primary_container}" >"${work_dir}/primary-kill.stdout" 2>"${work_dir}/primary-kill.stderr"
for poll in {1..100}; do
  [[ "$(docker inspect --format '{{.State.Running}}' "${primary_container}" 2>/dev/null || true)" == "false" ]] && break
  sleep 0.1
done
[[ "$(docker inspect --format '{{.State.Running}}' "${primary_container}" 2>/dev/null || true)" == "false" ]] ||
  die "hard-terminated primary remained running"

[[ "$(postgres_scalar "${standby_container}" 'SELECT pg_catalog.pg_promote(true, 60);')" == "t" ]] ||
  die "standby promotion was not accepted"
wait_promoted_writable
printf '%s\n' 'CHECKPOINT;' | postgres_script "${standby_container}" "${work_dir}/promoted-checkpoint.txt"
write_resume_file "${resume_file}"

set +e
wait "${test_pid}"
test_status=$?
set -e
test_pid=""
if [[ "${test_status}" -ne 0 ]]; then
  sed -n '1,300p' "${work_dir}/go-test.log" >&2
  die "PostgreSQL ambiguous-commit integration test failed"
fi

say "Verifying the exact terminal revision and receipt ledgers on both authorities"
[[ "$(postgres_scalar "${standby_container}" "SELECT revision FROM mesh.mesh_state_documents WHERE document_key = 'control';")" == "4" ]] ||
  die "promoted authority did not retain the exact four-revision control timeline"
[[ "$(postgres_scalar "${standby_container}" 'SELECT pg_catalog.count(*) FROM mesh.mesh_write_receipts;')" == "5" ]] ||
  die "promoted authority did not retain the exact five-receipt ledger"
[[ "$(postgres_scalar "${divergent_container}" "SELECT revision FROM mesh.mesh_state_documents WHERE document_key = 'control';")" == "1" ]] ||
  die "divergent authority mutated during changed-authority resolution"
[[ "$(postgres_scalar "${divergent_container}" 'SELECT pg_catalog.count(*) FROM mesh.mesh_write_receipts;')" == "2" ]] ||
  die "divergent authority receipt ledger changed"

say "Capturing bounded diagnostics and proving disposable database secrets were not emitted"
capture_container_diagnostics "${primary_container}" primary
capture_container_diagnostics "${standby_container}" standby
capture_container_diagnostics "${divergent_container}" divergent
scan_for_secret_leaks

say "PASS: callback cancellation was a definite noncommit before receipt SQL, with one callback and no mutation"
say "PASS: a pre-COMMIT transport loss rolled back physically but remained process-uncertain and gated without callback replay"
say "PASS: remote_apply preserved the lost-acknowledgment receipt across hard primary loss and exact standby promotion"
say "PASS: the exact promoted receipt resolved success once, then and only then allowed a fresh write"
say "PASS: a writable authority with a distinct system identifier and missing receipt returned ErrUncertainCommit and gated readiness, reads, and writes"
say "LIMIT: bounded synthetic transaction-boundary injection; no sustained failover, automatic election/fencing, PITR, production TLS/roles, load, or soak claim"
