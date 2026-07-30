#!/usr/bin/env bash

# Disposable PostgreSQL 17 proof for an authenticated backup in the compiled
# import range plus non-empty schema-v8 mobile runtime telemetry across two
# independent application pools.

set -Eeuo pipefail
umask 077

readonly skip_status=77
readonly postgres_image="postgres:17-alpine"
readonly smoke_kind="postgres-mobile-runtime"
readonly resource_prefix="mesh-postgres-mobile-runtime-smoke"

(( $# == 0 )) || {
  printf '%s\n' 'ERROR: postgres mobile-runtime smoke accepts no arguments' >&2
  exit 1
}

for command in docker go python3; do
  command -v "${command}" >/dev/null 2>&1 || {
    printf 'SKIP: required command is unavailable: %s\n' "${command}" >&2
    exit "${skip_status}"
  }
done
docker info >/dev/null 2>&1 || {
  printf '%s\n' 'SKIP: Docker daemon is unavailable' >&2
  exit "${skip_status}"
}

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
run_id="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(8))
PY
)"
readonly run_id
readonly resource_id="${smoke_kind}-${run_id}"
readonly container_name="${resource_prefix}-${run_id}"

container_id=""
postgres_image_id=""
container_started=0

container_matches() {
  local observed observed_id observed_name observed_kind observed_instance
  local observed_role observed_image

  [[ "${container_started}" == "1" &&
     "${container_name}" =~ ^mesh-postgres-mobile-runtime-smoke-[0-9a-f]{16}$ &&
     "${container_id}" =~ ^[0-9a-f]{64}$ &&
     "${postgres_image_id}" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  observed="$(docker inspect --format \
    '{{.Id}}|{{.Name}}|{{index .Config.Labels "io.mesh.smoke.kind"}}|{{index .Config.Labels "io.mesh.smoke.instance"}}|{{index .Config.Labels "io.mesh.smoke.role"}}|{{.Image}}' \
    "${container_id}" 2>/dev/null || true)"
  IFS='|' read -r observed_id observed_name observed_kind observed_instance \
    observed_role observed_image <<<"${observed}"
  observed_name="${observed_name#/}"
  [[ "${observed_id}" == "${container_id}" &&
     "${observed_name}" == "${container_name}" &&
     "${observed_kind}" == "${smoke_kind}" &&
     "${observed_instance}" == "${resource_id}" &&
     "${observed_role}" == "postgres" &&
     "${observed_image}" == "${postgres_image_id}" ]]
}

cleanup() {
  local status=$?

  trap - EXIT HUP INT TERM
  set +e
  if [[ "${container_started}" == "1" ]]; then
    if container_matches; then
      docker rm --force --volumes -- "${container_id}" >/dev/null 2>&1 ||
        status=1
    elif docker inspect "${container_name}" >/dev/null 2>&1; then
      printf '%s\n' \
        'ERROR: refusing to remove a PostgreSQL container whose exact identity changed' \
        >&2
      status=1
    fi
  fi
  exit "${status}"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

docker image inspect "${postgres_image}" >/dev/null 2>&1 ||
  docker pull "${postgres_image}" >/dev/null
postgres_image_id="$(docker image inspect --format '{{.Id}}' "${postgres_image}")"
[[ "${postgres_image_id}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
  printf '%s\n' 'ERROR: PostgreSQL image identity is invalid' >&2
  exit 1
}

container_id="$(docker run --detach \
  --name "${container_name}" \
  --label "io.mesh.smoke.kind=${smoke_kind}" \
  --label "io.mesh.smoke.instance=${resource_id}" \
  --label "io.mesh.smoke.role=postgres" \
  --env POSTGRES_HOST_AUTH_METHOD=trust \
  --publish 127.0.0.1::5432 \
  "${postgres_image}")"
[[ "${container_id}" =~ ^[0-9a-f]{64}$ ]] || {
  printf '%s\n' 'ERROR: PostgreSQL container identity is invalid' >&2
  exit 1
}
container_started=1
container_matches || {
  printf '%s\n' 'ERROR: PostgreSQL container identity check failed' >&2
  exit 1
}

ready=0
for ((attempt = 1; attempt <= 60; attempt++)); do
  if docker exec "${container_id}" \
    pg_isready --username postgres --dbname postgres >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
[[ "${ready}" == "1" ]] || {
  printf '%s\n' 'ERROR: disposable PostgreSQL did not become ready' >&2
  exit 1
}

binding="$(docker port "${container_id}" 5432/tcp)"
[[ "${binding}" =~ ^127\.0\.0\.1:([0-9]{1,5})$ ]] || {
  printf '%s\n' 'ERROR: PostgreSQL loopback port binding is invalid' >&2
  exit 1
}
port="${BASH_REMATCH[1]}"
dsn="postgres://postgres@127.0.0.1:${port}/postgres?sslmode=disable"

(
  cd -- "${repo_root}"
  MESH_POSTGRES_TEST_DSN="${dsn}" \
    go test ./internal/postgresstore \
      -run '^TestPostgresIntegration$' \
      -count=1
  MESH_RUNTIME_TELEMETRY_POSTGRES_TEST_DSN="${dsn}" \
    go test ./internal/runtimetelemetry \
      -run '^TestPostgresMobileRuntimeIntegration$' \
      -count=1
)

dsn=""
printf '%s\n' \
  'PASS: compiled-range backup import and schema-v8 mobile runtime telemetry persisted across PostgreSQL application pools'
