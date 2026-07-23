#!/usr/bin/env bash
set -Eeuo pipefail

readonly script_name="$(basename "$0")"
readonly repository_root="$(cd "$(dirname "$0")/.." && pwd -P)"
readonly compose_file="${repository_root}/packaging/compose/compose.yaml"

work_dir=""
project_name=""
container_id=""

say() {
  printf '%s\n' "$*"
}

skip() {
  printf 'SKIP: %s\n' "$*" >&2
  exit 77
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

compose() {
  BUILDX_CONFIG="${work_dir}/buildx" docker compose \
    --project-name "${project_name}" \
    --file "${compose_file}" "$@"
}

cleanup() {
  local status=$?
  trap - EXIT ERR HUP INT TERM
  if [[ -n "${project_name}" && -n "${work_dir}" ]]; then
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  if [[ -n "${MESH_IMAGE:-}" ]]; then
    docker image rm --force "${MESH_IMAGE}" >/dev/null 2>&1 || true
  fi
  case "${work_dir}" in
    /tmp/mesh-compose-smoke.*) rm -rf -- "${work_dir}" ;;
    "") ;;
    *) printf 'Refusing to remove unexpected work directory %s\n' "${work_dir}" >&2 ;;
  esac
  exit "${status}"
}

on_error() {
  local status=$?
  local line="${1:-unknown}"
  trap - ERR
  printf 'ERROR: %s failed at line %s\n' "${script_name}" "${line}" >&2
  if [[ -n "${project_name}" && -n "${work_dir}" ]]; then
    compose logs --no-color --tail 80 >&2 2>/dev/null || true
  fi
  exit "${status}"
}

pick_loopback_port() {
  python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

wait_for_healthy() {
  local health poll
  container_id="$(compose ps --quiet mesh)"
  [[ -n "${container_id}" ]] || die "Compose did not create the Mesh container"
  for poll in {1..160}; do
    health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "${container_id}")"
    case "${health}" in
      healthy) return ;;
      unhealthy) die "container readiness became unhealthy" ;;
      starting) ;;
      *) die "unexpected container health state ${health}" ;;
    esac
    sleep 0.25
  done
  die "container did not become ready within forty seconds"
}

trap cleanup EXIT
trap 'on_error "${LINENO}"' ERR
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

command -v docker >/dev/null 2>&1 || skip "Docker is unavailable"
docker info >/dev/null 2>&1 || skip "Docker daemon is unavailable"
docker compose version >/dev/null 2>&1 || skip "Docker Compose is unavailable"
command -v openssl >/dev/null 2>&1 || skip "OpenSSL is unavailable"
command -v curl >/dev/null 2>&1 || skip "curl is unavailable"
command -v python3 >/dev/null 2>&1 || skip "python3 is unavailable"

work_dir="$(mktemp -d /tmp/mesh-compose-smoke.XXXXXX)"
project_name="mesh-compose-smoke-$$"
install -d -m 0700 "${work_dir}/data" "${work_dir}/secrets" "${work_dir}/tls" "${work_dir}/buildx"
umask 077

admin_token="$(openssl rand -base64 32 | tr '/+' '_-' | tr -d '=\n')"
master_key="$(openssl rand -base64 32 | tr '/+' '_-' | tr -d '=\n')"
[[ ${#admin_token} -eq 43 && ${#master_key} -eq 43 ]] || die "OpenSSL did not produce canonical 256-bit credentials"
printf '%s\n' "${admin_token}" >"${work_dir}/secrets/admin.token"
printf '%s\n' "${master_key}" >"${work_dir}/secrets/master.key"
chmod 0600 "${work_dir}/secrets/admin.token" "${work_dir}/secrets/master.key"
unset master_key

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
  -subj '/CN=127.0.0.1' \
  -addext 'subjectAltName=IP:127.0.0.1' \
  -keyout "${work_dir}/tls/server.key" \
  -out "${work_dir}/tls/server.crt" >/dev/null 2>&1
cp -- "${work_dir}/tls/server.crt" "${work_dir}/tls/ca.crt"
chmod 0600 "${work_dir}/tls/server.key"
chmod 0644 "${work_dir}/tls/server.crt" "${work_dir}/tls/ca.crt"

port="$(pick_loopback_port)"
[[ "${port}" =~ ^[0-9]+$ && "${port}" -ge 1024 && "${port}" -le 65535 ]] || die "kernel returned an invalid port"

export MESH_IMAGE="mesh-control-plane:compose-smoke-$$"
export MESH_RUNTIME_UID="$(id -u)"
export MESH_RUNTIME_GID="$(id -g)"
export MESH_HTTPS_BIND="127.0.0.1"
export MESH_HTTPS_PORT="${port}"
export MESH_PUBLIC_URL="https://127.0.0.1:${port}"
export MESH_PUBLIC_HOST="127.0.0.1"
export MESH_DATA_DIR="${work_dir}/data"
export MESH_ADMIN_TOKEN_FILE="${work_dir}/secrets/admin.token"
export MESH_MASTER_KEY_FILE="${work_dir}/secrets/master.key"
export MESH_TLS_CERT_FILE="${work_dir}/tls/server.crt"
export MESH_TLS_KEY_FILE="${work_dir}/tls/server.key"
export MESH_TLS_CA_FILE="${work_dir}/tls/ca.crt"
export MESH_LINUX_INSTALL_BUNDLE_URL=""
export MESH_LINUX_BOOTSTRAP_HANDOFF_URL=""

say "Validating the hardened Compose model"
compose config --quiet

say "Building the pinned non-root scratch image"
compose build --quiet

say "Starting the native-HTTPS control plane"
compose up --detach --no-build
wait_for_healthy

docker inspect "${container_id}" >"${work_dir}/container-inspect.json"
python3 - "${work_dir}/container-inspect.json" "${MESH_RUNTIME_UID}:${MESH_RUNTIME_GID}" "${work_dir}/data" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))[0]
expected_user = sys.argv[2]
data_source = sys.argv[3]
assert document["Config"]["User"] == expected_user, document["Config"]["User"]
assert document["HostConfig"]["ReadonlyRootfs"] is True, document["HostConfig"]["ReadonlyRootfs"]
assert {item.upper() for item in document["HostConfig"]["CapDrop"]} == {"ALL"}, document["HostConfig"]["CapDrop"]
assert document["HostConfig"]["SecurityOpt"] == ["no-new-privileges:true"], document["HostConfig"]["SecurityOpt"]
assert document["HostConfig"]["PidsLimit"] == 128, document["HostConfig"]["PidsLimit"]
assert document["HostConfig"]["Memory"] == 512 * 1024 * 1024, document["HostConfig"]["Memory"]
assert not any(item.startswith(("MESH_ADMIN_TOKEN=", "MESH_MASTER_KEY=")) for item in document["Config"]["Env"])
mounts = {item["Destination"]: item for item in document["Mounts"]}
assert mounts["/var/lib/mesh"]["Source"] == data_source and mounts["/var/lib/mesh"]["RW"] is True
for target in ("/run/secrets/admin.token", "/run/secrets/master.key", "/run/tls/server.crt", "/run/tls/server.key", "/run/tls/ca.crt"):
    assert mounts[target]["RW"] is False
PY

docker exec "${container_id}" /usr/local/bin/mesh-healthcheck
ready_body="$(curl --silent --show-error --fail --noproxy '*' \
  --cacert "${work_dir}/tls/ca.crt" \
  --connect-timeout 2 --max-time 5 \
  "${MESH_PUBLIC_URL}/readyz")"
[[ "${ready_body}" == '{"status":"ready"}' ]] || die "external readiness returned an unexpected body"

say "Creating authoritative state through the HTTPS API"
curl --silent --show-error --fail --noproxy '*' \
  --cacert "${work_dir}/tls/ca.crt" \
  --connect-timeout 2 --max-time 15 \
  --header "Authorization: Bearer ${admin_token}" \
  --header 'Content-Type: application/json' \
  --data-binary '{"name":"compose-proof","cidr":"10.249.0.0/24"}' \
  --output "${work_dir}/created-network.json" \
  "${MESH_PUBLIC_URL}/api/v1/networks"

python3 - "${work_dir}/created-network.json" <<'PY'
import json
import pathlib
import sys

network = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert network["name"] == "compose-proof"
assert network["cidr"] == "10.249.0.0/24"
assert network["config_revision"] == 1
assert isinstance(network["id"], str) and network["id"]
PY

unset admin_token
state_hash_before="$(sha256sum "${work_dir}/data/state.json" | awk '{print $1}')"
state_metadata_before="$(stat -c '%i:%s:%y' "${work_dir}/data/state.json")"

say "Restarting the container and proving byte-stable persistence"
compose restart mesh >/dev/null
wait_for_healthy
state_hash_after="$(sha256sum "${work_dir}/data/state.json" | awk '{print $1}')"
state_metadata_after="$(stat -c '%i:%s:%y' "${work_dir}/data/state.json")"
[[ "${state_hash_after}" == "${state_hash_before}" ]] || die "control state changed across a no-op restart"
[[ "${state_metadata_after}" == "${state_metadata_before}" ]] || die "control state metadata changed across a no-op restart"

admin_token="$(sed -n '1p' "${work_dir}/secrets/admin.token")"
curl --silent --show-error --fail --noproxy '*' \
  --cacert "${work_dir}/tls/ca.crt" \
  --connect-timeout 2 --max-time 15 \
  --header "Authorization: Bearer ${admin_token}" \
  --output "${work_dir}/networks-after-restart.json" \
  "${MESH_PUBLIC_URL}/api/v1/networks"
unset admin_token

python3 - "${work_dir}/networks-after-restart.json" <<'PY'
import json
import pathlib
import sys

networks = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
matches = [item for item in networks if item.get("name") == "compose-proof"]
assert len(matches) == 1
assert matches[0]["cidr"] == "10.249.0.0/24"
assert matches[0]["config_revision"] == 1
PY

say "PASS: hardened HTTPS Compose deployment, strict file credentials, readiness, state creation, and byte-stable restart verified"
