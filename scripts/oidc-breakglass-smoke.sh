#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_dir="$(mktemp -d /tmp/mesh-breakglass-smoke.XXXXXX)"
server_pid=""

cleanup() {
  if [[ -n "${server_pid}" ]] && kill -0 "${server_pid}" 2>/dev/null; then
    kill -TERM "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
  fi
  if [[ "${work_dir}" == /tmp/mesh-breakglass-smoke.* ]]; then
    chmod -R u+w "${work_dir}" 2>/dev/null || true
    rm -rf -- "${work_dir}"
  fi
}
trap cleanup EXIT INT TERM

for command in curl openssl python3; do
  command -v "${command}" >/dev/null || { echo "missing prerequisite: ${command}" >&2; exit 77; }
done

server_bin="${work_dir}/mesh-server"
(cd "${root_dir}" && go build -buildvcs=false -trimpath -o "${server_bin}" ./cmd/mesh-server)

port="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    print(sock.getsockname()[1])
PY
)"
origin="https://127.0.0.1:${port}"
data_dir="${work_dir}/data"
config_path="${work_dir}/identity.json"
secret_path="${work_dir}/oidc-client-secret"
cert_path="${work_dir}/tls.crt"
key_path="${work_dir}/tls.key"
mkdir -m 0700 "${data_dir}"

admin_token="$(openssl rand -base64 48 | tr -d '\n')"
master_key="$(openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=\n')"
printf '%s' "$(openssl rand -base64 48 | tr -d '\n')" >"${secret_path}"
chmod 0600 "${secret_path}"
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' \
  -keyout "${key_path}" -out "${cert_path}" >/dev/null 2>&1
chmod 0600 "${key_path}"

write_config() {
  local mode="$1"
  python3 - "${config_path}" "${mode}" "${secret_path}" <<'PY'
import json, os, sys
path, mode, secret = sys.argv[1:]
document = {
    'schema': 'mesh-identity-v2',
    'mode': mode,
    'legacy_browser_login': False,
    'oidc': {
        'issuer': 'https://127.0.0.1:1/tenant',
        'client_id': 'mesh-breakglass-smoke',
        'client_secret_file': secret,
        'scopes': ['openid'],
        'allowed_signing_algorithms': ['RS256'],
        'admins': [{'kind': 'subject', 'value': 'smoke-admin'}],
        'required_amr_all': ['otp'],
        'max_authentication_age': '15m',
    },
    'sessions': {
        'idle_ttl': '15m',
        'absolute_ttl': '1h',
        'login_attempt_ttl': '5m',
        'touch_interval': '1m',
    },
    'break_glass': {'enabled': True, 'minimum_usable_codes': 2},
}
encoded = json.dumps(document, indent=2, sort_keys=True).encode() + b'\n'
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, 'wb') as output:
    output.write(encoded)
PY
}

start_server() {
  local log_path="$1"
  MESH_ADMIN_TOKEN="${admin_token}" MESH_MASTER_KEY="${master_key}" \
    "${server_bin}" --listen "127.0.0.1:${port}" --public-url "${origin}" \
    --tls-cert "${cert_path}" --tls-key "${key_path}" \
    --identity-config "${config_path}" --data-dir "${data_dir}" >"${log_path}" 2>&1 &
  server_pid=$!
  for _ in $(seq 1 100); do
    if curl --insecure --fail --silent "${origin}/readyz" >/dev/null 2>&1; then
      return
    fi
    if ! kill -0 "${server_pid}" 2>/dev/null; then
      echo "server exited before readiness" >&2
      sed -n '1,80p' "${log_path}" >&2
      exit 1
    fi
    sleep 0.05
  done
  echo "server did not become ready" >&2
  exit 1
}

stop_server() {
  kill -TERM "${server_pid}"
  wait "${server_pid}"
  server_pid=""
}

opaque() {
  openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=\n'
}

write_config hybrid
start_server "${work_dir}/hybrid.log"

expires_at="$(python3 - <<'PY'
from datetime import datetime, timedelta, timezone
print((datetime.now(timezone.utc) + timedelta(days=30)).isoformat(timespec='seconds').replace('+00:00', 'Z'))
PY
)"
code_one="mesh-bg-v1.bg_$(opaque).$(opaque)"
code_two="mesh-bg-v1.bg_$(opaque).$(opaque)"
for index in one two; do
  if [[ "${index}" == one ]]; then code="${code_one}"; else code="${code_two}"; fi
  request_path="${work_dir}/register-${index}.json"
  response_path="${work_dir}/register-${index}-response.json"
  printf '{"code":"%s","expires_at":"%s"}' "${code}" "${expires_at}" >"${request_path}"
  chmod 0600 "${request_path}"
  status="$(curl --insecure --silent --output "${response_path}" --write-out '%{http_code}' \
    -H "Authorization: Bearer ${admin_token}" -H 'Content-Type: application/json' \
    --data-binary "@${request_path}" "${origin}/api/v1/break-glass-codes")"
  [[ "${status}" == 201 ]] || { echo "registration ${index} returned ${status}" >&2; exit 1; }
  if grep -Fq -- "${code}" "${response_path}" || grep -Fq 'token_hash' "${response_path}"; then
    echo "registration response exposed credential material" >&2
    exit 1
  fi
done

inventory_path="${work_dir}/hybrid-inventory.json"
curl --insecure --fail --silent -H "Authorization: Bearer ${admin_token}" \
  "${origin}/api/v1/break-glass-codes" >"${inventory_path}"
python3 - "${inventory_path}" <<'PY'
import json, sys
inventory = json.load(open(sys.argv[1], encoding='utf-8'))
assert inventory['minimum_usable_codes'] == 2 and inventory['usable_codes'] == 2
codes = inventory['codes']
assert len(codes) == 2 and all(code['state'] == 'usable' for code in codes)
assert 'token_hash' not in open(sys.argv[1], encoding='utf-8').read()
PY
stop_server

write_config oidc
start_server "${work_dir}/oidc.log"

bearer_status="$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  -H "Authorization: Bearer ${admin_token}" "${origin}/api/v1/networks")"
[[ "${bearer_status}" == 401 ]] || { echo "OIDC-only bearer returned ${bearer_status}" >&2; exit 1; }

login_path="${work_dir}/recovery-login.json"
cookie_path="${work_dir}/recovery.cookies"
printf '{"code":"%s"}' "${code_one}" >"${login_path}"
chmod 0600 "${login_path}"
login_status="$(curl --insecure --silent --output "${work_dir}/recovery-session.json" --write-out '%{http_code}' \
  --cookie-jar "${cookie_path}" -H "Origin: ${origin}" -H 'Sec-Fetch-Site: same-origin' \
  -H 'Content-Type: application/json' --data-binary "@${login_path}" \
  "${origin}/api/v1/auth/break-glass")"
[[ "${login_status}" == 200 ]] || { echo "recovery login returned ${login_status}" >&2; exit 1; }

csrf="$(awk '$6 == "__Host-mesh_csrf" { print $7 }' "${cookie_path}")"
[[ "${csrf}" =~ ^[A-Za-z0-9_-]{43}$ ]] || { echo "recovery CSRF credential is invalid" >&2; exit 1; }
printf '%s' '{"name":"breakglass-smoke","cidr":"10.94.0.0/24"}' >"${work_dir}/network.json"
mutation_status="$(curl --insecure --silent --output "${work_dir}/network-response.json" --write-out '%{http_code}' \
  --cookie "${cookie_path}" -H "Origin: ${origin}" -H 'Sec-Fetch-Site: same-origin' \
  -H "X-Mesh-CSRF: ${csrf}" -H 'Content-Type: application/json' \
  --data-binary "@${work_dir}/network.json" "${origin}/api/v1/networks")"
[[ "${mutation_status}" == 201 ]] || { echo "recovery mutation returned ${mutation_status}" >&2; exit 1; }

replay_status="$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  -H "Origin: ${origin}" -H 'Sec-Fetch-Site: same-origin' -H 'Content-Type: application/json' \
  --data-binary "@${login_path}" "${origin}/api/v1/auth/break-glass")"
[[ "${replay_status}" == 401 ]] || { echo "recovery replay returned ${replay_status}" >&2; exit 1; }
management_status="$(curl --insecure --silent --output /dev/null --write-out '%{http_code}' \
  --cookie "${cookie_path}" "${origin}/api/v1/break-glass-codes")"
[[ "${management_status}" == 401 ]] || { echo "recovery session management returned ${management_status}" >&2; exit 1; }
stop_server

python3 - "${data_dir}/identity-state.json" "${code_one}" "${code_two}" <<'PY'
import json, sys
path, first, second = sys.argv[1:]
raw = open(path, encoding='utf-8').read()
assert first not in raw and second not in raw
state = json.loads(raw)
codes = state['break_glass_codes']
usable = [code for code in codes if 'used_at' not in code and 'revoked_at' not in code]
assert len(codes) == 2 and len(usable) == 1
PY

write_config hybrid
start_server "${work_dir}/post-use-hybrid.log"
curl --insecure --fail --silent -H "Authorization: Bearer ${admin_token}" \
  "${origin}/api/v1/break-glass-codes" >"${work_dir}/post-use-inventory.json"
python3 - "${work_dir}/post-use-inventory.json" <<'PY'
import json, sys
inventory = json.load(open(sys.argv[1], encoding='utf-8'))
assert inventory['minimum_usable_codes'] == 2
assert inventory['usable_codes'] == 1
assert len(inventory['codes']) == 2
PY
stop_server

write_config oidc
set +e
MESH_ADMIN_TOKEN="${admin_token}" MESH_MASTER_KEY="${master_key}" timeout 10s \
  "${server_bin}" --listen "127.0.0.1:${port}" --public-url "${origin}" \
  --tls-cert "${cert_path}" --tls-key "${key_path}" \
  --identity-config "${config_path}" --data-dir "${data_dir}" >"${work_dir}/floor.log" 2>&1
floor_status=$?
set -e
if [[ "${floor_status}" == 0 || "${floor_status}" == 124 ]]; then
  echo "OIDC-only server did not fail closed below its recovery inventory floor" >&2
  exit 1
fi
grep -Fq 'requires at least 2 usable break-glass recovery codes' "${work_dir}/floor.log" || {
  echo "inventory-floor failure was not explicit" >&2
  sed -n '1,80p' "${work_dir}/floor.log" >&2
  exit 1
}

echo "PASS: hybrid provisioning, OIDC-only bearer removal, one-use recovery mutation, replay rejection, below-floor posture, retained recovery, and startup floor"
