#!/usr/bin/env bash

# Rerunnable, clean-room proof of Mesh's encrypted offline backup and restore
# workflow. The smoke keeps all credentials in private files or process input;
# it never prints them or places one-time credentials in diagnostic JSON.

set -Eeuo pipefail
umask 077

readonly skip_status=77
readonly script_name="${0##*/}"
readonly keep_smoke="${KEEP_MESH_BACKUP_SMOKE:-0}"

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
mesh_server_candidate="${MESH_SERVER_BIN:-${repo_root}/bin/mesh-server}"
mesh_backup_candidate="${MESH_BACKUP_BIN:-${repo_root}/bin/mesh-backup}"
meshctl_candidate="${MESHCTL_BIN:-${repo_root}/bin/meshctl}"
nebula_candidate="${NEBULA_BIN:-nebula}"
nebula_cert_candidate="${NEBULA_CERT_BIN:-nebula-cert}"

work_dir=""
work_parent=""
server_pid=""
server_url=""
server_port=""
source_data=""
restore_data=""
bearer_config=""
cookie_jar=""

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

path_absent() {
  [[ ! -e "$1" && ! -L "$1" ]]
}

stop_server() {
  local pid="${server_pid}"
  local attempt

  server_pid=""
  if [[ -z "${pid}" || ! "${pid}" =~ ^[0-9]+$ || "${pid}" -le 1 ]]; then
    return
  fi
  if ! kill -0 "${pid}" 2>/dev/null; then
    wait "${pid}" 2>/dev/null || true
    return
  fi
  kill -TERM "${pid}" 2>/dev/null || true
  for attempt in {1..100}; do
    if ! kill -0 "${pid}" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  if kill -0 "${pid}" 2>/dev/null; then
    kill -KILL "${pid}" 2>/dev/null || true
  fi
  wait "${pid}" 2>/dev/null || true
}

cleanup() {
  local status=$?
  local base parent

  trap - ERR EXIT HUP INT TERM
  set +e
  stop_server
  if [[ -n "${work_dir}" && -d "${work_dir}" ]]; then
    if [[ "${keep_smoke}" == "1" ]]; then
      printf 'Kept private backup smoke workspace for debugging: %s\n' "${work_dir}" >&2
      printf 'It contains live test credentials; remove it when finished.\n' >&2
    else
      base="${work_dir##*/}"
      parent="$(cd -- "$(dirname -- "${work_dir}")" 2>/dev/null && pwd -P)"
      if [[ "${base}" == mesh-backup-restore-smoke.* && -n "${work_parent}" && "${parent}" == "${work_parent}" && ! -L "${work_dir}" ]]; then
        rm -rf -- "${work_dir}"
      else
        printf 'ERROR: refusing to remove unexpected smoke path %s\n' "${work_dir}" >&2
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
  printf 'ERROR: %s failed at line %s (use KEEP_MESH_BACKUP_SMOKE=1 to retain private diagnostics)\n' \
    "${script_name}" "${line}" >&2
  exit "${status}"
}

trap cleanup EXIT
trap 'on_error "${LINENO}"' ERR
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

resolve_executable() {
  local candidate="$1"

  if [[ "${candidate}" == */* ]]; then
    [[ -f "${candidate}" && -x "${candidate}" ]] || return 1
    printf '%s\n' "${candidate}"
    return
  fi
  command -v -- "${candidate}"
}

nebula_version_exact() {
  local output="$1"
  local major minor patch

  if [[ ! "${output}" =~ ([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
    return 1
  fi
  major="${BASH_REMATCH[1]}"
  minor="${BASH_REMATCH[2]}"
  patch="${BASH_REMATCH[3]}"
  (( major == 1 && minor == 10 && patch == 3 ))
}

pick_loopback_port() {
  python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

start_server() {
  local data_dir="$1"
  local log_path="$2"
  local poll ready=0

  [[ -d "${data_dir}" && ! -L "${data_dir}" ]] || die "server data directory is missing or unsafe: ${data_dir}"
  : >"${log_path}"
  MESH_MASTER_KEY= MESH_ADMIN_TOKEN= NEBULA_CERT_BINARY="${nebula_cert}" \
    "${mesh_server}" \
    --dev \
    --listen "127.0.0.1:${server_port}" \
    --data-dir "${data_dir}" \
    >>"${log_path}" 2>&1 &
  server_pid=$!

  for poll in {1..150}; do
    if curl --silent --show-error --fail --noproxy '*' \
      --connect-timeout 1 --max-time 1 \
      --output /dev/null "${server_url}/healthz" 2>/dev/null; then
      ready=1
      break
    fi
    if ! kill -0 "${server_pid}" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  if [[ "${ready}" != "1" ]]; then
    stop_server
    die "control plane did not start on the selected loopback port"
  fi
}

api_request() {
  local method="$1"
  local path="$2"
  local output="$3"
  local -a arguments

  arguments=(
    --config "${bearer_config}"
    --request "${method}"
    --output "${output}"
    --noproxy '*'
  )
  if [[ $# -eq 4 ]]; then
    arguments+=(--data-binary "@$4")
  fi
  curl "${arguments[@]}" "${server_url}${path}"
}

browser_login() {
  local admin_token="$1"
  local output="$2"

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
      --header "Origin: ${server_url}" \
      --header 'Sec-Fetch-Site: same-origin' \
      --cookie-jar "${cookie_jar}" \
      --data-binary @- \
      --output "${output}" \
      "${server_url}/api/v1/session"
}

browser_get() {
  local path="$1"
  local output="$2"

  curl --silent --show-error --fail --noproxy '*' \
    --connect-timeout 2 --max-time 30 \
    --request GET \
    --header "Origin: ${server_url}" \
    --header 'Sec-Fetch-Site: same-origin' \
    --cookie "${cookie_jar}" \
    --cookie-jar "${cookie_jar}" \
    --output "${output}" \
    "${server_url}${path}"
}

json_scalar() {
  local path="$1"
  local field="$2"

  python3 - "${path}" "${field}" <<'PY'
import json
import pathlib
import sys

def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON name: {key}")
        result[key] = value
    return result

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

require_record_id() {
  local value="$1"
  local label="$2"

  [[ "${value}" =~ ^[A-Za-z0-9_-]+$ ]] || die "${label} is not a canonical record ID"
}

require_backup_id() {
  local value="$1"
  local label="$2"

  [[ "${value}" =~ ^[0-9a-f]{32}$ ]] || die "${label} is not a canonical backup ID"
}

require_operation_id() {
  local value="$1"
  local label="$2"

  [[ "${value}" =~ ^[0-9a-f]{32}$ ]] || die "${label} is not a canonical operation ID"
}

require_positive_integer() {
  local value="$1"
  local label="$2"

  [[ "${value}" =~ ^[0-9]+$ && "${value}" -gt 0 ]] || die "${label} is not a positive integer"
}

assert_command_result() {
  local path="$1"
  local expected_status="$2"
  local expected_backup_id="$3"

  python3 - "${path}" "${expected_status}" "${expected_backup_id}" <<'PY'
import datetime
import json
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
value, end = decoder.raw_decode(raw)
if raw[end:].strip() or not isinstance(value, dict):
    raise SystemExit("backup command result is not one strict JSON object")
if value.get("schema") != "mesh-backup-command-result-v1":
    raise SystemExit("backup command result schema changed")
if value.get("status") != sys.argv[2] or value.get("backup_id") != sys.argv[3]:
    raise SystemExit("backup command result identity or status changed")
if not re.fullmatch(r"[0-9a-f]{32}", value["backup_id"]):
    raise SystemExit("backup command result has a non-canonical ID")
created = value.get("created_at")
if not isinstance(created, str) or not created.endswith("Z"):
    raise SystemExit("backup command result has a non-canonical timestamp")
try:
    parsed = datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
except ValueError as error:
    raise SystemExit("backup command result timestamp is invalid") from error
if parsed.microsecond or parsed.utcoffset() != datetime.timedelta(0):
    raise SystemExit("backup command result timestamp is not a whole UTC second")
PY
}

read_dev_secret() {
  local path="$1"
  local label="$2"

  python3 - "${path}" "${label}" <<'PY'
import base64
import os
import stat
import sys

path, label = sys.argv[1:]
before = os.lstat(path)
if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
    raise SystemExit(f"{label} is not a real regular file")
if stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.geteuid() or before.st_nlink != 1:
    raise SystemExit(f"{label} does not have private single-link ownership")
flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(path, flags)
try:
    after = os.fstat(fd)
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise SystemExit(f"{label} changed while opening")
    raw = b""
    while True:
        chunk = os.read(fd, 128)
        if not chunk:
            break
        raw += chunk
        if len(raw) > 128:
            raise SystemExit(f"{label} is too large")
finally:
    os.close(fd)
if len(raw) != 44 or not raw.endswith(b"\n") or b"\r" in raw:
    raise SystemExit(f"{label} is not one canonical line")
encoded = raw[:-1]
try:
    decoded = base64.urlsafe_b64decode(encoded + b"=")
except Exception as error:
    raise SystemExit(f"{label} is not base64url") from error
if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).rstrip(b"=") != encoded:
    raise SystemExit(f"{label} is not canonical 256-bit base64url")
print(encoded.decode("ascii"))
PY
}

assert_cookie_jar() {
  local path="$1"
  local admin_path="$2"

  python3 - "${path}" "${admin_path}" <<'PY'
import pathlib
import re
import sys

admin = pathlib.Path(sys.argv[2]).read_text(encoding="ascii").strip()
cookies = {}
for line in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    if not line or (line.startswith("#") and not line.startswith("#HttpOnly_")):
        continue
    fields = line.split("\t")
    if len(fields) != 7:
        raise SystemExit("cookie jar contains a malformed entry")
    cookies[fields[5]] = fields[6]
if set(cookies) != {"mesh_session", "mesh_csrf"}:
    raise SystemExit("browser login did not create exactly the expected cookies")
if any(not re.fullmatch(r"[A-Za-z0-9_-]{43}", value) for value in cookies.values()):
    raise SystemExit("browser login produced a non-canonical opaque cookie")
if cookies["mesh_session"] == cookies["mesh_csrf"] or admin in cookies.values():
    raise SystemExit("browser credentials were reused")
PY
}

save_expected_network() {
  local response="$1"
  local output="$2"
  local expected_name="$3"
  local expected_cidr="$4"

  python3 - "${response}" "${output}" "${expected_name}" "${expected_cidr}" <<'PY'
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
network, end = decoder.raw_decode(raw)
if raw[end:].strip() or not isinstance(network, dict):
    raise SystemExit("network response is not one strict JSON object")
expected = {
    "id": network.get("id"),
    "name": network.get("name"),
    "cidr": network.get("cidr"),
    "config_revision": network.get("config_revision"),
}
if not isinstance(expected["id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]+", expected["id"]):
    raise SystemExit("network response has an invalid ID")
if expected["name"] != sys.argv[3] or expected["cidr"] != sys.argv[4]:
    raise SystemExit("network response identity changed")
if isinstance(expected["config_revision"], bool) or not isinstance(expected["config_revision"], int) or expected["config_revision"] < 1:
    raise SystemExit("network response has an invalid config revision")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(sys.argv[2], flags, 0o600)
try:
    body = (json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    os.write(fd, body)
    os.fsync(fd)
finally:
    os.close(fd)
PY
}

assert_network_list() {
  local response="$1"
  local expected_path="$2"

  python3 - "${response}" "${expected_path}" <<'PY'
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

def strict_load(path):
    raw = pathlib.Path(path).read_text(encoding="utf-8")
    decoder = json.JSONDecoder(object_pairs_hook=reject_duplicates)
    value, end = decoder.raw_decode(raw)
    if raw[end:].strip():
        raise SystemExit(f"trailing JSON data in {path}")
    return value

networks = strict_load(sys.argv[1])
expected = strict_load(sys.argv[2])
if not isinstance(networks, list) or not isinstance(expected, dict):
    raise SystemExit("network proof documents have invalid shapes")
matches = [item for item in networks if isinstance(item, dict) and item.get("id") == expected.get("id")]
if len(matches) != 1:
    raise SystemExit("restored API did not return exactly one expected network")
actual = matches[0]
for field in ("id", "name", "cidr", "config_revision"):
    if actual.get(field) != expected.get(field):
        raise SystemExit(f"restored network field changed: {field}")
PY
}

capture_pending_node() {
  local payload="$1"
  local token_path="$2"
  local sanitized_path="$3"
  local expected_role="$4"
  local private_response="${sanitized_path}.private-response"

  curl --config "${bearer_config}" \
    --request POST \
    --output "${private_response}" \
    --noproxy '*' \
    --data-binary "@${payload}" \
    "${server_url}/api/v1/networks/${network_id}/nodes"
  python3 - "${private_response}" "${token_path}" "${sanitized_path}" "${expected_role}" <<'PY'
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
if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
    raise SystemExit("node response omitted its canonical one-time enrollment token")
node = created.get("node")
if not isinstance(node, dict) or node.get("role") != sys.argv[4] or node.get("status") != "pending":
    raise SystemExit(f"node response is not a pending {sys.argv[4]}")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
token_fd = os.open(sys.argv[2], flags, 0o600)
try:
    os.write(token_fd, token.encode("ascii") + b"\n")
    os.fsync(token_fd)
finally:
    os.close(token_fd)
safe_fd = os.open(sys.argv[3], flags, 0o600)
try:
    safe = (json.dumps(created, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    os.write(safe_fd, safe)
    os.fsync(safe_fd)
finally:
    os.close(safe_fd)
PY
  rm -- "${private_response}"
}

save_active_node_checkpoint() {
  local response="$1"
  local state_path="$2"
  local expected_id="$3"
  local expected_network_id="$4"
  local expected_name="$5"
  local output="$6"

  python3 - "${response}" "${state_path}" "${expected_id}" "${expected_network_id}" "${expected_name}" "${output}" <<'PY'
import datetime
import ipaddress
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

def strict_load(path):
    raw = pathlib.Path(path).read_text(encoding="utf-8")
    decoder = json.JSONDecoder(object_pairs_hook=reject_duplicates)
    value, end = decoder.raw_decode(raw)
    if raw[end:].strip():
        raise SystemExit(f"trailing JSON data in {path}")
    return value

nodes = strict_load(sys.argv[1])
state = strict_load(sys.argv[2])
if not isinstance(nodes, list) or not isinstance(state, dict):
    raise SystemExit("active member proof documents have invalid shapes")
matches = [item for item in nodes if isinstance(item, dict) and item.get("id") == sys.argv[3]]
if len(matches) != 1:
    raise SystemExit("node list did not return exactly one active member identity")
node = matches[0]
expected_identity = {
    "id": sys.argv[3],
    "network_id": sys.argv[4],
    "name": sys.argv[5],
    "role": "member",
    "status": "active",
}
for field, expected in expected_identity.items():
    if node.get(field) != expected:
        raise SystemExit(f"active member identity field is invalid: {field}")
address = node.get("ip")
try:
    parsed_address = ipaddress.ip_address(address)
except ValueError as exc:
    raise SystemExit("active member has no canonical IP identity") from exc
if parsed_address.version != 4 or str(parsed_address) != address:
    raise SystemExit("active member IP identity is not canonical IPv4")
fingerprint = node.get("certificate_fingerprint")
if not isinstance(fingerprint, str) or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
    raise SystemExit("active member certificate fingerprint is not canonical")
generation = node.get("certificate_generation")
if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
    raise SystemExit("active member certificate generation is not positive")
expires_at = node.get("certificate_expires_at")
if not isinstance(expires_at, str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", expires_at) is None:
    raise SystemExit("active member certificate expiry is not canonical UTC")
parsed_expiry = datetime.datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
if parsed_expiry.utcoffset() != datetime.timedelta(0):
    raise SystemExit("active member certificate expiry is not UTC")
for field, expected in {
    "node_id": node["id"],
    "network_id": node["network_id"],
    "certificate_fingerprint": fingerprint,
    "certificate_generation": generation,
}.items():
    if state.get(field) != expected:
        raise SystemExit(f"active member state disagrees with the API: {field}")
state_expires_at = state.get("certificate_expires_at")
if not isinstance(state_expires_at, str):
    raise SystemExit("active member state has no certificate expiry")
try:
    parsed_state_expiry = datetime.datetime.fromisoformat(state_expires_at.replace("Z", "+00:00"))
except ValueError as exc:
    raise SystemExit("active member state certificate expiry is invalid") from exc
if parsed_state_expiry.tzinfo is None or parsed_state_expiry != parsed_expiry:
    raise SystemExit("active member state certificate expiry disagrees with the API")
checkpoint = {
    "id": node["id"],
    "network_id": node["network_id"],
    "name": node["name"],
    "ip": address,
    "role": node["role"],
    "status": node["status"],
    "certificate_fingerprint": fingerprint,
    "certificate_generation": generation,
    "certificate_expires_at": expires_at,
}
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(sys.argv[6], flags, 0o600)
try:
    os.write(fd, (json.dumps(checkpoint, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))
    os.fsync(fd)
finally:
    os.close(fd)
PY
}

assert_active_node_checkpoint() {
  local response="$1"
  local expected_path="$2"

  python3 - "${response}" "${expected_path}" <<'PY'
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

def strict_load(path):
    raw = pathlib.Path(path).read_text(encoding="utf-8")
    decoder = json.JSONDecoder(object_pairs_hook=reject_duplicates)
    value, end = decoder.raw_decode(raw)
    if raw[end:].strip():
        raise SystemExit(f"trailing JSON data in {path}")
    return value

nodes = strict_load(sys.argv[1])
expected = strict_load(sys.argv[2])
if not isinstance(nodes, list) or not isinstance(expected, dict):
    raise SystemExit("restored active member proof documents have invalid shapes")
expected_fields = {
    "id",
    "network_id",
    "name",
    "ip",
    "role",
    "status",
    "certificate_fingerprint",
    "certificate_generation",
    "certificate_expires_at",
}
if set(expected) != expected_fields:
    raise SystemExit("active member checkpoint has an invalid shape")
matches = [item for item in nodes if isinstance(item, dict) and item.get("id") == expected.get("id")]
if len(matches) != 1:
    raise SystemExit("restored API did not return exactly one checkpointed active member")
actual = {field: matches[0].get(field) for field in expected_fields}
if actual != expected:
    changed = sorted(field for field in expected_fields if actual.get(field) != expected.get(field))
    raise SystemExit(f"restored active member identity or certificate metadata changed: {changed}")
PY
}

assert_pending_node() {
  local response="$1"
  local expected_id="$2"

  python3 - "${response}" "${expected_id}" <<'PY'
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
nodes, end = decoder.raw_decode(raw)
if raw[end:].strip() or not isinstance(nodes, list):
    raise SystemExit("node list is not one strict JSON array")
matches = [item for item in nodes if isinstance(item, dict) and item.get("id") == sys.argv[2]]
if len(matches) != 1 or matches[0].get("status") != "pending" or matches[0].get("role") != "lighthouse":
    raise SystemExit("pending lighthouse identity was not preserved")
PY
}

snapshot_four() {
  local data_dir="$1"
  local output="$2"

  python3 - "${data_dir}" "${output}" <<'PY'
import hashlib
import json
import os
import stat
import sys

root, output = sys.argv[1:]
result = {}
for name in ("state.json", "identity-state.json", "master.key", "admin.token"):
    path = os.path.join(root, name)
    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise SystemExit(f"unsafe snapshot source: {name}")
    if stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.geteuid() or before.st_nlink != 1:
        raise SystemExit(f"snapshot source is not private and single-link: {name}")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise SystemExit(f"snapshot source changed while opening: {name}")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    finally:
        os.close(fd)
    if size != before.st_size:
        raise SystemExit(f"snapshot source changed while hashing: {name}")
    result[name] = {"sha256": digest.hexdigest(), "size": size, "mode": "0600"}
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(output, flags, 0o600)
try:
    os.write(fd, (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))
    os.fsync(fd)
finally:
    os.close(fd)
PY
}

snapshot_restored_tree() {
  local data_dir="$1"
  local output="$2"

  python3 - "${data_dir}" "${output}" <<'PY'
import hashlib
import json
import os
import stat
import sys

root, output = sys.argv[1:]
expected = {"state.json", "identity-state.json", "master.key", "admin.token", ".mesh-restore-receipt.json"}
actual = set(os.listdir(root))
if actual != expected:
    raise SystemExit(f"restored target contains unexpected entries: {sorted(actual ^ expected)}")
result = {}
for name in sorted(expected):
    path = os.path.join(root, name)
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SystemExit(f"unsafe restored entry: {name}")
    if stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid() or info.st_nlink != 1:
        raise SystemExit(f"restored entry is not private and single-link: {name}")
    with open(path, "rb") as handle:
        raw = handle.read()
    result[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw), "mode": "0600"}
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(output, flags, 0o600)
try:
    os.write(fd, (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))
    os.fsync(fd)
finally:
    os.close(fd)
PY
}

assert_same_snapshot() {
  local expected="$1"
  local actual="$2"

  python3 - "${expected}" "${actual}" <<'PY'
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
    raw = pathlib.Path(path).read_text(encoding="ascii")
    decoder = json.JSONDecoder(object_pairs_hook=reject_duplicates)
    value, end = decoder.raw_decode(raw)
    if raw[end:].strip():
        raise SystemExit(f"snapshot has trailing JSON data: {path}")
    return value

if load(sys.argv[1]) != load(sys.argv[2]):
    raise SystemExit("file snapshots differ")
PY
}

sha256_private_file() {
  local path="$1"

  python3 - "${path}" <<'PY'
import hashlib
import os
import stat
import sys

info = os.lstat(sys.argv[1])
if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
    raise SystemExit("digest target is not a real regular file")
if stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid() or info.st_nlink != 1:
    raise SystemExit("digest target is not private and single-link")
with open(sys.argv[1], "rb") as handle:
    digest = hashlib.sha256()
    while True:
        chunk = handle.read(1 << 20)
        if not chunk:
            break
        digest.update(chunk)
    print(digest.hexdigest())
PY
}

assert_error_contains() {
  local path="$1"
  shift

  python3 - "${path}" "$@" <<'PY'
import pathlib
import sys

message = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="strict")
if not all(fragment in message for fragment in sys.argv[2:]):
    raise SystemExit("failure diagnostic did not prove the expected boundary")
PY
}

assert_no_archive_temporary() {
  local archive_path="$1"

  python3 - "${archive_path}" <<'PY'
import pathlib
import sys

archive = pathlib.Path(sys.argv[1])
prefix = "." + archive.name + ".mesh-backup-tmp-"
leftovers = [entry.name for entry in archive.parent.iterdir() if entry.name.startswith(prefix)]
if leftovers:
    raise SystemExit("backup publication left a sibling temporary file")
PY
}

marker_path_for() {
  local target="$1"
  printf '%s/.%s.mesh-restore-incomplete\n' "$(dirname -- "${target}")" "$(basename -- "${target}")"
}

reconstruct_restore_marker() {
  local receipt_path="$1"
  local target="$2"
  local marker_path="$3"

  python3 - "${receipt_path}" "${target}" "${marker_path}" <<'PY'
import datetime
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
receipt, end = decoder.raw_decode(raw)
if raw[end:].strip() or not isinstance(receipt, dict):
    raise SystemExit("restore receipt is not one strict JSON object")
required = {
    "schema", "backup_id", "operation_id", "target_dir", "restored_at",
    "control_state_sha256", "identity_state_sha256", "receipt_hmac_sha256",
}
if set(receipt) != required or receipt["schema"] != "mesh-restore-receipt-v1":
    raise SystemExit("restore receipt schema changed")
if receipt["target_dir"] != sys.argv[2]:
    raise SystemExit("restore receipt target changed")
if not re.fullmatch(r"[0-9a-f]{32}", receipt["backup_id"]) or not re.fullmatch(r"[0-9a-f]{32}", receipt["operation_id"]):
    raise SystemExit("restore receipt IDs are not canonical")
stamp = receipt["restored_at"]
if not isinstance(stamp, str) or not stamp.endswith("Z"):
    raise SystemExit("restore receipt time is not canonical UTC")
parsed = datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00"))
if parsed.microsecond or parsed.utcoffset() != datetime.timedelta(0):
    raise SystemExit("restore receipt time is not a whole UTC second")
marker = {
    "schema": "mesh-restore-marker-v1",
    "backup_id": receipt["backup_id"],
    "operation_id": receipt["operation_id"],
    "target": receipt["target_dir"],
    "created_at": receipt["restored_at"],
}
# Match Go encoding/json's compact, HTML-safe string encoding.
encoded = json.dumps(marker, ensure_ascii=False, separators=(",", ":"))
encoded = encoded.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
encoded = encoded.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
body = encoded.encode("utf-8") + b"\n"
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(sys.argv[3], flags, 0o600)
try:
    os.write(fd, body)
    os.fsync(fd)
finally:
    os.close(fd)
parent_fd = os.open(str(pathlib.Path(sys.argv[3]).parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(parent_fd)
finally:
    os.close(parent_fd)
PY
}

expect_marker_startup_refusal() {
  local data_dir="$1"
  local log_path="$2"
  local poll status=0

  : >"${log_path}"
  MESH_MASTER_KEY= MESH_ADMIN_TOKEN= NEBULA_CERT_BINARY="${nebula_cert}" \
    "${mesh_server}" \
    --dev \
    --listen "127.0.0.1:${server_port}" \
    --data-dir "${data_dir}" \
    >>"${log_path}" 2>&1 &
  server_pid=$!

  for poll in {1..100}; do
    if curl --silent --fail --noproxy '*' --connect-timeout 1 --max-time 1 \
      --output /dev/null "${server_url}/healthz" 2>/dev/null; then
      stop_server
      die "mesh-server ignored the incomplete restore marker"
    fi
    if ! kill -0 "${server_pid}" 2>/dev/null; then
      if wait "${server_pid}"; then
        status=0
      else
        status=$?
      fi
      server_pid=""
      [[ "${status}" -ne 0 ]] || die "mesh-server exited successfully despite the restore marker"
      assert_error_contains "${log_path}" "open fenced state" "incomplete-restore check" "marker exists"
      return
    fi
    sleep 0.05
  done
  stop_server
  die "mesh-server did not fail closed on the incomplete restore marker"
}

validate_bundle() {
  local output_dir="$1"
  local current="${output_dir}/current"
  local validation_log="$2"

  [[ -L "${current}" ]] || die "restored enrollment did not publish an atomic current symlink"
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
  "${nebula_cert}" verify \
    -ca "${current}/ca.crt" \
    -crt "${current}/host.crt" \
    >>"${validation_log}" 2>&1
  "${nebula}" -test -config "${current}/config.yml" \
    >>"${validation_log}" 2>&1
}

assert_no_known_credentials_in_diagnostics() {
  local admin_path="$1"
  local master_path="$2"
  local lighthouse_enrollment_path="$3"
  local active_member_enrollment_path="$4"
  local backup_key_path="$5"
  local cookies_path="$6"

  python3 - "${work_dir}" "${admin_path}" "${master_path}" "${lighthouse_enrollment_path}" \
    "${active_member_enrollment_path}" "${backup_key_path}" "${cookies_path}" <<'PY'
import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
secrets = []
for path in sys.argv[2:7]:
    value = pathlib.Path(path).read_bytes().strip()
    if value:
        secrets.append(value)
for line in pathlib.Path(sys.argv[7]).read_bytes().splitlines():
    if not line or (line.startswith(b"#") and not line.startswith(b"#HttpOnly_")):
        continue
    fields = line.split(b"\t")
    if len(fields) == 7 and fields[6]:
        secrets.append(fields[6])
for path in root.rglob("*"):
    if not path.is_file() or path.suffix not in {".json", ".log", ".stdout", ".stderr"}:
        continue
    raw = path.read_bytes()
    if any(secret in raw for secret in secrets):
        raise SystemExit(f"known credential leaked into diagnostic output: {path.relative_to(root)}")
PY
}

case "$(uname -s 2>/dev/null || true)" in
  Linux) ;;
  *) skip "backup/restore durability proof requires the supported Linux filesystem implementation" ;;
esac

for prerequisite in python3 curl mktemp chmod rm mkdir dirname basename uname; do
  command -v -- "${prerequisite}" >/dev/null 2>&1 || skip "required command is unavailable: ${prerequisite}"
done
python3 - <<'PY' >/dev/null 2>&1 || skip "Python 3.9 or newer is required"
import sys
raise SystemExit(0 if sys.version_info >= (3, 9) else 1)
PY

mesh_server="$(resolve_executable "${mesh_server_candidate}")" ||
  skip "mesh-server is unavailable; run 'make build' or set MESH_SERVER_BIN"
mesh_backup="$(resolve_executable "${mesh_backup_candidate}")" ||
  skip "mesh-backup is unavailable; run 'make build' or set MESH_BACKUP_BIN"
meshctl="$(resolve_executable "${meshctl_candidate}")" ||
  skip "meshctl is unavailable; run 'make build' or set MESHCTL_BIN"
nebula="$(resolve_executable "${nebula_candidate}")" ||
  skip "real nebula is unavailable; install exact Nebula 1.10.3 or set NEBULA_BIN"
nebula_cert="$(resolve_executable "${nebula_cert_candidate}")" ||
  skip "real nebula-cert is unavailable; install exact Nebula 1.10.3 or set NEBULA_CERT_BIN"

nebula_version="$(${nebula} -version 2>&1)" || skip "nebula -version failed"
nebula_version_exact "${nebula_version}" || skip "exact Nebula 1.10.3 is required"
nebula_cert_version="$(${nebula_cert} -version 2>&1)" || skip "nebula-cert -version failed"
nebula_version_exact "${nebula_cert_version}" || skip "exact nebula-cert 1.10.3 is required"
unset nebula_version nebula_cert_version

temp_parent="${TMPDIR:-/tmp}"
[[ -d "${temp_parent}" && ! -L "${temp_parent}" ]] || skip "private temporary directory parent is unavailable"
work_parent="$(cd -- "${temp_parent}" && pwd -P)"
work_dir="$(mktemp -d "${work_parent%/}/mesh-backup-restore-smoke.XXXXXX")"
[[ -d "${work_dir}" && ! -L "${work_dir}" ]] || die "mktemp did not create a real private directory"
chmod 0700 "${work_dir}"

source_data="${work_dir}/source"
restore_data="${work_dir}/restored"
bearer_config="${work_dir}/admin.curlrc"
cookie_jar="${work_dir}/browser.cookies"
backup_key="${work_dir}/backup.key"
archive="${work_dir}/control-plane.meshbackup"
mkdir -- "${source_data}"
chmod 0700 "${source_data}"

server_port="$(pick_loopback_port)"
[[ "${server_port}" =~ ^[0-9]+$ && "${server_port}" -ge 1024 && "${server_port}" -le 65535 ]] ||
  die "kernel returned an invalid numeric loopback port"
server_url="http://127.0.0.1:${server_port}"

say "Starting an isolated control plane and creating pre-backup state"
start_server "${source_data}" "${work_dir}/source-server.log"

admin_token="$(read_dev_secret "${source_data}/admin.token" "development admin token")"
master_key="$(read_dev_secret "${source_data}/master.key" "development master key")"
{
  printf 'silent\n'
  printf 'show-error\n'
  printf 'fail\n'
  printf 'connect-timeout = 2\n'
  printf 'max-time = 30\n'
  printf 'header = "Authorization: Bearer %s"\n' "${admin_token}"
  printf 'header = "Content-Type: application/json"\n'
  printf 'header = "Accept: application/json"\n'
} >"${bearer_config}"
chmod 0600 "${bearer_config}"

browser_login "${admin_token}" "${work_dir}/browser-login.json"
assert_cookie_jar "${cookie_jar}" "${source_data}/admin.token"
session_id="$(json_scalar "${work_dir}/browser-login.json" session_id)"
require_record_id "${session_id}" "browser session ID"

network_name="backup-restore-smoke"
network_cidr="10.86.240.0/24"
printf '%s\n' "{\"name\":\"${network_name}\",\"cidr\":\"${network_cidr}\"}" >"${work_dir}/network-create-request.json"
api_request POST "/api/v1/networks" "${work_dir}/network-created.json" "${work_dir}/network-create-request.json"
save_expected_network "${work_dir}/network-created.json" "${work_dir}/expected-network.json" "${network_name}" "${network_cidr}"
network_id="$(json_scalar "${work_dir}/expected-network.json" id)"
network_revision="$(json_scalar "${work_dir}/expected-network.json" config_revision)"
require_record_id "${network_id}" "network ID"
require_positive_integer "${network_revision}" "network config revision"

printf '%s\n' '{"name":"backup-smoke-lighthouse","role":"lighthouse","public_endpoint":"127.0.0.1:4242"}' \
  >"${work_dir}/lighthouse-create-request.json"
enrollment_token_file="${work_dir}/lighthouse.enrollment-token"
capture_pending_node "${work_dir}/lighthouse-create-request.json" "${enrollment_token_file}" \
  "${work_dir}/lighthouse-created-sanitized.json" lighthouse
lighthouse_id="$(json_scalar "${work_dir}/lighthouse-created-sanitized.json" node.id)"
require_record_id "${lighthouse_id}" "pending lighthouse ID"
api_request GET "/api/v1/networks/${network_id}/nodes" "${work_dir}/nodes-before-active-enroll.json"
assert_pending_node "${work_dir}/nodes-before-active-enroll.json" "${lighthouse_id}"

say "Enrolling and validating an active member before backup"
active_member_name="backup-smoke-active-member"
printf '%s\n' "{\"name\":\"${active_member_name}\",\"role\":\"member\"}" \
  >"${work_dir}/active-member-create-request.json"
active_member_enrollment_token_file="${work_dir}/active-member.enrollment-token"
capture_pending_node "${work_dir}/active-member-create-request.json" "${active_member_enrollment_token_file}" \
  "${work_dir}/active-member-created-sanitized.json" member
active_member_id="$(json_scalar "${work_dir}/active-member-created-sanitized.json" node.id)"
require_record_id "${active_member_id}" "active member ID"
active_member_root="${work_dir}/active-member"
active_member_state="${active_member_root}/agent/state.json"
active_member_output="${active_member_root}/nebula"
mkdir -p -- "${active_member_root}/agent"
chmod 0700 "${active_member_root}" "${active_member_root}/agent"
MESH_ENROLL_TOKEN= "${meshctl}" enroll \
  --server "${server_url}" \
  --token-file "${active_member_enrollment_token_file}" \
  --state "${active_member_state}" \
  --output "${active_member_output}" \
  --nebula "${nebula}" \
  --nebula-cert "${nebula_cert}" \
  >"${work_dir}/active-member-enroll.log" 2>&1
[[ "$(json_scalar "${active_member_state}" node_id)" == "${active_member_id}" ]] || die "enrolled active member state has the wrong node ID"
[[ "$(json_scalar "${active_member_state}" network_id)" == "${network_id}" ]] || die "enrolled active member state has the wrong network ID"
validate_bundle "${active_member_output}" "${work_dir}/active-member-bundle-validation.log"
api_request GET "/api/v1/networks/${network_id}/nodes" "${work_dir}/nodes-before-backup.json"
assert_pending_node "${work_dir}/nodes-before-backup.json" "${lighthouse_id}"
save_active_node_checkpoint \
  "${work_dir}/nodes-before-backup.json" \
  "${active_member_state}" \
  "${active_member_id}" \
  "${network_id}" \
  "${active_member_name}" \
  "${work_dir}/active-member-before-backup.json"

"${mesh_backup}" keygen --output "${backup_key}" >"${work_dir}/keygen.json" 2>"${work_dir}/keygen.stderr"
[[ "$(json_scalar "${work_dir}/keygen.json" schema)" == "mesh-backup-command-result-v1" ]] || die "backup keygen schema changed"
[[ "$(json_scalar "${work_dir}/keygen.json" status)" == "created" ]] || die "backup keygen did not report creation"
read_dev_secret "${backup_key}" "backup root key" >/dev/null

say "Proving offline locking and encrypted create-only publication"
if MESH_MASTER_KEY="${master_key}" MESH_ADMIN_TOKEN="${admin_token}" \
  "${mesh_backup}" create \
  --data-dir "${source_data}" \
  --key-file "${backup_key}" \
  --output "${archive}" \
  >"${work_dir}/live-create.stdout" 2>"${work_dir}/live-create.stderr"; then
  live_create_status=0
else
  live_create_status=$?
fi
[[ "${live_create_status}" -ne 0 ]] || die "backup creation succeeded while mesh-server held its state locks"
path_absent "${archive}" || die "failed live backup left an output archive"
assert_error_contains "${work_dir}/live-create.stderr" "is locked" "stop mesh-server"

stop_server
snapshot_four "${source_data}" "${work_dir}/source-before-create.hashes.json"

MESH_MASTER_KEY="${master_key}" MESH_ADMIN_TOKEN="${admin_token}" \
  "${mesh_backup}" create \
  --data-dir "${source_data}" \
  --key-file "${backup_key}" \
  --output "${archive}" \
  >"${work_dir}/create.json" 2>"${work_dir}/create.stderr"
backup_id="$(json_scalar "${work_dir}/create.json" backup_id)"
require_backup_id "${backup_id}" "created backup ID"
assert_command_result "${work_dir}/create.json" created "${backup_id}"

"${mesh_backup}" inspect --key-file "${backup_key}" --archive "${archive}" \
  >"${work_dir}/inspect.json" 2>"${work_dir}/inspect.stderr"
assert_command_result "${work_dir}/inspect.json" inspected "${backup_id}"
"${mesh_backup}" verify --key-file "${backup_key}" --archive "${archive}" \
  >"${work_dir}/verify.json" 2>"${work_dir}/verify.stderr"
assert_command_result "${work_dir}/verify.json" verified "${backup_id}"
archive_digest="$(sha256_private_file "${archive}")"
[[ "${archive_digest}" =~ ^[0-9a-f]{64}$ ]] || die "archive digest is not canonical"
assert_no_archive_temporary "${archive}"

snapshot_four "${source_data}" "${work_dir}/source-after-create.hashes.json"
assert_same_snapshot "${work_dir}/source-before-create.hashes.json" "${work_dir}/source-after-create.hashes.json"

if MESH_MASTER_KEY="${master_key}" MESH_ADMIN_TOKEN="${admin_token}" \
  "${mesh_backup}" create \
  --data-dir "${source_data}" \
  --key-file "${backup_key}" \
  --output "${archive}" \
  >"${work_dir}/second-create.stdout" 2>"${work_dir}/second-create.stderr"; then
  second_create_status=0
else
  second_create_status=$?
fi
[[ "${second_create_status}" -ne 0 ]] || die "second backup creation overwrote an existing archive"
assert_error_contains "${work_dir}/second-create.stderr" "already exists" "never overwritten"
[[ "$(sha256_private_file "${archive}")" == "${archive_digest}" ]] || die "refused create changed the published archive"
assert_no_archive_temporary "${archive}"
snapshot_four "${source_data}" "${work_dir}/source-after-refused-create.hashes.json"
assert_same_snapshot "${work_dir}/source-before-create.hashes.json" "${work_dir}/source-after-refused-create.hashes.json"
unset master_key admin_token

say "Proving restore identity fences and create-only targets"
if [[ "${backup_id:0:1}" == "0" ]]; then
  wrong_backup_id="1${backup_id:1}"
else
  wrong_backup_id="0${backup_id:1}"
fi
wrong_target="${work_dir}/wrong-id-target"
wrong_marker="$(marker_path_for "${wrong_target}")"
if "${mesh_backup}" restore \
  --key-file "${backup_key}" \
  --archive "${archive}" \
  --target-dir "${wrong_target}" \
  --expect-backup-id "${wrong_backup_id}" \
  >"${work_dir}/wrong-id-restore.stdout" 2>"${work_dir}/wrong-id-restore.stderr"; then
  wrong_restore_status=0
else
  wrong_restore_status=$?
fi
[[ "${wrong_restore_status}" -ne 0 ]] || die "restore accepted the wrong expected backup ID"
path_absent "${wrong_target}" || die "wrong-ID restore created its target"
path_absent "${wrong_marker}" || die "wrong-ID restore created an incomplete marker"
assert_error_contains "${work_dir}/wrong-id-restore.stderr" "expected backup ID does not match"

"${mesh_backup}" restore \
  --key-file "${backup_key}" \
  --archive "${archive}" \
  --target-dir "${restore_data}" \
  --expect-backup-id "${backup_id}" \
  >"${work_dir}/restore.json" 2>"${work_dir}/restore.stderr"
assert_command_result "${work_dir}/restore.json" restored "${backup_id}"
restore_operation_id="$(json_scalar "${work_dir}/restore.json" operation_id)"
require_operation_id "${restore_operation_id}" "restore operation ID"
[[ "$(json_scalar "${work_dir}/restore.json" target_dir)" == "${restore_data}" ]] || die "restore result target changed"
restore_marker="$(marker_path_for "${restore_data}")"
path_absent "${restore_marker}" || die "successful restore left its incomplete marker"
snapshot_four "${restore_data}" "${work_dir}/restored-four.hashes.json"
assert_same_snapshot "${work_dir}/source-before-create.hashes.json" "${work_dir}/restored-four.hashes.json"
snapshot_restored_tree "${restore_data}" "${work_dir}/restored-before-existing-refusal.hashes.json"

if "${mesh_backup}" restore \
  --key-file "${backup_key}" \
  --archive "${archive}" \
  --target-dir "${restore_data}" \
  --expect-backup-id "${backup_id}" \
  >"${work_dir}/existing-target-restore.stdout" 2>"${work_dir}/existing-target-restore.stderr"; then
  existing_restore_status=0
else
  existing_restore_status=$?
fi
[[ "${existing_restore_status}" -ne 0 ]] || die "restore overwrote an existing target"
assert_error_contains "${work_dir}/existing-target-restore.stderr" "restore target already exists" "overwrite restores are forbidden"
path_absent "${restore_marker}" || die "existing-target refusal left an incomplete marker"
snapshot_restored_tree "${restore_data}" "${work_dir}/restored-after-existing-refusal.hashes.json"
assert_same_snapshot "${work_dir}/restored-before-existing-refusal.hashes.json" "${work_dir}/restored-after-existing-refusal.hashes.json"

say "Proving the crash fence and receipt-validated finalization"
reconstruct_restore_marker "${restore_data}/.mesh-restore-receipt.json" "${restore_data}" "${restore_marker}"
marker_digest="$(sha256_private_file "${restore_marker}")"
snapshot_restored_tree "${restore_data}" "${work_dir}/restored-before-fenced-start.hashes.json"
expect_marker_startup_refusal "${restore_data}" "${work_dir}/fenced-server.log"
[[ "$(sha256_private_file "${restore_marker}")" == "${marker_digest}" ]] || die "refused startup changed the restore marker"
snapshot_restored_tree "${restore_data}" "${work_dir}/restored-after-fenced-start.hashes.json"
assert_same_snapshot "${work_dir}/restored-before-fenced-start.hashes.json" "${work_dir}/restored-after-fenced-start.hashes.json"

"${mesh_backup}" finalize-restore --target-dir "${restore_data}" \
  >"${work_dir}/finalize.json" 2>"${work_dir}/finalize.stderr"
assert_command_result "${work_dir}/finalize.json" finalized "${backup_id}"
[[ "$(json_scalar "${work_dir}/finalize.json" operation_id)" == "${restore_operation_id}" ]] || die "finalization operation identity changed"
path_absent "${restore_marker}" || die "receipt-validated finalization did not remove the marker"
snapshot_restored_tree "${restore_data}" "${work_dir}/restored-after-finalize.hashes.json"
assert_same_snapshot "${work_dir}/restored-before-fenced-start.hashes.json" "${work_dir}/restored-after-finalize.hashes.json"

say "Restarting the restored control plane on the same origin"
start_server "${restore_data}" "${work_dir}/restored-server.log"
browser_get "/api/v1/session" "${work_dir}/restored-session.json"
[[ "$(json_scalar "${work_dir}/restored-session.json" session_id)" == "${session_id}" ]] || die "restored browser session identity changed"
api_request GET "/api/v1/networks" "${work_dir}/restored-networks.json"
assert_network_list "${work_dir}/restored-networks.json" "${work_dir}/expected-network.json"
api_request GET "/api/v1/networks/${network_id}/nodes" "${work_dir}/restored-nodes-before-enroll.json"
assert_pending_node "${work_dir}/restored-nodes-before-enroll.json" "${lighthouse_id}"
assert_active_node_checkpoint \
  "${work_dir}/restored-nodes-before-enroll.json" \
  "${work_dir}/active-member-before-backup.json"

say "Enrolling the pre-backup lighthouse and validating its real Nebula bundle"
lighthouse_root="${work_dir}/lighthouse"
lighthouse_state="${lighthouse_root}/agent/state.json"
lighthouse_output="${lighthouse_root}/nebula"
mkdir -p -- "${lighthouse_root}/agent"
chmod 0700 "${lighthouse_root}" "${lighthouse_root}/agent"
MESH_ENROLL_TOKEN= "${meshctl}" enroll \
  --server "${server_url}" \
  --token-file "${enrollment_token_file}" \
  --state "${lighthouse_state}" \
  --output "${lighthouse_output}" \
  --nebula "${nebula}" \
  --nebula-cert "${nebula_cert}" \
  >"${work_dir}/lighthouse-enroll.log" 2>&1
[[ "$(json_scalar "${lighthouse_state}" node_id)" == "${lighthouse_id}" ]] || die "enrolled lighthouse state has the wrong node ID"
[[ "$(json_scalar "${lighthouse_state}" network_id)" == "${network_id}" ]] || die "enrolled lighthouse state has the wrong network ID"
validate_bundle "${lighthouse_output}" "${work_dir}/bundle-validation.log"

snapshot_four "${source_data}" "${work_dir}/source-final.hashes.json"
assert_same_snapshot "${work_dir}/source-before-create.hashes.json" "${work_dir}/source-final.hashes.json"
assert_no_known_credentials_in_diagnostics \
  "${source_data}/admin.token" \
  "${source_data}/master.key" \
  "${enrollment_token_file}" \
  "${active_member_enrollment_token_file}" \
  "${backup_key}" \
  "${cookie_jar}"

stop_server
say "Backup/restore smoke passed: offline capture, encrypted no-clobber archive, fenced restore, session and active-certificate continuity, and real Nebula enrollment verified."
