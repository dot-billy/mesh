#!/usr/bin/env bash
set -euo pipefail

image="${MESH_HELM_SMOKE_IMAGE:-mesh-control-plane:helm-contract-verified}"
command -v docker >/dev/null 2>&1 || { echo "helm-runtime-smoke: docker is required" >&2; exit 77; }
command -v openssl >/dev/null 2>&1 || { echo "helm-runtime-smoke: openssl is required" >&2; exit 77; }
command -v curl >/dev/null 2>&1 || { echo "helm-runtime-smoke: curl is required" >&2; exit 77; }
docker image inspect "${image}" >/dev/null 2>&1 || { echo "helm-runtime-smoke: image ${image} is unavailable" >&2; exit 77; }

runtime_uid="$(id -u)"
runtime_gid="$(id -g)"
work_dir="$(mktemp -d)"
container_name="mesh-helm-runtime-smoke-$RANDOM-$$"

cleanup() {
  docker rm -f "${container_name}" >/dev/null 2>&1 || true
  rm -rf -- "${work_dir}"
}
trap cleanup EXIT

credentials_root="${work_dir}/credentials"
tls_root="${work_dir}/tls"
output_root="${work_dir}/prepared"
data_root="${work_dir}/data"
revision="..2026_07_21_00_00_00.000000000"
install -d -m 0755 "${credentials_root}" "${tls_root}" "${output_root}" "${data_root}"
install -d -m 0700 "${credentials_root}/${revision}" "${tls_root}/${revision}"

openssl rand -base64 32 | tr '/+' '_-' | tr -d '=\n' >"${credentials_root}/${revision}/admin.token"
printf '\n' >>"${credentials_root}/${revision}/admin.token"
openssl rand -base64 32 | tr '/+' '_-' | tr -d '=\n' >"${credentials_root}/${revision}/master.key"
printf '\n' >>"${credentials_root}/${revision}/master.key"
chmod 0400 "${credentials_root}/${revision}/admin.token" "${credentials_root}/${revision}/master.key"

openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
  -subj '/CN=mesh.example.test' \
  -addext 'subjectAltName=DNS:mesh.example.test' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -keyout "${tls_root}/${revision}/tls.key" \
  -out "${tls_root}/${revision}/tls.crt" >/dev/null 2>&1
cp -- "${tls_root}/${revision}/tls.crt" "${tls_root}/${revision}/ca.crt"
chmod 0400 "${tls_root}/${revision}/tls.key"
chmod 0444 "${tls_root}/${revision}/tls.crt" "${tls_root}/${revision}/ca.crt"

for root in "${credentials_root}" "${tls_root}"; do
  ln -s "${revision}" "${root}/..data"
done
for name in admin.token master.key; do
  ln -s "..data/${name}" "${credentials_root}/${name}"
done
for name in tls.crt tls.key ca.crt; do
  ln -s "..data/${name}" "${tls_root}/${name}"
done

docker run --rm \
  --user 0:0 \
  --cap-drop ALL \
  --cap-add CHOWN \
  --cap-add DAC_OVERRIDE \
  --cap-add FOWNER \
  --security-opt no-new-privileges:true \
  --read-only \
  --entrypoint /usr/local/bin/mesh-kube-init \
  -v "${credentials_root}:/input/credentials:ro" \
  -v "${tls_root}:/input/tls:ro" \
  -v "${output_root}:/prepared" \
  -v "${data_root}:/data" \
  "${image}" \
  --credentials-source-dir=/input/credentials \
  --tls-source-dir=/input/tls \
  --output-root=/prepared \
  --data-dir=/data \
  --tls-server-name=mesh.example.test \
  --runtime-uid="${runtime_uid}" \
  --runtime-gid="${runtime_gid}"

python3 - "${output_root}/private" "${runtime_uid}" "${runtime_gid}" <<'PY'
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
uid = int(sys.argv[2])
gid = int(sys.argv[3])
expected = {
    "admin.token": 0o400,
    "master.key": 0o400,
    "server.crt": 0o444,
    "server.key": 0o400,
    "ca.crt": 0o444,
}
if sorted(item.name for item in root.iterdir()) != sorted(expected):
    raise SystemExit("materialized private inventory mismatch")
for name, mode in expected.items():
    info = (root / name).lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != mode:
        raise SystemExit(f"unsafe materialized metadata for {name}")
    if info.st_uid != uid or info.st_gid != gid or info.st_nlink != 1:
        raise SystemExit(f"unsafe materialized ownership for {name}")
PY

docker run -d \
  --name "${container_name}" \
  --user "${runtime_uid}:${runtime_gid}" \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777 \
  -v "${output_root}:/run/mesh:ro" \
  -v "${data_root}:/var/lib/mesh" \
  -p 127.0.0.1::8443 \
  "${image}" \
  --listen=0.0.0.0:8443 \
  --public-url=https://mesh.example.test \
  --tls-cert=/run/mesh/private/server.crt \
  --tls-key=/run/mesh/private/server.key \
  --admin-token-file=/run/mesh/private/admin.token \
  --master-key-file=/run/mesh/private/master.key \
  --data-dir=/var/lib/mesh >/dev/null

published="$(docker port "${container_name}" 8443/tcp)"
port="${published##*:}"
[[ "${port}" =~ ^[0-9]+$ ]] || { echo "helm-runtime-smoke: Docker returned an invalid port" >&2; exit 1; }

ready=""
for _ in $(seq 1 30); do
  if ready="$(curl --silent --show-error --fail \
      --resolve "mesh.example.test:${port}:127.0.0.1" \
      --cacert "${tls_root}/${revision}/ca.crt" \
      "https://mesh.example.test:${port}/readyz" 2>/dev/null)"; then
    break
  fi
  if ! docker inspect "${container_name}" --format '{{.State.Running}}' 2>/dev/null | grep -Fxq true; then
    docker logs "${container_name}" >&2 || true
    echo "helm-runtime-smoke: control plane exited before readiness" >&2
    exit 1
  fi
  sleep 1
done
[[ "${ready}" == '{"status":"ready"}' ]] || {
  docker logs "${container_name}" >&2 || true
  echo "helm-runtime-smoke: verified TLS readiness did not converge" >&2
  exit 1
}

docker stop --time 15 "${container_name}" >/dev/null
for required in state.json identity-state.json runtime-telemetry.json; do
  test -s "${data_root}/${required}" || {
    echo "helm-runtime-smoke: durable state is missing ${required}" >&2
    exit 1
  }
done

echo "helm runtime smoke passed"
