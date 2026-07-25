#!/usr/bin/env bash
set -Eeuo pipefail

readonly script_name="$(basename "$0")"
readonly repository_root="$(cd "$(dirname "$0")/.." && pwd -P)"
readonly compose_file="${repository_root}/packaging/origin/compose.yaml"
readonly compose_build_file="${repository_root}/packaging/origin/compose.build.yaml"
readonly registry_base_image="registry:2"

work_dir=""
project_name=""
container_id=""
registry_container_name=""
registry_image=""
runtime_image=""

say() { printf '%s\n' "$*"; }
skip() { printf 'SKIP: %s\n' "$*" >&2; exit 77; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

production_compose() {
  docker compose \
    --project-name "${project_name}" \
    --file "${compose_file}" "$@"
}

build_compose() {
  BUILDX_CONFIG="${work_dir}/buildx" docker compose \
    --project-name "${project_name}" \
    --file "${compose_file}" \
    --file "${compose_build_file}" "$@"
}

cleanup() {
  local status=$?
  trap - EXIT ERR HUP INT TERM
  if [[ -n "${project_name}" && -n "${work_dir}" ]]; then
    production_compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  if [[ -n "${registry_container_name}" ]]; then
    docker container rm --force "${registry_container_name}" >/dev/null 2>&1 || true
  fi
  for image in "${runtime_image}" "${registry_image}" "${MESH_ORIGIN_BUILD_IMAGE:-}"; do
    if [[ -n "${image}" ]]; then
      docker image rm --force "${image}" >/dev/null 2>&1 || true
    fi
  done
  case "${work_dir}" in
    /tmp/mesh-release-origin-smoke.*)
      if [[ -d "${work_dir}/generations" ]]; then
        chmod -R u+rwX -- "${work_dir}/generations" 2>/dev/null || true
      fi
      rm -rf -- "${work_dir}"
      ;;
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
    production_compose logs --no-color --tail 80 >&2 2>/dev/null || true
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
  container_id="$(production_compose ps --quiet origin)"
  [[ -n "${container_id}" ]] || die "Compose did not create the origin container"
  for poll in {1..160}; do
    health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "${container_id}")"
    case "${health}" in
      healthy) return ;;
      unhealthy) die "release origin readiness became unhealthy" ;;
      starting) ;;
      *) die "unexpected release origin health state ${health}" ;;
    esac
    sleep 0.25
  done
  die "release origin did not become ready within forty seconds"
}

trap cleanup EXIT
trap 'on_error "${LINENO}"' ERR
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

command -v docker >/dev/null 2>&1 || skip "Docker is unavailable"
docker info >/dev/null 2>&1 || skip "Docker daemon is unavailable"
docker compose version >/dev/null 2>&1 || skip "Docker Compose is unavailable"
docker image inspect "${registry_base_image}" >/dev/null 2>&1 || skip "cached ${registry_base_image} is unavailable"
for command in openssl curl python3 go sha256sum tar; do
  command -v "${command}" >/dev/null 2>&1 || skip "${command} is unavailable"
done
unset MESH_ORIGIN_IMAGE MESH_ORIGIN_IMAGE_REPOSITORY MESH_ORIGIN_IMAGE_SHA256 MESH_ORIGIN_BUILD_IMAGE

work_dir="$(mktemp -d /tmp/mesh-release-origin-smoke.XXXXXX)"
project_name="mesh-release-origin-smoke-$$"
install -d -m 0700 \
  "${work_dir}/buildx" "${work_dir}/keys" "${work_dir}/metadata" \
  "${work_dir}/repository/bootstrap/stable" \
  "${work_dir}/repository/channels/stable" "${work_dir}/repository/releases/1.0.0" \
  "${work_dir}/generations" "${work_dir}/tls" "${work_dir}/tools"
umask 077

mesh_release="${work_dir}/tools/mesh-release"
mesh_package="${work_dir}/tools/mesh-package"
mesh_origin_audit="${work_dir}/tools/mesh-origin-audit"
mesh_origin_image_verify="${work_dir}/tools/mesh-origin-image-verify"
mesh_origin_runtime_verify="${work_dir}/tools/mesh-origin-runtime-verify"
smoke_client="${work_dir}/tools/mesh-origin-smokeclient"
go build -buildvcs=false -trimpath -o "${mesh_release}" ./cmd/mesh-release
go build -buildvcs=false -trimpath -o "${mesh_package}" ./cmd/mesh-package
go build -buildvcs=false -trimpath -o "${mesh_origin_audit}" ./cmd/mesh-origin-audit
go build -buildvcs=false -trimpath -o "${mesh_origin_image_verify}" ./cmd/mesh-origin-image-verify
go build -buildvcs=false -trimpath -o "${mesh_origin_runtime_verify}" ./cmd/mesh-origin-runtime-verify
go build -buildvcs=false -trimpath -o "${smoke_client}" ./internal/releaseorigin/smokeclient

for key in root-a root-b release-a release-b; do
  "${mesh_release}" generate-key --private "${work_dir}/keys/${key}.private.json" >/dev/null
  "${mesh_release}" export-public \
    --private "${work_dir}/keys/${key}.private.json" \
    --public "${work_dir}/keys/${key}.public.json" >/dev/null
done

issued_at="$(date -u -d '-1 minute' '+%Y-%m-%dT%H:%M:%SZ')"
verification_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
release_expires="$(date -u -d '+1 hour' '+%Y-%m-%dT%H:%M:%SZ')"
root_expires="$(date -u -d '+30 days' '+%Y-%m-%dT%H:%M:%SZ')"
"${mesh_release}" create-root \
  --output "${work_dir}/metadata/root-v1.json" \
  --channel stable \
  --release-epoch 1 \
  --minimum-release-sequence 1 \
  --minimum-security-floor 1 \
  --issued "${issued_at}" \
  --expires "${root_expires}" \
  --root-threshold 2 \
  --root-public "${work_dir}/keys/root-a.public.json" \
  --root-public "${work_dir}/keys/root-b.public.json" \
  --release-threshold 2 \
  --release-public "${work_dir}/keys/release-a.public.json" \
  --release-public "${work_dir}/keys/release-b.public.json" >/dev/null

cp -- "${work_dir}/metadata/root-v1.json" \
  "${work_dir}/repository/bootstrap/stable/root-v1.json"

architecture="$(go env GOARCH)"
[[ "${architecture}" == "amd64" || "${architecture}" == "arm64" ]] || skip "unsupported Linux origin-smoke architecture ${architecture}"
source_epoch="$(date -u -d "${issued_at}" '+%s')"
build_identity="$("${mesh_release}" build-identity \
  --version 1.0.0 \
  --commit 1111111111111111111111111111111111111111 \
  --build-time "${issued_at}" \
  --security-floor 1 \
  --agent-state-read-min 2 \
  --agent-state-read-max 2 \
  --agent-state-write-version 2)"
[[ "${build_identity}" != *[[:space:]]* ]] || die "compiled build identity frame is not canonical"
authenticode_policy="$("${mesh_release}" windows-authenticode-policy \
  --mesh-signer-spki-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --wintun-signer-spki-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)"
[[ "${authenticode_policy}" != *[[:space:]]* ]] || die "compiled Windows Authenticode policy frame is not canonical"

say "Building the independently authenticated Linux and Windows verifier packages and root-authorized installer courier set"
for verifier_os in linux windows; do
  for verifier_arch in amd64 arm64; do
    verifier_suffix=""
    if [[ "${verifier_os}" == "windows" ]]; then
      verifier_suffix=".exe"
    fi
    verifier_ldflags="-buildid= -X mesh/internal/buildinfo.Identity=${build_identity}"
    if [[ "${verifier_os}" == "windows" ]]; then
      verifier_ldflags+=" -X mesh/internal/windowsauthenticode.Identity=${authenticode_policy}"
    fi
    CGO_ENABLED=0 GOOS="${verifier_os}" GOARCH="${verifier_arch}" go build \
      -trimpath -buildvcs=false \
      "-ldflags=${verifier_ldflags}" \
      -o "${work_dir}/tools/mesh-bootstrap-verify-${verifier_os}-${verifier_arch}${verifier_suffix}" ./cmd/mesh-bootstrap-verify
    "${mesh_package}" build-bootstrap-verifier \
      --version 1.0.0 \
      --commit 1111111111111111111111111111111111111111 \
      --source-date-epoch "${source_epoch}" \
      --security-floor 1 \
      --os "${verifier_os}" \
      --arch "${verifier_arch}" \
      --verifier "${work_dir}/tools/mesh-bootstrap-verify-${verifier_os}-${verifier_arch}${verifier_suffix}" \
      --output "${work_dir}/repository/bootstrap/stable/mesh-bootstrap-verifier-${verifier_os}-${verifier_arch}.tar" >/dev/null
  done
done
"${mesh_release}" create-bootstrap-handoff \
  --output "${work_dir}/repository/bootstrap/stable/bootstrap-handoff.json" \
  --root "${work_dir}/repository/bootstrap/stable/root-v1.json" \
  --issued "${verification_at}" \
  --expires "${release_expires}" \
  --verifier-package "${work_dir}/repository/bootstrap/stable/mesh-bootstrap-verifier-linux-amd64.tar" \
  --verifier-package "${work_dir}/repository/bootstrap/stable/mesh-bootstrap-verifier-linux-arm64.tar" \
  --verifier-package "${work_dir}/repository/bootstrap/stable/mesh-bootstrap-verifier-windows-amd64.tar" \
  --verifier-package "${work_dir}/repository/bootstrap/stable/mesh-bootstrap-verifier-windows-arm64.tar" >/dev/null
handoff_sha_before="$(sha256sum -- "${work_dir}/repository/bootstrap/stable/bootstrap-handoff.json" | awk '{print $1}')"
if "${mesh_release}" create-bootstrap-handoff \
  --output "${work_dir}/repository/bootstrap/stable/bootstrap-handoff.json" \
  --root "${work_dir}/repository/bootstrap/stable/root-v1.json" \
  --issued "${verification_at}" --expires "${release_expires}" \
  --verifier-package "${work_dir}/repository/bootstrap/stable/mesh-bootstrap-verifier-linux-amd64.tar" \
  --verifier-package "${work_dir}/repository/bootstrap/stable/mesh-bootstrap-verifier-linux-arm64.tar" \
  --verifier-package "${work_dir}/repository/bootstrap/stable/mesh-bootstrap-verifier-windows-amd64.tar" \
  --verifier-package "${work_dir}/repository/bootstrap/stable/mesh-bootstrap-verifier-windows-arm64.tar" >/dev/null 2>&1; then
  die "bootstrap handoff author overwrote an existing record"
fi
[[ "$(sha256sum -- "${work_dir}/repository/bootstrap/stable/bootstrap-handoff.json" | awk '{print $1}')" == "${handoff_sha_before}" ]] || die "failed handoff overwrite changed the existing record"
"${mesh_release}" create-bootstrap-anchor \
  --handoff "${work_dir}/repository/bootstrap/stable/bootstrap-handoff.json" \
  --output "${work_dir}/metadata/bootstrap-anchor.json" >/dev/null
anchor_sha_before="$(sha256sum -- "${work_dir}/metadata/bootstrap-anchor.json" | awk '{print $1}')"
if "${mesh_release}" create-bootstrap-anchor \
  --handoff "${work_dir}/repository/bootstrap/stable/bootstrap-handoff.json" \
  --output "${work_dir}/metadata/bootstrap-anchor.json" >/dev/null 2>&1; then
  die "bootstrap anchor author overwrote the independently transferable record"
fi
[[ "$(sha256sum -- "${work_dir}/metadata/bootstrap-anchor.json" | awk '{print $1}')" == "${anchor_sha_before}" ]] || die "failed anchor overwrite changed the existing record"
ln -s -- "${work_dir}/repository/bootstrap/stable/bootstrap-handoff.json" "${work_dir}/metadata/bootstrap-handoff.link"
if "${mesh_release}" create-bootstrap-anchor \
  --handoff "${work_dir}/metadata/bootstrap-handoff.link" \
  --output "${work_dir}/metadata/linked-input-anchor.json" >/dev/null 2>&1; then
  die "bootstrap anchor author accepted a symlinked handoff"
fi
[[ ! -e "${work_dir}/metadata/linked-input-anchor.json" ]] || die "rejected linked-input anchor was published"
rm -f -- "${work_dir}/metadata/bootstrap-handoff.link"
if "${mesh_release}" create-bootstrap-handoff \
  --output "${work_dir}/metadata/duplicate-arch-handoff.json" \
  --root "${work_dir}/repository/bootstrap/stable/root-v1.json" \
  --issued "${verification_at}" --expires "${release_expires}" \
  --verifier-package "${work_dir}/repository/bootstrap/stable/mesh-bootstrap-verifier-linux-amd64.tar" \
  --verifier-package "${work_dir}/repository/bootstrap/stable/mesh-bootstrap-verifier-linux-amd64.tar" \
  --verifier-package "${work_dir}/repository/bootstrap/stable/mesh-bootstrap-verifier-windows-amd64.tar" \
  --verifier-package "${work_dir}/repository/bootstrap/stable/mesh-bootstrap-verifier-windows-arm64.tar" >/dev/null 2>&1; then
  die "bootstrap handoff accepted duplicate architecture packages"
fi
[[ ! -e "${work_dir}/metadata/duplicate-arch-handoff.json" ]] || die "rejected duplicate-architecture handoff was published"
ln -s -- "${work_dir}/repository/bootstrap/stable/mesh-bootstrap-verifier-linux-arm64.tar" "${work_dir}/metadata/verifier-package.link"
if "${mesh_release}" create-bootstrap-handoff \
  --output "${work_dir}/metadata/linked-input-handoff.json" \
  --root "${work_dir}/repository/bootstrap/stable/root-v1.json" \
  --issued "${verification_at}" --expires "${release_expires}" \
  --verifier-package "${work_dir}/repository/bootstrap/stable/mesh-bootstrap-verifier-linux-amd64.tar" \
  --verifier-package "${work_dir}/metadata/verifier-package.link" \
  --verifier-package "${work_dir}/repository/bootstrap/stable/mesh-bootstrap-verifier-windows-amd64.tar" \
  --verifier-package "${work_dir}/repository/bootstrap/stable/mesh-bootstrap-verifier-windows-arm64.tar" >/dev/null 2>&1; then
  die "bootstrap handoff accepted a symlinked verifier package"
fi
[[ ! -e "${work_dir}/metadata/linked-input-handoff.json" ]] || die "rejected linked-input handoff was published"
rm -f -- "${work_dir}/metadata/verifier-package.link"

installer_policy="$("${mesh_release}" installer-policy \
  --root "${work_dir}/repository/bootstrap/stable/root-v1.json")"
[[ "${installer_policy}" != *[[:space:]]* ]] || die "compiled installer policy frame is not canonical"
CGO_ENABLED=0 GOOS=linux GOARCH="${architecture}" go build \
  -trimpath -buildvcs=false \
  "-ldflags=-s -w -buildid= -X mesh/internal/buildinfo.Identity=${build_identity} -X mesh/internal/installtrust.Identity=${installer_policy}" \
  -o "${work_dir}/repository/bootstrap/stable/mesh-install-linux-${architecture}" ./cmd/mesh-install
"${mesh_release}" create-bootstrap-manifest \
  --output "${work_dir}/repository/bootstrap/stable/mesh-install.bootstrap.json" \
  --root "${work_dir}/repository/bootstrap/stable/root-v1.json" \
  --installer "${work_dir}/repository/bootstrap/stable/mesh-install-linux-${architecture}" \
  --arch "${architecture}" \
  --issued "${verification_at}" \
  --expires "${release_expires}" >/dev/null
for signer in a b; do
  "${mesh_release}" sign \
    --private "${work_dir}/keys/root-${signer}.private.json" \
    --manifest "${work_dir}/repository/bootstrap/stable/mesh-install.bootstrap.json" \
    --signature "${work_dir}/repository/bootstrap/stable/mesh-install.bootstrap.root-${signer}.json" >/dev/null
done

independent_anchor_sha="$(sha256sum -- "${work_dir}/metadata/bootstrap-anchor.json" | awk '{print $1}')"
independent_handoff_sha="$(python3 - "${work_dir}/metadata/bootstrap-anchor.json" "${verification_at}" <<'PY'
import json
import pathlib
import sys

raw = pathlib.Path(sys.argv[1]).read_bytes()
anchor = json.loads(raw)
assert raw.endswith(b"\n") and raw.count(b"\n") == 1
assert anchor["schema"] == "mesh-bootstrap-anchor-v2"
assert anchor["channel"] == "stable"
assert anchor["handoff"]["name"] == "bootstrap-handoff.json"
assert anchor["handoff"]["issued_at"] == sys.argv[2]
assert anchor["root"]["name"] == "root-v1.json"
assert anchor["root"]["version"] == 1 and anchor["root"]["release_epoch"] == 1
assert anchor["build"] == {"version": "1.0.0", "commit": "1" * 40, "security_floor": 1}
assert [(item["os"], item["arch"]) for item in anchor["verifiers"]] == [
    ("linux", "amd64"), ("linux", "arm64"),
    ("windows", "amd64"), ("windows", "arm64"),
]
print(anchor["handoff"]["sha256"])
PY
)"
[[ "${independent_anchor_sha}" =~ ^[0-9a-f]{64}$ && "${independent_handoff_sha}" =~ ^[0-9a-f]{64}$ ]] || die "independent bootstrap anchor authority is not canonical"

printf 'threshold-authenticated release-origin artifact\n' \
  >"${work_dir}/repository/releases/1.0.0/mesh-linux-bundle.tar"
chmod 0644 "${work_dir}/repository/releases/1.0.0/mesh-linux-bundle.tar"

port="$(pick_loopback_port)"
[[ "${port}" =~ ^[0-9]+$ && "${port}" -ge 1024 && "${port}" -le 65535 ]] || die "kernel returned an invalid port"
origin_url="https://127.0.0.1:${port}"

"${mesh_release}" create-release-manifest \
  --output "${work_dir}/repository/releases/1.0.0/release.json" \
  --root "${work_dir}/metadata/root-v1.json" \
  --version 1.0.0 \
  --sequence 1 \
  --security-floor 1 \
  --issued "${issued_at}" \
  --expires "${release_expires}" \
  --os linux \
  --arch "${architecture}" \
  --artifact-url "${origin_url}/releases/1.0.0/mesh-linux-bundle.tar" \
  --test-only-allow-unscanned-linux-artifact \
  --artifact "${work_dir}/repository/releases/1.0.0/mesh-linux-bundle.tar" >/dev/null

"${mesh_release}" create-channel-manifest \
  --output "${work_dir}/metadata/channel.json" \
  --root "${work_dir}/metadata/root-v1.json" \
  --release-manifest "${work_dir}/repository/releases/1.0.0/release.json" \
  --manifest-url "${origin_url}/releases/1.0.0/release.json" \
  --issued "${issued_at}" \
  --expires "${release_expires}" >/dev/null

for signer in a b; do
  "${mesh_release}" sign \
    --private "${work_dir}/keys/release-${signer}.private.json" \
    --manifest "${work_dir}/repository/releases/1.0.0/release.json" \
    --signature "${work_dir}/metadata/release-${signer}.signature.json" >/dev/null
  "${mesh_release}" sign \
    --private "${work_dir}/keys/release-${signer}.private.json" \
    --manifest "${work_dir}/metadata/channel.json" \
    --signature "${work_dir}/metadata/channel-${signer}.signature.json" >/dev/null
done

"${mesh_release}" assemble-online-bundle \
  --output "${work_dir}/repository/channels/stable/bundle.json" \
  --channel-manifest "${work_dir}/metadata/channel.json" \
  --channel-signature "${work_dir}/metadata/channel-a.signature.json" \
  --channel-signature "${work_dir}/metadata/channel-b.signature.json" \
  --release-manifest "${work_dir}/repository/releases/1.0.0/release.json" \
  --release-signature "${work_dir}/metadata/release-a.signature.json" \
  --release-signature "${work_dir}/metadata/release-b.signature.json" >/dev/null

"${mesh_release}" create-origin-index \
  --root "${work_dir}/repository" \
  --output "${work_dir}/origin-index.json" \
  --object /bootstrap/stable/bootstrap-handoff.json \
  --object /bootstrap/stable/mesh-bootstrap-verifier-linux-amd64.tar \
  --object /bootstrap/stable/mesh-bootstrap-verifier-linux-arm64.tar \
  --object /bootstrap/stable/mesh-bootstrap-verifier-windows-amd64.tar \
  --object /bootstrap/stable/mesh-bootstrap-verifier-windows-arm64.tar \
  --object /bootstrap/stable/mesh-install-linux-${architecture} \
  --object /bootstrap/stable/mesh-install.bootstrap.json \
  --object /bootstrap/stable/mesh-install.bootstrap.root-a.json \
  --object /bootstrap/stable/mesh-install.bootstrap.root-b.json \
  --object /bootstrap/stable/root-v1.json \
  --object /channels/stable/bundle.json \
  --object /releases/1.0.0/release.json \
  --object /releases/1.0.0/mesh-linux-bundle.tar >/dev/null

generation_id="$(sha256sum -- "${work_dir}/origin-index.json" | awk '{print $1}')"
[[ "${generation_id}" =~ ^[0-9a-f]{64}$ ]] || die "origin generation identity was not canonical"
generation_path="${work_dir}/generations/${generation_id}"
published_repository="${generation_path}/repository"
"${mesh_release}" publish-origin-generation \
  --source-root "${work_dir}/repository" \
  --index "${work_dir}/origin-index.json" \
  --generations-root "${work_dir}/generations" >/dev/null
"${mesh_release}" inspect-origin-generation --generation "${generation_path}" >/dev/null
if "${mesh_release}" publish-origin-generation \
  --source-root "${work_dir}/repository" \
  --index "${work_dir}/origin-index.json" \
  --generations-root "${work_dir}/generations" >/dev/null 2>&1; then
  die "origin generation publication replaced an existing generation"
fi
if find "${work_dir}/generations" -mindepth 1 -maxdepth 1 -type d -name '.mesh-origin-generation.*' -print -quit | grep -q .; then
  die "failed duplicate generation publication left staging residue"
fi

printf 'candidate generation only\n' >"${work_dir}/repository/releases/1.0.0/origin-generation-marker"
"${mesh_release}" create-origin-index \
  --root "${work_dir}/repository" \
  --output "${work_dir}/candidate-origin-index.json" \
  --object /bootstrap/stable/bootstrap-handoff.json \
  --object /bootstrap/stable/mesh-bootstrap-verifier-linux-amd64.tar \
  --object /bootstrap/stable/mesh-bootstrap-verifier-linux-arm64.tar \
  --object /bootstrap/stable/mesh-bootstrap-verifier-windows-amd64.tar \
  --object /bootstrap/stable/mesh-bootstrap-verifier-windows-arm64.tar \
  --object /bootstrap/stable/mesh-install-linux-${architecture} \
  --object /bootstrap/stable/mesh-install.bootstrap.json \
  --object /bootstrap/stable/mesh-install.bootstrap.root-a.json \
  --object /bootstrap/stable/mesh-install.bootstrap.root-b.json \
  --object /bootstrap/stable/root-v1.json \
  --object /channels/stable/bundle.json \
  --object /releases/1.0.0/release.json \
  --object /releases/1.0.0/mesh-linux-bundle.tar \
  --object /releases/1.0.0/origin-generation-marker >/dev/null
candidate_generation_id="$(sha256sum -- "${work_dir}/candidate-origin-index.json" | awk '{print $1}')"
[[ "${candidate_generation_id}" =~ ^[0-9a-f]{64}$ && "${candidate_generation_id}" != "${generation_id}" ]] || die "candidate origin generation identity was not distinct and canonical"
candidate_generation_path="${work_dir}/generations/${candidate_generation_id}"
"${mesh_release}" publish-origin-generation \
  --source-root "${work_dir}/repository" \
  --index "${work_dir}/candidate-origin-index.json" \
  --generations-root "${work_dir}/generations" >/dev/null
"${mesh_release}" inspect-origin-generation --generation "${candidate_generation_path}" >/dev/null

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
  -subj '/CN=127.0.0.1' \
  -addext 'subjectAltName=IP:127.0.0.1' \
  -keyout "${work_dir}/tls/server.key" \
  -out "${work_dir}/tls/server.crt" >/dev/null 2>&1
cp -- "${work_dir}/tls/server.crt" "${work_dir}/tls/ca.crt"
chmod 0600 "${work_dir}/tls/server.key"
chmod 0644 "${work_dir}/tls/server.crt" "${work_dir}/tls/ca.crt"

export MESH_ORIGIN_UID="$(id -u)"
export MESH_ORIGIN_GID="$(id -g)"
export MESH_ORIGIN_BIND="127.0.0.1"
export MESH_ORIGIN_PORT="${port}"
export MESH_ORIGIN_PUBLIC_URL="${origin_url}"
export MESH_ORIGIN_PUBLIC_HOST="127.0.0.1"
export MESH_ORIGIN_GENERATION="${generation_path}"
export MESH_ORIGIN_TLS_CERT="${work_dir}/tls/server.crt"
export MESH_ORIGIN_TLS_KEY="${work_dir}/tls/server.key"
export MESH_ORIGIN_TLS_CA="${work_dir}/tls/ca.crt"

say "Proving production Compose fails closed without exact image identity"
if docker compose --project-name "${project_name}" --file "${compose_file}" config --quiet \
  >"${work_dir}/missing-image.stdout" 2>"${work_dir}/missing-image.stderr"; then
  die "production Compose accepted a missing image repository and digest"
fi
[[ ! -s "${work_dir}/missing-image.stdout" && -s "${work_dir}/missing-image.stderr" ]] || die "missing production image identity did not fail closed"

export MESH_ORIGIN_IMAGE_REPOSITORY="registry.invalid/mesh-release-origin"
export MESH_ORIGIN_IMAGE_SHA256="0000000000000000000000000000000000000000000000000000000000000000"
export MESH_ORIGIN_BUILD_IMAGE="mesh-release-origin:smoke-$$"
say "Proving the production Compose contract has one digest-pinned image and no build"
docker compose \
  --project-name "${project_name}" \
  --file "${compose_file}" \
  config --format json >"${work_dir}/production-contract.json"
python3 - "${work_dir}/production-contract.json" \
  "${MESH_ORIGIN_IMAGE_REPOSITORY}@sha256:${MESH_ORIGIN_IMAGE_SHA256}" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
origin = document["services"]["origin"]
assert origin["image"] == sys.argv[2]
assert "build" not in origin
PY

say "Validating and building the read-only origin through the local-only override"
build_compose config --quiet
build_compose config --format json >"${work_dir}/build-compose.json"
python3 - "${work_dir}/build-compose.json" "${MESH_ORIGIN_BUILD_IMAGE}" <<'PY'
import json
import pathlib
import sys

origin = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["services"]["origin"]
assert origin["image"] == sys.argv[2]
assert origin["build"]["dockerfile"].endswith("packaging/origin/Dockerfile")
PY
build_compose build --quiet

say "Producing a test-only image-security receipt to exercise runtime custody binding"
security_image_id="$(docker image inspect --format '{{.Id}}' "${MESH_ORIGIN_BUILD_IMAGE}")"
[[ "${security_image_id}" =~ ^sha256:[0-9a-f]{64}$ ]] || die "Docker returned an invalid built origin image ID"
python3 - "${work_dir}/origin-image-security.json" "${security_image_id}" <<'PY'
import datetime as dt
import hashlib
import json
import pathlib
import sys

def digest(label):
    return hashlib.sha256(label.encode("utf-8")).hexdigest()

def record(label, size):
    return {"sha256": digest(label), "size": size}

empty_file = hashlib.sha256(b"").hexdigest()
empty_gitleaks = hashlib.sha256(b"[]\n").hexdigest()
receipt = {
    "image": {
        "archive": record("test-only origin image archive", 2 * 1024 * 1024),
        "config_digest": digest("test-only origin config"),
        "docker_image_id": sys.argv[2],
        "files": {
            "etc/ssl/certs/ca-certificates.crt": record("test-only CA bundle", 128 * 1024),
            "run/origin/index.json": {"sha256": empty_file, "size": 0},
            "run/tls/ca.crt": {"sha256": empty_file, "size": 0},
            "run/tls/server.crt": {"sha256": empty_file, "size": 0},
            "run/tls/server.key": {"sha256": empty_file, "size": 0},
            "usr/local/bin/mesh-healthcheck": record("test-only healthcheck", 2 * 1024 * 1024),
            "usr/local/bin/mesh-origin": record("test-only origin", 2 * 1024 * 1024),
        },
        "filesystem_entry_count": 18,
        "platform": "linux/amd64",
        "schema": "mesh-origin-image-archive-evidence-v1",
    },
    "sbom": {
        "spdx_json": record("test-only SPDX", 1024),
        "spdx_package_count": 6,
        "spdx_version": "SPDX-2.3",
        "syft_json": record("test-only Syft", 1024),
        "syft_package_count": 5,
        "syft_schema": "16.1.3",
        "syft_version": "1.44.0",
    },
    "scanner_boundary": {
        "database_update": "networked scanner with only an empty private database cache mounted",
        "image_archive_and_scan": "networkless, read-only, non-root, capability-free containers without a Docker socket",
    },
    "schema": "mesh-origin-image-security-receipt-v1",
    "secret_scan": {
        "binary_strings_report": {"sha256": empty_gitleaks, "size": 3},
        "gitleaks_version": "v8.30.1",
        "policy": "default rules over exact origin rootfs text and both binaries' strings; only the exact public oauth2 v0.36.0 Go checksum is allowlisted",
        "rootfs_report": {"sha256": empty_gitleaks, "size": 3},
    },
    "verified_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "vulnerability_scan": {
        "counts_by_severity": {},
        "database_built": "2026-07-21T07:05:18Z",
        "database_schema": "v6.1.9",
        "database_status": record("test-only database status", 1024),
        "grype_version": "0.112.0",
        "match_count": 0,
        "policy": "reject High or Critical matches and every match with a published fix",
        "remaining_nonfixed_ids": [],
        "report": record("test-only Grype report", 1024),
    },
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
chmod 0400 "${work_dir}/origin-image-security.json"

say "Publishing the one built image to an exact disposable local registry digest"
registry_port="$(pick_loopback_port)"
while [[ "${registry_port}" == "${port}" ]]; do registry_port="$(pick_loopback_port)"; done
registry_container_name="mesh-release-origin-registry-$$"
docker container run --detach \
  --name "${registry_container_name}" \
  --label "mesh.release-origin-smoke=${project_name}" \
  --publish "127.0.0.1:${registry_port}:5000" \
  "${registry_base_image}" >"${work_dir}/registry-container-id"
registry_url="http://127.0.0.1:${registry_port}"
for poll in {1..80}; do
  if curl --silent --show-error --fail --noproxy '*' --output /dev/null "${registry_url}/v2/"; then break; fi
  [[ "${poll}" -lt 80 ]] || die "disposable image registry did not become ready"
  sleep 0.25
done
registry_repository="127.0.0.1:${registry_port}/mesh-release-origin"
registry_image="${registry_repository}:smoke-$$"
docker image tag "${MESH_ORIGIN_BUILD_IMAGE}" "${registry_image}"
docker image push "${registry_image}" >"${work_dir}/registry-push.log"
runtime_image="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "${registry_image}" | awk -v prefix="${registry_repository}@sha256:" 'index($0,prefix)==1 {print; exit}')"
[[ "${runtime_image}" =~ ^127\.0\.0\.1:[0-9]+/mesh-release-origin@sha256:[0-9a-f]{64}$ ]] || die "registry did not return one canonical origin manifest digest"
export MESH_ORIGIN_IMAGE_REPOSITORY="${runtime_image%@sha256:*}"
export MESH_ORIGIN_IMAGE_SHA256="${runtime_image##*@sha256:}"

say "Producing image-custody evidence through the exact preflight command"
printf '%s\n' 'test-only independent public key fixture' >"${work_dir}/keys/origin-cosign.pub"
printf '%s\n' \
  '#!/bin/sh' \
  'set -eu' \
  '[ "$#" -eq 7 ]' \
  '[ "$1" = verify ]' \
  '[ "$2" = --key ]' \
  '[ -f "$3" ]' \
  '[ "$4" = --check-claims=true ]' \
  '[ "$5" = --output ]' \
  '[ "$6" = json ]' \
  'digest="${7##*@sha256:}"' \
  'printf '\''[{"critical":{"image":{"docker-manifest-digest":"sha256:%s"},"type":"cosign container image signature"}}]'\'' "$digest"' \
  >"${work_dir}/tools/cosign-fixture"
chmod 0555 "${work_dir}/tools/cosign-fixture"
"${mesh_origin_image_verify}" \
  --image "${runtime_image}" \
  --key "${work_dir}/keys/origin-cosign.pub" \
  --cosign "${work_dir}/tools/cosign-fixture" \
  --timeout 30s \
  --output "${work_dir}/origin-image-verification.json" \
  >"${work_dir}/origin-image-verification.stdout"
cmp --silent -- "${work_dir}/origin-image-verification.stdout" "${work_dir}/origin-image-verification.json" || die "image verification stdout and durable receipt differ"

say "Pulling and starting only the authenticated digest through production Compose"
production_compose config --format json >"${work_dir}/initial-production-compose.json"
production_compose pull
production_compose up --detach --no-build --pull never
wait_for_healthy

say "Proving a mismatched image-security receipt fails runtime verification closed"
python3 - "${work_dir}/origin-image-security.json" "${work_dir}/wrong-origin-image-security.json" <<'PY'
import json
import pathlib
import sys

receipt = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
receipt["image"]["docker_image_id"] = "sha256:" + "f" * 64
pathlib.Path(sys.argv[2]).write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
chmod 0400 "${work_dir}/wrong-origin-image-security.json"
if "${mesh_origin_runtime_verify}" \
  --image-receipt "${work_dir}/origin-image-verification.json" \
  --security-receipt "${work_dir}/wrong-origin-image-security.json" \
  --compose-config "${work_dir}/initial-production-compose.json" \
  --generation "${generation_path}" \
  --container-id "${container_id}" \
  --docker "$(command -v docker)" \
  --docker-socket /run/docker.sock \
  --timeout 30s \
  --output "${work_dir}/wrong-security-runtime-verification.json" \
  >"${work_dir}/wrong-security-runtime-verification.stdout" 2>"${work_dir}/wrong-security-runtime-verification.stderr"; then
  die "runtime verifier accepted an image differing from its security receipt"
fi
[[ ! -e "${work_dir}/wrong-security-runtime-verification.json" && ! -s "${work_dir}/wrong-security-runtime-verification.stdout" && -s "${work_dir}/wrong-security-runtime-verification.stderr" ]] || die "failed image-security binding emitted a success receipt"

say "Proving runtime-bound generation selection and retained-generation rollback"
export MESH_ORIGIN_GENERATION="${candidate_generation_path}"
production_compose config --format json >"${work_dir}/candidate-production-compose.json"
production_compose up --detach --no-build --pull never --force-recreate
wait_for_healthy
"${mesh_origin_runtime_verify}" \
  --image-receipt "${work_dir}/origin-image-verification.json" \
  --security-receipt "${work_dir}/origin-image-security.json" \
  --compose-config "${work_dir}/candidate-production-compose.json" \
  --generation "${candidate_generation_path}" \
  --container-id "${container_id}" \
  --docker "$(command -v docker)" \
  --docker-socket /run/docker.sock \
  --timeout 30s \
  --output "${work_dir}/candidate-runtime-verification.json" \
  >"${work_dir}/candidate-runtime-verification.stdout"
cmp --silent -- "${work_dir}/candidate-runtime-verification.stdout" "${work_dir}/candidate-runtime-verification.json" || die "candidate runtime verification stdout and durable receipt differ"
curl --silent --show-error --fail --noproxy '*' \
  --cacert "${work_dir}/tls/ca.crt" \
  --output "${work_dir}/candidate-generation-marker" \
  "${origin_url}/releases/1.0.0/origin-generation-marker"
cmp --silent -- \
  "${work_dir}/candidate-generation-marker" \
  "${candidate_generation_path}/repository/releases/1.0.0/origin-generation-marker" || die "candidate generation response changed exact bytes"
"${mesh_origin_audit}" \
  --generation "${candidate_generation_path}" \
  --origin "${origin_url}" \
  --ca-file "${work_dir}/tls/ca.crt" \
  --timeout 30s \
  --output "${work_dir}/candidate-origin-audit.json" >"${work_dir}/candidate-origin-audit.stdout"
cmp --silent -- "${work_dir}/candidate-origin-audit.stdout" "${work_dir}/candidate-origin-audit.json" || die "candidate external audit stdout and durable receipt differ"
export MESH_ORIGIN_GENERATION="${generation_path}"
production_compose config --format json >"${work_dir}/rollback-production-compose.json"
production_compose up --detach --no-build --pull never --force-recreate
wait_for_healthy
"${mesh_origin_runtime_verify}" \
  --image-receipt "${work_dir}/origin-image-verification.json" \
  --security-receipt "${work_dir}/origin-image-security.json" \
  --compose-config "${work_dir}/rollback-production-compose.json" \
  --generation "${generation_path}" \
  --container-id "${container_id}" \
  --docker "$(command -v docker)" \
  --docker-socket /run/docker.sock \
  --timeout 30s \
  --output "${work_dir}/rollback-runtime-verification.json" \
  >"${work_dir}/rollback-runtime-verification.stdout"
cmp --silent -- "${work_dir}/rollback-runtime-verification.stdout" "${work_dir}/rollback-runtime-verification.json" || die "rollback runtime verification stdout and durable receipt differ"
status="$(curl --silent --show-error --noproxy '*' --cacert "${work_dir}/tls/ca.crt" --output /dev/null --write-out '%{http_code}' "${origin_url}/releases/1.0.0/origin-generation-marker")"
[[ "${status}" == "404" ]] || die "retained generation rollback exposed candidate-only object with status ${status}"
"${mesh_release}" inspect-origin-generation --generation "${generation_path}" >/dev/null
"${mesh_origin_audit}" \
  --generation "${generation_path}" \
  --origin "${origin_url}" \
  --ca-file "${work_dir}/tls/ca.crt" \
  --timeout 30s \
  --output "${work_dir}/rollback-origin-audit.json" >"${work_dir}/rollback-origin-audit.stdout"
cmp --silent -- "${work_dir}/rollback-origin-audit.stdout" "${work_dir}/rollback-origin-audit.json" || die "rollback external audit stdout and durable receipt differ"
python3 - \
  "${work_dir}/candidate-origin-audit.json" \
  "${work_dir}/rollback-origin-audit.json" \
  "${work_dir}/candidate-runtime-verification.json" \
  "${work_dir}/rollback-runtime-verification.json" \
  "${work_dir}/origin-image-verification.json" \
  "${work_dir}/origin-image-security.json" \
  "${candidate_generation_id}" "${generation_id}" "${origin_url}" \
  "${runtime_image}" "${MESH_ORIGIN_UID}:${MESH_ORIGIN_GID}" <<'PY'
import hashlib
import json
import pathlib
import sys

candidate = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
rollback = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
candidate_runtime = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
rollback_runtime = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
image_path = pathlib.Path(sys.argv[5])
image_raw = image_path.read_bytes()
image_receipt = json.loads(image_raw)
security_path = pathlib.Path(sys.argv[6])
security_raw = security_path.read_bytes()
security_receipt = json.loads(security_raw)
for receipt, generation, objects in ((candidate, sys.argv[7], 14), (rollback, sys.argv[8], 13)):
    assert set(receipt) == {
        "schema", "generation", "index_sha256", "origin", "certificate_sha256",
        "certificate_not_after", "checked_at", "object_count", "total_size", "request_count",
    }
    assert receipt["schema"] == "mesh-release-origin-audit-v1"
    assert receipt["generation"] == generation == receipt["index_sha256"]
    assert receipt["origin"] == sys.argv[9]
    assert len(receipt["certificate_sha256"]) == 64
    assert receipt["object_count"] == objects and receipt["total_size"] > 0
    assert receipt["request_count"] == 2 * objects + 3
assert candidate["generation"] != rollback["generation"]
assert candidate["certificate_sha256"] == rollback["certificate_sha256"]
assert set(image_receipt) == {
    "schema", "image", "manifest_sha256", "public_key_sha256", "cosign_sha256",
    "verified_at", "signature_count",
}
assert image_receipt["schema"] == "mesh-origin-image-verification-v1"
assert image_receipt["image"] == sys.argv[10]
assert image_receipt["manifest_sha256"] == sys.argv[10].split("@sha256:", 1)[1]
assert image_receipt["signature_count"] == 1
image_receipt_sha = hashlib.sha256(image_raw).hexdigest()
security_receipt_sha = hashlib.sha256(security_raw).hexdigest()
assert security_receipt["schema"] == "mesh-origin-image-security-receipt-v1"
for receipt, generation in ((candidate_runtime, sys.argv[7]), (rollback_runtime, sys.argv[8])):
    assert set(receipt) == {
        "schema", "image_receipt_sha256", "security_receipt_sha256", "image", "manifest_sha256", "compose_sha256",
        "generation", "container_id", "local_image_id", "docker_sha256", "public_url",
        "runtime_user", "verified_at",
    }
    assert receipt["schema"] == "mesh-origin-runtime-verification-v2"
    assert receipt["image_receipt_sha256"] == image_receipt_sha
    assert receipt["security_receipt_sha256"] == security_receipt_sha
    assert receipt["image"] == sys.argv[10]
    assert receipt["manifest_sha256"] == image_receipt["manifest_sha256"]
    assert receipt["generation"] == generation
    assert receipt["public_url"] == sys.argv[9]
    assert receipt["runtime_user"] == sys.argv[11]
    for key in ("compose_sha256", "container_id", "local_image_id", "docker_sha256"):
        assert len(receipt[key]) == 64
assert candidate_runtime["container_id"] != rollback_runtime["container_id"]
assert candidate_runtime["local_image_id"] == rollback_runtime["local_image_id"]
assert candidate_runtime["docker_sha256"] == rollback_runtime["docker_sha256"]
assert candidate_runtime["compose_sha256"] != rollback_runtime["compose_sha256"]
PY

docker inspect "${container_id}" >"${work_dir}/container-inspect.json"
python3 - "${work_dir}/container-inspect.json" "${MESH_ORIGIN_UID}:${MESH_ORIGIN_GID}" "${published_repository}" "${generation_path}/origin-index.json" "${runtime_image}" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))[0]
assert document["Config"]["User"] == sys.argv[2]
assert document["Config"]["Image"] == sys.argv[5]
assert document["HostConfig"]["ReadonlyRootfs"] is True
assert {item.upper() for item in document["HostConfig"]["CapDrop"]} == {"ALL"}
assert document["HostConfig"]["SecurityOpt"] == ["no-new-privileges:true"]
assert document["HostConfig"]["PidsLimit"] == 64
assert document["HostConfig"]["Memory"] == 128 * 1024 * 1024
mounts = {item["Destination"]: item for item in document["Mounts"]}
assert mounts["/srv/repository"]["Source"] == sys.argv[3]
assert mounts["/run/origin/index.json"]["Source"] == sys.argv[4]
for target in ("/srv/repository", "/run/origin/index.json", "/run/tls/server.crt", "/run/tls/server.key", "/run/tls/ca.crt"):
    assert mounts[target]["RW"] is False
PY

say "Verifying exact public object behavior"
curl --silent --show-error --fail --noproxy '*' \
  --cacert "${work_dir}/tls/ca.crt" \
  --dump-header "${work_dir}/channel.headers" \
  --output "${work_dir}/fetched-bundle.json" \
  "${origin_url}/channels/stable/bundle.json"
tr -d '\r' <"${work_dir}/channel.headers" >"${work_dir}/channel.headers.clean"
cmp --silent -- "${work_dir}/fetched-bundle.json" "${published_repository}/channels/stable/bundle.json" || die "channel response changed exact bytes"
grep -Fxiq 'content-type: application/json' "${work_dir}/channel.headers.clean" || die "channel content type was not exact"
grep -Fxiq 'cache-control: public, max-age=30, must-revalidate, no-transform' "${work_dir}/channel.headers.clean" || die "channel cache policy was not exact"
grep -Eiq '^etag: "sha256:[0-9a-f]{64}"$' "${work_dir}/channel.headers.clean" || die "channel ETag was not exact"
if grep -Eiq '^content-encoding:' "${work_dir}/channel.headers.clean"; then
  die "origin unexpectedly encoded channel bytes"
fi

curl --silent --show-error --fail --noproxy '*' \
  --cacert "${work_dir}/tls/ca.crt" \
  --dump-header "${work_dir}/artifact.headers" \
  --output "${work_dir}/fetched-artifact" \
  "${origin_url}/releases/1.0.0/mesh-linux-bundle.tar"
tr -d '\r' <"${work_dir}/artifact.headers" >"${work_dir}/artifact.headers.clean"
cmp --silent -- "${work_dir}/fetched-artifact" "${published_repository}/releases/1.0.0/mesh-linux-bundle.tar" || die "artifact response changed exact bytes"
grep -Fxiq 'content-type: application/octet-stream' "${work_dir}/artifact.headers.clean" || die "artifact content type was not exact"
grep -Fxiq 'cache-control: public, max-age=31536000, immutable, no-transform' "${work_dir}/artifact.headers.clean" || die "artifact cache policy was not exact"

say "Fetching the complete bootstrap courier set and applying the independently transferred anchor"
install -d -m 0700 "${work_dir}/fetched-bootstrap" "${work_dir}/trusted-verifier"
for name in \
  bootstrap-handoff.json \
  mesh-bootstrap-verifier-linux-amd64.tar \
  mesh-bootstrap-verifier-linux-arm64.tar \
  mesh-bootstrap-verifier-windows-amd64.tar \
  mesh-bootstrap-verifier-windows-arm64.tar \
  "mesh-install-linux-${architecture}" \
  mesh-install.bootstrap.json \
  mesh-install.bootstrap.root-a.json \
  mesh-install.bootstrap.root-b.json \
  root-v1.json; do
  curl --silent --show-error --fail --noproxy '*' \
    --cacert "${work_dir}/tls/ca.crt" \
    --output "${work_dir}/fetched-bootstrap/${name}" \
    "${origin_url}/bootstrap/stable/${name}"
  cmp --silent -- \
    "${work_dir}/fetched-bootstrap/${name}" \
    "${published_repository}/bootstrap/stable/${name}" || die "bootstrap object ${name} changed exact bytes"
done

fetched_handoff_sha="$(sha256sum -- "${work_dir}/fetched-bootstrap/bootstrap-handoff.json" | awk '{print $1}')"
[[ "${fetched_handoff_sha}" == "${independent_handoff_sha}" ]] || die "fetched bootstrap handoff differs from the independently authenticated digest"
read -r expected_root_sha expected_verifier_package_sha < <(python3 - \
  "${work_dir}/fetched-bootstrap/bootstrap-handoff.json" "${architecture}" "${verification_at}" <<'PY'
import json
import pathlib
import sys

handoff = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
architecture = sys.argv[2]
verification_at = sys.argv[3]
assert handoff["schema"] == "mesh-bootstrap-handoff-v2"
assert handoff["channel"] == "stable"
assert handoff["issued_at"] == verification_at
assert handoff["root"]["name"] == "root-v1.json"
assert handoff["root"]["version"] == 1 and handoff["root"]["release_epoch"] == 1
assert handoff["build"]["version"] == "1.0.0"
assert handoff["build"]["commit"] == "1" * 40
assert [(item["os"], item["arch"]) for item in handoff["verifiers"]] == [
    ("linux", "amd64"), ("linux", "arm64"),
    ("windows", "amd64"), ("windows", "arm64"),
]
selected = next(item for item in handoff["verifiers"] if item["os"] == "linux" and item["arch"] == architecture)
assert selected["name"] == f"mesh-bootstrap-verifier-linux-{architecture}.tar"
print(handoff["root"]["sha256"], selected["sha256"])
PY
)
[[ "${expected_root_sha}" =~ ^[0-9a-f]{64}$ && "${expected_verifier_package_sha}" =~ ^[0-9a-f]{64}$ ]] || die "authenticated handoff did not yield canonical platform digests"
[[ "$(sha256sum -- "${work_dir}/fetched-bootstrap/root-v1.json" | awk '{print $1}')" == "${expected_root_sha}" ]] || die "fetched root differs from the authenticated handoff"
fetched_verifier_package_sha="$(sha256sum -- "${work_dir}/fetched-bootstrap/mesh-bootstrap-verifier-linux-${architecture}.tar" | awk '{print $1}')"
[[ "${fetched_verifier_package_sha}" == "${expected_verifier_package_sha}" ]] || die "fetched verifier package differs from the authenticated handoff"
python3 - \
  "${work_dir}/fetched-bootstrap/mesh-bootstrap-verifier-linux-${architecture}.tar" \
  "${architecture}" "${source_epoch}" <<'PY'
import hashlib
import json
import pathlib
import sys
import tarfile

archive_path = pathlib.Path(sys.argv[1])
architecture = sys.argv[2]
source_epoch = int(sys.argv[3])
with tarfile.open(archive_path, mode="r:") as archive:
    members = archive.getmembers()
    assert [member.name for member in members] == ["package.json", "bin/mesh-bootstrap-verify"]
    assert [(member.mode, member.uid, member.gid, int(member.mtime)) for member in members] == [
        (0o444, 0, 0, source_epoch),
        (0o555, 0, 0, source_epoch),
    ]
    package_raw = archive.extractfile(members[0]).read()
    verifier_raw = archive.extractfile(members[1]).read()
package = json.loads(package_raw)
assert package_raw.endswith(b"\n") and package_raw.count(b"\n") == 1
assert package["schema"] == "mesh-bootstrap-verifier-bundle-v1"
assert package["build"]["version"] == "1.0.0"
assert package["build"]["commit"] == "1" * 40
assert package["target"] == {"os": "linux", "arch": architecture}
assert package["entries"] == [{
    "path": "bin/mesh-bootstrap-verify",
    "mode": 0o555,
    "size": len(verifier_raw),
    "sha256": hashlib.sha256(verifier_raw).hexdigest(),
}]
PY
tar --extract \
  --file="${work_dir}/fetched-bootstrap/mesh-bootstrap-verifier-linux-${architecture}.tar" \
  --directory="${work_dir}/trusted-verifier" \
  --no-same-owner --no-same-permissions \
  bin/mesh-bootstrap-verify
chmod 0500 "${work_dir}/trusted-verifier/bin/mesh-bootstrap-verify"

readonly -a handoff_verify_args=(
  --handoff "${work_dir}/fetched-bootstrap/bootstrap-handoff.json"
  --handoff-anchor "${work_dir}/metadata/bootstrap-anchor.json"
  --root "${work_dir}/fetched-bootstrap/root-v1.json" \
  --manifest "${work_dir}/fetched-bootstrap/mesh-install.bootstrap.json" \
  --signature "${work_dir}/fetched-bootstrap/mesh-install.bootstrap.root-a.json" \
  --signature "${work_dir}/fetched-bootstrap/mesh-install.bootstrap.root-b.json" \
  --installer "${work_dir}/fetched-bootstrap/mesh-install-linux-${architecture}" \
  --now "${verification_at}"
)
"${work_dir}/trusted-verifier/bin/mesh-bootstrap-verify" "${handoff_verify_args[@]}" >"${work_dir}/bootstrap-verification-receipt.json"
"${mesh_release}" verify-bootstrap "${handoff_verify_args[@]}" >"${work_dir}/bootstrap-verification-compatibility-receipt.json"
cmp --silent -- "${work_dir}/bootstrap-verification-receipt.json" "${work_dir}/bootstrap-verification-compatibility-receipt.json" || die "anchor receipts differ between the standalone and compatibility verifier"
python3 - "${work_dir}/bootstrap-verification-receipt.json" "${independent_anchor_sha}" "${independent_handoff_sha}" "${expected_verifier_package_sha}" "${expected_root_sha}" "${architecture}" <<'PY'
import json
import pathlib
import sys

receipt = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert receipt["schema"] == "mesh-bootstrap-verification-v3"
assert receipt["anchor_sha256"] == sys.argv[2]
assert receipt["handoff_sha256"] == sys.argv[3]
assert receipt["verifier_package_sha256"] == sys.argv[4]
assert receipt["root_sha256"] == sys.argv[5]
assert receipt["version"] == "1.0.0"
assert receipt["os"] == "linux" and receipt["arch"] == sys.argv[6]
assert len(receipt["signer_key_ids"]) == 2
assert receipt["signer_key_ids"] == sorted(set(receipt["signer_key_ids"]))
PY

readonly -a direct_handoff_verify_args=(
  --handoff "${work_dir}/fetched-bootstrap/bootstrap-handoff.json"
  --expected-handoff-sha256 "${independent_handoff_sha}"
  --root "${work_dir}/fetched-bootstrap/root-v1.json"
  --manifest "${work_dir}/fetched-bootstrap/mesh-install.bootstrap.json"
  --signature "${work_dir}/fetched-bootstrap/mesh-install.bootstrap.root-a.json"
  --signature "${work_dir}/fetched-bootstrap/mesh-install.bootstrap.root-b.json"
  --installer "${work_dir}/fetched-bootstrap/mesh-install-linux-${architecture}"
  --now "${verification_at}"
)
"${work_dir}/trusted-verifier/bin/mesh-bootstrap-verify" "${direct_handoff_verify_args[@]}" >"${work_dir}/bootstrap-verification-v2-receipt.json"
python3 - "${work_dir}/bootstrap-verification-v2-receipt.json" "${independent_handoff_sha}" <<'PY'
import json
import pathlib
import sys

receipt = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert receipt["schema"] == "mesh-bootstrap-verification-v2"
assert "anchor_sha256" not in receipt
assert receipt["handoff_sha256"] == sys.argv[2]
PY

cp -- "${work_dir}/metadata/bootstrap-anchor.json" "${work_dir}/metadata/wrong-bootstrap-anchor.json"
printf '\n' >>"${work_dir}/metadata/wrong-bootstrap-anchor.json"
if "${work_dir}/trusted-verifier/bin/mesh-bootstrap-verify" \
  --handoff "${work_dir}/fetched-bootstrap/bootstrap-handoff.json" \
  --handoff-anchor "${work_dir}/metadata/wrong-bootstrap-anchor.json" \
  --root "${work_dir}/fetched-bootstrap/root-v1.json" \
  --manifest "${work_dir}/fetched-bootstrap/mesh-install.bootstrap.json" \
  --signature "${work_dir}/fetched-bootstrap/mesh-install.bootstrap.root-a.json" \
  --signature "${work_dir}/fetched-bootstrap/mesh-install.bootstrap.root-b.json" \
  --installer "${work_dir}/fetched-bootstrap/mesh-install-linux-${architecture}" \
  --now "${verification_at}" \
  >"${work_dir}/wrong-anchor.stdout" 2>"${work_dir}/wrong-anchor.stderr"; then
  die "standalone verifier accepted a changed independent bootstrap anchor"
fi
[[ ! -s "${work_dir}/wrong-anchor.stdout" && -s "${work_dir}/wrong-anchor.stderr" ]] || die "wrong-anchor failure did not fail closed"
cp -- "${work_dir}/fetched-bootstrap/bootstrap-handoff.json" "${work_dir}/fetched-bootstrap/wrong-bootstrap-handoff.json"
printf '\n' >>"${work_dir}/fetched-bootstrap/wrong-bootstrap-handoff.json"
if "${work_dir}/trusted-verifier/bin/mesh-bootstrap-verify" \
  --handoff "${work_dir}/fetched-bootstrap/wrong-bootstrap-handoff.json" \
  --handoff-anchor "${work_dir}/metadata/bootstrap-anchor.json" \
  --root "${work_dir}/fetched-bootstrap/root-v1.json" \
  --manifest "${work_dir}/fetched-bootstrap/mesh-install.bootstrap.json" \
  --signature "${work_dir}/fetched-bootstrap/mesh-install.bootstrap.root-a.json" \
  --signature "${work_dir}/fetched-bootstrap/mesh-install.bootstrap.root-b.json" \
  --installer "${work_dir}/fetched-bootstrap/mesh-install-linux-${architecture}" \
  --now "${verification_at}" \
  >"${work_dir}/wrong-handoff.stdout" 2>"${work_dir}/wrong-handoff.stderr"; then
  die "standalone verifier accepted courier handoff bytes differing from the independent anchor"
fi
[[ ! -s "${work_dir}/wrong-handoff.stdout" && -s "${work_dir}/wrong-handoff.stderr" ]] || die "wrong-handoff failure did not fail closed"
if "${work_dir}/trusted-verifier/bin/mesh-bootstrap-verify" \
  "${handoff_verify_args[@]}" --expected-handoff-sha256 "${independent_handoff_sha}" \
  >"${work_dir}/mixed-handoff-authority.stdout" 2>"${work_dir}/mixed-handoff-authority.stderr"; then
  die "standalone verifier accepted mixed handoff authorities"
fi
[[ ! -s "${work_dir}/mixed-handoff-authority.stdout" && -s "${work_dir}/mixed-handoff-authority.stderr" ]] || die "mixed-handoff-authority failure did not fail closed"
ln -s -- "${work_dir}/metadata/bootstrap-anchor.json" "${work_dir}/metadata/bootstrap-anchor.link"
if "${work_dir}/trusted-verifier/bin/mesh-bootstrap-verify" \
  --handoff "${work_dir}/fetched-bootstrap/bootstrap-handoff.json" \
  --handoff-anchor "${work_dir}/metadata/bootstrap-anchor.link" \
  --root "${work_dir}/fetched-bootstrap/root-v1.json" \
  --manifest "${work_dir}/fetched-bootstrap/mesh-install.bootstrap.json" \
  --signature "${work_dir}/fetched-bootstrap/mesh-install.bootstrap.root-a.json" \
  --signature "${work_dir}/fetched-bootstrap/mesh-install.bootstrap.root-b.json" \
  --installer "${work_dir}/fetched-bootstrap/mesh-install-linux-${architecture}" \
  --now "${verification_at}" \
  >"${work_dir}/linked-anchor.stdout" 2>"${work_dir}/linked-anchor.stderr"; then
  die "standalone verifier accepted a linked bootstrap anchor"
fi
[[ ! -s "${work_dir}/linked-anchor.stdout" && -s "${work_dir}/linked-anchor.stderr" ]] || die "linked-anchor failure did not fail closed"
rm -f -- "${work_dir}/metadata/bootstrap-anchor.link"
cp -- "${work_dir}/fetched-bootstrap/root-v1.json" "${work_dir}/fetched-bootstrap/wrong-root-v1.json"
printf '\n' >>"${work_dir}/fetched-bootstrap/wrong-root-v1.json"
if "${work_dir}/trusted-verifier/bin/mesh-bootstrap-verify" \
  --handoff "${work_dir}/fetched-bootstrap/bootstrap-handoff.json" \
  --handoff-anchor "${work_dir}/metadata/bootstrap-anchor.json" \
  --root "${work_dir}/fetched-bootstrap/wrong-root-v1.json" \
  --manifest "${work_dir}/fetched-bootstrap/mesh-install.bootstrap.json" \
  --signature "${work_dir}/fetched-bootstrap/mesh-install.bootstrap.root-a.json" \
  --signature "${work_dir}/fetched-bootstrap/mesh-install.bootstrap.root-b.json" \
  --installer "${work_dir}/fetched-bootstrap/mesh-install-linux-${architecture}" \
  --now "${verification_at}" \
  >"${work_dir}/wrong-handoff-root.stdout" 2>"${work_dir}/wrong-handoff-root.stderr"; then
  die "standalone verifier accepted root bytes differing from the authenticated handoff"
fi
[[ ! -s "${work_dir}/wrong-handoff-root.stdout" && -s "${work_dir}/wrong-handoff-root.stderr" ]] || die "wrong-handoff-root failure did not fail closed"
if "${work_dir}/trusted-verifier/bin/mesh-bootstrap-verify" \
  "${handoff_verify_args[@]/${verification_at}/${release_expires}}" \
  >"${work_dir}/expired-handoff.stdout" 2>"${work_dir}/expired-handoff.stderr"; then
  die "standalone verifier accepted an expired handoff"
fi
[[ ! -s "${work_dir}/expired-handoff.stdout" && -s "${work_dir}/expired-handoff.stderr" ]] || die "expired-handoff failure did not fail closed"

for path in '/not-indexed' '/channels/stable/bundle.json?x=1' '/bootstrap/stable/bootstrap-anchor.json'; do
  status="$(curl --silent --show-error --noproxy '*' --cacert "${work_dir}/tls/ca.crt" --output /dev/null --write-out '%{http_code}' "${origin_url}${path}")"
  [[ "${status}" == "404" ]] || die "unpublished path ${path} returned ${status}"
done
status="$(curl --silent --show-error --noproxy '*' --cacert "${work_dir}/tls/ca.crt" --request POST --output /dev/null --write-out '%{http_code}' "${origin_url}/channels/stable/bundle.json")"
[[ "${status}" == "405" ]] || die "origin write returned ${status}"

say "Fetching through the production online client and verifying two signatures"
SSL_CERT_FILE="${work_dir}/tls/ca.crt" "${smoke_client}" \
  --bundle-url "${origin_url}/channels/stable/bundle.json" \
  --release-public "${work_dir}/keys/release-a.public.json" \
  --release-public "${work_dir}/keys/release-b.public.json" \
  --output "${work_dir}/client-artifact" >/dev/null
cmp --silent -- "${work_dir}/client-artifact" "${published_repository}/releases/1.0.0/mesh-linux-bundle.tar" || die "production client output differs from the threshold-authenticated artifact"

say "Proving in-place bootstrap-object mutation fails readiness closed"
chmod 0644 "${published_repository}/bootstrap/stable/mesh-install-linux-${architecture}"
printf 'tampered after startup\n' >"${published_repository}/bootstrap/stable/mesh-install-linux-${architecture}"
if "${mesh_release}" inspect-origin-generation --generation "${generation_path}" >/dev/null 2>&1; then
  die "origin generation inspection accepted a mutated selected object"
fi
if "${mesh_origin_runtime_verify}" \
  --image-receipt "${work_dir}/origin-image-verification.json" \
  --security-receipt "${work_dir}/origin-image-security.json" \
  --compose-config "${work_dir}/rollback-production-compose.json" \
  --generation "${generation_path}" \
  --container-id "${container_id}" \
  --docker "$(command -v docker)" \
  --docker-socket /run/docker.sock \
  --timeout 30s \
  --output "${work_dir}/mutated-runtime-verification.json" \
  >"${work_dir}/mutated-runtime-verification.stdout" 2>"${work_dir}/mutated-runtime-verification.stderr"; then
  die "runtime verifier accepted a mutated selected generation"
fi
[[ ! -e "${work_dir}/mutated-runtime-verification.json" && ! -s "${work_dir}/mutated-runtime-verification.stdout" && -s "${work_dir}/mutated-runtime-verification.stderr" ]] || die "failed runtime verification emitted a success receipt"
if "${mesh_origin_audit}" \
  --generation "${generation_path}" \
  --origin "${origin_url}" \
  --ca-file "${work_dir}/tls/ca.crt" \
  --timeout 30s \
  --output "${work_dir}/mutated-origin-audit.json" \
  >"${work_dir}/mutated-origin-audit.stdout" 2>"${work_dir}/mutated-origin-audit.stderr"; then
  die "external origin auditor accepted a mutated selected generation"
fi
[[ ! -e "${work_dir}/mutated-origin-audit.json" && ! -s "${work_dir}/mutated-origin-audit.stdout" && -s "${work_dir}/mutated-origin-audit.stderr" ]] || die "failed external audit emitted a success receipt"
status="$(curl --silent --show-error --noproxy '*' --cacert "${work_dir}/tls/ca.crt" --output /dev/null --write-out '%{http_code}' "${origin_url}/readyz")"
[[ "${status}" == "503" ]] || die "mutated repository readiness returned ${status}"
status="$(curl --silent --show-error --noproxy '*' --cacert "${work_dir}/tls/ca.crt" --output /dev/null --write-out '%{http_code}' "${origin_url}/bootstrap/stable/mesh-install-linux-${architecture}")"
[[ "${status}" == "503" ]] || die "mutated indexed object returned ${status}"

say "PASS: one locally built image published to and started from an exact disposable registry digest, image-custody and runtime-binding receipts, production Compose with no build, durable content-addressed origin generations, full external HTTPS audit receipts across candidate selection and retained-generation rollback, one independently transferred create-only bootstrap anchor kept off origin and binding the courier handoff, all four Linux and Windows verifier packages, and the root, canonical Linux verifier extraction, root-authorized installer verification, v3 anchor and compatible v2 digest receipts, mixed-authority and mutation fail-closed behavior, threshold-authenticated production retrieval, and cleanup verified"
