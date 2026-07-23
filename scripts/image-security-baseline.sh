#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

say() {
  printf '%s\n' "$*"
}

die() {
  printf 'image security baseline: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 0 ]] || die "this gate accepts no arguments"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "${script_dir}/.." && pwd -P)"
verify_script="${script_dir}/image_security_verify.py"
gitleaks_config="${repo_root}/.gitleaks-image.toml"
dockerfile="${repo_root}/packaging/container/Dockerfile"
[[ -f "${verify_script}" && -f "${gitleaks_config}" && -f "${dockerfile}" ]] || die "image-security inputs are missing"

for required in docker python3 strings id install mktemp; do
  command -v "${required}" >/dev/null 2>&1 || die "required command is unavailable: ${required}"
done
docker info >/dev/null 2>&1 || die "Docker daemon is unavailable"
[[ "$(id -u)" -ne 0 ]] || die "run this gate as the unprivileged Docker build account, not root"

syft_version="1.44.0"
grype_version="0.112.0"
gitleaks_version="v8.30.1"
syft_image="docker.io/anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6"
grype_image="docker.io/anchore/grype@sha256:391bfda62888fb4e98ff5c4c81598f7431a3c1eac3f8519d69d1ff00df247c1d"
gitleaks_image="ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"

temporary_parent="${TMPDIR:-/tmp}"
[[ -d "${temporary_parent}" && ! -L "${temporary_parent}" ]] || die "temporary directory parent is unavailable or linked"
temporary_parent="$(cd -- "${temporary_parent}" && pwd -P)"
work_dir="$(mktemp -d "${temporary_parent%/}/mesh-image-security.XXXXXX")"
[[ -d "${work_dir}" && ! -L "${work_dir}" && "${work_dir}" == "${temporary_parent%/}/mesh-image-security."* ]] || die "mktemp returned an unsafe workspace"
chmod 0700 "${work_dir}"
install -d -m 0700 "${work_dir}/buildx" "${work_dir}/db" "${work_dir}/prepared" "${work_dir}/binary-strings"

image_tag="mesh-control-plane:image-security-$$"
published_dir=""
publish_complete=false

cleanup() {
  local status=$?
  trap - EXIT ERR HUP INT TERM
  docker image rm "${image_tag}" >/dev/null 2>&1 || true
  if [[ "${publish_complete}" != true && -n "${published_dir}" && -d "${published_dir}" && ! -L "${published_dir}" ]]; then
    case "${published_dir}" in
      "${repo_root}/bin/image-security/"*) rm -rf -- "${published_dir}" ;;
      *) printf 'Refusing to remove unexpected partial publication %s\n' "${published_dir}" >&2 ;;
    esac
  fi
  if [[ -n "${work_dir:-}" && -d "${work_dir}" && "${work_dir}" == "${temporary_parent%/}/mesh-image-security."* ]]; then
    rm -rf -- "${work_dir}"
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

pull_if_missing() {
  local image=$1
  if ! docker image inspect "${image}" >/dev/null 2>&1; then
    say "Pulling digest-pinned scanner ${image%%@*}"
    docker pull "${image}" >/dev/null
  fi
}

scanner_base=(
  run --rm
  --network=none
  --read-only
  --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777
  --cap-drop=ALL
  --security-opt=no-new-privileges
  --pids-limit=128
  --memory=768m
  --user="$(id -u):$(id -g)"
  -e HOME=/tmp
  -e XDG_CACHE_HOME=/tmp/.cache
)

pull_if_missing "${syft_image}"
pull_if_missing "${grype_image}"
pull_if_missing "${gitleaks_image}"

actual_syft_version="$(docker "${scanner_base[@]}" "${syft_image}" version | awk '$1 == "Version:" {print $2}')"
actual_grype_version="$(docker "${scanner_base[@]}" "${grype_image}" version | awk '$1 == "Version:" {print $2}')"
actual_gitleaks_version="$(docker "${scanner_base[@]}" "${gitleaks_image}" version)"
[[ "${actual_syft_version}" == "${syft_version}" ]] || die "Syft version ${actual_syft_version} does not match ${syft_version}"
[[ "${actual_grype_version}" == "${grype_version}" ]] || die "Grype version ${actual_grype_version} does not match ${grype_version}"
[[ "${actual_gitleaks_version}" == "${gitleaks_version}" ]] || die "Gitleaks version ${actual_gitleaks_version} does not match ${gitleaks_version}"

say "Building the pinned linux/amd64 scratch image"
cd -- "${repo_root}"
BUILDX_CONFIG="${work_dir}/buildx" docker build \
  --pull \
  --provenance=false \
  --platform=linux/amd64 \
  --file "${dockerfile}" \
  --tag "${image_tag}" \
  . >/dev/null

image_id="$(docker image inspect "${image_tag}" --format '{{.Id}}')"
[[ "${image_id}" =~ ^sha256:[0-9a-f]{64}$ ]] || die "Docker returned an invalid image ID"
docker image save --output "${work_dir}/image.tar" "${image_id}"
chmod 0400 "${work_dir}/image.tar"

say "Validating the exact final filesystem and extracting bounded scan inputs"
python3 "${verify_script}" prepare \
  --archive "${work_dir}/image.tar" \
  --image-id "${image_id}" \
  --output-dir "${work_dir}/prepared"

say "Generating Syft and SPDX SBOMs offline with Syft ${syft_version}"
docker "${scanner_base[@]}" \
  -e SYFT_CHECK_FOR_APP_UPDATE=false \
  -v "${work_dir}:/work:rw" \
  "${syft_image}" docker-archive:/work/image.tar \
  -o syft-json=/work/sbom.syft.json \
  -o spdx-json=/work/sbom.spdx.json >/dev/null

say "Refreshing the isolated Grype vulnerability database"
docker run --rm \
  --read-only \
  --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=512m,mode=1777 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --pids-limit=128 \
  --memory=2g \
  --user="$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e XDG_CACHE_HOME=/tmp/.cache \
  -e GRYPE_DB_CACHE_DIR=/db \
  -e GRYPE_CHECK_FOR_APP_UPDATE=false \
  -v "${work_dir}/db:/db:rw" \
  "${grype_image}" db update >/dev/null

docker "${scanner_base[@]}" \
  -e GRYPE_DB_CACHE_DIR=/db \
  -e GRYPE_CHECK_FOR_APP_UPDATE=false \
  -v "${work_dir}/db:/db:ro" \
  "${grype_image}" db status --output json >"${work_dir}/grype-db-status.json"

say "Scanning the bound SBOM offline with Grype ${grype_version}"
set +e
docker "${scanner_base[@]}" \
  -e GRYPE_DB_CACHE_DIR=/work/db \
  -e GRYPE_CHECK_FOR_APP_UPDATE=false \
  -v "${work_dir}:/work:rw" \
  "${grype_image}" sbom:/work/sbom.syft.json \
  --fail-on high \
  --output json \
  --file /work/vulnerabilities.json
grype_status=$?
set -e
case "${grype_status}" in
  0|2) ;;
  *) die "Grype failed with status ${grype_status}" ;;
esac

say "Scanning final rootfs text and extracted binary strings with Gitleaks ${gitleaks_version}"
for binary in mesh-server mesh-healthcheck mesh-kube-init nebula-cert; do
  strings -a -n 8 "${work_dir}/prepared/binaries/${binary}" >"${work_dir}/binary-strings/${binary}.strings"
  chmod 0400 "${work_dir}/binary-strings/${binary}.strings"
done

docker "${scanner_base[@]}" \
  -v "${work_dir}/prepared/rootfs-text:/scan:ro" \
  -v "${work_dir}:/output:rw" \
  -v "${gitleaks_config}:/config/image.toml:ro" \
  "${gitleaks_image}" dir /scan \
  --config=/config/image.toml \
  --no-banner \
  --no-color \
  --redact=100 \
  --max-target-megabytes=64 \
  --max-archive-depth=0 \
  --max-decode-depth=3 \
  --timeout=120 \
  --report-format=json \
  --report-path=/output/rootfs-secrets.json

docker "${scanner_base[@]}" \
  -v "${work_dir}/binary-strings:/scan:ro" \
  -v "${work_dir}:/output:rw" \
  -v "${gitleaks_config}:/config/image.toml:ro" \
  "${gitleaks_image}" dir /scan \
  --config=/config/image.toml \
  --no-banner \
  --no-color \
  --redact=100 \
  --max-target-megabytes=64 \
  --max-archive-depth=0 \
  --max-decode-depth=3 \
  --timeout=120 \
  --report-format=json \
  --report-path=/output/binary-secrets.json

say "Binding image, SBOM, database, vulnerability, and secret evidence"
python3 "${verify_script}" finalize \
  --work-dir "${work_dir}" \
  --receipt "${work_dir}/receipt.json"

output_root="${repo_root}/bin/image-security"
if [[ -e "${output_root}" ]]; then
  [[ -d "${output_root}" && ! -L "${output_root}" ]] || die "image-security output root is unsafe"
else
  install -d -m 0700 "${output_root}"
fi
image_digest="${image_id#sha256:}"
verification_stamp="$(python3 - "${work_dir}/receipt.json" <<'PY'
import datetime as dt
import json
import pathlib
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["verified_at"]
parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(dt.timezone.utc)
print(parsed.strftime("%Y%m%dT%H%M%SZ"))
PY
)"
[[ "${verification_stamp}" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || die "receipt returned an invalid verification timestamp"
published_dir="${output_root}/${image_digest}-${verification_stamp}"
mkdir -m 0700 -- "${published_dir}" || die "refusing to replace existing evidence at ${published_dir}"

install -m 0400 "${work_dir}/prepared/image-metadata.json" "${published_dir}/image-metadata.json"
install -m 0400 "${work_dir}/sbom.syft.json" "${published_dir}/mesh-control-plane.syft.json"
install -m 0400 "${work_dir}/sbom.spdx.json" "${published_dir}/mesh-control-plane.spdx.json"
install -m 0400 "${work_dir}/grype-db-status.json" "${published_dir}/grype-db-status.json"
install -m 0400 "${work_dir}/vulnerabilities.json" "${published_dir}/vulnerabilities.json"
install -m 0400 "${work_dir}/rootfs-secrets.json" "${published_dir}/rootfs-secrets.json"
install -m 0400 "${work_dir}/binary-secrets.json" "${published_dir}/binary-secrets.json"
install -m 0400 "${work_dir}/receipt.json" "${published_dir}/receipt.json"
publish_complete=true

say "PASS: exact final image, SBOM, current vulnerability policy, and redacted image secret scans verified"
say "Evidence: ${published_dir}"
