#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

say() {
  printf '%s\n' "$*"
}

die() {
  printf 'observer security baseline: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 0 ]] || die "this gate accepts no arguments"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "${script_dir}/.." && pwd -P)"
verify_script="${script_dir}/observer_security_verify.py"
lock_file="${repo_root}/third_party/nebula-observer/v1.10.3-build.lock.json"
series_file="${repo_root}/third_party/nebula-observer/series"
gitleaks_config="${repo_root}/.gitleaks-image.toml"
[[ -f "${verify_script}" && -f "${lock_file}" && -f "${series_file}" && -f "${gitleaks_config}" ]] || die "observer-security inputs are missing"

for required in docker go git python3 strings id install mktemp cp chmod; do
  command -v "${required}" >/dev/null 2>&1 || die "required command is unavailable: ${required}"
done
docker info >/dev/null 2>&1 || die "Docker daemon is unavailable"
[[ "$(id -u)" -ne 0 ]] || die "run this gate as the unprivileged Docker build account, not root"

go_toolchain="go1.26.5"
govulncheck_version="v1.6.0"
syft_version="1.44.0"
grype_version="0.112.0"
gitleaks_version="v8.30.1"
syft_image="docker.io/anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6"
grype_image="docker.io/anchore/grype@sha256:391bfda62888fb4e98ff5c4c81598f7431a3c1eac3f8519d69d1ff00df247c1d"
gitleaks_image="ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"

temporary_parent="${TMPDIR:-/tmp}"
[[ -d "${temporary_parent}" && ! -L "${temporary_parent}" ]] || die "temporary directory parent is unavailable or linked"
temporary_parent="$(cd -- "${temporary_parent}" && pwd -P)"
work_dir="$(mktemp -d "${temporary_parent%/}/mesh-observer-security.XXXXXX")"
[[ -d "${work_dir}" && ! -L "${work_dir}" && "${work_dir}" == "${temporary_parent%/}/mesh-observer-security."* ]] || die "mktemp returned an unsafe workspace"
chmod 0700 "${work_dir}"
install -d -m 0700 "${work_dir}/bin" "${work_dir}/db" "${work_dir}/binary-strings"

published_dir=""
publish_complete=false

cleanup() {
  local status=$?
  trap - EXIT ERR HUP INT TERM
  if [[ "${publish_complete}" != true && -n "${published_dir}" && -d "${published_dir}" && ! -L "${published_dir}" ]]; then
    case "${published_dir}" in
      "${repo_root}/bin/observer-security/"*) rm -rf -- "${published_dir}" ;;
      *) printf 'Refusing to remove unexpected partial publication %s\n' "${published_dir}" >&2 ;;
    esac
  fi
  if [[ -n "${work_dir:-}" && -d "${work_dir}" && "${work_dir}" == "${temporary_parent%/}/mesh-observer-security."* ]]; then
    chmod -R u+w "${work_dir}" 2>/dev/null || true
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

cd -- "${repo_root}"
export GOTOOLCHAIN="${go_toolchain}"
export GOTELEMETRY=off
export GOWORK=off
export GOFLAGS=-buildvcs=false
actual_go_version="$(go env GOVERSION)"
[[ "${actual_go_version}" == "${go_toolchain}" ]] || die "resolved Go toolchain ${actual_go_version} does not match ${go_toolchain}"

say "Building and authenticating both locked observer architectures"
go build -trimpath -o "${work_dir}/bin/mesh-deps" ./cmd/mesh-deps
for arch in amd64 arm64; do
  "${work_dir}/bin/mesh-deps" build-nebula-observer \
    --arch "${arch}" \
    --output-dir "${work_dir}/stage-${arch}"
done

say "Reconstructing the exact patched source for govulncheck ${govulncheck_version}"
module_cache="$(go env GOMODCACHE)"
module_source="${module_cache}/github.com/slackhq/nebula@v1.10.3"
[[ -d "${module_source}" && ! -L "${module_source}" ]] || die "authenticated Nebula module source is not cached"
cp -a -- "${module_source}" "${work_dir}/source"
chmod -R u+w "${work_dir}/source"
while IFS= read -r patch_name; do
  [[ -n "${patch_name}" && "${patch_name}" != */* && -f "${repo_root}/third_party/nebula-observer/${patch_name}" ]] || die "observer patch series is invalid"
  git -C "${work_dir}/source" apply --check --whitespace=error-all "${repo_root}/third_party/nebula-observer/${patch_name}"
  git -C "${work_dir}/source" apply --whitespace=error-all "${repo_root}/third_party/nebula-observer/${patch_name}"
done < "${series_file}"

GOBIN="${work_dir}/bin" go install "golang.org/x/vuln/cmd/govulncheck@${govulncheck_version}"
set +e
(
  cd -- "${work_dir}/source"
  GOFLAGS='-mod=readonly -buildvcs=false' "${work_dir}/bin/govulncheck" -mode=source ./cmd/nebula ./cmd/nebula-cert
) >"${work_dir}/source-vulnerabilities.txt" 2>&1
govuln_status=$?
set -e
if [[ "${govuln_status}" -ne 0 ]]; then
  sed -n '1,240p' "${work_dir}/source-vulnerabilities.txt" >&2
  die "govulncheck rejected the patched observer source"
fi
chmod 0400 "${work_dir}/source-vulnerabilities.txt"

say "Generating Syft and SPDX SBOMs offline with Syft ${syft_version}"
for arch in amd64 arm64; do
  docker "${scanner_base[@]}" \
    -e SYFT_CHECK_FOR_APP_UPDATE=false \
    -v "${work_dir}/stage-${arch}:/scan:ro" \
    -v "${work_dir}:/work:rw" \
    "${syft_image}" dir:/scan \
    -o "syft-json=/work/linux-${arch}.syft.json" \
    -o "spdx-json=/work/linux-${arch}.spdx.json" >/dev/null
done

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

say "Scanning both bound SBOMs offline with Grype ${grype_version}"
for arch in amd64 arm64; do
  set +e
  docker "${scanner_base[@]}" \
    -e GRYPE_DB_CACHE_DIR=/work/db \
    -e GRYPE_CHECK_FOR_APP_UPDATE=false \
    -v "${work_dir}:/work:rw" \
    "${grype_image}" "sbom:/work/linux-${arch}.syft.json" \
    --fail-on high \
    --output json \
    --file "/work/linux-${arch}.vulnerabilities.json"
  grype_status=$?
  set -e
  case "${grype_status}" in
    0|2) ;;
    *) die "Grype failed for linux/${arch} with status ${grype_status}" ;;
  esac
done

say "Scanning strings from all four locked executables with Gitleaks ${gitleaks_version}"
for arch in amd64 arm64; do
  for binary in nebula nebula-cert; do
    strings -a -n 8 "${work_dir}/stage-${arch}/${binary}" >"${work_dir}/binary-strings/linux-${arch}-${binary}.strings"
    chmod 0400 "${work_dir}/binary-strings/linux-${arch}-${binary}.strings"
  done
done

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

say "Binding the lock, artifacts, source scan, SBOMs, database, vulnerabilities, and secret report"
PYTHONDONTWRITEBYTECODE=1 python3 "${verify_script}" \
  --work-dir "${work_dir}" \
  --lock "${lock_file}" \
  --receipt "${work_dir}/receipt.json"

output_root="${repo_root}/bin/observer-security"
if [[ -e "${output_root}" ]]; then
  [[ -d "${output_root}" && ! -L "${output_root}" ]] || die "observer-security output root is unsafe"
else
  install -d -m 0700 "${output_root}"
fi
readarray -t publication_identity < <(PYTHONDONTWRITEBYTECODE=1 python3 - "${work_dir}/receipt.json" <<'PY'
import datetime as dt
import json
import pathlib
import sys

receipt = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
verified = dt.datetime.fromisoformat(receipt["verified_at"].replace("Z", "+00:00")).astimezone(dt.timezone.utc)
print(receipt["policy"]["sha256"])
print(verified.strftime("%Y%m%dT%H%M%SZ"))
PY
)
policy_digest="${publication_identity[0]:-}"
verification_stamp="${publication_identity[1]:-}"
[[ "${policy_digest}" =~ ^[0-9a-f]{64}$ && "${verification_stamp}" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || die "receipt returned an invalid publication identity"
published_dir="${output_root}/${policy_digest}-${verification_stamp}"
mkdir -m 0700 -- "${published_dir}" || die "refusing to replace existing evidence at ${published_dir}"

for artifact in \
  source-vulnerabilities.txt \
  grype-db-status.json \
  binary-secrets.json \
  linux-amd64.syft.json \
  linux-amd64.spdx.json \
  linux-amd64.vulnerabilities.json \
  linux-arm64.syft.json \
  linux-arm64.spdx.json \
  linux-arm64.vulnerabilities.json \
  receipt.json; do
  install -m 0400 "${work_dir}/${artifact}" "${published_dir}/${artifact}"
done
publish_complete=true

say "PASS: locked observer artifacts, source graph, SBOMs, vulnerability policy, and binary secret scan verified"
say "Evidence: ${published_dir}"
