#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

say() { printf '%s\n' "$*"; }
die() { printf 'Windows package security baseline: %s\n' "$*" >&2; exit 1; }

[[ $# -eq 1 && -n "$1" ]] || die "usage: $0 /clean/absolute/mesh-windows-bundle.tar"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "${script_dir}/.." && pwd -P)"
verify_script="${script_dir}/windows_package_security_verify.py"
gitleaks_config="${repo_root}/.gitleaks-image.toml"
bundle="$1"
[[ "${bundle}" == /* && "${bundle}" != / && -f "${bundle}" && ! -L "${bundle}" ]] || die "bundle must be a clean absolute regular-file path"
[[ "$(realpath -e -- "${bundle}")" == "${bundle}" ]] || die "bundle path cannot traverse symlinks or noncanonical components"
[[ -f "${verify_script}" && -f "${gitleaks_config}" ]] || die "verification inputs are missing"

for required in docker python3 strings go id install mktemp realpath sha256sum stat; do
  command -v "${required}" >/dev/null 2>&1 || die "required command is unavailable: ${required}"
done
docker info >/dev/null 2>&1 || die "Docker daemon is unavailable"
[[ "$(id -u)" -ne 0 ]] || die "run this gate as the unprivileged release build account, not root"

syft_version="1.44.0"
grype_version="0.112.0"
gitleaks_version="v8.30.1"
syft_image="docker.io/anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6"
grype_image="docker.io/anchore/grype@sha256:391bfda62888fb4e98ff5c4c81598f7431a3c1eac3f8519d69d1ff00df247c1d"
gitleaks_image="ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"

temporary_parent="${TMPDIR:-/tmp}"
[[ -d "${temporary_parent}" && ! -L "${temporary_parent}" ]] || die "temporary directory parent is unavailable or linked"
temporary_parent="$(cd -- "${temporary_parent}" && pwd -P)"
work_dir="$(mktemp -d "${temporary_parent%/}/mesh-windows-package-security.XXXXXX")"
[[ -d "${work_dir}" && ! -L "${work_dir}" && "${work_dir}" == "${temporary_parent%/}/mesh-windows-package-security."* ]] || die "mktemp returned an unsafe workspace"
chmod 0700 "${work_dir}"
install -d -m 0700 "${work_dir}/build" "${work_dir}/db" "${work_dir}/staged" "${work_dir}/text" "${work_dir}/binary-strings"

published_dir=""
publish_complete=false
cleanup() {
  local status=$?
  trap - EXIT ERR HUP INT TERM
  if [[ "${publish_complete}" != true && -n "${published_dir}" && -d "${published_dir}" && ! -L "${published_dir}" ]]; then
    case "${published_dir}" in
      "${repo_root}/bin/windows-package-security/"*) rm -rf -- "${published_dir}" ;;
      *) printf 'Refusing to remove unexpected partial publication %s\n' "${published_dir}" >&2 ;;
    esac
  fi
  if [[ -n "${work_dir:-}" && -d "${work_dir}" && "${work_dir}" == "${temporary_parent%/}/mesh-windows-package-security."* ]]; then
    chmod -R u+rwX -- "${work_dir}" 2>/dev/null || true
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
  run --rm --network=none --read-only
  --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777
  --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=128 --memory=768m
  --user="$(id -u):$(id -g)" -e HOME=/tmp -e XDG_CACHE_HOME=/tmp/.cache
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

say "Building the current exact Windows package verifier"
cd -- "${repo_root}"
CGO_ENABLED=0 GOOS=linux GOARCH="$(go env GOARCH)" go build -mod=readonly -trimpath -buildvcs=false \
  -o "${work_dir}/build/mesh-package" ./cmd/mesh-package
chmod 0500 "${work_dir}/build/mesh-package"

say "Stably validating and staging the exact Windows candidate through production policy"
"${work_dir}/build/mesh-package" inspect-windows \
  --artifact "${bundle}" \
  --output-dir "${work_dir}/staged" >"${work_dir}/candidate-inspection.json"
chmod 0400 "${work_dir}/candidate-inspection.json"
artifact_sha="$(python3 - "${work_dir}/candidate-inspection.json" <<'PY'
import json, pathlib, sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
print(document["artifact_sha256"])
PY
)"
[[ "${artifact_sha}" =~ ^[0-9a-f]{64}$ ]] || die "candidate verifier returned an invalid artifact digest"
install -m 0400 "${bundle}" "${work_dir}/bundle.tar"
[[ "$(sha256sum -- "${work_dir}/bundle.tar" | awk '{print $1}')" == "${artifact_sha}" ]] || die "candidate changed while copying the scanner snapshot"

say "Generating exact Windows Syft and SPDX inventories offline"
docker "${scanner_base[@]}" -e SYFT_CHECK_FOR_APP_UPDATE=false -v "${work_dir}:/work:rw" \
  "${syft_image}" dir:/work/staged -o syft-json=/work/sbom.syft.json -o spdx-json=/work/sbom.spdx.json >/dev/null

say "Refreshing the isolated Grype vulnerability database"
docker run --rm --read-only --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=512m,mode=1777 \
  --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=128 --memory=2g \
  --user="$(id -u):$(id -g)" -e HOME=/tmp -e XDG_CACHE_HOME=/tmp/.cache \
  -e GRYPE_DB_CACHE_DIR=/db -e GRYPE_CHECK_FOR_APP_UPDATE=false \
  -v "${work_dir}/db:/db:rw" "${grype_image}" db update >/dev/null
docker "${scanner_base[@]}" -e GRYPE_DB_CACHE_DIR=/db -e GRYPE_CHECK_FOR_APP_UPDATE=false \
  -v "${work_dir}/db:/db:ro" "${grype_image}" db status --output json >"${work_dir}/grype-db-status.json"

say "Scanning the exact Windows package SBOM offline with Grype ${grype_version}"
set +e
docker "${scanner_base[@]}" -e GRYPE_DB_CACHE_DIR=/work/db -e GRYPE_CHECK_FOR_APP_UPDATE=false \
  -v "${work_dir}:/work:rw" "${grype_image}" sbom:/work/sbom.syft.json \
  --fail-on high --output json --file /work/vulnerabilities.json
grype_status=$?
set -e
case "${grype_status}" in 0|2) ;; *) die "Grype failed with status ${grype_status}" ;; esac

say "Scanning exact Windows package text and all four PEs' strings with Gitleaks ${gitleaks_version}"
for path in package.json bin/dist/windows/wintun/LICENSE.txt bin/dist/windows/wintun/README.md share/licenses/nebula/LICENSE; do
  destination="${work_dir}/text/${path//\//__}"
  install -m 0400 "${work_dir}/staged/${path}" "${destination}"
done
arch="$(python3 - "${work_dir}/candidate-inspection.json" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["package"]["target"]["arch"])
PY
)"
for relative in bin/meshctl.exe bin/nebula.exe bin/nebula-cert.exe "bin/dist/windows/wintun/bin/${arch}/wintun.dll"; do
  name="${relative//\//__}"
  strings -a -n 8 "${work_dir}/staged/${relative}" >"${work_dir}/binary-strings/${name}.strings"
  chmod 0400 "${work_dir}/binary-strings/${name}.strings"
done
for scan in text binary-strings; do
  report="text-secrets.json"
  [[ "${scan}" == binary-strings ]] && report="binary-secrets.json"
  docker "${scanner_base[@]}" -v "${work_dir}/${scan}:/scan:ro" -v "${work_dir}:/output:rw" \
    -v "${gitleaks_config}:/config/image.toml:ro" "${gitleaks_image}" dir /scan \
    --config=/config/image.toml --no-banner --no-color --redact=100 \
    --max-target-megabytes=128 --max-archive-depth=0 --max-decode-depth=3 --timeout=120 \
    --report-format=json --report-path="/output/${report}"
done

say "Binding Windows candidate, exact inventory, vulnerability, and secret evidence"
PYTHONDONTWRITEBYTECODE=1 python3 "${verify_script}" \
  --work-dir "${work_dir}" --verifier "${work_dir}/build/mesh-package" --receipt "${work_dir}/receipt.json"

output_root="${repo_root}/bin/windows-package-security"
if [[ -e "${output_root}" ]]; then
  [[ -d "${output_root}" && ! -L "${output_root}" ]] || die "evidence output root is unsafe"
else
  install -d -m 0700 "${output_root}"
fi
verification_stamp="$(python3 - "${work_dir}/receipt.json" <<'PY'
import datetime as dt, json, pathlib, sys
receipt = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
value = dt.datetime.fromisoformat(receipt["verified_at"].replace("Z", "+00:00")).astimezone(dt.timezone.utc)
print(value.strftime("%Y%m%dT%H%M%SZ"))
PY
)"
[[ "${verification_stamp}" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || die "receipt returned an invalid verification time"
published_dir="${output_root}/${artifact_sha}-${verification_stamp}"
mkdir -m 0700 -- "${published_dir}" || die "refusing to replace existing evidence at ${published_dir}"
for evidence in candidate-inspection.json sbom.syft.json sbom.spdx.json grype-db-status.json vulnerabilities.json text-secrets.json binary-secrets.json receipt.json; do
  install -m 0400 "${work_dir}/${evidence}" "${published_dir}/${evidence}"
done
publish_complete=true

say "PASS: exact final signed Windows bundle, production policy, SBOM, current vulnerability policy, and redacted secret scans verified"
say "Evidence: ${published_dir}"
