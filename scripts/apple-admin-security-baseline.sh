#!/bin/bash
# Produce create-only security evidence for one exact unsigned macOS Admin app.
set -Eeuo pipefail
umask 077

say() { printf '%s\n' "$*"; }
die() { printf 'Apple Admin security baseline: %s\n' "$*" >&2; exit 1; }

[[ $# -eq 3 ]] || die "usage: $0 /absolute/Mesh\\ Admin.app /absolute/source-receipt.json /absolute/flutter"
[[ "$(uname -s)" == Darwin ]] || die "this gate requires a native Mac"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "${script_dir}/.." && pwd -P)"
desktop_root="${repo_root}/desktop"
verify_script="${script_dir}/apple_admin_security_verify.py"
gitleaks_config="${repo_root}/.gitleaks-image.toml"
app="$1"
source_receipt="$2"
flutter="$3"

[[ "${app}" == /* && -d "${app}" && ! -L "${app}" && "${app##*/}" == "Mesh Admin.app" ]] || die "app must be an absolute unlinked Mesh Admin.app directory"
[[ "${source_receipt}" == /* && -f "${source_receipt}" && ! -L "${source_receipt}" ]] || die "source receipt must be an absolute unlinked regular file"
[[ "${flutter}" == /* && -x "${flutter}" && ! -L "${flutter}" && "${flutter##*/}" == flutter ]] || die "flutter must be the absolute executable from the verified pinned SDK"
[[ -f "${verify_script}" && -f "${gitleaks_config}" ]] || die "verification inputs are missing"
[[ "$(id -u)" -ne 0 ]] || die "run this gate as the unprivileged release build account, not root"

for required in docker python3 strings id install mktemp stat ditto; do
  command -v "${required}" >/dev/null 2>&1 || die "required command is unavailable: ${required}"
done
docker info >/dev/null 2>&1 || die "Docker daemon is unavailable"

for name in \
  AC_PASSWORD APPLE_ID APPLE_TEAM_ID APP_STORE_CONNECT_API_KEY \
  APP_STORE_CONNECT_API_KEY_ID APP_STORE_CONNECT_ISSUER_ID \
  DEVELOPER_ID_APPLICATION DEVELOPER_ID_INSTALLER FASTLANE_PASSWORD \
  MATCH_PASSWORD NOTARY_PASSWORD NOTARY_PROFILE; do
  [[ -z "${!name:-}" ]] || die "unsigned security scan received release credential variable ${name}"
done

flutter_identity="$("${flutter}" --version --machine)"
python3 - "${desktop_root}/tool/flutter-sdk.json" "${flutter_identity}" <<'PY'
import json, pathlib, sys
declared = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
actual = json.loads(sys.argv[2])
if actual.get("frameworkVersion") != declared["version"]:
    raise SystemExit("Apple Admin security baseline: Flutter version differs from the pinned declaration")
if actual.get("frameworkRevision") != declared["framework_commit"]:
    raise SystemExit("Apple Admin security baseline: Flutter commit differs from the pinned declaration")
PY
dart="${flutter%/flutter}/dart"
[[ -x "${dart}" && ! -L "${dart}" ]] || die "pinned Flutter SDK does not contain its Dart executable"

syft_version="1.44.0"
grype_version="0.112.0"
gitleaks_version="v8.30.1"
syft_image="docker.io/anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6"
grype_image="docker.io/anchore/grype@sha256:391bfda62888fb4e98ff5c4c81598f7431a3c1eac3f8519d69d1ff00df247c1d"
gitleaks_image="ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"

temporary_parent="${TMPDIR:-/tmp}"
[[ -d "${temporary_parent}" && ! -L "${temporary_parent}" ]] || die "temporary directory parent is unavailable or linked"
temporary_parent="$(cd -- "${temporary_parent}" && pwd -P)"
work_dir="$(mktemp -d "${temporary_parent%/}/mesh-apple-admin-security.XXXXXX")"
[[ -d "${work_dir}" && ! -L "${work_dir}" && "${work_dir}" == "${temporary_parent%/}/mesh-apple-admin-security."* ]] || die "mktemp returned an unsafe workspace"
chmod 0700 "${work_dir}"
install -d -m 0700 "${work_dir}/scan-root" "${work_dir}/scan-root/metadata" "${work_dir}/db" "${work_dir}/metadata" "${work_dir}/app-strings" "${work_dir}/docker-config"
export DOCKER_CONFIG="${work_dir}/docker-config"

published_dir=""
publish_complete=false
cleanup() {
  local status=$?
  trap - EXIT ERR HUP INT TERM
  if [[ "${publish_complete}" != true && -n "${published_dir}" && -d "${published_dir}" && ! -L "${published_dir}" ]]; then
    case "${published_dir}" in
      "${repo_root}/bin/apple-admin-security/"*) rm -rf -- "${published_dir}" ;;
      *) printf 'Refusing to remove unexpected partial publication %s\n' "${published_dir}" >&2 ;;
    esac
  fi
  if [[ -n "${work_dir:-}" && -d "${work_dir}" && "${work_dir}" == "${temporary_parent%/}/mesh-apple-admin-security."* ]]; then
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

say "Taking a stable snapshot of the exact unsigned Release app"
/usr/bin/ditto --norsrc --noextattr "${app}" "${work_dir}/scan-root/Mesh Admin.app"
install -m 0400 "${source_receipt}" "${work_dir}/source-receipt.json"
install -m 0400 "${desktop_root}/pubspec.yaml" "${work_dir}/scan-root/metadata/pubspec.yaml"
install -m 0400 "${desktop_root}/pubspec.lock" "${work_dir}/scan-root/metadata/pubspec.lock"
(
  cd -- "${desktop_root}"
  "${dart}" pub deps --json >"${work_dir}/pub-deps.json"
)
chmod 0400 "${work_dir}/pub-deps.json"

python3 - "${work_dir}" <<'PY'
import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path.cwd() / "scripts"))
from apple_admin_security_verify import canonical_source_receipt
from apple_source_artifact_receipt import tree_identity
work = pathlib.Path(sys.argv[1])
receipt = canonical_source_receipt(work / "source-receipt.json")
observed = tree_identity(work / "scan-root" / "Mesh Admin.app")
expected = receipt["bundle"]
if observed != (expected["tree_sha256"], expected["regular_files"], expected["regular_file_bytes"]):
    raise SystemExit("Apple Admin security baseline: stable app snapshot differs from its source receipt")
PY

say "Generating exact Syft and SPDX inventories offline"
docker "${scanner_base[@]}" \
  -e SYFT_CHECK_FOR_APP_UPDATE=false \
  -v "${work_dir}/scan-root:/scan:ro" -v "${work_dir}:/output:rw" \
  "${syft_image}" dir:/scan \
  -o syft-json=/output/sbom.syft.json \
  -o spdx-json=/output/sbom.spdx.json >/dev/null

say "Refreshing the isolated Grype vulnerability database"
docker run --rm --read-only \
  --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=512m,mode=1777 \
  --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=128 --memory=2g \
  --user="$(id -u):$(id -g)" -e HOME=/tmp -e XDG_CACHE_HOME=/tmp/.cache \
  -e GRYPE_DB_CACHE_DIR=/db -e GRYPE_CHECK_FOR_APP_UPDATE=false \
  -v "${work_dir}/db:/db:rw" "${grype_image}" db update >/dev/null
docker "${scanner_base[@]}" \
  -e GRYPE_DB_CACHE_DIR=/db -e GRYPE_CHECK_FOR_APP_UPDATE=false \
  -v "${work_dir}/db:/db:ro" "${grype_image}" db status --output json >"${work_dir}/grype-db-status.json"

say "Scanning the exact app SBOM offline with Grype ${grype_version}"
set +e
docker "${scanner_base[@]}" \
  -e GRYPE_DB_CACHE_DIR=/work/db -e GRYPE_CHECK_FOR_APP_UPDATE=false \
  -v "${work_dir}:/work:rw" "${grype_image}" sbom:/work/sbom.syft.json \
  --fail-on high --output json --file /work/vulnerabilities.json
grype_status=$?
set -e
case "${grype_status}" in 0|2) ;; *) die "Grype failed with status ${grype_status}" ;; esac

say "Preparing metadata and secret-scan text from every regular app-bundle file"
install -m 0400 "${work_dir}/source-receipt.json" "${work_dir}/metadata/source-receipt.json"
install -m 0400 "${work_dir}/pub-deps.json" "${work_dir}/metadata/pub-deps.json"
install -m 0400 "${desktop_root}/pubspec.yaml" "${work_dir}/metadata/pubspec.yaml"
install -m 0400 "${desktop_root}/pubspec.lock" "${work_dir}/metadata/pubspec.lock"
python3 - "${work_dir}/scan-root/Mesh Admin.app" "${work_dir}/app-strings" <<'PY'
import json, os, pathlib, plistlib, subprocess, sys
app, output = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
paths = sorted(path for path in app.rglob("*") if path.is_file() and not path.is_symlink())

def normalize_code_resources(value):
    if isinstance(value, bytes):
        return "<generated-code-signature-digest>"
    if isinstance(value, dict):
        return {
            key: normalize_code_resources(item)
            for key, item in sorted(value.items())
        }
    if isinstance(value, list):
        return [normalize_code_resources(item) for item in value]
    return value

for index, path in enumerate(paths):
    destination = output / f"{index:04d}.strings"
    relative = path.relative_to(app)
    if (
        path.name == "CodeResources"
        and path.parent.name == "_CodeSignature"
    ):
        document = plistlib.loads(path.read_bytes())
        destination.write_text(
            json.dumps(
                normalize_code_resources(document),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
    else:
        with destination.open("wb") as target:
            result = subprocess.run(
                ["/usr/bin/strings", "-a", "-n", "8", str(path)],
                check=False, stdout=target, stderr=subprocess.PIPE,
            )
        if result.returncode != 0:
            raise SystemExit(f"strings failed for {relative}")
    os.chmod(destination, 0o400)
(output / "paths.json").write_text(
    json.dumps(
        [str(path.relative_to(app)) for path in paths],
        sort_keys=True, separators=(",", ":"),
    ) + "\n",
    encoding="utf-8",
)
os.chmod(output / "paths.json", 0o400)
PY
python3 - "${work_dir}/scan-root/Mesh Admin.app/Contents/Frameworks/App.framework/Versions/A/Resources/flutter_assets/NOTICES.Z" "${work_dir}/metadata/NOTICES.txt" <<'PY'
import gzip, os, pathlib, sys
payload = gzip.decompress(pathlib.Path(sys.argv[1]).read_bytes())
pathlib.Path(sys.argv[2]).write_bytes(payload)
os.chmod(sys.argv[2], 0o400)
PY

say "Scanning bound metadata and app strings with Gitleaks ${gitleaks_version}"
for scan in metadata app-strings; do
  report="metadata-secrets.json"
  [[ "${scan}" == app-strings ]] && report="app-strings-secrets.json"
  docker "${scanner_base[@]}" \
    -v "${work_dir}/${scan}:/scan:ro" -v "${work_dir}:/output:rw" \
    -v "${gitleaks_config}:/config/image.toml:ro" "${gitleaks_image}" dir /scan \
    --config=/config/image.toml --no-banner --no-color --redact=100 \
    --max-target-megabytes=128 --max-archive-depth=0 --max-decode-depth=3 --timeout=120 \
    --report-format=json --report-path="/output/${report}"
done

say "Binding app, dependency, license, privacy, vulnerability, and secret evidence"
PYTHONDONTWRITEBYTECODE=1 python3 "${verify_script}" \
  --work-dir "${work_dir}" \
  --receipt "${work_dir}/receipt.json"

artifact_sha="$(python3 - "${work_dir}/receipt.json" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["artifact"]["tree_sha256"])
PY
)"
verification_stamp="$(python3 - "${work_dir}/receipt.json" <<'PY'
import datetime as dt, json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["verified_at"]
print(dt.datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
PY
)"
[[ "${artifact_sha}" =~ ^[0-9a-f]{64}$ && "${verification_stamp}" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || die "receipt returned an invalid identity"
output_root="${repo_root}/bin/apple-admin-security"
if [[ -e "${output_root}" ]]; then
  [[ -d "${output_root}" && ! -L "${output_root}" ]] || die "evidence output root is unsafe"
else
  install -d -m 0700 "${output_root}"
fi
published_dir="${output_root}/${artifact_sha}-${verification_stamp}"
mkdir -m 0700 -- "${published_dir}" || die "refusing to replace existing evidence at ${published_dir}"
for evidence in source-receipt.json pub-deps.json sbom.syft.json sbom.spdx.json grype-db-status.json vulnerabilities.json metadata-secrets.json app-strings-secrets.json receipt.json; do
  install -m 0400 "${work_dir}/${evidence}" "${published_dir}/${evidence}"
done
publish_complete=true

say "PASS: exact unsigned macOS Admin app security evidence verified"
say "Evidence: ${published_dir}"
