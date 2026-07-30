#!/bin/bash
# Produce create-only security evidence for one exact unsigned MeshMobile XCFramework.
set -Eeuo pipefail
umask 077

say() { printf '%s\n' "$*"; }
die() { printf 'Apple mobile framework security baseline: %s\n' "$*" >&2; exit 1; }

[[ $# -eq 2 ]] || die "usage: $0 /absolute/MeshMobile.xcframework /absolute/source-receipt.json"
[[ "$(uname -s)" == Darwin ]] || die "this gate requires a native Mac"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "${script_dir}/.." && pwd -P)"
engine_root="${repo_root}/ios-tunnel/engine"
verify_script="${script_dir}/apple_mobile_framework_security_verify.py"
gitleaks_config="${repo_root}/.gitleaks-apple-mobile.toml"
framework="$1"
source_receipt="$2"

[[ "${framework}" == /* && -d "${framework}" && ! -L "${framework}" && "${framework##*/}" == "MeshMobile.xcframework" ]] || die "framework must be an absolute unlinked MeshMobile.xcframework directory"
[[ "${source_receipt}" == /* && -f "${source_receipt}" && ! -L "${source_receipt}" ]] || die "source receipt must be an absolute unlinked regular file"
[[ -f "${verify_script}" && -f "${gitleaks_config}" ]] || die "verification inputs are missing"
[[ "$(id -u)" -ne 0 ]] || die "run this gate as the unprivileged release build account, not root"

for required in docker go python3 strings id install mktemp stat ditto; do
  command -v "${required}" >/dev/null 2>&1 || die "required command is unavailable: ${required}"
done
[[ "$(go version)" == "go version go1.26.5 darwin/arm64" ]] || die "Go 1.26.5 darwin/arm64 is required"
docker info >/dev/null 2>&1 || die "Docker daemon is unavailable"

for name in \
  AC_PASSWORD APPLE_ID APPLE_TEAM_ID APP_STORE_CONNECT_API_KEY \
  APP_STORE_CONNECT_API_KEY_ID APP_STORE_CONNECT_ISSUER_ID \
  DEVELOPER_ID_APPLICATION DEVELOPER_ID_INSTALLER FASTLANE_PASSWORD \
  MATCH_PASSWORD NOTARY_PASSWORD NOTARY_PROFILE; do
  [[ -z "${!name:-}" ]] || die "unsigned security scan received release credential variable ${name}"
done

syft_version="1.44.0"
grype_version="0.112.0"
gitleaks_version="v8.30.1"
syft_image="docker.io/anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6"
grype_image="docker.io/anchore/grype@sha256:391bfda62888fb4e98ff5c4c81598f7431a3c1eac3f8519d69d1ff00df247c1d"
gitleaks_image="ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"

temporary_parent="${TMPDIR:-/tmp}"
[[ -d "${temporary_parent}" && ! -L "${temporary_parent}" ]] || die "temporary directory parent is unavailable or linked"
temporary_parent="$(cd -- "${temporary_parent}" && pwd -P)"
work_dir="$(mktemp -d "${temporary_parent%/}/mesh-apple-mobile-security.XXXXXX")"
[[ -d "${work_dir}" && ! -L "${work_dir}" && "${work_dir}" == "${temporary_parent%/}/mesh-apple-mobile-security."* ]] || die "mktemp returned an unsafe workspace"
chmod 0700 "${work_dir}"
install -d -m 0700 \
  "${work_dir}/scan-root" \
  "${work_dir}/scan-root/metadata" \
  "${work_dir}/scan-root/metadata/runtime" \
  "${work_dir}/db" \
  "${work_dir}/metadata" \
  "${work_dir}/framework-strings" \
  "${work_dir}/docker-config"
export DOCKER_CONFIG="${work_dir}/docker-config"

published_dir=""
publish_complete=false
cleanup() {
  local status=$?
  trap - EXIT ERR HUP INT TERM
  if [[ "${publish_complete}" != true && -n "${published_dir}" && -d "${published_dir}" && ! -L "${published_dir}" ]]; then
    case "${published_dir}" in
      "${repo_root}/bin/apple-mobile-framework-security/"*) rm -rf -- "${published_dir}" ;;
      *) printf 'Refusing to remove unexpected partial publication %s\n' "${published_dir}" >&2 ;;
    esac
  fi
  if [[ -n "${work_dir:-}" && -d "${work_dir}" && "${work_dir}" == "${temporary_parent%/}/mesh-apple-mobile-security."* ]]; then
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

say "Taking a stable snapshot of the exact unsigned mobile framework"
/usr/bin/ditto --norsrc --noextattr "${framework}" "${work_dir}/scan-root/MeshMobile.xcframework"
install -m 0400 "${source_receipt}" "${work_dir}/source-receipt.json"
install -m 0400 "${source_receipt}" "${work_dir}/scan-root/metadata/source-receipt.json"
install -m 0400 "${engine_root}/go.mod" "${work_dir}/scan-root/metadata/go.mod"
install -m 0400 "${engine_root}/go.sum" "${work_dir}/scan-root/metadata/go.sum"

say "Resolving the exact iOS arm64 runtime module and license inventory"
python3 - "${engine_root}" "${work_dir}/scan-root/metadata/runtime" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

engine = pathlib.Path(sys.argv[1])
runtime = pathlib.Path(sys.argv[2])
expected = {
    "dario.cat/mergo": "v1.0.2",
    "filippo.io/bigmod": "v0.1.0",
    "github.com/anmitsu/go-shlex": "v0.0.0-20200514113438-38f4b401e2be",
    "github.com/armon/go-radix": "v1.0.0",
    "github.com/beorn7/perks": "v1.0.1",
    "github.com/cespare/xxhash/v2": "v2.3.0",
    "github.com/cyberdelia/go-metrics-graphite": "v0.0.0-20161219230853-39f87cc3b432",
    "github.com/flynn/noise": "v1.1.0",
    "github.com/gaissmai/bart": "v0.26.0",
    "github.com/gogo/protobuf": "v1.3.2",
    "github.com/google/gopacket": "v1.1.19",
    "github.com/miekg/dns": "v1.1.70",
    "github.com/munnerz/goautoneg": "v0.0.0-20191010083416-a7dc8b61c822",
    "github.com/nbrownus/go-metrics-prometheus": "v0.0.0-20210712211119-974a6260965f",
    "github.com/prometheus/client_golang": "v1.23.2",
    "github.com/prometheus/client_model": "v0.6.2",
    "github.com/prometheus/common": "v0.66.1",
    "github.com/rcrowley/go-metrics": "v0.0.0-20201227073835-cf1acfcdf475",
    "github.com/sirupsen/logrus": "v1.9.4",
    "github.com/slackhq/nebula": "v1.10.3",
    "github.com/stefanberger/go-pkcs11uri": "v0.0.0-20230803200340-78284954bff6",
    "go.yaml.in/yaml/v2": "v2.4.2",
    "go.yaml.in/yaml/v3": "v3.0.4",
    "golang.org/x/crypto": "v0.54.0",
    "golang.org/x/mobile": "v0.0.0-20260709172247-6129f5bee9d5",
    "golang.org/x/net": "v0.57.0",
    "golang.org/x/sys": "v0.47.0",
    "golang.org/x/term": "v0.45.0",
    "google.golang.org/protobuf": "v1.36.11",
}
environment = dict(os.environ)
environment.update({"GOOS": "ios", "GOARCH": "arm64", "CGO_ENABLED": "1"})


def run_json(arguments):
    result = subprocess.run(
        arguments,
        cwd=engine,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=300,
    )
    return json.loads(result.stdout)


result = subprocess.run(
    ["go", "list", "-deps", "-json", "."],
    cwd=engine,
    env=environment,
    check=True,
    capture_output=True,
    text=True,
    timeout=300,
)
decoder = json.JSONDecoder()
position = 0
modules = {}
while position < len(result.stdout):
    while position < len(result.stdout) and result.stdout[position].isspace():
        position += 1
    if position == len(result.stdout):
        break
    package, position = decoder.raw_decode(result.stdout, position)
    module = package.get("Module")
    if isinstance(module, dict) and not module.get("Main"):
        if module.get("Path") == "mesh":
            replacement = module.get("Replace")
            if (
                not isinstance(replacement, dict)
                or pathlib.Path(replacement.get("Dir", "")).resolve()
                != engine.parents[1].resolve()
            ):
                raise SystemExit(
                    "Apple mobile framework security baseline: shared Mesh source replacement is invalid"
                )
            continue
        modules[module["Path"]] = module["Version"]
modules["golang.org/x/mobile"] = run_json(
    [
        "go",
        "list",
        "-m",
        "-json",
        f"golang.org/x/mobile@{expected['golang.org/x/mobile']}",
    ]
)["Version"]
if modules != expected:
    raise SystemExit(
        "Apple mobile framework security baseline: runtime module graph differs from the reviewed allowlist"
    )

license_pattern = re.compile(
    r"^(?:LICENSE|COPYING|NOTICE)(?:[.-].*)?$", re.IGNORECASE
)
records = []
for index, (name, version) in enumerate(sorted(modules.items())):
    downloaded = run_json(["go", "mod", "download", "-json", f"{name}@{version}"])
    if downloaded.get("Error"):
        raise SystemExit(
            f"Apple mobile framework security baseline: module download failed: {name}"
        )
    module_dir = pathlib.Path(downloaded["Dir"])
    found = sorted(
        path
        for path in module_dir.iterdir()
        if path.is_file()
        and not path.is_symlink()
        and license_pattern.fullmatch(path.name)
    )
    if not found:
        raise SystemExit(
            f"Apple mobile framework security baseline: module lacks a top-level license or notice: {name}"
        )
    destination = runtime / "licenses" / f"{index:02d}"
    destination.mkdir(parents=True, mode=0o700)
    licenses = []
    for source in found:
        target = destination / source.name
        shutil.copyfile(source, target)
        os.chmod(target, 0o400)
        payload = target.read_bytes()
        licenses.append(
            {
                "name": source.name,
                "path": f"licenses/{index:02d}/{source.name}",
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
        )
    records.append(
        {
            "name": name,
            "version": version,
            "sum": downloaded["Sum"],
            "go_mod_sum": downloaded["GoModSum"],
            "licenses": licenses,
        }
    )
manifest = {
    "schema": "mesh-apple-mobile-runtime-modules-v1",
    "goos": "ios",
    "goarch": "arm64",
    "modules": records,
}
manifest_path = runtime / "runtime-modules.json"
manifest_path.write_text(
    json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
os.chmod(manifest_path, 0o400)
PY

python3 - "${work_dir}" <<'PY'
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path.cwd() / "scripts"))
from apple_mobile_framework_receipt import tree_identity
from apple_mobile_framework_security_verify import canonical_source_receipt

work = pathlib.Path(sys.argv[1])
receipt = canonical_source_receipt(work / "source-receipt.json")
observed = tree_identity(work / "scan-root" / "MeshMobile.xcframework")
expected = receipt["framework"]
if observed != (
    expected["tree_sha256"],
    expected["regular_files"],
    expected["regular_file_bytes"],
):
    raise SystemExit(
        "Apple mobile framework security baseline: stable framework snapshot differs from its source receipt"
    )
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

say "Scanning the exact framework SBOM offline with Grype ${grype_version}"
set +e
docker "${scanner_base[@]}" \
  -e GRYPE_DB_CACHE_DIR=/work/db -e GRYPE_CHECK_FOR_APP_UPDATE=false \
  -v "${work_dir}:/work:rw" "${grype_image}" sbom:/work/sbom.syft.json \
  --fail-on high --output json --file /work/vulnerabilities.json
grype_status=$?
set -e
case "${grype_status}" in 0|2) ;; *) die "Grype failed with status ${grype_status}" ;; esac

say "Preparing bound metadata and secret-scan strings from every framework file"
/usr/bin/ditto --norsrc --noextattr \
  "${work_dir}/scan-root/metadata" "${work_dir}/metadata"
python3 - "${work_dir}/scan-root/MeshMobile.xcframework" "${work_dir}/framework-strings" <<'PY'
import json
import os
import pathlib
import subprocess
import sys

framework, output = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
paths = sorted(
    path for path in framework.rglob("*") if path.is_file() and not path.is_symlink()
)
for index, path in enumerate(paths):
    destination = output / f"{index:04d}.strings"
    relative = path.relative_to(framework)
    with destination.open("wb") as target:
        result = subprocess.run(
            ["/usr/bin/strings", "-a", "-n", "8", str(path)],
            check=False,
            stdout=target,
            stderr=subprocess.PIPE,
        )
    if result.returncode != 0:
        raise SystemExit(f"strings failed for {relative}")
    os.chmod(destination, 0o400)
(output / "paths.json").write_text(
    json.dumps(
        [str(path.relative_to(framework)) for path in paths],
        sort_keys=True,
        separators=(",", ":"),
    )
    + "\n",
    encoding="utf-8",
)
os.chmod(output / "paths.json", 0o400)
PY

say "Scanning bound metadata and framework strings with Gitleaks ${gitleaks_version}"
for scan in metadata framework-strings; do
  report="metadata-secrets.json"
  [[ "${scan}" == framework-strings ]] && report="framework-strings-secrets.json"
  docker "${scanner_base[@]}" \
    -v "${work_dir}/${scan}:/scan:ro" -v "${work_dir}:/output:rw" \
    -v "${gitleaks_config}:/config/apple-mobile.toml:ro" "${gitleaks_image}" dir /scan \
    --config=/config/apple-mobile.toml --no-banner --no-color --redact=100 \
    --max-target-megabytes=128 --max-archive-depth=0 --max-decode-depth=3 --timeout=120 \
    --report-format=json --report-path="/output/${report}"
done

say "Binding framework, dependency, license, vulnerability, and secret evidence"
PYTHONDONTWRITEBYTECODE=1 python3 "${verify_script}" \
  --work-dir "${work_dir}" \
  --receipt "${work_dir}/receipt.json"

artifact_sha="$(python3 - "${work_dir}/receipt.json" <<'PY'
import json
import pathlib
import sys

print(
    json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))[
        "artifact"
    ]["tree_sha256"]
)
PY
)"
verification_stamp="$(python3 - "${work_dir}/receipt.json" <<'PY'
import datetime as dt
import json
import pathlib
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["verified_at"]
print(
    dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    .astimezone(dt.timezone.utc)
    .strftime("%Y%m%dT%H%M%SZ")
)
PY
)"
[[ "${artifact_sha}" =~ ^[0-9a-f]{64}$ && "${verification_stamp}" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || die "receipt returned an invalid identity"
output_root="${repo_root}/bin/apple-mobile-framework-security"
if [[ -e "${output_root}" ]]; then
  [[ -d "${output_root}" && ! -L "${output_root}" ]] || die "evidence output root is unsafe"
else
  install -d -m 0700 "${output_root}"
fi
published_dir="${output_root}/${artifact_sha}-${verification_stamp}"
mkdir -m 0700 -- "${published_dir}" || die "refusing to replace existing evidence at ${published_dir}"
for evidence in source-receipt.json sbom.syft.json sbom.spdx.json grype-db-status.json vulnerabilities.json metadata-secrets.json framework-strings-secrets.json receipt.json; do
  install -m 0400 "${work_dir}/${evidence}" "${published_dir}/${evidence}"
done
/usr/bin/ditto --norsrc --noextattr \
  "${work_dir}/scan-root/metadata/runtime" "${published_dir}/runtime"
chmod -R a-w "${published_dir}/runtime"
publish_complete=true

say "PASS: exact unsigned iOS mobile framework security evidence verified"
say "Evidence: ${published_dir}"
