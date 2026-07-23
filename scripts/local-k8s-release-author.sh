#!/usr/bin/env bash

# Author one private, threshold-signed Linux release for the local Kubernetes
# verification deployment. Signing keys and the independent bootstrap anchor
# remain outside the public origin generation.

set -Eeuo pipefail
umask 077

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"

die() {
  printf 'local-k8s-release-author: %s\n' "$*" >&2
  exit 1
}

usage() {
  printf '%s\n' \
    'usage:' \
    '  local-k8s-release-author.sh prepare ABSOLUTE_OUTPUT_ROOT HTTPS_ORIGIN VERSION COMMIT NEBULA_DIR' \
    '  local-k8s-release-author.sh finalize ABSOLUTE_OUTPUT_ROOT LINUX_SECURITY_RECEIPT' >&2
  exit 2
}

require_command() {
  command -v -- "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

require_private_root() {
  local root="$1"
  [[ "${root}" == /* && "${root}" != / && -d "${root}" && ! -L "${root}" ]] ||
    die "output root must be an absolute real directory"
  [[ "$(realpath -e -- "${root}")" == "${root}" ]] ||
    die "output root path is not canonical"
  [[ "$(stat -c '%u:%a' -- "${root}")" == "$(id -u):700" ]] ||
    die "output root must be effective-user-owned mode 0700"
}

validate_origin() {
  python3 - "$1" <<'PY'
import re
import sys
import urllib.parse

raw = sys.argv[1]
parsed = urllib.parse.urlsplit(raw)
if (
    parsed.scheme != "https"
    or parsed.username is not None
    or parsed.password is not None
    or not parsed.hostname
    or parsed.port is not None
    or parsed.path not in ("", "/")
    or parsed.query
    or parsed.fragment
    or raw != f"https://{parsed.hostname}"
    or parsed.hostname != parsed.hostname.lower()
    or parsed.hostname.endswith(".")
    or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in parsed.hostname.split(".")
    )
):
    raise SystemExit("origin must be one canonical DNS HTTPS origin without an explicit port")
PY
}

prepare() {
  [[ $# -eq 5 ]] || usage
  local output_root="$1"
  local origin="$2"
  local version="$3"
  local commit="$4"
  local nebula_dir="$5"
  local parent root_name architecture issued_at verification_at release_expires root_expires
  local source_epoch build_identity authenticode_policy installer_policy
  local mesh_release mesh_package verifier_os verifier_arch verifier_suffix verifier_ldflags signer

  validate_origin "${origin}"
  [[ "${version}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
    die "version must be canonical SemVer without prerelease metadata"
  [[ "${commit}" =~ ^[0-9a-f]{40}$ ]] || die "commit must be forty lowercase hexadecimal characters"
  [[ "${output_root}" == /* && "${output_root}" != / && ! -e "${output_root}" && ! -L "${output_root}" ]] ||
    die "prepare output root must be a new absolute path"
  parent="$(dirname -- "${output_root}")"
  root_name="$(basename -- "${output_root}")"
  [[ "${root_name}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] ||
    die "output root name is not canonical"
  [[ -d "${parent}" && ! -L "${parent}" && "$(realpath -e -- "${parent}")/${root_name}" == "${output_root}" ]] ||
    die "output root parent is unavailable, linked, or noncanonical"
  [[ -d "${nebula_dir}" && ! -L "${nebula_dir}" && "$(realpath -e -- "${nebula_dir}")" == "${nebula_dir}" ]] ||
    die "Nebula dependency directory must be a canonical real directory"
  for file in nebula nebula-cert observer-build.json; do
    [[ -f "${nebula_dir}/${file}" && ! -L "${nebula_dir}/${file}" ]] ||
      die "Nebula dependency is missing or unsafe: ${file}"
  done

  architecture="$(go env GOARCH)"
  [[ "${architecture}" == "amd64" ]] || die "local Kubernetes release author currently requires linux/amd64"
  install -d -m 0700 \
    "${output_root}" \
    "${output_root}/authority" \
    "${output_root}/signing" \
    "${output_root}/tools" \
    "${output_root}/repository/bootstrap/stable" \
    "${output_root}/repository/channels/stable" \
    "${output_root}/repository/releases/${version}" \
    "${output_root}/generations"
  require_private_root "${output_root}"

  mesh_release="${output_root}/tools/mesh-release"
  mesh_package="${output_root}/tools/mesh-package"
  (
    cd -- "${repo_root}"
    CGO_ENABLED=0 GOOS=linux GOARCH="${architecture}" go build \
      -mod=readonly -trimpath -buildvcs=false -o "${mesh_release}" ./cmd/mesh-release
    CGO_ENABLED=0 GOOS=linux GOARCH="${architecture}" go build \
      -mod=readonly -trimpath -buildvcs=false -o "${mesh_package}" ./cmd/mesh-package
  )
  chmod 0500 "${mesh_release}" "${mesh_package}"

  for signer in root-a root-b release-a release-b; do
    "${mesh_release}" generate-key \
      --private "${output_root}/signing/${signer}.private.json" >/dev/null
    "${mesh_release}" export-public \
      --private "${output_root}/signing/${signer}.private.json" \
      --public "${output_root}/signing/${signer}.public.json" >/dev/null
  done

  issued_at="$(date -u -d '-1 minute' '+%Y-%m-%dT%H:%M:%SZ')"
  verification_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  release_expires="$(date -u -d '+7 days' '+%Y-%m-%dT%H:%M:%SZ')"
  root_expires="$(date -u -d '+30 days' '+%Y-%m-%dT%H:%M:%SZ')"
  source_epoch="$(date -u -d "${verification_at}" '+%s')"

  "${mesh_release}" create-root \
    --output "${output_root}/signing/root-v1.json" \
    --channel stable \
    --release-epoch 1 \
    --minimum-release-sequence 1 \
    --minimum-security-floor 1 \
    --issued "${issued_at}" \
    --expires "${root_expires}" \
    --root-threshold 2 \
    --root-public "${output_root}/signing/root-a.public.json" \
    --root-public "${output_root}/signing/root-b.public.json" \
    --release-threshold 2 \
    --release-public "${output_root}/signing/release-a.public.json" \
    --release-public "${output_root}/signing/release-b.public.json" >/dev/null
  install -m 0400 \
    "${output_root}/signing/root-v1.json" \
    "${output_root}/repository/bootstrap/stable/root-v1.json"

  build_identity="$("${mesh_release}" build-identity \
    --version "${version}" \
    --commit "${commit}" \
    --build-time "${verification_at}" \
    --security-floor 1 \
    --agent-state-read-min 2 \
    --agent-state-read-max 2 \
    --agent-state-write-version 2)"
  [[ "${build_identity}" != *[[:space:]]* ]] || die "compiled build identity is not canonical"
  authenticode_policy="$("${mesh_release}" windows-authenticode-policy \
    --mesh-signer-spki-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --wintun-signer-spki-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)"
  [[ "${authenticode_policy}" != *[[:space:]]* ]] || die "Windows verifier policy is not canonical"

  for verifier_os in linux windows; do
    for verifier_arch in amd64 arm64; do
      verifier_suffix=""
      verifier_ldflags="-buildid= -X mesh/internal/buildinfo.Identity=${build_identity}"
      if [[ "${verifier_os}" == "windows" ]]; then
        verifier_suffix=".exe"
        verifier_ldflags+=" -X mesh/internal/windowsauthenticode.Identity=${authenticode_policy}"
      fi
      (
        cd -- "${repo_root}"
        CGO_ENABLED=0 GOOS="${verifier_os}" GOARCH="${verifier_arch}" go build \
          -mod=readonly -trimpath -buildvcs=false \
          "-ldflags=${verifier_ldflags}" \
          -o "${output_root}/tools/mesh-bootstrap-verify-${verifier_os}-${verifier_arch}${verifier_suffix}" \
          ./cmd/mesh-bootstrap-verify
      )
      "${mesh_package}" build-bootstrap-verifier \
        --version "${version}" \
        --commit "${commit}" \
        --source-date-epoch "${source_epoch}" \
        --security-floor 1 \
        --os "${verifier_os}" \
        --arch "${verifier_arch}" \
        --verifier "${output_root}/tools/mesh-bootstrap-verify-${verifier_os}-${verifier_arch}${verifier_suffix}" \
        --output "${output_root}/repository/bootstrap/stable/mesh-bootstrap-verifier-${verifier_os}-${verifier_arch}.tar" >/dev/null
    done
  done

  "${mesh_release}" create-bootstrap-handoff \
    --output "${output_root}/repository/bootstrap/stable/bootstrap-handoff.json" \
    --root "${output_root}/repository/bootstrap/stable/root-v1.json" \
    --issued "${verification_at}" \
    --expires "${release_expires}" \
    --verifier-package "${output_root}/repository/bootstrap/stable/mesh-bootstrap-verifier-linux-amd64.tar" \
    --verifier-package "${output_root}/repository/bootstrap/stable/mesh-bootstrap-verifier-linux-arm64.tar" \
    --verifier-package "${output_root}/repository/bootstrap/stable/mesh-bootstrap-verifier-windows-amd64.tar" \
    --verifier-package "${output_root}/repository/bootstrap/stable/mesh-bootstrap-verifier-windows-arm64.tar" >/dev/null
  "${mesh_release}" create-bootstrap-anchor \
    --handoff "${output_root}/repository/bootstrap/stable/bootstrap-handoff.json" \
    --output "${output_root}/authority/bootstrap-anchor.json" >/dev/null

  installer_policy="$("${mesh_release}" installer-policy \
    --root "${output_root}/repository/bootstrap/stable/root-v1.json")"
  [[ "${installer_policy}" != *[[:space:]]* ]] || die "installer policy is not canonical"
  (
    cd -- "${repo_root}"
    CGO_ENABLED=0 GOOS=linux GOARCH="${architecture}" go build \
      -mod=readonly -trimpath -buildvcs=false \
      "-ldflags=-s -w -buildid= -X mesh/internal/buildinfo.Identity=${build_identity}" \
      -o "${output_root}/tools/meshctl" ./cmd/meshctl
    CGO_ENABLED=0 GOOS=linux GOARCH="${architecture}" go build \
      -mod=readonly -trimpath -buildvcs=false \
      "-ldflags=-s -w -buildid= -X mesh/internal/buildinfo.Identity=${build_identity} -X mesh/internal/installtrust.Identity=${installer_policy}" \
      -o "${output_root}/repository/bootstrap/stable/mesh-install-linux-${architecture}" ./cmd/mesh-install
  )

  "${mesh_package}" build-linux \
    --version "${version}" \
    --commit "${commit}" \
    --source-date-epoch "${source_epoch}" \
    --security-floor 1 \
    --arch "${architecture}" \
    --mesh-install "${output_root}/repository/bootstrap/stable/mesh-install-linux-${architecture}" \
    --meshctl "${output_root}/tools/meshctl" \
    --nebula-dir "${nebula_dir}" \
    --output "${output_root}/repository/releases/${version}/mesh-linux-bundle.tar" >/dev/null

  "${mesh_release}" create-bootstrap-manifest \
    --output "${output_root}/repository/bootstrap/stable/mesh-install.bootstrap.json" \
    --root "${output_root}/repository/bootstrap/stable/root-v1.json" \
    --installer "${output_root}/repository/bootstrap/stable/mesh-install-linux-${architecture}" \
    --arch "${architecture}" \
    --issued "${verification_at}" \
    --expires "${release_expires}" >/dev/null
  for signer in a b; do
    "${mesh_release}" sign \
      --private "${output_root}/signing/root-${signer}.private.json" \
      --manifest "${output_root}/repository/bootstrap/stable/mesh-install.bootstrap.json" \
      --signature "${output_root}/repository/bootstrap/stable/mesh-install.bootstrap.root-${signer}.json" >/dev/null
  done

  python3 - \
    "${output_root}/prepare.json" \
    "${origin}" "${version}" "${commit}" "${architecture}" \
    "${issued_at}" "${verification_at}" "${release_expires}" "${root_expires}" \
    "${source_epoch}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
document = {
    "schema": "mesh-local-k8s-release-prepare-v1",
    "origin": sys.argv[2],
    "version": sys.argv[3],
    "commit": sys.argv[4],
    "architecture": sys.argv[5],
    "issued_at": sys.argv[6],
    "verification_at": sys.argv[7],
    "release_expires": sys.argv[8],
    "root_expires": sys.argv[9],
    "source_epoch": int(sys.argv[10]),
}
descriptor = path.open("x", encoding="utf-8")
with descriptor:
    json.dump(document, descriptor, separators=(",", ":"), sort_keys=True)
    descriptor.write("\n")
PY
  chmod 0600 "${output_root}/prepare.json"
  printf 'candidate=%s\nanchor=%s\n' \
    "${output_root}/repository/releases/${version}/mesh-linux-bundle.tar" \
    "${output_root}/authority/bootstrap-anchor.json"
}

finalize() {
  [[ $# -eq 2 ]] || usage
  local output_root="$1"
  local security_receipt="$2"
  local mesh_release origin version architecture issued_at release_expires
  local release_dir generation_id generation_path signer handoff_sha security_sha

  require_private_root "${output_root}"
  [[ -f "${output_root}/prepare.json" && ! -L "${output_root}/prepare.json" ]] ||
    die "prepare metadata is missing"
  [[ -f "${security_receipt}" && ! -L "${security_receipt}" && "${security_receipt}" == /* ]] ||
    die "Linux security receipt must be an absolute real file"
  [[ "$(realpath -e -- "${security_receipt}")" == "${security_receipt}" ]] ||
    die "Linux security receipt path is not canonical"
  [[ ! -e "${output_root}/origin-index.json" ]] || die "release is already finalized"

  read -r origin version architecture issued_at release_expires < <(
    python3 - "${output_root}/prepare.json" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if set(document) != {
    "schema", "origin", "version", "commit", "architecture", "issued_at",
    "verification_at", "release_expires", "root_expires", "source_epoch",
} or document["schema"] != "mesh-local-k8s-release-prepare-v1":
    raise SystemExit("prepare metadata is invalid")
for key in ("origin", "version", "architecture", "issued_at", "release_expires"):
    if not isinstance(document[key], str) or not document[key]:
        raise SystemExit("prepare metadata field is invalid")
print(document["origin"], document["version"], document["architecture"], document["issued_at"], document["release_expires"])
PY
  )
  validate_origin "${origin}"
  release_dir="${output_root}/repository/releases/${version}"
  mesh_release="${output_root}/tools/mesh-release"

  "${mesh_release}" create-release-manifest \
    --output "${release_dir}/release.json" \
    --root "${output_root}/signing/root-v1.json" \
    --version "${version}" \
    --sequence 1 \
    --security-floor 1 \
    --issued "${issued_at}" \
    --expires "${release_expires}" \
    --os linux \
    --arch "${architecture}" \
    --artifact-url "${origin}/releases/${version}/mesh-linux-bundle.tar" \
    --artifact "${release_dir}/mesh-linux-bundle.tar" \
    --linux-package-security-receipt "${security_receipt}" >/dev/null
  "${mesh_release}" create-channel-manifest \
    --output "${output_root}/signing/channel.json" \
    --root "${output_root}/signing/root-v1.json" \
    --release-manifest "${release_dir}/release.json" \
    --manifest-url "${origin}/releases/${version}/release.json" \
    --issued "${issued_at}" \
    --expires "${release_expires}" >/dev/null
  for signer in a b; do
    "${mesh_release}" sign \
      --private "${output_root}/signing/release-${signer}.private.json" \
      --manifest "${release_dir}/release.json" \
      --signature "${output_root}/signing/release-${signer}.signature.json" >/dev/null
    "${mesh_release}" sign \
      --private "${output_root}/signing/release-${signer}.private.json" \
      --manifest "${output_root}/signing/channel.json" \
      --signature "${output_root}/signing/channel-${signer}.signature.json" >/dev/null
  done
  "${mesh_release}" assemble-online-bundle \
    --output "${output_root}/repository/channels/stable/bundle.json" \
    --channel-manifest "${output_root}/signing/channel.json" \
    --channel-signature "${output_root}/signing/channel-a.signature.json" \
    --channel-signature "${output_root}/signing/channel-b.signature.json" \
    --release-manifest "${release_dir}/release.json" \
    --release-signature "${output_root}/signing/release-a.signature.json" \
    --release-signature "${output_root}/signing/release-b.signature.json" >/dev/null

  "${mesh_release}" create-origin-index \
    --root "${output_root}/repository" \
    --output "${output_root}/origin-index.json" \
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
    --object /releases/${version}/release.json \
    --object /releases/${version}/mesh-linux-bundle.tar >/dev/null
  generation_id="$(sha256sum -- "${output_root}/origin-index.json" | awk '{print $1}')"
  [[ "${generation_id}" =~ ^[0-9a-f]{64}$ ]] || die "origin generation identity is invalid"
  "${mesh_release}" publish-origin-generation \
    --source-root "${output_root}/repository" \
    --index "${output_root}/origin-index.json" \
    --generations-root "${output_root}/generations" >/dev/null
  generation_path="${output_root}/generations/${generation_id}"
  "${mesh_release}" inspect-origin-generation --generation "${generation_path}" >/dev/null

  handoff_sha="$(sha256sum -- "${output_root}/repository/bootstrap/stable/bootstrap-handoff.json" | awk '{print $1}')"
  security_sha="$(sha256sum -- "${security_receipt}" | awk '{print $1}')"
  python3 - \
    "${output_root}/release.json" \
    "${origin}" "${version}" "${architecture}" "${generation_id}" \
    "${handoff_sha}" "${security_sha}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
document = {
    "schema": "mesh-local-k8s-release-v1",
    "origin": sys.argv[2],
    "version": sys.argv[3],
    "architecture": sys.argv[4],
    "generation": sys.argv[5],
    "bundle_url": f"{sys.argv[2]}/channels/stable/bundle.json",
    "bootstrap_handoff_url": f"{sys.argv[2]}/bootstrap/stable/bootstrap-handoff.json",
    "bootstrap_handoff_sha256": sys.argv[6],
    "linux_security_receipt_sha256": sys.argv[7],
    "bootstrap_anchor_path": "authority/bootstrap-anchor.json",
}
with path.open("x", encoding="utf-8") as output:
    json.dump(document, output, separators=(",", ":"), sort_keys=True)
    output.write("\n")
PY
  chmod 0600 "${output_root}/release.json"
  printf 'generation=%s\nbundle_url=%s/channels/stable/bundle.json\nhandoff_url=%s/bootstrap/stable/bootstrap-handoff.json\n' \
    "${generation_path}" "${origin}" "${origin}"
}

for command in go python3 realpath stat install sha256sum; do
  require_command "${command}"
done

[[ $# -ge 1 ]] || usage
operation="$1"
shift
case "${operation}" in
  prepare) prepare "$@" ;;
  finalize) finalize "$@" ;;
  *) usage ;;
esac
