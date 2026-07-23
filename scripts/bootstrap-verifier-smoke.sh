#!/usr/bin/env bash

# Standalone first-installer verifier proof. This builds one production
# mesh-install ELF and proves the narrow verifier accepts only the exact
# independently rooted, threshold-authorized bytes. It creates no container,
# network, service, or host installation.

set -Eeuo pipefail
umask 077

readonly script_name="${0##*/}"
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
work_dir=""

say() {
  printf '%s\n' "$*"
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local status=$?
  trap - ERR EXIT HUP INT TERM
  if [[ -n "${work_dir}" && -d "${work_dir}" ]]; then
    case "${work_dir##*/}" in
      mesh-bootstrap-verifier-smoke.*)
        if [[ -L "${work_dir}" ]]; then
          printf 'ERROR: refusing to remove linked smoke workspace %s\n' "${work_dir}" >&2
          status=1
        else
          chmod -R u+w -- "${work_dir}" || status=1
          rm -rf -- "${work_dir}" || status=1
        fi
        ;;
      *)
        printf 'ERROR: refusing to remove unexpected smoke workspace %s\n' "${work_dir}" >&2
        status=1
        ;;
    esac
  fi
  exit "${status}"
}

on_error() {
  local status=$?
  local line="${1:-unknown}"
  trap - ERR
  printf 'ERROR: %s failed at line %s\n' "${script_name}" "${line}" >&2
  exit "${status}"
}

trap cleanup EXIT
trap 'on_error "${LINENO}"' ERR
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for command in go date sha256sum python3 mktemp grep; do
  command -v -- "${command}" >/dev/null 2>&1 || die "required command is unavailable: ${command}"
done

temp_parent="${TMPDIR:-/tmp}"
[[ -d "${temp_parent}" && ! -L "${temp_parent}" ]] || die "temporary parent is unavailable or linked: ${temp_parent}"
work_dir="$(mktemp -d "${temp_parent%/}/mesh-bootstrap-verifier-smoke.XXXXXX")"
[[ -d "${work_dir}" && ! -L "${work_dir}" ]] || die "private smoke workspace was not created safely"
mkdir -p -- "${work_dir}/tools" "${work_dir}/keys" "${work_dir}/release"
chmod 0700 "${work_dir}/tools" "${work_dir}/keys" "${work_dir}/release"

cd -- "${repo_root}"
say "Building the release author and deterministic package builder"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false \
  -o "${work_dir}/tools/mesh-release" ./cmd/mesh-release
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false \
  -o "${work_dir}/tools/mesh-package" ./cmd/mesh-package

issued_at="$(date -u -d '-1 minute' '+%Y-%m-%dT%H:%M:%SZ')"
now_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
root_expires_at="$(date -u -d '+1 day' '+%Y-%m-%dT%H:%M:%SZ')"
bootstrap_expires_at="$(date -u -d '+1 hour' '+%Y-%m-%dT%H:%M:%SZ')"
expired_at="$(date -u -d '+2 hours' '+%Y-%m-%dT%H:%M:%SZ')"
source_epoch="$(date -u -d "${issued_at}" '+%s')"
identity="$("${work_dir}/tools/mesh-release" build-identity \
  --version 1.0.0 \
  --commit 1111111111111111111111111111111111111111 \
  --build-time "${issued_at}" \
  --security-floor 1 \
  --agent-state-read-min 2 \
  --agent-state-read-max 2 \
  --agent-state-write-version 2)"
[[ "${identity}" != *[[:space:]]* ]] || die "compiled build identity frame is not canonical"

say "Building and auditing the production-identity standalone verifier"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false \
  "-ldflags=-buildid= -X mesh/internal/buildinfo.Identity=${identity}" \
  -o "${work_dir}/tools/mesh-bootstrap-verify" ./cmd/mesh-bootstrap-verify

GOFLAGS=-buildvcs=false go list -deps ./cmd/mesh-bootstrap-verify >"${work_dir}/verifier-dependencies.txt"
for forbidden in os/exec net/http mesh/internal/bootstrapanchorauthor mesh/internal/bootstraphandoffauthor mesh/internal/verifierbundle mesh/internal/linuxbundle mesh/internal/linuxinstall mesh/packaging/systemd; do
  if grep -Fxq -- "${forbidden}" "${work_dir}/verifier-dependencies.txt"; then
    die "standalone verifier source dependency includes forbidden capability: ${forbidden}"
  fi
done
go tool nm "${work_dir}/tools/mesh-bootstrap-verify" >"${work_dir}/verifier-symbols.txt"
if grep -Eq -- 'os/exec\.(Command|CommandContext)|mesh/internal/release\.(SignManifest|GeneratePrivateKeyFile)|mesh/internal/bootstrapanchorauthor|mesh/internal/bootstraphandoffauthor|mesh/internal/verifierbundle|mesh/internal/linuxbundle|mesh/internal/linuxinstall' "${work_dir}/verifier-symbols.txt"; then
  die "standalone verifier binary retains a signing, subprocess, package, or installation symbol"
fi

help_text="$("${work_dir}/tools/mesh-bootstrap-verify" --help 2>&1)"
for required in --root --expected-root-sha256 --handoff --expected-handoff-sha256 --handoff-anchor --manifest --signature --installer; do
  [[ "${help_text}" == *"${required}"* ]] || die "standalone verifier omits required command surface: ${required}"
done
for forbidden in generate-key export-public create-root private-key output-file; do
  [[ "${help_text}" != *"${forbidden}"* ]] || die "standalone verifier exposes forbidden command surface: ${forbidden}"
done

say "Building the verifier distribution artifact twice and proving exact bytes"
for suffix in one two; do
  "${work_dir}/tools/mesh-package" build-bootstrap-verifier \
    --version 1.0.0 \
    --commit 1111111111111111111111111111111111111111 \
    --source-date-epoch "${source_epoch}" \
    --security-floor 1 \
    --arch amd64 \
    --verifier "${work_dir}/tools/mesh-bootstrap-verify" \
    --output "${work_dir}/release/mesh-bootstrap-verifier.${suffix}.tar" \
    >"${work_dir}/release/package.${suffix}.txt"
done
cmp --silent -- "${work_dir}/release/mesh-bootstrap-verifier.one.tar" "${work_dir}/release/mesh-bootstrap-verifier.two.tar" ||
  die "identical verifier package inputs did not produce identical bytes"
package_sha="$(sha256sum -- "${work_dir}/release/mesh-bootstrap-verifier.one.tar" | awk '{print $1}')"
[[ "${package_sha}" =~ ^[0-9a-f]{64}$ ]] || die "verifier package digest is not canonical"
grep -Fq -- "SHA-256 ${package_sha}" "${work_dir}/release/package.one.txt" || die "package receipt omitted the exact artifact digest"
python3 - "${work_dir}/release/mesh-bootstrap-verifier.one.tar" "${work_dir}/tools/mesh-bootstrap-verify" "${source_epoch}" <<'PY'
import hashlib
import json
import pathlib
import sys
import tarfile

archive_path = pathlib.Path(sys.argv[1])
verifier_path = pathlib.Path(sys.argv[2])
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
assert package["target"] == {"os": "linux", "arch": "amd64"}
assert len(package["entries"]) == 1
entry = package["entries"][0]
assert entry["path"] == "bin/mesh-bootstrap-verify" and entry["mode"] == 0o555
assert entry["size"] == len(verifier_raw)
assert entry["sha256"] == hashlib.sha256(verifier_raw).hexdigest()
assert verifier_raw == verifier_path.read_bytes()
PY
package_sha_before="$(sha256sum -- "${work_dir}/release/mesh-bootstrap-verifier.one.tar" | awk '{print $1}')"
if "${work_dir}/tools/mesh-package" build-bootstrap-verifier \
  --version 1.0.0 --commit 1111111111111111111111111111111111111111 \
  --source-date-epoch "${source_epoch}" --security-floor 1 --arch amd64 \
  --verifier "${work_dir}/tools/mesh-bootstrap-verify" \
  --output "${work_dir}/release/mesh-bootstrap-verifier.one.tar" >/dev/null 2>&1; then
  die "verifier package builder overwrote an existing artifact"
fi
[[ "$(sha256sum -- "${work_dir}/release/mesh-bootstrap-verifier.one.tar" | awk '{print $1}')" == "${package_sha_before}" ]] ||
  die "failed no-replace verifier publication changed the existing artifact"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false \
  -o "${work_dir}/tools/mesh-bootstrap-verify.development" ./cmd/mesh-bootstrap-verify
if "${work_dir}/tools/mesh-package" build-bootstrap-verifier \
  --version 1.0.0 --commit 1111111111111111111111111111111111111111 \
  --source-date-epoch "${source_epoch}" --security-floor 1 --arch amd64 \
  --verifier "${work_dir}/tools/mesh-bootstrap-verify.development" \
  --output "${work_dir}/release/development-verifier.tar" >/dev/null 2>&1; then
  die "development-identity verifier was packaged"
fi
[[ ! -e "${work_dir}/release/development-verifier.tar" ]] || die "rejected development verifier published an artifact"
if "${work_dir}/tools/mesh-package" build-bootstrap-verifier \
  --version 1.0.1 --commit 1111111111111111111111111111111111111111 \
  --source-date-epoch "${source_epoch}" --security-floor 1 --arch amd64 \
  --verifier "${work_dir}/tools/mesh-bootstrap-verify" \
  --output "${work_dir}/release/wrong-identity-verifier.tar" >/dev/null 2>&1; then
  die "package identity differing from the compiled verifier was accepted"
fi
[[ ! -e "${work_dir}/release/wrong-identity-verifier.tar" ]] || die "wrong-identity verifier published an artifact"
ln -s -- "${work_dir}/tools/mesh-bootstrap-verify" "${work_dir}/tools/mesh-bootstrap-verify.link"
if "${work_dir}/tools/mesh-package" build-bootstrap-verifier \
  --version 1.0.0 --commit 1111111111111111111111111111111111111111 \
  --source-date-epoch "${source_epoch}" --security-floor 1 --arch amd64 \
  --verifier "${work_dir}/tools/mesh-bootstrap-verify.link" \
  --output "${work_dir}/release/linked-verifier.tar" >/dev/null 2>&1; then
  die "symlinked verifier input was packaged"
fi
[[ ! -e "${work_dir}/release/linked-verifier.tar" ]] || die "linked verifier published an artifact"
rm -f -- "${work_dir}/tools/mesh-bootstrap-verify.link"
ln -- "${work_dir}/tools/mesh-bootstrap-verify" "${work_dir}/tools/mesh-bootstrap-verify.hardlink"
if "${work_dir}/tools/mesh-package" build-bootstrap-verifier \
  --version 1.0.0 --commit 1111111111111111111111111111111111111111 \
  --source-date-epoch "${source_epoch}" --security-floor 1 --arch amd64 \
  --verifier "${work_dir}/tools/mesh-bootstrap-verify.hardlink" \
  --output "${work_dir}/release/hardlinked-verifier.tar" >/dev/null 2>&1; then
  die "multiply linked verifier input was packaged"
fi
[[ ! -e "${work_dir}/release/hardlinked-verifier.tar" ]] || die "hardlinked verifier published an artifact"
rm -f -- "${work_dir}/tools/mesh-bootstrap-verify.hardlink"

for signer in root-a root-b release-a release-b; do
  "${work_dir}/tools/mesh-release" generate-key \
    --private "${work_dir}/keys/${signer}.private.json" >/dev/null
  "${work_dir}/tools/mesh-release" export-public \
    --private "${work_dir}/keys/${signer}.private.json" \
    --public "${work_dir}/keys/${signer}.public.json" >/dev/null
done

create_root() {
  local output="$1"
  local channel="$2"
  "${work_dir}/tools/mesh-release" create-root \
    --output "${output}" \
    --channel "${channel}" \
    --release-epoch 1 \
    --minimum-release-sequence 1 \
    --minimum-security-floor 1 \
    --issued "${issued_at}" \
    --expires "${root_expires_at}" \
    --root-threshold 2 \
    --root-public "${work_dir}/keys/root-a.public.json" \
    --root-public "${work_dir}/keys/root-b.public.json" \
    --release-threshold 2 \
    --release-public "${work_dir}/keys/release-a.public.json" \
    --release-public "${work_dir}/keys/release-b.public.json" >/dev/null
}

create_root "${work_dir}/release/root-v1.json" stable
create_root "${work_dir}/release/wrong-root-v1.json" preview
root_sha="$(sha256sum -- "${work_dir}/release/root-v1.json" | awk '{print $1}')"
wrong_root_sha="$(sha256sum -- "${work_dir}/release/wrong-root-v1.json" | awk '{print $1}')"
[[ "${root_sha}" =~ ^[0-9a-f]{64}$ && "${wrong_root_sha}" =~ ^[0-9a-f]{64}$ ]] || die "root digest is not canonical"

installer_policy="$("${work_dir}/tools/mesh-release" installer-policy --root "${work_dir}/release/root-v1.json")"
[[ "${installer_policy}" != *[[:space:]]* ]] || die "compiled installer policy frame is not canonical"
authenticode_policy="$("${work_dir}/tools/mesh-release" windows-authenticode-policy \
  --mesh-signer-spki-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --wintun-signer-spki-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)"
[[ "${authenticode_policy}" != *[[:space:]]* ]] || die "compiled Windows Authenticode policy frame is not canonical"

say "Building and root-authorizing one exact production installer"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -trimpath -buildvcs=false \
  "-ldflags=-s -w -buildid= -X mesh/internal/buildinfo.Identity=${identity} -X mesh/internal/installtrust.Identity=${installer_policy}" \
  -o "${work_dir}/release/mesh-install" ./cmd/mesh-install
"${work_dir}/tools/mesh-release" create-bootstrap-manifest \
  --output "${work_dir}/release/bootstrap.json" \
  --root "${work_dir}/release/root-v1.json" \
  --installer "${work_dir}/release/mesh-install" \
  --arch amd64 \
  --issued "${now_at}" \
  --expires "${bootstrap_expires_at}" >/dev/null
for signer in root-a root-b release-a release-b; do
  "${work_dir}/tools/mesh-release" sign \
    --private "${work_dir}/keys/${signer}.private.json" \
    --manifest "${work_dir}/release/bootstrap.json" \
    --signature "${work_dir}/release/bootstrap.${signer}.json" >/dev/null
done

readonly -a common_args=(
  --root "${work_dir}/release/root-v1.json"
  --expected-root-sha256 "${root_sha}"
  --manifest "${work_dir}/release/bootstrap.json"
  --signature "${work_dir}/release/bootstrap.root-a.json"
  --signature "${work_dir}/release/bootstrap.root-b.json"
  --installer "${work_dir}/release/mesh-install"
  --now "${now_at}"
)
say "Verifying the independently rooted 2-of-2 authorization without execution"
"${work_dir}/tools/mesh-bootstrap-verify" "${common_args[@]}" >"${work_dir}/receipt.json"
"${work_dir}/tools/mesh-release" verify-bootstrap "${common_args[@]}" >"${work_dir}/legacy-receipt.json"
cmp --silent -- "${work_dir}/receipt.json" "${work_dir}/legacy-receipt.json" || die "standalone and compatibility verifier receipts differ"
python3 - "${work_dir}/receipt.json" "${root_sha}" <<'PY'
import json
import pathlib
import sys

receipt = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert receipt["schema"] == "mesh-bootstrap-verification-v1"
assert receipt["root_sha256"] == sys.argv[2]
assert receipt["version"] == "1.0.0"
assert receipt["os"] == "linux"
assert receipt["arch"] == "amd64"
assert len(receipt["signer_key_ids"]) == 2
assert receipt["signer_key_ids"] == sorted(set(receipt["signer_key_ids"]))
PY

say "Building and root-authorizing exact Windows installer PEs"
for windows_arch in amd64 arm64; do
  windows_installer="${work_dir}/release/mesh-install-windows-${windows_arch}.exe"
  windows_manifest="${work_dir}/release/bootstrap-windows-${windows_arch}.json"
  CGO_ENABLED=0 GOOS=windows GOARCH="${windows_arch}" go build \
    -trimpath -buildvcs=false \
    "-ldflags=-s -w -buildid= -X mesh/internal/buildinfo.Identity=${identity} -X mesh/internal/installtrust.Identity=${installer_policy} -X mesh/internal/windowsauthenticode.Identity=${authenticode_policy}" \
    -o "${windows_installer}" ./cmd/mesh-install-windows
  "${work_dir}/tools/mesh-release" create-bootstrap-manifest \
    --output "${windows_manifest}" \
    --root "${work_dir}/release/root-v1.json" \
    --installer "${windows_installer}" \
    --os windows \
    --arch "${windows_arch}" \
    --issued "${now_at}" \
    --expires "${bootstrap_expires_at}" >/dev/null
  for signer in root-a root-b; do
    "${work_dir}/tools/mesh-release" sign \
      --private "${work_dir}/keys/${signer}.private.json" \
      --manifest "${windows_manifest}" \
      --signature "${work_dir}/release/bootstrap-windows-${windows_arch}.${signer}.json" >/dev/null
  done
  windows_args=(
    --root "${work_dir}/release/root-v1.json"
    --expected-root-sha256 "${root_sha}"
    --manifest "${windows_manifest}"
    --signature "${work_dir}/release/bootstrap-windows-${windows_arch}.root-a.json"
    --signature "${work_dir}/release/bootstrap-windows-${windows_arch}.root-b.json"
    --installer "${windows_installer}"
    --now "${now_at}"
  )
  "${work_dir}/tools/mesh-bootstrap-verify" "${windows_args[@]}" >"${work_dir}/windows-${windows_arch}-receipt.json"
  "${work_dir}/tools/mesh-release" verify-bootstrap "${windows_args[@]}" >"${work_dir}/windows-${windows_arch}-legacy-receipt.json"
  cmp --silent -- "${work_dir}/windows-${windows_arch}-receipt.json" "${work_dir}/windows-${windows_arch}-legacy-receipt.json" || die "Windows ${windows_arch} standalone and compatibility verifier receipts differ"
  python3 - "${work_dir}/windows-${windows_arch}-receipt.json" "${root_sha}" "${windows_arch}" <<'PY'
import json
import pathlib
import sys

receipt = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert receipt["schema"] == "mesh-bootstrap-verification-v1"
assert receipt["root_sha256"] == sys.argv[2]
assert receipt["version"] == "1.0.0"
assert receipt["os"] == "windows"
assert receipt["arch"] == sys.argv[3]
assert len(receipt["signer_key_ids"]) == 2
PY
done

expect_failure() {
  local label="$1"
  shift
  if "${work_dir}/tools/mesh-bootstrap-verify" "$@" >"${work_dir}/${label}.stdout" 2>"${work_dir}/${label}.stderr"; then
    die "standalone verifier accepted ${label}"
  fi
  [[ ! -s "${work_dir}/${label}.stdout" ]] || die "failed ${label} verification emitted an acceptance receipt"
  [[ -s "${work_dir}/${label}.stderr" ]] || die "failed ${label} verification omitted diagnostics"
}

say "Proving wrong-root, wrong-role, mutation, threshold, expiry, and symlink rejection"
expect_failure wrong-independent-digest \
  --root "${work_dir}/release/root-v1.json" \
  --expected-root-sha256 "$(printf '0%.0s' {1..64})" \
  --manifest "${work_dir}/release/bootstrap.json" \
  --signature "${work_dir}/release/bootstrap.root-a.json" \
  --signature "${work_dir}/release/bootstrap.root-b.json" \
  --installer "${work_dir}/release/mesh-install" --now "${now_at}"
expect_failure wrong-root \
  --root "${work_dir}/release/wrong-root-v1.json" \
  --expected-root-sha256 "${wrong_root_sha}" \
  --manifest "${work_dir}/release/bootstrap.json" \
  --signature "${work_dir}/release/bootstrap.root-a.json" \
  --signature "${work_dir}/release/bootstrap.root-b.json" \
  --installer "${work_dir}/release/mesh-install" --now "${now_at}"
expect_failure wrong-role \
  --root "${work_dir}/release/root-v1.json" \
  --expected-root-sha256 "${root_sha}" \
  --manifest "${work_dir}/release/bootstrap.json" \
  --signature "${work_dir}/release/bootstrap.release-a.json" \
  --signature "${work_dir}/release/bootstrap.release-b.json" \
  --installer "${work_dir}/release/mesh-install" --now "${now_at}"
expect_failure one-of-two \
  --root "${work_dir}/release/root-v1.json" \
  --expected-root-sha256 "${root_sha}" \
  --manifest "${work_dir}/release/bootstrap.json" \
  --signature "${work_dir}/release/bootstrap.root-a.json" \
  --installer "${work_dir}/release/mesh-install" --now "${now_at}"
cp -- "${work_dir}/release/mesh-install" "${work_dir}/release/mesh-install.changed"
printf 'changed\n' >>"${work_dir}/release/mesh-install.changed"
expect_failure changed-installer \
  --root "${work_dir}/release/root-v1.json" \
  --expected-root-sha256 "${root_sha}" \
  --manifest "${work_dir}/release/bootstrap.json" \
  --signature "${work_dir}/release/bootstrap.root-a.json" \
  --signature "${work_dir}/release/bootstrap.root-b.json" \
  --installer "${work_dir}/release/mesh-install.changed" --now "${now_at}"
expect_failure expired-manifest \
  --root "${work_dir}/release/root-v1.json" \
  --expected-root-sha256 "${root_sha}" \
  --manifest "${work_dir}/release/bootstrap.json" \
  --signature "${work_dir}/release/bootstrap.root-a.json" \
  --signature "${work_dir}/release/bootstrap.root-b.json" \
  --installer "${work_dir}/release/mesh-install" --now "${expired_at}"
ln -s -- "${work_dir}/release/root-v1.json" "${work_dir}/release/root-link.json"
expect_failure linked-root \
  --root "${work_dir}/release/root-link.json" \
  --expected-root-sha256 "${root_sha}" \
  --manifest "${work_dir}/release/bootstrap.json" \
  --signature "${work_dir}/release/bootstrap.root-a.json" \
  --signature "${work_dir}/release/bootstrap.root-b.json" \
  --installer "${work_dir}/release/mesh-install" --now "${now_at}"

printf 'PASS: deterministic standalone verifier package reproduced exactly; verifier accepted exact 2-of-2 bootstrap authority and rejected wrong roots, wrong roles, insufficient threshold, changed bytes, expiry, and linked inputs\n'
