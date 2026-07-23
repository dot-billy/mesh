#!/usr/bin/env bash

# Prove the Linux-verifiable Darwin release-staging boundary. This harness
# deliberately does not install software, activate launchd, mutate extended
# ACLs, perform codesigning/notarization, or make a native lifecycle claim.
set -Eeuo pipefail
umask 077

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/mesh-darwin-bundle-smoke.XXXXXX")"

cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [[ -n "${work_dir:-}" && -d "${work_dir}" && "$(basename -- "${work_dir}")" == mesh-darwin-bundle-smoke.* ]]; then
    chmod -R u+rwX -- "${work_dir}" 2>/dev/null || true
    rm -r -- "${work_dir}"
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

for command_name in go cmp cp date basename find mktemp rm truncate stat; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    printf 'SKIP: required command %s is unavailable\n' "${command_name}" >&2
    exit 77
  }
done

tools_dir="${work_dir}/tools"
release_dir="${work_dir}/release"
mkdir -p -- "${tools_dir}" "${release_dir}"
chmod 0700 "${tools_dir}" "${release_dir}"

printf 'Building release, package, dependency, and verification tools\n'
(
  cd -- "${repo_root}"
  go build -buildvcs=false -trimpath -o "${tools_dir}/mesh-release" ./cmd/mesh-release
  go build -buildvcs=false -trimpath -o "${tools_dir}/mesh-package" ./cmd/mesh-package
  go build -buildvcs=false -trimpath -o "${tools_dir}/mesh-deps" ./cmd/mesh-deps
  go build -buildvcs=false -trimpath -o "${tools_dir}/meshctl" ./cmd/meshctl
)

version="1.0.0"
commit="0123456789012345678901234567890123456789"
source_epoch="1784476800"
build_time="2026-07-19T16:00:00Z"
security_floor="1"

identity="$("${tools_dir}/mesh-release" build-identity \
  --version "${version}" \
  --commit "${commit}" \
  --build-time "${build_time}" \
  --security-floor "${security_floor}" \
  --agent-state-read-min 2 \
  --agent-state-read-max 2 \
  --agent-state-write-version 2)"
[[ "${identity}" != *[[:space:]]* ]] || {
  printf 'release build identity was not one canonical frame\n' >&2
  exit 1
}

build_target() {
  local arch="$1"
  local runtime_dir="$2"
  local target_dir="${work_dir}/darwin-${arch}"
  local meshctl_path="${target_dir}/meshctl"
  local first_bundle="${target_dir}/mesh-darwin-${arch}.tar"
  local second_bundle="${target_dir}/mesh-darwin-${arch}.repro.tar"
  local stage_dir="${target_dir}/stage"
  mkdir -p -- "${target_dir}"
  mkdir -m 0700 -- "${stage_dir}"
  chmod 0700 "${target_dir}"

  (
    cd -- "${repo_root}"
    CGO_ENABLED=0 GOOS=darwin GOARCH="${arch}" go build \
      -buildvcs=false -trimpath \
      "-ldflags=-s -w -buildid= -X mesh/internal/buildinfo.Identity=${identity}" \
      -o "${meshctl_path}" ./cmd/meshctl
  )

  local -a package_args=(
    build-darwin
    --version "${version}"
    --commit "${commit}"
    --source-date-epoch "${source_epoch}"
    --security-floor "${security_floor}"
    --arch "${arch}"
    --meshctl "${meshctl_path}"
    --nebula-runtime-dir "${runtime_dir}"
  )
  "${tools_dir}/mesh-package" "${package_args[@]}" --output "${first_bundle}" >/dev/null
  "${tools_dir}/mesh-package" "${package_args[@]}" --output "${second_bundle}" >/dev/null
  cmp --silent -- "${first_bundle}" "${second_bundle}" || {
    printf 'darwin/%s staging bundle was not reproducible\n' "${arch}" >&2
    exit 1
  }
  "${tools_dir}/mesh-package" inspect-darwin \
    --artifact "${first_bundle}" --output-dir "${stage_dir}" >/dev/null
  printf '%s\n' "${first_bundle}"
}

printf 'Reproducibly building security-patched Darwin Nebula runtimes\n'
"${tools_dir}/mesh-deps" build-nebula-darwin-runtime \
  --arch amd64 --output-dir "${work_dir}/runtime-amd64" >/dev/null
"${tools_dir}/mesh-deps" build-nebula-darwin-runtime \
  --arch arm64 --output-dir "${work_dir}/runtime-arm64" >/dev/null

printf 'Building, reproducing, and inspecting darwin/amd64 and darwin/arm64 bundles\n'
bundle_amd64="$(build_target amd64 "${work_dir}/runtime-amd64")"
bundle_arm64="$(build_target arm64 "${work_dir}/runtime-arm64")"

printf 'Rejecting an appended Darwin candidate without partial staging\n'
trailing_bundle="${work_dir}/trailing.tar"
trailing_stage="${work_dir}/trailing-stage"
cp -- "${bundle_amd64}" "${trailing_bundle}"
trailing_size="$(stat -c %s -- "${trailing_bundle}")"
truncate -s "$((trailing_size + 1))" -- "${trailing_bundle}"
mkdir -m 0700 -- "${trailing_stage}"
if "${tools_dir}/mesh-package" inspect-darwin \
  --artifact "${trailing_bundle}" --output-dir "${trailing_stage}" >/dev/null 2>&1; then
  printf 'appended Darwin candidate unexpectedly passed inspection\n' >&2
  exit 1
fi
[[ -z "$(find "${trailing_stage}" -mindepth 1 -print -quit)" ]] || {
  printf 'failed Darwin inspection left partial staged content\n' >&2
  exit 1
}

issued_at="$(date -u -d '-1 minute' '+%Y-%m-%dT%H:%M:%SZ')"
expires_at="$(date -u -d '+1 day' '+%Y-%m-%dT%H:%M:%SZ')"
root_expires_at="$(date -u -d '+30 days' '+%Y-%m-%dT%H:%M:%SZ')"
manifest="${release_dir}/release.json"
root="${release_dir}/root-v1.json"

for role in root release; do
  for signer in a b; do
    "${tools_dir}/mesh-release" generate-key \
      --private "${release_dir}/${role}-${signer}.private.json" >/dev/null
    "${tools_dir}/mesh-release" export-public \
      --private "${release_dir}/${role}-${signer}.private.json" \
      --public "${release_dir}/${role}-${signer}.public.json" >/dev/null
  done
done

"${tools_dir}/mesh-release" create-root \
  --output "${root}" --channel stable --release-epoch 1 \
  --minimum-release-sequence 1 --minimum-security-floor "${security_floor}" \
  --issued "${issued_at}" --expires "${root_expires_at}" \
  --root-threshold 2 --release-threshold 2 \
  --root-public "${release_dir}/root-a.public.json" \
  --root-public "${release_dir}/root-b.public.json" \
  --release-public "${release_dir}/release-a.public.json" \
  --release-public "${release_dir}/release-b.public.json" >/dev/null

# The bypass is restricted to this synthetic scanner-independent smoke. Real
# release candidates require receipts from darwin-package-security-baseline.
"${tools_dir}/mesh-release" create-release-manifest \
  --output "${manifest}" --root "${root}" --version "${version}" \
  --sequence 1 --security-floor "${security_floor}" \
  --issued "${issued_at}" --expires "${expires_at}" \
  --test-only-allow-unscanned-darwin-artifact \
  --os darwin --arch arm64 \
  --artifact-url https://releases.invalid/mesh-darwin-arm64.tar \
  --artifact "${bundle_arm64}" \
  --os darwin --arch amd64 \
  --artifact-url https://releases.invalid/mesh-darwin-amd64.tar \
  --artifact "${bundle_amd64}" >/dev/null

for signer in a b; do
  "${tools_dir}/mesh-release" sign \
    --private "${release_dir}/release-${signer}.private.json" \
    --manifest "${manifest}" \
    --signature "${release_dir}/release-${signer}.signature.json" >/dev/null
done

verify_target() {
  local arch="$1"
  local artifact="$2"
  "${tools_dir}/meshctl" verify-release \
    --manifest "${manifest}" \
    --signature "${release_dir}/release-a.signature.json" \
    --signature "${release_dir}/release-b.signature.json" \
    --trusted-public-key "${release_dir}/release-a.public.json" \
    --trusted-public-key "${release_dir}/release-b.public.json" \
    --channel stable --minimum-sequence 1 \
    --minimum-security-floor "${security_floor}" \
    --os darwin --arch "${arch}" --artifact "${artifact}" >/dev/null
}

printf 'Verifying one canonical 2-of-2 manifest against both exact artifacts\n'
verify_target amd64 "${bundle_amd64}"
verify_target arm64 "${bundle_arm64}"

printf 'PASS: deterministic threshold-authenticated Darwin staging bundles for amd64 and arm64; no native macOS lifecycle claim was made\n'
