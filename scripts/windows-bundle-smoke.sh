#!/usr/bin/env bash

# Prove the Linux-verifiable Windows release-staging boundary. This harness
# deliberately does not install software, mutate Windows services, apply DACLs,
# or make an Authenticode decision.
set -Eeuo pipefail
umask 077

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/mesh-windows-bundle-smoke.XXXXXX")"

cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [[ -n "${work_dir:-}" && -d "${work_dir}" && "$(basename -- "${work_dir}")" == mesh-windows-bundle-smoke.* ]]; then
	chmod -R u+rwX -- "${work_dir}" 2>/dev/null || true
    rm -r -- "${work_dir}"
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

for command_name in go cmp date basename mktemp rm; do
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

dependency_dir() {
  local arch="$1"
  local configured=""
  case "${arch}" in
    amd64) configured="${MESH_WINDOWS_NEBULA_AMD64_DIR:-}" ;;
    arm64) configured="${MESH_WINDOWS_NEBULA_ARM64_DIR:-}" ;;
    *) printf 'unsupported proof architecture %s\n' "${arch}" >&2; return 1 ;;
  esac
  if [[ -n "${configured}" ]]; then
    printf '%s\n' "${configured}"
    return
  fi
  local destination="${work_dir}/nebula-${arch}"
  "${tools_dir}/mesh-deps" fetch-nebula \
    --os windows \
    --arch "${arch}" \
    --output-dir "${destination}" >/dev/null
  printf '%s\n' "${destination}"
}

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
  local nebula_dir="$2"
  local runtime_dir="$3"
  local target_dir="${work_dir}/windows-${arch}"
  local meshctl_path="${target_dir}/meshctl.exe"
  local first_bundle="${target_dir}/mesh-windows-${arch}.tar"
  local second_bundle="${target_dir}/mesh-windows-${arch}.repro.tar"
  mkdir -p -- "${target_dir}"
  chmod 0700 "${target_dir}"

  (
    cd -- "${repo_root}"
    CGO_ENABLED=0 GOOS=windows GOARCH="${arch}" go build \
      -buildvcs=false -trimpath \
      "-ldflags=-s -w -buildid= -X mesh/internal/buildinfo.Identity=${identity}" \
      -o "${meshctl_path}" ./cmd/meshctl
  )

  local -a package_args=(
    build-windows
    --version "${version}"
    --commit "${commit}"
    --source-date-epoch "${source_epoch}"
    --security-floor "${security_floor}"
    --arch "${arch}"
    --meshctl "${meshctl_path}"
    --nebula-dir "${nebula_dir}"
    --nebula-runtime-dir "${runtime_dir}"
  )
  "${tools_dir}/mesh-package" "${package_args[@]}" --output "${first_bundle}" >/dev/null
  "${tools_dir}/mesh-package" "${package_args[@]}" --output "${second_bundle}" >/dev/null
  cmp --silent -- "${first_bundle}" "${second_bundle}" || {
    printf 'windows/%s staging bundle was not reproducible\n' "${arch}" >&2
    exit 1
  }
  printf '%s\n' "${first_bundle}"
}

printf 'Authenticating pinned Windows Nebula dependencies\n'
nebula_amd64="$(dependency_dir amd64)"
nebula_arm64="$(dependency_dir arm64)"

printf 'Reproducibly building security-patched Windows Nebula runtimes\n'
"${tools_dir}/mesh-deps" build-nebula-windows-runtime \
  --arch amd64 --output-dir "${work_dir}/runtime-amd64" >/dev/null
"${tools_dir}/mesh-deps" build-nebula-windows-runtime \
  --arch arm64 --output-dir "${work_dir}/runtime-arm64" >/dev/null

printf 'Building and reproducing windows/amd64 and windows/arm64 bundles\n'
bundle_amd64="$(build_target amd64 "${nebula_amd64}" "${work_dir}/runtime-amd64")"
bundle_arm64="$(build_target arm64 "${nebula_arm64}" "${work_dir}/runtime-arm64")"

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
  --output "${root}" \
  --channel stable \
  --release-epoch 1 \
  --minimum-release-sequence 1 \
  --minimum-security-floor "${security_floor}" \
  --issued "${issued_at}" \
  --expires "${root_expires_at}" \
  --root-threshold 2 \
  --release-threshold 2 \
  --root-public "${release_dir}/root-a.public.json" \
  --root-public "${release_dir}/root-b.public.json" \
  --release-public "${release_dir}/release-a.public.json" \
  --release-public "${release_dir}/release-b.public.json" >/dev/null

# Supply the targets in reverse canonical order. The generator must still emit
# windows/amd64 before windows/arm64 and bind each exact opened descriptor.
"${tools_dir}/mesh-release" create-release-manifest \
  --output "${manifest}" \
  --root "${root}" \
  --version "${version}" \
  --sequence 1 \
  --security-floor "${security_floor}" \
  --issued "${issued_at}" \
  --expires "${expires_at}" \
  --test-only-allow-unscanned-windows-artifact \
  --os windows \
  --arch arm64 \
  --artifact-url https://releases.invalid/mesh-windows-arm64.tar \
  --artifact "${bundle_arm64}" \
  --os windows \
  --arch amd64 \
  --artifact-url https://releases.invalid/mesh-windows-amd64.tar \
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
    --channel stable \
    --minimum-sequence 1 \
    --minimum-security-floor "${security_floor}" \
    --os windows \
    --arch "${arch}" \
    --artifact "${artifact}" >/dev/null
}

printf 'Verifying one canonical 2-of-2 manifest against both exact artifacts\n'
verify_target amd64 "${bundle_amd64}"
verify_target arm64 "${bundle_arm64}"

printf 'PASS: deterministic threshold-authenticated Windows staging bundles for amd64 and arm64; no Windows lifecycle claim was made\n'
