#!/bin/bash
# Build, normalize, reproduce, and inspect the unsigned MeshMobile XCFramework.
set -euo pipefail
umask 077

if [[ "$#" -ne 1 ]]; then
  printf 'usage: apple-ios-mobile-framework-build.sh <new-absolute-output>\n' >&2
  exit 2
fi
if [[ "$(uname -s)" != Darwin ]]; then
  printf 'Apple iOS mobile framework build requires a native Mac\n' >&2
  exit 77
fi

output_root="$1"
if [[ "${output_root}" != /* || -e "${output_root}" ]]; then
  printf 'Apple iOS mobile framework output must be a new absolute path\n' >&2
  exit 2
fi
if [[ -z "${MESH_APPLE_INPUT_RECEIPT:-}" || "${MESH_APPLE_INPUT_RECEIPT}" != /* || ! -f "${MESH_APPLE_INPUT_RECEIPT}" || -L "${MESH_APPLE_INPUT_RECEIPT}" ]]; then
  printf 'MESH_APPLE_INPUT_RECEIPT must name the preflight receipt\n' >&2
  exit 2
fi
if [[ -z "${MESH_SOURCE_KEYCHAIN:-}" || "${MESH_SOURCE_KEYCHAIN}" != /* || ! -f "${MESH_SOURCE_KEYCHAIN}" || -L "${MESH_SOURCE_KEYCHAIN}" ]]; then
  printf 'MESH_SOURCE_KEYCHAIN must name the private empty source-build Keychain\n' >&2
  exit 2
fi
if [[ "$(stat -f '%Lp' "${MESH_SOURCE_KEYCHAIN}")" != "600" ]]; then
  printf 'MESH_SOURCE_KEYCHAIN must have mode 0600\n' >&2
  exit 2
fi
keychain_identities="$(security find-identity -v -p codesigning "${MESH_SOURCE_KEYCHAIN}")"
if [[ "${keychain_identities}" != *"0 valid identities found"* ]]; then
  printf 'MESH_SOURCE_KEYCHAIN must contain no code-signing identity\n' >&2
  exit 1
fi
for name in \
  AC_PASSWORD APPLE_ID APPLE_TEAM_ID APP_STORE_CONNECT_API_KEY \
  APP_STORE_CONNECT_API_KEY_ID APP_STORE_CONNECT_ISSUER_ID \
  DEVELOPER_ID_APPLICATION DEVELOPER_ID_INSTALLER FASTLANE_PASSWORD \
  MATCH_PASSWORD NOTARY_PASSWORD NOTARY_PROFILE; do
  if [[ -n "${!name:-}" ]]; then
    printf 'unsigned Apple mobile framework build received release credential variable %s\n' "${name}" >&2
    exit 1
  fi
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
engine_root="${repo_root}/ios-tunnel/engine"
canonical_source_root="/private/var/tmp/mesh-apple-ios-mobile-source-v5"
parent="$(dirname "${output_root}")"
if [[ ! -d "${parent}" || -L "${parent}" ]]; then
  printf 'Apple mobile framework output parent must be one existing physical directory\n' >&2
  exit 2
fi

python3 "${repo_root}/scripts/apple_mobile_framework_receipt.py" \
  --preflight-only \
  --input-receipt "${MESH_APPLE_INPUT_RECEIPT}"

if [[ -e "${canonical_source_root}" || -L "${canonical_source_root}" ]]; then
  printf 'Canonical Apple mobile framework source root is already in use\n' >&2
  exit 1
fi
mkdir -m 700 "${canonical_source_root}"
cleanup_canonical_source_root() {
  if [[ \
    "${canonical_source_root}" == "/private/var/tmp/mesh-apple-ios-mobile-source-v5" &&
    -d "${canonical_source_root}" &&
    ! -L "${canonical_source_root}" \
  ]]; then
    chmod -R u+w "${canonical_source_root}"
    find "${canonical_source_root}" -depth -delete
  fi
}
trap cleanup_canonical_source_root EXIT

stage_source_file() {
  local relative="$1"
  local source="${repo_root}/${relative}"
  local destination="${canonical_source_root}/${relative}"
  if [[ ! -f "${source}" || -L "${source}" ]]; then
    printf 'Canonical Apple mobile framework source is unavailable: %s\n' "${relative}" >&2
    exit 1
  fi
  mkdir -m 700 -p "$(dirname "${destination}")"
  install -m 0444 "${source}" "${destination}"
  if ! cmp -s "${source}" "${destination}"; then
    printf 'Canonical Apple mobile framework source copy differs: %s\n' "${relative}" >&2
    exit 1
  fi
}

for relative in \
  go.mod \
  go.sum \
  internal/configsignature/configsignature.go \
  internal/mobileruntime/contract.go \
  ios-tunnel/engine/go.mod \
  ios-tunnel/engine/go.sum; do
  stage_source_file "${relative}"
done
while IFS= read -r -d '' source; do
  stage_source_file "${source#"${repo_root}/"}"
done < <(find "${engine_root}" -maxdepth 1 -type f -name '*.go' -print0 | sort -z)
canonical_engine_root="${canonical_source_root}/ios-tunnel/engine"

mkdir -m 700 "${output_root}"
mkdir -m 700 \
  "${output_root}/go-bin" \
  "${output_root}/go-cache-first" \
  "${output_root}/go-cache-second" \
  "${output_root}/go-mod-cache" \
  "${output_root}/go-workspace" \
  "${output_root}/raw-first" \
  "${output_root}/raw-second"

pinned_go_root="$(cd "${repo_root}" && go env GOROOT)"
if [[ "${pinned_go_root}" != /* || ! -x "${pinned_go_root}/bin/go" ]]; then
  printf 'pinned Go root is not one absolute toolchain directory\n' >&2
  exit 1
fi
if [[ "$("${pinned_go_root}/bin/go" version)" != "go version go1.26.5 darwin/$(go env GOARCH)" ]]; then
  printf 'pinned Go toolchain is not Go 1.26.5 for this host\n' >&2
  exit 1
fi

export GOBIN="${output_root}/go-bin"
export GOENV=off
export GOMODCACHE="${output_root}/go-mod-cache"
export GOPATH="${output_root}/go-workspace"
export GOTOOLCHAIN=local
export PATH="${GOBIN}:${pinned_go_root}/bin:${PATH}"

(
  cd "${engine_root}"
  go mod download
  go test ./...
  go test \
    -run '^TestPinnedNebulaEngineUsesCallbackPacketsOverRealUDP$' \
    -count=20
  go install golang.org/x/mobile/cmd/gobind
  go install golang.org/x/mobile/cmd/gomobile
)

build_framework() {
  local cache="$1"
  local destination="$2"
  (
    cd "${canonical_engine_root}"
    GOCACHE="${cache}" gomobile bind \
      -trimpath \
      -ldflags=-buildid= \
      -target=ios \
      -iosversion=17.0 \
      -o "${destination}" \
      .
  )
  python3 "${repo_root}/scripts/apple_mobile_framework_normalize.py" \
    "${destination}"
}

build_framework \
  "${output_root}/go-cache-first" \
  "${output_root}/raw-first/MeshMobile.xcframework"
build_framework \
  "${output_root}/go-cache-second" \
  "${output_root}/raw-second/MeshMobile.xcframework"

mv \
  "${output_root}/raw-first/MeshMobile.xcframework" \
  "${output_root}/MeshMobile.xcframework"

python3 "${repo_root}/scripts/apple_mobile_framework_receipt.py" \
  --framework "${output_root}/MeshMobile.xcframework" \
  --rebuild "${output_root}/raw-second/MeshMobile.xcframework" \
  --input-receipt "${MESH_APPLE_INPUT_RECEIPT}" \
  --output "${output_root}/mesh-apple-ios-mobile-framework-source-receipt.json"
