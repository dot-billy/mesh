#!/bin/bash
# Build, verify, upload, and distribute one Mesh Tunnel TestFlight release.
set -euo pipefail
umask 077

die() {
  printf 'Mesh TestFlight release: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage:
  scripts/publish-ios-tunnel-testflight.sh status [build-number]
  scripts/publish-ios-tunnel-testflight.sh distribute [build-number]
  scripts/publish-ios-tunnel-testflight.sh publish

Configuration is read from environment variables or, when present, the
owner-only file ~/.config/mesh/testflight.env:

  APP_STORE_CONNECT_API_KEY_ID
  APP_STORE_CONNECT_ISSUER_ID
  APP_STORE_CONNECT_API_KEY_PATH       (optional; inferred from key ID)
  MESH_TESTFLIGHT_TESTER_EMAIL         (required for distribute/publish)
  MESH_TESTFLIGHT_BETA_GROUP           (optional when selection is unambiguous)
  MESH_FLUTTER                         (optional local toolchain override)
  MESH_FLUTTER_ARCHIVE                 (optional pinned archive override)
  MESH_TESTFLIGHT_OUTPUT_PARENT        (optional; defaults to /private/var/tmp)
EOF
}

[[ "$(uname -s)" == "Darwin" ]] ||
  die "iOS TestFlight publishing requires a native Mac"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "${repo_root}"

config_path="${MESH_TESTFLIGHT_CONFIG:-${HOME}/.config/mesh/testflight.env}"
if [[ -e "${config_path}" || -L "${config_path}" ]]; then
  [[ -f "${config_path}" && ! -L "${config_path}" ]] ||
    die "configuration must be one physical regular file"
  [[ "$(stat -f '%u' "${config_path}")" == "$(id -u)" ]] ||
    die "configuration must be owned by the current user"
  [[ "$(stat -f '%Lp' "${config_path}")" == "600" ]] ||
    die "configuration must have mode 0600"
  # This is a private, owner-controlled environment file, not repository input.
  set -a
  # shellcheck source=/dev/null
  source "${config_path}"
  set +a
fi

key_id="${APP_STORE_CONNECT_API_KEY_ID:-}"
issuer_id="${APP_STORE_CONNECT_ISSUER_ID:-}"
[[ -n "${key_id}" && -n "${issuer_id}" ]] ||
  die "App Store Connect key ID and issuer ID are required"
key_path="${APP_STORE_CONNECT_API_KEY_PATH:-${HOME}/private_keys/AuthKey_${key_id}.p8}"
[[ "${key_path}" == /* && -f "${key_path}" && ! -L "${key_path}" ]] ||
  die "App Store Connect private key is unavailable"
[[ "$(stat -f '%u' "${key_path}")" == "$(id -u)" ]] ||
  die "App Store Connect private key must be owned by the current user"
[[ "$(stat -f '%Lp' "${key_path}")" == "600" ]] ||
  die "App Store Connect private key must have mode 0600"

asc=(
  python3 "${repo_root}/scripts/app_store_connect.py"
  --key-id "${key_id}"
  --issuer-id "${issuer_id}"
  --private-key "${key_path}"
)
bundle_id="io.rw0.mesh.tunnel.mobile"

build_setting() {
  local name="$1"
  xcodebuild \
    -project "${repo_root}/ios-tunnel/MeshTunnel.xcodeproj" \
    -scheme MeshTunnel \
    -configuration Profile \
    -showBuildSettings 2>/dev/null |
    awk -F ' = ' -v expected="${name}" '
      $1 ~ "^[[:space:]]*" expected "$" { print $2; exit }
    '
}

version="$(build_setting MARKETING_VERSION)"
project_build="$(build_setting CURRENT_PROJECT_VERSION)"
[[ "${version}" =~ ^[0-9]+([.][0-9]+){1,2}$ ]] ||
  die "project marketing version is invalid"
[[ "${project_build}" =~ ^[0-9]+$ ]] ||
  die "project build number is invalid"

command="${1:-}"
if [[ -z "${command}" || "${command}" == "-h" || "${command}" == "--help" ]]; then
  usage
  exit 0
fi
shift

requested_build="${1:-${project_build}}"
if [[ "${command}" == "status" || "${command}" == "distribute" ]]; then
  [[ "$#" -le 1 && "${requested_build}" =~ ^[0-9]+$ ]] || {
    usage >&2
    exit 2
  }
fi

status_build() {
  local build_number="$1"
  local arguments=(
    status
    --bundle-id "${bundle_id}"
    --version "${version}"
    --build-number "${build_number}"
  )
  if [[ -n "${MESH_TESTFLIGHT_TESTER_EMAIL:-}" ]]; then
    arguments+=(--tester-email "${MESH_TESTFLIGHT_TESTER_EMAIL}")
  fi
  "${asc[@]}" "${arguments[@]}"
}

distribute_build() {
  local build_number="$1"
  [[ -n "${MESH_TESTFLIGHT_TESTER_EMAIL:-}" ]] ||
    die "MESH_TESTFLIGHT_TESTER_EMAIL is required"
  local arguments=(
    distribute
    --bundle-id "${bundle_id}"
    --version "${version}"
    --build-number "${build_number}"
    --tester-email "${MESH_TESTFLIGHT_TESTER_EMAIL}"
    --uses-only-exempt-encryption
    --submit-beta-review
  )
  if [[ -n "${MESH_TESTFLIGHT_BETA_GROUP:-}" ]]; then
    arguments+=(
      --beta-group "${MESH_TESTFLIGHT_BETA_GROUP}"
      --create-beta-group
    )
  fi
  "${asc[@]}" "${arguments[@]}"
}

case "${command}" in
  status)
    status_build "${requested_build}"
    exit 0
    ;;
  distribute)
    distribute_build "${requested_build}"
    exit 0
    ;;
  publish)
    [[ "$#" -eq 0 ]] || {
      usage >&2
      exit 2
    }
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

[[ -n "${MESH_TESTFLIGHT_TESTER_EMAIL:-}" ]] ||
  die "MESH_TESTFLIGHT_TESTER_EMAIL is required"
[[ -z "$(git status --porcelain)" ]] ||
  die "publish requires a clean Git checkout"
source_commit="$(git rev-parse HEAD)"
[[ "${source_commit}" =~ ^[0-9a-f]{40}$ ]] ||
  die "source commit is invalid"

next_build="$(
  "${asc[@]}" next-build \
    --bundle-id "${bundle_id}" \
    --version "${version}" \
    --local-floor "${project_build}"
)"
[[ "${next_build}" =~ ^[0-9]+$ && "${next_build}" -gt "${project_build}" ]] ||
  die "App Store Connect returned an invalid next build number"

output_parent="${MESH_TESTFLIGHT_OUTPUT_PARENT:-/private/var/tmp}"
[[ "${output_parent}" == /* && -d "${output_parent}" && ! -L "${output_parent}" ]] ||
  die "output parent must be one existing physical directory"
output_root="${output_parent}/mesh-testflight-${source_commit:0:12}-${version}-${next_build}"
[[ ! -e "${output_root}" && ! -L "${output_root}" ]] ||
  die "release output already exists: ${output_root}"
mkdir -m 700 "${output_root}"

flutter="${MESH_FLUTTER:-${repo_root}/../.mesh-toolchains/flutter-3.44.8-arm64/flutter/bin/flutter}"
flutter_archive="${MESH_FLUTTER_ARCHIVE:-${repo_root}/../.mesh-toolchains/downloads/flutter_macos_arm64_3.44.8-stable.zip}"
[[ "${flutter}" == /* && -x "${flutter}" ]] ||
  die "pinned Flutter executable is unavailable"
[[ "${flutter_archive}" == /* && -f "${flutter_archive}" && ! -L "${flutter_archive}" ]] ||
  die "pinned Flutter archive is unavailable"

source_keychain="${output_root}/source-build.keychain-db"
source_keychain_password="$(/usr/bin/openssl rand -hex 32)"
security create-keychain -p "${source_keychain_password}" "${source_keychain}"
chmod 600 "${source_keychain}"
cleanup_source_keychain() {
  if [[ -f "${source_keychain}" && ! -L "${source_keychain}" ]]; then
    security delete-keychain "${source_keychain}" >/dev/null 2>&1 || true
  fi
}
trap cleanup_source_keychain EXIT

unset_release_credentials=(
  -u AC_PASSWORD
  -u APPLE_ID
  -u APPLE_TEAM_ID
  -u APP_STORE_CONNECT_API_KEY
  -u APP_STORE_CONNECT_API_KEY_ID
  -u APP_STORE_CONNECT_ISSUER_ID
  -u DEVELOPER_ID_APPLICATION
  -u DEVELOPER_ID_INSTALLER
  -u FASTLANE_PASSWORD
  -u MATCH_PASSWORD
  -u NOTARY_PASSWORD
  -u NOTARY_PROFILE
)

printf 'Running Mesh Apple source gates for %s (%s)...\n' "${version}" "${next_build}"
make apple-preflight-test
preflight_receipt="${output_root}/mesh-apple-source-build-receipt.json"
env "${unset_release_credentials[@]}" \
  python3 "${repo_root}/scripts/apple-build-preflight.py" \
    --flutter "${flutter}" \
    --flutter-archive "${flutter_archive}" \
    --source-keychain "${source_keychain}" \
    --output "${preflight_receipt}" \
    --require-clean

source_output="${output_root}/source"
env "${unset_release_credentials[@]}" \
  MESH_APPLE_INPUT_RECEIPT="${preflight_receipt}" \
  MESH_SOURCE_KEYCHAIN="${source_keychain}" \
  "${repo_root}/scripts/apple-ios-tunnel-source-build.sh" "${source_output}"

framework_slice="${source_output}/mobile-framework/MeshMobile.xcframework/ios-arm64"
[[ -d "${framework_slice}" && ! -L "${framework_slice}" ]] ||
  die "device MeshMobile framework slice is unavailable"

archive="${output_root}/MeshTunnel-${version}-${next_build}.xcarchive"
printf 'Archiving signed Mesh Tunnel %s (%s)...\n' "${version}" "${next_build}"
xcodebuild -quiet \
  -project "${repo_root}/ios-tunnel/MeshTunnel.xcodeproj" \
  -scheme MeshTunnel \
  -configuration Profile \
  -sdk iphoneos \
  -destination 'generic/platform=iOS' \
  -archivePath "${archive}" \
  -allowProvisioningUpdates \
  -authenticationKeyPath "${key_path}" \
  -authenticationKeyID "${key_id}" \
  -authenticationKeyIssuerID "${issuer_id}" \
  archive \
  "CURRENT_PROJECT_VERSION=${next_build}" \
  "MARKETING_VERSION=${version}" \
  "FRAMEWORK_SEARCH_PATHS=\$(inherited) ${framework_slice}" \
  "OTHER_LDFLAGS=\$(inherited) -framework MeshMobile"

export_root="${output_root}/export"
xcodebuild -quiet \
  -exportArchive \
  -archivePath "${archive}" \
  -exportPath "${export_root}" \
  -exportOptionsPlist \
    "${repo_root}/packaging/apple/ios-tunnel-app-store-export-options.plist" \
  -allowProvisioningUpdates \
  -authenticationKeyPath "${key_path}" \
  -authenticationKeyID "${key_id}" \
  -authenticationKeyIssuerID "${issuer_id}"

ipa_count="$(
  find "${export_root}" -maxdepth 1 -type f -name '*.ipa' -print |
    wc -l |
    tr -d '[:space:]'
)"
[[ "${ipa_count}" == "1" ]] ||
  die "export did not produce exactly one IPA"
ipa="$(find "${export_root}" -maxdepth 1 -type f -name '*.ipa' -print)"

profile_root="${HOME}/Library/Developer/Xcode/UserData/Provisioning Profiles"
host_profile="${profile_root}/9ae4c36f-22a0-4d67-b078-f40049321616.mobileprovision"
extension_profile="${profile_root}/4201014e-16f3-4836-8da4-04b856709c51.mobileprovision"
distribution_receipt="${output_root}/ios-tunnel-distribution-verification.json"
python3 "${repo_root}/scripts/apple_distribution_verify.py" \
  --product ios-tunnel \
  --host-profile "${host_profile}" \
  --extension-profile "${extension_profile}" \
  --tunnel-archive "${archive}" \
  --tunnel-ipa "${ipa}" \
  --output "${distribution_receipt}"

printf 'Uploading verified Mesh Tunnel %s (%s)...\n' "${version}" "${next_build}"
xcrun altool --upload-app \
  --file "${ipa}" \
  --type ios \
  --apiKey "${key_id}" \
  --apiIssuer "${issuer_id}" \
  --output-format json

"${asc[@]}" wait \
  --bundle-id "${bundle_id}" \
  --version "${version}" \
  --build-number "${next_build}" \
  --tester-email "${MESH_TESTFLIGHT_TESTER_EMAIL}" \
  --timeout 1800 \
  --poll-interval 30
distribute_build "${next_build}"

printf 'Mesh Tunnel TestFlight release completed.\n'
printf 'Source commit: %s\n' "${source_commit}"
printf 'Version/build: %s (%s)\n' "${version}" "${next_build}"
printf 'Evidence: %s\n' "${output_root}"
