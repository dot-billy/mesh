#!/bin/bash
# Build and inspect the unsigned, fail-closed Mesh Tunnel simulator proof.
set -euo pipefail
umask 077

if [[ "$#" -ne 1 ]]; then
  printf 'usage: apple-ios-tunnel-source-build.sh <new-absolute-output>\n' >&2
  exit 2
fi
if [[ "$(uname -s)" != Darwin ]]; then
  printf 'Apple iOS Tunnel source build requires a native Mac\n' >&2
  exit 77
fi

output_root="$1"
if [[ "${output_root}" != /* || -e "${output_root}" ]]; then
  printf 'Apple iOS Tunnel source output must be a new absolute path\n' >&2
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
    printf 'unsigned Apple iOS Tunnel build received release credential variable %s\n' "${name}" >&2
    exit 1
  fi
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
project_root="${repo_root}/ios-tunnel"
parent="$(dirname "${output_root}")"
if [[ ! -d "${parent}" || -L "${parent}" ]]; then
  printf 'Apple iOS Tunnel output parent must be one existing physical directory\n' >&2
  exit 2
fi
mkdir -m 700 "${output_root}"

mobile_framework_root="${MESH_IOS_MOBILE_FRAMEWORK_OUTPUT:-}"
if [[ -z "${mobile_framework_root}" ]]; then
  mobile_framework_root="${output_root}/mobile-framework"
  "${repo_root}/scripts/apple-ios-mobile-framework-build.sh" \
    "${mobile_framework_root}"
fi
if [[ "${mobile_framework_root}" != /* || ! -d "${mobile_framework_root}" || -L "${mobile_framework_root}" ]]; then
  printf 'MESH_IOS_MOBILE_FRAMEWORK_OUTPUT must name one absolute physical framework build output\n' >&2
  exit 2
fi
mobile_framework="${mobile_framework_root}/MeshMobile.xcframework"
mobile_framework_receipt="${mobile_framework_root}/mesh-apple-ios-mobile-framework-source-receipt.json"
mobile_simulator_slice="${mobile_framework}/ios-arm64_x86_64-simulator"
if [[ ! -d "${mobile_framework}" || -L "${mobile_framework}" || ! -d "${mobile_simulator_slice}" || -L "${mobile_simulator_slice}" || ! -f "${mobile_framework_receipt}" || -L "${mobile_framework_receipt}" ]]; then
  printf 'MeshMobile framework output is incomplete or linked\n' >&2
  exit 2
fi

swift test \
  --package-path "${project_root}" \
  --scratch-path "${output_root}/swift-contract"

xcodebuild -quiet \
  -project "${project_root}/MeshTunnel.xcodeproj" \
  -scheme MeshTunnel \
  -configuration Debug \
  -sdk iphonesimulator \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath "${output_root}/xcode" \
  build \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGN_ENTITLEMENTS= \
  "FRAMEWORK_SEARCH_PATHS=\$(inherited) ${mobile_simulator_slice}" \
  "OTHER_LDFLAGS=\$(inherited) -framework MeshMobile" \
  "OTHER_CODE_SIGN_FLAGS=--keychain ${MESH_SOURCE_KEYCHAIN}"

app="${output_root}/xcode/Build/Products/Debug-iphonesimulator/Mesh Tunnel.app"
python3 "${repo_root}/scripts/apple_source_artifact_receipt.py" \
  --platform ios-tunnel-simulator \
  --configuration debug \
  --app "${app}" \
  --input-receipt "${MESH_APPLE_INPUT_RECEIPT}" \
  --mobile-framework "${mobile_framework}" \
  --mobile-framework-receipt "${mobile_framework_receipt}" \
  --output "${output_root}/mesh-apple-ios-tunnel-simulator-source-receipt.json"
