#!/bin/bash
# Build one unsigned macOS source artifact in a new DerivedData directory.
set -euo pipefail
umask 077

if [[ "$#" -ne 2 ]]; then
  printf 'usage: apple-source-build.sh <debug|release> <new-absolute-derived-data>\n' >&2
  exit 2
fi
if [[ "$(uname -s)" != Darwin ]]; then
  printf 'Apple source build requires a native Mac\n' >&2
  exit 77
fi

configuration="$1"
case "${configuration}" in
  debug) xcode_configuration=Debug ;;
  release) xcode_configuration=Release ;;
  *) printf 'Apple source build configuration must be debug or release\n' >&2; exit 2 ;;
esac

derived_data="$2"
if [[ "${derived_data}" != /* || -e "${derived_data}" ]]; then
  printf 'Apple source build output must be a new absolute path\n' >&2
  exit 2
fi
if [[ -z "${MESH_FLUTTER:-}" || "${MESH_FLUTTER}" != /* || ! -x "${MESH_FLUTTER}" ]]; then
  printf 'MESH_FLUTTER must name the executable from the verified pinned SDK\n' >&2
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
    printf 'unsigned Apple source build received release credential variable %s\n' "${name}" >&2
    exit 1
  fi
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
desktop_root="${repo_root}/desktop"
source_commit="$(python3 - "${MESH_APPLE_INPUT_RECEIPT}" <<'PY'
import json
import pathlib
import re
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text())
commit = value.get("source", {}).get("commit", "")
if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
    raise SystemExit("Apple input receipt source commit is invalid")
print(commit)
PY
)"
parent="$(dirname "${derived_data}")"
if [[ ! -d "${parent}" || -L "${parent}" ]]; then
  printf 'Apple source build output parent must be one existing physical directory\n' >&2
  exit 2
fi

(
  cd "${desktop_root}"
  "${MESH_FLUTTER}" build macos "--${configuration}" --config-only \
    --dart-define=MESH_APP_VERSION=0.1.0 \
    --dart-define=MESH_APP_BUILD=1 \
    "--dart-define=MESH_SOURCE_COMMIT=${source_commit}"
  xcodebuild -quiet \
    -workspace macos/Runner.xcworkspace \
    -scheme Runner \
    -configuration "${xcode_configuration}" \
    -derivedDataPath "${derived_data}" \
    build \
    CODE_SIGNING_ALLOWED=NO \
    CODE_SIGN_ENTITLEMENTS= \
    "OTHER_CODE_SIGN_FLAGS=--keychain ${MESH_SOURCE_KEYCHAIN}"
)

app="${derived_data}/Build/Products/${xcode_configuration}/Mesh Admin.app"
python3 "${repo_root}/scripts/apple_source_artifact_receipt.py" \
  --configuration "${configuration}" \
  --app "${app}" \
  --input-receipt "${MESH_APPLE_INPUT_RECEIPT}" \
  --output "${derived_data}/mesh-apple-${configuration}-source-receipt.json"
