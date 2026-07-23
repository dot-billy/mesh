#!/usr/bin/env bash

# Run only on a disposable or approved native Mac. The tests create and remove
# one exact root-owned directory below /private/var/db and start disposable
# sleep/shell process groups to prove native path and child-lifecycle behavior.
# With an additional explicit gate, they also create and remove one exact
# proof-only plist in /Library/LaunchDaemons and mutate its unique system label.
set -Eeuo pipefail
umask 077

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"

if [[ "$(uname -s)" != Darwin ]]; then
  printf 'SKIP: darwin-native-runtime-smoke requires a native Mac\n' >&2
  exit 77
fi
if [[ "$(id -u)" -ne 0 || "$(id -g)" -ne 0 ]]; then
  printf 'darwin-native-runtime-smoke must run as root:wheel\n' >&2
  exit 1
fi
for command_name in awk chmod date go install mkdir mktemp rm shasum sort sw_vers uname; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    printf 'required command is unavailable: %s\n' "${command_name}" >&2
    exit 1
  }
done

system_launchctl_test="${MESH_DARWIN_SYSTEM_LAUNCHCTL_TEST:-0}"
case "${system_launchctl_test}" in
  0|1) ;;
  *)
    printf 'MESH_DARWIN_SYSTEM_LAUNCHCTL_TEST must be exactly 0 or 1\n' >&2
    exit 1
    ;;
esac
native_bundle="${MESH_DARWIN_NATIVE_BUNDLE:-}"
bundle_sha="none"
if [[ -n "${native_bundle}" ]]; then
  [[ "${native_bundle}" == /* && -f "${native_bundle}" && ! -L "${native_bundle}" ]] || {
    printf 'MESH_DARWIN_NATIVE_BUNDLE must be an absolute non-symlink regular file\n' >&2
    exit 1
  }
  bundle_sha="$(shasum -a 256 "${native_bundle}" | awk '{print $1}')"
fi
if [[ "${system_launchctl_test}" == 1 && -z "${native_bundle}" ]]; then
  printf 'the system launchctl proof requires MESH_DARWIN_NATIVE_BUNDLE so the complete native lifecycle runs with it\n' >&2
  exit 1
fi

work_dir="$(mktemp -d /private/var/tmp/mesh-darwin-native-runtime.XXXXXX)"
started_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [[ -n "${work_dir:-}" && -d "${work_dir}" && "${work_dir}" == /private/var/tmp/mesh-darwin-native-runtime.* ]]; then
    chmod -RN "${work_dir}" 2>/dev/null || true
    chmod -R u+rwX "${work_dir}" 2>/dev/null || true
    rm -r -- "${work_dir}"
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

{
  sw_vers
  uname -a
  printf 'go_version=%s\n' "$(go version)"
  printf 'executed_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
} >"${work_dir}/system.txt"

cd -- "${repo_root}"
MESH_DARWIN_NATIVE_FAULT_TEST=1 \
MESH_DARWIN_SYSTEM_LAUNCHCTL_TEST="${system_launchctl_test}" \
MESH_DARWIN_NATIVE_BUNDLE="${native_bundle}" \
go test \
  ./internal/nodeagent ./internal/darwininstall ./cmd/meshctl \
  -run '^TestDarwinNative' -count=1 -v >"${work_dir}/tests.txt" 2>&1

system_sha="$(shasum -a 256 "${work_dir}/system.txt" | awk '{print $1}')"
tests_sha="$(shasum -a 256 "${work_dir}/tests.txt" | awk '{print $1}')"
case "$(uname -m)" in
  x86_64) architecture=amd64 ;;
  arm64) architecture=arm64 ;;
  *) printf 'unsupported native Darwin architecture\n' >&2; exit 1 ;;
esac
source_paths=(
  scripts/darwin-native-runtime-smoke.sh
  cmd/meshctl/agent_entry_other.go
  cmd/meshctl/agent_supervised_runtime_darwin.go
  cmd/meshctl/agent_supervised_runtime_darwin_test.go
  internal/darwinbundle/candidate.go
  internal/darwininstall/runtime_gate_darwin.go
  internal/darwininstall/runtime_gate_darwin_test.go
  internal/nodeagent/darwin_native_pathsecurity_test.go
  internal/nodeagent/pathsecurity_darwin.go
  internal/nodeagent/pathsecurity_platform_darwin.go
  packaging/launchd/io.mesh.node-agent.plist
)
: >"${work_dir}/source.txt"
while IFS= read -r relative; do
  [[ -f "${repo_root}/${relative}" && ! -L "${repo_root}/${relative}" ]] || {
    printf 'native Darwin evidence source is missing or linked: %s\n' "${relative}" >&2
    exit 1
  }
  printf '%s  %s\n' "$(shasum -a 256 "${repo_root}/${relative}" | awk '{print $1}')" "${relative}" >>"${work_dir}/source.txt"
done < <(printf '%s\n' "${source_paths[@]}" | LC_ALL=C sort -u)
source_sha="$(shasum -a 256 "${work_dir}/source.txt" | awk '{print $1}')"
stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
{
  printf 'schema=mesh-darwin-native-runtime-proof-v3\n'
  printf 'architecture=%s\n' "${architecture}"
  printf 'system_launchctl_mutation_test=%s\n' "${system_launchctl_test}"
  printf 'system_launchctl_proof_label=io.mesh.node-agent.native-proof\n'
  printf 'darwin_bundle_sha256=%s\n' "${bundle_sha}"
  printf 'system_sha256=%s\n' "${system_sha}"
  printf 'tests_sha256=%s\n' "${tests_sha}"
  printf 'source_sha256=%s\n' "${source_sha}"
  printf 'started_at=%s\n' "${started_at}"
  printf 'verified_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
} >"${work_dir}/receipt.txt"

evidence_root="${MESH_DARWIN_NATIVE_EVIDENCE_DIR:-${repo_root}/bin/darwin-native-runtime}"
[[ "${evidence_root}" == /* && "${evidence_root}" != / ]] || {
  printf 'native evidence root must be a non-root absolute path\n' >&2
  exit 1
}
if [[ -e "${evidence_root}" ]]; then
  [[ -d "${evidence_root}" && ! -L "${evidence_root}" ]] || {
    printf 'native evidence root is unsafe\n' >&2
    exit 1
  }
else
  mkdir -m 0700 -- "${evidence_root}"
fi
evidence_dir="${evidence_root}/${stamp}-${architecture}"
mkdir -m 0700 -- "${evidence_dir}"
for name in system.txt tests.txt source.txt receipt.txt; do
  install -m 0400 "${work_dir}/${name}" "${evidence_dir}/${name}"
done

if [[ "${system_launchctl_test}" == 1 ]]; then
  printf 'PASS: native Darwin path, ACL, installer, offline intake, exact-child, system launchctl mutation, group-kill, and reap faults passed\n'
else
  printf 'PASS: native Darwin path, ACL, installer gate, exact-child, group-kill, and reap faults passed; system launchctl mutation remained explicitly disabled\n'
fi
printf 'Evidence: %s\n' "${evidence_dir}"
