#!/usr/bin/env bash

# Exercise every Linux-verifiable part of the native Darwin path-security
# boundary. This does not execute fgetattrlist on a Mac and therefore cannot
# replace the real-host fault-injection checklist in docs/darwin-path-security.md.
set -Eeuo pipefail
umask 077

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/mesh-darwin-path-security-smoke.XXXXXX")"

cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [[ -n "${work_dir:-}" && -d "${work_dir}" && "$(basename -- "${work_dir}")" == mesh-darwin-path-security-smoke.* ]]; then
    chmod -R u+rwX -- "${work_dir}" 2>/dev/null || true
    rm -r -- "${work_dir}"
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

for command_name in go file cmp grep mktemp rm; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    printf 'SKIP: required command %s is unavailable\n' "${command_name}" >&2
    exit 77
  }
done

cd -- "${repo_root}"

printf 'Running portable Darwin ACL parser and path-walk fault injection\n'
go test ./internal/nodeagent \
  -run '^(TestParseDarwinExtendedSecurityResult|TestValidateDarwinPathWith|TestValidateDarwinPersistentRuntimeGate|TestValidateDarwinPackagedExecutable)' \
  -count=1
go test ./cmd/meshctl \
  -run '^(TestAuthorizeSupervisedRuntimeRequiresPersistentGateBeforeAdapter|TestSupervisedRuntime|TestAgentCycleAuthorizesPersistentGate|TestParseDarwinProcessArguments|TestValidateDarwinProcessArguments)' \
  -count=1
go test ./internal/darwininstall -count=1

printf 'Validating the physical launchd state-path contract\n'
go test ./packaging/launchd -count=1
if grep -Eq '([<`])/?var/db/mesh-(agent|installer)' \
  packaging/launchd/io.mesh.node-agent.plist packaging/launchd/README.md; then
  printf 'launchd assets contain a symlinked /var state path\n' >&2
  exit 1
fi

for arch in amd64 arm64; do
  printf 'Cross-compiling Darwin path-security test and production binaries for %s\n' "${arch}"
  GOOS=darwin GOARCH="${arch}" CGO_ENABLED=0 \
    go test -c -buildvcs=false -trimpath ./internal/nodeagent \
      -o "${work_dir}/nodeagent-${arch}.test"
  GOOS=darwin GOARCH="${arch}" CGO_ENABLED=0 \
    go test -c -buildvcs=false -trimpath ./cmd/meshctl \
      -o "${work_dir}/meshctl-${arch}.test"
  GOOS=darwin GOARCH="${arch}" CGO_ENABLED=0 \
    go test -c -buildvcs=false -trimpath ./internal/darwininstall \
      -o "${work_dir}/darwininstall-${arch}.test"
  GOOS=darwin GOARCH="${arch}" CGO_ENABLED=0 \
    go test -c -buildvcs=false -trimpath ./internal/darwinbundle \
      -o "${work_dir}/darwinbundle-${arch}.test"
  for copy in first second; do
    GOOS=darwin GOARCH="${arch}" CGO_ENABLED=0 \
      go build -buildvcs=false -trimpath -ldflags=-buildid= \
        -o "${work_dir}/meshctl-${arch}-${copy}" ./cmd/meshctl
  done
  cmp --silent -- \
    "${work_dir}/meshctl-${arch}-first" \
    "${work_dir}/meshctl-${arch}-second" || {
    printf 'darwin/%s meshctl build was not reproducible\n' "${arch}" >&2
    exit 1
  }
  file "${work_dir}/nodeagent-${arch}.test" "${work_dir}/meshctl-${arch}.test" "${work_dir}/darwininstall-${arch}.test" "${work_dir}/darwinbundle-${arch}.test" "${work_dir}/meshctl-${arch}-first" |
    grep -Eq "Mach-O 64-bit (x86_64|arm64) executable" || {
    printf 'darwin/%s output is not a 64-bit Mach-O executable\n' "${arch}" >&2
    exit 1
  }
  go version -m "${work_dir}/meshctl-${arch}-first" |
    grep -Fx $'\tbuild\tGOOS=darwin' >/dev/null
  go version -m "${work_dir}/meshctl-${arch}-first" |
    grep -Fx $'\tbuild\tGOARCH='"${arch}" >/dev/null
  go version -m "${work_dir}/meshctl-${arch}-first" |
    grep -Fx $'\tbuild\tCGO_ENABLED=0' >/dev/null
done

printf 'PASS: deterministic darwin/amd64 and darwin/arm64 path-security binaries; native Mac execution is still required\n'
