#!/usr/bin/env bash
set -euo pipefail
umask 077

say() {
  printf '%s\n' "$*"
}

die() {
  printf 'security baseline: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 0 ]] || die "this gate accepts no arguments"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "${script_dir}/.." && pwd -P)"
[[ -f "${repo_root}/go.mod" && -f "${repo_root}/.gitleaks.toml" ]] || die "repository security inputs are missing"

for required in go docker find id mktemp; do
  command -v "${required}" >/dev/null 2>&1 || die "required command is unavailable: ${required}"
done

go_toolchain="go1.26.5"
govulncheck_version="v1.6.0"
gitleaks_version="v8.30.1"
gitleaks_image="ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"

temporary_parent="${TMPDIR:-/tmp}"
[[ -d "${temporary_parent}" && ! -L "${temporary_parent}" ]] || die "temporary directory parent is unavailable or linked"
temporary_parent="$(cd -- "${temporary_parent}" && pwd -P)"
work_dir="$(mktemp -d "${temporary_parent%/}/mesh-security-baseline.XXXXXX")"
[[ -d "${work_dir}" && ! -L "${work_dir}" && "${work_dir}" == "${temporary_parent%/}/mesh-security-baseline."* ]] || die "mktemp returned an unsafe workspace"
chmod 0700 "${work_dir}"

cleanup() {
  if [[ -n "${work_dir:-}" && -d "${work_dir}" && "${work_dir}" == "${temporary_parent%/}/mesh-security-baseline."* ]]; then
    rm -rf -- "${work_dir}"
  fi
}
trap cleanup EXIT

mkdir -m 0700 "${work_dir}/bin" "${work_dir}/empty-bin"

cd -- "${repo_root}"
export GOTOOLCHAIN="${go_toolchain}"
export GOTELEMETRY=off
export GOWORK=off
export GOFLAGS=-buildvcs=false

actual_go_version="$(go env GOVERSION)"
[[ "${actual_go_version}" == "${go_toolchain}" ]] || die "resolved Go toolchain ${actual_go_version} does not match ${go_toolchain}"

say "Verifying module checksums with ${actual_go_version}"
go mod verify

say "Running the complete Go test and vet gates"
go test ./...
go vet ./...

say "Installing and running govulncheck ${govulncheck_version}"
GOBIN="${work_dir}/bin" go install "golang.org/x/vuln/cmd/govulncheck@${govulncheck_version}"
[[ -x "${work_dir}/bin/govulncheck" ]] || die "govulncheck installation did not produce an executable"
"${work_dir}/bin/govulncheck" -mode=source ./... github.com/slackhq/nebula/cmd/nebula-cert

oversized_source="$(find "${repo_root}" \
  -path "${repo_root}/bin" -prune -o \
  -path "${repo_root}/.git" -prune -o \
  -type f -size +10M -print -quit)"
[[ -z "${oversized_source}" ]] || die "secret scan would skip oversized source file: ${oversized_source}"

if ! docker image inspect "${gitleaks_image}" >/dev/null 2>&1; then
  say "Pulling the digest-pinned Gitleaks image"
  docker pull "${gitleaks_image}" >/dev/null
fi

docker_args=(
  run --rm
  --network=none
  --read-only
  --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=32m
  --cap-drop=ALL
  --security-opt=no-new-privileges
  --pids-limit=128
  --memory=256m
  --user="$(id -u):$(id -g)"
)

actual_gitleaks_version="$(docker "${docker_args[@]}" "${gitleaks_image}" version)"
[[ "${actual_gitleaks_version}" == "${gitleaks_version}" ]] || die "Gitleaks version ${actual_gitleaks_version} does not match ${gitleaks_version}"

say "Scanning the current source tree with ${gitleaks_version} in a networkless read-only container"
source_mounts=(-v "${repo_root}:/repo:ro")
if [[ -d "${repo_root}/bin" ]]; then
  source_mounts+=(-v "${work_dir}/empty-bin:/repo/bin:ro")
fi
docker "${docker_args[@]}" \
  "${source_mounts[@]}" \
  "${gitleaks_image}" dir /repo \
  --config=/repo/.gitleaks.toml \
  --no-banner \
  --no-color \
  --redact=100 \
  --max-target-megabytes=10 \
  --max-archive-depth=2 \
  --max-decode-depth=3 \
  --timeout=120

say "PASS: patched toolchain, module integrity, tests, vet, reachable vulnerability scan, and redacted secret scan"
