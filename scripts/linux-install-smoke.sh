#!/usr/bin/env bash

# Clean-host proof for Mesh's authenticated HTTPS and offline Linux install paths.
#
# This intentionally uses an isolated privileged systemd container. It never
# changes host sysctls, never mounts a host install path into the container,
# and never places enrollment bearers or private signing keys in argv/output.

set -Eeuo pipefail
umask 077

readonly skip_status=77
readonly script_name="${0##*/}"
readonly keep_smoke="${KEEP_MESH_INSTALL_SMOKE:-0}"
readonly ui_guided_package_smoke="${MESH_UI_GUIDED_PACKAGE_SMOKE:-0}"
readonly proof_image="${MESH_SYSTEMD_PROOF_IMAGE:-mesh-systemd-proof:fedora42}"
readonly proof_image_identity="fedora42-v5"
readonly channel="stable"
readonly security_floor=1
readonly arch="amd64"
release_base_url="https://127.0.0.1:18443"
readonly version_one="1.0.0"
readonly version_two="1.0.1"
readonly version_three="1.0.2"
readonly version_four="1.0.3"
readonly version_five="2.0.0"
readonly commit_one="1111111111111111111111111111111111111111"
readonly commit_two="2222222222222222222222222222222222222222"
readonly commit_three="3333333333333333333333333333333333333333"
readonly commit_four="4444444444444444444444444444444444444444"
readonly commit_five="5555555555555555555555555555555555555555"

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
nebula_dir="${MESH_NEBULA_DIR:-}"
work_dir=""
container_name=""
offline_container_name=""
ui_lighthouse_container_name=""
ui_member_container_name=""
proof_network_name=""
run_id=""
container_started=0
offline_container_started=0
ui_lighthouse_container_started=0
ui_member_container_started=0
proof_network_started=0
proof_control_ip=""
proof_lighthouse_ip=""
proof_member_ip=""

say() {
  printf '%s\n' "$*"
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

skip() {
  printf 'SKIP: %s\n' "$*" >&2
  exit "${skip_status}"
}

cleanup() {
  local status=$?
  local observed_label=""

  trap - ERR EXIT HUP INT TERM
  set +e

  if [[ "${keep_smoke}" == "1" ]]; then
    if [[ -n "${work_dir}" ]]; then
      printf 'Kept private Linux install smoke workspace: %s\n' "${work_dir}" >&2
    fi
    if [[ "${container_started}" == "1" ]]; then
      printf 'Kept isolated Linux install smoke container: %s\n' "${container_name}" >&2
    fi
    if [[ "${offline_container_started}" == "1" ]]; then
      printf 'Kept isolated offline-regression container: %s\n' "${offline_container_name}" >&2
    fi
    if [[ "${ui_lighthouse_container_started}" == "1" ]]; then
      printf 'Kept isolated UI-guided lighthouse host: %s\n' "${ui_lighthouse_container_name}" >&2
    fi
    if [[ "${ui_member_container_started}" == "1" ]]; then
      printf 'Kept isolated UI-guided member host: %s\n' "${ui_member_container_name}" >&2
    fi
    if [[ "${proof_network_started}" == "1" ]]; then
      printf 'Kept isolated Linux install proof network: %s\n' "${proof_network_name}" >&2
    fi
    if [[ -n "${work_dir}" || "${container_started}" == "1" ]]; then
      printf 'Kept proof state contains live test credentials; remove it when finished.\n' >&2
    fi
    exit "${status}"
  fi

  if [[ "${ui_member_container_started}" == "1" ]]; then
    observed_label="$(docker inspect --format '{{index .Config.Labels "mesh.install-smoke.id"}}' "${ui_member_container_name}" 2>/dev/null || true)"
    if [[ -n "${run_id}" && "${observed_label}" == "${run_id}-ui-member" && "${ui_member_container_name}" == "mesh-install-smoke-${run_id}-ui-member" ]]; then
      docker rm --force --volumes -- "${ui_member_container_name}" >/dev/null 2>&1 || status=1
    else
      printf 'ERROR: refusing to remove UI-guided member container with an unexpected proof identity: %s\n' "${ui_member_container_name}" >&2
      status=1
    fi
    ui_member_container_started=0
  fi

  if [[ "${ui_lighthouse_container_started}" == "1" ]]; then
    observed_label="$(docker inspect --format '{{index .Config.Labels "mesh.install-smoke.id"}}' "${ui_lighthouse_container_name}" 2>/dev/null || true)"
    if [[ -n "${run_id}" && "${observed_label}" == "${run_id}-ui-lighthouse" && "${ui_lighthouse_container_name}" == "mesh-install-smoke-${run_id}-ui-lighthouse" ]]; then
      docker rm --force --volumes -- "${ui_lighthouse_container_name}" >/dev/null 2>&1 || status=1
    else
      printf 'ERROR: refusing to remove UI-guided lighthouse container with an unexpected proof identity: %s\n' "${ui_lighthouse_container_name}" >&2
      status=1
    fi
    ui_lighthouse_container_started=0
  fi

  if [[ "${offline_container_started}" == "1" ]]; then
    observed_label="$(docker inspect --format '{{index .Config.Labels "mesh.install-smoke.id"}}' "${offline_container_name}" 2>/dev/null || true)"
    if [[ -n "${run_id}" && "${observed_label}" == "${run_id}-offline" && "${offline_container_name}" == "mesh-install-smoke-${run_id}-offline" ]]; then
      docker rm --force --volumes -- "${offline_container_name}" >/dev/null 2>&1 || status=1
    else
      printf 'ERROR: refusing to remove offline container with an unexpected proof identity: %s\n' "${offline_container_name}" >&2
      status=1
    fi
    offline_container_started=0
  fi

  if [[ "${container_started}" == "1" ]]; then
    observed_label="$(docker inspect --format '{{index .Config.Labels "mesh.install-smoke.id"}}' "${container_name}" 2>/dev/null || true)"
    if [[ -n "${run_id}" && "${observed_label}" == "${run_id}" && "${container_name}" == "mesh-install-smoke-${run_id}" ]]; then
      docker rm --force --volumes -- "${container_name}" >/dev/null 2>&1 || status=1
    else
      printf 'ERROR: refusing to remove container with an unexpected proof identity: %s\n' "${container_name}" >&2
      status=1
    fi
    container_started=0
  fi

  if [[ "${proof_network_started}" == "1" ]]; then
    observed_label="$(docker network inspect --format '{{index .Labels "mesh.install-smoke.id"}}' "${proof_network_name}" 2>/dev/null || true)"
    if [[ -n "${run_id}" && "${observed_label}" == "${run_id}-network" && "${proof_network_name}" == "mesh-install-smoke-${run_id}-network" ]]; then
      docker network rm -- "${proof_network_name}" >/dev/null 2>&1 || status=1
    else
      printf 'ERROR: refusing to remove network with an unexpected proof identity: %s\n' "${proof_network_name}" >&2
      status=1
    fi
    proof_network_started=0
  fi

  if [[ -n "${work_dir}" && -d "${work_dir}" ]]; then
    case "${work_dir##*/}" in
      mesh-install-smoke.*)
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
  printf 'ERROR: %s failed at line %s (set KEEP_MESH_INSTALL_SMOKE=1 to retain private diagnostics)\n' \
    "${script_name}" "${line}" >&2
  exit "${status}"
}

trap cleanup EXIT
trap 'on_error "${LINENO}"' ERR
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

need_command() {
  command -v -- "$1" >/dev/null 2>&1 || skip "required command is unavailable: $1"
}

json_get() {
  local path="$1"
  local field="$2"

  python3 - "${path}" "${field}" <<'PY'
import json
import pathlib
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
for part in sys.argv[2].split("."):
    if not isinstance(value, dict) or part not in value:
        raise SystemExit(f"missing JSON field: {sys.argv[2]}")
    value = value[part]
if isinstance(value, bool):
    print("true" if value else "false")
elif value is None:
    print("null")
elif isinstance(value, (str, int, float)):
    print(value)
else:
    raise SystemExit(f"JSON field is not scalar: {sys.argv[2]}")
PY
}

expect_json() {
  local path="$1"
  local field="$2"
  local expected="$3"
  local actual

  actual="$(json_get "${path}" "${field}")"
  [[ "${actual}" == "${expected}" ]] ||
    die "${path##*/} field ${field}=${actual@Q}, want ${expected@Q}"
}

expect_json_absent() {
  local path="$1"
  local field="$2"

  python3 - "${path}" "${field}" <<'PY'
import json
import pathlib
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
for part in sys.argv[2].split("."):
    if not isinstance(value, dict) or part not in value:
        raise SystemExit(0)
    value = value[part]
raise SystemExit(f"unexpected JSON field: {sys.argv[2]}")
PY
}

wait_for_systemd() {
  local attempt state=""
  local target="${1:-${container_name}}"

  for attempt in {1..120}; do
    state="$(docker exec "${target}" systemctl is-system-running 2>/dev/null || true)"
    if [[ "${state}" == "running" ]]; then
      return
    fi
    # A restartable base-image unit may briefly make systemd report degraded
    # while boot jobs are still converging. Do not mistake that transient for
    # readiness, but also do not fail before the bounded boot window expires.
    case "${state}" in
      ""|initializing|starting|degraded) ;;
      *) die "isolated systemd reached unexpected state ${state@Q}" ;;
    esac
    sleep 0.25
  done
  docker exec "${target}" systemctl --failed --no-legend --plain >&2 || true
  die "isolated systemd did not reach running state (last state ${state@Q})"
}

build_release() {
  local sequence="$1"
  local version="$2"
  local commit="$3"
  local source_epoch="$4"
  local destination="$5"
	local root_path="$6"
	local signer_a="$7"
	local signer_b="$8"
	shift 8
	local build_time identity
  local meshctl_path mesh_install_path bundle_path
  local -a package_args

  mkdir -p -- "${destination}"
  chmod 0700 "${destination}"
  build_time="$(date -u -d "@${source_epoch}" '+%Y-%m-%dT%H:%M:%SZ')"
  identity="$("${work_dir}/tools/mesh-release" build-identity \
    --version "${version}" \
    --commit "${commit}" \
    --build-time "${build_time}" \
    --security-floor "${security_floor}" \
    --agent-state-read-min 2 \
    --agent-state-read-max 2 \
    --agent-state-write-version 2)"
  [[ "${identity}" != *[[:space:]]* ]] || die "build identity was not a single canonical frame"

  meshctl_path="${destination}/meshctl"
  mesh_install_path="${destination}/mesh-install"
  bundle_path="${destination}/mesh-linux-bundle.tar"

  CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build \
    -trimpath -buildvcs=false \
    "-ldflags=-s -w -buildid= -X mesh/internal/buildinfo.Identity=${identity}" \
    -o "${meshctl_path}" ./cmd/meshctl
  CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build \
    -trimpath -buildvcs=false \
    "-ldflags=-s -w -buildid= -X mesh/internal/buildinfo.Identity=${identity} -X mesh/internal/installtrust.Identity=${installer_policy}" \
    -o "${mesh_install_path}" ./cmd/mesh-install

  package_args=(build-linux \
    --version "${version}" \
    --commit "${commit}" \
    --source-date-epoch "${source_epoch}" \
    --security-floor "${security_floor}" \
    --arch "${arch}" \
    --mesh-install "${mesh_install_path}" \
    --meshctl "${meshctl_path}" \
    --nebula-dir "${nebula_dir}")
  "${work_dir}/tools/mesh-package" "${package_args[@]}" \
    --output "${bundle_path}" >/dev/null
  if [[ "${sequence}" == "1" ]]; then
    "${work_dir}/tools/mesh-package" "${package_args[@]}" \
      --output "${destination}/mesh-linux-bundle.repro.tar" >/dev/null
    cmp --silent -- "${bundle_path}" "${destination}/mesh-linux-bundle.repro.tar" ||
      die "identical release inputs did not produce the same Linux bundle bytes"
    rm -f -- "${destination}/mesh-linux-bundle.repro.tar"
  fi

  "${work_dir}/tools/mesh-release" create-release-manifest \
    --output "${destination}/release.json" \
		--root "${root_path}" \
    --version "${version}" \
    --sequence "${sequence}" \
    --security-floor "${security_floor}" \
    --issued "${issued_at}" \
    --expires "${expires_at}" \
    --os linux \
    --arch "${arch}" \
    --artifact-url "${release_base_url}/releases/${version}/mesh-linux-bundle.tar" \
    --test-only-allow-unscanned-linux-artifact \
    --artifact "${bundle_path}" >/dev/null
  "${work_dir}/tools/mesh-release" create-channel-manifest \
    --output "${destination}/channel.json" \
		--root "${root_path}" \
    --release-manifest "${destination}/release.json" \
    --manifest-url "${release_base_url}/releases/${version}/release.json" \
    --issued "${issued_at}" \
    --expires "${expires_at}" >/dev/null

  "${work_dir}/tools/mesh-release" sign \
		--private "${signer_a}" \
    --manifest "${destination}/release.json" \
    --signature "${destination}/release.signer-a.json" >/dev/null
  "${work_dir}/tools/mesh-release" sign \
		--private "${signer_b}" \
    --manifest "${destination}/release.json" \
    --signature "${destination}/release.signer-b.json" >/dev/null
  "${work_dir}/tools/mesh-release" sign \
		--private "${signer_a}" \
    --manifest "${destination}/channel.json" \
    --signature "${destination}/channel.signer-a.json" >/dev/null
  "${work_dir}/tools/mesh-release" sign \
		--private "${signer_b}" \
    --manifest "${destination}/channel.json" \
    --signature "${destination}/channel.signer-b.json" >/dev/null

	local -a online_args=(assemble-online-bundle
		--output "${destination}/online-bundle.json"
		--channel-manifest "${destination}/channel.json"
		--channel-signature "${destination}/channel.signer-a.json"
		--channel-signature "${destination}/channel.signer-b.json"
		--release-manifest "${destination}/release.json"
		--release-signature "${destination}/release.signer-a.json"
		--release-signature "${destination}/release.signer-b.json")
	local root_update
	for root_update in "$@"; do
		cp -- "${root_update}" "${destination}/$(basename -- "${root_update}")"
		online_args+=(--root-update "${root_update}")
	done
	"${work_dir}/tools/mesh-release" "${online_args[@]}" >/dev/null
}

assemble_root_transition() {
	local previous_root="$1"
	local next_root="$2"
	local output="$3"
	shift 3
	local -a assemble_args=(assemble-root-update
		--output "${output}"
		--previous-root "${previous_root}"
		--root "${next_root}")
	local signer signature index=0
	for signer in "$@"; do
		index=$((index + 1))
		signature="${output%.json}.signer-${index}.json"
		"${work_dir}/tools/mesh-release" sign \
			--private "${signer}" --manifest "${next_root}" --signature "${signature}" >/dev/null
		assemble_args+=(--signature "${signature}")
	done
	"${work_dir}/tools/mesh-release" "${assemble_args[@]}" >/dev/null
}

build_fixture_bundle() {
  local name="$1"
  local artifact_url="$2"
  local artifact_size="$3"
  local artifact_sha="$4"
  local fixture_issued="$5"
  local fixture_expires="$6"
  local signature_count="$7"
  local destination="${work_dir}/fixtures/${name}"
  local -a assemble_args

  mkdir -p -- "${destination}"
  chmod 0700 "${destination}"
  python3 - \
    "${work_dir}/releases/one/release.json" \
    "${work_dir}/releases/one/channel.json" \
    "${destination}/release.json" \
    "${destination}/channel.json" \
    "${artifact_url}" "${artifact_size}" "${artifact_sha}" \
    "${fixture_issued}" "${fixture_expires}" \
    "${release_base_url}/fixtures/${name}/release.json" <<'PY'
import hashlib
import json
import pathlib
import sys

base_release, base_channel, release_path, channel_path = map(pathlib.Path, sys.argv[1:5])
artifact_url, artifact_size, artifact_sha, issued, expires, manifest_url = sys.argv[5:]
release = json.loads(base_release.read_text(encoding='utf-8'))
release['issued_at'] = issued
release['expires_at'] = expires
release['artifacts'][0]['url'] = artifact_url
release['artifacts'][0]['size'] = int(artifact_size)
release['artifacts'][0]['sha256'] = artifact_sha
release_raw = (json.dumps(release, separators=(',', ':'), ensure_ascii=False) + '\n').encode()
release_path.write_bytes(release_raw)

channel = json.loads(base_channel.read_text(encoding='utf-8'))
channel['issued_at'] = issued
channel['expires_at'] = expires
channel['release']['manifest_url'] = manifest_url
channel['release']['manifest_size'] = len(release_raw)
channel['release']['manifest_sha256'] = hashlib.sha256(release_raw).hexdigest()
channel_path.write_bytes((json.dumps(channel, separators=(',', ':'), ensure_ascii=False) + '\n').encode())
PY

  "${work_dir}/tools/mesh-release" sign \
    --private "${work_dir}/signing/signer-a.private.json" \
    --manifest "${destination}/release.json" \
    --signature "${destination}/release.signer-a.json" >/dev/null
  "${work_dir}/tools/mesh-release" sign \
    --private "${work_dir}/signing/signer-a.private.json" \
    --manifest "${destination}/channel.json" \
    --signature "${destination}/channel.signer-a.json" >/dev/null
  assemble_args=(assemble-online-bundle
    --output "${destination}/online-bundle.json"
    --channel-manifest "${destination}/channel.json"
    --channel-signature "${destination}/channel.signer-a.json"
    --release-manifest "${destination}/release.json"
    --release-signature "${destination}/release.signer-a.json")
  if [[ "${signature_count}" == "2" ]]; then
    "${work_dir}/tools/mesh-release" sign \
      --private "${work_dir}/signing/signer-b.private.json" \
      --manifest "${destination}/release.json" \
      --signature "${destination}/release.signer-b.json" >/dev/null
    "${work_dir}/tools/mesh-release" sign \
      --private "${work_dir}/signing/signer-b.private.json" \
      --manifest "${destination}/channel.json" \
      --signature "${destination}/channel.signer-b.json" >/dev/null
    assemble_args+=(
      --channel-signature "${destination}/channel.signer-b.json"
      --release-signature "${destination}/release.signer-b.json")
  fi
  "${work_dir}/tools/mesh-release" "${assemble_args[@]}" >/dev/null
}

copy_and_assemble_snapshot() {
  local number="$1"
  local release_dir="$2"
  local input_dir="/root/mesh-proof/input-${number}"
  local snapshot_dir="/root/mesh-proof/snapshot-${number}"

  docker exec "${container_name}" mkdir -p -- "${input_dir}"
  docker exec "${container_name}" chmod 0700 "${input_dir}"
  docker cp "${release_dir}/." "${container_name}:${input_dir}/" >/dev/null
  docker exec "${container_name}" chown -R root:root "${input_dir}"
	local -a snapshot_args=(/root/mesh-proof/tools/mesh-release assemble-snapshot
		--output "${snapshot_dir}"
		--channel-manifest "${input_dir}/channel.json"
		--channel-signature "${input_dir}/channel.signer-a.json"
		--channel-signature "${input_dir}/channel.signer-b.json"
		--release-manifest "${input_dir}/release.json"
		--release-signature "${input_dir}/release.signer-a.json"
		--release-signature "${input_dir}/release.signer-b.json"
		--artifact "${input_dir}/mesh-linux-bundle.tar")
	local update_path
	while IFS= read -r update_path; do
		snapshot_args+=(--root-update "${input_dir}/$(basename -- "${update_path}")")
	done < <(find "${release_dir}" -maxdepth 1 -type f -name 'root-update-*.json' -print | sort)
	docker exec "${container_name}" "${snapshot_args[@]}" >/dev/null
  docker exec -i "${container_name}" bash -s -- "${snapshot_dir}" <<'CONTAINER'
set -Eeuo pipefail
snapshot="$1"
[[ "$(stat -c '%U:%G:%a' -- "${snapshot}")" == "root:root:700" ]]
python3 - "${snapshot}/install.json" <<'PY'
import json, pathlib, sys
descriptor = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert descriptor['schema'] == 'mesh-linux-install-snapshot-v2'
assert descriptor['root_updates'] == [f'root-update-{i:03d}.json' for i in range(len(descriptor['root_updates']))]
PY
count=0
while IFS= read -r -d '' path; do
  [[ "$(stat -c '%U:%G:%a' -- "${path}")" == "root:root:400" ]]
  count=$((count + 1))
done < <(find "${snapshot}" -mindepth 1 -maxdepth 1 -type f -print0)
root_count="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["root_updates"]))' "${snapshot}/install.json")"
[[ "${count}" == "$((8 + root_count))" ]]
[[ -z "$(find "${snapshot}" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" ]]
CONTAINER
}

publish_online_release() {
  local version="$1"
  local release_dir="$2"
  local destination="/root/mesh-proof/repository/releases/${version}"

  docker exec "${container_name}" mkdir -p -- "${destination}"
  docker exec "${container_name}" chmod 0755 "${destination}"
  # The artifact must become readable before metadata capable of selecting it.
  docker cp "${release_dir}/mesh-linux-bundle.tar" "${container_name}:${destination}/mesh-linux-bundle.tar" >/dev/null
  docker exec "${container_name}" chmod 0444 "${destination}/mesh-linux-bundle.tar"
  docker cp "${release_dir}/release.json" "${container_name}:${destination}/release.json" >/dev/null
  docker exec "${container_name}" chmod 0444 "${destination}/release.json"
  docker cp "${release_dir}/online-bundle.json" "${container_name}:${destination}/online-bundle.json" >/dev/null
  docker exec "${container_name}" chmod 0444 "${destination}/online-bundle.json"
}

publish_online_fixture() {
  local name="$1"
  local source="${work_dir}/fixtures/${name}"
  local destination="/root/mesh-proof/repository/fixtures/${name}"

  docker exec "${container_name}" mkdir -p -- "${destination}"
  docker exec "${container_name}" chmod 0755 "${destination}"
  docker cp "${source}/release.json" "${container_name}:${destination}/release.json" >/dev/null
  docker cp "${source}/online-bundle.json" "${container_name}:${destination}/bundle.json" >/dev/null
  docker exec "${container_name}" chmod 0444 "${destination}/release.json" "${destination}/bundle.json"
}

publish_stable_bundle() {
  local version="$1"
  docker exec "${container_name}" mkdir -p /root/mesh-proof/repository/channels/stable
  docker exec "${container_name}" cp -- \
    "/root/mesh-proof/repository/releases/${version}/online-bundle.json" \
    /root/mesh-proof/repository/channels/stable/bundle.json
  docker exec "${container_name}" chmod 0444 /root/mesh-proof/repository/channels/stable/bundle.json
}

assert_no_pending_online_intake() {
  docker exec -i "${container_name}" bash -s <<'CONTAINER'
set -Eeuo pipefail
intake=/var/lib/mesh-installer/online-intake
if [[ -e "${intake}" ]]; then
  [[ "$(stat -c '%U:%G:%a' -- "${intake}")" == "root:root:700" ]]
  [[ -z "$(find "${intake}" -mindepth 1 -maxdepth 1 ! -name online.lock -print -quit)" ]]
  if [[ -e "${intake}/online.lock" ]]; then
    [[ "$(stat -c '%U:%G:%a' -- "${intake}/online.lock")" == "root:root:600" ]]
  fi
fi
CONTAINER
}

assert_pristine_install_boundary() {
  docker exec -i "${container_name}" bash -s <<'CONTAINER'
set -Eeuo pipefail
[[ ! -e /var/lib/mesh-installer/state.json ]]
[[ ! -e /opt/mesh/current ]]
[[ ! -e /usr/local/lib/systemd/system/mesh-agent.service ]]
[[ ! -e /usr/local/lib/systemd/system/mesh-nebula.service ]]
[[ ! -e /var/lib/mesh-installer/runtime.enabled ]]
[[ ! -e /etc/systemd/system/multi-user.target.wants/mesh-agent.service ]]
[[ "$(systemctl is-active mesh-agent.service 2>/dev/null || true)" != "active" ]]
[[ "$(systemctl is-active mesh-nebula.service 2>/dev/null || true)" != "active" ]]
CONTAINER
  assert_no_pending_online_intake
}

expect_online_failure() {
  local label="$1"
  local url="$2"
  local installer="${3:-/root/mesh-proof/bootstrap/mesh-install}"

  if docker exec "${container_name}" "${installer}" install-online "${url}" \
    >"${work_dir}/${label}.stdout" 2>"${work_dir}/${label}.stderr"; then
    die "online negative fixture unexpectedly succeeded: ${label}"
  fi
}

capture_installed_fingerprint() {
  local output="$1"
  docker exec -i "${container_name}" bash -s >"${output}" <<'CONTAINER'
set -Eeuo pipefail
sha256sum /var/lib/mesh-installer/state.json \
  /usr/local/lib/systemd/system/mesh-agent.service \
  /usr/local/lib/systemd/system/mesh-nebula.service \
  /usr/local/lib/systemd/system/mesh-agent.service.d/10-timeout-abort.conf \
  /usr/local/lib/systemd/system/mesh-nebula.service.d/10-timeout-abort.conf
readlink -- /opt/mesh/current
printf 'gate=%s\n' "$(test -e /var/lib/mesh-installer/runtime.enabled && echo present || echo absent)"
printf 'enabled=%s\n' "$(systemctl is-enabled mesh-agent.service 2>/dev/null || true)"
printf 'agent=%s:%s\n' "$(systemctl is-active mesh-agent.service 2>/dev/null || true)" "$(systemctl show mesh-agent.service -p MainPID --value)"
printf 'nebula=%s:%s\n' "$(systemctl is-active mesh-nebula.service 2>/dev/null || true)" "$(systemctl show mesh-nebula.service -p MainPID --value)"
CONTAINER
}

start_blocked_online_install() {
  local version="$1"
  local label="$2"
  local installer="${3:-/root/mesh-proof/bootstrap/mesh-install}"
  local url="${release_base_url}/releases/${version}/online-bundle.json"

  docker exec "${container_name}" rm -f -- \
    "/root/mesh-proof/semaphores/block-${version}.started" \
    "/root/mesh-proof/semaphores/block-${version}.release"
  docker exec "${container_name}" touch "/root/mesh-proof/semaphores/block-${version}.enabled"
  docker exec -i "${container_name}" bash -s -- "${installer}" "${url}" "${label}" <<'CONTAINER'
set -Eeuo pipefail
installer="$1"
url="$2"
label="$3"
(
  set +e
  "${installer}" install-online "${url}" \
    >"/root/mesh-proof/${label}.stdout" \
    2>"/root/mesh-proof/${label}.stderr" </dev/null
  status=$?
  printf '%s\n' "${status}" >"/root/mesh-proof/${label}.status"
  exit "${status}"
) &
printf '%s\n' "$!" >"/root/mesh-proof/${label}.pid"
CONTAINER
  for attempt in {1..300}; do
    if docker exec "${container_name}" test -e "/root/mesh-proof/semaphores/block-${version}.started"; then
      return
    fi
    if docker exec "${container_name}" test -e "/root/mesh-proof/${label}.status"; then
      docker exec "${container_name}" sh -c \
        "printf 'blocked status: '; cat '/root/mesh-proof/${label}.status'; cat '/root/mesh-proof/${label}.stderr'" >&2 || true
      docker exec "${container_name}" systemctl status --no-pager mesh-proof-https.service >&2 || true
      die "blocked online install exited before reaching the artifact response: ${label}"
    fi
    if [[ "${attempt}" == "300" ]]; then
      docker exec "${container_name}" sh -c \
        "cat '/root/mesh-proof/${label}.stderr'; ps -o pid,ppid,stat,comm,args -p \$(cat '/root/mesh-proof/${label}.pid') --ppid \$(cat '/root/mesh-proof/${label}.pid')" >&2 || true
      docker exec "${container_name}" systemctl status --no-pager mesh-proof-https.service >&2 || true
      die "blocked online install did not reach the artifact response: ${label}"
    fi
    sleep 0.1
  done
}

stop_blocked_online_install() {
  local version="$1"
  local label="$2"
  local signal="$3"
  local pid target_pid

  pid="$(docker exec "${container_name}" cat "/root/mesh-proof/${label}.pid")"
  [[ "${pid}" =~ ^[0-9]+$ && "${pid}" -gt 1 ]] || die "blocked install PID is invalid: ${label}"
  target_pid="$(docker exec "${container_name}" pgrep -P "${pid}" -x mesh-install || true)"
  [[ "${target_pid}" =~ ^[0-9]+$ && "${target_pid}" -gt 1 ]] || die "blocked mesh-install child PID is invalid: ${label}"
  docker exec "${container_name}" kill "-${signal}" "${target_pid}"
  for attempt in {1..120}; do
    if ! docker exec "${container_name}" kill -0 "${target_pid}" 2>/dev/null; then
      break
    fi
    if [[ "${attempt}" == "120" ]]; then
      die "blocked online install survived ${signal}: ${label}"
    fi
    sleep 0.1
  done
  docker exec "${container_name}" touch "/root/mesh-proof/semaphores/block-${version}.release"
  docker exec "${container_name}" rm -f -- "/root/mesh-proof/semaphores/block-${version}.enabled"
}

release_blocked_online_install() {
  local version="$1"
  local label="$2"
  local expected_status="$3"
  local status=""

  docker exec "${container_name}" touch "/root/mesh-proof/semaphores/block-${version}.release"
  docker exec "${container_name}" rm -f -- "/root/mesh-proof/semaphores/block-${version}.enabled"
  for attempt in {1..300}; do
    if docker exec "${container_name}" test -f "/root/mesh-proof/${label}.status"; then
      status="$(docker exec "${container_name}" cat "/root/mesh-proof/${label}.status")"
      break
    fi
    if [[ "${attempt}" == "300" ]]; then
      die "released online install did not finish: ${label}"
    fi
    sleep 0.1
  done
  [[ "${status}" == "${expected_status}" ]] || {
    docker exec "${container_name}" cat "/root/mesh-proof/${label}.stderr" >&2 || true
    die "released online install ${label} exited ${status@Q}, want ${expected_status}"
  }
  docker cp "${container_name}:/root/mesh-proof/${label}.stdout" "${work_dir}/${label}.json" >/dev/null
}

assert_exact_units() {
  docker exec -i "${container_name}" bash -s -- \
    "${agent_unit_sha}" "${nebula_unit_sha}" "${timeout_abort_mask_sha}" <<'CONTAINER'
set -Eeuo pipefail
agent_sha="$1"
nebula_sha="$2"
mask_sha="$3"
agent=/usr/local/lib/systemd/system/mesh-agent.service
nebula=/usr/local/lib/systemd/system/mesh-nebula.service
agent_mask=/usr/local/lib/systemd/system/mesh-agent.service.d/10-timeout-abort.conf
nebula_mask=/usr/local/lib/systemd/system/mesh-nebula.service.d/10-timeout-abort.conf
[[ "$(stat -c '%U:%G:%a' -- "${agent}")" == "root:root:444" ]]
[[ "$(stat -c '%U:%G:%a' -- "${nebula}")" == "root:root:444" ]]
[[ "$(stat -c '%U:%G:%a' -- "${agent_mask}")" == "root:root:444" ]]
[[ "$(stat -c '%U:%G:%a' -- "${nebula_mask}")" == "root:root:444" ]]
[[ "$(sha256sum -- "${agent}" | awk '{print $1}')" == "${agent_sha}" ]]
[[ "$(sha256sum -- "${nebula}" | awk '{print $1}')" == "${nebula_sha}" ]]
[[ "$(sha256sum -- "${agent_mask}" | awk '{print $1}')" == "${mask_sha}" ]]
[[ "$(sha256sum -- "${nebula_mask}" | awk '{print $1}')" == "${mask_sha}" ]]
[[ "$(systemctl show mesh-agent.service --property=FragmentPath --value)" == "${agent}" ]]
[[ "$(systemctl show mesh-nebula.service --property=FragmentPath --value)" == "${nebula}" ]]
[[ "$(systemctl show mesh-agent.service --property=DropInPaths --value)" == "${agent_mask}" ]]
[[ "$(systemctl show mesh-nebula.service --property=DropInPaths --value)" == "${nebula_mask}" ]]
[[ "$(systemctl show mesh-agent.service --property=TimeoutStopFailureMode --value)" == "terminate" ]]
[[ "$(systemctl show mesh-nebula.service --property=TimeoutStopFailureMode --value)" == "terminate" ]]
CONTAINER
}

assert_stopped_install() {
  local installed_id="$1"

  assert_exact_units
  docker exec -i "${container_name}" bash -s -- "${installed_id}" <<'CONTAINER'
set -Eeuo pipefail
installed_id="$1"
[[ "$(readlink -- /opt/mesh/current)" == "releases/${installed_id}" ]]
[[ "$(systemctl is-enabled mesh-agent.service 2>/dev/null || true)" == "disabled" ]]
[[ "$(systemctl is-enabled mesh-nebula.service 2>/dev/null || true)" == "static" ]]
[[ "$(systemctl is-active mesh-agent.service 2>/dev/null || true)" == "inactive" ]]
[[ "$(systemctl is-active mesh-nebula.service 2>/dev/null || true)" == "inactive" ]]
[[ "$(systemctl show mesh-agent.service --property=MainPID --value)" == "0" ]]
[[ "$(systemctl show mesh-nebula.service --property=MainPID --value)" == "0" ]]
[[ ! -e /var/lib/mesh-installer/runtime.enabled ]]
[[ ! -e /run/mesh-agent ]]
[[ ! -e /run/mesh-nebula ]]
[[ ! -e /etc/systemd/system/multi-user.target.wants/mesh-agent.service ]]
CONTAINER
}

assert_active_install() {
  local installed_id="$1"
  local version="$2"

  assert_exact_units
  docker exec -i "${container_name}" bash -s -- "${installed_id}" <<'CONTAINER'
set -Eeuo pipefail
installed_id="$1"
release="/opt/mesh/releases/${installed_id}"
[[ "$(readlink -- /opt/mesh/current)" == "releases/${installed_id}" ]]
systemctl is-enabled --quiet mesh-agent.service
systemctl is-active --quiet mesh-agent.service
systemctl is-active --quiet mesh-nebula.service
[[ "$(systemctl is-enabled mesh-nebula.service 2>/dev/null || true)" == "static" ]]
[[ "$(readlink -- /etc/systemd/system/multi-user.target.wants/mesh-agent.service)" == "/usr/local/lib/systemd/system/mesh-agent.service" ]]
[[ -z "$(find /etc/systemd/system -type l -lname '*mesh-nebula.service' -print -quit)" ]]
[[ "$(stat -c '%U:%G:%a' -- /var/lib/mesh-installer/runtime.enabled)" == "root:root:400" ]]
[[ "$(cat /var/lib/mesh-installer/runtime.enabled)" == "mesh-runtime-enabled-v1" ]]
[[ "$(stat -c '%U:%G:%a' -- /run/mesh-agent)" == "root:root:700" ]]
[[ "$(stat -c '%U:%G:%a' -- /run/mesh-agent/nebula.validated)" == "root:root:400" ]]
[[ "$(cat /run/mesh-agent/nebula.validated)" == "mesh-nebula-validated-v1" ]]
for attempt in {1..40}; do
  [[ -S /run/mesh-nebula/runtime-observer.sock ]] && break
  sleep 0.25
done
[[ -S /run/mesh-nebula/runtime-observer.sock ]]
[[ "$(stat -c '%U:%G:%a' -- /run/mesh-nebula)" == "root:root:700" ]]
[[ "$(stat -c '%U:%G:%a' -- /run/mesh-nebula/runtime-observer.sock)" == "root:root:600" ]]
agent_pid="$(systemctl show mesh-agent.service --property=MainPID --value)"
nebula_pid="$(systemctl show mesh-nebula.service --property=MainPID --value)"
[[ "${agent_pid}" =~ ^[0-9]+$ && "${agent_pid}" -gt 1 ]]
[[ "${nebula_pid}" =~ ^[0-9]+$ && "${nebula_pid}" -gt 1 ]]
[[ "$(sed -n 's/^CapEff:[[:space:]]*//p' "/proc/${agent_pid}/status")" == "0000000000000000" ]]
[[ "$(sed -n 's/^CapBnd:[[:space:]]*//p' "/proc/${agent_pid}/status")" == "0000000000000000" ]]
[[ "$(readlink -e -- "/proc/${agent_pid}/exe")" == "${release}/bin/meshctl" ]]
[[ "$(readlink -e -- "/proc/${nebula_pid}/exe")" == "${release}/bin/nebula" ]]
probe_journal=/var/lib/mesh-agent/state.json.runtime-probe.json
if [[ -e "${probe_journal}" ]]; then
  [[ -f "${probe_journal}" && ! -L "${probe_journal}" ]]
  [[ "$(stat -c '%U:%G:%a' -- "${probe_journal}")" == "root:root:600" ]]
fi
CONTAINER

  docker exec "${container_name}" /usr/local/bin/meshctl version --json >"${work_dir}/current-meshctl-version.json"
  docker exec "${container_name}" /usr/local/bin/mesh-install version >"${work_dir}/current-mesh-install-version.json"
  expect_json "${work_dir}/current-meshctl-version.json" version "${version}"
  expect_json "${work_dir}/current-mesh-install-version.json" version "${version}"
}

assert_active_result() {
  local path="$1"
  local installed_id="$2"
  local operation="$3"

  expect_json "${path}" operation "${operation}"
  expect_json "${path}" release.installed_id "${installed_id}"
  expect_json "${path}" agent_enabled true
  expect_json "${path}" agent_active true
  expect_json "${path}" nebula_active true
  expect_json "${path}" runtime_gate_open true
}

capture_and_assert_state() {
  local label="$1"
  local active_id="$2"
  local previous_id="$3"
  local high_water_id="$4"
  local high_water_sequence="$5"
	local release_epoch="${6:-1}"
	local root_version="${7:-1}"
  local path="${work_dir}/state-${label}.json"

  docker exec "${container_name}" cat /var/lib/mesh-installer/state.json >"${path}"
	expect_json "${path}" schema mesh-linux-install-state-v3
  expect_json "${path}" channel "${channel}"
  expect_json "${path}" active.installed_id "${active_id}"
  expect_json "${path}" high_water.installed_id "${high_water_id}"
	expect_json "${path}" high_water.sequence "${high_water_sequence}"
	expect_json "${path}" high_water.release_epoch "${release_epoch}"
	expect_json "${path}" high_water.trusted_root_version "${root_version}"
  expect_json_absent "${path}" pending
  if [[ -n "${previous_id}" ]]; then
    expect_json "${path}" previous.installed_id "${previous_id}"
  else
    expect_json_absent "${path}" previous
  fi
}

case "${ui_guided_package_smoke}" in
  0 | 1) ;;
  *) die "MESH_UI_GUIDED_PACKAGE_SMOKE must be exactly 0 or 1" ;;
esac

for command in bash cmp curl date docker git go mktemp openssl python3 rg sha256sum sleep; do
  need_command "${command}"
done
if [[ "${ui_guided_package_smoke}" == "1" ]]; then
  for command in firefox geckodriver; do
    need_command "${command}"
  done
  [[ -f "${repo_root}/scripts/ui_guided_author.py" && ! -L "${repo_root}/scripts/ui_guided_author.py" ]] ||
    die "UI-guided browser author is unavailable or linked"
fi
[[ "$(go env GOOS)" == "linux" && "$(go env GOARCH)" == "${arch}" ]] ||
  skip "this proof currently requires a linux/amd64 build host"
date -u -d '+1 day' '+%Y-%m-%dT%H:%M:%SZ' >/dev/null 2>&1 ||
  skip "GNU date with relative UTC time support is required"

temp_parent="${TMPDIR:-/tmp}"
[[ -d "${temp_parent}" ]] || skip "temporary directory parent does not exist: ${temp_parent}"
work_dir="$(mktemp -d "${temp_parent%/}/mesh-install-smoke.XXXXXX")"
[[ -d "${work_dir}" && ! -L "${work_dir}" ]] || die "mktemp did not create a real private directory"
chmod 0700 "${work_dir}"
run_id="${work_dir##*.}"
run_id="${run_id,,}"
[[ "${run_id}" =~ ^[a-z0-9]+$ ]] || die "mktemp returned a noncanonical proof identifier"
container_name="mesh-install-smoke-${run_id}"
offline_container_name="mesh-install-smoke-${run_id}-offline"
ui_lighthouse_container_name="mesh-install-smoke-${run_id}-ui-lighthouse"
ui_member_container_name="mesh-install-smoke-${run_id}-ui-member"
proof_network_name="mesh-install-smoke-${run_id}-network"

docker info >/dev/null 2>&1 || skip "Docker daemon is unavailable to the current user"
if [[ "${ui_guided_package_smoke}" == "1" ]]; then
  docker network create \
    --label "mesh.install-smoke.id=${run_id}-network" \
    "${proof_network_name}" >/dev/null
  proof_network_started=1
  proof_subnet="$(docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' "${proof_network_name}")"
  read -r proof_control_ip proof_lighthouse_ip proof_member_ip < <(
    python3 - "${proof_subnet}" <<'PY'
import ipaddress
import sys

try:
    network = ipaddress.ip_network(sys.argv[1], strict=True)
except ValueError as error:
    raise SystemExit(f"Docker returned an invalid proof subnet: {error}")
private = tuple(ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
if network.version != 4 or network.num_addresses < 32 or not any(network.subnet_of(parent) for parent in private):
    raise SystemExit("Docker proof subnet is not a bounded RFC1918 IPv4 network")
print(network[10], network[11], network[12])
PY
  )
  [[ "${proof_control_ip}" =~ ^[0-9.]+$ && "${proof_lighthouse_ip}" =~ ^[0-9.]+$ && "${proof_member_ip}" =~ ^[0-9.]+$ ]] ||
    die "could not derive canonical proof host addresses"
  release_base_url="https://${proof_control_ip}:18443"
fi

mkdir -p -- "${work_dir}/tls"
chmod 0700 "${work_dir}/tls"
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
  -subj '/CN=Mesh install smoke CA' \
  -keyout "${work_dir}/tls/ca.key" \
  -out "${work_dir}/tls/ca.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -sha256 \
  -subj '/CN=127.0.0.1' \
  -keyout "${work_dir}/tls/server.key" \
  -out "${work_dir}/tls/server.csr" >/dev/null 2>&1
openssl x509 -req -sha256 -days 2 \
  -in "${work_dir}/tls/server.csr" \
  -CA "${work_dir}/tls/ca.crt" \
  -CAkey "${work_dir}/tls/ca.key" \
  -CAcreateserial \
  -extfile <(
    if [[ "${ui_guided_package_smoke}" == "1" ]]; then
      printf 'subjectAltName=IP:127.0.0.1,IP:%s\n' "${proof_control_ip}"
    else
      printf 'subjectAltName=IP:127.0.0.1\n'
    fi
    printf 'keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n'
  ) \
  -out "${work_dir}/tls/server.crt" >/dev/null 2>&1
rm -f -- "${work_dir}/tls/server.csr" "${work_dir}/tls/ca.srl"
chmod 0400 "${work_dir}/tls/ca.key" "${work_dir}/tls/ca.crt" \
  "${work_dir}/tls/server.key" "${work_dir}/tls/server.crt"
openssl verify -CAfile "${work_dir}/tls/ca.crt" "${work_dir}/tls/server.crt" >/dev/null
openssl x509 -in "${work_dir}/tls/server.crt" -noout -checkip 127.0.0.1 >/dev/null
if [[ "${ui_guided_package_smoke}" == "1" ]]; then
  openssl x509 -in "${work_dir}/tls/server.crt" -noout -checkip "${proof_control_ip}" >/dev/null
fi
proof_image_observed="$(docker image inspect --format '{{index .Config.Labels "io.mesh.systemd-proof"}}' "${proof_image}" 2>/dev/null || true)"
if [[ "${proof_image_observed}" != "${proof_image_identity}" ]]; then
  if [[ -n "${MESH_SYSTEMD_PROOF_IMAGE:-}" ]]; then
    skip "caller-selected systemd proof image is unavailable or has the wrong identity: ${proof_image}"
  fi
  say "Building the pinned Fedora 42 systemd proof image"
  mkdir -p -- "${work_dir}/docker-config"
  chmod 0700 "${work_dir}/docker-config"
  DOCKER_CONFIG="${work_dir}/docker-config" docker build \
    --file "${repo_root}/packaging/systemd/proof-fedora42.Dockerfile" \
    --tag "${proof_image}" \
    "${repo_root}/packaging/systemd" >/dev/null
  proof_image_observed="$(docker image inspect --format '{{index .Config.Labels "io.mesh.systemd-proof"}}' "${proof_image}" 2>/dev/null || true)"
  [[ "${proof_image_observed}" == "${proof_image_identity}" ]] ||
    die "built systemd proof image has identity ${proof_image_observed@Q}, want ${proof_image_identity@Q}"
fi
# systemd needs several root-owned inotify instances during early boot. Probe a
# conservative reserve in a separate exact container and skip without changing
# host sysctls when another workload has exhausted the per-UID kernel quota.
if ! docker run --rm \
  --name "mesh-install-smoke-${run_id}-inotify-probe" \
  --label "mesh.install-smoke.id=${run_id}-inotify-probe" \
  --security-opt label=disable \
  "${proof_image}" python3 -c '
import ctypes
import errno
import os
import sys

libc = ctypes.CDLL(None, use_errno=True)
descriptors = []
for _ in range(32):
    descriptor = libc.inotify_init1(os.O_CLOEXEC)
    if descriptor < 0:
        value = ctypes.get_errno()
        print(f"inotify reserve unavailable: {errno.errorcode.get(value, value)}", file=sys.stderr)
        raise SystemExit(1)
    descriptors.append(descriptor)
for descriptor in descriptors:
    os.close(descriptor)
' >/dev/null; then
  skip "root inotify-instance quota cannot reserve 32 slots for the isolated systemd fixture; host sysctls were not changed"
fi
mkdir -p -- "${work_dir}/tools" "${work_dir}/signing" "${work_dir}/releases"
chmod 0700 "${work_dir}/tools" "${work_dir}/signing" "${work_dir}/releases"

say "Building offline release, package, server, and production node binaries"
CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build -trimpath -buildvcs=false \
  -o "${work_dir}/tools/mesh-release" ./cmd/mesh-release
CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build -trimpath -buildvcs=false \
  -o "${work_dir}/tools/mesh-bootstrap-verify" ./cmd/mesh-bootstrap-verify
CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build -trimpath -buildvcs=false \
  -o "${work_dir}/tools/mesh-package" ./cmd/mesh-package
CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build -trimpath -buildvcs=false \
  -o "${work_dir}/tools/mesh-server" ./cmd/mesh-server

if [[ -z "${nebula_dir}" ]]; then
  say "Reproducibly building and authenticating the observer-enabled Nebula dependency"
  CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build -trimpath -buildvcs=false \
    -o "${work_dir}/tools/mesh-deps" ./cmd/mesh-deps
  mkdir -p -- "${work_dir}/dependencies"
  chmod 0700 "${work_dir}/dependencies"
  nebula_dir="${work_dir}/dependencies/nebula-observer-v1.10.3-linux-${arch}"
  "${work_dir}/tools/mesh-deps" build-nebula-observer \
    --arch "${arch}" \
    --output-dir "${nebula_dir}" >/dev/null
fi
[[ -d "${nebula_dir}" && ! -L "${nebula_dir}" ]] ||
  die "exact Nebula dependency directory is unavailable: ${nebula_dir}"
for binary in nebula nebula-cert; do
  [[ -f "${nebula_dir}/${binary}" && -x "${nebula_dir}/${binary}" && ! -L "${nebula_dir}/${binary}" ]] ||
    die "exact Nebula dependency is unavailable or unsafe: ${nebula_dir}/${binary}"
done
[[ -f "${nebula_dir}/observer-build.json" && ! -L "${nebula_dir}/observer-build.json" ]] ||
  die "observer build provenance is unavailable or unsafe: ${nebula_dir}/observer-build.json"

source_epoch="$(date -u '+%s')"
[[ "${source_epoch}" =~ ^[0-9]+$ && "${source_epoch}" -gt 0 ]] || die "UTC epoch was not canonical"
issued_at="$(date -u -d '-1 minute' '+%Y-%m-%dT%H:%M:%SZ')"
expires_at="$(date -u -d '+1 day' '+%Y-%m-%dT%H:%M:%SZ')"

for signer in root-a root-b signer-a signer-b signer-c signer-d; do
	"${work_dir}/tools/mesh-release" generate-key \
		--private "${work_dir}/signing/${signer}.private.json" >/dev/null
	"${work_dir}/tools/mesh-release" export-public \
		--private "${work_dir}/signing/${signer}.private.json" \
		--public "${work_dir}/signing/${signer}.public.json" >/dev/null
done

"${work_dir}/tools/mesh-release" create-root \
	--output "${work_dir}/signing/root-v1.json" \
	--channel "${channel}" \
	--release-epoch 1 \
	--minimum-release-sequence 1 \
	--minimum-security-floor "${security_floor}" \
	--issued "${issued_at}" \
	--expires "${expires_at}" \
	--root-threshold 2 \
	--root-public "${work_dir}/signing/root-a.public.json" \
	--root-public "${work_dir}/signing/root-b.public.json" \
	--release-threshold 2 \
	--release-public "${work_dir}/signing/signer-a.public.json" \
	--release-public "${work_dir}/signing/signer-b.public.json" >/dev/null
"${work_dir}/tools/mesh-release" inspect-root --root "${work_dir}/signing/root-v1.json" >/dev/null
if "${work_dir}/tools/mesh-release" create-root \
	--output "${work_dir}/signing/overlapping-role-root.json" \
	--channel "${channel}" --release-epoch 1 --minimum-release-sequence 1 \
	--minimum-security-floor 1 --issued "${issued_at}" --expires "${expires_at}" \
	--root-threshold 2 --release-threshold 2 \
	--root-public "${work_dir}/signing/root-a.public.json" \
	--root-public "${work_dir}/signing/root-b.public.json" \
	--release-public "${work_dir}/signing/root-a.public.json" \
	--release-public "${work_dir}/signing/signer-a.public.json" >/dev/null 2>&1; then
	die "root/release role overlap was accepted"
fi
[[ ! -e "${work_dir}/signing/overlapping-role-root.json" ]] || die "failed role-overlap check published output"

installer_policy="$("${work_dir}/tools/mesh-release" installer-policy \
	--root "${work_dir}/signing/root-v1.json")"
[[ "${installer_policy}" != *[[:space:]]* ]] || die "installer bootstrap was not a single canonical frame"

build_release 1 "${version_one}" "${commit_one}" "${source_epoch}" "${work_dir}/releases/one" \
	"${work_dir}/signing/root-v1.json" "${work_dir}/signing/signer-a.private.json" "${work_dir}/signing/signer-b.private.json"
build_release 2 "${version_two}" "${commit_two}" "${source_epoch}" "${work_dir}/releases/two" \
	"${work_dir}/signing/root-v1.json" "${work_dir}/signing/signer-a.private.json" "${work_dir}/signing/signer-b.private.json"
build_release 3 "${version_three}" "${commit_three}" "${source_epoch}" "${work_dir}/releases/three" \
	"${work_dir}/signing/root-v1.json" "${work_dir}/signing/signer-a.private.json" "${work_dir}/signing/signer-b.private.json"

say "Authorizing and independently verifying the first installer bootstrap with the root role"
bootstrap_issued_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
bootstrap_expires_at="$(date -u -d '+1 hour' '+%Y-%m-%dT%H:%M:%SZ')"
bootstrap_root_sha="$(sha256sum -- "${work_dir}/signing/root-v1.json" | awk '{print $1}')"
[[ "${bootstrap_root_sha}" =~ ^[0-9a-f]{64}$ ]] || die "bootstrap root digest was not canonical"
"${work_dir}/tools/mesh-release" create-bootstrap-manifest \
	--output "${work_dir}/releases/one/bootstrap.json" \
	--root "${work_dir}/signing/root-v1.json" \
	--installer "${work_dir}/releases/one/mesh-install" \
	--arch "${arch}" \
	--issued "${bootstrap_issued_at}" \
	--expires "${bootstrap_expires_at}" >/dev/null
for signer in root-a root-b; do
	"${work_dir}/tools/mesh-release" sign \
		--private "${work_dir}/signing/${signer}.private.json" \
		--manifest "${work_dir}/releases/one/bootstrap.json" \
		--signature "${work_dir}/releases/one/bootstrap.${signer}.json" >/dev/null
done
"${work_dir}/tools/mesh-bootstrap-verify" \
	--root "${work_dir}/signing/root-v1.json" \
	--expected-root-sha256 "${bootstrap_root_sha}" \
	--manifest "${work_dir}/releases/one/bootstrap.json" \
	--signature "${work_dir}/releases/one/bootstrap.root-a.json" \
	--signature "${work_dir}/releases/one/bootstrap.root-b.json" \
	--installer "${work_dir}/releases/one/mesh-install" \
	--now "${bootstrap_issued_at}" >"${work_dir}/bootstrap-verification.json"
expect_json "${work_dir}/bootstrap-verification.json" schema mesh-bootstrap-verification-v1
expect_json "${work_dir}/bootstrap-verification.json" root_sha256 "${bootstrap_root_sha}"
expect_json "${work_dir}/bootstrap-verification.json" version "${version_one}"
expect_json "${work_dir}/bootstrap-verification.json" os linux
expect_json "${work_dir}/bootstrap-verification.json" arch "${arch}"
for signer in signer-a signer-b; do
	"${work_dir}/tools/mesh-release" sign \
		--private "${work_dir}/signing/${signer}.private.json" \
		--manifest "${work_dir}/releases/one/bootstrap.json" \
		--signature "${work_dir}/releases/one/bootstrap.${signer}.json" >/dev/null
done
if "${work_dir}/tools/mesh-bootstrap-verify" \
	--root "${work_dir}/signing/root-v1.json" \
	--expected-root-sha256 "${bootstrap_root_sha}" \
	--manifest "${work_dir}/releases/one/bootstrap.json" \
	--signature "${work_dir}/releases/one/bootstrap.signer-a.json" \
	--signature "${work_dir}/releases/one/bootstrap.signer-b.json" \
	--installer "${work_dir}/releases/one/mesh-install" \
	--now "${bootstrap_issued_at}" >/dev/null 2>&1; then
	die "release-role signatures authorized the first installer bootstrap"
fi
if "${work_dir}/tools/mesh-bootstrap-verify" \
	--root "${work_dir}/signing/root-v1.json" \
	--expected-root-sha256 "$(printf '0%.0s' {1..64})" \
	--manifest "${work_dir}/releases/one/bootstrap.json" \
	--signature "${work_dir}/releases/one/bootstrap.root-a.json" \
	--signature "${work_dir}/releases/one/bootstrap.root-b.json" \
	--installer "${work_dir}/releases/one/mesh-install" \
	--now "${bootstrap_issued_at}" >/dev/null 2>&1; then
	die "wrong independently authenticated root digest was accepted"
fi
cp -- "${work_dir}/releases/one/mesh-install" "${work_dir}/releases/one/mesh-install.tampered"
printf 'x' >>"${work_dir}/releases/one/mesh-install.tampered"
if "${work_dir}/tools/mesh-bootstrap-verify" \
	--root "${work_dir}/signing/root-v1.json" \
	--expected-root-sha256 "${bootstrap_root_sha}" \
	--manifest "${work_dir}/releases/one/bootstrap.json" \
	--signature "${work_dir}/releases/one/bootstrap.root-a.json" \
	--signature "${work_dir}/releases/one/bootstrap.root-b.json" \
	--installer "${work_dir}/releases/one/mesh-install.tampered" \
	--now "${bootstrap_issued_at}" >/dev/null 2>&1; then
	die "changed installer bytes were accepted by bootstrap verification"
fi
rm -f -- "${work_dir}/releases/one/mesh-install.tampered"

artifact_one_size="$(python3 -c 'import os,sys; print(os.stat(sys.argv[1]).st_size)' "${work_dir}/releases/one/mesh-linux-bundle.tar")"
artifact_one_sha="$(sha256sum -- "${work_dir}/releases/one/mesh-linux-bundle.tar" | awk '{print $1}')"
expired_fixture_expires_at="$(date -u -d '+30 seconds' '+%Y-%m-%dT%H:%M:%SZ')"
expired_fixture_expires_epoch="$(date -u -d "${expired_fixture_expires_at}" '+%s')"
mkdir -p -- "${work_dir}/fixtures"
chmod 0700 "${work_dir}/fixtures"
build_fixture_bundle insufficient \
  "${release_base_url}/releases/${version_one}/mesh-linux-bundle.tar" \
  "${artifact_one_size}" "${artifact_one_sha}" "${issued_at}" "${expires_at}" 1
build_fixture_bundle replayed \
  "${release_base_url}/releases/${version_one}/mesh-linux-bundle.tar" \
  "${artifact_one_size}" "${artifact_one_sha}" "${issued_at}" "${expires_at}" 2
build_fixture_bundle expired \
  "${release_base_url}/releases/${version_one}/mesh-linux-bundle.tar" \
  "${artifact_one_size}" "${artifact_one_sha}" \
  "${issued_at}" "${expired_fixture_expires_at}" 2
build_fixture_bundle truncated \
  "${release_base_url}/fixtures/truncated/mesh-linux-bundle.tar" \
  "${artifact_one_size}" "${artifact_one_sha}" "${issued_at}" "${expires_at}" 2
build_fixture_bundle wrong-digest \
  "${release_base_url}/fixtures/wrong-digest/mesh-linux-bundle.tar" \
  "${artifact_one_size}" "${artifact_one_sha}" "${issued_at}" "${expires_at}" 2
build_fixture_bundle oversized \
  "${release_base_url}/fixtures/oversized/mesh-linux-bundle.tar" \
  "$((272 * 1024 * 1024 + 1))" \
  '0000000000000000000000000000000000000000000000000000000000000000' \
  "${issued_at}" "${expires_at}" 2
python3 -c 'import pathlib; pathlib.Path(__import__("sys").argv[1]).write_bytes(b"{not-json\n")' \
  "${work_dir}/fixtures/corrupt-bundle.json"

agent_unit_sha="$(sha256sum -- "${repo_root}/packaging/systemd/mesh-agent.service" | awk '{print $1}')"
nebula_unit_sha="$(sha256sum -- "${repo_root}/packaging/systemd/mesh-nebula.service" | awk '{print $1}')"
timeout_abort_mask_sha="$(sha256sum -- "${repo_root}/packaging/systemd/10-timeout-abort.conf" | awk '{print $1}')"

say "Starting a fresh isolated privileged systemd host"
proof_network_args=()
if [[ "${ui_guided_package_smoke}" == "1" ]]; then
  proof_network_args=(--network "${proof_network_name}" --ip "${proof_control_ip}")
fi
if ! docker run --detach \
  --name "${container_name}" \
  --label "mesh.install-smoke.id=${run_id}" \
  "${proof_network_args[@]}" \
  --privileged \
  --cgroupns private \
  --security-opt label=disable \
  --tmpfs /run \
  --tmpfs /run/lock \
  "${proof_image}" /sbin/init >/dev/null; then
  if [[ "$(docker inspect --format '{{index .Config.Labels "mesh.install-smoke.id"}}' "${container_name}" 2>/dev/null || true)" == "${run_id}" ]]; then
    container_started=1
  fi
  skip "could not start a privileged container from ${proof_image}"
fi
container_started=1
wait_for_systemd
if ! docker exec "${container_name}" bash -lc '
  for command in awk bash cat chmod chown curl find journalctl pgrep readlink sed sha256sum sleep stat systemctl systemd-run; do
    command -v -- "${command}" >/dev/null || exit 1
  done
'; then
  skip "systemd proof image is missing a required runtime command"
fi
docker exec "${container_name}" test -c /dev/net/tun || skip "isolated host has no TUN device"

docker exec "${container_name}" mkdir -p /root/mesh-proof/tools /root/mesh-proof/bootstrap
docker exec "${container_name}" chmod 0700 /root/mesh-proof /root/mesh-proof/tools /root/mesh-proof/bootstrap
docker cp "${work_dir}/tools/mesh-release" "${container_name}:/root/mesh-proof/tools/mesh-release" >/dev/null
docker cp "${work_dir}/tools/mesh-server" "${container_name}:/root/mesh-proof/tools/mesh-server" >/dev/null
docker cp "${work_dir}/releases/one/mesh-install" "${container_name}:/root/mesh-proof/bootstrap/mesh-install" >/dev/null
docker exec "${container_name}" chown -R root:root /root/mesh-proof
docker exec "${container_name}" chmod 0700 \
  /root/mesh-proof/tools/mesh-release \
  /root/mesh-proof/tools/mesh-server \
  /root/mesh-proof/bootstrap/mesh-install

say "Starting a trusted systemd-managed HTTPS release repository"
docker exec "${container_name}" mkdir -p \
  /root/mesh-proof/repository /root/mesh-proof/semaphores /root/mesh-proof/tls \
  /etc/pki/ca-trust/source/anchors
docker exec "${container_name}" chmod 0755 /root/mesh-proof/repository
docker exec "${container_name}" chmod 0700 /root/mesh-proof/semaphores /root/mesh-proof/tls
docker cp "${work_dir}/tls/ca.crt" \
  "${container_name}:/etc/pki/ca-trust/source/anchors/mesh-install-smoke-ca.crt" >/dev/null
docker cp "${work_dir}/tls/server.crt" "${container_name}:/root/mesh-proof/tls/server.crt" >/dev/null
docker cp "${work_dir}/tls/server.key" "${container_name}:/root/mesh-proof/tls/server.key" >/dev/null
docker exec "${container_name}" chown root:root \
  /etc/pki/ca-trust/source/anchors/mesh-install-smoke-ca.crt \
  /root/mesh-proof/tls/server.crt /root/mesh-proof/tls/server.key
docker exec "${container_name}" chmod 0444 \
  /etc/pki/ca-trust/source/anchors/mesh-install-smoke-ca.crt \
  /root/mesh-proof/tls/server.crt
docker exec "${container_name}" chmod 0400 /root/mesh-proof/tls/server.key
docker exec "${container_name}" update-ca-trust
docker exec -i "${container_name}" bash -c \
  'umask 077; cat > /root/mesh-proof/https_server.py; chmod 0500 /root/mesh-proof/https_server.py' <<'PY'
import http.server
import os
import pathlib
import re
import ssl
import time
import urllib.parse

ROOT = pathlib.Path('/root/mesh-proof/repository')
SEMAPHORES = pathlib.Path('/root/mesh-proof/semaphores')
SOURCE_ARTIFACT = ROOT / 'releases/1.0.0/mesh-linux-bundle.tar'
BASE_URL = os.environ.get('MESH_PROOF_RELEASE_BASE_URL', 'https://127.0.0.1:18443')
LISTEN = os.environ.get('MESH_PROOF_RELEASE_LISTEN', '127.0.0.1')
if not re.fullmatch(r'https://(?:127\.0\.0\.1|10(?:\.[0-9]{1,3}){3}|172\.(?:1[6-9]|2[0-9]|3[01])(?:\.[0-9]{1,3}){2}|192\.168(?:\.[0-9]{1,3}){2}):18443', BASE_URL):
    raise SystemExit('invalid release base URL')
if LISTEN not in {'127.0.0.1', '0.0.0.0'}:
    raise SystemExit('invalid release listener')


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, format, *args):
        return

    def empty(self, status, location=None):
        self.send_response(status)
        if location is not None:
            self.send_header('Location', location)
        self.send_header('Content-Length', '0')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.close_connection = True

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.query or parsed.fragment or urllib.parse.quote(parsed.path, safe='/.-_') != parsed.path:
            self.empty(404)
            return
        if parsed.path == '/fixtures/redirect/bundle.json':
            self.empty(302, BASE_URL + '/channels/stable/bundle.json')
            return

        relative = parsed.path.removeprefix('/')
        if relative.startswith('/') or '..' in pathlib.PurePosixPath(relative).parts:
            self.empty(404)
            return
        candidate = ROOT / relative
        special = ''
        if parsed.path == '/fixtures/truncated/mesh-linux-bundle.tar':
            candidate = SOURCE_ARTIFACT
            special = 'truncated'
        elif parsed.path == '/fixtures/wrong-digest/mesh-linux-bundle.tar':
            candidate = SOURCE_ARTIFACT
            special = 'wrong-digest'
        elif parsed.path == '/fixtures/oversized/mesh-linux-bundle.tar':
            self.empty(500)
            return

        match = re.fullmatch(r'/releases/([0-9]+\.[0-9]+\.[0-9]+)/mesh-linux-bundle\.tar', parsed.path)
        if match:
            version = match.group(1)
            enabled = SEMAPHORES / f'block-{version}.enabled'
            if enabled.exists():
                (SEMAPHORES / f'block-{version}.started').touch(exist_ok=True)
                released = SEMAPHORES / f'block-{version}.release'
                for _ in range(900):
                    if released.exists():
                        break
                    time.sleep(0.1)
                else:
                    self.empty(504)
                    return

        try:
            if not candidate.is_file() or candidate.is_symlink():
                self.empty(404)
                return
            data = candidate.read_bytes()
        except OSError:
            self.empty(500)
            return
        if special == 'wrong-digest':
            data = bytes([data[0] ^ 1]) + data[1:]

        self.send_response(200)
        self.send_header('Content-Type', 'application/json' if candidate.suffix == '.json' else 'application/octet-stream')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Connection', 'close')
        self.end_headers()
        if special == 'truncated':
            self.wfile.write(data[:-1])
        else:
            self.wfile.write(data)
        self.wfile.flush()
        self.close_connection = True


server = http.server.ThreadingHTTPServer((LISTEN, 18443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain('/root/mesh-proof/tls/server.crt', '/root/mesh-proof/tls/server.key')
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY

publish_online_release "${version_one}" "${work_dir}/releases/one"
publish_online_release "${version_two}" "${work_dir}/releases/two"
publish_online_release "${version_three}" "${work_dir}/releases/three"
for fixture in insufficient replayed expired truncated wrong-digest oversized; do
  publish_online_fixture "${fixture}"
done
docker cp "${work_dir}/fixtures/corrupt-bundle.json" \
  "${container_name}:/root/mesh-proof/repository/fixtures/corrupt-bundle.json" >/dev/null
docker exec "${container_name}" chmod 0444 /root/mesh-proof/repository/fixtures/corrupt-bundle.json
publish_stable_bundle "${version_one}"

release_listen="127.0.0.1"
if [[ "${ui_guided_package_smoke}" == "1" ]]; then
  release_listen="0.0.0.0"
fi
docker exec "${container_name}" systemd-run \
  --unit=mesh-proof-https.service \
  --property=Type=simple \
  --property=WorkingDirectory=/root/mesh-proof \
  --property="Environment=MESH_PROOF_RELEASE_BASE_URL=${release_base_url}" \
  --property="Environment=MESH_PROOF_RELEASE_LISTEN=${release_listen}" \
  /usr/bin/python3 /root/mesh-proof/https_server.py >/dev/null
for attempt in {1..120}; do
  if docker exec "${container_name}" curl --silent --show-error --fail --noproxy '*' \
    --connect-timeout 1 --max-time 1 --output /dev/null \
    "${release_base_url}/channels/stable/bundle.json" 2>/dev/null; then
    break
  fi
  if [[ "${attempt}" == "120" ]]; then
    docker exec "${container_name}" journalctl --no-pager -u mesh-proof-https.service >&2 || true
    die "isolated HTTPS release repository did not become ready"
  fi
  sleep 0.25
done

copy_and_assemble_snapshot 1 "${work_dir}/releases/one"
copy_and_assemble_snapshot 2 "${work_dir}/releases/two"
copy_and_assemble_snapshot 3 "${work_dir}/releases/three"

say "Rejecting every negative online fixture before any install mutation"
while (( $(date -u '+%s') < expired_fixture_expires_epoch )); do
  sleep 0.25
done
while IFS='|' read -r label path; do
  expect_online_failure "pre-${label}" "${release_base_url}${path}"
  assert_pristine_install_boundary
done <<'FIXTURES'
corrupt|/fixtures/corrupt-bundle.json
insufficient|/fixtures/insufficient/bundle.json
expired|/fixtures/expired/bundle.json
redirect|/fixtures/redirect/bundle.json
truncated|/fixtures/truncated/bundle.json
oversized|/fixtures/oversized/bundle.json
wrong-digest|/fixtures/wrong-digest/bundle.json
FIXTURES

say "Installing sequence 1 through authenticated HTTPS with the separately placed bootstrap installer"
docker exec "${container_name}" /root/mesh-proof/bootstrap/mesh-install install-online \
  "${release_base_url}/channels/stable/bundle.json" >"${work_dir}/install-one.json"
expect_json "${work_dir}/install-one.json" operation activate
expect_json "${work_dir}/install-one.json" first_install true
expect_json "${work_dir}/install-one.json" agent_enabled false
expect_json "${work_dir}/install-one.json" agent_active false
expect_json "${work_dir}/install-one.json" nebula_active false
expect_json "${work_dir}/install-one.json" runtime_gate_open false
installed_one="$(json_get "${work_dir}/install-one.json" release.installed_id)"
[[ "${installed_one}" =~ ^e[0-9]{20}-s[0-9]{20}-r[0-9a-f]{16}-a[0-9a-f]{16}$ ]] || die "sequence 1 installed ID was not canonical"
assert_stopped_install "${installed_one}"
capture_and_assert_state first-install "${installed_one}" "" "${installed_one}" 1

say "Proving post-install online failures and equivocation cannot mutate stopped state"
capture_installed_fingerprint "${work_dir}/stopped-before-negatives.fingerprint"
while IFS='|' read -r label path; do
  expect_online_failure "post-${label}" "${release_base_url}${path}"
  capture_installed_fingerprint "${work_dir}/stopped-after-${label}.fingerprint"
  cmp --silent -- \
    "${work_dir}/stopped-before-negatives.fingerprint" \
    "${work_dir}/stopped-after-${label}.fingerprint" ||
    die "online negative fixture mutated installed state: ${label}"
  assert_no_pending_online_intake
done <<'FIXTURES'
corrupt|/fixtures/corrupt-bundle.json
insufficient|/fixtures/insufficient/bundle.json
expired|/fixtures/expired/bundle.json
replayed|/fixtures/replayed/bundle.json
redirect|/fixtures/redirect/bundle.json
truncated-equivocation|/fixtures/truncated/bundle.json
oversized-equivocation|/fixtures/oversized/bundle.json
wrong-digest-equivocation|/fixtures/wrong-digest/bundle.json
FIXTURES
assert_stopped_install "${installed_one}"

docker exec "${container_name}" /root/mesh-proof/bootstrap/mesh-install install-online \
  "${release_base_url}/channels/stable/bundle.json" >"${work_dir}/install-one-retry.json"
expect_json "${work_dir}/install-one-retry.json" already_active true
capture_installed_fingerprint "${work_dir}/stopped-after-exact-retry.fingerprint"
cmp --silent -- \
  "${work_dir}/stopped-before-negatives.fingerprint" \
  "${work_dir}/stopped-after-exact-retry.fingerprint" ||
  die "exact online install retry mutated stopped state"

say "Proving SIGTERM cleanup and SIGKILL reconciliation for private online intake"
start_blocked_online_install "${version_two}" blocked-term
stop_blocked_online_install "${version_two}" blocked-term TERM
assert_no_pending_online_intake
capture_installed_fingerprint "${work_dir}/stopped-after-sigterm.fingerprint"
cmp --silent -- \
  "${work_dir}/stopped-before-negatives.fingerprint" \
  "${work_dir}/stopped-after-sigterm.fingerprint" ||
  die "SIGTERM during online retrieval mutated installed state"

start_blocked_online_install "${version_two}" blocked-kill
stop_blocked_online_install "${version_two}" blocked-kill KILL
docker exec -i "${container_name}" bash -s <<'CONTAINER'
set -Eeuo pipefail
intake=/var/lib/mesh-installer/online-intake
mapfile -t pending < <(find "${intake}" -mindepth 1 -maxdepth 1 -type d -name 'pending-*' -printf '%f\n')
[[ "${#pending[@]}" == "1" ]]
[[ "${pending[0]}" =~ ^pending-[0-9a-f]{32}$ ]]
[[ "$(stat -c '%U:%G:%a' -- "${intake}/${pending[0]}")" == "root:root:700" ]]
CONTAINER
docker exec "${container_name}" /root/mesh-proof/bootstrap/mesh-install install-online \
  "${release_base_url}/channels/stable/bundle.json" >"${work_dir}/install-after-kill.json"
expect_json "${work_dir}/install-after-kill.json" already_active true
assert_no_pending_online_intake
capture_installed_fingerprint "${work_dir}/stopped-after-kill-reconcile.fingerprint"
cmp --silent -- \
  "${work_dir}/stopped-before-negatives.fingerprint" \
  "${work_dir}/stopped-after-kill-reconcile.fingerprint" ||
  die "SIGKILL reconciliation mutated installed state"

say "Starting an isolated loopback control plane and enrolling without exposing its bearer"
docker exec "${container_name}" systemd-run \
  --unit=mesh-proof-control.service \
  --property=Type=simple \
  --property=WorkingDirectory=/root/mesh-proof \
  --property=Environment=NEBULA_CERT_BINARY=/usr/local/bin/nebula-cert \
  /root/mesh-proof/tools/mesh-server \
  --dev \
  --listen 127.0.0.1:18080 \
  --data-dir /root/mesh-proof/control >/dev/null
for attempt in {1..120}; do
  if docker exec "${container_name}" curl --silent --show-error --fail --noproxy '*' \
    --connect-timeout 1 --max-time 1 --output /dev/null http://127.0.0.1:18080/healthz 2>/dev/null; then
    break
  fi
  if [[ "${attempt}" == "120" ]]; then
    docker exec "${container_name}" journalctl --no-pager -u mesh-proof-control.service >&2 || true
    die "isolated loopback control plane did not become ready"
  fi
  sleep 0.25
done

docker exec -i "${container_name}" bash -s <<'CONTAINER'
set -Eeuo pipefail
umask 077
admin_token="$(< /root/mesh-proof/control/admin.token)"
[[ "${admin_token}" =~ ^[A-Za-z0-9_-]{43}$ ]]
network_output="$(MESH_ADMIN_TOKEN="${admin_token}" /usr/local/bin/meshctl create-network \
  --server http://127.0.0.1:18080 \
  --name linux-install-smoke \
  --cidr 10.231.0.0/24)"
network_id="$(printf '%s\n' "${network_output}" | sed -n 's/^.* id \([A-Za-z0-9_-][A-Za-z0-9_-]*\)$/\1/p')"
[[ "${network_id}" =~ ^[A-Za-z0-9_-]+$ ]]
node_output=/root/mesh-proof/node-created.private
MESH_ADMIN_TOKEN="${admin_token}" /usr/local/bin/meshctl create-node \
  --server http://127.0.0.1:18080 \
  --network "${network_id}" \
  --name linux-install-smoke-lighthouse \
  --role lighthouse \
  --site linux-install-smoke \
  --failure-domain linux-install-smoke-a \
  --endpoint 127.0.0.1:4242 >"${node_output}"
unset admin_token
enrollment_token="$(sed -n '$p' "${node_output}")"
[[ "${enrollment_token}" =~ ^[A-Za-z0-9_-]{43}$ ]]
printf '%s\n' "${enrollment_token}" | /usr/local/bin/meshctl enroll \
  --server http://127.0.0.1:18080 \
  --token-file - \
  --state /var/lib/mesh-agent/state.json \
  --output /var/lib/mesh-agent/nebula \
  --nebula /usr/local/bin/nebula \
  --nebula-cert /usr/local/bin/nebula-cert >/root/mesh-proof/enroll.log
unset enrollment_token network_id network_output
rm -f -- "${node_output}"
[[ -f /var/lib/mesh-agent/state.json ]]
[[ -L /var/lib/mesh-agent/nebula/current ]]
CONTAINER

say "Activating the enrolled runtime and proving retry idempotency"
docker exec "${container_name}" /usr/local/bin/mesh-install activate >"${work_dir}/activate-one.json"
assert_active_result "${work_dir}/activate-one.json" "${installed_one}" activate
expect_json_absent "${work_dir}/activate-one.json" runtime_already_active
assert_active_install "${installed_one}" "${version_one}"
capture_and_assert_state first-activation "${installed_one}" "" "${installed_one}" 1

docker exec "${container_name}" /usr/local/bin/mesh-install activate >"${work_dir}/activate-one-retry.json"
assert_active_result "${work_dir}/activate-one-retry.json" "${installed_one}" activate
expect_json "${work_dir}/activate-one-retry.json" runtime_already_active true
assert_active_install "${installed_one}" "${version_one}"

say "Racing sequence 2 online verification against the same exact offline install"
publish_stable_bundle "${version_two}"
start_blocked_online_install "${version_two}" race-same /usr/local/bin/mesh-install
docker exec "${container_name}" /usr/local/bin/mesh-install install \
  /root/mesh-proof/snapshot-2 >"${work_dir}/install-two.json"
installed_two="$(json_get "${work_dir}/install-two.json" release.installed_id)"
[[ "${installed_two}" =~ ^e[0-9]{20}-s[0-9]{20}-r[0-9a-f]{16}-a[0-9a-f]{16}$ ]] || die "sequence 2 installed ID was not canonical"
[[ "${installed_two}" != "${installed_one}" ]] || die "upgrade reused the sequence 1 installed ID"
assert_active_result "${work_dir}/install-two.json" "${installed_two}" activate
expect_json "${work_dir}/install-two.json" first_install false
expect_json "${work_dir}/install-two.json" previous.installed_id "${installed_one}"
assert_active_install "${installed_two}" "${version_two}"
capture_and_assert_state upgrade "${installed_two}" "${installed_one}" "${installed_two}" 2
agent_pid_after_two="$(docker exec "${container_name}" systemctl show mesh-agent.service --property=MainPID --value)"
nebula_pid_after_two="$(docker exec "${container_name}" systemctl show mesh-nebula.service --property=MainPID --value)"
release_blocked_online_install "${version_two}" race-same 0
expect_json "${work_dir}/race-same.json" already_active true
assert_active_result "${work_dir}/race-same.json" "${installed_two}" activate
[[ "$(docker exec "${container_name}" systemctl show mesh-agent.service --property=MainPID --value)" == "${agent_pid_after_two}" ]] ||
  die "same-byte online race restarted the lifecycle agent"
[[ "$(docker exec "${container_name}" systemctl show mesh-nebula.service --property=MainPID --value)" == "${nebula_pid_after_two}" ]] ||
  die "same-byte online race restarted Nebula"
assert_no_pending_online_intake

say "Rejecting a stale online candidate after a different signed next sequence wins"
start_blocked_online_install "${version_two}" race-stale /usr/local/bin/mesh-install
docker exec "${container_name}" /usr/local/bin/mesh-install install \
  /root/mesh-proof/snapshot-3 >"${work_dir}/install-three.json"
installed_three="$(json_get "${work_dir}/install-three.json" release.installed_id)"
[[ "${installed_three}" =~ ^e[0-9]{20}-s[0-9]{20}-r[0-9a-f]{16}-a[0-9a-f]{16}$ ]] || die "sequence 3 installed ID was not canonical"
[[ "${installed_three}" != "${installed_two}" ]] || die "sequence 3 reused the sequence 2 installed ID"
assert_active_result "${work_dir}/install-three.json" "${installed_three}" activate
expect_json "${work_dir}/install-three.json" previous.installed_id "${installed_two}"
assert_active_install "${installed_three}" "${version_three}"
capture_and_assert_state state-race-newer "${installed_three}" "${installed_two}" "${installed_three}" 3
capture_installed_fingerprint "${work_dir}/before-stale-release.fingerprint"
release_blocked_online_install "${version_two}" race-stale 1
capture_installed_fingerprint "${work_dir}/after-stale-release.fingerprint"
cmp --silent -- "${work_dir}/before-stale-release.fingerprint" "${work_dir}/after-stale-release.fingerprint" ||
  die "stale online candidate mutated the newer installed state"
assert_no_pending_online_intake

say "Interrupting a real prepared rollback and completing it through recover"
docker exec -i "${container_name}" bash -s -- "${installed_two}" <<'CONTAINER'
set -Eeuo pipefail
umask 077
target="$1"
/usr/local/bin/mesh-install rollback "${target}" \
  >/root/mesh-proof/interrupted-rollback.stdout \
  2>/root/mesh-proof/interrupted-rollback.stderr </dev/null &
installer_pid=$!
printf '%s\n' "${installer_pid}" >/root/mesh-proof/interrupted-rollback.pid
python3 - "${installer_pid}" >/root/mesh-proof/interrupted-rollback-watcher.log 2>&1 <<'PY' &
import json
import os
import signal
import sys
import time

installer_pid = int(sys.argv[1])
deadline = time.monotonic() + 30
while time.monotonic() < deadline:
    try:
        with open("/var/lib/mesh-installer/state.json", encoding="utf-8") as state_file:
            state = json.load(state_file)
    except (FileNotFoundError, json.JSONDecodeError):
        time.sleep(0.001)
        continue
    if not state.get("pending"):
        time.sleep(0.001)
        continue
    try:
        os.kill(installer_pid, signal.SIGSTOP)
    except ProcessLookupError:
        break
    with open("/var/lib/mesh-installer/state.json", encoding="utf-8") as state_file:
        stopped_state = json.load(state_file)
    if stopped_state.get("pending"):
        with open("/root/mesh-proof/interrupted-rollback.observed", "x", encoding="utf-8") as marker:
            marker.write(stopped_state["pending"]["phase"] + "\n")
        break
    os.kill(installer_pid, signal.SIGCONT)
PY
CONTAINER
for attempt in {1..300}; do
  if docker exec "${container_name}" test -s /root/mesh-proof/interrupted-rollback.observed &&
    docker exec "${container_name}" python3 -c \
      'import json; raise SystemExit(0 if json.load(open("/var/lib/mesh-installer/state.json")).get("pending") else 1)' \
      2>/dev/null; then
    break
  fi
  if [[ "${attempt}" == "300" ]]; then
    die "rollback did not publish a controlled pending transaction"
  fi
  sleep 0.1
done
rollback_installer_pid="$(docker exec "${container_name}" cat /root/mesh-proof/interrupted-rollback.pid)"
[[ "${rollback_installer_pid}" =~ ^[0-9]+$ && "${rollback_installer_pid}" -gt 1 ]] ||
  die "interrupted rollback installer PID was not available"
docker exec "${container_name}" kill -KILL "${rollback_installer_pid}"
for attempt in {1..120}; do
  if ! docker exec "${container_name}" kill -0 "${rollback_installer_pid}" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
docker exec "${container_name}" /usr/local/bin/mesh-install recover >"${work_dir}/recover-rollback.json"
assert_active_result "${work_dir}/recover-rollback.json" "${installed_two}" rollback
expect_json "${work_dir}/recover-rollback.json" previous.installed_id "${installed_three}"
assert_active_install "${installed_two}" "${version_two}"
capture_and_assert_state recovered-rollback "${installed_two}" "${installed_three}" "${installed_three}" 3
agent_pid_before_retry="$(docker exec "${container_name}" systemctl show mesh-agent.service --property=MainPID --value)"
nebula_pid_before_retry="$(docker exec "${container_name}" systemctl show mesh-nebula.service --property=MainPID --value)"

docker exec "${container_name}" /usr/local/bin/mesh-install rollback "${installed_two}" \
  >"${work_dir}/rollback-two-retry.json"
assert_active_result "${work_dir}/rollback-two-retry.json" "${installed_two}" rollback
expect_json "${work_dir}/rollback-two-retry.json" already_active true
[[ "$(docker exec "${container_name}" systemctl show mesh-agent.service --property=MainPID --value)" == "${agent_pid_before_retry}" ]] ||
  die "rollback retry restarted the lifecycle agent"
[[ "$(docker exec "${container_name}" systemctl show mesh-nebula.service --property=MainPID --value)" == "${nebula_pid_before_retry}" ]] ||
  die "rollback retry restarted Nebula"
assert_active_install "${installed_two}" "${version_two}"
capture_and_assert_state rollback-retry "${installed_two}" "${installed_three}" "${installed_three}" 3

say "Building and proving versioned root rotation and release-epoch reset"
rotation_issued="$(date -u -d '-1 minute' '+%Y-%m-%dT%H:%M:%SZ')"
root_two_expires="$(date -u -d '+90 seconds' '+%Y-%m-%dT%H:%M:%SZ')"
root_two_expires_epoch="$(date -u -d "${root_two_expires}" '+%s')"
root_three_expires="$(date -u -d '+1 day' '+%Y-%m-%dT%H:%M:%SZ')"

"${work_dir}/tools/mesh-release" create-root \
	--output "${work_dir}/signing/root-v2.json" \
	--previous-root "${work_dir}/signing/root-v1.json" \
	--issued "${rotation_issued}" --expires "${root_two_expires}" \
	--root-public "${work_dir}/signing/root-a.public.json" \
	--root-public "${work_dir}/signing/root-b.public.json" \
	--release-public "${work_dir}/signing/signer-a.public.json" \
	--release-public "${work_dir}/signing/signer-b.public.json" >/dev/null
"${work_dir}/tools/mesh-release" create-root \
	--output "${work_dir}/signing/root-v2-alternate.json" \
	--previous-root "${work_dir}/signing/root-v1.json" \
	--minimum-release-sequence 2 \
	--issued "${rotation_issued}" --expires "${root_two_expires}" \
	--root-public "${work_dir}/signing/root-a.public.json" \
	--root-public "${work_dir}/signing/root-b.public.json" \
	--release-public "${work_dir}/signing/signer-a.public.json" \
	--release-public "${work_dir}/signing/signer-b.public.json" >/dev/null
assemble_root_transition \
	"${work_dir}/signing/root-v1.json" "${work_dir}/signing/root-v2.json" \
	"${work_dir}/signing/root-update-v1-v2.json" \
	"${work_dir}/signing/root-a.private.json" "${work_dir}/signing/root-b.private.json"
assemble_root_transition \
	"${work_dir}/signing/root-v1.json" "${work_dir}/signing/root-v2-alternate.json" \
	"${work_dir}/signing/root-update-v1-v2-alternate.json" \
	"${work_dir}/signing/root-a.private.json" "${work_dir}/signing/root-b.private.json"

"${work_dir}/tools/mesh-release" create-root \
	--output "${work_dir}/signing/root-v3.json" \
	--previous-root "${work_dir}/signing/root-v2.json" \
	--release-epoch 2 --minimum-release-sequence 1 \
	--issued "${rotation_issued}" --expires "${root_three_expires}" \
	--root-public "${work_dir}/signing/root-a.public.json" \
	--root-public "${work_dir}/signing/root-b.public.json" \
	--release-public "${work_dir}/signing/signer-c.public.json" \
	--release-public "${work_dir}/signing/signer-d.public.json" >/dev/null
assemble_root_transition \
	"${work_dir}/signing/root-v2.json" "${work_dir}/signing/root-v3.json" \
	"${work_dir}/signing/root-update-v2-v3.json" \
	"${work_dir}/signing/root-a.private.json" "${work_dir}/signing/root-b.private.json"

issued_at="${rotation_issued}"
expires_at="${root_two_expires}"
build_release 4 "${version_four}" "${commit_four}" "${source_epoch}" "${work_dir}/releases/four" \
	"${work_dir}/signing/root-v2.json" "${work_dir}/signing/signer-a.private.json" "${work_dir}/signing/signer-b.private.json" \
	"${work_dir}/signing/root-update-v1-v2.json"
expires_at="${root_three_expires}"
build_release 1 "${version_five}" "${commit_five}" "${source_epoch}" "${work_dir}/releases/five" \
	"${work_dir}/signing/root-v3.json" "${work_dir}/signing/signer-c.private.json" "${work_dir}/signing/signer-d.private.json" \
	"${work_dir}/signing/root-update-v1-v2.json" "${work_dir}/signing/root-update-v2-v3.json"

mkdir -p -- "${work_dir}/fixtures/root-insufficient" "${work_dir}/fixtures/root-gap" \
	"${work_dir}/fixtures/root-equivocation" "${work_dir}/fixtures/revoked-release" "${work_dir}/fixtures/old-epoch"
python3 - "${work_dir}/releases/four/online-bundle.json" \
	"${work_dir}/fixtures/root-insufficient/bundle.json" <<'PY'
import base64, json, pathlib, sys
source, output = map(pathlib.Path, sys.argv[1:])
bundle = json.loads(source.read_text())
update = json.loads(base64.urlsafe_b64decode(bundle['root_updates'][0] + '==='))
update['signatures'] = update['signatures'][:1]
raw = (json.dumps(update, separators=(',', ':')) + '\n').encode()
bundle['root_updates'] = [base64.urlsafe_b64encode(raw).decode().rstrip('=')]
output.write_text(json.dumps(bundle, separators=(',', ':')) + '\n')
PY
"${work_dir}/tools/mesh-release" assemble-online-bundle \
	--output "${work_dir}/fixtures/root-gap/bundle.json" \
	--root-update "${work_dir}/signing/root-update-v2-v3.json" \
	--channel-manifest "${work_dir}/releases/five/channel.json" \
	--channel-signature "${work_dir}/releases/five/channel.signer-a.json" \
	--channel-signature "${work_dir}/releases/five/channel.signer-b.json" \
	--release-manifest "${work_dir}/releases/five/release.json" \
	--release-signature "${work_dir}/releases/five/release.signer-a.json" \
	--release-signature "${work_dir}/releases/five/release.signer-b.json" >/dev/null
"${work_dir}/tools/mesh-release" assemble-online-bundle \
	--output "${work_dir}/fixtures/root-equivocation/bundle.json" \
	--root-update "${work_dir}/signing/root-update-v1-v2-alternate.json" \
	--channel-manifest "${work_dir}/releases/four/channel.json" \
	--channel-signature "${work_dir}/releases/four/channel.signer-a.json" \
	--channel-signature "${work_dir}/releases/four/channel.signer-b.json" \
	--release-manifest "${work_dir}/releases/four/release.json" \
	--release-signature "${work_dir}/releases/four/release.signer-a.json" \
	--release-signature "${work_dir}/releases/four/release.signer-b.json" >/dev/null

for role in release channel; do
	"${work_dir}/tools/mesh-release" sign --private "${work_dir}/signing/signer-a.private.json" \
		--manifest "${work_dir}/releases/five/${role}.json" \
		--signature "${work_dir}/fixtures/revoked-release/${role}.signer-a.json" >/dev/null
	"${work_dir}/tools/mesh-release" sign --private "${work_dir}/signing/signer-b.private.json" \
		--manifest "${work_dir}/releases/five/${role}.json" \
		--signature "${work_dir}/fixtures/revoked-release/${role}.signer-b.json" >/dev/null
done
"${work_dir}/tools/mesh-release" assemble-online-bundle \
	--output "${work_dir}/fixtures/revoked-release/bundle.json" \
	--channel-manifest "${work_dir}/releases/five/channel.json" \
	--channel-signature "${work_dir}/fixtures/revoked-release/channel.signer-a.json" \
	--channel-signature "${work_dir}/fixtures/revoked-release/channel.signer-b.json" \
	--release-manifest "${work_dir}/releases/five/release.json" \
	--release-signature "${work_dir}/fixtures/revoked-release/release.signer-a.json" \
	--release-signature "${work_dir}/fixtures/revoked-release/release.signer-b.json" >/dev/null

python3 - "${work_dir}/releases/five/release.json" "${work_dir}/releases/five/channel.json" \
	"${work_dir}/fixtures/old-epoch/release.json" "${work_dir}/fixtures/old-epoch/channel.json" <<'PY'
import hashlib, json, pathlib, sys
release_in, channel_in, release_out, channel_out = map(pathlib.Path, sys.argv[1:])
release = json.loads(release_in.read_text()); release['release_epoch'] = 1
release_raw = (json.dumps(release, separators=(',', ':')) + '\n').encode(); release_out.write_bytes(release_raw)
channel = json.loads(channel_in.read_text()); channel['release_epoch'] = 1
channel['release']['manifest_size'] = len(release_raw)
channel['release']['manifest_sha256'] = hashlib.sha256(release_raw).hexdigest()
channel_out.write_text(json.dumps(channel, separators=(',', ':')) + '\n')
PY
for role in release channel; do
	"${work_dir}/tools/mesh-release" sign --private "${work_dir}/signing/signer-c.private.json" \
		--manifest "${work_dir}/fixtures/old-epoch/${role}.json" \
		--signature "${work_dir}/fixtures/old-epoch/${role}.signer-a.json" >/dev/null
	"${work_dir}/tools/mesh-release" sign --private "${work_dir}/signing/signer-d.private.json" \
		--manifest "${work_dir}/fixtures/old-epoch/${role}.json" \
		--signature "${work_dir}/fixtures/old-epoch/${role}.signer-b.json" >/dev/null
done
"${work_dir}/tools/mesh-release" assemble-online-bundle \
	--output "${work_dir}/fixtures/old-epoch/bundle.json" \
	--channel-manifest "${work_dir}/fixtures/old-epoch/channel.json" \
	--channel-signature "${work_dir}/fixtures/old-epoch/channel.signer-a.json" \
	--channel-signature "${work_dir}/fixtures/old-epoch/channel.signer-b.json" \
	--release-manifest "${work_dir}/fixtures/old-epoch/release.json" \
	--release-signature "${work_dir}/fixtures/old-epoch/release.signer-a.json" \
	--release-signature "${work_dir}/fixtures/old-epoch/release.signer-b.json" >/dev/null

publish_online_release "${version_four}" "${work_dir}/releases/four"
publish_online_release "${version_five}" "${work_dir}/releases/five"
for fixture in root-insufficient root-gap root-equivocation revoked-release old-epoch; do
	docker exec "${container_name}" mkdir -p "/root/mesh-proof/repository/fixtures/${fixture}"
	docker cp "${work_dir}/fixtures/${fixture}/bundle.json" \
		"${container_name}:/root/mesh-proof/repository/fixtures/${fixture}/bundle.json" >/dev/null
	docker exec "${container_name}" chmod 0444 "/root/mesh-proof/repository/fixtures/${fixture}/bundle.json"
done
copy_and_assemble_snapshot 4 "${work_dir}/releases/four"
copy_and_assemble_snapshot 5 "${work_dir}/releases/five"

capture_installed_fingerprint "${work_dir}/before-root-negatives.fingerprint"
expect_online_failure root-insufficient "${release_base_url}/fixtures/root-insufficient/bundle.json"
expect_online_failure root-gap "${release_base_url}/fixtures/root-gap/bundle.json"
capture_installed_fingerprint "${work_dir}/after-root-negatives.fingerprint"
cmp --silent -- "${work_dir}/before-root-negatives.fingerprint" "${work_dir}/after-root-negatives.fingerprint" ||
	die "invalid root chains mutated installed state"

publish_stable_bundle "${version_four}"
docker exec "${container_name}" /usr/local/bin/mesh-install install-online \
	"${release_base_url}/channels/stable/bundle.json" >"${work_dir}/install-four.json"
installed_four="$(json_get "${work_dir}/install-four.json" release.installed_id)"
assert_active_result "${work_dir}/install-four.json" "${installed_four}" activate
assert_active_install "${installed_four}" "${version_four}"
capture_and_assert_state root-only-rotation "${installed_four}" "${installed_two}" "${installed_four}" 4 1 2

expect_online_failure root-equivocation "${release_base_url}/fixtures/root-equivocation/bundle.json" /usr/local/bin/mesh-install
while (( $(date -u '+%s') < root_two_expires_epoch )); do sleep 0.25; done
expect_online_failure expired-final-root "${release_base_url}/releases/${version_four}/online-bundle.json" /usr/local/bin/mesh-install

publish_stable_bundle "${version_five}"
docker exec "${container_name}" /usr/local/bin/mesh-install install-online \
	"${release_base_url}/channels/stable/bundle.json" >"${work_dir}/install-five.json"
installed_five="$(json_get "${work_dir}/install-five.json" release.installed_id)"
[[ "${installed_five}" =~ ^e00000000000000000002-s00000000000000000001-r[0-9a-f]{16}-a[0-9a-f]{16}$ ]] ||
	die "epoch-2 sequence reset did not produce a canonical identity"
assert_active_result "${work_dir}/install-five.json" "${installed_five}" activate
assert_active_install "${installed_five}" "${version_five}"
capture_and_assert_state epoch-two-reset "${installed_five}" "${installed_four}" "${installed_five}" 1 2 3

capture_installed_fingerprint "${work_dir}/before-revoked-negatives.fingerprint"
expect_online_failure revoked-release "${release_base_url}/fixtures/revoked-release/bundle.json" /usr/local/bin/mesh-install
expect_online_failure old-epoch "${release_base_url}/fixtures/old-epoch/bundle.json" /usr/local/bin/mesh-install
capture_installed_fingerprint "${work_dir}/after-revoked-negatives.fingerprint"
cmp --silent -- "${work_dir}/before-revoked-negatives.fingerprint" "${work_dir}/after-revoked-negatives.fingerprint" ||
	die "revoked or old-epoch metadata mutated installed state"

say "Proving the original offline snapshot path in a second clean systemd host"
docker run --detach \
  --name "${offline_container_name}" \
  --label "mesh.install-smoke.id=${run_id}-offline" \
  --privileged \
  --cgroupns private \
  --security-opt label=disable \
  --tmpfs /run \
  --tmpfs /run/lock \
  "${proof_image}" /sbin/init >/dev/null
offline_container_started=1
wait_for_systemd "${offline_container_name}"
docker exec "${offline_container_name}" mkdir -p \
  /root/mesh-proof/tools /root/mesh-proof/bootstrap /root/mesh-proof/input-1
docker exec "${offline_container_name}" chmod 0700 \
  /root/mesh-proof /root/mesh-proof/tools /root/mesh-proof/bootstrap /root/mesh-proof/input-1
docker cp "${work_dir}/tools/mesh-release" \
  "${offline_container_name}:/root/mesh-proof/tools/mesh-release" >/dev/null
docker cp "${work_dir}/releases/one/mesh-install" \
  "${offline_container_name}:/root/mesh-proof/bootstrap/mesh-install" >/dev/null
docker cp "${work_dir}/releases/one/." \
  "${offline_container_name}:/root/mesh-proof/input-1/" >/dev/null
docker exec "${offline_container_name}" chown -R root:root /root/mesh-proof
docker exec "${offline_container_name}" chmod 0700 \
  /root/mesh-proof/tools/mesh-release /root/mesh-proof/bootstrap/mesh-install
docker exec "${offline_container_name}" /root/mesh-proof/tools/mesh-release assemble-snapshot \
  --output /root/mesh-proof/snapshot-1 \
  --channel-manifest /root/mesh-proof/input-1/channel.json \
  --channel-signature /root/mesh-proof/input-1/channel.signer-a.json \
  --channel-signature /root/mesh-proof/input-1/channel.signer-b.json \
  --release-manifest /root/mesh-proof/input-1/release.json \
  --release-signature /root/mesh-proof/input-1/release.signer-a.json \
  --release-signature /root/mesh-proof/input-1/release.signer-b.json \
  --artifact /root/mesh-proof/input-1/mesh-linux-bundle.tar >/dev/null
docker exec "${offline_container_name}" /root/mesh-proof/bootstrap/mesh-install install \
  /root/mesh-proof/snapshot-1 >"${work_dir}/offline-install-one.json"
expect_json "${work_dir}/offline-install-one.json" first_install true
expect_json "${work_dir}/offline-install-one.json" agent_enabled false
expect_json "${work_dir}/offline-install-one.json" runtime_gate_open false
offline_installed_one="$(json_get "${work_dir}/offline-install-one.json" release.installed_id)"
[[ "${offline_installed_one}" == "${installed_one}" ]] || die "offline regression produced a different installed identity"
docker exec -i "${offline_container_name}" bash -s -- "${offline_installed_one}" <<'CONTAINER'
set -Eeuo pipefail
installed_id="$1"
[[ "$(readlink -- /opt/mesh/current)" == "releases/${installed_id}" ]]
[[ "$(systemctl is-enabled mesh-agent.service 2>/dev/null || true)" == "disabled" ]]
[[ "$(systemctl is-active mesh-agent.service 2>/dev/null || true)" == "inactive" ]]
[[ "$(systemctl is-active mesh-nebula.service 2>/dev/null || true)" == "inactive" ]]
[[ ! -e /var/lib/mesh-installer/runtime.enabled ]]
CONTAINER

say "Proving exact v2-to-v3 migration before offline multi-root catch-up"
docker exec -i "${offline_container_name}" bash -s <<'CONTAINER'
set -Eeuo pipefail
legacy_policy="$(/root/mesh-proof/bootstrap/mesh-install version | python3 -c 'import json,sys; print(json.load(sys.stdin)["installer_legacy_policy_sha256"])')"
python3 - "${legacy_policy}" <<'PY'
import json, os, pathlib, sys
state_path = pathlib.Path('/var/lib/mesh-installer/state.json')
state = json.loads(state_path.read_text())
legacy_policy = sys.argv[1]
def legacy(identity):
    installed = identity['installed_id']
    if not installed.startswith('e') or '-s' not in installed:
        raise SystemExit('unexpected rooted installed id')
    identity['installed_id'] = 's' + installed.split('-s', 1)[1]
    for key in ('release_epoch', 'trusted_root_version', 'trusted_root_sha256', 'installer_bootstrap_root_sha256'):
        identity.pop(key, None)
    return identity
old_id = state['active']['installed_id']
legacy(state['high_water']); legacy(state['active'])
new_id = state['active']['installed_id']
if set(state) != {'schema', 'bootstrap_trust_sha256', 'channel', 'high_water', 'active'}:
    raise SystemExit('unexpected simple v3 state shape for the exact v2 migration fixture')
state = {
    'schema': 'mesh-linux-install-state-v2',
    'trust_policy_sha256': legacy_policy,
    'channel': state['channel'],
    'high_water': state['high_water'],
    'active': state['active'],
}
releases = pathlib.Path('/opt/mesh/releases')
os.rename(releases / old_id, releases / new_id)
temporary_link = pathlib.Path('/opt/mesh/.current-legacy')
os.symlink('releases/' + new_id, temporary_link)
os.replace(temporary_link, '/opt/mesh/current')
raw = (json.dumps(state, separators=(',', ':')) + '\n').encode()
temporary = state_path.with_name('.state-legacy')
fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'wb') as output:
    output.write(raw); output.flush(); os.fsync(output.fileno())
os.replace(temporary, state_path)
for directory in ('/opt/mesh/releases', '/opt/mesh', '/var/lib/mesh-installer'):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
pathlib.Path('/root/mesh-proof/legacy-installed-id').write_text(new_id + '\n')
PY
CONTAINER
offline_legacy_id="$(docker exec "${offline_container_name}" cat /root/mesh-proof/legacy-installed-id)"
docker exec "${offline_container_name}" /root/mesh-proof/bootstrap/mesh-install install \
	/root/mesh-proof/snapshot-1 >"${work_dir}/offline-migration-retry.json"
expect_json "${work_dir}/offline-migration-retry.json" already_active true
expect_json "${work_dir}/offline-migration-retry.json" release.installed_id "${offline_legacy_id}"
docker exec "${offline_container_name}" python3 -c \
	'import json; s=json.load(open("/var/lib/mesh-installer/state.json")); assert s["schema"] == "mesh-linux-install-state-v3"; assert s["active"]["installed_id"].startswith("s")'

docker exec "${offline_container_name}" mkdir -p /root/mesh-proof/input-5
docker exec "${offline_container_name}" chmod 0700 /root/mesh-proof/input-5
docker cp "${work_dir}/releases/five/." "${offline_container_name}:/root/mesh-proof/input-5/" >/dev/null
docker exec "${offline_container_name}" chown -R root:root /root/mesh-proof/input-5
docker exec "${offline_container_name}" /root/mesh-proof/tools/mesh-release assemble-snapshot \
	--output /root/mesh-proof/snapshot-5 \
	--root-update /root/mesh-proof/input-5/root-update-v1-v2.json \
	--root-update /root/mesh-proof/input-5/root-update-v2-v3.json \
	--channel-manifest /root/mesh-proof/input-5/channel.json \
	--channel-signature /root/mesh-proof/input-5/channel.signer-a.json \
	--channel-signature /root/mesh-proof/input-5/channel.signer-b.json \
	--release-manifest /root/mesh-proof/input-5/release.json \
	--release-signature /root/mesh-proof/input-5/release.signer-a.json \
	--release-signature /root/mesh-proof/input-5/release.signer-b.json \
	--artifact /root/mesh-proof/input-5/mesh-linux-bundle.tar >/dev/null
docker exec "${offline_container_name}" /root/mesh-proof/bootstrap/mesh-install install \
	/root/mesh-proof/snapshot-5 >"${work_dir}/offline-multi-root.json"
expect_json "${work_dir}/offline-multi-root.json" release.release_epoch 2
expect_json "${work_dir}/offline-multi-root.json" release.trusted_root_version 3
expect_json "${work_dir}/offline-multi-root.json" previous.installed_id "${offline_legacy_id}"
docker exec -i "${offline_container_name}" bash -s <<'CONTAINER'
set -Eeuo pipefail
[[ -f /var/lib/mesh-installer/trust/roots/00000000000000000002.root-update.json ]]
[[ -f /var/lib/mesh-installer/trust/roots/00000000000000000003.root-update.json ]]
python3 - <<'PY'
import json
state = json.load(open('/var/lib/mesh-installer/state.json'))
assert state['schema'] == 'mesh-linux-install-state-v3'
assert state['high_water']['release_epoch'] == 2
assert state['high_water']['sequence'] == 1
assert state['high_water']['trusted_root_version'] == 3
PY
CONTAINER
docker rm --force --volumes -- "${offline_container_name}" >/dev/null
offline_container_started=0

if [[ "${ui_guided_package_smoke}" == "1" ]]; then
  say "Starting two fresh packaged systemd hosts on the isolated proof underlay"
  if ! docker run --detach \
    --name "${ui_lighthouse_container_name}" \
    --label "mesh.install-smoke.id=${run_id}-ui-lighthouse" \
    --network "${proof_network_name}" \
    --ip "${proof_lighthouse_ip}" \
    --privileged \
    --cgroupns private \
    --security-opt label=disable \
    --tmpfs /run \
    --tmpfs /run/lock \
    "${proof_image}" /sbin/init >/dev/null; then
    if [[ "$(docker inspect --format '{{index .Config.Labels "mesh.install-smoke.id"}}' "${ui_lighthouse_container_name}" 2>/dev/null || true)" == "${run_id}-ui-lighthouse" ]]; then
      ui_lighthouse_container_started=1
    fi
    die "could not start the fresh UI-guided lighthouse host"
  fi
  ui_lighthouse_container_started=1
  if ! docker run --detach \
    --name "${ui_member_container_name}" \
    --label "mesh.install-smoke.id=${run_id}-ui-member" \
    --network "${proof_network_name}" \
    --ip "${proof_member_ip}" \
    --privileged \
    --cgroupns private \
    --security-opt label=disable \
    --tmpfs /run \
    --tmpfs /run/lock \
    "${proof_image}" /sbin/init >/dev/null; then
    if [[ "$(docker inspect --format '{{index .Config.Labels "mesh.install-smoke.id"}}' "${ui_member_container_name}" 2>/dev/null || true)" == "${run_id}-ui-member" ]]; then
      ui_member_container_started=1
    fi
    die "could not start the fresh UI-guided member host"
  fi
  ui_member_container_started=1

  ui_output_dir="${work_dir}/ui-guided-package"
  mkdir -p -- "${ui_output_dir}"
  chmod 0700 "${ui_output_dir}"
  for ui_host in "${ui_lighthouse_container_name}" "${ui_member_container_name}"; do
    wait_for_systemd "${ui_host}"
    docker exec "${ui_host}" test -c /dev/net/tun || die "fresh UI-guided host has no TUN device"
    docker exec "${ui_host}" bash -lc '
      for command in curl ping sudo systemctl; do
        command -v -- "${command}" >/dev/null || exit 1
      done
      test ! -e /usr/local/bin/mesh-install
      test ! -e /var/lib/mesh-installer
      mkdir -p /root/mesh-proof /etc/pki/ca-trust/source/anchors
      chmod 0700 /root/mesh-proof
    ' || die "fresh UI-guided host did not preserve the clean package boundary"
    docker cp "${work_dir}/tls/ca.crt" \
      "${ui_host}:/etc/pki/ca-trust/source/anchors/mesh-install-smoke-ca.crt" >/dev/null
    docker cp "${work_dir}/releases/one/mesh-install" \
      "${ui_host}:/root/mesh-proof/mesh-install" >/dev/null
    docker exec "${ui_host}" chown root:root \
      /etc/pki/ca-trust/source/anchors/mesh-install-smoke-ca.crt \
      /root/mesh-proof/mesh-install
    docker exec "${ui_host}" chmod 0444 /etc/pki/ca-trust/source/anchors/mesh-install-smoke-ca.crt
    docker exec "${ui_host}" chmod 0700 /root/mesh-proof/mesh-install
    docker exec "${ui_host}" update-ca-trust
  done

  proof_control_url="https://${proof_control_ip}:18081"
  say "Starting the browser-facing TLS control plane on ${proof_control_url}"
  docker exec "${container_name}" systemd-run \
    --unit=mesh-proof-ui-control.service \
    --property=Type=simple \
    --property=WorkingDirectory=/root/mesh-proof \
    --property=Environment=NEBULA_CERT_BINARY=/usr/local/bin/nebula-cert \
    /root/mesh-proof/tools/mesh-server \
    --dev \
    --listen 0.0.0.0:18081 \
    --tls-cert /root/mesh-proof/tls/server.crt \
    --tls-key /root/mesh-proof/tls/server.key \
    --public-url "${proof_control_url}" \
    --linux-install-bundle-url "${release_base_url}/channels/stable/bundle.json" \
    --data-dir /root/mesh-proof/ui-control >/dev/null
  for attempt in {1..120}; do
    if curl --silent --show-error --fail --noproxy '*' \
      --cacert "${work_dir}/tls/ca.crt" \
      --connect-timeout 1 --max-time 1 --output /dev/null \
      "${proof_control_url}/healthz" 2>/dev/null; then
      break
    fi
    if [[ "${attempt}" == "120" ]]; then
      docker exec "${container_name}" journalctl --no-pager -u mesh-proof-ui-control.service >&2 || true
      die "browser-facing TLS control plane did not become ready"
    fi
    sleep 0.25
  done
  docker cp "${container_name}:/root/mesh-proof/ui-control/admin.token" \
    "${ui_output_dir}/admin.token" >/dev/null
  chmod 0600 "${ui_output_dir}/admin.token"

  say "Authoring both fresh hosts in Firefox, then executing the displayed package lifecycle"
  ui_package_started_epoch="$(date -u '+%s')"
  python3 "${repo_root}/scripts/ui_guided_author.py" \
    --server-url "${proof_control_url}" \
    --allow-private-https \
    --admin-token-file "${ui_output_dir}/admin.token" \
    --output-dir "${ui_output_dir}" \
    --network-name package-proof \
    --cidr 10.232.0.0/24 \
    --lighthouse-name package-lighthouse \
    --lighthouse-endpoint "${ui_lighthouse_container_name}:4242" \
    --member-name package-member

  python3 - \
    "${ui_output_dir}/ui-guide.json" \
    "${release_base_url}/channels/stable/bundle.json" \
    "${proof_control_url}" <<'PY'
import json
import pathlib
import sys

guide = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
bundle_url, control_url = sys.argv[2:]
expected_install = f"sudo ./mesh-install install-online '{bundle_url}'"
expected_enroll = (
    "read -rsp 'Enrollment token: ' MESH_TOKEN_INPUT && printf '\\n' && "
    "printf '%s\\n' \"$MESH_TOKEN_INPUT\" | sudo /usr/local/bin/meshctl enroll "
    f"--server '{control_url}' --token-file - --state /var/lib/mesh-agent/state.json "
    "--output /var/lib/mesh-agent/nebula --nebula /usr/local/bin/nebula "
    "--nebula-cert /usr/local/bin/nebula-cert; MESH_ENROLL_STATUS=$?; "
    "unset MESH_TOKEN_INPUT; test \"$MESH_ENROLL_STATUS\" -eq 0"
)
if guide != {
    "schema": "mesh-ui-guided-author-result-v2",
    "elapsed_milliseconds": guide.get("elapsed_milliseconds"),
    "pending_readiness_verified": True,
    "install_command": expected_install,
    "enroll_command": expected_enroll,
    "activate_command": "sudo /usr/local/bin/mesh-install activate",
}:
    raise SystemExit("browser guide did not contain the exact supported package lifecycle")
if not isinstance(guide["elapsed_milliseconds"], int) or guide["elapsed_milliseconds"] < 0:
    raise SystemExit("browser guide elapsed time is invalid")
PY

  ui_install_command="$(json_get "${ui_output_dir}/ui-guide.json" install_command)"
  ui_enroll_command="$(json_get "${ui_output_dir}/ui-guide.json" enroll_command)"
  ui_activate_command="$(json_get "${ui_output_dir}/ui-guide.json" activate_command)"
  for ui_role in lighthouse member; do
    if [[ "${ui_role}" == "lighthouse" ]]; then
      ui_host="${ui_lighthouse_container_name}"
      ui_created="${ui_output_dir}/lighthouse-created.json"
    else
      ui_host="${ui_member_container_name}"
      ui_created="${ui_output_dir}/member-created.json"
    fi
    docker exec --workdir /root/mesh-proof "${ui_host}" bash -lc "${ui_install_command}" \
      >"${ui_output_dir}/${ui_role}-install.json"
    expect_json "${ui_output_dir}/${ui_role}-install.json" release.release_epoch 2
    expect_json "${ui_output_dir}/${ui_role}-install.json" release.sequence 1
    expect_json "${ui_output_dir}/${ui_role}-install.json" release.trusted_root_version 3
    ui_enrollment_token="$(json_get "${ui_created}" enrollment_token)"
    [[ "${ui_enrollment_token}" =~ ^[A-Za-z0-9_-]{43}$ ]] || die "browser returned an invalid ${ui_role} enrollment token"
    if [[ "${ui_role}" == "lighthouse" ]]; then
      docker exec "${ui_host}" ip route add blackhole 10.232.0.0/24 metric 42419 ||
        die "could not inject the pre-enrollment route conflict"
      if printf '%s\n' "${ui_enrollment_token}" | \
        docker exec -i "${ui_host}" bash -lc "${ui_enroll_command}" \
        >"${ui_output_dir}/${ui_role}-preflight-blocked.log" 2>&1; then
        docker exec "${ui_host}" ip route del blackhole 10.232.0.0/24 metric 42419 >/dev/null 2>&1 || true
        die "pre-enrollment route conflict did not block the fresh lighthouse"
      fi
      rg -q 'pre-enrollment route conflict' "${ui_output_dir}/${ui_role}-preflight-blocked.log" ||
        die "pre-enrollment route failure was not explicit"
      docker exec "${ui_host}" test ! -e /var/lib/mesh-agent/state.json
      docker exec "${ui_host}" test ! -e /var/lib/mesh-agent/state.json.enrollment.json
      docker exec "${ui_host}" ip route del blackhole 10.232.0.0/24 metric 42419 ||
        die "could not remove the pre-enrollment route conflict"
    else
      docker exec "${ui_host}" sh -c \
        "install -m 0600 /etc/resolv.conf /run/mesh-preflight-resolv.conf && printf 'nameserver 127.0.0.1\\noptions attempts:1 timeout:1\\n' > /etc/resolv.conf" ||
        die "could not inject the pre-enrollment DNS failure"
      if printf '%s\n' "${ui_enrollment_token}" | \
        docker exec -i "${ui_host}" bash -lc "${ui_enroll_command}" \
        >"${ui_output_dir}/${ui_role}-preflight-blocked.log" 2>&1; then
        docker exec "${ui_host}" sh -c \
          'cp /run/mesh-preflight-resolv.conf /etc/resolv.conf && rm -f /run/mesh-preflight-resolv.conf' >/dev/null 2>&1 || true
        die "pre-enrollment DNS failure did not block the fresh member"
      fi
      rg -q 'pre-enrollment DNS check failed' "${ui_output_dir}/${ui_role}-preflight-blocked.log" ||
        die "pre-enrollment DNS failure was not explicit"
      docker exec "${ui_host}" test ! -e /var/lib/mesh-agent/state.json
      docker exec "${ui_host}" test ! -e /var/lib/mesh-agent/state.json.enrollment.json
      docker exec "${ui_host}" sh -c \
        'cp /run/mesh-preflight-resolv.conf /etc/resolv.conf && rm -f /run/mesh-preflight-resolv.conf' ||
        die "could not restore DNS after the pre-enrollment failure"
    fi
    printf '%s\n' "${ui_enrollment_token}" | \
      docker exec -i "${ui_host}" bash -lc "${ui_enroll_command}" \
      >"${ui_output_dir}/${ui_role}-enroll.log" 2>&1
    rg -q 'Pre-enrollment route and DNS checks passed' "${ui_output_dir}/${ui_role}-enroll.log" ||
      die "successful ${ui_role} enrollment did not prove local pre-enrollment checks"
    unset ui_enrollment_token
    docker exec "${ui_host}" bash -lc "${ui_activate_command}" \
      >"${ui_output_dir}/${ui_role}-activate.json"
    expect_json "${ui_output_dir}/${ui_role}-activate.json" operation activate
    docker exec "${ui_host}" systemctl is-active --quiet mesh-agent.service
    docker exec "${ui_host}" systemctl is-active --quiet mesh-nebula.service
  done
  unset ui_install_command ui_enroll_command ui_activate_command

  ui_lighthouse_overlay_ip="$(json_get "${ui_output_dir}/lighthouse-created.json" node.ip)"
  [[ "${ui_lighthouse_overlay_ip}" =~ ^10\.232\.0\.[0-9]{1,3}$ ]] || die "browser returned an invalid lighthouse overlay address"
  for attempt in {1..120}; do
    if docker exec "${ui_member_container_name}" ping -c 1 -W 1 "${ui_lighthouse_overlay_ip}" \
      >"${ui_output_dir}/overlay-establish.log" 2>&1; then
      break
    fi
    if (( $(date -u '+%s') - ui_package_started_epoch > 300 )); then
      die "UI-guided package lifecycle exceeded five minutes before authenticated packet delivery"
    fi
    sleep 0.25
  done
  docker exec "${ui_member_container_name}" ping -c 2 -W 2 "${ui_lighthouse_overlay_ip}" \
    >"${ui_output_dir}/overlay-proof.log"
  ui_package_elapsed_seconds="$(( $(date -u '+%s') - ui_package_started_epoch ))"
  (( ui_package_elapsed_seconds >= 0 && ui_package_elapsed_seconds <= 300 )) ||
    die "UI-guided package lifecycle exceeded five minutes"
  docker exec "${ui_lighthouse_container_name}" systemctl is-active --quiet mesh-nebula.service
  docker exec "${ui_member_container_name}" systemctl is-active --quiet mesh-nebula.service
  python3 - \
    "${proof_control_url}" \
    "${ui_output_dir}/admin.token" \
    "${work_dir}/tls/ca.crt" \
    "${ui_output_dir}/lighthouse-created.json" \
    "${ui_member_container_name}" <<'PY'
import json
import pathlib
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

control_url, token_path, ca_path, lighthouse_path, member_container = sys.argv[1:]
token = pathlib.Path(token_path).read_text(encoding="ascii").rstrip("\n")
lighthouse = json.loads(pathlib.Path(lighthouse_path).read_text(encoding="utf-8"))["node"]

def fetch_readiness():
    completed = subprocess.run(
        [
            "curl", "--silent", "--show-error", "--noproxy", "*", "--max-time", "8", "--cacert", ca_path,
            "--config", "-", "--write-out", "\n%{http_code}",
            f"{control_url}/api/v1/networks/{lighthouse['network_id']}/readiness",
        ],
        input=f'header = "Authorization: Bearer {token}"\n',
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit("active readiness authenticated transport failed")
    body, separator, status = completed.stdout.rpartition("\n")
    if separator == "" or status != "200":
        raise SystemExit("active readiness did not return HTTP 200")
    return json.loads(body)

def wait_for_readiness(predicate, timeout, failure):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = fetch_readiness()
        if predicate(last):
            return last
        time.sleep(0.5)
    raise SystemExit(failure)

def runtime_readiness_pass(value):
    checks = value.get("checks", {})
    return (
        checks.get("public_udp_reachability", {}).get("status") == "pass"
        and checks.get("client_route_overlap", {}).get("status") == "pass"
        and checks.get("member_dns_resolution", {}).get("status") == "pass"
    )

report = wait_for_readiness(
    runtime_readiness_pass,
    60,
    "fresh packaged node evidence did not verify routes and public UDP within 60 seconds",
)
checks = report.get("checks", {})
redundancy = checks.get("lighthouse_redundancy", {})
topology = checks.get("topology_diversity", {})
dns = checks.get("dns_resolution", {})
udp = checks.get("public_udp_reachability", {})
routes = checks.get("client_route_overlap", {})
member_dns = checks.get("member_dns_resolution", {})
projected = report.get("lighthouses", [])
sites = report.get("sites", [])
if (
    report.get("schema") != "mesh-network-readiness-v6"
    or report.get("overall") != "verification_required"
    or checks.get("managed_route_overlap", {}).get("status") != "pass"
    or routes.get("status") != "pass"
    or routes.get("evidence_source") != "authenticated_node_route_inventory"
    or routes.get("observed_nodes") != 2
    or routes.get("required_nodes") != 2
    or routes.get("overlapping_nodes") != 0
    or routes.get("freshness_window_seconds") != 90
    or not isinstance(routes.get("evidence_at"), str)
    or member_dns.get("status") != "pass"
    or member_dns.get("evidence_source") != "authenticated_member_dns_resolution"
    or member_dns.get("observed_members") != 1
    or member_dns.get("required_members") != 1
    or member_dns.get("failing_members") != 0
    or member_dns.get("dns_names") != 1
    or member_dns.get("freshness_window_seconds") != 90
    or not isinstance(member_dns.get("evidence_at"), str)
    or udp.get("status") != "pass"
    or udp.get("evidence_source") != "authenticated_member_active_probe"
    or not isinstance(udp.get("observed_members"), int)
    or udp.get("observed_members") < 1
    or udp.get("required_members") != 1
    or udp.get("verified_lighthouses") != 1
    or udp.get("required_lighthouses") != 1
    or udp.get("freshness_window_seconds") != 30
    or not isinstance(udp.get("evidence_at"), str)
    or redundancy.get("status") != "warning"
    or redundancy.get("configured_lighthouses") != 1
    or redundancy.get("active_lighthouses") != 1
    or redundancy.get("required_lighthouses") != 2
    or topology.get("status") != "warning"
    or topology.get("evidence_source") != "control_inventory"
    or topology.get("configured_sites") != 2
    or topology.get("active_sites") != 2
    or topology.get("active_nodes") != 2
    or topology.get("assigned_active_nodes") != 2
    or topology.get("active_lighthouses") != 1
    or topology.get("assigned_active_lighthouses") != 1
    or topology.get("distinct_lighthouse_failure_domains") != 1
    or topology.get("required_lighthouse_failure_domains") != 2
    or dns.get("status") != "pass"
    or dns.get("dns_names") != 1
    or dns.get("resolved_dns_names") != 1
    or dns.get("unresolved_dns_names") != 0
    or len(projected) != 1
    or projected[0].get("id") != lighthouse["id"]
    or projected[0].get("lifecycle_status") != "active"
    or projected[0].get("site") != "proof-edge"
    or projected[0].get("failure_domain") != "proof-edge-a"
    or projected[0].get("endpoint_host_type") != "dns"
    or projected[0].get("dns_resolution") != "resolved"
    or not isinstance(projected[0].get("resolved_address_count"), int)
    or projected[0].get("resolved_address_count") < 1
    or [site.get("name") for site in sites] != ["proof-client", "proof-edge"]
    or any(site.get("configured_nodes") != 1 or site.get("active_nodes") != 1 for site in sites)
):
    raise SystemExit("active readiness did not preserve configured, topology, DNS, redundancy, route, and authenticated UDP evidence boundaries")
try:
    generated = datetime.fromisoformat(report["generated_at"].replace("Z", "+00:00"))
    evidence = datetime.fromisoformat(udp["evidence_at"].replace("Z", "+00:00"))
    route_evidence = datetime.fromisoformat(routes["evidence_at"].replace("Z", "+00:00"))
    member_dns_evidence = datetime.fromisoformat(member_dns["evidence_at"].replace("Z", "+00:00"))
except (KeyError, TypeError, ValueError) as error:
    raise SystemExit("active readiness returned an invalid evidence timestamp") from error
if generated.tzinfo is None or evidence.tzinfo is None or generated > datetime.now(timezone.utc) + timedelta(seconds=5) or evidence > generated or (generated - evidence).total_seconds() > 30:
    raise SystemExit("active readiness returned stale or future UDP evidence")
if route_evidence.tzinfo is None or route_evidence > generated or (generated - route_evidence).total_seconds() > 90:
    raise SystemExit("active readiness returned stale or future route evidence")
if member_dns_evidence.tzinfo is None or member_dns_evidence > generated or (generated - member_dns_evidence).total_seconds() > 90:
    raise SystemExit("active readiness returned stale or future member DNS evidence")
encoded = json.dumps(report, sort_keys=True, separators=(",", ":"))
for forbidden in ('"target_ip"', '"local_ip"', '"plan_sha256"', '"nonce"', '"packet"', '"socket_error"', '"interface_name"', '"route_prefix"', '"gateway"', '"route_table"', '"resolved_addresses"', '"resolver_error"', '"resolver_config"'):
    if forbidden in encoded:
        raise SystemExit("active readiness exposed private probe detail")

# Prove the packaged kernel observer detects and later clears a real route
# conflict without disclosing the injected route. A broader /8 is selected so
# the exact Nebula /24 remains the packet path while readiness blocks.
default_result = subprocess.run(
    ["docker", "exec", member_container, "ip", "-j", "-4", "route", "show", "default"],
    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
)
try:
    defaults = json.loads(default_result.stdout)
except (TypeError, ValueError) as error:
    raise SystemExit("packaged member default route inventory was invalid") from error
if default_result.returncode != 0 or len(defaults) != 1 or not isinstance(defaults[0].get("gateway"), str) or not isinstance(defaults[0].get("dev"), str):
    raise SystemExit("packaged member did not expose one usable default route")
gateway, device = defaults[0]["gateway"], defaults[0]["dev"]
add_result = subprocess.run(
    ["docker", "exec", member_container, "ip", "route", "add", "10.0.0.0/8", "via", gateway, "dev", device, "metric", "42420"],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
)
if add_result.returncode != 0:
    raise SystemExit("could not inject the packaged route-overlap fixture")
dns_failure_result = subprocess.run(
    [
        "docker", "exec", member_container, "sh", "-c",
        "install -m 0600 /etc/resolv.conf /run/mesh-proof-resolv.conf && printf 'nameserver 127.0.0.1\\noptions attempts:1 timeout:1\\n' > /etc/resolv.conf",
    ],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
)
if dns_failure_result.returncode != 0:
    subprocess.run(
        ["docker", "exec", member_container, "ip", "route", "del", "10.0.0.0/8", "via", gateway, "dev", device, "metric", "42420"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    raise SystemExit("could not inject the packaged member-DNS failure fixture")
try:
    conflicted = wait_for_readiness(
        lambda value: (
            value.get("checks", {}).get("client_route_overlap", {}).get("status") == "blocked"
            and value.get("checks", {}).get("member_dns_resolution", {}).get("status") == "blocked"
        ),
        75,
        "packaged route-overlap and member-DNS fixtures were not detected within 75 seconds",
    )
    conflict_routes = conflicted.get("checks", {}).get("client_route_overlap", {})
    conflict_dns = conflicted.get("checks", {}).get("member_dns_resolution", {})
    if (
        conflicted.get("overall") != "blocked"
        or conflict_routes.get("evidence_source") != "authenticated_node_route_inventory"
        or conflict_routes.get("observed_nodes") != 2
        or conflict_routes.get("required_nodes") != 2
        or conflict_routes.get("overlapping_nodes") != 1
        or not isinstance(conflict_routes.get("evidence_at"), str)
        or conflict_dns.get("evidence_source") != "authenticated_member_dns_resolution"
        or conflict_dns.get("observed_members") != 1
        or conflict_dns.get("required_members") != 1
        or conflict_dns.get("failing_members") != 1
        or conflict_dns.get("dns_names") != 1
        or not isinstance(conflict_dns.get("evidence_at"), str)
    ):
        raise SystemExit("packaged route and member-DNS conflicts did not preserve the strict blocked evidence contract")
    conflict_encoded = json.dumps(conflicted, sort_keys=True, separators=(",", ":"))
    for forbidden in ('"10.0.0.0/8"', '"interface_name"', '"route_prefix"', '"gateway"', '"route_table"'):
        if forbidden in conflict_encoded:
            raise SystemExit("packaged route conflict exposed private route detail")
finally:
    restore_dns_result = subprocess.run(
        [
            "docker", "exec", member_container, "sh", "-c",
            "test -f /run/mesh-proof-resolv.conf && cp /run/mesh-proof-resolv.conf /etc/resolv.conf && rm -f /run/mesh-proof-resolv.conf",
        ],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    delete_result = subprocess.run(
        ["docker", "exec", member_container, "ip", "route", "del", "10.0.0.0/8", "via", gateway, "dev", device, "metric", "42420"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if restore_dns_result.returncode != 0 or delete_result.returncode != 0:
        raise SystemExit("could not remove the packaged route-overlap or member-DNS fixture")

report = wait_for_readiness(
    runtime_readiness_pass,
    75,
    "packaged route evidence did not recover after fixture removal within 75 seconds",
)
recovered_routes = report.get("checks", {}).get("client_route_overlap", {})
if recovered_routes.get("observed_nodes") != 2 or recovered_routes.get("required_nodes") != 2 or recovered_routes.get("overlapping_nodes") != 0:
    raise SystemExit("packaged route recovery did not restore complete no-overlap evidence")
recovered_dns = report.get("checks", {}).get("member_dns_resolution", {})
if recovered_dns.get("observed_members") != 1 or recovered_dns.get("required_members") != 1 or recovered_dns.get("failing_members") != 0:
    raise SystemExit("packaged route recovery did not preserve complete member DNS evidence")
token = ""
PY
  docker exec "${ui_member_container_name}" ping -c 1 -W 2 "${ui_lighthouse_overlay_ip}" \
    >"${ui_output_dir}/overlay-after-route-recovery.log"
  ui_package_elapsed_seconds="$(( $(date -u '+%s') - ui_package_started_epoch ))"
  (( ui_package_elapsed_seconds >= 0 && ui_package_elapsed_seconds <= 300 )) ||
    die "UI-guided package lifecycle exceeded five minutes before authenticated readiness evidence"
  say "PASS: two browser-authored fresh packaged hosts blocked pre-enrollment route and DNS failures without consuming their tokens, then reached authenticated overlay traffic, published route, member-DNS, and UDP readiness evidence, blocked post-enrollment route and DNS failures, and recovered in ${ui_package_elapsed_seconds} seconds"
fi

say "PASS: independently anchored bootstrap authorization, versioned-root online/offline install, root-only rotation, epoch reset, revocation rejection, expired-intermediate catch-up, v2 migration, activation, state race, rollback, recovery, cleanup, gates, units, and exact process provenance verified"
