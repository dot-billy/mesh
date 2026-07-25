#!/usr/bin/env bash
set -euo pipefail

umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
observer_dir="$repo_root/third_party/nebula-observer"
lock_file="$repo_root/third_party/nebula/v1.10.3.lock.json"
fixture_dir="$observer_dir/fixtures"
module_path=github.com/slackhq/nebula
module_version=v1.10.3
module_sum='h1:EstYj8ODEcv6T0R9X5BVq1zgWZnyU5gtPzk99QF1PMU='
upstream_commit=f573e8a26695278f9d71587390fbfe0d0933aa21
go_toolchain=go1.26.5

for required_command in go git python3 sha256sum find sort xargs awk grep cp chmod mktemp; do
	if ! command -v "$required_command" >/dev/null 2>&1; then
		echo "missing required command: $required_command" >&2
		exit 1
	fi
done

scratch=$(mktemp -d /tmp/mesh-nebula-observer-smoke.XXXXXX)
source_copy="$scratch/nebula"
mkdir -p "$source_copy" "$scratch/bin" "$scratch/go-build-cache" "$scratch/go-tmp"
cleanup() {
	chmod -R u+w "$scratch" 2>/dev/null || true
	rm -rf -- "$scratch"
}
trap cleanup EXIT HUP INT TERM

export GOTOOLCHAIN="$go_toolchain"
export GOPROXY=off
export GOFLAGS=-mod=readonly
export GOCACHE="$scratch/go-build-cache"
export GOTMPDIR="$scratch/go-tmp"

if [ "$(go env GOVERSION)" != "$go_toolchain" ]; then
	echo "resolved Go toolchain does not match $go_toolchain" >&2
	exit 1
fi

if ! grep -Fqx "$module_path $module_version $module_sum" "$repo_root/go.sum"; then
	echo "Mesh go.sum does not contain the reviewed Nebula module checksum" >&2
	exit 1
fi

python3 - "$lock_file" "$module_path" "$module_version" "$upstream_commit" <<'PY'
import json
import sys

path, expected_module, expected_version, expected_commit = sys.argv[1:]
with open(path, "rb") as source:
    lock = json.load(source)
expected = {
    "schema": "mesh.nebula-dependency-lock.v1",
    "repository": "https://github.com/slackhq/nebula",
    "release_tag": expected_version,
    "commit": expected_commit,
    "module": expected_module,
    "version": expected_version,
}
for key, value in expected.items():
    if lock.get(key) != value:
        raise SystemExit("reviewed Nebula lock identity mismatch")
PY

module_metadata=$(cd "$repo_root" && go list -m -json "$module_path")
module_metadata_file="$scratch/module-metadata.json"
printf '%s\n' "$module_metadata" > "$module_metadata_file"
module_dir=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], "rb")).get("Dir", ""))' "$module_metadata_file")
python3 - "$module_metadata_file" "$module_path" "$module_version" "$module_sum" <<'PY'
import json
import sys

metadata_path, expected_path, expected_version, expected_sum = sys.argv[1:]
with open(metadata_path, "rb") as source:
    metadata = json.load(source)
if (
    metadata.get("Path") != expected_path
    or metadata.get("Version") != expected_version
    or metadata.get("Sum") != expected_sum
    or not metadata.get("Dir")
):
    raise SystemExit("cached Nebula module identity mismatch")
PY
if [ ! -d "$module_dir" ]; then
	echo "reviewed Nebula module is not already present in the module cache" >&2
	exit 1
fi

(cd "$module_dir" && sha256sum --check --strict "$observer_dir/base-files.sha256")

fingerprint_tree() {
	tree_root=$1
	(
		cd "$tree_root"
		find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
		find . -printf '%P %y %m %u %g %s\n' | LC_ALL=C sort
	) | sha256sum | awk '{print $1}'
}

module_fingerprint_before=$(fingerprint_tree "$module_dir")
cp -a -- "$module_dir/." "$source_copy/"
chmod -R u+w "$source_copy"
(cd "$source_copy" && sha256sum --check --strict "$observer_dir/base-files.sha256")

patch_count=0
while IFS= read -r patch_name; do
	if [ -z "$patch_name" ] || [ ! -f "$observer_dir/$patch_name" ]; then
		echo "invalid observer patch series entry" >&2
		exit 1
	fi
	git -C "$source_copy" apply --check --whitespace=error-all "$observer_dir/$patch_name"
	git -C "$source_copy" apply --whitespace=error-all "$observer_dir/$patch_name"
	patch_count=$((patch_count + 1))
done < "$observer_dir/series"
if [ "$patch_count" -ne 4 ]; then
	echo "unexpected observer patch count: $patch_count" >&2
	exit 1
fi

export MESH_NEBULA_OBSERVER_FIXTURES="$fixture_dir"
(cd "$source_copy" && go test ./...)
(cd "$source_copy" && go test -race -count=1 -run RuntimeObserver ./)

(cd "$repo_root" && go build -trimpath -buildvcs=false -o "$scratch/bin/mesh-deps" ./cmd/mesh-deps)
for architecture in amd64 arm64; do
	stage="$scratch/stage-linux-$architecture"
	"$scratch/bin/mesh-deps" build-nebula-observer --arch "$architecture" --output-dir "$stage"
	echo "locked linux/$architecture nebula $(sha256sum "$stage/nebula" | awk '{print $1}')"
	echo "locked linux/$architecture nebula-cert $(sha256sum "$stage/nebula-cert" | awk '{print $1}')"
done

module_fingerprint_after=$(fingerprint_tree "$module_dir")
if [ "$module_fingerprint_before" != "$module_fingerprint_after" ]; then
	echo "Nebula module cache source changed during smoke" >&2
	exit 1
fi

echo "Nebula observer source/build smoke passed for $module_version ($upstream_commit)"
