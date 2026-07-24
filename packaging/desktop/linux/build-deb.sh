#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 PATH_TO_FLUTTER_LINUX_BUNDLE" >&2
  exit 2
fi

bundle_dir="$(realpath "$1")"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
package_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for required_file in \
  mesh_desktop \
  lib/libapp.so \
  lib/libflutter_linux_gtk.so \
  lib/libflutter_secure_storage_linux_plugin.so \
  lib/liburl_launcher_linux_plugin.so \
  data/icudtl.dat \
  data/flutter_assets/NOTICES.Z; do
  if [[ ! -f "$bundle_dir/$required_file" ]]; then
    echo "invalid Mesh desktop Linux bundle: missing $required_file" >&2
    exit 1
  fi
done
if [[ ! -x "$bundle_dir/mesh_desktop" ]]; then
  echo "invalid Mesh desktop Linux bundle: executable is not executable" >&2
  exit 1
fi

version="$(
  sed -n 's/^version:[[:space:]]*//p' "$repo_root/desktop/pubspec.yaml" |
    head -n 1 |
    cut -d+ -f1
)"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.]+)?$ ]]; then
  echo "invalid desktop version: $version" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64)
    deb_arch="amd64"
    expected_elf_machine="Advanced Micro Devices X86-64"
    ;;
  aarch64 | arm64)
    deb_arch="arm64"
    expected_elf_machine="AArch64"
    ;;
  *)
    echo "unsupported Debian architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

for binary in "$bundle_dir/mesh_desktop" "$bundle_dir"/lib/*.so; do
  machine="$(
    readelf --file-header "$binary" |
      sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p'
  )"
  if [[ "$machine" != "$expected_elf_machine" ]]; then
    echo "bundle architecture mismatch for $binary: $machine" >&2
    exit 1
  fi
done

temp_root="$(realpath "${TMPDIR:-/tmp}")"
stage_prefix="$temp_root/mesh-desktop-deb."
stage_dir="$(mktemp -d "${stage_prefix}XXXXXXXX")"
cleanup() {
  if [[ "$stage_dir" == "$stage_prefix"* && -d "$stage_dir" ]]; then
    rm -rf -- "$stage_dir"
  fi
}
trap cleanup EXIT

chmod 0755 "$stage_dir"
install -d -m 0755 \
  "$stage_dir/DEBIAN" \
  "$stage_dir/opt/mesh-desktop" \
  "$stage_dir/usr/bin" \
  "$stage_dir/usr/share/doc/mesh-desktop" \
  "$stage_dir/usr/share/applications" \
  "$stage_dir/usr/share/icons/hicolor/scalable/apps" \
  "$stage_dir/usr/share/metainfo"
cp -a "$bundle_dir/." "$stage_dir/opt/mesh-desktop/"
ln -s /opt/mesh-desktop/mesh_desktop "$stage_dir/usr/bin/mesh-desktop"
install -m 0644 "$package_root/io.rw0.mesh.desktop.desktop" \
  "$stage_dir/usr/share/applications/io.rw0.mesh.desktop.desktop"
install -m 0644 "$package_root/io.rw0.mesh.desktop.svg" \
  "$stage_dir/usr/share/icons/hicolor/scalable/apps/io.rw0.mesh.desktop.svg"
install -m 0644 "$package_root/io.rw0.mesh.desktop.metainfo.xml" \
  "$stage_dir/usr/share/metainfo/io.rw0.mesh.desktop.metainfo.xml"
install -m 0644 "$repo_root/LICENSE" \
  "$stage_dir/usr/share/doc/mesh-desktop/LICENSE"
install -m 0644 "$repo_root/THIRD_PARTY_NOTICES.md" \
  "$stage_dir/usr/share/doc/mesh-desktop/THIRD_PARTY_NOTICES.md"
sed \
  -e "s/@VERSION@/$version/g" \
  -e "s/@ARCH@/$deb_arch/g" \
  "$package_root/control.in" >"$stage_dir/DEBIAN/control"
chmod 0644 "$stage_dir/DEBIAN/control"
find "$stage_dir" -type d -exec chmod 0755 {} +

output_dir="$repo_root/artifacts/desktop"
install -d "$output_dir"
output="$output_dir/mesh-desktop_${version}_${deb_arch}.deb"
fakeroot dpkg-deb --build --root-owner-group "$stage_dir" "$output"

invalid_directory_mode=0
invalid_owner=0
while IFS= read -r entry; do
  read -r mode owner _ <<<"$entry"
  if [[ "${mode:0:1}" == "d" && "$mode" != "drwxr-xr-x" ]]; then
    echo "invalid packaged directory mode: $entry" >&2
    invalid_directory_mode=1
  fi
  if [[ "$owner" != "root/root" ]]; then
    echo "invalid packaged owner: $entry" >&2
    invalid_owner=1
  fi
done < <(dpkg-deb --contents "$output")
if [[ "$invalid_directory_mode" -ne 0 || "$invalid_owner" -ne 0 ]]; then
  exit 1
fi

if [[ "$(dpkg-deb --field "$output" Package)" != "mesh-desktop" ||
      "$(dpkg-deb --field "$output" Version)" != "$version" ||
      "$(dpkg-deb --field "$output" Architecture)" != "$deb_arch" ]]; then
  echo "Debian package metadata validation failed" >&2
  exit 1
fi

if ar t "$output" | awk '/^_gpg/ { found = 1 } END { exit !found }'; then
  echo "CI packaging must remain unsigned; found an embedded signature" >&2
  exit 1
fi

validation_dir="$stage_dir/package-validation"
install -d -m 0755 "$validation_dir"
dpkg-deb --extract "$output" "$validation_dir"
if [[ ! -x "$validation_dir/opt/mesh-desktop/mesh_desktop" ||
      ! -f "$validation_dir/opt/mesh-desktop/lib/libapp.so" ||
      ! -s "$validation_dir/opt/mesh-desktop/data/flutter_assets/NOTICES.Z" ||
      ! -s "$validation_dir/usr/share/doc/mesh-desktop/LICENSE" ||
      ! -s "$validation_dir/usr/share/doc/mesh-desktop/THIRD_PARTY_NOTICES.md" ||
      "$(readlink "$validation_dir/usr/bin/mesh-desktop")" != "/opt/mesh-desktop/mesh_desktop" ]]; then
  echo "Debian package payload validation failed" >&2
  exit 1
fi

dpkg-deb --info "$output"
(cd "$output_dir" && sha256sum "$(basename "$output")") >"$output.sha256"
(cd "$output_dir" && sha256sum --check "$(basename "$output").sha256")
echo "built validated unsigned Debian package $output"
