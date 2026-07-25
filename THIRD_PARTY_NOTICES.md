# Third-party notices

Mesh's original source is licensed under the [MIT License](LICENSE). Files
identified as third-party software remain under their upstream licenses.

## Slack Nebula

The source and derived runtime work under `third_party/nebula`,
`third_party/nebula-observer`, `third_party/nebula-darwin-runtime`, and
`third_party/nebula-windows-runtime` incorporate or modify Slack Nebula.
Nebula is MIT-licensed:

- Copyright (c) 2018-2019 Slack Technologies, Inc.
- Full license: [`third_party/nebula/LICENSE`](third_party/nebula/LICENSE)

## Font Awesome

The dashboard bundles Font Awesome files under
`internal/httpapi/web/font-awesome`:

- CSS and related source are licensed under Expat/MIT terms.
- Font files are licensed under the SIL Open Font License 1.1.
- Full copyright and license text:
  [`internal/httpapi/web/font-awesome/LICENSE.txt`](internal/httpapi/web/font-awesome/LICENSE.txt)

## Flutter desktop client

Linux and Windows desktop bundles are built with Flutter 3.44.8 from the
official SDK archives pinned and SHA-256-verified in
`.github/workflows/desktop.yml`. Flutter framework and engine code is
BSD-3-Clause licensed and also incorporates separately licensed third-party
components.

The desktop lockfile resolves these directly used packages and platform
implementations:

- `flutter_secure_storage` 10.3.1,
  `flutter_secure_storage_linux` 3.0.1,
  `flutter_secure_storage_windows` 4.2.2, and
  `flutter_secure_storage_platform_interface` 2.0.1 — BSD-3-Clause.
- `url_launcher` 6.3.2, `url_launcher_linux` 3.2.2,
  `url_launcher_windows` 3.1.5, and
  `url_launcher_platform_interface` 2.3.2 — BSD-3-Clause.
- `material_color_utilities` 0.13.0 — Apache License 2.0.
- Supporting Dart, Flutter, FFI, path-provider, Win32, and XDG packages retain
  the license terms shipped in their package metadata.

Flutter generates the complete consolidated runtime notices at
`data/flutter_assets/NOTICES.Z` in every desktop release bundle. That file
contains the full license texts collected from the resolved packages, Flutter
engine, fonts, shaders, and other runtime components. Packaging validation
requires it to remain present and nonempty. Redistributors must preserve that
embedded notice.

Linux packages dynamically link to GTK 3 and libsecret. Those system libraries
are declared as package dependencies and are not copied into the Mesh Debian
artifact.

## Other dependencies and packaged artifacts

Go module dependencies are declared in `go.mod` and authenticated by `go.sum`;
each dependency retains its own license. Release tooling can also package
upstream Nebula and Wintun artifacts. Review the exact generated package
manifest, software bill of materials, and bundled notices before
redistribution.

This file is informational and does not replace any third-party license text.
