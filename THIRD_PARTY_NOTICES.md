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

## Other dependencies and packaged artifacts

Go module dependencies are declared in `go.mod` and authenticated by `go.sum`;
each dependency retains its own license. Release tooling can also package
upstream Nebula and Wintun artifacts. Review the exact generated package
manifest, software bill of materials, and bundled notices before
redistribution.

This file is informational and does not replace any third-party license text.
