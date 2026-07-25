# Linux desktop package

`build-deb.sh` turns an existing Flutter Linux release bundle into an
unprivileged Debian package. The package installs the application under
`/opt/mesh-desktop`, adds a launcher in `/usr/bin`, and includes the project
license and third-party notice.

Build the Flutter bundle and package it on a Debian-compatible x64 or arm64
host:

```bash
flutter build linux --release
packaging/desktop/linux/build-deb.sh \
  desktop/build/linux/x64/release/bundle
```

The script requires `binutils`, `dpkg-dev`, and `fakeroot`. It validates package
metadata, root ownership, `0755` directory traversal permissions, the executable
payload, embedded Flutter notices, and the absence of an embedded `dpkg-sig`
signature. It writes a SHA-256 sidecar next to the package.

CI artifacts are intentionally unsigned. A checksum proves download integrity;
it is not publisher authentication. Publish the package through a signed APT
repository or apply the approved release-signing process before distribution.
