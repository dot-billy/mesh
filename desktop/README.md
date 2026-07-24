# Mesh Desktop

Mesh Desktop is a preview operator console for Linux and Windows. It connects
to a remote Mesh control plane and does not run as a node, install Nebula, or
manage a local tunnel.

The client shows fleet health, networks, nodes, signed policy, readiness,
activity, and role-scoped access controls. The server remains the source of
truth for authorization and lifecycle state. Use the web control plane or API
for a workflow that the preview client does not expose.

The preview can create networks and node enrollments, reissue a pending
enrollment, rotate or permanently revoke a node identity, revoke a
control-plane session, and create one-use recovery access. The control plane
checks the signed-in role and permission again for every mutation.

Creating a lighthouse requires a reachable public UDP endpoint such as
`vpn.example.com:4242`. Enrollment tokens and recovery codes appear in a
one-time custody view. They are removed when the view closes or the app leaves
the foreground. Mesh Desktop creates recovery access with a seven-day lifetime;
use the web control plane or API when a different expiry is required.

## Sign in safely

Use the exact HTTPS origin of the Mesh control plane. Plain HTTP is accepted
only for an explicitly enabled loopback development profile.

Browser sign-in uses a request that expires after five minutes:

1. Mesh Desktop starts the request and keeps the one-time poll secret in the
   native process.
2. The system browser opens a verification URL that contains only the public
   request ID.
3. The operator signs in if needed, checks that they started the request, and
   approves or denies it.
4. Approval creates a separate Mesh session with the same principal, role, and
   permissions. The request can create a session only once.

The client stores only the session and CSRF cookie pair in the operating system
credential store. A legacy administrator token, when a deployment still
allows one, stays in memory and is not saved.

### Multi-replica upgrade order

This release adds `desktop_authorizations` to the shared identity document.
Older strict readers reject that field after a new server writes the document.

For a multi-replica control plane:

1. Block identity-writing traffic.
2. Replace every control-plane replica with the new build.
3. Restore traffic and test one denied request before testing one approved
   request.
4. Confirm that approval and completion can use different replicas.

Do not roll back to an older build after the field has been written unless an
operator first applies a reviewed state migration or restores a verified
pre-upgrade identity backup.

## Toolchain

The repository pins Flutter 3.44.8 and the official archive SHA-256 values in
[`tool/flutter-sdk.json`](tool/flutter-sdk.json). Use that SDK rather than a
moving stable channel.

Linux builds require Clang, CMake, Ninja, GTK 3 development files, pkg-config,
and libsecret development files. Debian packaging also requires `fakeroot` and
`dpkg-deb`.

Windows builds require Visual Studio with Desktop development with C++ and a
current Windows SDK. The MSIX packaging step uses `MakeAppx.exe`.

## Verify the source

From the repository root:

```bash
make desktop-check
```

That target enforces the lock file, checks formatting, runs static analysis,
and runs the Flutter test suite.

To build and package on Linux:

```bash
make desktop-linux-package
```

The package is written under `artifacts/desktop/`.

On Windows:

```powershell
cd desktop
dart pub get --enforce-lockfile
dart format --output=none --set-exit-if-changed lib test
flutter analyze
flutter test
flutter build windows --release
```

Then follow
[`packaging/desktop/windows/README.md`](../packaging/desktop/windows/README.md)
to create an unsigned MSIX. Sign and validate the package in a protected
release environment before distribution.
