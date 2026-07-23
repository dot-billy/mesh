# Slack Nebula v1.10.3 Darwin runtime output lock

This directory layers exact Darwin output identities over the authenticated
source, patch, dependency, toolchain, and build policy in
`../nebula-observer/v1.10.3-build.lock.json`. Its embedded base-policy digest
invalidates these outputs whenever the common source policy changes.

For each of `darwin/amd64` and `darwin/arm64`, the lock binds exact thin
Mach-O `nebula` and `nebula-cert` executables by main package, mode, size, and
SHA-256. `mesh-deps build-nebula-darwin-runtime` authenticates the base source,
applies the ordered patch set, uses Go 1.26.5 and the locked build flags, builds
twice with separate clean caches, and publishes only byte-identical output
matching this file.

`mesh-package build-darwin` consumes the exact locked stage for one
architecture, adds production-identity Mesh plus reviewed launchd assets, and
emits a deterministic non-installing USTAR. The
[Darwin staging-bundle gate](../../docs/darwin-package-security.md) validates
that final artifact and produces the canonical receipt required by production
release authoring.

The patched observer endpoint is a reviewed no-I/O stub on Darwin. This lock
does not claim a macOS telemetry transport, codesigning, notarization,
extended-ACL safety, launchd installation, native execution, rollout, or
rollback. Those remain separate native-host boundaries.
