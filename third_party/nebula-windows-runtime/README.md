# Slack Nebula v1.10.3 Windows runtime output lock

This directory layers exact Windows output identities over the authenticated
source, patch, dependency, toolchain, and build policy in
`../nebula-observer/v1.10.3-build.lock.json`. The canonical digest of that base
lock is embedded as `base_observer_lock_sha256`; changing the source policy
therefore invalidates this lock instead of silently retaining old PE outputs.

For each of `windows/amd64` and `windows/arm64`, the lock binds exactly
`nebula.exe` and `nebula-cert.exe`: main package, mode, size, and SHA-256.
`mesh-deps build-nebula-windows-runtime` authenticates the base source tree,
applies the ordered patch set, uses Go 1.26.5 and the locked build flags, builds
twice with separate clean caches, and publishes only byte-identical outputs
matching this file.

The patched observer endpoint is a reviewed no-I/O stub on Windows. This lock
does not claim a Windows telemetry transport, Authenticode, DACLs, Windows
Service integration, installation, rollout, or rollback. Windows bundle schema
v2 combines these source-built PEs with only the exact Wintun runtime and
notices from the separately authenticated upstream Windows archive. The final
[Windows staging-bundle gate](../../docs/windows-package-security.md) validates
both provenance chains inside each exact release candidate.
