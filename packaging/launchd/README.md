# macOS launchd ownership contract

This directory contains the reviewed launchd contract for a future native
macOS node package. It is embedded in the deterministic non-installing Darwin
staging bundle for testing, scanning, and release review. The native installer
foundation can journal, publish, select, and apply fail-closed activation to an
authenticated immutable release below `/opt/mesh/releases`. Its exact-plist
publisher can atomically replace this asset, but no supported installer invokes
that path against the system launchd domain. Do not copy or bootstrap the plist manually:
macOS code-signing, native execution of the implemented activation
journal and online/offline bounded intake paths, native proof of the mutation-only launchctl controller, extended-ACL validation,
and clean-host launchd proof are still required before this asset is safe to
install.

The production layout is fixed:

- immutable releases live below `/opt/mesh/releases`;
- `/opt/mesh/current` selects one authenticated release;
- lifecycle state lives at the physical, symlink-free path
  `/private/var/db/mesh-agent/state.json`;
- the installer-owned persistent gate is
  `/private/var/db/mesh-installer/runtime.enabled`; and
- the sole job definition is
  `/Library/LaunchDaemons/io.mesh.node-agent.plist`.

There is intentionally no independent Nebula LaunchDaemon. The one root-owned
`io.mesh.node-agent` job runs `meshctl agent --supervise-nebula`; after a fresh
signed-state validation the agent starts Nebula as its foreground child. The
agent must remove its ephemeral authorization before terminating the child,
wait until that exact child exits, and refuse a healthy acknowledgement until
the exact binary and managed config are proven live. `AbandonProcessGroup` is
false so launchd retains process-group ownership as an additional teardown
backstop; this behavior still requires native fault-injection proof.

`KeepAlive.PathState` is only a launchd availability hint. It is not the security boundary.
The staged Darwin agent now recognizes `--supervise-nebula` and independently
validates the exact root:wheel, mode-0400, single-link persistent gate before
it can construct a child adapter. The cross-built adapter authenticates the
resolved root:wheel mode-0555 release executable, starts it directly with an
empty environment and a dedicated process group, proves its kernel identity
and exact argument vector, and closes its in-memory authorization before
termination and exact reap. It rechecks the persistent gate before polling and
every child operation. None of those native calls has executed on a Mac;
removing the gate does not replace explicit child quarantine and `bootout`
during an upgrade.

The plist contains no enrollment token, bearer, signing key, environment
override, shell, user-selected path, socket trigger, or writable log path. It
must be installed as an exact root:wheel mode-0644 file without an extended
ACL. Both managed executables and all state paths must be root-owned and must
not traverse writable or symbolic-link ancestors. The `/private/var` spelling
is intentional: `/var` is a compatibility symlink on macOS and is therefore
outside this contract.

Before this contract can be called supported, a real Mac must prove native
arm64 and amd64 execution, Developer ID validation and notarization, first
signed-poll gating, child removal after agent SIGTERM and SIGKILL, reboot
behavior, five-minute stale-state quarantine, packet exchange, upgrade,
rollback, and crash recovery.

`make darwin-native-runtime-smoke` is the root-only, self-cleaning first native
mechanism step. It exercises real path/ACL/gate syscalls and direct-child
identity, termination, forced process-group kill, exact reap, and group absence
with disposable objects. With `MESH_DARWIN_NATIVE_BUNDLE`, it also publishes the
exact plist into a disposable directory through a fake service controller and
proves accepted-metadata persistence, root-private offline snapshot admission,
bounded capture, interrupted deterministic
stage reset, recognized activation, and explicit rollback crash recovery. By default it deliberately does not touch
`/Library/LaunchDaemons`, invoke launchctl, or satisfy the launchd, reboot,
package-signing, real launchd-controller upgrade/rollback, or packet requirements.

On an approved clean Mac, setting both
`MESH_DARWIN_SYSTEM_LAUNCHCTL_TEST=1` and an absolute
`MESH_DARWIN_NATIVE_BUNDLE` enables the separate proof-only system mutation.
It refuses a pre-existing proof plist, creates only
`io.mesh.node-agent.native-proof.plist`, binds the production runner to that
exact path and `system/io.mesh.node-agent.native-proof`, proves absent/load/
bootout/idempotent recovery, then proves absence before removing the exact
fixture. This does not install or exercise the production job label.
