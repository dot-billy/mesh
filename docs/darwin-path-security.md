# Darwin node path-security boundary

The node agent now has a native Darwin implementation for the filesystem
privacy checks that previously disabled every macOS lifecycle path. This is a
prerequisite for a supported installer; it is not itself an installer or a
native-host validation result.

The staged agent also recognizes the reviewed `--supervise-nebula` launchd
mode and authenticates `/private/var/db/mesh-installer/runtime.enabled` before
constructing a process adapter. The gate must be an unchanged root:wheel,
mode-0400, single-link regular file containing exactly
`mesh-runtime-enabled-v1` plus one newline, with no file flags, ACL, security
xattr, symlink component, or ignored-ownership mount. Closed or malformed gates
fail before polling. The cross-built process adapter now starts the resolved
release executable directly, owns and reaps that one child, and rechecks the
persistent gate before every agent cycle, reload, and observation. This code
has not executed on a Mac and is not native-host proof.

Run the Linux-verifiable regression with:

```sh
make darwin-path-security-smoke
```

The smoke runs portable ACL, path-walk, executable-metadata, persistent-gate,
process-argument, supervisor-ordering, activation/plist crash-ordering, and
cycle-ordering tests; validates the launchd path contract; cross-compiles the
complete node-agent and `meshctl` test binaries for `darwin/amd64` and
`darwin/arm64`; and reproducibly cross-builds the production `meshctl` Mach-O
for both architectures. It deliberately does not claim that a Darwin syscall
executed.

On an approved disposable native Mac, run the root-only mechanism harness from
the authenticated source tree:

```sh
sudo make darwin-native-runtime-smoke
```

That default keeps real system launchd mutation disabled. On a clean,
explicitly approved Mac, run the complete native fixture with the exact
architecture-matching scanned bundle:

```sh
sudo MESH_DARWIN_SYSTEM_LAUNCHCTL_TEST=1 \
  MESH_DARWIN_NATIVE_BUNDLE=/absolute/path/mesh-darwin-bundle.tar \
  make darwin-native-runtime-smoke
```

The additional gate refuses to run without the bundle, refuses any pre-existing
`/Library/LaunchDaemons/io.mesh.node-agent.native-proof.plist`, creates that one
exact root:wheel mode-0644 fixture, and uses the production authenticated
`/bin/launchctl` runner against only the unique
`system/io.mesh.node-agent.native-proof` target. It proves the initially absent
bootstrap-then-bootout route, successful loading, direct bootout, and idempotent
absent recovery. Cleanup proves the label absent before authenticating and
removing only the exact fixture; a cleanup failure preserves the plist rather
than hiding a potentially loaded job.

The harness is opt-in and returns prerequisite status 77 on non-Darwin hosts.
It creates and removes one uniquely named root-owned directory below
`/private/var/db`, injects mode, hard-link, symlink, and extended-ACL faults,
checks exact persistent-gate presence/absence, exercises installer-owned gate
creation, incomplete-publication recovery, idempotent open, malformed-state
refusal, close, and directory-mode faults, and starts disposable process groups
for exact kernel identity/argv, cycle-context cancellation, ordinary
termination, forced whole-group `SIGKILL`, exact reap, and residual-group
absence. A passing run publishes `system.txt`, `tests.txt`, `source.txt`, and a
canonical v3 hash-bound
receipt below `bin/darwin-native-runtime/<UTC>-<architecture>/` (or an explicit
absolute `MESH_DARWIN_NATIVE_EVIDENCE_DIR`). Run it independently on amd64 and
arm64. With an exact `MESH_DARWIN_NATIVE_BUNDLE`, it also exercises release
publication, offline snapshot intake, journal recovery, expected-prior
selection, and exact plist replacement in a disposable directory through a
fake service controller. Unless the separate system-launchctl gate is exactly
`1`, it never writes `/Library/LaunchDaemons` or invokes `launchctl`. The v3
receipt records normalized architecture, that gate, the proof label, bundle
SHA-256, host-facts hash, test-transcript hash, exact producer/source inventory,
and bounded start/completion times. Partial gate-disabled runs remain useful
diagnostics but cannot satisfy full evidence verification.

Within 24 hours, verify a full-system evidence directory against the
independently recorded bundle identity:

```sh
mesh-release verify-darwin-native-evidence \
  --evidence-dir /absolute/path/bin/darwin-native-runtime/<UTC>-<architecture> \
  --arch arm64 \
  --bundle-sha256 <bundle-sha256>
```

The verifier requires the exact mode-0700 directory and four mode-0400 files,
recomputes every retained digest, validates the exact sorted source inventory,
rejects partial launchctl-disabled evidence, and enforces 24-hour freshness
with at most five minutes of future skew. This remains local clean-host
evidence, not codesigning, notarization, remote attestation, or the complete
reboot and adversarial-race proof below.

## Exact policy

For each sensitive state or managed-output path, the Darwin adapter:

1. requires one absolute, lexically canonical path;
2. opens `/` and then every existing component by descriptor with
   `O_NOFOLLOW`, `O_NOFOLLOW_ANY`, and `O_CLOEXEC`;
3. requires every ancestor to be a real directory owned by root or the
   effective agent user with no group/world write bits;
4. rejects a mount carrying `MNT_UNKNOWNPERMISSIONS`, because ownership and
   mode checks are not authoritative there;
5. invokes `fgetattrlist` on the opened descriptor for
   `ATTR_CMN_EXTENDED_SECURITY` plus `ATTR_CMN_RETURNED_ATTRS`, validates the
   complete length/bitmap/attribute-reference representation, and accepts only
   no returned ACL or Apple's exact `KAUTH_FILESEC_NOACL` sentinel;
6. rejects every empty or populated ACL object, malformed representation, or
   `com.apple.system.Security` xattr; and
7. repeats the ACL read around the bounded xattr inspection and rejects a
   changed result.

The existing UID and exact mode predicates remain mandatory after that native
check: state and bundle files are owner mode `0600`, managed directories are
`0700`, and managed parents cannot be group/world writable. Directory
durability re-walks the path, opens the exact directory without following a
symlink, repeats its native security check, and only then calls `Sync`.

The launchd contract uses `/private/var/db/mesh-agent/state.json` and
`/private/var/db/mesh-installer/runtime.enabled`. The physical `/private/var`
spelling is intentional; macOS exposes `/var` as a compatibility symlink, and
accepting it would contradict the no-symlink ancestor policy.

## Cross-built child contract

Before the adapter is constructed, the reviewed `/opt/mesh/current` selector
is resolved to one physical Nebula executable. That target must pass the same
descriptor-anchored path inspection and remain an exact root:wheel,
single-link, mode-0555, nonempty regular file with no file flags, ACL, security
xattr, writable ancestor, remaining symlink component, or
ignored-ownership mount. The physical target, rather than the selector, is the
path passed to `exec`.

The adapter uses an empty environment, `/` as the working directory, and a new
process group. It records the kernel PID, parent PID, process group, root UID,
and start time. Healthy observation requires that stable identity, a non-zombie
status, the exact resolved executable reported by `KERN_PROCARGS2`, and the
exact three-element argument vector
`[/opt/mesh/current/bin/nebula, -config, <managed current/config.yml>]`. Normal
running/sleeping status transitions are allowed; parent, group, UID, start
time, executable, or argument drift is not.

The in-memory child authorization opens immediately before start and closes
before group termination. Quarantine retains an exited child as an unreaped
zombie until the exact `Wait` step, preventing PID reuse during the ordinary
termination path. A deadline forces the tracked process to `SIGKILL`, and an
unproven wait remains a cleanup error. A persistent-gate failure first requests
that same quarantine and never becomes a healthy observation. Gate removal is
checked at the next cycle or child operation; this is not an asynchronous file
watcher.

The installer-side persistent-gate primitive is separately implemented under
`internal/darwininstall`. It creates only the last component of an exact
root:wheel mode-0700 state directory through an authenticated physical parent.
Opening authorization writes and syncs one exclusive mode-0400 recovery file,
syncs the directory, revalidates the exact content and metadata, syncs the file
again, and publishes it with Darwin `renameatx_np(RENAME_EXCL)` before the final
directory sync and readback. A complete recovery file resumes after a crash;
an incomplete exact prefix is removed, synced, and recreated; unexpected bytes,
links, flags, modes, owners, ACLs, xattrs, or live-plus-recovery ambiguity fail
without deletion. Close authenticates and durably removes the live gate first,
then any recognized recovery file, and proves both absent.

The next installer primitive now owns create-only immutable release
publication. Low-level Darwin-host candidate intake accepts only a single-link
physical bundle and reconstructs the exact canonical USTAR into one root:wheel
mode-0700 stage. Production online intake first persists the exact canonical
signed metadata as a mode-0400 accepted record, re-verifies it at its original
acceptance time against compiled trust and replayed root history, captures only
the selected bounded artifact through the no-redirect client, and expands it
into one deterministic candidate-bound stage. An interrupted private or sealed
pre-journal stage is descriptor-anchored, bounded, removed, and rebuilt from
the immutable capture; unrelated metadata, root updates, install-state changes,
and rollback are blocked while the accepted record is active. The stage is
sealed mode 0555; every fixed directory and file
is reauthenticated through the native ACL/xattr/mount policy, every file is
reopened without following any symlink, and its exact size and SHA-256 are
rechecked against the authenticated package inspection. `/opt/mesh` and
`/opt/mesh/releases` are descriptor-anchored root:wheel mode-0755 directories.
Publication syncs the finalized stage, uses
`renameatx_np(RENAME_EXCL)` to prevent adoption or replacement, syncs the
releases directory, and proves the private name absent and the final name bound
to the same opened directory. Portable fault injection covers every ordering
failure and the post-rename/pre-sync recovery state; both architectures
cross-compile the native intake and layout adapter.

Current-release selection is also implemented as a separate
descriptor-relative transaction. It creates one exact root:wheel relative
symlink, syncs the layout, rechecks that `current` still equals the journal's
expected prior release, then atomically replaces it and syncs again. A stale
transaction cannot overwrite a newer selection. A journal-recorded temporary
can resume before replacement, after replacement but before sync, or with a
recognized leftover; final proof requires the selected release to rehash
exactly and the temporary to be absent.

The publication, selection, and activation primitives are now joined by a
canonical `mesh-darwin-install-journal-v4` transaction in the physical root:wheel
mode-0700 installer state directory. One exact empty mode-0600 lock file plus
nonblocking `flock` serializes processes. The mode-0400 single-link journal
binds the installed ID, exact private stage name, expected prior, random current-link
temporary, complete authenticated candidate inspection, outer release
authority, and pre-activation runtime-gate intent. Activation permits only
`staged -> published -> activated`; rollback binds the exact high-water,
source-active, and target-previous authorities and permits only
`prepared -> activated`. Every other field is immutable. Each create or phase advance writes and syncs one
exclusive pending file, rechecks the locked snapshot, atomically publishes it,
syncs the directory, and reads the exact canonical bytes back. Restart
reconciles only the deterministic next phase and reattaches the exact stage,
published release, current-link transaction, and activation target.

Activation closes and re-proves the persistent gate, boots out and re-proves
service absence, selects the journal target, publishes the exact authenticated
plist, bootstraps and re-proves the service, restores the journaled gate intent,
and finally re-proves the selected release, plist, service, and gate before the
journal can clear. The journal and canonical mode-0400 install-state file share
one lock: begin durably advances exact epoch/sequence/root/artifact high-water
authority before publishing an activation journal, and completion records the activated
release before clearing it. Rollback reauthenticates the already-published target from its
canonical package metadata, closes the gate, boots out the service, switches current,
publishes the target plist, bootstraps, restores the recorded gate intent, swaps only the
state-recorded active/previous pair, and retains the exact high-water authority. Recovery
recognizes both the exact pre-swap state and the exact post-swap/pre-clear state, preventing
a terminal retry from swapping forward again. Same-position equivocation, lower epoch/sequence,
security-floor decrease, trusted-root rollback, cross-channel/architecture
substitution, irreversible agent-state schema changes, and rollback to anything
other than the recorded previous release are rejected. A crash between the
state and journal writes leaves only an exact retryable high-water candidate,
never lower authority.

Plist replacement anchors an exact root:wheel mode-0755
directory, accepts only structurally trusted live or recovery files, writes a
private mode-0600 exact-content pending file, syncs it, finalizes mode 0644,
atomically replaces the live file, syncs the directory, and reads the exact
bytes and metadata back. Unexpected pending content fails without deletion.

This is still not a complete supported installation transaction. Journal v4 activation begins only
after an exact bundle has been authenticated and finalized in its named stage. Darwin
metadata intake loads the compiled bootstrap root and production build identity,
canonically reparses the signed release bundle, persists a contiguous create-only mode-0400
root-update history under the transaction lock, threshold-verifies the selected Darwin
artifact, durably records that decision before download, and binds outer authority to exact
staged-bundle inspection. The same lock orders bounded capture, deterministic stage reset,
high-water commit, journal creation, capture removal, and intake removal; restart re-verifies
the signed record rather than treating root-owned cached fields as authority.

Offline intake now uses one create-only mode-0700 directory containing exactly
three mode-0400 files:

```text
install.json
bundle.json
mesh-darwin-bundle.tar
```

`install.json` is canonical `mesh-darwin-install-snapshot-v1` and may name only
those two fixed payload basenames. It has no unsigned trust, platform, clock,
floor, size, digest, or key field. On a Linux release workstation,
`mesh-release assemble-darwin-snapshot --output <new-directory>
--online-bundle <canonical-bundle.json> --artifact <darwin-bundle.tar>` stably
opens both single-link inputs, copies them into a private staging directory,
fsyncs each object and the directory, reads them back, and publishes the exact
directory without replacement. No metadata is trusted during assembly.

The native importer accepts only a physical root:wheel mode-0700 directory
with no ACL, security xattr, ignored ownership, symlinked component, or file
flag. It requires the exact three-entry tree and root:wheel single-link
mode-0400 files, holds directory and artifact descriptors, and rechecks their
complete identity before and after use. Metadata follows the same compiled-root,
root-history, replay, and durable-intake path as online installation. The local
artifact must match the signed size and SHA-256, is hashed while streaming into
the bounded pending capture, and is independently rehashed before create-only
publication. A failed copy leaves only the deterministic private partial and
the exact retryable intake; an unrelated release remains fenced. Transfer media
is never a trusted source path: copy the three files into a new trusted physical
directory with `install -o root -g wheel -m 0400`, then set the directory itself
to root:wheel mode 0700 before import.

The
native activation composite now has a fixed `/bin/launchctl` system-domain
controller, but deliberately has no status parser: Apple's manual states that
`launchctl print` output is not an API. With the runtime gate already proven
closed, controller recovery accepts absence only after one successful
`bootout`; when the service was absent it first bootstraps the exact immutable
release plist and then requires bootout to succeed. Loading is accepted only
after the preceding proven absence and one successful bootstrap of the exact
published `/Library/LaunchDaemons` plist. Commands use fixed arguments, an
empty environment, a bounded timeout/output sink, stable authentication of
`/bin/launchctl`, and reject output even on zero exit. An activated-phase
restart repeats that idempotent sequence instead of parsing status text.
Native execution is opt-in through the existing
root-only harness; setting `MESH_DARWIN_NATIVE_BUNDLE` adds journal-driven
offline snapshot admission, publication/current/plist recovery, and explicit active/previous rollback to exact bundle staging, stale-switch
rejection, and upgrade checks. The harness uses a fake service controller and a
disposable plist directory, not the system launchd domain.

The packed formats and constants are grounded in Apple's
[`attr.h`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/attr.h),
[`kauth.h`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/kauth.h),
and [`vfs_attrlist.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/vfs/vfs_attrlist.c).
The process-argument and identity layouts are grounded in Apple's
[`kern_sysctl.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_sysctl.c)
and [`proc.h`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc.h).

## Required real-Mac proof

Before this can become a supported native lifecycle boundary, clean amd64 and
arm64 Macs must run a fault-injection harness that proves:

- ordinary APFS root-owned physical paths pass, while `/var/...` and a symlink
  injected at every other component fail before state mutation;
- `chmod +a` ACLs on the root, an ancestor, the managed directory, and a
  managed file all fail, including inherited and empty ACL objects;
- an external volume with **Ignore ownership on this volume** is rejected;
- ACL/xattr mutation, component rename, and replacement races never produce a
  successful validation of an unsafe descriptor;
- executable-selector and physical-target replacement races cannot start or
  acknowledge bytes outside the authenticated installed release;
- the physical launchd state and runtime-gate paths survive reboot and remain
  exact root-owned private objects; and
- normal running/sleeping transitions remain healthy, while executable, argv,
  parent, process-group, UID, start-time, and zombie fault injection fails;
- persistent-gate removal during a live session closes authorization and
  removes the child by the next bounded cycle;
- agent `SIGTERM`, forced `SIGKILL`, child signal refusal, unexpected exit,
  exact reap, descendant cleanup, reboot, and launchd restart never leave an
  authorized orphan; and
- directory `Sync` behavior, immutable release publication and collision
  recovery, and installed-agent packet recovery pass on both architectures.

Codesigning, notarization, package receipts, native execution on both
architectures, native proof of the mutation-only launchctl controller, real `/Library/LaunchDaemons` activation,
and an installed-host packet proof are separate gates. Until those exist, the
Darwin release remains a reviewed, scanned, non-installing staging bundle.
