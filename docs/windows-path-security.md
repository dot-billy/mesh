# Windows path security and service lifecycle

Mesh now has a cross-built Windows installer/runtime foundation for `amd64`
and `arm64`. It is deliberately fail closed and separate from the
[non-installing staging-bundle gate](windows-package-security.md). The code has
portable fault-order tests and reproducible Windows test-binary cross-builds;
it has not yet produced a passing receipt on a clean Windows host and therefore
does not make a supported native-package or installed-host claim.

## Security descriptor contract

Installer-owned release, state, journal, credential, and runtime-gate objects
use a non-null, non-defaulted, protected DACL. The only admitted trustees are:

- the exact service actor SID;
- LocalSystem (`S-1-5-18`); and
- local Administrators (`S-1-5-32-544`).

Each trustee has one exact full-control allow ACE. Broad trustees, deny or
object ACEs, duplicate trustees, unexpected masks, inherited ACEs on protected
objects, null/default DACLs, and untrusted owners are rejected. Protected
directories propagate both object- and container-inheritance. A dynamic child
is accepted only when all authority is inherited from an already authenticated
parent; a managed object may instead carry the exact protected form. Secrets,
transaction files, candidate artifacts, and every published release file
also require exactly one hard link.

The SCM service object has its own policy. Its protected DACL grants exact
`SERVICE_ALL_ACCESS` only to LocalSystem and local Administrators, with one of
those principals as owner. Installation verifies the immutable configuration
before repairing an existing service DACL, so it cannot take over an unrelated
service with the same name. Microsoft documents that service-object access is
checked independently by the SCM and that `READ_CONTROL`, `WRITE_DAC`, and
`WRITE_OWNER` govern security-descriptor inspection and mutation; granting
configuration or stop rights to untrusted users can become LocalSystem code
execution ([Service Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)).

Native inspection reads the owner and DACL through the already-open object
handle. A create-only Go handle is reopened as the same file-system object with
only `READ_CONTROL`, `WRITE_DAC`, `WRITE_OWNER`, and attribute-read access;
mutation applies the replacement descriptor through that reopened handle and
then re-reads it through the retained original. Microsoft specifies that
`ReOpenFile` reopens the supplied object with different access, sharing, and
flags, including no-reparse and directory semantics
([ReOpenFile](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reopenfile)).
This also follows Microsoft's handle-oriented security-descriptor guidance,
avoiding a second pathname lookup between authorization and use
([Security Descriptor Operations](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-operations),
[GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)).

## Path and release selection

Every installer directory component is opened relative to its retained parent
handle with `NtCreateFile`, `FILE_OPEN_REPARSE_POINT`, and
`OBJ_DONT_REPARSE`. Each handle must identify a real directory with no reparse
attribute before traversal continues. The final handle is identity-compared to
the `os.Root` used for all later relative operations. Revalidation confirms the
public pathname still names that same root before each selector mutation.

Production artifact acquisition uses the verified intake's signed HTTPS URL,
size, and SHA-256 with the shared bounded no-redirect client. It streams into a
protected single-link pending file below the installer root. Recovery deletes
only a stable partial file, completes publication of an already complete exact
file, or reuses the exact write-through no-replace live capture. The capture is
independently rehashed before staging and is removed under the installer lock
only after active state is committed and activation finalization can replay
without it.

Offline import uses one exact no-reparse, LocalSystem-private directory with
only `install.json`, `bundle.json`, and `mesh-windows-bundle.tar`. The unsigned
descriptor has fixed basenames and no policy, platform, clock, floor, size,
digest, URL, or key field. Every file is a bounded single-link object with the
exact protected DACL. Mesh authenticates the canonical signed bundle through
the same compiled trust/root-history path, then copies exactly its signed
artifact byte count and SHA-256 through the same capture boundary while
revalidating the source handles and directory before and after use.
The Windows-only `mesh-install-windows prepare-snapshot` command creates this
exact directory without replacing an existing destination. It accepts ordinary
transferred canonical bundle and candidate-tar files only as untrusted source
bytes, applies the fixed DACLs through retained handles, structurally inspects
the complete candidate for the native architecture, and removes only its own
recognized new destination on failure. Threshold authentication still occurs
during `install`; preparation does not promote archive metadata into release
authority.

Bundle intake starts from a clean local drive path whose parents are opened by
that same no-reparse walker. The candidate must remain one bounded, single-link
regular file with the exact actor/System/Administrators DACL throughout a
stable read. Mesh then validates the complete canonical USTAR, package schema,
compiled dependency policy, PE identities, file digests, and full artifact
digest in memory. Those package bytes grant no release authority. Production
metadata intake is bound to the installer-compiled version-1 root and build
identity, verifies the canonical online bundle with the root's release-role
threshold, advances a contiguous dual-threshold root history, and persists the
exact signed bytes plus their accepted decision. Restart replays the complete
root history and reproduces that decision from the signed bytes at its original
verification time. Only exact outer artifact, package, architecture,
security-floor, agent-state, and installed-ID bindings can construct the
`CurrentDescriptor` used for extraction.

Production extraction derives one deterministic private
`.stage-<installed-id>-<intake-digest>` below the anchored releases directory.
Restart either authenticates and publishes an exact finalized stage or safely
removes only a bounded, fully DACL-authenticated interrupted tree before
re-extraction; it never guesses among orphaned random stages. Every directory and file receives the exact
protected DACL, each file is flushed and reauthenticated as single-link, and
the expanded tree is reconstructed into the canonical USTAR again before it
can be finalized. Publication is a no-replace `MoveFileEx` with
`MOVEFILE_WRITE_THROUGH`; recovery accepts exactly one of the journal-named
stage or installed-ID directory and re-proves the entire artifact. This is the
production filesystem primitive used after the threshold-authenticated intake
has advanced durable epoch/sequence/root/security-floor high water.

Windows uses a protected canonical `current.json` descriptor instead of a
symbolic link. It binds the installed ID, full artifact SHA-256, package JSON
SHA-256, architecture, and security floor. Switching requires an exact expected
prior, a create-only random temporary, a flushed file, and atomic replacement.
Before selection, Mesh authenticates the complete target topology and DACLs,
checks every file size and digest, reconstructs the canonical USTAR stream, and
requires its full size and SHA-256 to equal the descriptor authority. A
DACL-protected but byte-drifted tree cannot become current.

## Service and contained Nebula process

The sole service is `MeshNodeAgent`, an automatic own-process LocalSystem
service with an unrestricted service SID. Its executable is the selected
immutable `bin\meshctl.exe`; its complete argument vector fixes the state path,
poll interval, five-minute staleness bound, selected `nebula.exe` and
`nebula-cert.exe`, and supervised-child mode. Inspection rejects configuration,
identity, command-line, description, start-account, dependency, or service-DACL
drift. Running proof opens the SCM-reported PID and requires its image handle to
identify the configured immutable executable.

When SCM invokes the binary, `meshctl` enters the Windows service dispatcher,
reports start-pending until agent setup succeeds, reports running only after
that boundary, and handles Stop/Shutdown by canceling and waiting for bounded
cleanup. Nebula is created suspended with an empty environment and the exact
`-config` vector, assigned to a no-breakaway Job Object configured with
kill-on-close, and resumed only after containment. Health proof retains the
process handle and requires stable creation time, exact image, arguments,
authenticated config, and Job Object policy. Teardown terminates the whole job
and waits for the exact child, so descendants cannot escape a PID-only stop.
Microsoft documents both the process-tree containment semantics of
[Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
and whole-job termination through
[TerminateJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-terminatejobobject).

## Persistent gate and activation journal

The LocalSystem-owned `runtime.enabled` file in the private installer
directory contains exactly `enabled\n`. Opening the gate is a recoverable
create, flush, no-replace `MOVEFILE_WRITE_THROUGH` publication. Closing removes
both live and recognized recovery files before proving absence. The service
rechecks this single-link authority before constructing a Nebula supervisor.

The canonical activation/rollback journal fixes one `activate` or `rollback`
operation, the exact source and target authorities, and the unchanged accepted
high-water authority, then advances only through:

1. `prepared`: immutable source observations, target descriptor, selector
   temporary name, and desired service/gate state are durable;
2. `quiesced`: the gate is proven closed and the exact source or recovery
   target service is stopped;
3. `selected`: the exact current descriptor and protected target SCM service
   are installed; and
4. `activated`: desired gate/service state and the exact selected target are
   re-proven.

Only the phase may change, and only to the adjacent phase. Each transition is
published through a protected, flushed pending file plus write-through atomic
replacement. Restart recovery completes only a canonical next phase from the
same immutable transaction. A failure after selection closes the persistent
gate and stops whichever exact journal-bound service exists.

The journal embeds the full target authority and optional active source
authority. Activation requires the target to equal accepted high water and the
matching accepted intake. Rollback requires the target to equal persisted
`previous`, rejects any overlapping intake, proves bidirectional agent-state
compatibility and security-floor support, and swaps `active`/`previous` without
lowering high water. A protected install-state document retains immutable
bootstrap/channel/architecture bindings, accepted high water, and active and
previous release identities. Replay, same-position equivocation, root-version
rollback, security-floor decrease, and agent-state-incompatible activation or
rollback are rejected without lowering high water. One protected single-link
`installer.lock` byte-range lock spans accepted-intake verification, root/state
recovery, selector and SCM mutations, every journal advance, and terminal
state/intake/journal finalization. Public callers cannot clear the journal or
write arbitrary install state around that authority boundary.

## Operator command boundary

The Windows-only `mesh-install-windows.exe` is a separate privileged command,
not a `meshctl` subcommand and not part of the long-lived service process. Its
fixed production layout is `%ProgramData%\Mesh`: immutable releases and
`current.json` are below that root, transaction state and the persistent gate
are below `installer`, and the service's agent state is
`agent\state.json`. It exposes only:

```text
version
install-online EXACT_BUNDLE_URL
prepare-snapshot ABSOLUTE_BUNDLE_JSON ABSOLUTE_WINDOWS_TAR NEW_ABSOLUTE_SNAPSHOT_DIR
install ABSOLUTE_PRIVATE_SNAPSHOT_DIR
recover
activate
uninstall-runtime
rollback PREVIOUS_INSTALLED_ID
```

`install-online` and `install` run signed intake, capture, deterministic
publication, current selection, exact SCM installation, and terminal state
finalization. A first install intentionally leaves the automatic service
stopped and the persistent gate closed: the operator enrolls with the selected
immutable `meshctl.exe`, the fixed `%ProgramData%\Mesh\agent\state.json`, and a
private managed-output directory, then invokes `activate`. `activate` changes
no release authority; under the same installer lock it proves the active
selector and exact stopped service, opens the gate, starts the service, and
compensates by closing the gate if start fails. `rollback` accepts only the
exact persisted previous installed ID and preserves the source running/gate
intent. `recover` consumes no new authority and resumes only the exact durable
intake or activation journal; when it finds a runtime-uninstall journal it
directs the operator to replay `uninstall-runtime`, which is itself the exact
recovery entry point. `uninstall-runtime` first journals immutable active and
high-water authority, then closes the persistent gate, stops and deletes the
exact protected service, removes only the exact authenticated `current.json`,
and clears active/previous state. It refuses current-switch residue or any
overlapping intake, activation, rollback, or root mutation. It never deletes a
release tree, agent enrollment state, installer trust/root history, or retained
anti-rollback high water; a retry after terminal response loss proves the
already-deactivated state.

These command paths cross-build for `amd64` and `arm64`, but the executable is
not yet a supported native package. A URL-free direct-root bootstrap manifest
can bind either exact installer PE. Deterministic verifier USTARs now carry the
Windows standalone verifier PE for both architectures, and the canonical v2
handoff/anchor requires the complete Linux/Windows four-package set and selects
by exact host OS/architecture. The verifier statically checks the installer's
PE64 platform, Go build identity, sole compiled root, exact Windows
installer-state compatibility frame, Authenticode policy, signed size, and
digest without executing it. On Windows it also requires that policy
to equal the verifier's compiled policy and verifies the installer's embedded
signature, SHA-256 signer, code-signing certificate, online whole-chain
revocation, and Mesh-role SPKI pin. The release-origin proof exercises Windows
PE packaging and handoff/anchor authoring plus Linux selection; signed
production artifacts, clean-host Windows extraction/execution, and interruption
and reboot receipts are still required before operators should use it outside
an isolated proof host.

## Native proof gate

First authenticate and execute the native standalone verifier on the target
host. Derive the selected package SHA-256 from the independently transferred v2
anchor on an already trusted operator workstation; do not copy that digest from
the release origin. Transfer the anchor, handoff, exact package, root, manifest,
signatures, and installer, then run from an elevated shell:

```powershell
$env:MESH_WINDOWS_BOOTSTRAP_NATIVE_TEST = "1"
.\scripts\windows-bootstrap-verifier-smoke.ps1 `
  -VerifierPackagePath C:\proof\mesh-bootstrap-verifier-windows-amd64.tar `
  -ExpectedVerifierPackageSHA256 <independently-derived-64-lowerhex> `
  -AnchorPath C:\proof\bootstrap-anchor.json `
  -HandoffPath C:\proof\bootstrap-handoff.json `
  -RootPath C:\proof\root-v1.json `
  -ManifestPath C:\proof\bootstrap-windows-amd64.json `
  -SignaturePath @("C:\proof\bootstrap.root-a.json", "C:\proof\bootstrap.root-b.json") `
  -InstallerPath C:\proof\mesh-install-windows.exe
```

The harness hashes the package before parsing or extracting it, requires the
exact two-member Windows USTAR, extracts only the verifier into a new private
LocalSystem/Administrators directory, and runs it without executing the
installer. Its create-only receipt binds the package, anchor, handoff, root,
installer, exact v3 verifier receipt, host architecture, and relevant source
hashes. A clean-host receipt is still required for each architecture; the
script's existence is not native execution evidence.

Run only in an elevated PowerShell session on an isolated Windows host where
`MeshNodeAgent` does not already exist. Supply two distinct canonical,
security-gated signed-v3 versions matching the host architecture:

```powershell
$env:MESH_WINDOWS_NATIVE_FAULT_TEST = "1"
.\scripts\windows-native-runtime-smoke.ps1 `
  -BundlePath C:\proof\mesh-windows-amd64.tar `
  -UpgradeBundlePath C:\proof\mesh-windows-amd64-upgrade.tar `
  -NativeDNSLocalIP 10.42.0.9 `
  -AuthenticodePolicyFrame <canonical-policy-frame>
```

The harness refuses an existing service. It exercises suspended Job Object
containment and whole-tree teardown, DACL drift rejection/repair,
component-level reparse rejection, ephemeral 2-of-2 threshold metadata
acceptance, exact signed-byte intake persistence, durable high-water commit,
exact root-private offline snapshot import, bounded signed-artifact
capture/recovery/discard, authenticated candidate intake, exact
DACL/single-link extraction, operator snapshot preparation, deterministic finalized-stage restart recovery, write-through
no-replace publication, hard-link drift rejection, full bundle reconstruction
and current selection, runtime-gate and journal publication, protected SCM
service create/inspect/stopped proof/delete, authority-bound activation
finalization including response-loss recognition, recovery-safe runtime
upgrade to a distinct sequence-2 artifact, rollback to the exact persisted
prior while retaining the upgrade as authority high water, and runtime
uninstall with exact service/gate/selector removal and both retained release trees,
agent state, trusted-root history, and anti-rollback high water. It also links
the supplied Authenticode policy into the test executable, requires every
activated PE to pass native role-pinned trust, creates and proves one exact
Mesh-owned NRPT suffix rule, resolves a real test name through the Windows DNS
client and local adapter, then proves exact rule cleanup. The create-only v4
receipt binds the source, both bundle identities, policy, native resolver
address, and proof.

Within 24 hours of both clean-host runs, verify the canonical receipts against
the independently recorded release identities:

```powershell
mesh-release verify-windows-native-evidence `
  --bootstrap-receipt C:\proof\bootstrap-receipt.json `
  --runtime-receipt C:\proof\runtime-receipt.json `
  --arch amd64 `
  --authenticode-policy-sha256 <policy-sha256> `
  --installer-sha256 <installer-sha256> `
  --bundle-sha256 <initial-bundle-sha256> `
  --upgrade-bundle-sha256 <upgrade-bundle-sha256>
```

The verifier rejects unknown or duplicate JSON fields, noncanonical encoding,
producer/source inventory drift, altered proof claims, mismatched identities,
receipts more than 24 hours old, and more than five minutes of future skew.
This is local evidence verification, not remote attestation.

Required before support: passing receipts from clean Windows `amd64` and
`arm64` hosts; repeated interruption at every journal, publication, and
selector boundary;
reboot recovery; real enrolled service start/stop and packet-level activation;
clean-host Windows verifier extraction/execution plus native uninstall and
resolver receipts; production signing execution and retained Authenticode
evidence; and installed-host SBOM, vulnerability, secret, and adversarial race
review.
