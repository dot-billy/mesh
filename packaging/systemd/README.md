# Linux systemd install and boot contract

The supported Linux paths are the authenticated online installer and the
signed offline snapshot installer. Do not copy these unit files by hand and do
not run `systemctl enable --now` yourself. Both paths enter the same installer
transaction, which owns exact mode-0444 unit definitions in
`/usr/local/lib/systemd/system`, exact comment-only unit drop-ins that mask a
same-named distribution-wide `10-timeout-abort.conf`, exact compatibility
links through `/opt/mesh/current`, durable anti-rollback state in
`/var/lib/mesh-installer`, and every service transition.

Requirements:

- Linux `amd64` or `arm64` with systemd 249 or newer;
- real/effective UID and GID 0 for `mesh-install`;
- trusted root-owned systemd configuration and no competing Nebula service;
- an authenticated bootstrap copy of `mesh-install` whose compiled version-1
  root is independent of the candidate snapshot, online release, and URL;
- for online installation, direct access to the exact canonical HTTPS bundle
  and artifact URLs using the host's trusted CA store; or
- for offline installation, a root-owned mode-0700 snapshot directory
  containing only files emitted by `mesh-release assemble-snapshot`.

## Install, enroll, activate

The simplest supported path retrieves a `mesh-online-release-bundle-v2` from
the exact stable HTTPS object configured by the release operator:

```sh
sudo /path/to/bootstrap/mesh-install install-online \
  'https://releases.example/channels/stable/bundle.json'
```

The bundle is bounded to 40 MiB and contains only a bounded contiguous root
chain, exact manifests, and detached signatures. The installer accepts no
redirects, proxy, cookies, compression, or URL normalization. It replays its
compiled and persisted roots, fsyncs accepted rotations, and authenticates
metadata under the latest release role before requesting the artifact. It
requires the artifact's signed exact
`Content-Length` and SHA-256, materializes a private offline snapshot, and then
repeats the full ordinary installation verification. Root-private crash
residue under `/var/lib/mesh-installer/online-intake` is removed on the next
online run only when two inspections prove it is a recognized unchanged
workspace; unsafe or unknown entries fail closed.

The bootstrap `mesh-install` binary must still be separately authenticated.
The online bundle, TLS endpoint, URL, and Mesh control plane cannot replace its
compiled initial root. Only a threshold-authorized immediate successor can
change keys, thresholds, epoch, channel floors, or security floors.

The supported offline authorization mechanism is documented in
[Versioned release trust](../../docs/release-trust.md): root custodians sign a
URL-free `mesh-bootstrap-manifest-v1`, and the narrow
`mesh-bootstrap-verify` executable requires the canonical bootstrap anchor,
handoff SHA-256, or version-1 root SHA-256 from an independent channel before
it statically validates the exact installer.
`mesh-release verify-bootstrap` is a compatibility alias backed by the same
implementation. The verifier must already be trusted or independently
authenticated too; downloading it beside the installer would be circular.
The canonical unsigned bootstrap handoff binds root version 1 and both Linux
verifier packages so one independently transferred anchor supplies those exact
expected values. The preferred verifier invocation passes the local handoff
plus `--handoff-anchor`; the verifier reads the anchor first and emits a v3
receipt. Direct `--expected-handoff-sha256` and `--expected-root-sha256` remain
mutually exclusive v2 and v1 compatibility modes. Production still requires an
actual immutable origin, real independent anchor-transfer channel, and
authenticated origin image/custodian ceremony.

The fully supported offline alternative installs the complete
threshold-signed snapshot:

```sh
sudo /path/to/bootstrap/mesh-install install /absolute/path/to/snapshot
```

First installation intentionally leaves the persistent runtime gate closed,
the lifecycle agent disabled, and both services stopped. Enroll without
placing the one-time bearer in argv or the environment:

```sh
(
  IFS= read -rsp 'Enrollment token: ' MESH_TOKEN && printf '\n' >&2
  trap 'unset MESH_TOKEN' EXIT HUP INT TERM
  printf '%s\n' "$MESH_TOKEN" | sudo /usr/local/bin/meshctl enroll \
    --server https://mesh.example.com \
    --token-file - \
    --state /var/lib/mesh-agent/state.json \
    --output /var/lib/mesh-agent/nebula \
    --nebula /usr/local/bin/nebula \
    --nebula-cert /usr/local/bin/nebula-cert
)
```

Then perform the only supported boot-enablement transition:

```sh
sudo /usr/local/bin/mesh-install activate
```

`activate` is locked and retry-safe. It audits the authenticated current
release, opens the fixed installer gate, establishes only the canonical
`multi-user.target` link for `mesh-agent.service`, and starts the agent. It
succeeds only after the exact agent and Nebula processes are both running from
the authenticated release. Both units use `Type=exec`, so systemd acknowledges
startup only after it has entered the reviewed executable rather than during
the pre-`execve` fork window. A synchronous failure closes both gates, stops
both services, disables the agent, and reports whether quarantine was proven.

## Control-plane install guidance

After publishing the artifact first and then the exact stable bundle, expose
that canonical bundle URL through the authenticated browser guide:

```sh
mesh-server \
  --linux-install-bundle-url \
  'https://releases.example/channels/stable/bundle.json' \
  --linux-bootstrap-handoff-url \
  'https://releases.example/bootstrap/stable/bootstrap-handoff.json' \
  # ...the server's remaining required flags
```

Both flags are browser guidance only; neither is a server-side trust override,
and each is rejected unless it is one canonical HTTPS object URL. The
authenticated enrollment dialog displays the handoff location with an explicit
warning that the dashboard, origin, and TLS do not authenticate it; the
independent handoff digest is never configured or returned by Mesh. Users then
receive the three-step flow: run `install-online` with the exact configured
bundle URL, enroll by passing the one-time token on stdin with `--token-file -`,
then run `mesh-install activate`. If the bundle flag is unset—or an older
server returns 404—the UI keeps enrollment and activation available but
explicitly requires an
independently authenticated offline/bootstrap installation first. The
one-time token is displayed separately and is never concatenated into a shell
command.

## Rerunnable browser-to-package proof

From the repository root, the Linux clean-host proof is:

```sh
make ui-guided-linux-package-smoke
```

The target first runs the complete online/offline versioned-root regression,
then creates an isolated private bridge with one TLS release/control host and
two fresh pinned Fedora systemd hosts. Before measurement, it places only the
separately authenticated bootstrap and the local fixture CA on each node. The
measured interval begins with Firefox authoring the network and both nodes,
executes the browser's exact `install-online`, prompted stdin enrollment, and
`activate` commands on both hosts, waits for the managed services, and ends
only after an authenticated member-to-lighthouse overlay ping. The audited
2026-07-20 run completed that interval in 11 seconds.

The harness fail-closes on noncanonical browser guidance, an unsafe credential
file, missing systemd/TUN/browser prerequisites, a five-minute overrun, or an
unexpected cleanup identity. It removes only exact label-verified resources.
Repository/control provisioning, host preparation, and real bootstrap
distribution/authentication are deliberately outside the timing boundary, so
this remains a Linux systemd mechanism proof rather than a production
distribution or cross-platform claim.

## Two independent runtime gates

`/var/lib/mesh-installer/runtime.enabled` is a root-private persistent gate
owned by the installer transaction. It prevents either managed unit from
starting during installation, upgrade, rollback, or incomplete recovery.

`/run/mesh-agent/nebula.validated` is an ephemeral root-private child gate.
systemd creates its mode-0700 `RuntimeDirectory` empty on every agent start and
removes it on stop, crash, or reboot. The agent publishes the marker only after
a successful signed-state poll and exact bundle validation, immediately before
starting Nebula. Every quarantine path removes and syncs it before stopping
Nebula. Even an accidentally loaded alternate dependency therefore cannot
start the child before the current signed state has been validated.

The agent polls every minute and, by default, quarantines Nebula when it can no
longer prove signed-state freshness within five minutes. The child binds to the
agent, so stopping or losing the agent also stops Nebula. Neither gate makes an
untrusted OS root safe: root-owned systemd configuration, the kernel, and the
installer state directory remain inside the trusted computing base.

When an administrator separately enables native resolver integration for the
network, the signed node configuration also carries one strict
`mesh-native-dns-v1` policy. The agent starts a local suffix-only UDP adapter on
the node's overlay address and uses `resolvectl` to register that address plus
the chosen search domain on the unique interface carrying it. The registration
is transient, non-default-route, and does not forward unrelated DNS. Every poll
reasserts the exact per-link settings so a systemd-resolved restart converges;
disable, stale signed state, quarantine, agent shutdown, interface replacement,
or a partial apply closes the adapter and runs `resolvectl revert` for the
previous link. If systemd-resolved or the required interface cannot be proven,
the agent quarantines Nebula instead of claiming operational convergence. This
option is implemented only for packaged Linux nodes; leave it disabled on other
platforms or hosts whose resolver lifecycle is managed separately.

`/run/mesh-nebula` is a separate root-owned mode-0700
`RuntimeDirectory` created only for `mesh-nebula.service` and removed whenever
that service stops. The observer-enabled runtime creates exactly
`runtime-observer.sock` there as a root-owned mode-0600 Unix socket; it accepts
only root peers verified with `SO_PEERCRED`. This local snapshot boundary is
observational only and does not replace either runtime gate or prove remote
peer reachability.

## Upgrade, recovery, and explicit rollback

Apply a newer signed snapshot with the active installed binary:

```sh
sudo /usr/local/bin/mesh-install install /absolute/path/to/new-snapshot
```

The installer preserves the exact prior enabled/active state. It closes and
syncs the persistent gate before stopping services, switches the immutable
`current` release only after stop proof, and restores the agent and previously
active Nebula only after the new release is audited. It never enables or
disables a unit during an ordinary upgrade.

After interruption or an ambiguous journal error, run:

```sh
sudo /usr/local/bin/mesh-install recover
```

Rollback names the exact recorded installed ID shown in prior JSON output:

```sh
sudo /usr/local/bin/mesh-install rollback \
  s00000000000000000001-r0123456789abcdef-a0123456789abcdef
```

Repeating the same rollback target after a lost success response is a no-op;
an unrecorded or malformed target is rejected.

## Verification

```sh
systemctl is-enabled mesh-agent.service
systemctl is-active mesh-agent.service mesh-nebula.service
systemctl show mesh-agent.service -p FragmentPath -p DropInPaths -p TimeoutStopFailureMode -p MainPID
systemctl show mesh-nebula.service -p FragmentPath -p DropInPaths -p TimeoutStopFailureMode -p MainPID
test -r /var/lib/mesh-installer/runtime.enabled
test -r /run/mesh-agent/nebula.validated
journalctl -u mesh-agent.service -u mesh-nebula.service
```

`mesh-nebula.service` is static and intentionally has no `[Install]` section.
Each managed unit must report only its exact installer-owned
`10-timeout-abort.conf` in `DropInPaths` and
`TimeoutStopFailureMode=terminate`; any other drop-in remains forbidden.
Never enable or independently supervise it. Remove any legacy
`nebula.service`, cron job, container, or other supervisor before installation;
two runtime owners invalidate Mesh's bounded-revocation guarantee.
