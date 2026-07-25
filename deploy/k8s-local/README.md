# Local Kubernetes deployment

This deployment is isolated in the `mesh-system` namespace of the
`local-verify` cluster and leaves host development listeners unchanged.

- Mesh: `https://mesh.verify.rw0.io`
- Authentik: `https://auth-mesh.verify.rw0.io`
- Release origin: `https://releases-mesh.verify.rw0.io`
- Authentik chart: `authentik/authentik` version `2026.5.6`
- Mesh image: the exact digest recorded in `mesh-values.yaml`
- Persistent state: one local-path PVC for Mesh and one for Authentik PostgreSQL
- Helm releases: `mesh`, `mesh-authentik`, and `mesh-origin` in `mesh-system`

The OIDC application slug is `mesh`, with the per-provider issuer
`https://auth-mesh.verify.rw0.io/application/o/mesh/` and callback
`https://mesh.verify.rw0.io/api/v1/auth/oidc/callback`.

Role groups are mapped directly into the `groups` ID-token claim:

| Authentik group | Mesh role |
| --- | --- |
| `mesh-admins` | `admin` |
| `mesh-operators` | `operator` |
| `mesh-viewers` | `viewer` |

Runtime secrets are Kubernetes Secrets and are intentionally absent from this
directory. Retrieve the bootstrap identities only through an authorized
cluster-admin session:

```bash
kubectl --context local-verify -n mesh-system get secret mesh-login-credentials \
  -o jsonpath='{.data.admin-username}' | base64 -d
kubectl --context local-verify -n mesh-system get secret mesh-login-credentials \
  -o jsonpath='{.data.admin-password}' | base64 -d
```

The operator and viewer records use the corresponding `operator-*` and
`viewer-*` keys. The Authentik API bootstrap token and Mesh recovery bearer are
kept in `mesh-authentik-env` and `mesh-credentials`; neither is a routine
browser credential.

## Repeat the live RBAC check

The Firefox audit signs in through Authentik as each seeded identity, verifies
the OIDC issuer and group claim, checks the resolved Mesh permissions, and
probes read, write, security, and identity-management boundaries without
creating a network:

```bash
python3 bin/ui-audit/verify_k8s_rbac.py
```

Screenshots and the geckodriver log are written to
`bin/ui-audit/20260722-k8s-rbac/`. The script retrieves credentials directly
from the Kubernetes Secret and does not write their values to the workspace.

## Live lifecycle proof

The 2026-07-22 production-shaped check used the seeded `mesh-admins` identity
through Authentik and the real browser UI to create `quickstart-live-3`
(`10.91.0.0/24`), its first lighthouse, and its first member. The guided UI
completed in 4.998 seconds and verified the exact pending-readiness evidence
before publishing any proof output. Both one-time credentials were then
consumed through stdin, both generated Nebula 1.10.3 bundles passed certificate
and configuration verification, and both agents converged on signed
configuration revision 2.

The packet check started the two real Nebula peers in separate Linux network
namespaces joined only by a point-to-point veth. Both directions resolved over
the Nebula `tun0` interfaces, and the member delivered 3 of 3 ICMP packets to
the lighthouse with zero packet loss. The temporary peers and namespaces were
removed after the check; the authored network and node inventory remain
visible in the UI.

The private evidence is in `bin/ui-audit/20260722-live-onboarding/`:

- `ui-guide.json` records the OIDC-guided workflow and elapsed time.
- `lighthouse-created.json` and `member-created.json` retain the private
  browser-issued enrollment records.
- `packet-proof.json` is the sanitized packet-level receipt.
- `packet-work/` retains the private enrolled state and validation logs.

The directory is mode `0700`; files containing credentials, keys, state, or
receipts are mode `0600`. Do not publish or attach the directory as a whole.

The cluster also serves one immutable, threshold-signed v0.1.0 release
generation through the digest-pinned `mesh-origin` Helm release. The origin is
only a read-only courier: release signing keys and the independent bootstrap
anchor remain outside Kubernetes. `release-origin-values.yaml` records the
exact image and generation digests, while
`release-origin-servers-transport.yaml` makes Traefik validate the native TLS
backend with the public release-origin SNI.

## Live clean-host online installation proof

The 2026-07-23 clean-host check started two pristine Fedora 42 systemd hosts on
an isolated `192.0.2.0/24` underlay. Before any transfer, each host proved that
`mesh-install`, `meshctl`, installer state, and agent state were absent and
that `/dev/net/tun` was present. The only locally transferred object was the
independent `bootstrap-anchor.json`; each host fetched the handoff, Linux
bootstrap verifier, trust root, two detached signatures, installer, and release
from `https://releases-mesh.verify.rw0.io`.

Both hosts independently verified the anchored handoff and two release signers,
installed v0.1.0 using the exact command displayed by the OIDC-authenticated UI,
consumed their one-time enrollment tokens through stdin, and ran the exact
displayed activation command. The control plane then reported both nodes
active with Nebula running. The member at `10.92.0.11` delivered 3 of 3
authenticated overlay ICMP packets to the lighthouse at `10.92.0.10` with zero
loss, four seconds after member enrollment began.

The live readiness endpoint reported passing authenticated node-route,
member-DNS, and active public-UDP probe evidence. Its overall state remains
`verification_required` because this deliberately minimal two-node network has
one lighthouse; the UI correctly recommends a second lighthouse in an
independent failure domain for production redundancy.

The sanitized receipt is
`bin/ui-audit/20260722-clean-host-online/clean-host-proof/clean-host-online-proof.json`.
The adjacent SHA-256 manifest covers the bootstrap, install, activation,
server-state, readiness, and packet receipts. The proof directory is mode
`0700`, its files are mode `0600`, and an explicit scan confirmed that it
contains no enrollment token, admin token, master key, or private key. The
temporary hosts and their Docker network were removed after the proof.
