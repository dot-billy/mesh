# Mesh control-plane Helm deployment

This chart deploys the existing production Mesh control plane with native TLS,
digest-only images, non-root runtime execution, a read-only root filesystem,
durable JSON state or an external PostgreSQL authority, and verified startup
and readiness probes. It deliberately does not mint recovery credentials,
certificates, image trust, or a release-origin bootstrap channel inside Helm.

Kubernetes projected Secret keys are root-owned symlinks. Mesh does not weaken
its private-file checks to accept them. A narrow init command from the same
digest-pinned image reads only fixed projected keys, validates the canonical
credentials and complete TLS identity, copies them into a memory-backed
create-only regular-file directory owned by UID/GID 65532, and prepares only
the JSON volume's mount root. It runs with only `CHOWN`, `DAC_OVERRIDE`, and
`FOWNER`; the server has no capabilities and receives no service-account token.

## Prerequisites

- Kubernetes 1.29 or newer and Helm 4.
- A published, authenticated `linux/amd64` or `linux/arm64` control-plane image
  and its exact `sha256:` digest. Run `make security-baseline` and
  `make image-security-baseline` before publishing the image.
- A server certificate covering the exact `publicHost`, its private key, and a
  CA bundle that verifies that certificate.
- A storage class for JSON mode, or an already initialized external PostgreSQL
  deployment following [`docs/ha-storage.md`](../../../docs/ha-storage.md).

Create the namespace and credentials without placing credential bytes in Helm
values or shell arguments:

```bash
kubectl create namespace mesh-system
umask 077
mesh_secret_dir="$(mktemp -d)"
openssl rand -base64 32 | tr '/+' '_-' | tr -d '=\n' >"${mesh_secret_dir}/admin.token"
printf '\n' >>"${mesh_secret_dir}/admin.token"
openssl rand -base64 32 | tr '/+' '_-' | tr -d '=\n' >"${mesh_secret_dir}/master.key"
printf '\n' >>"${mesh_secret_dir}/master.key"
kubectl -n mesh-system create secret generic mesh-credentials \
  --from-file=admin.token="${mesh_secret_dir}/admin.token" \
  --from-file=master.key="${mesh_secret_dir}/master.key"
kubectl -n mesh-system create secret generic mesh-tls \
  --from-file=tls.crt=/secure/mesh/server.crt \
  --from-file=tls.key=/secure/mesh/server.key \
  --from-file=ca.crt=/secure/mesh/ca.crt
```

Remove the temporary directory through the workstation's recoverable secure
cleanup procedure after separately recording the administrator token and
master key in their approved custody systems.

Create a private values file:

```yaml
image:
  repository: registry.example.com/mesh/control-plane
  digest: sha256:REPLACE_WITH_EXACT_64_HEX_DIGEST

publicURL: https://mesh.example.com
publicHost: mesh.example.com

credentials:
  secretName: mesh-credentials
tls:
  secretName: mesh-tls

storage:
  backend: json
  persistence:
    size: 2Gi
```

Install atomically and wait for the TLS-identity-verifying durable-store probe:

```bash
helm upgrade --install mesh \
  ./packaging/helm/mesh-control-plane \
  --namespace mesh-system \
  --values /secure/mesh/values.yaml \
  --atomic --wait --timeout 5m
kubectl -n mesh-system rollout status deployment/mesh-mesh-control-plane
```

Before touching a cluster, `make helm-chart-smoke` verifies strict JSON,
PostgreSQL, OIDC, Ingress, and NetworkPolicy renders. After building the exact
candidate image locally, run
`MESH_HELM_SMOKE_IMAGE=registry.example.com/mesh/control-plane@sha256:... make helm-runtime-smoke`.
That self-cleaning container drill simulates Kubernetes projected Secret
symlinks, exercises the init capability set, starts the same image as a non-root
server, verifies its TLS identity and `/readyz`, and requires all three JSON
state documents. It is still not a Kubernetes storage, Secret, or ingress proof.

For an explicit cluster-admin mechanism proof, run
`MESH_HELM_KUBERNETES_IMAGE=mesh-control-plane:helm-contract-verified make helm-kubernetes-smoke`.
The harness requires a matching image-security receipt no older than 24 hours,
creates one isolated namespace, imports and names that exact digest through a
short-lived privileged RKE2 loader, creates ephemeral credential/TLS Secrets
and a proof-owned node-local PV, installs the chart, creates real authoritative
network state over verified TLS, deletes the running pod, and requires a new
pod identity to recover that exact state from the same PVC. It then removes the
release, namespace, PVC/PV directory, host archive, and both image aliases and
publishes a create-only receipt under `bin/helm-kubernetes/`.

The first audited homelab run passed on RKE2 v1.35.0. An earlier attempt through
the cluster's default Longhorn class provisioned and attached a volume, but
`k8s-01` refused its first ext4 format because the block device appeared in use.
The harness did not modify Longhorn and does not claim that production storage
path. The passing node-local proof establishes the chart and Kubernetes
lifecycle mechanism, not registry/admission, production Secret/PVC, ingress,
multi-node failover, backup, or recovery operations.

Expose the Service only through an edge that forwards HTTPS to the `https`
backend port. When enabling the chart's Ingress, set the controller-specific
HTTPS-backend annotation and its public TLS Secret; a controller that forwards
cleartext HTTP cannot reach this native-TLS backend. The chart does not claim
that an arbitrary Ingress controller verifies the backend certificate.

## OIDC and PostgreSQL

OIDC mode requires one Secret containing `identity.json` and
`oidc-client.secret`. The policy's `oidc.client_secret_file` must be exactly
`/run/mesh/private/oidc-client.secret`. Set `identity.enabled=true` and
`identity.secretName`. The init command validates JSON syntax and materializes
both files under the same strict private-file contract; `mesh-server` still
performs the authoritative identity-policy validation.

PostgreSQL mode requires a Secret containing one canonical `postgres.dsn` line.
Set `storage.backend=postgres` and `storage.postgres.secretName`. The chart then
omits the JSON PVC and permits up to nine application replicas. It does not
deploy, migrate, import, back up, or promote PostgreSQL for you; complete those
operations with `mesh-storage` before starting the application replicas.

## Upgrades, rollback, and network policy

JSON mode is fixed to one replica and uses `Recreate` so two processes never
concurrently own the file store. Take a coordinated Mesh backup before every
upgrade and use Helm's atomic rollback only with a storage-compatible image.
PostgreSQL mode uses a zero-unavailable rolling update, but database migrations
and release compatibility remain explicit operator gates.

`networkPolicy.enabled` creates an ingress-only allowlist to TCP/8443. Supply
`networkPolicy.ingressFrom` for the exact ingress/controller namespace or pod
selectors. Egress remains untouched because OIDC discovery, PostgreSQL, and
operator-selected integrations differ by deployment; enforce it with a
site-specific policy after enumerating those destinations.
