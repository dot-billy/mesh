# HTTPS Compose deployment

This is the first production-shaped container deployment for the Mesh control
plane. It runs one JSON-backed replica with native TLS, a read-only image,
owner-only file-mounted recovery credentials, no Linux capabilities, a
non-root UID/GID, bounded process and memory resources, rotated local logs, and
a readiness check that verifies the TLS identity plus `/readyz` durable-store
validation.

It is not a signed release image, an HA topology, or the independent Linux
installer bootstrap/origin ceremony. Build and authenticate the image through
your release system, protect the host and Docker authority, back up the data
directory, and use the separately authenticated installer release path before
calling this production.

Before retaining or deploying a candidate, run `make security-baseline` and
`make image-security-baseline` from the repository root. The latter publishes a
create-only, digest-bound Syft/SPDX/vulnerability/secret evidence set described
in [`docs/image-security.md`](../../docs/image-security.md). It covers this
Linux amd64 control-plane image only and does not sign or publish it.

## Prepare the host

Copy `.env.example` to a private deployment directory as `.env`, replace every
path and origin, and set `MESH_RUNTIME_UID`/`MESH_RUNTIME_GID` to the numeric
owner of the state and secret files. `MESH_PUBLIC_HOST` must be present in the
server certificate and is used by the in-container TLS readiness verifier.

Create the state directory with mode `0700`. Create independent 256-bit
credentials as canonical unpadded base64url, one per owner-only mode-`0600`
file:

```bash
umask 077
install -d -m 0700 /srv/mesh/data /srv/mesh/secrets /srv/mesh/tls
openssl rand -base64 32 | tr '/+' '_-' | tr -d '=\n' > /srv/mesh/secrets/admin.token
printf '\n' >> /srv/mesh/secrets/admin.token
openssl rand -base64 32 | tr '/+' '_-' | tr -d '=\n' > /srv/mesh/secrets/master.key
printf '\n' >> /srv/mesh/secrets/master.key
chmod 0600 /srv/mesh/secrets/admin.token /srv/mesh/secrets/master.key
```

Install a real server certificate, private key, and CA bundle at the configured
TLS paths. The private key and both recovery credentials must be owned by the
runtime UID and inaccessible to group/other users. The certificate may be
public. If the server certificate is issued by an intermediate, `ca.crt` must
contain the roots needed to verify that certificate from inside the container.

`MESH_LINUX_INSTALL_BUNDLE_URL` and
`MESH_LINUX_BOOTSTRAP_HANDOFF_URL` may be empty while provisioning the control
plane. Setting them only teaches the authenticated dashboard the exact
canonical HTTPS courier locations. The dashboard explicitly labels the
handoff as unauthenticated and supplies neither an anchor nor its expected
digest; bootstrap authority must come from the independent operator channel.

## Validate and start

From this directory, with the private environment file outside source control:

```bash
docker compose --env-file /secure/path/mesh.env config --quiet
docker compose --env-file /secure/path/mesh.env build --pull
docker compose --env-file /secure/path/mesh.env up -d
docker compose --env-file /secure/path/mesh.env ps
```

Wait for `healthy`, then open `MESH_PUBLIC_URL` and sign in with the contents of
the administrator-token file. A restart must retain the same state:

```bash
docker compose --env-file /secure/path/mesh.env restart mesh
docker compose --env-file /secure/path/mesh.env ps
```

Use `mesh-backup` and the documented restore fence before upgrades. Never copy
the JSON files from a running container or place the recovery credentials in
Compose environment variables.
