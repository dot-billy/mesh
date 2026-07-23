# Browser identity and OIDC operations

Mesh supports three production browser and operator authentication paths:

- persistent browser sessions created through OIDC;
- optional browser or direct API authentication with the shared administrator token in legacy and hybrid modes; and
- browser sessions created by one-use break-glass codes when that lifecycle is enabled.

OIDC-only mode removes the shared administrator token from HTTP authentication and requires a proven inventory of at least 2-32 unexpired, unused, unrevoked break-glass codes at every startup. The administrator token remains an offline cryptographic recovery binding for control and backup state, so it must still be stored as a production root credential. Invalid local policy, client-secret, identity-state, or recovery-inventory checks fail startup before an authentication path is available.

## Configure hybrid OIDC

1. Copy the strict example policy to a private path owned by the account that runs `mesh-server` (run these commands as that account, or set the ownership explicitly afterward):

   ```bash
   install -d -m 0700 /etc/mesh
   install -m 0600 \
     config/mesh-identity.example.json \
     /etc/mesh/identity.json
   ```

   `--identity-config` requires a clean absolute path, real (non-symlink) directory components, and an owner-controlled regular file with exactly one hard link and no group/other permissions. New deployments use strict `mesh-identity-v2`; the existing `mesh-hybrid-identity-v1` schema remains readable without gaining OIDC-only behavior. Duplicate JSON names, unknown fields, trailing data, and unsafe duration or URL forms are rejected.

2. Edit the copied policy for the provider. Set the canonical HTTPS issuer, client ID, scopes, permitted ID-token signing algorithms, administrator selectors, role bindings, and MFA assurance policy. Any matching `subject`, canonical `verified_email`, or configured `group` selector in either `admins` or `role_bindings` grants login access. Selectors in `admins` grant the `admin` role; selectors in `role_bindings` grant their explicit role. A selector may appear only once across the complete access policy.

   At least one assurance rule is mandatory. `required_acr_any` accepts one of the configured ACR values; `required_amr_all` requires every configured AMR value. `max_authentication_age` also requires a recent provider authentication. The example requires both `pwd` and `otp`, limits authentication age to 15 minutes, and leaves `legacy_browser_login` false so the shared token is not offered in the browser.

## Role-based access control

Mesh resolves one role for every authenticated request and enforces permissions in the HTTP server before a route handler can read request content or mutate control state. The session response includes the resolved `role` and `permissions` so the dashboard can hide unavailable actions, but those client fields are informational only.

| Role | Network visibility | Routine lifecycle changes | Trust/security changes | Identity administration |
| --- | --- | --- | --- | --- |
| `viewer` | Read inventory, health, readiness, policy state, telemetry, and audit | No | No | No |
| `operator` | Same as viewer | Create networks/nodes; manage enrollment, topology, DNS, relays, firewall, and routes | No | No |
| `admin` | Full | Full | CA rotation, network retirement, agent recovery, identity replacement, certificate rotation, revocation, and archival | Session and recovery-code management |

The legacy administrator bearer, legacy browser session, service principals, and break-glass sessions resolve to `admin`. Existing break-glass restrictions still apply: a break-glass session cannot list, create, or revoke recovery codes even though it can recover the rest of the control plane.

OIDC role bindings are part of the identity policy fingerprint. Adding, removing, or changing a binding intentionally invalidates existing browser sessions at the next restart, ensuring a stale session cannot retain authority from an older policy. When a principal matches more than one binding, Mesh selects the highest role (`admin`, then `operator`, then `viewer`).

Example group bindings:

```json
"admins": [
  { "kind": "group", "value": "mesh-admins" }
],
"role_bindings": [
  {
    "role": "operator",
    "selector": { "kind": "group", "value": "mesh-operators" }
  },
  {
    "role": "viewer",
    "selector": { "kind": "group", "value": "mesh-viewers" }
  }
]
```

3. Provision the client secret separately as a mode-0600 file at the clean absolute `client_secret_file` path. The service account must own this single-link, owner-readable, non-executable regular file. The file is read as exact UTF-8 secret bytes: do not add a newline or surrounding whitespace. Use a secret manager or an equivalent private-file delivery path rather than putting the secret in the JSON policy.

4. Register this exact redirect URI with the provider, using the same origin supplied to `--public-url`:

   ```text
   https://mesh.example.com/api/v1/auth/oidc/callback
   ```

5. Generate `MESH_ADMIN_TOKEN` and `MESH_MASTER_KEY` once, store them in a secret manager, and load the same values on every restart. The exports below are first-deployment generation examples; do not regenerate them as part of service startup. Then start Mesh with the private policy and an HTTPS public origin. For a trusted TLS reverse proxy:

   ```bash
   export MESH_ADMIN_TOKEN="$(openssl rand -base64 48 | tr -d '\n')"
   export MESH_MASTER_KEY="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
   ./bin/mesh-server \
     --listen 127.0.0.1:8080 \
     --public-url https://mesh.example.com \
     --behind-tls-proxy \
     --identity-config /etc/mesh/identity.json \
     --data-dir /var/lib/mesh
   ```

   The proxy must be the only external path to Mesh and must provide the canonical public HTTPS origin. The proxy-marked backend is restricted to loopback. Mesh does not trust `X-Forwarded-For` or similar headers. With native TLS, provide `--tls-cert` and `--tls-key`, bind the required listener, and set `--public-url` to the exact browser origin (including any non-default port). Default ports must be omitted from canonical URLs.

The policy, client secret, and identity state are loaded only at startup; there is no hot reload. A local validation or read failure prevents `mesh-server` from listening. In hybrid mode, a later remote discovery outage does not affect direct bearer requests. In OIDC-only mode, use an independently custodied one-use recovery code.

## Provision recovery codes and cut over to OIDC-only

Start with the v2 example in `"mode": "hybrid"`. Sign in through OIDC, open **Activity**, and create at least the configured `minimum_usable_codes`. The authenticated inventory shows its same-snapshot usable count, configured floor, and an explicit **Restart ready** or **Below floor** result; no cutover or restart safety is inferred when that read fails. Each displayed value has the form `mesh-bg-v1.bg_<id>.<secret>` and is generated from two independent 256-bit Web Crypto values in the browser. Mesh stores only the secret hash. Copy or save each code to a separate approved secure location, acknowledge custody, and close the dialog; the dashboard scrubs its in-memory plaintext when the dialog closes, the tab becomes hidden, or the session ends.

After independently verifying custody, stop Mesh, change only `"mode": "oidc"`, and restart. The v2 loader infers that the legacy bearer is disabled, rejects legacy browser login, and performs a current identity-store read before constructing the HTTP server. Startup fails if fewer than the configured minimum codes are usable. Keep the same external `MESH_ADMIN_TOKEN`; OIDC-only mode no longer accepts it over HTTP, but control-state and backup recovery still require its existing cryptographic binding.

A recovery login consumes one code atomically before creating a browser session. Invalid, malformed, expired, used, and revoked codes receive the same delayed unauthorized response. A successful session has at most a five-minute idle lifetime and fifteen-minute absolute lifetime, uses independent session and CSRF credentials, and can administer the control plane. It cannot list, create, or revoke recovery codes. If the response or process is lost after consumption, that code remains burned; the mandatory inventory floor preserves another recovery path. After the IdP returns, use a normal OIDC session to replace consumed or expiring codes before the next restart.

The native Windows `mesh-server` currently fails closed in every identity mode, including legacy-only mode, because the package cannot yet prove the private identity-state DACL. Supplying `--identity-config` is also rejected, and private client-secret DACL proof is not implemented. Cross-compiled binaries do not constitute a supported Windows control-plane runtime.

## OIDC security contract

Mesh uses Authorization Code flow with a one-use 256-bit state, independent 256-bit nonce, and PKCE S256. Discovery is lazy and retryable: `mesh-server` can start, and the administrator bearer remains usable, while the IdP is unavailable. An OIDC start attempt fails until strict HTTPS discovery succeeds.

Discovery must preserve the exact issuer and advertise the code flow, PKCE S256, a configured signing algorithm, and a supported explicit client-secret authentication method. Mesh does not use OAuth client's automatic auth-style retry. Redirects and discovery/JWKS/token responses are bounded.

On callback, Mesh consumes a valid state transaction once before exchanging the code. It requires a signed ID token and strictly validates issuer, subject, audience and authorized party, expiry, issued-at time, nonce, authentication time, configured ACR/AMR assurance, selector authorization, typed verified-email/group claims, and `at_hash` when present. It does not fall back to UserInfo, request `offline_access`, retain provider access/ID tokens, or retain refresh tokens.

Consumption, token exchange, session persistence, and cookie delivery are deliberately not one transaction. Discovery failure occurs before consumption and can be retried while the attempt remains valid; a wrong state does not burn the legitimate attempt. After a valid state is consumed, an exchange, validation, persistence, timeout, or process failure requires a fresh OIDC start. If session persistence commits but the response or cookies are lost, the browser cannot recover that bearer; the inaccessible record can remain visible even after expiry until it is pruned or explicitly revoked. This is an availability boundary, not an authentication bypass.

MFA is enforced through the provider claims selected in the policy: Mesh rejects a signed login whose ACR/AMR claims do not meet that policy. Break-glass codes are a separate one-use recovery authority, not an MFA factor or native WebAuthn implementation.

## Cookies and sessions

An OIDC start sets a short-lived HttpOnly, Secure, SameSite=Lax `__Host-mesh_oidc` transaction cookie on `/`; Lax permits the top-level provider callback. A consumed success or provider denial clears it. Successful login returns only to a validated same-origin relative path and creates:

- HttpOnly, Secure, SameSite=Strict `__Host-mesh_session`, containing an independent 256-bit opaque session token;
- Secure, SameSite=Strict `__Host-mesh_csrf`, containing a separate 256-bit CSRF credential used by browser writes.

Only SHA-256 hashes of the session and CSRF tokens are stored in `identity-state.json`. OIDC state and transaction tokens are also hashed; nonce and PKCE material are authenticated-encrypted under the master key for the lifetime of the login attempt. Provider tokens are not persisted.

Sessions have both an idle expiry and an absolute expiry. Activity extends the idle deadline at the configured touch interval but never beyond the absolute deadline. Logout, expiry, explicit revocation, or an identity-policy fingerprint change makes a session unusable. Policy/configuration changes take effect only after restart.

Persisted sessions are part of coordinated recovery state. Do not copy `identity-state.json` independently: use `mesh-backup` so the exact identity and control stores, master key, and administrator credential are captured under both offline locks and cryptographically validated together. The identity policy, canonical public URL, and OIDC client secret remain external recovery requirements. Restoring those values unchanged preserves otherwise-valid opaque sessions; changing the policy fingerprint or legacy credential binding invalidates them intentionally. See [backup and recovery](backup-recovery.md).

Session time checks fail closed on wall-clock rollback: a request timestamp earlier than the session's last accepted activity is rejected rather than extending or bypassing its idle or absolute lifetime. Production hosts still need trustworthy time synchronization because a forward jump can expire sessions early.

When `legacy_browser_login` is enabled, the startup session fingerprint is additionally bound to both `MESH_ADMIN_TOKEN` and `MESH_MASTER_KEY`. A successful restart with a changed binding rejects every browser session in that configuration, including OIDC sessions. With the example's `legacy_browser_login: false`, rotating the administrator bearer does **not** invalidate existing OIDC sessions; revoke them explicitly or change the identity policy. Replacing `MESH_MASTER_KEY` is not a supported logout operation because that key also protects existing CA and signing state. Changing only the OIDC client-secret bytes or path does not change the session policy fingerprint, and the new secret is not read until restart.

Control schema v2 independently anchors the master key and the master/admin pair. A changed administrator bearer therefore fails startup unless the operator keeps the exact master key and supplies `--rotate-admin-token` for that one startup. Verify the rotation audit and remove the flag immediately; it is not a permanent compatibility option. Development-mode rotation must replace the private persisted `admin.token` first rather than relying on an environment override that disappears on the next restart.

Administrators can inspect and revoke sessions with the full-privilege bearer:

```bash
curl --fail --silent --show-error \
  -H "Authorization: Bearer $MESH_ADMIN_TOKEN" \
  'https://mesh.example.com/api/v1/sessions?limit=100&include_revoked=false'

curl --fail --silent --show-error -X DELETE \
  -H "Authorization: Bearer $MESH_ADMIN_TOKEN" \
  'https://mesh.example.com/api/v1/sessions/SESSION_ID'
```

Repeated DELETE of a retained, already-revoked session is successful. Revoking the currently used browser session also clears its cookies. Bearer-authenticated automation does not create a browser session and does not use cookie CSRF.

The session list is inventory, not an assertion that each record can still authenticate. `include_revoked=false` excludes explicitly revoked records only; an expired session or one carrying an old policy fingerprint can remain listed until a later cleanup even though authentication rejects it.

## Audit boundaries

Authenticated `GET /api/v1/audit` returns the newest 100 combined control and identity events with no query filters. It sorts by timestamp, then event ID, and exposes the actor structurally; identity events also identify their target principal and session. The dashboard **Security activity** view uses this endpoint. Identity actions include `session.created`, `session.rotated`, `session.revoked`, `principal.revoked`, `break_glass.registered`, `break_glass.consumed`, and `break_glass.revoked`.

The combined response is not a transactional snapshot. Control mutations and their audit records commit together in `state.json`; identity mutations and their audit records commit together in `identity-state.json`. Those two files have separate locks and transactions, no shared sequence, and no cryptographic integrity link. Equal or nearby timestamps do not establish a global causal order. The offline recovery command coordinates both locks and stores but does not make the audit streams globally ordered.

The durable identity audit is append-only and capped at 8,192 events. There is no pruning, archival, or external export path. When the cap is reached, any new session creation or audited session rotation/revocation fails closed with its mutation; existing authenticated sessions continue until another rule rejects them. Monitor capacity before it becomes an availability event. The merged HTTP response cap of 100 is a read limit and does not reduce the durable log.

## Edge controls and recovery

OIDC endpoints have bounded concurrency plus global and address-keyed process-local token buckets. With the required loopback reverse proxy, every request reaches Mesh from the proxy address, so all users collapse into one apparent client and share that bucket. Mesh deliberately ignores forwarded client-IP headers rather than trusting spoofable values. The trusted edge must enforce distributed limits using a verified client address or identity; otherwise one client can throttle every OIDC login. Native-TLS deployments retain Mesh's address separation, but the counters are still neither shared across replicas nor durable.

The optional legacy browser-token login has only a bounded pool of delayed failure workers; it does not have the OIDC global/per-client token buckets. Apply trusted-edge rate limiting to it as well. Do not treat any in-process limit as a perimeter control.

If the remote IdP is unavailable in hybrid mode, the retained administrator bearer remains the deliberate full-privilege recovery authority. In OIDC-only mode it is rejected over HTTP; use one independently custodied break-glass code instead. Neither path can recover a process that refuses to start because local policy, secret, state, key validation, or the configured usable-code floor fails. Test code custody, one-use login, replacement, and offline local-configuration recovery before relying on OIDC-only production access.
