# OIDC-only break-glass lifecycle

**Status:** Implemented and self-contained lifecycle proof passing.

## Problem

Mesh can persist one-use break-glass records and attribute a break-glass
principal, but no production path can provision, inventory, consume, or revoke
those records. Identity configuration therefore keeps the shared administrator
bearer enabled and rejects OIDC-only mode. That leaves a powerful reusable HTTP
credential in every production deployment even when browser token login is
hidden.

The administrator credential remains required as an offline recovery binding
for encrypted control and backup state. OIDC-only mode removes it from HTTP
authentication; it does not remove or weaken that cryptographic recovery
binding.

## Credential and custody boundary

A displayed recovery code is one canonical string:

```text
mesh-bg-v1.bg_<256-bit-base64url-id>.<256-bit-base64url-secret>
```

The browser generates both random values with Web Crypto before registration.
The server strictly parses the string and stores only the secret SHA-256 with
the record ID, creation time, and expiry. Registration never returns or
persists the plaintext code. An ambiguous registration can retry the same
code and expiry exactly; the retained browser value is still usable after the
server confirms inventory by ID. The UI must keep the plaintext only in memory,
show it once, require an explicit custody acknowledgement, and scrub it when
the dialog closes, the view hides, or the session ends.

Codes expire after at most 90 days and are one-use. Operators should create
several, split their custody, and exercise replacement before expiry. A
break-glass-authenticated session cannot create or revoke codes, so one recovery
code cannot mint a permanent replacement authority during an IdP outage.

## Configuration and startup

The strict `mesh-identity-v2` policy names `mode` as `hybrid` or `oidc` and has
an explicit break-glass block. Hybrid mode continues to require the legacy
bearer and may enable break-glass provisioning before cutover. OIDC-only mode
requires:

- OIDC configuration and HTTPS;
- legacy browser login and legacy bearer both disabled;
- break glass enabled;
- a configured minimum of 2-32 usable codes; and
- a current identity-store read proving at least that many unexpired, unused,
  unrevoked codes before the HTTP server is constructed.

The v1 hybrid policy remains readable and retains its existing behavior. A
v2 policy change alters the policy fingerprint and intentionally invalidates
old sessions.

## API and session lifecycle

Public `GET /api/v1/auth/methods` exposes only whether OIDC, legacy browser
login, and break-glass login are configured. Public break-glass login is a
same-origin JSON POST with the combined code. Invalid, expired, used, revoked,
or malformed values receive the same bounded delayed unauthorized response.

Authenticated non-break-glass administrators can:

- list credential-free code summaries;
- register one browser-generated code with a canonical expiry; and
- revoke an unused code idempotently.

Registration, consumption, and revocation each append a credential-free
identity audit event in the same document transaction as the record mutation.
Successful consumption creates a short break-glass browser session with a
maximum 5-minute idle and 15-minute absolute lifetime, independent session and
CSRF credentials, and the existing full actor attribution. Consumption and
session creation remain separate durable transactions: response loss or a
crash may burn one code without delivering a session, but can never reuse the
code or create an unaudited success. The startup minimum exists so a second
independently custodied code can recover that availability failure.

## Proof

Store tests cover exact registration retry, collision, inventory without
hashes, atomic audit, use, expiry, revocation, replay, and usable counts on JSON
and PostgreSQL adapters. HTTP and browser tests cover same-origin enforcement,
uniform failure, principal/session attribution, short lifetime, CSRF, response
scrubbing, forbidden code management by break-glass sessions, and v1/v2 policy
behavior. A self-contained server proof must provision codes in hybrid mode,
restart in OIDC-only mode with no HTTP bearer, consume exactly one code, mutate
through its session, reject replay, retain another usable code, and fail startup
when inventory falls below the configured minimum.
