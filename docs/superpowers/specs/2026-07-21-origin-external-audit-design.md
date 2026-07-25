# External release-origin deployment audit

**Status:** Implementation target.

## Problem

Origin generation inspection proves local bytes and layout, while container
health proves one loopback readiness route. Neither proves that the public TLS
route serves the selected generation without proxy, mount, header, or rollout
drift. Operators need a rerunnable deployment gate and monitor that compares
the public service to one exact retained generation.

## Boundary

`mesh-origin-audit` is a read-only external observer. It has no signing,
publishing, installation, control-plane, or private-key operation. The origin
index and audit receipt remain courier evidence, not release authority. Only
the independently authenticated bootstrap handoff and threshold-signed release
metadata authorize software.

The auditor accepts one clean absolute local generation, one canonical HTTPS
origin base URL, an optional explicit CA bundle, one bounded total timeout, and
an optional create-only receipt path. It first performs full generation
inspection. It never downloads an index from the origin or lets the origin
choose expected bytes.

## Public verification

Using a proxy-disabled, cookie-free, redirect-rejecting, compression-disabled
TLS 1.2+ client, the auditor must:

1. require exact `/readyz` status, JSON bytes, no-store policy, security
   headers, and TLS identity;
2. issue HEAD and GET for every object in path order;
3. require status 200, identity transfer, exact content length, content type,
   cache policy, SHA-256 ETag, and security headers on both methods;
4. stream exactly the indexed byte count and compare SHA-256 in constant time;
5. require one consistent leaf-certificate SHA-256 and expiry across all
   responses;
6. require one canonical unlisted GET to remain 404 and one write attempt to
   remain 405; and
7. fail without a receipt on any timeout, redirect, TLS failure, extra/missing
   body byte, header drift, generation mismatch, or route ambiguity.

The client deliberately uses HTTP/1.1 and does not inherit environment proxy
settings. The optional CA bundle is bounded and read from one unchanged regular
file; omitting it uses system roots.

## Receipt

Success emits canonical `mesh-release-origin-audit-v1` JSON plus one LF. It
binds the generation/index digest, canonical origin URL, observed leaf
certificate SHA-256 and expiry, explicit UTC verification time, object count,
and exact total bytes. A file output is clean absolute, create-only, fsynced,
and never replaced. The receipt is safe for monitoring but is not a signature
or independent trust anchor.

## Proof

Unit tests use a real TLS test server and exact generated generation to prove
success plus rejection of changed bodies, headers, ETags, redirects,
certificate drift, readiness drift, unknown routes, writes, stale local
generation evidence, and output replacement. The native-TLS origin smoke runs
the production auditor after candidate selection and again after rollback. It
requires candidate-only exposure to be reflected by the matching generation,
then requires the prior receipt after rollback, and requires mutation to fail
without producing evidence.
