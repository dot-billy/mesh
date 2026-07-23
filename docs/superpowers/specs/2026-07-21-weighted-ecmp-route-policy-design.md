# Weighted ECMP routed-prefix policy

Status: implemented and verified on 2026-07-21

## Runtime contract

Mesh is pinned to Nebula 1.10.3. That runtime accepts one
`tun.unsafe_routes` entry whose `via` value is a list of gateway objects. Each
gateway has a positive integer weight. Nebula calculates hash-threshold buckets
from those weights and selects a gateway from the packet's local and remote
transport ports. If the selected gateway is not reachable through the overlay,
Nebula tries the other configured gateways and temporarily ignores the weights
to preserve connectivity.

This is real weighted ECMP. Separate duplicate unsafe-route entries are not a
multipath representation: Nebula inserts routes into a prefix table, so the
later duplicate replaces the earlier value. Mesh must therefore render exactly
one route entry per prefix.

`metric` controls the installed host route, `mtu` overrides the route MTU where
the operating system supports it, and `install` controls host-route
installation. Mesh keeps `install: true` for managed routes so dashboard-created
routes remain usable by ordinary host applications. The operator-facing route
controls are weight, metric, and MTU.

## Durable model

`Node.routed_subnets` remains the certificate-authorization source of truth. An
exact prefix may be held by multiple active, enrolled nodes in the same network;
partial, covering, cross-network, managed-CIDR, and special-range overlaps remain
invalid. A prefix has at most eight gateways.

Each network may retain a canonical route policy for a live exact prefix:

- one sorted gateway record for every current active certificate owner;
- a weight from 1 through 1,000 for every gateway;
- MTU 0 (inherit the tunnel MTU) or 500 through 65,535; and
- metric 0 through 2,147,483,647.

The gateway set in a stored policy must exactly match current active ownership.
An absent policy derives equal weight 1, inherited MTU, metric 0, and installed
host routing. Reconciliation after an ownership mutation preserves surviving
weights and route controls, gives a new gateway weight 1, removes departed
gateways, and removes policy state after the final owner disappears.

## Certificate-first membership changes

The existing route-profile state machine is the only active-node path for
joining or leaving an ECMP group:

- Joining adds an exact prefix already owned in the same network. The new
  gateway receives and proves the expanded certificate before promotion. Peers
  continue using the old gateway set during prepare. Promotion atomically adds
  durable certificate ownership, reconciles the route policy, and publishes the
  new multipath route in one signed revision.
- Leaving is route-first. Start atomically removes the gateway from published
  ownership, reconciles the route policy, advances one signed revision, and only
  then requests a cleaned certificate. The remaining gateways continue serving
  the prefix while cleanup converges.

Creating an ordinary pending node with a duplicate prefix remains rejected.
This prevents an unproved new credential from implicitly changing route
topology and keeps the staged active-node workflow as the normal ECMP
membership authority. Atomic identity replacement is the narrow exception: it
revokes an already-authorized owner route-first, may retain the exact prefix on
its pending successor while another active enrolled same-network owner keeps
serving it, and republishes that successor only after certificate enrollment.
Route transfer is restricted to single-owner prefixes; ordinary ECMP
membership is changed with the node route-profile workflow instead.

## Rendering and safety

The renderer groups active owners by exact prefix and emits one deterministic
unsafe-route entry. A non-owner receives either a scalar `via` for one gateway
or a sorted weighted gateway list for multiple gateways. A node that owns the
prefix receives no unsafe route for that prefix, even when other gateways own it,
because it serves the directly attached destination itself. Its certificate
prefix still expands the managed inbound firewall rules through `local_cidr`.

Policy updates are administrator-authenticated, bound to the visible signed
configuration revision and a 16-128 character request ID, and audited. They are
fenced during CA rotation, firewall rollout, route transfer, or route-profile
editing. The requested gateway set must exactly match the current server-derived
owner set, so a stale browser cannot silently omit or invent a gateway.

## API and dashboard

- `GET /api/v1/networks/{networkID}/route-policies`
- `POST /api/v1/networks/{networkID}/route-policies`

The read returns schema `mesh-network-route-policies-v1`, the current signed
revision, and every live exact prefix with canonical owner identity, address,
weight, MTU, metric, and available actions. The update replaces one prefix's
complete policy and contains the exact gateway list, MTU, metric,
`expected_config_revision`, and `request_id`. Exact response-loss replay is
write-free; conflicting request-ID reuse fails closed.

The dashboard explains that weights are relative, previews the resulting share,
shows inherited MTU and default metric explicitly, and never labels the fallback
path as health-aware rebalancing. Membership changes link to the existing safe
route-profile editor rather than directly editing certificate ownership.

## Verification

Unit and HTTP tests must cover canonical policy bounds, exact-owner binding,
same-network exact duplicates, graph rejection of all other overlaps,
certificate-first join, route-first leave, deterministic grouped rendering,
optimistic/idempotent updates, lifecycle fences, migration, backup/PostgreSQL
maximum-version gates, and fail-closed browser parsing.

A self-cleaning Linux namespace proof must run a member, two gateways, and a
non-Nebula routed host with the pinned Nebula binary. Distinct TCP/UDP port pairs
must exercise both gateways, configured weights must produce the expected
bounded distribution, disabling one gateway must preserve packets through the
other, restoring it must restore weighted selection, and removing it through the
route-profile lifecycle must keep packets flowing while its certificate is
cleaned. Exact signed generation, fingerprint, revision, digest, and runtime
heartbeats remain the promotion/completion evidence.
