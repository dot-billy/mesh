# Native split-DNS design

Status: implemented and verified on 2026-07-21

## Outcome

An administrator may explicitly opt a managed Nebula network into Linux host
resolver integration and choose one canonical search domain. A node named
`api` in a network using `corp.mesh` then resolves as `api.corp.mesh` and as
the single-label search name `api`, without sending unrelated DNS traffic to
Nebula.

The existing lighthouse responder remains authoritative only for exact Nebula
certificate names. A node-local adapter strips the configured suffix, forwards
the exact name to active lighthouse overlay resolvers, restores the suffix on
the response, and never performs general recursive forwarding.

## Trust and activation boundary

- Resolver integration is opt-in. Enabling the Nebula DNS responder alone
  continues to leave the operating system untouched.
- One canonical `mesh-native-dns-v1` policy is embedded in every rendered
  Nebula configuration as an authenticated comment. The existing desired-
  artifact signature therefore covers the enable bit, local overlay address,
  managed CIDR, search domain, upstream port, and complete active-resolver set.
- The Linux lifecycle agent parses only that strict signed projection. It
  starts a UDP adapter on the node's own overlay address, discovers the unique
  interface carrying that address, and configures systemd-resolved on that
  Mesh-owned interface with a non-default route and the chosen search domain.
- Resolver reconciliation must succeed before the agent sends an operational
  heartbeat. Failure quarantines Nebula and removes any resolver registration;
  disable, signed-state staleness, agent shutdown, and interface replacement
  also revert the transient per-link resolver state.
- The adapter accepts only local-source, single-question DNS packets for the
  configured suffix. It bounds packet size and deadlines, verifies the exact
  upstream response tuple, tries each authenticated active lighthouse, and
  returns no answer for other domains. It never reads or forwards the host's
  ordinary resolver configuration.

## State and compatibility

Control schema v12 adds `native_resolver` and `search_domain` to the existing
network DNS settings. Migration from v11 writes disabled native integration
with an empty domain, adds one audit event, and does not change any signed
revision because the disabled projection is absent. Old agents safely ignore
the signed comment; the dashboard labels native integration as requiring a
current packaged Linux agent.

The strict v1 DNS API document adds those two fields. Enabling native resolver
integration requires managed DNS to be enabled and a lowercase canonical DNS
domain. Disabling managed DNS resets the port to 53, disables native
integration, and clears the domain.

## Proof

Unit tests cover migration, canonical validation, signed projection stability,
query rewriting, upstream failover, local-source enforcement, resolver command
ordering, idempotence, rollback, and quarantine. The `native-dns-smoke` Linux
namespace gate starts the production adapter from the exact signed member
configuration, resolves `packet-member.packet.mesh.` through the real Nebula
lighthouse, rejects an unrelated recursive query, and then completes signed
firewall, restoration, revocation, and cleanup stages.
