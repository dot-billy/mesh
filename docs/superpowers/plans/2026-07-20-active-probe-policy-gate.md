# Active Probe Policy Gate Implementation Plan

**Goal:** Build a fail-closed probe planner that proves exact signed topology
and outbound ICMP permission before any active-probe executor can be called.

### Task 1: Specify the planner with failing tests

- [x] Add tests for host-any, matching CIDR, `group: "all"`, policy denial,
  inbound-only permission, nonmatching selectors, and no remote lighthouse.
- [x] Add adversarial tests for duplicate/malformed sections and for a
  lighthouse missing from `static_host_map`.
- [x] Add a cardinality test proving deterministic numeric ordering and an
  eight-target cap.
- [x] Run the focused tests and confirm they fail before implementation.

### Task 2: Implement strict topology and firewall parsing

- [x] Reuse the verified certificate and strict lighthouse parser to establish
  the local overlay identity and remote candidate set.
- [x] Strictly parse the exact Mesh-rendered static-host-map keys without
  retaining or returning underlay endpoints.
- [x] Strictly parse the exact Mesh-rendered outbound firewall rule grammar.
- [x] Match only provable ICMP/any rules and return the bounded private plan.

### Task 3: Verify and document the boundary

- [x] Run focused node-agent tests, the full node-agent package, `go test
  ./...`, `go vet ./...`, and the node-agent race suite.
- [x] Update the runtime contract to mark only the no-I/O policy gate complete;
  retain socket execution, result schemas, UI, and live probe proof as
  outstanding.
