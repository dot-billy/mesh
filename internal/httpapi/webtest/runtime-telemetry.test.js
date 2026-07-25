'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const telemetry = require('../web/runtime-telemetry.js');

const nowMS = Date.parse('2026-07-20T18:00:00.000Z');
const iso = (offset = 0) => new Date(nowMS + offset).toISOString();
const clone = (value) => JSON.parse(JSON.stringify(value));

function activeProbe(state = 'unsupported', overrides = {}) {
  const defaults = {
    not_eligible: { sample_age_ms: 0, attempted: 0, replied: 0, duration_ms: 0 },
    unsupported: { sample_age_ms: null, attempted: 0, replied: 0, duration_ms: 0 },
    capability_unavailable: { sample_age_ms: 0, attempted: 0, replied: 0, duration_ms: 0 },
    attempted: { sample_age_ms: 0, attempted: 2, replied: 1, duration_ms: 14 },
    unavailable: { sample_age_ms: null, attempted: 0, replied: 0, duration_ms: 0 },
  };
  return { version: 1, state, ...defaults[state], ...overrides };
}

function initialProbeTransition(state) {
  if (state === 'not_eligible') return 'not_eligible';
  if (state === 'attempted') return 'unclassified';
  return 'unavailable';
}

function activeProbeForTransition(transition) {
  return activeProbe('attempted', { attempted: 2, replied: transition === 'recovered' ? 2 : 1 });
}

function observedRecord(nodeID = 'node-a', heartbeatSequence = 7) {
  return {
    node_id: nodeID,
    heartbeat_sequence: heartbeatSequence,
    received_at: iso(-60 * 1000),
    observation_version: 2,
    process_continuity: 'continuous',
    state: 'observed',
    active_probe: activeProbe(),
    probe_transition: 'unavailable',
    snapshot: {
      sample_sequence: 11,
      process_uptime_ms: 60000,
      handshakes: {
        completed_total: 3,
        timed_out_total: 1,
        pending: 0,
        most_recent_completion_age_ms: 500,
      },
      peers: {
        established: 2,
        authenticated_rx_within_2m: 1,
        authenticated_rx_within_5m: 2,
        oldest_authenticated_rx_age_ms: 300,
      },
      lighthouses: {
        configured: 2,
        established: 1,
        authenticated_rx_within_2m: 1,
        authenticated_rx_within_5m: 1,
        most_recent_authenticated_rx_age_ms: 250,
        overflow: false,
      },
    },
  };
}

function projection() {
  return {
    schema: telemetry.SCHEMA,
    generated_at: iso(),
    policy: {
      observation_stale_after_seconds: 300,
      aggregate_only: true,
      end_to_end_reachability_proven: false,
    },
    records: [observedRecord()],
  };
}

test('accepts the exact aggregate-only projection and indexes by node', () => {
  const result = telemetry.validateFleetProjection(projection(), nowMS);
  assert.equal(result.recordsByNode.get('node-a').heartbeatSequence, 7);
  assert.equal(result.recordsByNode.get('node-a').processContinuity, 'continuous');
  assert.equal(result.recordsByNode.get('node-a').snapshot.peers.established, 2);
  assert.equal(result.recordsByNode.get('node-a').snapshot.lighthouses.mostRecentAuthenticatedRXAgeMS, 250);
  assert.deepEqual(result.recordsByNode.get('node-a').activeProbe, {
    version: 1, state: 'unsupported', sampleAgeMS: null, attempted: 0, replied: 0, durationMS: 0,
  });
  assert.equal(result.recordsByNode.get('node-a').probeTransition, 'unavailable');
  assert.equal(result.policy.endToEndReachabilityProven, false);
});

test('accepts unknown only without a snapshot and rejects new fields', () => {
  const value = projection();
  value.records[0] = {
    node_id: 'node-a', heartbeat_sequence: 7, received_at: iso(-1000), observation_version: 2,
    process_continuity: 'unavailable', state: 'unknown', active_probe: activeProbe(), probe_transition: 'unavailable',
  };
  assert.equal(telemetry.validateFleetProjection(value, nowMS).records[0].state, 'unknown');

  const withSnapshot = clone(value);
  withSnapshot.records[0].snapshot = observedRecord().snapshot;
  assert.throws(() => telemetry.validateFleetProjection(withSnapshot, nowMS), /unknown state carries a snapshot/);
  const leakedIdentity = projection();
  leakedIdentity.records[0].snapshot.process_instance_id = '0123456789abcdef0123456789abcdef';
  assert.throws(() => telemetry.validateFleetProjection(leakedIdentity, nowMS), /process_instance_id is not allowed/);
});

test('accepts exact fleet v2 through v4 with current-only legacy probe transitions', () => {
  const legacyObserved = projection();
  legacyObserved.schema = 'mesh-runtime-telemetry-fleet-v2';
  delete legacyObserved.records[0].process_continuity;
  delete legacyObserved.records[0].active_probe;
  delete legacyObserved.records[0].probe_transition;
  const observed = telemetry.validateFleetProjection(legacyObserved, nowMS);
  assert.equal(observed.records[0].processContinuity, 'unclassified');
  assert.deepEqual(observed.records[0].activeProbe, {
    version: 1, state: 'unsupported', sampleAgeMS: null, attempted: 0, replied: 0, durationMS: 0,
  });
  assert.equal(observed.records[0].probeTransition, 'unavailable');

  const legacyUnknown = clone(legacyObserved);
  legacyUnknown.records[0] = { node_id: 'node-a', heartbeat_sequence: 7, received_at: iso(-1000), observation_version: 2, state: 'unknown' };
  const unknown = telemetry.validateFleetProjection(legacyUnknown, nowMS);
  assert.equal(unknown.records[0].processContinuity, 'unavailable');

  const fleetV3 = projection();
  fleetV3.schema = 'mesh-runtime-telemetry-fleet-v3';
  delete fleetV3.records[0].active_probe;
  delete fleetV3.records[0].probe_transition;
  assert.equal(telemetry.validateFleetProjection(fleetV3, nowMS).records[0].activeProbe.state, 'unsupported');

  const legacyWithProbe = clone(fleetV3);
  legacyWithProbe.records[0].active_probe = activeProbe('attempted');
  assert.throws(() => telemetry.validateFleetProjection(legacyWithProbe, nowMS), /active_probe is not allowed/);

  const fleetV4 = projection();
  fleetV4.schema = 'mesh-runtime-telemetry-fleet-v4';
  fleetV4.records[0].active_probe = activeProbe('attempted');
  delete fleetV4.records[0].probe_transition;
  assert.equal(telemetry.validateFleetProjection(fleetV4, nowMS).records[0].probeTransition, 'unclassified');

  const legacyWithTransition = clone(fleetV4);
  legacyWithTransition.records[0].probe_transition = 'recovered';
  assert.throws(() => telemetry.validateFleetProjection(legacyWithTransition, nowMS), /probe_transition is not allowed/);
});

test('requires exact process continuity semantics in fleet v3 through v5', () => {
  const missing = projection();
  delete missing.records[0].process_continuity;
  assert.throws(() => telemetry.validateFleetProjection(missing, nowMS), /process_continuity is required/);

  const invalid = projection();
  invalid.records[0].process_continuity = 'maybe';
  assert.throws(() => telemetry.validateFleetProjection(invalid, nowMS), /process_continuity is invalid/);

  const unavailableObserved = projection();
  unavailableObserved.records[0].process_continuity = 'unavailable';
  assert.throws(() => telemetry.validateFleetProjection(unavailableObserved, nowMS), /process continuity is inconsistent/);

  const continuousUnknown = projection();
  continuousUnknown.records[0] = {
    node_id: 'node-a', heartbeat_sequence: 7, received_at: iso(-1000), observation_version: 2,
    process_continuity: 'continuous', state: 'unknown', active_probe: activeProbe(), probe_transition: 'unavailable',
  };
  assert.throws(() => telemetry.validateFleetProjection(continuousUnknown, nowMS), /process continuity is inconsistent/);
});

test('requires the exact fleet-v5 active probe shape and Go-side invariants', () => {
  for (const state of ['not_eligible', 'unsupported', 'capability_unavailable', 'attempted', 'unavailable']) {
    const value = projection();
    value.records[0].active_probe = activeProbe(state);
    value.records[0].probe_transition = initialProbeTransition(state);
    assert.equal(telemetry.validateFleetProjection(value, nowMS).records[0].activeProbe.state, state);
  }

  const invalid = [
    (probe) => { delete probe.duration_ms; },
    (probe) => { probe.extra = true; },
    (probe) => { probe.version = 2; },
    (probe) => { probe.state = 'maybe'; },
    (probe) => { probe.sample_age_ms = 30001; },
    (probe) => { probe.attempted = 0; },
    (probe) => { probe.attempted = 9; },
    (probe) => { probe.replied = 3; },
    (probe) => { probe.duration_ms = 6001; },
    (probe) => { probe.sample_age_ms = null; },
  ];
  for (const mutate of invalid) {
    const value = projection();
    value.records[0].active_probe = activeProbe('attempted');
    mutate(value.records[0].active_probe);
    assert.throws(() => telemetry.validateFleetProjection(value, nowMS), /active_probe/);
  }

  for (const [state, mutate] of [
    ['not_eligible', (probe) => { probe.sample_age_ms = 1; }],
    ['unsupported', (probe) => { probe.sample_age_ms = 0; }],
    ['capability_unavailable', (probe) => { probe.attempted = 1; }],
    ['unavailable', (probe) => { probe.duration_ms = 1; }],
  ]) {
    const value = projection();
    value.records[0].active_probe = activeProbe(state);
    value.records[0].probe_transition = initialProbeTransition(state);
    mutate(value.records[0].active_probe);
    assert.throws(() => telemetry.validateFleetProjection(value, nowMS), /active_probe/);
  }
});

test('requires exact config-bound probe transition semantics in fleet v5', () => {
  for (const transition of ['unclassified', 'stable', 'recovered', 'degraded', 'changed']) {
    const value = projection();
    value.records[0].active_probe = activeProbeForTransition(transition);
    value.records[0].probe_transition = transition;
    assert.equal(telemetry.validateFleetProjection(value, nowMS).records[0].probeTransition, transition);
  }

  for (const [state, transition] of [
    ['not_eligible', 'not_eligible'],
    ['unsupported', 'unavailable'],
    ['capability_unavailable', 'unavailable'],
    ['unavailable', 'unavailable'],
  ]) {
    const value = projection();
    value.records[0].active_probe = activeProbe(state);
    value.records[0].probe_transition = transition;
    assert.equal(telemetry.validateFleetProjection(value, nowMS).records[0].probeTransition, transition);
  }

  const invalid = [
    ['', 'attempted'],
    ['maybe', 'attempted'],
    ['recovered', 'unsupported'],
    ['unavailable', 'attempted'],
    ['not_eligible', 'attempted'],
    ['stable', 'not_eligible'],
  ];
  for (const [transition, state] of invalid) {
    const value = projection();
    value.records[0].active_probe = activeProbe(state);
    value.records[0].probe_transition = transition;
    assert.throws(() => telemetry.validateFleetProjection(value, nowMS), /probe_transition/);
  }

  for (const [transition, replied] of [['recovered', 1], ['degraded', 2], ['changed', 2]]) {
    const value = projection();
    value.records[0].active_probe = activeProbe('attempted', { attempted: 2, replied });
    value.records[0].probe_transition = transition;
    assert.throws(() => telemetry.validateFleetProjection(value, nowMS), /probe_transition/);
  }

  const missing = projection();
  delete missing.records[0].probe_transition;
  assert.throws(() => telemetry.validateFleetProjection(missing, nowMS), /probe_transition is required/);
});

test('rejects stale envelopes, future receipts, and normalized invalid timestamps', () => {
  const stale = projection();
  stale.generated_at = iso(-telemetry.MAX_SNAPSHOT_AGE_MS - 1);
  assert.throws(() => telemetry.validateFleetProjection(stale, nowMS), /generated_at is stale/);

  const futureReceipt = projection();
  futureReceipt.records[0].received_at = iso(1);
  assert.throws(() => telemetry.validateFleetProjection(futureReceipt, nowMS), /after snapshot generation/);

  for (const invalid of ['2026-02-31T18:00:00Z', '2026-07-20T24:00:00Z']) {
    const value = projection();
    value.generated_at = invalid;
    assert.throws(() => telemetry.validateFleetProjection(value, nowMS), /generated_at is invalid/);
  }
});

test('rejects false semantics and inconsistent aggregates', () => {
  const claimedReachability = projection();
  claimedReachability.policy.end_to_end_reachability_proven = true;
  assert.throws(() => telemetry.validateFleetProjection(claimedReachability, nowMS), /must not claim end-to-end reachability/);

  const peerOrdering = projection();
  peerOrdering.records[0].snapshot.peers.authenticated_rx_within_2m = 3;
  assert.throws(() => telemetry.validateFleetProjection(peerOrdering, nowMS), /peers is inconsistent/);

  const lighthouseSubset = projection();
  lighthouseSubset.records[0].snapshot.lighthouses.established = 3;
  assert.throws(() => telemetry.validateFleetProjection(lighthouseSubset, nowMS), /lighthouses is inconsistent/);

  const impossibleAge = projection();
  impossibleAge.records[0].snapshot.handshakes.most_recent_completion_age_ms = 60001;
  assert.throws(() => telemetry.validateFleetProjection(impossibleAge, nowMS), /handshakes is inconsistent/);

  const missingRetainedAge = projection();
  missingRetainedAge.records[0].snapshot.lighthouses.most_recent_authenticated_rx_age_ms = null;
  assert.throws(() => telemetry.validateFleetProjection(missingRetainedAge, nowMS), /lighthouses is inconsistent/);

  const retainedWithoutConfiguration = projection();
  retainedWithoutConfiguration.records[0].snapshot.lighthouses = {
    configured: 0,
    established: 0,
    authenticated_rx_within_2m: 0,
    authenticated_rx_within_5m: 0,
    most_recent_authenticated_rx_age_ms: 1,
    overflow: false,
  };
  assert.throws(() => telemetry.validateFleetProjection(retainedWithoutConfiguration, nowMS), /lighthouses is inconsistent/);
});

test('accepts retained lighthouse history without an established tunnel and preserves v1 compatibility', () => {
  const retained = projection();
  retained.records[0].snapshot.process_uptime_ms = 300000;
  retained.records[0].snapshot.peers = {
    established: 0,
    authenticated_rx_within_2m: 0,
    authenticated_rx_within_5m: 0,
    oldest_authenticated_rx_age_ms: null,
  };
  retained.records[0].snapshot.lighthouses = {
    configured: 1,
    established: 0,
    authenticated_rx_within_2m: 0,
    authenticated_rx_within_5m: 0,
    most_recent_authenticated_rx_age_ms: 125000,
    overflow: false,
  };
  retained.records[0].snapshot.handshakes.completed_total = 1;
  const validated = telemetry.validateFleetProjection(retained, nowMS);
  const presentation = telemetry.presentation({ id: 'node-a', heartbeat_sequence: 7 }, validated, nowMS);
  assert.match(presentation.detail, /last authenticated lighthouse receive was at least 3m ago/i);
  assert.match(presentation.detail, /0\/1 lighthouses established/);
  assert.doesNotMatch(`${presentation.label} ${presentation.detail}`, /healthy|reachable/i);

  const legacy = projection();
  legacy.records[0].observation_version = 1;
  legacy.records[0].snapshot.lighthouses.most_recent_authenticated_rx_age_ms = null;
  const legacyValidated = telemetry.validateFleetProjection(legacy, nowMS);
  assert.match(telemetry.presentation({ id: 'node-a', heartbeat_sequence: 7 }, legacyValidated, nowMS).detail, /legacy sample/i);
});

test('requires canonical unique records and safe heartbeat counters', () => {
  const outOfOrder = projection();
  outOfOrder.records = [observedRecord('node-b'), observedRecord('node-a')];
  assert.throws(() => telemetry.validateFleetProjection(outOfOrder, nowMS), /deterministically ordered/);

  const duplicate = projection();
  duplicate.records.push(observedRecord('node-a'));
  assert.throws(() => telemetry.validateFleetProjection(duplicate, nowMS), /deterministically ordered/);

  const unsafe = projection();
  unsafe.records[0].heartbeat_sequence = Number.MAX_SAFE_INTEGER + 1;
  assert.throws(() => telemetry.validateFleetProjection(unsafe, nowMS), /heartbeat_sequence is invalid/);
});

test('presentation remains observational and requires exact heartbeat binding', () => {
  const result = telemetry.validateFleetProjection(projection(), nowMS);
  const node = { id: 'node-a', heartbeat_sequence: 7 };
  const observed = telemetry.presentation(node, result, nowMS);
  assert.equal(observed.state, 'observed');
  assert.equal(observed.label, 'Runtime observed');
  assert.match(observed.detail, /same Nebula observer process advanced monotonically/i);
  assert.match(observed.detail, /Not an end-to-end reachability result/);
  assert.doesNotMatch(`${observed.label} ${observed.detail}`, /healthy/i);

  assert.equal(telemetry.presentation({ ...node, heartbeat_sequence: 8 }, result, nowMS).state, 'outdated');
  assert.equal(telemetry.presentation({ id: 'missing', heartbeat_sequence: 1 }, result, nowMS).state, 'unknown');
  assert.equal(telemetry.presentation(node, result, nowMS + 5 * 60 * 1000).state, 'stale');
  assert.equal(telemetry.presentation(node, null, nowMS).state, 'unavailable');

  const unknownValue = projection();
  unknownValue.records[0] = {
    node_id: 'node-a', heartbeat_sequence: 7, received_at: iso(-1000), observation_version: 2,
    process_continuity: 'unavailable', state: 'unknown', active_probe: activeProbe(), probe_transition: 'unavailable',
  };
  const unknown = telemetry.validateFleetProjection(unknownValue, nowMS);
  assert.equal(telemetry.presentation(node, unknown, nowMS).state, 'unknown');

  const restartedValue = projection();
  restartedValue.records[0].process_continuity = 'restarted';
  const restarted = telemetry.presentation(node, telemetry.validateFleetProjection(restartedValue, nowMS), nowMS);
  assert.match(restarted.detail, /observer process changed/i);
  assert.match(restarted.detail, /counters were not compared/i);

  const unclassifiedValue = projection();
  unclassifiedValue.records[0].process_continuity = 'unclassified';
  const unclassified = telemetry.presentation(node, telemetry.validateFleetProjection(unclassifiedValue, nowMS), nowMS);
  assert.match(unclassified.detail, /no immediately prior observed sample/i);

  for (const value of [observed, restarted, unclassified]) {
    assert.doesNotMatch(`${value.label} ${value.detail}`, /healthy|reachable|process_instance_id|[0-9a-f]{32}/i);
  }
});

test('presentation renders every probe state independently from passive observation', () => {
  const cases = [
    ['not_eligible', /ICMP probe not eligible under the active signed policy\./],
    ['unsupported', /ICMP probe unsupported on this platform\./],
    ['capability_unavailable', /ICMP probe capability unavailable under the current host sandbox\./],
    ['unavailable', /ICMP probe evidence unavailable\./],
  ];
  for (const [state, sentence] of cases) {
    const value = projection();
    value.records[0].active_probe = activeProbe(state);
    value.records[0].probe_transition = initialProbeTransition(state);
    const rendered = telemetry.presentation({ id: 'node-a', heartbeat_sequence: 7 }, telemetry.validateFleetProjection(value, nowMS), nowMS);
    assert.match(rendered.detail, sentence);
  }

  const attemptedValue = projection();
  attemptedValue.records[0].received_at = iso(-8000);
  attemptedValue.records[0].active_probe = activeProbe('attempted', { sample_age_ms: 0, attempted: 2, replied: 1 });
  attemptedValue.records[0].probe_transition = 'unclassified';
  const attempted = telemetry.presentation({ id: 'node-a', heartbeat_sequence: 7 }, telemetry.validateFleetProjection(attemptedValue, nowMS), nowMS);
  assert.match(attempted.detail, /Lighthouse ICMP replied from 1 of 2 attempts; sampled at least 8s ago\./);

  const unknownValue = projection();
  unknownValue.records[0] = {
    node_id: 'node-a', heartbeat_sequence: 7, received_at: iso(-8000), observation_version: 2,
    process_continuity: 'unavailable', state: 'unknown',
    active_probe: activeProbe('attempted', { sample_age_ms: 2000, attempted: 1, replied: 1 }),
    probe_transition: 'unclassified',
  };
  const unknown = telemetry.presentation({ id: 'node-a', heartbeat_sequence: 7 }, telemetry.validateFleetProjection(unknownValue, nowMS), nowMS);
  assert.match(unknown.detail, /node observer could not provide/i);
  assert.match(unknown.detail, /Lighthouse ICMP replied from 1 of 1 attempt; sampled at least 10s ago\./);

  for (const rendered of [attempted, unknown]) {
    assert.doesNotMatch(`${rendered.label} ${rendered.detail}`, /\b(healthy|reachable|online|connected|failed|down)\b|process_instance_id|plan_sha256|nonce|(?:\d{1,3}\.){3}\d{1,3}/i);
  }
});

test('presentation explains every attempted transition without promoting telemetry to health', () => {
  const cases = [
    ['unclassified', /No immediately prior probe under the same signed target policy is available/],
    ['stable', /same signed target policy produced the same reply count/],
    ['recovered', /replies recovered under the same signed target policy/],
    ['degraded', /replies decreased under the same signed target policy/],
    ['changed', /partial lighthouse reply count changed under the same signed target policy/],
  ];
  for (const [transition, sentence] of cases) {
    const value = projection();
    value.records[0].active_probe = activeProbeForTransition(transition);
    value.records[0].probe_transition = transition;
    const rendered = telemetry.presentation({ id: 'node-a', heartbeat_sequence: 7 }, telemetry.validateFleetProjection(value, nowMS), nowMS);
    assert.match(rendered.detail, sentence);
    assert.match(rendered.detail, /Not an end-to-end reachability result/);
    assert.doesNotMatch(`${rendered.label} ${rendered.detail}`, /\b(healthy|reachable|online|connected|failed|down)\b|applied_config_sha256|[0-9a-f]{64}/i);
  }
});

test('estimated server time advances only by local elapsed time', () => {
  assert.equal(telemetry.estimatedServerNow(nowMS, 1000, 4500), nowMS + 3500);
  assert.throws(() => telemetry.estimatedServerNow(nowMS, 5000, 4999), /elapsed response timing/);
});
