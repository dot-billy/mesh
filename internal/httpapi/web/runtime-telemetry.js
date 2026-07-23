(function publishMeshRuntimeTelemetry(root, factory) {
  const adapter = factory();
  if (typeof module === 'object' && module.exports) module.exports = adapter;
  if (root) root.MeshRuntimeTelemetry = adapter;
}(typeof globalThis === 'undefined' ? this : globalThis, function buildRuntimeTelemetryAdapter() {
  'use strict';

  const SCHEMA_V2 = 'mesh-runtime-telemetry-fleet-v2';
  const SCHEMA_V3 = 'mesh-runtime-telemetry-fleet-v3';
  const SCHEMA_V4 = 'mesh-runtime-telemetry-fleet-v4';
  const SCHEMA_V5 = 'mesh-runtime-telemetry-fleet-v5';
  const SCHEMA = SCHEMA_V5;
  const MAX_SNAPSHOT_AGE_MS = 60 * 1000;
  const MAX_FUTURE_SKEW_MS = 30 * 1000;
  const MAX_RECORDS = 1 << 16;
  const MAX_AGGREGATE_COUNT = (2 ** 32) - 1;
  const MAX_CONFIGURED_LIGHTHOUSES = 64;
  const MAX_LIGHTHOUSE_ENTRIES = 8;
  const MAX_ACTIVE_PROBE_TARGETS = 8;
  const MAX_ACTIVE_PROBE_AGE_MS = 30 * 1000;
  const MAX_ACTIVE_PROBE_DURATION_MS = 6 * 1000;
  const LEGACY_ACTIVE_PROBE = Object.freeze({
    version: 1,
    state: 'unsupported',
    sampleAgeMS: null,
    attempted: 0,
    replied: 0,
    durationMS: 0,
  });

  function fail(message) {
    throw new Error(`Invalid runtime telemetry snapshot: ${message}`);
  }

  function isRecord(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }

  function exactObject(value, required, optional, name) {
    if (!isRecord(value)) fail(`${name} must be an object`);
    const allowed = new Set([...required, ...optional]);
    for (const key of required) if (!Object.prototype.hasOwnProperty.call(value, key)) fail(`${name}.${key} is required`);
    for (const key of Object.keys(value)) if (!allowed.has(key)) fail(`${name}.${key} is not allowed`);
    return value;
  }

  function integer(value, name, maximum = Number.MAX_SAFE_INTEGER) {
    if (!Number.isSafeInteger(value) || value < 0 || value > maximum) fail(`${name} is invalid`);
    return value;
  }

  function nullableInteger(value, name, maximum = Number.MAX_SAFE_INTEGER) {
    return value === null ? null : integer(value, name, maximum);
  }

  function boolean(value, name) {
    if (typeof value !== 'boolean') fail(`${name} is invalid`);
    return value;
  }

  function timestamp(value, name) {
    if (typeof value !== 'string' || value.length > 64) fail(`${name} is invalid`);
    const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/.exec(value);
    if (!match) fail(`${name} is invalid`);
    const year = Number(match[1]);
    const month = Number(match[2]);
    const day = Number(match[3]);
    const hour = Number(match[4]);
    const minute = Number(match[5]);
    const second = Number(match[6]);
    const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    const daysInMonth = [0, 31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    const offsetHour = match[10] === undefined ? 0 : Number(match[10]);
    const offsetMinute = match[11] === undefined ? 0 : Number(match[11]);
    if (month < 1 || month > 12 || day < 1 || day > daysInMonth[month] || hour > 23 || minute > 59 || second > 59 || offsetHour > 23 || offsetMinute > 59) fail(`${name} is invalid`);
    const milliseconds = Date.parse(value);
    if (!Number.isFinite(milliseconds)) fail(`${name} is invalid`);
    return Object.freeze({ value, milliseconds });
  }

  function validatePolicy(raw) {
    exactObject(raw, ['observation_stale_after_seconds', 'aggregate_only', 'end_to_end_reachability_proven'], [], 'snapshot.policy');
    const staleAfterSeconds = integer(raw.observation_stale_after_seconds, 'snapshot.policy.observation_stale_after_seconds', 86400);
    if (staleAfterSeconds < 1) fail('snapshot.policy.observation_stale_after_seconds is invalid');
    if (boolean(raw.aggregate_only, 'snapshot.policy.aggregate_only') !== true) fail('snapshot.policy.aggregate_only must be true');
    if (boolean(raw.end_to_end_reachability_proven, 'snapshot.policy.end_to_end_reachability_proven') !== false) fail('snapshot.policy must not claim end-to-end reachability');
    return Object.freeze({
      observationStaleAfterSeconds: staleAfterSeconds,
      aggregateOnly: true,
      endToEndReachabilityProven: false,
    });
  }

  function validateHandshakes(raw, name, uptimeMS) {
    exactObject(raw, ['completed_total', 'timed_out_total', 'pending', 'most_recent_completion_age_ms'], [], name);
    const completedTotal = integer(raw.completed_total, `${name}.completed_total`);
    const timedOutTotal = integer(raw.timed_out_total, `${name}.timed_out_total`);
    const pending = integer(raw.pending, `${name}.pending`, MAX_AGGREGATE_COUNT);
    const mostRecentCompletionAgeMS = nullableInteger(raw.most_recent_completion_age_ms, `${name}.most_recent_completion_age_ms`);
    if ((completedTotal === 0) !== (mostRecentCompletionAgeMS === null) || (mostRecentCompletionAgeMS !== null && mostRecentCompletionAgeMS > uptimeMS)) fail(`${name} is inconsistent`);
    return Object.freeze({ completedTotal, timedOutTotal, pending, mostRecentCompletionAgeMS });
  }

  function validatePeers(raw, name, uptimeMS) {
    exactObject(raw, ['established', 'authenticated_rx_within_2m', 'authenticated_rx_within_5m', 'oldest_authenticated_rx_age_ms'], [], name);
    const established = integer(raw.established, `${name}.established`, MAX_AGGREGATE_COUNT);
    const authenticatedRXWithin2m = integer(raw.authenticated_rx_within_2m, `${name}.authenticated_rx_within_2m`, MAX_AGGREGATE_COUNT);
    const authenticatedRXWithin5m = integer(raw.authenticated_rx_within_5m, `${name}.authenticated_rx_within_5m`, MAX_AGGREGATE_COUNT);
    const oldestAuthenticatedRXAgeMS = nullableInteger(raw.oldest_authenticated_rx_age_ms, `${name}.oldest_authenticated_rx_age_ms`);
    if (authenticatedRXWithin2m > authenticatedRXWithin5m || authenticatedRXWithin5m > established ||
      (established === 0 && oldestAuthenticatedRXAgeMS !== null) || (oldestAuthenticatedRXAgeMS === null && authenticatedRXWithin5m !== 0) ||
      (oldestAuthenticatedRXAgeMS !== null && oldestAuthenticatedRXAgeMS > uptimeMS)) fail(`${name} is inconsistent`);
    return Object.freeze({ established, authenticatedRXWithin2m, authenticatedRXWithin5m, oldestAuthenticatedRXAgeMS });
  }

  function validateLighthouses(raw, name, peers, uptimeMS, observationVersion) {
    exactObject(raw, ['configured', 'established', 'authenticated_rx_within_2m', 'authenticated_rx_within_5m', 'most_recent_authenticated_rx_age_ms', 'overflow'], [], name);
    const configured = integer(raw.configured, `${name}.configured`, MAX_CONFIGURED_LIGHTHOUSES);
    const established = integer(raw.established, `${name}.established`, MAX_CONFIGURED_LIGHTHOUSES);
    const authenticatedRXWithin2m = integer(raw.authenticated_rx_within_2m, `${name}.authenticated_rx_within_2m`, MAX_CONFIGURED_LIGHTHOUSES);
    const authenticatedRXWithin5m = integer(raw.authenticated_rx_within_5m, `${name}.authenticated_rx_within_5m`, MAX_CONFIGURED_LIGHTHOUSES);
    const mostRecentAuthenticatedRXAgeMS = nullableInteger(raw.most_recent_authenticated_rx_age_ms, `${name}.most_recent_authenticated_rx_age_ms`);
    const overflow = boolean(raw.overflow, `${name}.overflow`);
    if (established > configured || established > peers.established || authenticatedRXWithin2m > authenticatedRXWithin5m ||
      authenticatedRXWithin5m > established || authenticatedRXWithin2m > peers.authenticatedRXWithin2m ||
      authenticatedRXWithin5m > peers.authenticatedRXWithin5m || overflow !== (configured > MAX_LIGHTHOUSE_ENTRIES) ||
      (mostRecentAuthenticatedRXAgeMS !== null && mostRecentAuthenticatedRXAgeMS > uptimeMS) ||
      (configured === 0 && mostRecentAuthenticatedRXAgeMS !== null) ||
      (observationVersion === 1 && mostRecentAuthenticatedRXAgeMS !== null) ||
      (observationVersion === 2 && authenticatedRXWithin5m > 0 && mostRecentAuthenticatedRXAgeMS === null) ||
      (observationVersion === 2 && authenticatedRXWithin2m > 0 && mostRecentAuthenticatedRXAgeMS > 120000) ||
      (observationVersion === 2 && authenticatedRXWithin5m > 0 && mostRecentAuthenticatedRXAgeMS > 300000)) fail(`${name} is inconsistent`);
    return Object.freeze({ configured, established, authenticatedRXWithin2m, authenticatedRXWithin5m, mostRecentAuthenticatedRXAgeMS, overflow });
  }

  function validateObservationSnapshot(raw, name, observationVersion) {
    exactObject(raw, ['sample_sequence', 'process_uptime_ms', 'handshakes', 'peers', 'lighthouses'], [], name);
    const sampleSequence = integer(raw.sample_sequence, `${name}.sample_sequence`);
    const processUptimeMS = integer(raw.process_uptime_ms, `${name}.process_uptime_ms`);
    const handshakes = validateHandshakes(raw.handshakes, `${name}.handshakes`, processUptimeMS);
    const peers = validatePeers(raw.peers, `${name}.peers`, processUptimeMS);
    const lighthouses = validateLighthouses(raw.lighthouses, `${name}.lighthouses`, peers, processUptimeMS, observationVersion);
    if (handshakes.completedTotal < peers.established) fail(`${name}.peers exceed completed handshakes`);
    return Object.freeze({ sampleSequence, processUptimeMS, handshakes, peers, lighthouses });
  }

  function validateActiveProbe(raw, name) {
    exactObject(raw, ['version', 'state', 'sample_age_ms', 'attempted', 'replied', 'duration_ms'], [], name);
    const version = integer(raw.version, `${name}.version`, 1);
    if (version !== 1) fail(`${name}.version is unsupported`);
    if (typeof raw.state !== 'string') fail(`${name}.state is invalid`);
    const state = raw.state;
    const sampleAgeMS = nullableInteger(raw.sample_age_ms, `${name}.sample_age_ms`, MAX_ACTIVE_PROBE_AGE_MS);
    const attempted = integer(raw.attempted, `${name}.attempted`, MAX_ACTIVE_PROBE_TARGETS);
    const replied = integer(raw.replied, `${name}.replied`, MAX_ACTIVE_PROBE_TARGETS);
    const durationMS = integer(raw.duration_ms, `${name}.duration_ms`, MAX_ACTIVE_PROBE_DURATION_MS);
    switch (state) {
      case 'not_eligible':
        if (sampleAgeMS !== 0 || attempted !== 0 || replied !== 0 || durationMS !== 0) fail(`${name} is inconsistent`);
        break;
      case 'unsupported':
      case 'unavailable':
        if (sampleAgeMS !== null || attempted !== 0 || replied !== 0 || durationMS !== 0) fail(`${name} is inconsistent`);
        break;
      case 'capability_unavailable':
        if (sampleAgeMS === null || attempted !== 0 || replied !== 0) fail(`${name} is inconsistent`);
        break;
      case 'attempted':
        if (sampleAgeMS === null || attempted < 1 || replied > attempted) fail(`${name} is inconsistent`);
        break;
      default:
        fail(`${name}.state is invalid`);
    }
    return Object.freeze({ version, state, sampleAgeMS, attempted, replied, durationMS });
  }

  function initialProbeTransition(probe) {
    if (probe.state === 'not_eligible') return 'not_eligible';
    if (probe.state === 'attempted') return 'unclassified';
    return 'unavailable';
  }

  function validateProbeTransition(raw, name, probe) {
    if (typeof raw !== 'string') fail(`${name} is invalid`);
    let valid;
    switch (probe.state) {
      case 'not_eligible':
        valid = raw === 'not_eligible';
        break;
      case 'attempted':
        valid = raw === 'unclassified' || raw === 'stable' ||
          (raw === 'recovered' && probe.replied === probe.attempted) ||
          ((raw === 'degraded' || raw === 'changed') && probe.replied < probe.attempted);
        break;
      default:
        valid = raw === 'unavailable';
    }
    if (!valid) fail(`${name} is inconsistent`);
    return raw;
  }

  function validateRecord(raw, name, generatedAtMS, schema) {
    const required = ['node_id', 'heartbeat_sequence', 'received_at', 'observation_version', 'state'];
    if (schema !== SCHEMA_V2) required.push('process_continuity');
    if (schema === SCHEMA_V4 || schema === SCHEMA_V5) required.push('active_probe');
    if (schema === SCHEMA_V5) required.push('probe_transition');
    exactObject(raw, required, ['snapshot'], name);
    if (typeof raw.node_id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(raw.node_id)) fail(`${name}.node_id is invalid`);
    const heartbeatSequence = integer(raw.heartbeat_sequence, `${name}.heartbeat_sequence`);
    if (heartbeatSequence < 1) fail(`${name}.heartbeat_sequence is invalid`);
    const observationVersion = integer(raw.observation_version, `${name}.observation_version`, 2);
    if (observationVersion < 1) fail(`${name}.observation_version is invalid`);
    const receivedAt = timestamp(raw.received_at, `${name}.received_at`);
    if (receivedAt.milliseconds > generatedAtMS) fail(`${name}.received_at is after snapshot generation`);
    if (raw.state !== 'unknown' && raw.state !== 'observed') fail(`${name}.state is invalid`);
    if (raw.state === 'unknown' && Object.prototype.hasOwnProperty.call(raw, 'snapshot')) fail(`${name}.unknown state carries a snapshot`);
    if (raw.state === 'observed' && !Object.prototype.hasOwnProperty.call(raw, 'snapshot')) fail(`${name}.observed state has no snapshot`);
    let processContinuity;
    if (schema === SCHEMA_V2) {
      processContinuity = raw.state === 'unknown' ? 'unavailable' : 'unclassified';
    } else {
      const validContinuity = new Set(['unavailable', 'unclassified', 'continuous', 'restarted']);
      if (!validContinuity.has(raw.process_continuity)) fail(`${name}.process_continuity is invalid`);
      processContinuity = raw.process_continuity;
    }
    if (raw.state === 'unknown' && processContinuity !== 'unavailable') fail(`${name}.process continuity is inconsistent`);
    if (raw.state === 'observed' && processContinuity === 'unavailable') fail(`${name}.process continuity is inconsistent`);
    const snapshot = raw.state === 'observed' ? validateObservationSnapshot(raw.snapshot, `${name}.snapshot`, observationVersion) : null;
    const activeProbe = schema === SCHEMA_V4 || schema === SCHEMA_V5 ? validateActiveProbe(raw.active_probe, `${name}.active_probe`) : LEGACY_ACTIVE_PROBE;
    const probeTransition = schema === SCHEMA_V5
      ? validateProbeTransition(raw.probe_transition, `${name}.probe_transition`, activeProbe)
      : initialProbeTransition(activeProbe);
    return Object.freeze({
      nodeID: raw.node_id,
      heartbeatSequence,
      observationVersion,
      receivedAt: receivedAt.value,
      receivedAtMS: receivedAt.milliseconds,
      processContinuity,
      state: raw.state,
      snapshot,
      activeProbe,
      probeTransition,
    });
  }

  function validateFleetProjection(raw, nowMS = Date.now()) {
    exactObject(raw, ['schema', 'generated_at', 'policy', 'records'], [], 'snapshot');
    if (raw.schema !== SCHEMA_V2 && raw.schema !== SCHEMA_V3 && raw.schema !== SCHEMA_V4 && raw.schema !== SCHEMA_V5) fail('snapshot.schema is unsupported');
    if (!Number.isFinite(nowMS)) fail('validation time is invalid');
    const generatedAt = timestamp(raw.generated_at, 'snapshot.generated_at');
    if (generatedAt.milliseconds < nowMS - MAX_SNAPSHOT_AGE_MS) fail('snapshot.generated_at is stale');
    if (generatedAt.milliseconds > nowMS + MAX_FUTURE_SKEW_MS) fail('snapshot.generated_at is too far in the future');
    const policy = validatePolicy(raw.policy);
    if (!Array.isArray(raw.records) || raw.records.length > MAX_RECORDS) fail('snapshot.records is invalid');
    const records = raw.records.map((record, index) => validateRecord(record, `snapshot.records[${index}]`, generatedAt.milliseconds, raw.schema));
    for (let index = 1; index < records.length; index += 1) {
      if (records[index - 1].nodeID >= records[index].nodeID) fail('snapshot.records are not uniquely and deterministically ordered');
    }
    return Object.freeze({
      schema: raw.schema,
      generatedAt: generatedAt.value,
      generatedAtMS: generatedAt.milliseconds,
      policy,
      records: Object.freeze(records),
      recordsByNode: new Map(records.map((record) => [record.nodeID, record])),
    });
  }

  function formatAge(milliseconds) {
    const seconds = Math.max(0, Math.floor(milliseconds / 1000));
    if (seconds >= 3600) return `${Math.floor(seconds / 3600)}h`;
    if (seconds >= 60) return `${Math.floor(seconds / 60)}m`;
    return `${seconds}s`;
  }

  function activeProbePresentation(probe, transition, recordAgeMS) {
    switch (probe.state) {
      case 'not_eligible':
        return 'ICMP probe not eligible under the active signed policy.';
      case 'unsupported':
        return 'ICMP probe unsupported on this platform.';
      case 'capability_unavailable':
        return 'ICMP probe capability unavailable under the current host sandbox.';
      case 'unavailable':
        return 'ICMP probe evidence unavailable.';
      case 'attempted': {
        const sampledAgeMS = Math.min(Number.MAX_SAFE_INTEGER, probe.sampleAgeMS + recordAgeMS);
        const attempts = probe.attempted === 1 ? 'attempt' : 'attempts';
        let comparison;
        switch (transition) {
          case 'unclassified':
            comparison = 'No immediately prior probe under the same signed target policy is available for comparison.';
            break;
          case 'stable':
            comparison = 'The same signed target policy produced the same reply count as the previous heartbeat.';
            break;
          case 'recovered':
            comparison = 'Lighthouse replies recovered under the same signed target policy since the previous heartbeat.';
            break;
          case 'degraded':
            comparison = 'Lighthouse replies decreased under the same signed target policy since the previous heartbeat.';
            break;
          case 'changed':
            comparison = 'The partial lighthouse reply count changed under the same signed target policy since the previous heartbeat.';
            break;
          default:
            fail('active probe presentation transition is invalid');
        }
        return `Lighthouse ICMP replied from ${probe.replied} of ${probe.attempted} ${attempts}; sampled at least ${formatAge(sampledAgeMS)} ago. ${comparison}`;
      }
      default:
        fail('active probe presentation state is invalid');
    }
  }

  // presentation never returns a health state. It only describes whether an
  // aggregate observation is available for the exact lifecycle heartbeat in
  // the concurrently displayed health snapshot.
  function presentation(node, projection, nowMS) {
    if (!projection) return Object.freeze({ state: 'unavailable', label: 'Observation unavailable', detail: 'The aggregate runtime observation feed is unavailable.', receivedAt: '' });
    if (!Number.isFinite(nowMS)) fail('presentation time is invalid');
    const record = projection.recordsByNode.get(node.id);
    if (!record) return Object.freeze({ state: 'unknown', label: 'No observation', detail: 'No aggregate runtime observation is bound to this heartbeat.', receivedAt: '' });
    if (record.heartbeatSequence !== node.heartbeat_sequence) return Object.freeze({ state: 'outdated', label: 'Observation not current', detail: 'The stored aggregate is bound to a different lifecycle heartbeat.', receivedAt: record.receivedAt });
    const ageMS = nowMS - record.receivedAtMS;
    if (ageMS < 0) return Object.freeze({ state: 'unavailable', label: 'Observation unavailable', detail: 'The observation timestamp cannot be verified.', receivedAt: record.receivedAt });
    if (ageMS >= projection.policy.observationStaleAfterSeconds * 1000) return Object.freeze({ state: 'stale', label: 'Observation stale', detail: `The last aggregate observation was received ${formatAge(ageMS)} ago and is not current evidence.`, receivedAt: record.receivedAt });
    const probeDetail = activeProbePresentation(record.activeProbe, record.probeTransition, ageMS);
    if (record.state === 'unknown') return Object.freeze({ state: 'unknown', label: 'Observer unavailable', detail: `The node observer could not provide an aggregate sample for this heartbeat. ${probeDetail}`, receivedAt: record.receivedAt });
    const peers = record.snapshot.peers;
    const lighthouses = record.snapshot.lighthouses;
    let lighthouseHistory;
    if (lighthouses.mostRecentAuthenticatedRXAgeMS !== null) {
      const retainedAgeMS = Math.min(Number.MAX_SAFE_INTEGER, lighthouses.mostRecentAuthenticatedRXAgeMS + ageMS);
      lighthouseHistory = `last authenticated lighthouse receive was at least ${formatAge(retainedAgeMS)} ago in this Nebula process`;
    } else if (record.observationVersion === 1) {
      lighthouseHistory = 'retained lighthouse receive history is unavailable for this legacy sample';
    } else {
      lighthouseHistory = 'no authenticated lighthouse receive is retained in this Nebula process';
    }
    let continuityDetail;
    switch (record.processContinuity) {
      case 'continuous':
        continuityDetail = 'the same Nebula observer process advanced monotonically from the previous accepted sample';
        break;
      case 'restarted':
        continuityDetail = 'the Nebula observer process changed since the previous accepted sample, so process-local counters were not compared across that boundary';
        break;
      case 'unclassified':
        continuityDetail = 'no immediately prior observed sample is available to classify Nebula observer process continuity';
        break;
      default:
        fail('observed record process continuity is invalid');
    }
    const detail = `${peers.established} established peer${peers.established === 1 ? '' : 's'}; authenticated receive activity from ${peers.authenticatedRXWithin2m} within 2m and ${peers.authenticatedRXWithin5m} within 5m; ${lighthouses.established}/${lighthouses.configured} lighthouses established; ${lighthouseHistory}; ${continuityDetail}. Not an end-to-end reachability result. ${probeDetail}`;
    return Object.freeze({ state: 'observed', label: 'Runtime observed', detail, receivedAt: record.receivedAt });
  }

  function estimatedServerNow(responseNowMS, loadedAtMS, localNowMS = Date.now()) {
    if (!Number.isFinite(responseNowMS) || !Number.isFinite(loadedAtMS) || !Number.isFinite(localNowMS) || localNowMS < loadedAtMS) fail('elapsed response timing is invalid');
    return responseNowMS + (localNowMS - loadedAtMS);
  }

  return Object.freeze({
    SCHEMA,
    SCHEMA_V2,
    SCHEMA_V3,
    SCHEMA_V4,
    SCHEMA_V5,
    MAX_SNAPSHOT_AGE_MS,
    MAX_FUTURE_SKEW_MS,
    validateFleetProjection,
    presentation,
    estimatedServerNow,
  });
}));
