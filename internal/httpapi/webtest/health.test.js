'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const health = require('../web/health.js');

const nowMS = Date.parse('2026-07-19T12:00:00.000Z');
const minute = 60 * 1000;
const day = 24 * 60 * 60 * 1000;
const iso = (offset = 0) => new Date(nowMS + offset).toISOString();
const clone = (value) => JSON.parse(JSON.stringify(value));

function severity(alerts) {
  if (alerts.some((alert) => alert.severity === 'critical')) return 'critical';
  if (alerts.some((alert) => alert.severity === 'warning')) return 'warning';
  return 'healthy';
}

function alertOrder(left, right) {
  const rank = { critical: 2, warning: 1, healthy: 0 };
  return rank[right.severity] - rank[left.severity] || left.code.localeCompare(right.code) || left.scope.localeCompare(right.scope) || (left.node_id || '').localeCompare(right.node_id || '');
}

function healthyNode(id, name, role = 'member') {
  return {
    id,
    name,
    ip: `10.42.0.${id.replace(/\D/g, '') || '9'}`,
		routed_subnets: [],
		site: role === 'lighthouse' && id.endsWith('2') ? 'gcp-use1' : 'aws-use1',
		failure_domain: role === 'lighthouse' && id.endsWith('2') ? 'gcp-use1-b' : 'aws-use1a',
    role,
    lifecycle_status: 'active',
    heartbeat_sequence: 1,
    phase: 'active',
    severity: 'healthy',
    operational: true,
    rollout_current: true,
    last_seen_at: iso(-30 * 1000),
    agent_status: 'healthy',
    nebula_running: true,
    desired_config_revision: 1,
    applied_config_revision: 1,
    desired_certificate_generation: 1,
    applied_certificate_generation: 1,
    certificate_expires_at: iso(90 * day),
    certificate_renew_after: iso(60 * day),
    agent_credential_expires_at: iso(60 * day),
    alerts: [],
  };
}

function emptySnapshot() {
  return {
    generated_at: iso(),
    policy: {
      heartbeat_warning_after_seconds: 120,
      heartbeat_offline_after_seconds: 300,
      credential_warning_before_seconds: 2592000,
      required_healthy_lighthouses: 2,
      evidence_source: 'authenticated_agent_heartbeat',
      overlay_reachability_observed: false,
    },
    summary: {
      overall: 'healthy', total_networks: 0, healthy_networks: 0, warning_networks: 0, critical_networks: 0,
      total_nodes: 0, setup_nodes: 0, active_nodes: 0, revoked_nodes: 0, healthy_nodes: 0, warning_nodes: 0, critical_nodes: 0,
    },
    rollout: { eligible_nodes: 0, converged_nodes: 0, drifted_nodes: 0, unreported_nodes: 0, percent: 100 },
    networks: [],
  };
}

function healthySnapshot() {
  const snapshot = emptySnapshot();
  snapshot.networks.push({
		network: { id: 'network-1', name: 'production', cidr: '10.42.0.0/24', listen_port: 4242, dns_settings: { enabled: false, listen_port: 53 }, relay_settings: { enabled: false, relay_node_ids: [] }, desired_config_revision: 1, config_updated_at: iso(-day) },
    summary: {},
    rollout: {},
    nodes: [healthyNode('node-1', 'lighthouse-a', 'lighthouse'), healthyNode('node-2', 'lighthouse-b', 'lighthouse')],
    alerts: [],
  });
  return recompute(snapshot);
}

function recompute(snapshot) {
  for (const report of snapshot.networks) {
    report.nodes.sort((left, right) => left.name.localeCompare(right.name) || left.id.localeCompare(right.id));
    for (const node of report.nodes) {
      node.alerts.sort(alertOrder);
      node.severity = severity(node.alerts);
    }
    const networkAlerts = report.alerts.filter((alert) => alert.scope === 'network');
    report.alerts = [...report.nodes.flatMap((node) => node.alerts), ...networkAlerts].sort(alertOrder);
    const active = report.nodes.filter((node) => node.lifecycle_status === 'active');
    const evaluated = active.filter((node) => node.phase !== 'setup');
    report.summary = {
      overall: severity(report.alerts),
      total_nodes: report.nodes.length,
      pending_nodes: report.nodes.filter((node) => node.lifecycle_status === 'pending').length,
      active_nodes: active.length,
      revoked_nodes: report.nodes.filter((node) => node.lifecycle_status === 'revoked').length,
      setup_nodes: report.nodes.filter((node) => node.phase === 'setup').length,
      healthy_nodes: evaluated.filter((node) => node.severity === 'healthy').length,
      warning_nodes: evaluated.filter((node) => node.severity === 'warning').length,
      critical_nodes: evaluated.filter((node) => node.severity === 'critical').length,
      active_lighthouses: active.filter((node) => node.role === 'lighthouse').length,
      healthy_lighthouses: active.filter((node) => node.role === 'lighthouse' && node.operational).length,
    };
    const converged = active.filter((node) => node.last_seen_at && node.rollout_current).length;
    const drifted = active.filter((node) => node.last_seen_at && !node.rollout_current).length;
    const unreported = active.filter((node) => !node.last_seen_at).length;
    report.rollout = {
      desired_config_revision: report.network.desired_config_revision,
      eligible_nodes: active.length,
      converged_nodes: converged,
      drifted_nodes: drifted,
      unreported_nodes: unreported,
      percent: active.length === 0 ? 100 : Math.floor((100 * converged) / active.length),
    };
  }
  snapshot.networks.sort((left, right) => left.network.name.localeCompare(right.network.name) || left.network.id.localeCompare(right.network.id));
  snapshot.summary = {
    overall: severity(snapshot.networks.map((report) => ({ severity: report.summary.overall }))),
    total_networks: snapshot.networks.length,
    healthy_networks: snapshot.networks.filter((report) => report.summary.overall === 'healthy').length,
    warning_networks: snapshot.networks.filter((report) => report.summary.overall === 'warning').length,
    critical_networks: snapshot.networks.filter((report) => report.summary.overall === 'critical').length,
    total_nodes: snapshot.networks.reduce((sum, report) => sum + report.summary.total_nodes, 0),
    setup_nodes: snapshot.networks.reduce((sum, report) => sum + report.summary.setup_nodes, 0),
    active_nodes: snapshot.networks.reduce((sum, report) => sum + report.summary.active_nodes, 0),
    revoked_nodes: snapshot.networks.reduce((sum, report) => sum + report.summary.revoked_nodes, 0),
    healthy_nodes: snapshot.networks.reduce((sum, report) => sum + report.summary.healthy_nodes, 0),
    warning_nodes: snapshot.networks.reduce((sum, report) => sum + report.summary.warning_nodes, 0),
    critical_nodes: snapshot.networks.reduce((sum, report) => sum + report.summary.critical_nodes, 0),
  };
  const eligible = snapshot.networks.reduce((sum, report) => sum + report.rollout.eligible_nodes, 0);
  const converged = snapshot.networks.reduce((sum, report) => sum + report.rollout.converged_nodes, 0);
  snapshot.rollout = {
    eligible_nodes: eligible,
    converged_nodes: converged,
    drifted_nodes: snapshot.networks.reduce((sum, report) => sum + report.rollout.drifted_nodes, 0),
    unreported_nodes: snapshot.networks.reduce((sum, report) => sum + report.rollout.unreported_nodes, 0),
    percent: eligible === 0 ? 100 : Math.floor((100 * converged) / eligible),
  };
  return snapshot;
}

function addCriticalMember(snapshot, code, evidence) {
  const report = snapshot.networks[0];
  const node = healthyNode('node-3', 'member-a');
  node.operational = false;
  node.rollout_current = code !== 'config_digest_drift' && code !== 'stale_revocation';
  node.alerts.push({ severity: 'critical', code, scope: 'node', node_id: node.id, evidence });
  if (code === 'stale_revocation') {
    node.applied_config_revision = 0;
    node.alerts.push({ severity: 'warning', code: 'config_drift', scope: 'node', node_id: node.id, evidence: { desired_config_revision: 1, applied_config_revision: 0 } });
  }
  report.nodes.push(node);
  return recompute(snapshot);
}

test('accepts a coherent authoritative snapshot and maps only allowlisted inventory', () => {
  const result = health.validateFleetSnapshot(healthySnapshot(), nowMS);
  assert.equal(result.summary.overall, 'healthy');
  assert.equal(result.rollout.percent, 100);
  assert.equal(result.networks[0].cidr, '10.42.0.0/24');
	assert.deepEqual(result.networks[0].dns_settings, { enabled: false, listen_port: 53, native_resolver: false, search_domain: '' });
	assert.deepEqual(result.networks[0].relay_settings, { enabled: false, relay_node_ids: [] });
  assert.equal(result.nodesByNetwork.get('network-1')[0].ip, '10.42.0.1');
  assert.equal(result.nodesByNetwork.get('network-1')[0].heartbeat_sequence, 1);
	assert.deepEqual(result.nodesByNetwork.get('network-1')[0].routed_subnets, []);
	assert.equal(Object.isFrozen(result.nodesByNetwork.get('network-1')[0].routed_subnets), true);
  assert.equal(Object.hasOwn(result.nodesByNetwork.get('network-1')[0], 'last_error'), false);
  assert.equal(Object.hasOwn(result.nodesByNetwork.get('network-1')[0], 'agent_version'), false);
});

test('accepts exact relay selection and rejects ambiguous or unavailable nodes', () => {
	const enabled = healthySnapshot();
	enabled.networks[0].network.relay_settings = { enabled: true, relay_node_ids: ['node-1', 'node-2'] };
	const result = health.validateFleetSnapshot(enabled, nowMS);
	assert.deepEqual(result.networks[0].relay_settings, { enabled: true, relay_node_ids: ['node-1', 'node-2'] });
	assert.equal(Object.isFrozen(result.networks[0].relay_settings.relay_node_ids), true);

	for (const settings of [
		{ enabled: false, relay_node_ids: ['node-1'] },
		{ enabled: true, relay_node_ids: [] },
		{ enabled: true, relay_node_ids: ['node-2', 'node-1'] },
		{ enabled: true, relay_node_ids: ['node-1', 'node-1'] },
		{ enabled: true, relay_node_ids: ['missing-node'] },
		{ enabled: false, relay_node_ids: [], endpoint: 'hidden' },
	]) {
		const invalid = healthySnapshot();
		invalid.networks[0].network.relay_settings = settings;
		assert.throws(() => health.validateFleetSnapshot(invalid, nowMS), /relay_settings/u);
	}
});

test('accepts exact network DNS settings and rejects ambiguous listener state', () => {
	const enabled = healthySnapshot();
	enabled.networks[0].network.dns_settings = { enabled: true, listen_port: 5353 };
	const result = health.validateFleetSnapshot(enabled, nowMS);
	assert.deepEqual(result.networks[0].dns_settings, { enabled: true, listen_port: 5353, native_resolver: false, search_domain: '' });
	assert.equal(Object.isFrozen(result.networks[0].dns_settings), true);

	for (const settings of [
		{ enabled: false, listen_port: 5353 },
		{ enabled: true, listen_port: 0 },
		{ enabled: true, listen_port: 4242 },
		{ enabled: 'true', listen_port: 53 },
		{ enabled: false, listen_port: 53, host: '0.0.0.0' },
	]) {
		const invalid = healthySnapshot();
		invalid.networks[0].network.dns_settings = settings;
		assert.throws(() => health.validateFleetSnapshot(invalid, nowMS), /dns_settings/u);
	}
});

test('accepts exact routed-subnet ownership and rejects ambiguous inventory', () => {
  const snapshot = healthySnapshot();
  snapshot.networks[0].nodes[0].routed_subnets = ['10.20.0.0/16', '192.168.50.0/24'];
  const result = health.validateFleetSnapshot(snapshot, nowMS);
  assert.deepEqual(result.nodesByNetwork.get('network-1')[0].routed_subnets, ['10.20.0.0/16', '192.168.50.0/24']);

  for (const routedSubnets of [
    ['192.168.50.1/24'],
    ['192.168.050.0/24'],
    ['0.0.0.0/1'],
    ['127.0.0.0/8'],
    ['224.0.0.0/4'],
    ['192.168.50.0/24', '10.20.0.0/16'],
    ['192.168.50.0/24', '192.168.50.0/24'],
  ]) {
    const invalid = healthySnapshot();
    invalid.networks[0].nodes[0].routed_subnets = routedSubnets;
    assert.throws(() => health.validateFleetSnapshot(invalid, nowMS), /routed_subnets|routed unicast|canonical IPv4/u);
  }
});

test('empty fleet is authoritative healthy with exact empty rollout', () => {
  const result = health.validateFleetSnapshot(emptySnapshot(), nowMS);
  assert.equal(result.reports.length, 0);
  assert.equal(result.rollout.percent, 100);
});

test('rejects replayed healthy and future snapshots at explicit bounds', () => {
  const stale = healthySnapshot();
  stale.generated_at = iso(-health.MAX_SNAPSHOT_AGE_MS - 1);
  assert.throws(() => health.validateFleetSnapshot(stale, nowMS), /stale/);
  const withinBound = emptySnapshot();
  withinBound.generated_at = iso(-health.MAX_SNAPSHOT_AGE_MS + 1);
  assert.doesNotThrow(() => health.validateFleetSnapshot(withinBound, nowMS));
  const future = healthySnapshot();
  future.generated_at = iso(health.MAX_FUTURE_SKEW_MS + 1);
  assert.throws(() => health.validateFleetSnapshot(future, nowMS), /future/);
});

test('counts delayed response body parsing against snapshot freshness', () => {
  const snapshot = emptySnapshot();
  snapshot.generated_at = iso(-health.MAX_SNAPSHOT_AGE_MS + 5000);
  assert.doesNotThrow(() => health.validateFleetSnapshot(snapshot, nowMS));

  const responseNowMS = health.responseAdjustedNow(nowMS, 1000, 6001);
  assert.equal(responseNowMS, nowMS + 5001);
  assert.throws(() => health.validateFleetSnapshot(snapshot, responseNowMS), /stale/);
  assert.throws(() => health.responseAdjustedNow(nowMS, 10, 9), /response timing/);
  assert.throws(() => health.responseAdjustedNow(nowMS, Number.NaN, 10), /response timing/);
});

test('rejects normalized impossible RFC3339 timestamps', () => {
  for (const generatedAt of ['2026-02-31T12:00:00Z', '2026-07-19T24:00:00Z', '2026-07-19T12:60:00Z']) {
    const snapshot = emptySnapshot();
    snapshot.generated_at = generatedAt;
    assert.throws(() => health.validateFleetSnapshot(snapshot, nowMS), /generated_at is invalid/);
  }
});

test('renders typed stale-revocation evidence and exact floor rollout', () => {
  const snapshot = addCriticalMember(healthySnapshot(), 'stale_revocation', {
    last_seen_at: iso(-minute), desired_config_revision: 1, applied_config_revision: 0,
    active_revocations: 1, revocation_at: iso(-2 * minute),
  });
  const result = health.validateFleetSnapshot(snapshot, nowMS);
  assert.equal(result.rollout.percent, 66);
  const alert = result.reports[0].nodes.find((node) => node.id === 'node-3').alerts[0];
  assert.match(health.alertPresentation(alert).evidence, /1 active revocation/);
  const wrong = clone(snapshot); wrong.rollout.percent = 67;
  assert.throws(() => health.validateFleetSnapshot(wrong, nowMS), /percent/);
});

test('accepts sanitized invalid telemetry only with its critical typed alert', () => {
  const snapshot = addCriticalMember(healthySnapshot(), 'telemetry_invalid', {});
  const rawNode = snapshot.networks[0].nodes.find((node) => node.id === 'node-3');
  delete rawNode.agent_status;
  rawNode.rollout_current = false;
  recompute(snapshot);
  const result = health.validateFleetSnapshot(snapshot, nowMS);
  assert.equal(result.reports[0].nodes.find((node) => node.id === 'node-3').severity, 'critical');

  const sanitizedRevision = addCriticalMember(healthySnapshot(), 'telemetry_invalid', {});
  const sanitizedNode = sanitizedRevision.networks[0].nodes.find((node) => node.id === 'node-3');
  sanitizedNode.applied_config_revision = 0;
  sanitizedNode.rollout_current = false;
  recompute(sanitizedRevision);
  assert.doesNotThrow(() => health.validateFleetSnapshot(sanitizedRevision, nowMS));

  const missingAlert = clone(snapshot);
  const node = missingAlert.networks[0].nodes.find((entry) => entry.id === 'node-3');
  node.alerts = [];
  recompute(missingAlert);
  assert.throws(() => health.validateFleetSnapshot(missingAlert, nowMS), /agent_status|operational|falsely healthy/);
});

test('accepts fail-closed certificate lifecycle metadata variants from the API', () => {
  const variants = [undefined, '0001-01-01T00:00:00Z', iso(90 * day), iso(90 * day + 1000)];
  for (const renewAfter of variants) {
    const snapshot = healthySnapshot();
    const node = healthyNode('node-3', 'member-a');
    node.operational = false;
    node.rollout_current = false;
    if (renewAfter === undefined) delete node.certificate_renew_after;
    else node.certificate_renew_after = renewAfter;
    node.alerts.push({ severity: 'critical', code: 'certificate_metadata_missing', scope: 'node', node_id: node.id, evidence: {} });
    snapshot.networks[0].nodes.push(node);
    recompute(snapshot);
    assert.doesNotThrow(() => health.validateFleetSnapshot(snapshot, nowMS));
  }
});

test('rejects rollout_current for offline or future heartbeat evidence', () => {
  const cases = [
    {
      lastSeen: iso(-6 * minute),
      alert: { severity: 'critical', code: 'heartbeat_offline', scope: 'node', node_id: 'node-3', evidence: { since_at: iso(-6 * minute), age_seconds: 360, threshold_seconds: 300 } },
    },
    {
      lastSeen: iso(minute),
      alert: { severity: 'critical', code: 'heartbeat_time_invalid', scope: 'node', node_id: 'node-3', evidence: { last_seen_at: iso(minute) } },
    },
  ];
  for (const scenario of cases) {
    const snapshot = healthySnapshot();
    const node = healthyNode('node-3', 'member-a');
    node.last_seen_at = scenario.lastSeen;
    node.operational = false;
    node.rollout_current = false;
    node.alerts.push(scenario.alert);
    snapshot.networks[0].nodes.push(node);
    recompute(snapshot);
    assert.doesNotThrow(() => health.validateFleetSnapshot(snapshot, nowMS));

    node.rollout_current = true;
    recompute(snapshot);
    assert.throws(() => health.validateFleetSnapshot(snapshot, nowMS), /rollout_current/);
  }
});

test('accepts API rollout state for stopped, expired, and degraded agents', () => {
  const cases = [
    {
      mutate(node) {
        node.nebula_running = false;
        node.operational = false;
        node.rollout_current = false;
        node.alerts.push({ severity: 'critical', code: 'nebula_stopped', scope: 'node', node_id: node.id, evidence: { nebula_running: false } });
      },
      rolloutCurrent: false,
    },
    {
      mutate(node) {
        node.certificate_expires_at = iso(-minute);
        node.certificate_renew_after = iso(-day);
        node.operational = false;
        node.rollout_current = false;
        node.alerts.push({ severity: 'critical', code: 'certificate_expired', scope: 'node', node_id: node.id, evidence: { expires_at: iso(-minute) } });
      },
      rolloutCurrent: false,
    },
    {
      mutate(node) {
        node.agent_status = 'degraded';
        node.operational = false;
        node.alerts.push({ severity: 'critical', code: 'agent_degraded', scope: 'node', node_id: node.id, evidence: { reported_status: 'degraded' } });
      },
      rolloutCurrent: true,
    },
  ];
  for (const scenario of cases) {
    const snapshot = healthySnapshot();
    const node = healthyNode('node-3', 'member-a');
    scenario.mutate(node);
    snapshot.networks[0].nodes.push(node);
    recompute(snapshot);
    const result = health.validateFleetSnapshot(snapshot, nowMS);
    assert.equal(result.reports[0].nodes.find((entry) => entry.id === node.id).rolloutCurrent, scenario.rolloutCurrent);
  }
});

test('requires lighthouse redundancy alert and exact typed evidence', () => {
  const snapshot = healthySnapshot();
  snapshot.networks[0].nodes.pop();
  recompute(snapshot);
  assert.throws(() => health.validateFleetSnapshot(snapshot, nowMS), /lighthouse redundancy/);
  const report = snapshot.networks[0];
  report.alerts.push({ severity: 'warning', code: 'lighthouse_single', scope: 'network', evidence: { active_lighthouses: 1, healthy_lighthouses: 1, required_lighthouses: 2 } });
  recompute(snapshot);
  assert.doesNotThrow(() => health.validateFleetSnapshot(snapshot, nowMS));
  report.alerts[0].evidence.required_lighthouses = 3;
  assert.throws(() => health.validateFleetSnapshot(snapshot, nowMS), /evidence is inconsistent/);
});

test('accepts new network safety alerts and rejects unknown or raw evidence', () => {
  const snapshot = healthySnapshot();
  snapshot.networks[0].alerts.push({ severity: 'critical', code: 'projection_limit_exceeded', scope: 'network', evidence: { observed_lighthouses: 65, projection_limit: 64 } });
  recompute(snapshot);
  const result = health.validateFleetSnapshot(snapshot, nowMS);
  assert.match(health.alertPresentation(result.reports[0].alerts[0]).evidence, /limit 64/);
  const unknown = clone(snapshot); unknown.networks[0].alerts[0].code = 'future_untyped_alert';
  assert.throws(() => health.validateFleetSnapshot(unknown, nowMS), /not allowlisted/);
  const raw = healthySnapshot(); raw.networks[0].nodes[0].last_error = 'secret';
  assert.throws(() => health.validateFleetSnapshot(raw, nowMS), /not allowed/);
});

test('rejects duplicate global network and node IDs before Map construction', () => {
  const duplicateNetwork = healthySnapshot();
  duplicateNetwork.networks.push(clone(duplicateNetwork.networks[0]));
  assert.throws(() => health.validateFleetSnapshot(duplicateNetwork, nowMS), /duplicate IDs/);

  const duplicateNode = healthySnapshot();
  const second = clone(duplicateNode.networks[0]);
  second.network.id = 'network-2'; second.network.name = 'zeta'; second.network.cidr = '10.43.0.0/24';
  duplicateNode.networks.push(second);
  assert.throws(() => health.validateFleetSnapshot(duplicateNode, nowMS), /duplicate node ID/);
});

test('rejects false-operational and expired false-green reports', () => {
  const stopped = healthySnapshot(); stopped.networks[0].nodes[0].nebula_running = false;
  assert.throws(() => health.validateFleetSnapshot(stopped, nowMS), /nebula_stopped|operational/);
  const expired = healthySnapshot(); expired.networks[0].nodes[0].certificate_expires_at = iso(-minute); expired.networks[0].nodes[0].certificate_renew_after = iso(-day);
  assert.throws(() => health.validateFleetSnapshot(expired, nowMS), /certificate lifecycle|operational|falsely healthy/);
});

test('forced refresh waits for an in-flight read and guarantees a trailing read', async () => {
  const resolvers = [];
  let calls = 0;
  const coordinator = health.createRefreshCoordinator(() => new Promise((resolve) => { calls += 1; resolvers.push(resolve); }));
  const initial = coordinator.refresh();
  await Promise.resolve();
  assert.equal(calls, 1);
  const forced = coordinator.refresh(true);
  resolvers.shift()();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(calls, 2);
  coordinator.refresh(true);
  resolvers.shift()();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(calls, 3);
  resolvers.shift()();
  await Promise.all([initial, forced]);
});
