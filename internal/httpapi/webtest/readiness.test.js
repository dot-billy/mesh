'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const readiness = require('../web/readiness.js');

const clone = (value) => JSON.parse(JSON.stringify(value));

function validReport() {
  return {
    schema: readiness.SCHEMA,
    generated_at: '2026-07-20T12:00:00Z',
    overall: 'ready',
    network: { id: 'network-a', name: 'production', cidr: '10.42.0.0/24', listen_port: 4242 },
    projection: { complete: true, observed_lighthouses: 2, included_lighthouses: 2, lighthouse_limit: 64 },
    checks: {
      managed_route_overlap: { status: 'pass', evidence_source: 'control_inventory', overlapping_network_count: 0, summary: 'No managed overlap.', action: 'No action.' },
      client_route_overlap: {
        status: 'pass', evidence_source: 'authenticated_node_route_inventory', observed_nodes: 2,
        required_nodes: 2, overlapping_nodes: 0, freshness_window_seconds: 90,
        evidence_at: '2026-07-20T11:59:30Z', summary: 'Current routes do not overlap.', action: 'Re-run after route changes.',
      },
      lighthouse_redundancy: { status: 'pass', evidence_source: 'control_inventory', configured_lighthouses: 2, active_lighthouses: 2, required_lighthouses: 2, summary: 'Two are active.', action: 'Separate failure domains.' },
		topology_diversity: { status: 'pass', evidence_source: 'control_inventory', configured_sites: 2, active_sites: 2, active_nodes: 3, assigned_active_nodes: 3, active_lighthouses: 2, assigned_active_lighthouses: 2, distinct_lighthouse_failure_domains: 2, required_lighthouse_failure_domains: 2, summary: 'Two independent domains.', action: 'Keep placement current.' },
      dns_resolution: { status: 'pass', evidence_source: 'control_plane_dns', dns_names: 1, resolved_dns_names: 1, unresolved_dns_names: 0, summary: 'DNS resolves.', action: 'Check member DNS.' },
      member_dns_resolution: {
        status: 'pass', evidence_source: 'authenticated_member_dns_resolution', observed_members: 2,
        required_members: 2, failing_members: 0, dns_names: 1, freshness_window_seconds: 90,
        evidence_at: '2026-07-20T11:59:30Z', summary: 'Members resolve DNS.', action: 'Re-run after DNS changes.',
      },
      public_udp_reachability: {
        status: 'pass', evidence_source: 'authenticated_member_active_probe', observed_members: 1,
        required_members: 1,
        verified_lighthouses: 2, required_lighthouses: 2, freshness_window_seconds: 30,
        evidence_at: '2026-07-20T11:59:57Z', summary: 'All lighthouses replied.', action: 'Keep a member reporting.',
      },
    },
    lighthouses: [
		{ id: 'lh-a', name: 'alpha', site: 'aws-use1', failure_domain: 'aws-use1a', lifecycle_status: 'active', public_endpoint: 'lh.example:4242', endpoint_host_type: 'dns', dns_resolution: 'resolved', resolved_address_count: 2 },
		{ id: 'lh-b', name: 'beta', site: 'gcp-use1', failure_domain: 'gcp-use1-b', lifecycle_status: 'active', public_endpoint: '198.51.100.10:4242', endpoint_host_type: 'ipv4', dns_resolution: 'not_applicable', resolved_address_count: 0 },
    ],
		sites: [
			{ name: 'aws-use1', configured_nodes: 2, active_nodes: 2, active_members: 1, active_lighthouses: 1, failure_domains: ['aws-use1a'] },
			{ name: 'gcp-use1', configured_nodes: 1, active_nodes: 1, active_members: 0, active_lighthouses: 1, failure_domains: ['gcp-use1-b'] },
		],
  };
}

test('validates, translates, and freezes exact readiness evidence', () => {
  const model = readiness.validate(validReport());
  assert.equal(model.schema, readiness.SCHEMA);
  assert.equal(model.overall, 'ready');
  assert.equal(model.network.listenPort, 4242);
  assert.equal(model.checks.dnsResolution.resolvedDNSNames, 1);
  assert.equal(model.checks.memberDNSResolution.observedMembers, 2);
  assert.equal(model.checks.publicUDPReachability.evidenceSource, 'authenticated_member_active_probe');
  assert.equal(model.checks.publicUDPReachability.verifiedLighthouses, 2);
  assert.equal(model.checks.publicUDPReachability.evidenceAt, '2026-07-20T11:59:57Z');
	assert.equal(model.checks.topologyDiversity.distinctLighthouseFailureDomains, 2);
	assert.equal(model.sites[0].name, 'aws-use1');
  assert.equal(model.lighthouses[0].resolvedAddressCount, 2);
  assert.ok(Object.isFrozen(model));
  assert.ok(Object.isFrozen(model.checks));
  assert.ok(Object.isFrozen(model.lighthouses));
  assert.ok(Object.isFrozen(model.lighthouses[0]));
  assert.equal(readiness.statusLabel('unknown'), 'Not observed');
  assert.equal(model.checks.clientRouteOverlap.observedNodes, 2);
  assert.equal(readiness.overallLabel(model.overall), 'Ready');
});

test('rejects unknown keys, wrong evidence sources, and ambiguous types', () => {
  const mutations = [
    (value) => { value.extra = true; },
    (value) => { value.schema = 'mesh-network-readiness-v2'; },
    (value) => { value.generated_at = 'yesterday'; },
    (value) => { value.network.listen_port = '4242'; },
    (value) => { value.projection.complete = 1; },
    (value) => { value.checks.client_route_overlap.evidence_source = 'browser_guess'; },
    (value) => { value.checks.member_dns_resolution.evidence_source = 'browser_guess'; },
    (value) => { value.checks.public_udp_reachability.evidence_source = 'browser_guess'; },
    (value) => { value.lighthouses[0].private_key = 'secret'; },
    (value) => { value.lighthouses[0].name = 'alpha\nforged'; },
  ];
  for (const mutate of mutations) {
    const value = clone(validReport());
    mutate(value);
    assert.throws(() => readiness.validate(value), /Invalid deployment readiness/);
  }
});

test('fails closed on inconsistent projection, counts, status, and ordering', () => {
  const mutations = [
    (value) => { value.projection.complete = false; },
    (value) => { value.projection.included_lighthouses = 1; },
    (value) => { value.checks.lighthouse_redundancy.active_lighthouses = 1; },
    (value) => { value.checks.dns_resolution.resolved_dns_names = 0; },
    (value) => { value.checks.managed_route_overlap.overlapping_network_count = 1; },
    (value) => { value.checks.client_route_overlap.observed_nodes = 1; },
    (value) => { value.checks.client_route_overlap.overlapping_nodes = 1; },
    (value) => { value.checks.client_route_overlap.freshness_window_seconds = 91; },
    (value) => { value.checks.client_route_overlap.evidence_at = '2026-07-20T11:58:29Z'; },
    (value) => { value.checks.member_dns_resolution.observed_members = 1; },
    (value) => { value.checks.member_dns_resolution.failing_members = 1; },
    (value) => { value.checks.member_dns_resolution.dns_names = 2; },
    (value) => { value.checks.member_dns_resolution.freshness_window_seconds = 91; },
    (value) => { value.checks.member_dns_resolution.evidence_at = '2026-07-20T11:58:29Z'; },
    (value) => { value.checks.public_udp_reachability.observed_members = 0; },
    (value) => { value.checks.public_udp_reachability.required_members = 2; },
    (value) => { value.checks.public_udp_reachability.verified_lighthouses = 1; },
    (value) => { value.checks.public_udp_reachability.required_lighthouses = 1; },
    (value) => { value.checks.public_udp_reachability.freshness_window_seconds = 31; },
    (value) => { value.checks.public_udp_reachability.evidence_at = '2026-07-20T12:00:01Z'; },
    (value) => { value.lighthouses[0].resolved_address_count = 0; },
    (value) => { value.lighthouses[1].dns_resolution = 'resolved'; },
    (value) => { value.lighthouses.reverse(); },
    (value) => { value.lighthouses[1].id = value.lighthouses[0].id; },
    (value) => { value.overall = 'verification_required'; },
  ];
  for (const mutate of mutations) {
    const value = clone(validReport());
    mutate(value);
    assert.throws(() => readiness.validate(value), /Invalid deployment readiness/);
  }
});

test('accepts a bounded blocked report without fabricating endpoint evidence', () => {
  const value = validReport();
  value.overall = 'blocked';
  value.projection = { complete: true, observed_lighthouses: 1, included_lighthouses: 1, lighthouse_limit: 64 };
  value.checks.lighthouse_redundancy = { status: 'blocked', evidence_source: 'control_inventory', configured_lighthouses: 1, active_lighthouses: 0, required_lighthouses: 2, summary: 'None active.', action: 'Activate one.' };
	value.checks.topology_diversity = { status: 'warning', evidence_source: 'control_inventory', configured_sites: 1, active_sites: 0, active_nodes: 0, assigned_active_nodes: 0, active_lighthouses: 0, assigned_active_lighthouses: 0, distinct_lighthouse_failure_domains: 0, required_lighthouse_failure_domains: 2, summary: 'No diversity yet.', action: 'Activate two.' };
  value.checks.dns_resolution = { status: 'blocked', evidence_source: 'control_plane_dns', dns_names: 1, resolved_dns_names: 0, unresolved_dns_names: 1, summary: 'DNS failed.', action: 'Fix DNS.' };
  value.checks.client_route_overlap = {
    status: 'unknown', evidence_source: 'not_observed', observed_nodes: 0,
    required_nodes: 0, overlapping_nodes: 0, freshness_window_seconds: 90,
    evidence_at: null, summary: 'Routes are not observed.', action: 'Activate nodes.',
  };
  value.checks.member_dns_resolution = {
    status: 'unknown', evidence_source: 'not_observed', observed_members: 0,
    required_members: 0, failing_members: 0, dns_names: 0, freshness_window_seconds: 90,
    evidence_at: null, summary: 'Member DNS is not observed.', action: 'Activate a member.',
  };
  value.checks.public_udp_reachability = {
    status: 'unknown', evidence_source: 'not_observed', observed_members: 0,
    required_members: 0,
    verified_lighthouses: 0, required_lighthouses: 0, freshness_window_seconds: 30,
    evidence_at: null, summary: 'UDP is not observed.', action: 'Test externally.',
  };
  value.lighthouses = [{ id: 'lh-a', name: 'alpha', site: 'aws-use1', failure_domain: 'aws-use1a', lifecycle_status: 'pending', public_endpoint: 'missing.example:4242', endpoint_host_type: 'dns', dns_resolution: 'unresolved', resolved_address_count: 0 }];
	value.sites = [{ name: 'aws-use1', configured_nodes: 1, active_nodes: 0, active_members: 0, active_lighthouses: 0, failure_domains: ['aws-use1a'] }];
  const model = readiness.validate(value);
  assert.equal(model.overall, 'blocked');
  assert.equal(model.checks.publicUDPReachability.status, 'unknown');
  assert.equal(model.lighthouses[0].dnsResolution, 'unresolved');
});

test('accepts authenticated route conflict evidence and rejects partial no-conflict claims', () => {
  const blocked = validReport();
  blocked.overall = 'blocked';
  blocked.checks.client_route_overlap = {
    status: 'blocked', evidence_source: 'authenticated_node_route_inventory', observed_nodes: 1,
    required_nodes: 2, overlapping_nodes: 1, freshness_window_seconds: 90,
    evidence_at: '2026-07-20T11:59:30Z', summary: 'One node overlaps.', action: 'Change the CIDR.',
  };
  const model = readiness.validate(blocked);
  assert.equal(model.checks.clientRouteOverlap.status, 'blocked');
  assert.equal(model.checks.clientRouteOverlap.overlappingNodes, 1);

  const partial = validReport();
  partial.overall = 'verification_required';
  partial.checks.client_route_overlap.observed_nodes = 1;
  assert.throws(() => readiness.validate(partial), /Invalid deployment readiness/);
});

test('accepts authenticated member DNS failure and rejects partial success claims', () => {
  const blocked = validReport();
  blocked.overall = 'blocked';
  blocked.checks.member_dns_resolution = {
    status: 'blocked', evidence_source: 'authenticated_member_dns_resolution', observed_members: 1,
    required_members: 2, failing_members: 1, dns_names: 1, freshness_window_seconds: 90,
    evidence_at: '2026-07-20T11:59:30Z', summary: 'One member cannot resolve.', action: 'Fix member DNS.',
  };
  const model = readiness.validate(blocked);
  assert.equal(model.checks.memberDNSResolution.status, 'blocked');
  assert.equal(model.checks.memberDNSResolution.failingMembers, 1);

  const partial = validReport();
  partial.overall = 'verification_required';
  partial.checks.member_dns_resolution.observed_members = 1;
  assert.throws(() => readiness.validate(partial), /Invalid deployment readiness/);
});

test('rejects fabricated, partial, stale-shaped, and mismatched UDP evidence', () => {
  const mutations = [
    (value) => { value.checks.public_udp_reachability.status = 'unknown'; },
    (value) => { value.checks.public_udp_reachability.evidence_at = null; },
    (value) => { value.checks.public_udp_reachability.observed_members = 0; },
    (value) => { value.checks.public_udp_reachability.required_members = 2; },
    (value) => { value.checks.public_udp_reachability.verified_lighthouses = 1; },
    (value) => { value.checks.public_udp_reachability.required_lighthouses = 3; },
    (value) => { value.checks.public_udp_reachability.freshness_window_seconds = 29; },
    (value) => { value.checks.public_udp_reachability.evidence_at = '2026-07-20T11:59:29Z'; },
  ];
  for (const mutate of mutations) {
    const value = clone(validReport());
    mutate(value);
    assert.throws(() => readiness.validate(value), /Invalid deployment readiness/);
  }
});

test('dashboard loads the readiness adapter and renders only text-safe evidence', () => {
  const index = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
  const app = fs.readFileSync(path.join(__dirname, '../web/app.js'), 'utf8');
  assert.ok(index.indexOf('src="/readiness.js"') < index.indexOf('src="/app.js"'));
  assert.match(app, /const readinessModel = globalThis\.MeshReadiness;/);
  assert.match(app, /\/api\/v1\/networks\/\$\{networkID\}\/readiness/);
  assert.match(app, /readinessModel\.validate/);
  assert.doesNotMatch(app, /innerHTML|outerHTML|insertAdjacentHTML|document\.write/);
  for (const id of ['readiness-dialog', 'readiness-overall', 'readiness-check-list', 'readiness-lighthouse-list', 'readiness-add-lighthouse', 'refresh-readiness']) {
    assert.equal((index.match(new RegExp(`id=["']${id}["']`, 'g')) || []).length, 1, `${id} must occur exactly once`);
  }
});
