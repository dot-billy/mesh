'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const dns = require('../web/dns-settings.js');

const base = () => ({
  schema: dns.SCHEMA,
  network_id: 'network_1',
  network_cidr: '10.42.0.0/24',
  enabled: true,
  listen_port: 5353,
	native_resolver: true,
	search_domain: 'corp.mesh',
  firewall_ready: true,
  resolvers: [
    { node_id: 'node_a', name: 'lighthouse-a', ip: '10.42.0.10' },
    { node_id: 'node_b', name: 'lighthouse-b', ip: '10.42.0.11' },
  ],
  config_revision: 4,
  config_updated_at: '2026-07-21T12:00:00Z',
});

test('validates and freezes an exact managed DNS document', () => {
  const result = dns.validate(base());
  assert.equal(result.enabled, true);
  assert.equal(result.listenPort, 5353);
	assert.equal(result.nativeResolver, true);
	assert.equal(result.searchDomain, 'corp.mesh');
  assert.deepEqual(result.resolvers[0], { nodeID: 'node_a', name: 'lighthouse-a', ip: '10.42.0.10' });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.resolvers), true);
  assert.equal(Object.isFrozen(result.resolvers[0]), true);
	assert.equal(dns.sameDesired(result, true, 5353, true, 'corp.mesh'), true);
  assert.equal(dns.sameDesired(result, false, 53), false);
});

test('accepts disabled DNS only with the canonical empty resolver state', () => {
  const value = base();
  value.enabled = false;
  value.listen_port = 53;
	value.native_resolver = false;
	value.search_domain = '';
  value.firewall_ready = false;
  value.resolvers = [];
  const result = dns.validate(value);
  assert.equal(result.enabled, false);
  assert.equal(result.resolvers.length, 0);
});

test('rejects schema, listener, firewall, and resolver ambiguity', () => {
  const mutations = [
    (value) => { value.schema = 'mesh-network-dns-v2'; },
    (value) => { value.unexpected = true; },
    (value) => { value.enabled = false; },
	(value) => { value.native_resolver = false; },
	(value) => { value.search_domain = 'corp.local'; },
    (value) => { value.firewall_ready = false; },
    (value) => { value.listen_port = 0; },
    (value) => { value.resolvers[0].ip = '10.43.0.10'; },
    (value) => { value.resolvers[1].ip = value.resolvers[0].ip; },
    (value) => { value.resolvers[1].node_id = value.resolvers[0].node_id; },
    (value) => { value.resolvers.reverse(); },
    (value) => { value.config_revision = 0; },
    (value) => { value.config_updated_at = '2026-02-31T12:00:00Z'; },
  ];
  for (const mutate of mutations) {
    const value = base();
    mutate(value);
    assert.throws(() => dns.validate(value), /Invalid network DNS document/u);
  }
});
