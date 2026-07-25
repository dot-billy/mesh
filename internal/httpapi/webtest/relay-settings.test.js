'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const relays = require('../web/relay-settings.js');

const base = () => ({
  schema: relays.SCHEMA,
  network_id: 'network_1',
  network_cidr: '10.42.0.0/24',
  enabled: true,
  relay_node_ids: ['node_a', 'node_b'],
  active_relays: [
    { node_id: 'node_a', name: 'relay-a', ip: '10.42.0.10', role: 'lighthouse' },
    { node_id: 'node_b', name: 'relay-b', ip: '10.42.0.11', role: 'member' },
  ],
  max_relay_nodes: 8,
  config_revision: 4,
  config_updated_at: '2026-07-21T12:00:00Z',
});

test('validates and freezes an exact managed relay document', () => {
  const result = relays.validate(base());
  assert.equal(result.enabled, true);
  assert.deepEqual(result.relayNodeIDs, ['node_a', 'node_b']);
  assert.deepEqual(result.activeRelays[0], { nodeID: 'node_a', name: 'relay-a', ip: '10.42.0.10', role: 'lighthouse' });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.relayNodeIDs), true);
  assert.equal(Object.isFrozen(result.activeRelays[0]), true);
  assert.equal(relays.sameDesired(result, true, ['node_b', 'node_a']), true);
  assert.equal(relays.sameDesired(result, false, []), false);
});

test('accepts pending selections and the canonical disabled state', () => {
  const pending = base(); pending.active_relays = [];
  assert.equal(relays.validate(pending).activeRelays.length, 0);
  const disabled = base(); disabled.enabled = false; disabled.relay_node_ids = []; disabled.active_relays = [];
  assert.equal(relays.validate(disabled).enabled, false);
});

test('rejects schema, selection, address, and active-relay ambiguity', () => {
  const mutations = [
    (value) => { value.schema = 'mesh-network-relays-v2'; },
    (value) => { value.unexpected = true; },
    (value) => { value.enabled = false; },
    (value) => { value.relay_node_ids = []; },
    (value) => { value.relay_node_ids.reverse(); },
    (value) => { value.relay_node_ids[1] = value.relay_node_ids[0]; },
    (value) => { value.active_relays[0].node_id = 'node_c'; },
    (value) => { value.active_relays[1].ip = value.active_relays[0].ip; },
    (value) => { value.active_relays[0].ip = '10.43.0.10'; },
    (value) => { value.active_relays[0].role = 'proxy'; },
    (value) => { value.active_relays.reverse(); },
    (value) => { value.max_relay_nodes = 9; },
    (value) => { value.config_revision = 0; },
    (value) => { value.config_updated_at = '2026-02-31T12:00:00Z'; },
  ];
  for (const mutate of mutations) {
    const value = base(); mutate(value);
    assert.throws(() => relays.validate(value), /Invalid network relay document/u);
  }
});
