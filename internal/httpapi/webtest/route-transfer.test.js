'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const model = require('../web/route-transfer.js');

function empty() {
  return {
    schema: model.SCHEMA, network_id: 'network_1', request_id: '', phase: '', routed_subnets: [], config_revision: 7,
    started_at: null, promoted_at: null, finished_at: null, source: null, target: null, available_actions: ['start'],
  };
}

function node(id, name, desired, ready) {
  return { node_id: id, name, certificate_generation: 2, applied_certificate_generation: ready ? 2 : 1, applied_config_revision: 8, desired_certificate_generation: desired, ready };
}

test('validates empty and convergence-gated preparing documents', () => {
  assert.deepEqual(model.validate(empty()).availableActions, ['start']);
  const preparing = empty();
  Object.assign(preparing, {
    request_id: 'route-transfer-0001', phase: 'preparing_target', routed_subnets: ['192.168.50.0/24'], config_revision: 8,
    started_at: '2026-07-21T20:00:00Z', source: node('node_source', 'source', 0, false), target: node('node_target', 'target', 2, true), available_actions: ['advance', 'cancel'],
  });
  const parsed = model.validate(preparing);
  assert.equal(parsed.target.ready, true);
  assert.deepEqual(parsed.availableActions, ['advance', 'cancel']);
});

test('rejects unknown fields and unproven advance actions', () => {
  const extra = empty(); extra.extra = true;
  assert.throws(() => model.validate(extra), /extra is not allowed/);
  const forged = empty();
  Object.assign(forged, {
    request_id: 'route-transfer-0001', phase: 'preparing_target', routed_subnets: ['192.168.50.0/24'],
    started_at: '2026-07-21T20:00:00Z', source: node('node_source', 'source', 0, false), target: node('node_target', 'target', 2, false), available_actions: ['advance'],
  });
  assert.throws(() => model.validate(forged), /advance action is not backed/);
});
