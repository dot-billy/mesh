'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const model = require('../web/route-profile.js');

function owner(desired = 0, ready = false) {
  return { node_id: 'node_owner', name: 'owner', certificate_generation: 2, applied_certificate_generation: ready ? 2 : 1, applied_config_revision: 8, desired_certificate_generation: desired, ready };
}

function empty() {
  return {
    schema: model.SCHEMA, network_id: 'network_1', node_id: 'node_owner', request_id: '', phase: '',
    original_routed_subnets: ['192.168.50.0/24'], desired_routed_subnets: ['192.168.50.0/24'], additions: [], removals: [], config_revision: 7,
    started_at: null, promoted_at: null, finished_at: null, owner: owner(), available_actions: ['start'],
  };
}

test('validates empty and convergence-gated mixed edits', () => {
  assert.deepEqual(model.validate(empty()).availableActions, ['start']);
  const preparing = empty();
  Object.assign(preparing, {
    request_id: 'route-profile-0001', phase: 'preparing_owner', desired_routed_subnets: ['192.168.51.0/24'],
    additions: ['192.168.51.0/24'], removals: ['192.168.50.0/24'], config_revision: 8,
    started_at: '2026-07-21T20:00:00Z', owner: owner(2, true), available_actions: ['advance', 'cancel'],
  });
  const parsed = model.validate(preparing);
  assert.equal(parsed.owner.ready, true);
  assert.deepEqual(parsed.availableActions, ['advance', 'cancel']);
});

test('rejects unknown fields, inconsistent differences, and unproven actions', () => {
  const extra = empty(); extra.extra = true;
  assert.throws(() => model.validate(extra), /extra is not allowed/);
  const inconsistent = empty(); inconsistent.additions = ['192.168.52.0/24'];
  assert.throws(() => model.validate(inconsistent), /differences are inconsistent/);
  const forged = empty();
  Object.assign(forged, {
    request_id: 'route-profile-0001', phase: 'preparing_owner', desired_routed_subnets: ['192.168.51.0/24'],
    additions: ['192.168.51.0/24'], removals: ['192.168.50.0/24'], started_at: '2026-07-21T20:00:00Z', owner: owner(2, false), available_actions: ['advance'],
  });
  assert.throws(() => model.validate(forged), /advance action is not backed/);
});
