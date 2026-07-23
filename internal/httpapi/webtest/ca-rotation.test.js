'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const model = require('../web/ca-rotation.js');

function stable() {
  return {
    schema: model.SCHEMA,
    network_id: 'network_1',
    phase: 'stable',
    current_trust_bundle_sha256: 'a'.repeat(64),
    previous_trust_bundle_sha256: '',
    active_ca_certificate_sha256: 'a'.repeat(64),
    target_ca_certificate_sha256: '',
    stage_config_revision: 0,
    config_revision: 7,
    config_updated_at: '2026-07-21T18:00:00Z',
    started_at: null,
    stage_started_at: null,
    active_nodes: 0,
    converged_nodes: 0,
    pending_recovery_replays: 0,
    available_actions: ['prepare'],
    nodes: [],
  };
}

test('validates exact stable and rotating lifecycle documents', () => {
  const current = model.validate(stable());
  assert.equal(current.phase, 'stable');
  assert.deepEqual(current.availableActions, ['prepare']);

  const rotating = stable();
  rotating.phase = 'rotating';
  rotating.current_trust_bundle_sha256 = 'c'.repeat(64);
  rotating.previous_trust_bundle_sha256 = 'a'.repeat(64);
  rotating.target_ca_certificate_sha256 = 'b'.repeat(64);
  rotating.stage_config_revision = 8;
  rotating.config_revision = 8;
  rotating.started_at = '2026-07-21T18:01:00Z';
  rotating.stage_started_at = '2026-07-21T18:02:00Z';
  rotating.active_nodes = 1;
  rotating.nodes = [{
    node_id: 'node_1', name: 'member-1', status: 'active', certificate_authority_sha256: 'a'.repeat(64),
    certificate_generation: 1, applied_certificate_generation: 1, applied_config_revision: 8, converged: false,
  }];
  rotating.available_actions = [];
  const parsed = model.validate(rotating);
  assert.equal(parsed.nodes[0].converged, false);
  assert.equal(parsed.targetCACertificateSHA256, 'b'.repeat(64));
});

test('rejects unknown fields, forged totals, and incoherent stable metadata', () => {
  const extra = stable(); extra.extra = true;
  assert.throws(() => model.validate(extra), /extra is not allowed/);
  const forged = stable(); forged.active_nodes = 1;
  assert.throws(() => model.validate(forged), /nodes is inconsistent/);
  const transition = stable(); transition.previous_trust_bundle_sha256 = 'b'.repeat(64);
  assert.throws(() => model.validate(transition), /stable lifecycle metadata is inconsistent/);
  const duplicateAction = stable(); duplicateAction.available_actions = ['prepare', 'prepare'];
  assert.throws(() => model.validate(duplicateAction), /available_actions is invalid/);
});
