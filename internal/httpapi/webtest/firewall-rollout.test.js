'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const model = require('../web/firewall-rollout.js');

function node(id = 'node_1') {
  return {
    node_id: id, name: id, ip: '10.100.0.2', role: 'member', canary: false,
    applied_config_revision: 7, applied_config_sha256: 'a'.repeat(64), desired_config_sha256: 'a'.repeat(64),
    certificate_generation: 1, applied_certificate_generation: 1, nebula_running: true, agent_status: 'healthy', converged: false,
  };
}

function stable() {
  return {
    schema: model.SCHEMA, network_id: 'network_1', phase: 'stable', config_revision: 7,
    config_updated_at: '2026-07-21T19:00:00Z', stage_config_revision: 0, started_at: null, paused_at: null,
    current_policy_sha256: 'a'.repeat(64), target_policy_sha256: '', target_policy: null,
    active_nodes: 1, canary_nodes: 0, converged_canaries: 0, available_actions: ['start'], nodes: [node()], last_transition: null,
    automatic_rollback_guards: ['activation_failed', 'target_runtime_stopped'],
  };
}

function canary() {
  const value = stable();
  value.phase = 'canary';
  value.config_revision = 8;
  value.stage_config_revision = 8;
  value.started_at = '2026-07-21T19:01:00Z';
  value.target_policy_sha256 = 'b'.repeat(64);
  value.target_policy = {
    mode: 'managed', renderer_version: 2,
    inbound: [{ proto: 'tcp', port: '443', group: 'all' }],
    outbound: [{ proto: 'tcp', port: '443', host: 'any' }],
    rendered_firewall: 'firewall:\n  inbound: []\n  outbound: []\n',
    policy_sha256: 'b'.repeat(64),
    effective_nodes: [{
      node_id: 'node_1', name: 'node_1', ip: '10.100.0.2', groups: ['all'],
      inbound: [{ proto: 'tcp', port: '443', group: 'all' }],
      outbound: [{ proto: 'tcp', port: '443', host: 'any' }],
      rendered_firewall: 'firewall:\n  inbound: []\n  outbound: []\n',
      sha256: 'b'.repeat(64),
    }],
  };
  value.canary_nodes = 1;
  value.nodes[0].canary = true;
  value.nodes[0].desired_config_sha256 = 'b'.repeat(64);
  value.nodes[0].applied_config_revision = 7;
  value.available_actions = ['pause', 'rollback'];
  return value;
}

test('validates exact stable and converged canary documents', () => {
  const current = model.validate(stable());
  assert.equal(current.phase, 'stable');
  assert.equal(current.nodes[0].canary, false);

  const staged = canary();
  staged.nodes[0].applied_config_revision = 8;
  staged.nodes[0].applied_config_sha256 = 'b'.repeat(64);
  staged.nodes[0].converged = true;
  staged.converged_canaries = 1;
  staged.available_actions = ['promote', 'pause', 'rollback'];
  const parsed = model.validate(staged);
  assert.equal(parsed.targetPolicy.inbound[0].port, '443');
  assert.equal(parsed.convergedCanaries, 1);
  assert.deepEqual(parsed.availableActions, ['promote', 'pause', 'rollback']);
});

test('validates paused target retention and rejects forged convergence', () => {
  const value = canary();
  value.phase = 'paused';
  value.config_revision = 9;
  value.config_updated_at = '2026-07-21T19:02:00Z';
  value.paused_at = '2026-07-21T19:02:00Z';
  value.nodes[0].desired_config_sha256 = 'a'.repeat(64);
  value.available_actions = ['resume', 'rollback'];
  value.last_transition = { action: 'paused', at: value.paused_at, reason_code: '', node_id: '' };
  const parsed = model.validate(value);
  assert.equal(parsed.phase, 'paused');
  assert.equal(parsed.pausedAt, value.paused_at);
  assert.deepEqual(parsed.availableActions, ['resume', 'rollback']);

  value.nodes[0].converged = true;
  value.converged_canaries = 1;
  assert.throws(() => model.validate(value), /paused lifecycle metadata is inconsistent/);
});

test('validates bounded automatic rollback evidence', () => {
  const value = stable();
  value.config_revision = 9;
  value.config_updated_at = '2026-07-21T19:02:00Z';
  value.last_transition = {
    action: 'auto_rolled_back', at: '2026-07-21T19:02:00Z',
    reason_code: 'canary_config_activation_failed', node_id: 'node_1',
  };
  const parsed = model.validate(value);
  assert.equal(parsed.lastTransition.action, 'auto_rolled_back');
  assert.equal(parsed.lastTransition.reasonCode, 'canary_config_activation_failed');

  value.last_transition.node_id = '';
  assert.throws(() => model.validate(value), /reason requires a node/);

  const stopped = stable();
  stopped.config_revision = 10;
  stopped.config_updated_at = '2026-07-21T19:03:00Z';
  stopped.last_transition = { action: 'auto_rolled_back', at: stopped.config_updated_at, reason_code: 'canary_target_runtime_stopped', node_id: 'node_1' };
  assert.equal(model.validate(stopped).lastTransition.reasonCode, 'canary_target_runtime_stopped');
});

test('rejects unknown fields, forged convergence, and incoherent lifecycle metadata', () => {
  const extra = stable(); extra.extra = true;
  assert.throws(() => model.validate(extra), /extra is not allowed/);

  const forged = canary(); forged.converged_canaries = 1; forged.available_actions = ['promote', 'pause', 'rollback'];
  assert.throws(() => model.validate(forged), /node evidence does not match/);

  const missingRollback = canary(); missingRollback.available_actions = [];
  assert.throws(() => model.validate(missingRollback), /canary lifecycle metadata is inconsistent/);

  const stableTarget = stable(); stableTarget.target_policy_sha256 = 'b'.repeat(64);
  assert.throws(() => model.validate(stableTarget), /stable lifecycle metadata is inconsistent/);

  const duplicateNode = stable(); duplicateNode.active_nodes = 2; duplicateNode.nodes.push(node());
  assert.throws(() => model.validate(duplicateNode), /nodes\[1\] is invalid/);

  const missingGuard = stable(); missingGuard.automatic_rollback_guards = ['activation_failed'];
  assert.throws(() => model.validate(missingGuard), /automatic_rollback_guards is invalid/);
});
