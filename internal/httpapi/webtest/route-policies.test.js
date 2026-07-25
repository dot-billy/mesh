'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const model = require('../web/route-policies.js');

function document() {
  return {
    schema: model.SCHEMA, network_id: 'network_1', config_revision: 9, available_actions: ['update'],
    policies: [{
      prefix: '192.168.50.0/24',
      gateways: [
        { node_id: 'node_a', name: 'gateway-a', ip: '10.40.0.2', weight: 3 },
        { node_id: 'node_b', name: 'gateway-b', ip: '10.40.0.3', weight: 1 },
      ],
      mtu: 1300, metric: 20, install: true,
      last_request_id: 'route-policy-0001', policy_revision: 9, updated_at: '2026-07-21T20:00:00Z',
      available_actions: ['update'],
    }],
  };
}

test('validates weighted route policies and derives relative shares', () => {
  const parsed = model.validate(document());
  assert.equal(parsed.policies[0].gateways[0].share, 0.75);
  assert.equal(parsed.policies[0].gateways[1].share, 0.25);
  assert.equal(parsed.policies[0].install, true);
});

test('accepts derived defaults without a direct-update receipt', () => {
  const raw = document();
  Object.assign(raw.policies[0], { mtu: 0, metric: 0, last_request_id: '', policy_revision: 0, updated_at: null });
  const parsed = model.validate(raw);
  assert.equal(parsed.policies[0].lastRequestID, '');
  assert.equal(parsed.policies[0].updatedAt, null);
});

test('rejects unknown fields, forged owners, bounds, and action mismatches', () => {
  const extra = document(); extra.policies[0].extra = true;
  assert.throws(() => model.validate(extra), /extra is not allowed/);
  const duplicate = document(); duplicate.policies[0].gateways[1].node_id = 'node_a';
  assert.throws(() => model.validate(duplicate), /gateways are not canonical/);
  const weight = document(); weight.policies[0].gateways[0].weight = 1001;
  assert.throws(() => model.validate(weight), /weight is invalid/);
  const action = document(); action.policies[0].available_actions = [];
  assert.throws(() => model.validate(action), /available_actions is inconsistent/);
  const receipt = document(); receipt.policies[0].last_request_id = '';
  assert.throws(() => model.validate(receipt), /receipt metadata is inconsistent/);
});
