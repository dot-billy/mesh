'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const model = require('../web/node-revocation.js');

function source(status = 'active') {
  return {
    node: { id: 'node_1', name: 'member-1', ip: '10.80.0.2', role: 'member', status, routed_subnets: ['192.168.80.0/24'] },
    network: { id: 'network_1', config_revision: 9 },
    requestID: 'revoke-00112233445566778899aabbccddeeff',
  };
}

function expectation(status = 'active') {
  const value = source(status);
  return model.expected(value.node, value.network, value.requestID);
}

function receipt(enrolled = true) {
  return {
    request_id: 'revoke-00112233445566778899aabbccddeeff', node_id: 'node_1', network_id: 'network_1',
    name: 'member-1', ip: '10.80.0.2', role: 'member', revoked_at: '2026-07-21T19:00:00.123456789Z',
    was_enrolled: enrolled, enrollment_records_invalidated: 1, agent_recovery_records_invalidated: enrolled ? 1 : 0,
    blocklist_entries_added: enrolled ? 2 : 0, relay_assignment_removed: false, firewall_canary_removed: false,
    firewall_rollout_auto_rolled_back: false, credentials_invalidated: true,
    routed_subnet_reservations_released: 1, config_revision: 10,
  };
}

test('builds and restores a frozen exact binding and accepts its exact receipt', () => {
  const expected = expectation();
  assert.equal(expected.wasEnrolled, true);
  assert.equal(Object.isFrozen(expected), true);
  assert.deepEqual(model.restoreExpected(JSON.parse(JSON.stringify(expected))), expected);
  const parsed = model.validateReceipt(receipt(), expected);
  assert.deepEqual(parsed, receipt());
  assert.equal(Object.isFrozen(parsed), true);
});

test('accepts the exact never-enrolled transition without fabricated blocklist evidence', () => {
  const parsed = model.validateReceipt(receipt(false), expectation('pending'));
  assert.equal(parsed.was_enrolled, false);
  assert.equal(parsed.blocklist_entries_added, 0);
});

test('rejects missing, extra, and mismatched identity evidence', () => {
  const missing = receipt(); delete missing.credentials_invalidated;
  assert.throws(() => model.validateReceipt(missing, expectation()), /credentials_invalidated is required/);
  const extra = receipt(); extra.fingerprint = 'not-allowed';
  assert.throws(() => model.validateReceipt(extra, expectation()), /fingerprint is not allowed/);
  for (const key of ['request_id', 'node_id', 'network_id', 'name', 'ip', 'role']) {
    const forged = receipt(); forged[key] = `${forged[key]}x`;
    assert.throws(() => model.validateReceipt(forged, expectation()), /identity does not match/);
  }
});

test('rejects impossible time, enrollment, credential, blocklist, route, and revision claims', () => {
  const cases = [
    ['revoked_at', '2026-02-30T19:00:00Z'], ['was_enrolled', false], ['enrollment_records_invalidated', -1],
    ['agent_recovery_records_invalidated', 1.5], ['blocklist_entries_added', 0], ['credentials_invalidated', false],
    ['routed_subnet_reservations_released', 0], ['config_revision', 11],
  ];
  for (const [key, value] of cases) {
    const forged = receipt(); forged[key] = value;
    assert.throws(() => model.validateReceipt(forged, expectation()), /invalid|inconsistent/);
  }
  const rollback = receipt(); rollback.firewall_rollout_auto_rolled_back = true;
  assert.throws(() => model.validateReceipt(rollback, expectation()), /rollback evidence is inconsistent/);
});

test('generates a canonical 128-bit request identity', () => {
  const requestID = model.newRequestID({ getRandomValues(bytes) {
    bytes.forEach((_, index) => { bytes[index] = 15 - index; });
    return bytes;
  } });
  assert.equal(requestID, 'revoke-0f0e0d0c0b0a09080706050403020100');
  assert.throws(() => model.newRequestID(undefined), /secure request identity generation is unavailable/);
});

test('rejects malformed authoritative and persisted request bindings', () => {
  const cases = [
    (value) => { value.node.status = 'revoked'; },
    (value) => { value.node.id = '../node'; },
    (value) => { value.node.name = ' member'; },
    (value) => { value.node.ip = '10.080.0.2'; },
    (value) => { value.node.role = 'relay'; },
    (value) => { value.node.routed_subnets = null; },
    (value) => { value.network.config_revision = 0; },
    (value) => { value.requestID = 'short'; },
  ];
  for (const mutate of cases) {
    const value = source(); mutate(value);
    assert.throws(() => model.expected(value.node, value.network, value.requestID));
  }
  const expected = expectation();
  assert.throws(() => model.restoreExpected({ ...expected, extra: true }), /extra is not allowed/);
  assert.throws(() => model.restoreExpected({ ...expected, wasEnrolled: 'yes' }), /wasEnrolled is invalid/);
});
