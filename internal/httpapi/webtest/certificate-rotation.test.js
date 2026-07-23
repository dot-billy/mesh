'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const model = require('../web/certificate-rotation.js');

function source() {
  return {
    node: {
      id: 'node_1', network_id: 'network_1', name: 'member-1', ip: '10.80.0.2', role: 'member', status: 'active',
      certificate_expires_at: '2026-07-22T18:00:00.123456789Z', certificate_generation: 4,
    },
    network: { id: 'network_1', config_revision: 9 },
    requestID: 'certrotate-00112233445566778899aabbccddeeff',
  };
}

function receipt() {
  return {
    request_id: 'certrotate-00112233445566778899aabbccddeeff', node_id: 'node_1', network_id: 'network_1',
    name: 'member-1', ip: '10.80.0.2', role: 'member', rotated_at: '2026-07-21T18:00:00.987654321Z',
    previous_certificate_expires_at: '2026-07-22T18:00:00.123456789Z', certificate_expires_at: '2026-07-22T18:00:01Z',
    certificate_renew_after: '2026-07-22T10:00:01Z', previous_certificate_generation: 4, certificate_generation: 5,
    agent_recovery_records_invalidated: 1, certificate_issuances_added: 1, blocklist_entries_added: 1,
    previous_certificate_blocklisted: true, config_revision: 10,
  };
}

function expectation() {
  const value = source();
  return model.expected(value.node, value.network, value.requestID);
}

test('builds frozen exact expectations and accepts only a matching frozen receipt', () => {
  const expected = expectation();
  assert.equal(expected.previousCertificateExpiresAt, '2026-07-22T18:00:00.123456789Z');
  assert.equal(expected.previousCertificateGeneration, 4);
  assert.equal(Object.isFrozen(expected), true);
  assert.deepEqual(model.restoreExpected(JSON.parse(JSON.stringify(expected))), expected);
  const parsed = model.validateReceipt(receipt(), expected);
  assert.deepEqual(parsed, receipt());
  assert.equal(Object.isFrozen(parsed), true);
});

test('restores only an exact internally consistent persisted replay binding', () => {
  const expected = expectation();
  const extra = { ...expected, extra: true };
  assert.throws(() => model.restoreExpected(extra), /extra is not allowed/);
  const wrongExpiry = { ...expected, previousCertificateExpiresAtMS: expected.previousCertificateExpiresAtMS + 1 };
  assert.throws(() => model.restoreExpected(wrongExpiry), /is inconsistent/);
  const invalidID = { ...expected, requestID: '../stolen-request' };
  assert.throws(() => model.restoreExpected(invalidID), /requestID is invalid/);
  assert.equal(Object.isFrozen(model.restoreExpected({ ...expected })), true);
});

test('rejects missing, extra, and mismatched receipt identity evidence', () => {
  const missing = receipt(); delete missing.blocklist_entries_added;
  assert.throws(() => model.validateReceipt(missing, expectation()), /blocklist_entries_added is required/);
  const extra = receipt(); extra.fingerprint = 'secret-ish';
  assert.throws(() => model.validateReceipt(extra, expectation()), /fingerprint is not allowed/);
  for (const key of ['request_id', 'node_id', 'network_id', 'name', 'ip', 'role']) {
    const forged = receipt(); forged[key] = `${forged[key]}x`;
    assert.throws(() => model.validateReceipt(forged, expectation()), /identity does not match/);
  }
});

test('rejects non-canonical or impossible lifecycle times and invalid ordering', () => {
  for (const value of ['2026-02-30T18:00:00Z', '2026-07-21T25:00:00Z', '2026-07-21T18:00:00+00:00', '2026-7-21T18:00:00Z']) {
    const forged = receipt(); forged.rotated_at = value;
    assert.throws(() => model.validateReceipt(forged, expectation()), /rotated_at is invalid/);
  }
  const wrongPrevious = receipt(); wrongPrevious.previous_certificate_expires_at = '2026-07-22T18:00:00.123Z';
  assert.throws(() => model.validateReceipt(wrongPrevious, expectation()), /timestamps are inconsistent/);
  const earlyExpiry = receipt(); earlyExpiry.certificate_expires_at = earlyExpiry.rotated_at;
  assert.throws(() => model.validateReceipt(earlyExpiry, expectation()), /timestamps are inconsistent/);
  const lateRenewal = receipt(); lateRenewal.certificate_renew_after = lateRenewal.certificate_expires_at;
  assert.throws(() => model.validateReceipt(lateRenewal, expectation()), /timestamps are inconsistent/);
});

test('rejects forged transition counts, generations, revisions, and blocklist evidence', () => {
  for (const [key, value] of [
    ['previous_certificate_generation', 3], ['certificate_generation', 6], ['config_revision', 11],
    ['agent_recovery_records_invalidated', -1], ['certificate_issuances_added', 2],
    ['blocklist_entries_added', 0], ['previous_certificate_blocklisted', false],
  ]) {
    const forged = receipt(); forged[key] = value;
    assert.throws(() => model.validateReceipt(forged, expectation()), /inconsistent|invalid/);
  }
});

test('generates a canonical 128-bit request identity from the supplied secure source', () => {
  let calls = 0;
  const requestID = model.newRequestID({ getRandomValues(bytes) {
    calls += 1;
    assert.equal(bytes.length, 16);
    bytes.forEach((_, index) => { bytes[index] = index; });
    return bytes;
  } });
  assert.equal(requestID, 'certrotate-000102030405060708090a0b0c0d0e0f');
  assert.equal(calls, 1);
  assert.throws(() => model.newRequestID(null), /secure request identity generation is unavailable/);
});

test('rejects unavailable or incoherent authoritative source metadata', () => {
  const cases = [
    ['node status', (value) => { value.node.status = 'pending'; }],
    ['node id', (value) => { value.node.id = '../node'; }],
    ['request id', (value) => { value.requestID = 'short'; }],
    ['node name', (value) => { value.node.name = ' member'; }],
    ['node IP', (value) => { value.node.ip = '10.080.0.2'; }],
    ['role', (value) => { value.node.role = 'relay'; }],
    ['expiry', (value) => { value.node.certificate_expires_at = '2026-02-30T00:00:00Z'; }],
    ['generation', (value) => { value.node.certificate_generation = 0; }],
    ['revision', (value) => { value.network.config_revision = 0; }],
  ];
  for (const [name, mutate] of cases) {
    const value = source(); mutate(value);
    assert.throws(() => model.expected(value.node, value.network, value.requestID), undefined, name);
  }
});
