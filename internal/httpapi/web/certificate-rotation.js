(function publishMeshCertificateRotation(root, factory) {
  const adapter = factory();
  if (typeof module === 'object' && module.exports) module.exports = adapter;
  if (root) root.MeshCertificateRotation = adapter;
}(typeof globalThis === 'undefined' ? this : globalThis, function buildMeshCertificateRotationAdapter() {
  'use strict';

  const receiptKeys = Object.freeze([
    'request_id', 'node_id', 'network_id', 'name', 'ip', 'role', 'rotated_at',
    'previous_certificate_expires_at', 'certificate_expires_at', 'certificate_renew_after',
    'previous_certificate_generation', 'certificate_generation',
    'agent_recovery_records_invalidated', 'certificate_issuances_added',
    'blocklist_entries_added', 'previous_certificate_blocklisted', 'config_revision',
  ]);
  const expectedKeys = Object.freeze([
    'requestID', 'nodeID', 'networkID', 'name', 'ip', 'role',
    'previousCertificateExpiresAt', 'previousCertificateExpiresAtMS',
    'previousCertificateGeneration', 'expectedConfigRevision',
  ]);

  function fail(message) {
    throw new Error(`Invalid certificate rotation evidence: ${message}`);
  }

  function record(value, name) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${name} must be an object`);
    return value;
  }

  function exactObject(value, keys, name) {
    record(value, name);
    const allowed = new Set(keys);
    for (const key of keys) if (!Object.prototype.hasOwnProperty.call(value, key)) fail(`${name}.${key} is required`);
    for (const key of Object.keys(value)) if (!allowed.has(key)) fail(`${name}.${key} is not allowed`);
    return value;
  }

  function resourceID(value, name, minimum = 1) {
    if (typeof value !== 'string' || value.length < minimum || value.length > 128 || !/^[A-Za-z0-9_-]+$/u.test(value)) fail(`${name} is invalid`);
    return value;
  }

  function nodeName(value, name) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/u.test(value)) fail(`${name} is invalid`);
    return value;
  }

  function integer(value, name, minimum = 0) {
    if (!Number.isSafeInteger(value) || value < minimum) fail(`${name} is invalid`);
    return value;
  }

  function ipv4(value, name) {
    if (typeof value !== 'string' || !/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/u.test(value)) fail(`${name} is invalid`);
    if (value.split('.').some((part) => Number(part) > 255)) fail(`${name} is invalid`);
    return value;
  }

  function timestamp(value, name) {
    if (typeof value !== 'string' || value.length > 64) fail(`${name} is invalid`);
    const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/u.exec(value);
    if (!match) fail(`${name} is invalid`);
    const year = Number(match[1]);
    const month = Number(match[2]);
    const day = Number(match[3]);
    const hour = Number(match[4]);
    const minute = Number(match[5]);
    const second = Number(match[6]);
    const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    const daysInMonth = [0, 31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if (year < 1 || month < 1 || month > 12 || day < 1 || day > daysInMonth[month] || hour > 23 || minute > 59 || second > 59) fail(`${name} is invalid`);
    const milliseconds = Date.parse(value);
    if (!Number.isFinite(milliseconds)) fail(`${name} is invalid`);
    return Object.freeze({ value, milliseconds });
  }

  function restoreExpected(raw) {
    exactObject(raw, expectedKeys, 'expected');
    const role = raw.role;
    if (role !== 'member' && role !== 'lighthouse') fail('expected.role is invalid');
    const previousExpiry = timestamp(raw.previousCertificateExpiresAt, 'expected.previousCertificateExpiresAt');
    if (raw.previousCertificateExpiresAtMS !== previousExpiry.milliseconds) fail('expected.previousCertificateExpiresAtMS is inconsistent');
    return Object.freeze({
      requestID: resourceID(raw.requestID, 'expected.requestID', 16),
      nodeID: resourceID(raw.nodeID, 'expected.nodeID'),
      networkID: resourceID(raw.networkID, 'expected.networkID'),
      name: nodeName(raw.name, 'expected.name'),
      ip: ipv4(raw.ip, 'expected.ip'),
      role,
      previousCertificateExpiresAt: previousExpiry.value,
      previousCertificateExpiresAtMS: previousExpiry.milliseconds,
      previousCertificateGeneration: integer(raw.previousCertificateGeneration, 'expected.previousCertificateGeneration', 1),
      expectedConfigRevision: integer(raw.expectedConfigRevision, 'expected.expectedConfigRevision', 1),
    });
  }

  function expected(node, network, requestID) {
    record(node, 'node');
    record(network, 'network');
    if (node.status !== 'active') fail('node.status must be active');
    const previousExpiry = timestamp(node.certificate_expires_at, 'node.certificate_expires_at');
    return restoreExpected({
      requestID,
      nodeID: node.id,
      networkID: network.id,
      name: node.name,
      ip: node.ip,
      role: node.role,
      previousCertificateExpiresAt: previousExpiry.value,
      previousCertificateExpiresAtMS: previousExpiry.milliseconds,
      previousCertificateGeneration: node.certificate_generation,
      expectedConfigRevision: network.config_revision,
    });
  }

  function newRequestID(cryptoSource) {
    if (cryptoSource === null || typeof cryptoSource !== 'object' || typeof cryptoSource.getRandomValues !== 'function') fail('secure request identity generation is unavailable');
    const bytes = new Uint8Array(16);
    cryptoSource.getRandomValues(bytes);
    return `certrotate-${[...bytes].map((value) => value.toString(16).padStart(2, '0')).join('')}`;
  }

  function validateReceipt(raw, expectation) {
    exactObject(raw, receiptKeys, 'receipt');
    record(expectation, 'expected');
    if (raw.request_id !== expectation.requestID || raw.node_id !== expectation.nodeID || raw.network_id !== expectation.networkID || raw.name !== expectation.name || raw.ip !== expectation.ip || raw.role !== expectation.role) fail('receipt identity does not match the selected node and request');

    const rotatedAt = timestamp(raw.rotated_at, 'receipt.rotated_at');
    const previousExpiry = timestamp(raw.previous_certificate_expires_at, 'receipt.previous_certificate_expires_at');
    const expiresAt = timestamp(raw.certificate_expires_at, 'receipt.certificate_expires_at');
    const renewAfter = timestamp(raw.certificate_renew_after, 'receipt.certificate_renew_after');
    if (previousExpiry.value !== expectation.previousCertificateExpiresAt || previousExpiry.milliseconds !== expectation.previousCertificateExpiresAtMS || expiresAt.milliseconds <= rotatedAt.milliseconds || renewAfter.milliseconds <= rotatedAt.milliseconds || renewAfter.milliseconds >= expiresAt.milliseconds) fail('receipt lifecycle timestamps are inconsistent');

    if (integer(raw.previous_certificate_generation, 'receipt.previous_certificate_generation', 1) !== expectation.previousCertificateGeneration || integer(raw.certificate_generation, 'receipt.certificate_generation', 1) !== expectation.previousCertificateGeneration + 1 || integer(raw.config_revision, 'receipt.config_revision', 1) !== expectation.expectedConfigRevision + 1) fail('receipt generation or revision transition is inconsistent');
    integer(raw.agent_recovery_records_invalidated, 'receipt.agent_recovery_records_invalidated');
    if (raw.certificate_issuances_added !== 1 || raw.blocklist_entries_added !== 1 || raw.previous_certificate_blocklisted !== true) fail('receipt replacement or blocklist evidence is inconsistent');

    return Object.freeze({ ...raw });
  }

  return Object.freeze({ expected, newRequestID, restoreExpected, validateReceipt });
}));
