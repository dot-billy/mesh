(function publishMeshNodeRevocation(root, factory) {
  const adapter = factory();
  if (typeof module === 'object' && module.exports) module.exports = adapter;
  if (root) root.MeshNodeRevocation = adapter;
}(typeof globalThis === 'undefined' ? this : globalThis, function buildMeshNodeRevocationAdapter() {
  'use strict';

  const expectedKeys = Object.freeze([
    'requestID', 'nodeID', 'networkID', 'name', 'ip', 'role', 'wasEnrolled',
    'routedSubnetReservationsReleased', 'expectedConfigRevision',
  ]);
  const receiptKeys = Object.freeze([
    'request_id', 'node_id', 'network_id', 'name', 'ip', 'role', 'revoked_at', 'was_enrolled',
    'enrollment_records_invalidated', 'agent_recovery_records_invalidated', 'blocklist_entries_added',
    'relay_assignment_removed', 'firewall_canary_removed', 'firewall_rollout_auto_rolled_back',
    'credentials_invalidated', 'routed_subnet_reservations_released', 'config_revision',
  ]);

  function fail(message) { throw new Error(`Invalid node revocation evidence: ${message}`); }
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
  function boolean(value, name) {
    if (typeof value !== 'boolean') fail(`${name} is invalid`);
    return value;
  }
  function ipv4(value, name) {
    if (typeof value !== 'string' || !/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/u.test(value) || value.split('.').some((part) => Number(part) > 255)) fail(`${name} is invalid`);
    return value;
  }
  function timestamp(value, name) {
    if (typeof value !== 'string' || value.length > 64) fail(`${name} is invalid`);
    const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/u.exec(value);
    if (!match) fail(`${name} is invalid`);
    const year = Number(match[1]); const month = Number(match[2]); const day = Number(match[3]);
    const hour = Number(match[4]); const minute = Number(match[5]); const second = Number(match[6]);
    const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    const daysInMonth = [0, 31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if (year < 1 || month < 1 || month > 12 || day < 1 || day > daysInMonth[month] || hour > 23 || minute > 59 || second > 59 || !Number.isFinite(Date.parse(value))) fail(`${name} is invalid`);
    return value;
  }

  function restoreExpected(raw) {
    exactObject(raw, expectedKeys, 'expected');
    if (raw.role !== 'member' && raw.role !== 'lighthouse') fail('expected.role is invalid');
    return Object.freeze({
      requestID: resourceID(raw.requestID, 'expected.requestID', 16),
      nodeID: resourceID(raw.nodeID, 'expected.nodeID'), networkID: resourceID(raw.networkID, 'expected.networkID'),
      name: nodeName(raw.name, 'expected.name'), ip: ipv4(raw.ip, 'expected.ip'), role: raw.role,
      wasEnrolled: boolean(raw.wasEnrolled, 'expected.wasEnrolled'),
      routedSubnetReservationsReleased: integer(raw.routedSubnetReservationsReleased, 'expected.routedSubnetReservationsReleased'),
      expectedConfigRevision: integer(raw.expectedConfigRevision, 'expected.expectedConfigRevision', 1),
    });
  }

  function expected(node, network, requestID) {
    record(node, 'node'); record(network, 'network');
    if (node.status !== 'active' && node.status !== 'pending') fail('node.status is invalid');
    if (!Array.isArray(node.routed_subnets)) fail('node routed subnets are inconsistent');
    return restoreExpected({
      requestID, nodeID: node.id, networkID: network.id, name: node.name, ip: node.ip, role: node.role,
      wasEnrolled: node.status === 'active', routedSubnetReservationsReleased: node.routed_subnets.length,
      expectedConfigRevision: network.config_revision,
    });
  }

  function newRequestID(cryptoSource) {
    if (cryptoSource === null || typeof cryptoSource !== 'object' || typeof cryptoSource.getRandomValues !== 'function') fail('secure request identity generation is unavailable');
    const bytes = new Uint8Array(16); cryptoSource.getRandomValues(bytes);
    return `revoke-${[...bytes].map((value) => value.toString(16).padStart(2, '0')).join('')}`;
  }

  function validateReceipt(raw, expectation) {
    exactObject(raw, receiptKeys, 'receipt'); record(expectation, 'expected');
    if (raw.request_id !== expectation.requestID || raw.node_id !== expectation.nodeID || raw.network_id !== expectation.networkID || raw.name !== expectation.name || raw.ip !== expectation.ip || raw.role !== expectation.role) fail('receipt identity does not match the selected node and request');
    timestamp(raw.revoked_at, 'receipt.revoked_at');
    if (raw.was_enrolled !== expectation.wasEnrolled) fail('receipt enrollment state is inconsistent');
    integer(raw.enrollment_records_invalidated, 'receipt.enrollment_records_invalidated');
    integer(raw.agent_recovery_records_invalidated, 'receipt.agent_recovery_records_invalidated');
    const blocklistEntries = integer(raw.blocklist_entries_added, 'receipt.blocklist_entries_added');
    if (expectation.wasEnrolled ? blocklistEntries < 1 : blocklistEntries !== 0) fail('receipt blocklist evidence is inconsistent');
    for (const key of ['relay_assignment_removed', 'firewall_canary_removed', 'firewall_rollout_auto_rolled_back', 'credentials_invalidated']) boolean(raw[key], `receipt.${key}`);
    if (raw.firewall_rollout_auto_rolled_back && !raw.firewall_canary_removed) fail('receipt firewall rollback evidence is inconsistent');
    if (raw.credentials_invalidated !== true || raw.routed_subnet_reservations_released !== expectation.routedSubnetReservationsReleased || raw.config_revision !== expectation.expectedConfigRevision + 1) fail('receipt trust cutoff or revision transition is inconsistent');
    return Object.freeze({ ...raw });
  }

  return Object.freeze({ expected, newRequestID, restoreExpected, validateReceipt });
}));
