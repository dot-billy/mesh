(function publishMeshRelaySettings(root, factory) {
  const adapter = factory();
  if (typeof module === 'object' && module.exports) module.exports = adapter;
  if (root) root.MeshRelaySettings = adapter;
}(typeof globalThis === 'undefined' ? this : globalThis, function buildMeshRelaySettingsAdapter() {
  'use strict';

  const SCHEMA = 'mesh-network-relays-v1';
  const MAX_RELAY_NODES = 8;

  function fail(message) {
    throw new Error(`Invalid network relay document: ${message}`);
  }

  function exactObject(value, required, name) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${name} must be an object`);
    const allowed = new Set(required);
    for (const key of required) if (!Object.prototype.hasOwnProperty.call(value, key)) fail(`${name}.${key} is required`);
    for (const key of Object.keys(value)) if (!allowed.has(key)) fail(`${name}.${key} is not allowed`);
  }

  function text(value, name, maximum = 128) {
    if (typeof value !== 'string' || value.length === 0 || value.length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) fail(`${name} is invalid`);
    return value;
  }

  function resourceID(value, name) {
    text(value, name);
    if (!/^[A-Za-z0-9_-]+$/u.test(value)) fail(`${name} is invalid`);
    return value;
  }

  function integer(value, name, maximum = Number.MAX_SAFE_INTEGER) {
    if (!Number.isSafeInteger(value) || value < 0 || value > maximum) fail(`${name} is invalid`);
    return value;
  }

  function boolean(value, name) {
    if (typeof value !== 'boolean') fail(`${name} is invalid`);
    return value;
  }

  function ipv4(value, name) {
    text(value, name, 15);
    const match = /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$/u.exec(value);
    if (!match) fail(`${name} is not canonical IPv4`);
    const octets = match.slice(1).map(Number);
    if (octets.some((part) => part > 255)) fail(`${name} is not canonical IPv4`);
    return Object.freeze({ value, numeric: (((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3]) >>> 0 });
  }

  function cidr(value, name) {
    text(value, name, 18);
    const parts = value.split('/');
    if (parts.length !== 2 || !/^(?:1[6-9]|2[0-8])$/u.test(parts[1])) fail(`${name} is not a managed IPv4 CIDR`);
    const address = ipv4(parts[0], name);
    const bits = Number(parts[1]);
    const mask = (0xffffffff << (32 - bits)) >>> 0;
    if ((address.numeric & mask) >>> 0 !== address.numeric) fail(`${name} is not canonical`);
    return Object.freeze({ value, numeric: address.numeric, mask });
  }

  function timestamp(value, name) {
    text(value, name, 64);
    const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/u.exec(value);
    if (!match) fail(`${name} is invalid`);
    const year = Number(match[1]); const month = Number(match[2]); const day = Number(match[3]);
    const hour = Number(match[4]); const minute = Number(match[5]); const second = Number(match[6]);
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    const days = [0, 31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if (month < 1 || month > 12 || day < 1 || day > days[month] || hour > 23 || minute > 59 || second > 59 || !Number.isFinite(Date.parse(value))) fail(`${name} is invalid`);
    return value;
  }

  function compareText(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
  }

  function validate(raw) {
    exactObject(raw, ['schema', 'network_id', 'network_cidr', 'enabled', 'relay_node_ids', 'active_relays', 'max_relay_nodes', 'config_revision', 'config_updated_at'], 'document');
    if (raw.schema !== SCHEMA) fail('document.schema is unsupported');
    const networkID = resourceID(raw.network_id, 'document.network_id');
    const network = cidr(raw.network_cidr, 'document.network_cidr');
    const enabled = boolean(raw.enabled, 'document.enabled');
    if (!Array.isArray(raw.relay_node_ids)) fail('document.relay_node_ids is invalid');
    const relayNodeIDs = raw.relay_node_ids.map((nodeID, index) => resourceID(nodeID, `document.relay_node_ids[${index}]`));
    if ((!enabled && relayNodeIDs.length !== 0) || (enabled && (relayNodeIDs.length < 1 || relayNodeIDs.length > MAX_RELAY_NODES))) fail('document relay selection is inconsistent');
    for (let index = 1; index < relayNodeIDs.length; index += 1) if (compareText(relayNodeIDs[index - 1], relayNodeIDs[index]) >= 0) fail('document.relay_node_ids are not uniquely ordered');
    const selected = new Set(relayNodeIDs);
    if (!Array.isArray(raw.active_relays) || raw.active_relays.length > relayNodeIDs.length) fail('document.active_relays is invalid');
    const activeIDs = new Set(); const activeIPs = new Set();
    const activeRelays = raw.active_relays.map((relay, index) => {
      const name = `document.active_relays[${index}]`;
      exactObject(relay, ['node_id', 'name', 'ip', 'role'], name);
      const nodeID = resourceID(relay.node_id, `${name}.node_id`);
      if (!selected.has(nodeID) || activeIDs.has(nodeID)) fail(`${name}.node_id is not selected or is duplicated`);
      const nodeName = text(relay.name, `${name}.name`, 63);
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/u.test(nodeName)) fail(`${name}.name is invalid`);
      const address = ipv4(relay.ip, `${name}.ip`);
      if ((address.numeric & network.mask) >>> 0 !== network.numeric || activeIPs.has(address.value)) fail(`${name}.ip is outside the network or duplicated`);
      if (relay.role !== 'member' && relay.role !== 'lighthouse') fail(`${name}.role is invalid`);
      activeIDs.add(nodeID); activeIPs.add(address.value);
      return Object.freeze({ nodeID, name: nodeName, ip: address.value, role: relay.role });
    });
    if (!enabled && activeRelays.length !== 0) fail('disabled relays contain active nodes');
    for (let index = 1; index < activeRelays.length; index += 1) {
      const previous = activeRelays[index - 1]; const current = activeRelays[index];
      if (compareText(previous.name, current.name) > 0 || (previous.name === current.name && compareText(previous.nodeID, current.nodeID) >= 0)) fail('document.active_relays are not uniquely and deterministically ordered');
    }
    if (integer(raw.max_relay_nodes, 'document.max_relay_nodes', MAX_RELAY_NODES) !== MAX_RELAY_NODES) fail('document.max_relay_nodes is unsupported');
    const configRevision = integer(raw.config_revision, 'document.config_revision');
    if (configRevision === 0) fail('document.config_revision is invalid');
    return Object.freeze({
      schema: SCHEMA, networkID, networkCIDR: network.value, enabled,
      relayNodeIDs: Object.freeze(relayNodeIDs), activeRelays: Object.freeze(activeRelays),
      maxRelayNodes: MAX_RELAY_NODES, configRevision,
      configUpdatedAt: timestamp(raw.config_updated_at, 'document.config_updated_at'),
    });
  }

  function sameDesired(document, enabled, relayNodeIDs) {
    if (!document || typeof enabled !== 'boolean' || !Array.isArray(relayNodeIDs)) return false;
    if (!enabled && relayNodeIDs.length !== 0) return false;
    const normalized = relayNodeIDs.slice().sort(compareText);
    if (normalized.some((nodeID, index) => !/^[A-Za-z0-9_-]+$/u.test(nodeID) || (index > 0 && nodeID === normalized[index - 1]))) return false;
    return document.enabled === enabled && document.relayNodeIDs.length === normalized.length && document.relayNodeIDs.every((nodeID, index) => nodeID === normalized[index]);
  }

  return Object.freeze({ SCHEMA, MAX_RELAY_NODES, validate, sameDesired });
}));
