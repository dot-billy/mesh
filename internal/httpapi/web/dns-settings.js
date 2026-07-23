(function publishMeshDNSSettings(root, factory) {
  const adapter = factory();
  if (typeof module === 'object' && module.exports) module.exports = adapter;
  if (root) root.MeshDNSSettings = adapter;
}(typeof globalThis === 'undefined' ? this : globalThis, function buildMeshDNSSettingsAdapter() {
  'use strict';

  const SCHEMA = 'mesh-network-dns-v1';

  function fail(message) {
    throw new Error(`Invalid network DNS document: ${message}`);
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
    const numeric = (((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3]) >>> 0;
    return Object.freeze({ value, numeric });
  }

  function cidr(value, name) {
    text(value, name, 18);
    const parts = value.split('/');
    if (parts.length !== 2 || !/^(?:1[6-9]|2[0-8])$/u.test(parts[1])) fail(`${name} is not a managed IPv4 CIDR`);
    const address = ipv4(parts[0], name);
    const bits = Number(parts[1]);
    const mask = (0xffffffff << (32 - bits)) >>> 0;
    if ((address.numeric & mask) >>> 0 !== address.numeric) fail(`${name} is not canonical`);
    return Object.freeze({ value, numeric: address.numeric, bits, mask });
  }

  function timestamp(value, name) {
    text(value, name, 64);
    const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/u.exec(value);
    if (!match) fail(`${name} is invalid`);
    const year = Number(match[1]);
    const month = Number(match[2]);
    const day = Number(match[3]);
    const hour = Number(match[4]);
    const minute = Number(match[5]);
    const second = Number(match[6]);
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    const days = [0, 31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if (month < 1 || month > 12 || day < 1 || day > days[month] || hour > 23 || minute > 59 || second > 59 || !Number.isFinite(Date.parse(value))) fail(`${name} is invalid`);
    return value;
  }

  function compareText(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
  }

  function domain(value, name) {
	text(value, name, 253);
	if (value !== value.toLowerCase() || value.endsWith('.')) fail(`${name} is not canonical`);
	const labels = value.split('.');
	if (labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))) fail(`${name} is invalid`);
	if (value === 'local' || value.endsWith('.local')) fail(`${name} cannot use multicast DNS .local`);
	return value;
  }

  function validate(raw) {
    exactObject(raw, ['schema', 'network_id', 'network_cidr', 'enabled', 'listen_port', 'native_resolver', 'search_domain', 'firewall_ready', 'resolvers', 'config_revision', 'config_updated_at'], 'document');
    if (raw.schema !== SCHEMA) fail('document.schema is unsupported');
    const networkID = text(raw.network_id, 'document.network_id');
    if (!/^[A-Za-z0-9_-]+$/u.test(networkID)) fail('document.network_id is invalid');
    const network = cidr(raw.network_cidr, 'document.network_cidr');
    const enabled = boolean(raw.enabled, 'document.enabled');
    const listenPort = integer(raw.listen_port, 'document.listen_port', 65535);
    if (listenPort === 0 || (!enabled && listenPort !== 53)) fail('document listener state is inconsistent');
	const nativeResolver = boolean(raw.native_resolver, 'document.native_resolver');
	if (nativeResolver && !enabled) fail('native resolver requires enabled DNS');
	if (typeof raw.search_domain !== 'string') fail('document.search_domain is invalid');
	const searchDomain = nativeResolver ? domain(raw.search_domain, 'document.search_domain') : raw.search_domain;
	if (!nativeResolver && searchDomain !== '') fail('disabled native resolver contains a search domain');
    const firewallReady = boolean(raw.firewall_ready, 'document.firewall_ready');
    if (enabled && !firewallReady) fail('enabled DNS is not firewall-ready');
    if (!Array.isArray(raw.resolvers) || raw.resolvers.length > 64) fail('document.resolvers is invalid');
    if (!enabled && raw.resolvers.length !== 0) fail('disabled DNS contains resolvers');
    const nodeIDs = new Set();
    const ips = new Set();
    const resolvers = raw.resolvers.map((resolver, index) => {
      const name = `document.resolvers[${index}]`;
      exactObject(resolver, ['node_id', 'name', 'ip'], name);
      const nodeID = text(resolver.node_id, `${name}.node_id`);
      if (!/^[A-Za-z0-9_-]+$/u.test(nodeID) || nodeIDs.has(nodeID)) fail(`${name}.node_id is invalid or duplicated`);
      const nodeName = text(resolver.name, `${name}.name`, 63);
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/u.test(nodeName)) fail(`${name}.name is invalid`);
      const address = ipv4(resolver.ip, `${name}.ip`);
      if ((address.numeric & network.mask) >>> 0 !== network.numeric || ips.has(address.value)) fail(`${name}.ip is outside the network or duplicated`);
      nodeIDs.add(nodeID);
      ips.add(address.value);
      return Object.freeze({ nodeID, name: nodeName, ip: address.value });
    });
    for (let index = 1; index < resolvers.length; index += 1) {
      const previous = resolvers[index - 1];
      const current = resolvers[index];
      if (compareText(previous.name, current.name) > 0 || (previous.name === current.name && compareText(previous.nodeID, current.nodeID) >= 0)) fail('document.resolvers are not uniquely and deterministically ordered');
    }
    const configRevision = integer(raw.config_revision, 'document.config_revision');
    if (configRevision === 0) fail('document.config_revision is invalid');
    return Object.freeze({
      schema: SCHEMA,
      networkID,
      networkCIDR: network.value,
      enabled,
      listenPort,
	  nativeResolver,
	  searchDomain,
      firewallReady,
      resolvers: Object.freeze(resolvers),
      configRevision,
      configUpdatedAt: timestamp(raw.config_updated_at, 'document.config_updated_at'),
    });
  }

  function sameDesired(document, enabled, listenPort, nativeResolver = false, searchDomain = '') {
    if (!document || typeof enabled !== 'boolean' || !Number.isSafeInteger(listenPort) || typeof nativeResolver !== 'boolean' || typeof searchDomain !== 'string') return false;
    return document.enabled === enabled && document.listenPort === listenPort && document.nativeResolver === nativeResolver && document.searchDomain === searchDomain;
  }

  return Object.freeze({ SCHEMA, validate, sameDesired });
}));
