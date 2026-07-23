(function publishMeshRoutePolicies(root, factory) {
  const adapter = factory();
  if (typeof module === 'object' && module.exports) module.exports = adapter;
  if (root) root.MeshRoutePolicies = adapter;
}(typeof globalThis === 'undefined' ? this : globalThis, function buildMeshRoutePoliciesAdapter() {
  'use strict';

  const SCHEMA = 'mesh-network-route-policies-v1';
  const ACTIONS = new Set(['update']);

  function fail(message) { throw new Error(`Invalid network route policies document: ${message}`); }
  function exactObject(value, keys, name) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${name} must be an object`);
    const allowed = new Set(keys);
    for (const key of keys) if (!Object.prototype.hasOwnProperty.call(value, key)) fail(`${name}.${key} is required`);
    for (const key of Object.keys(value)) if (!allowed.has(key)) fail(`${name}.${key} is not allowed`);
  }
  function resourceID(value, name, empty = false) {
    if (empty && value === '') return '';
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/u.test(value)) fail(`${name} is invalid`);
    return value;
  }
  function integer(value, name, minimum, maximum = Number.MAX_SAFE_INTEGER) {
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail(`${name} is invalid`);
    return value;
  }
  function timestamp(value, name) {
    if (value === null) return null;
    if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(value) || !Number.isFinite(Date.parse(value))) fail(`${name} is invalid`);
    return value;
  }
  function text(value, name, pattern) {
    if (typeof value !== 'string' || !pattern.test(value)) fail(`${name} is invalid`);
    return value;
  }
  function actions(raw, name) {
    if (!Array.isArray(raw)) fail(`${name} is invalid`);
    return Object.freeze(raw.map((action, index) => {
      if (!ACTIONS.has(action) || raw.indexOf(action) !== index) fail(`${name} is invalid`);
      return action;
    }));
  }
  function gateway(raw, name) {
    exactObject(raw, ['node_id', 'name', 'ip', 'weight'], name);
    return Object.freeze({
      nodeID: resourceID(raw.node_id, `${name}.node_id`),
      name: text(raw.name, `${name}.name`, /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/u),
      ip: text(raw.ip, `${name}.ip`, /^\d{1,3}(?:\.\d{1,3}){3}$/u),
      weight: integer(raw.weight, `${name}.weight`, 1, 1000),
    });
  }
  function policy(raw, name, configRevision, documentActions) {
    exactObject(raw, ['prefix', 'gateways', 'mtu', 'metric', 'install', 'last_request_id', 'policy_revision', 'updated_at', 'available_actions'], name);
    if (!Array.isArray(raw.gateways) || raw.gateways.length < 1 || raw.gateways.length > 8) fail(`${name}.gateways is invalid`);
    const gateways = raw.gateways.map((value, index) => gateway(value, `${name}.gateways[${index}]`));
    for (let index = 1; index < gateways.length; index += 1) if (gateways[index - 1].nodeID >= gateways[index].nodeID) fail(`${name}.gateways are not canonical`);
    const mtu = integer(raw.mtu, `${name}.mtu`, 0, 65535);
    if (mtu > 0 && mtu < 500) fail(`${name}.mtu is invalid`);
    const metric = integer(raw.metric, `${name}.metric`, 0, 2147483647);
    if (raw.install !== true) fail(`${name}.install must be true`);
    const lastRequestID = resourceID(raw.last_request_id, `${name}.last_request_id`, true);
    const policyRevision = integer(raw.policy_revision, `${name}.policy_revision`, 0);
    const updatedAt = timestamp(raw.updated_at, `${name}.updated_at`);
    if (lastRequestID ? lastRequestID.length < 16 || lastRequestID.length > 128 || policyRevision < 1 || policyRevision > configRevision || updatedAt === null : policyRevision !== 0 || updatedAt !== null) fail(`${name} receipt metadata is inconsistent`);
    const availableActions = actions(raw.available_actions, `${name}.available_actions`);
    if (availableActions.includes('update') !== documentActions.includes('update')) fail(`${name}.available_actions is inconsistent`);
    const totalWeight = gateways.reduce((sum, value) => sum + value.weight, 0);
    return Object.freeze({
      prefix: text(raw.prefix, `${name}.prefix`, /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/u),
      gateways: Object.freeze(gateways.map((value) => Object.freeze({ ...value, share: value.weight / totalWeight }))),
      mtu, metric, install: true, lastRequestID, policyRevision, updatedAt, availableActions, totalWeight,
    });
  }

  function validate(raw) {
    exactObject(raw, ['schema', 'network_id', 'config_revision', 'policies', 'available_actions'], 'document');
    if (raw.schema !== SCHEMA) fail('document.schema is invalid');
    const networkID = resourceID(raw.network_id, 'document.network_id');
    const configRevision = integer(raw.config_revision, 'document.config_revision', 1);
    const availableActions = actions(raw.available_actions, 'document.available_actions');
    if (!Array.isArray(raw.policies)) fail('document.policies is invalid');
    const policies = raw.policies.map((value, index) => policy(value, `document.policies[${index}]`, configRevision, availableActions));
    if (new Set(policies.map((value) => value.prefix)).size !== policies.length) fail('document.policies contains duplicate prefixes');
    return Object.freeze({ schema: SCHEMA, networkID, configRevision, policies: Object.freeze(policies), availableActions });
  }

  return Object.freeze({ SCHEMA, ACTIONS, validate });
}));
