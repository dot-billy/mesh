(function publishMeshRouteProfile(root, factory) {
  const adapter = factory();
  if (typeof module === 'object' && module.exports) module.exports = adapter;
  if (root) root.MeshRouteProfile = adapter;
}(typeof globalThis === 'undefined' ? this : globalThis, function buildMeshRouteProfileAdapter() {
  'use strict';

  const SCHEMA = 'mesh-node-route-profile-edit-v1';
  const PHASES = new Set(['', 'preparing_owner', 'cleaning_owner', 'cleaning_cancelled_owner', 'completed', 'cancelled']);
  const ACTIONS = new Set(['start', 'advance', 'cancel']);

  function fail(message) { throw new Error(`Invalid node route profile document: ${message}`); }
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
  function integer(value, name, minimum = 0) {
    if (!Number.isSafeInteger(value) || value < minimum) fail(`${name} is invalid`);
    return value;
  }
  function timestamp(value, name) {
    if (value === null) return null;
    if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(value) || !Number.isFinite(Date.parse(value))) fail(`${name} is invalid`);
    return value;
  }
  function nodeName(value, name) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/u.test(value)) fail(`${name} is invalid`);
    return value;
  }
  function subnet(value, name) {
    if (typeof value !== 'string' || !/^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/u.test(value)) fail(`${name} is invalid`);
    return value;
  }
  function subnetList(raw, name) {
    if (!Array.isArray(raw) || raw.length > 8) fail(`${name} is invalid`);
    const values = raw.map((value, index) => subnet(value, `${name}[${index}]`));
    if (new Set(values).size !== values.length) fail(`${name} contains duplicates`);
    return values;
  }
  function sameValues(left, right) {
    return left.length === right.length && left.every((value, index) => value === right[index]);
  }
  function difference(left, right) { return left.filter((value) => !right.includes(value)); }
  function ownerStatus(raw) {
    exactObject(raw, ['node_id', 'name', 'certificate_generation', 'applied_certificate_generation', 'applied_config_revision', 'desired_certificate_generation', 'ready'], 'document.owner');
    if (typeof raw.ready !== 'boolean') fail('document.owner.ready is invalid');
    const certificateGeneration = integer(raw.certificate_generation, 'document.owner.certificate_generation');
    const appliedCertificateGeneration = integer(raw.applied_certificate_generation, 'document.owner.applied_certificate_generation');
    const desiredCertificateGeneration = integer(raw.desired_certificate_generation, 'document.owner.desired_certificate_generation');
    if (appliedCertificateGeneration > certificateGeneration || raw.ready && (desiredCertificateGeneration < 1 || certificateGeneration < desiredCertificateGeneration || appliedCertificateGeneration !== certificateGeneration)) fail('document.owner generations are inconsistent');
    return Object.freeze({
      nodeID: resourceID(raw.node_id, 'document.owner.node_id'), name: nodeName(raw.name, 'document.owner.name'),
      certificateGeneration, appliedCertificateGeneration,
      appliedConfigRevision: integer(raw.applied_config_revision, 'document.owner.applied_config_revision'),
      desiredCertificateGeneration, ready: raw.ready,
    });
  }

  function validate(raw) {
    const keys = ['schema', 'network_id', 'node_id', 'request_id', 'phase', 'original_routed_subnets', 'desired_routed_subnets', 'additions', 'removals', 'config_revision', 'started_at', 'promoted_at', 'finished_at', 'owner', 'available_actions'];
    exactObject(raw, keys, 'document');
    if (raw.schema !== SCHEMA || !PHASES.has(raw.phase)) fail('document schema or phase is invalid');
    const networkID = resourceID(raw.network_id, 'document.network_id');
    const nodeID = resourceID(raw.node_id, 'document.node_id');
    const requestID = resourceID(raw.request_id, 'document.request_id', true);
    if (requestID && (requestID.length < 16 || requestID.length > 128)) fail('document.request_id is invalid');
    const originalRoutedSubnets = subnetList(raw.original_routed_subnets, 'document.original_routed_subnets');
    const desiredRoutedSubnets = subnetList(raw.desired_routed_subnets, 'document.desired_routed_subnets');
    const additions = subnetList(raw.additions, 'document.additions');
    const removals = subnetList(raw.removals, 'document.removals');
    if (!sameValues(additions, difference(desiredRoutedSubnets, originalRoutedSubnets)) || !sameValues(removals, difference(originalRoutedSubnets, desiredRoutedSubnets))) fail('document route-set differences are inconsistent');
    const configRevision = integer(raw.config_revision, 'document.config_revision', 1);
    const startedAt = timestamp(raw.started_at, 'document.started_at');
    const promotedAt = timestamp(raw.promoted_at, 'document.promoted_at');
    const finishedAt = timestamp(raw.finished_at, 'document.finished_at');
    const owner = ownerStatus(raw.owner);
    if (owner.nodeID !== nodeID) fail('document.owner does not match document.node_id');
    if (!Array.isArray(raw.available_actions)) fail('document.available_actions is invalid');
    const availableActions = raw.available_actions.map((action, index) => {
      if (!ACTIONS.has(action) || raw.available_actions.indexOf(action) !== index) fail('document.available_actions is invalid');
      return action;
    });
    if (raw.phase === '') {
      if (requestID || additions.length || removals.length || !sameValues(originalRoutedSubnets, desiredRoutedSubnets) || startedAt || promotedAt || finishedAt || owner.desiredCertificateGeneration !== 0 || owner.ready || availableActions.some((action) => action !== 'start')) fail('empty lifecycle metadata is inconsistent');
    } else {
      if (!requestID || additions.length + removals.length < 1 || !startedAt) fail('route-profile lifecycle metadata is incomplete');
      if (['preparing_owner', 'cleaning_owner', 'cleaning_cancelled_owner'].includes(raw.phase) && owner.desiredCertificateGeneration < 1) fail('active lifecycle is missing its desired certificate generation');
      if (raw.phase === 'preparing_owner' && (additions.length < 1 || promotedAt || finishedAt)) fail('prepare lifecycle metadata is inconsistent');
      if (raw.phase === 'cleaning_owner' && (removals.length < 1 || !promotedAt || finishedAt)) fail('owner cleanup metadata is inconsistent');
      if (raw.phase === 'cleaning_cancelled_owner' && (additions.length < 1 || promotedAt || finishedAt)) fail('cancellation cleanup metadata is inconsistent');
      if (raw.phase === 'completed' && (!promotedAt || !finishedAt || owner.desiredCertificateGeneration !== 0 || owner.ready)) fail('completion metadata is inconsistent');
      if (raw.phase === 'cancelled' && (promotedAt || !finishedAt || owner.desiredCertificateGeneration !== 0 || owner.ready)) fail('cancellation metadata is inconsistent');
      if (availableActions.includes('advance') && !owner.ready) fail('advance action is not backed by convergence');
      if (availableActions.includes('advance') && raw.phase !== 'preparing_owner' && raw.phase !== 'cleaning_owner') fail('advance action is not valid in this phase');
      if (availableActions.includes('cancel') && raw.phase !== 'preparing_owner' && !(raw.phase === 'cleaning_cancelled_owner' && owner.ready)) fail('cancel action is not backed by lifecycle state');
      if (availableActions.includes('start') && raw.phase !== 'completed' && raw.phase !== 'cancelled') fail('start action is not terminal');
    }
    return Object.freeze({
      schema: SCHEMA, networkID, nodeID, requestID, phase: raw.phase,
      originalRoutedSubnets: Object.freeze(originalRoutedSubnets), desiredRoutedSubnets: Object.freeze(desiredRoutedSubnets),
      additions: Object.freeze(additions), removals: Object.freeze(removals), configRevision,
      startedAt, promotedAt, finishedAt, owner, availableActions: Object.freeze(availableActions),
    });
  }

  return Object.freeze({ SCHEMA, PHASES, ACTIONS, validate });
}));
