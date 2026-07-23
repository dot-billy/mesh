(function publishMeshRouteTransfer(root, factory) {
  const adapter = factory();
  if (typeof module === 'object' && module.exports) module.exports = adapter;
  if (root) root.MeshRouteTransfer = adapter;
}(typeof globalThis === 'undefined' ? this : globalThis, function buildMeshRouteTransferAdapter() {
  'use strict';

  const SCHEMA = 'mesh-network-route-transfer-v1';
  const PHASES = new Set(['', 'preparing_target', 'cleaning_source', 'cleaning_target', 'completed', 'cancelled']);
  const ACTIONS = new Set(['start', 'advance', 'cancel']);

  function fail(message) { throw new Error(`Invalid network route transfer document: ${message}`); }
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
  function nodeStatus(raw, name) {
    if (raw === null) return null;
    exactObject(raw, ['node_id', 'name', 'certificate_generation', 'applied_certificate_generation', 'applied_config_revision', 'desired_certificate_generation', 'ready'], name);
    if (typeof raw.ready !== 'boolean') fail(`${name}.ready is invalid`);
    const certificateGeneration = integer(raw.certificate_generation, `${name}.certificate_generation`, 1);
    const appliedCertificateGeneration = integer(raw.applied_certificate_generation, `${name}.applied_certificate_generation`);
    const desiredCertificateGeneration = integer(raw.desired_certificate_generation, `${name}.desired_certificate_generation`);
    if (appliedCertificateGeneration > certificateGeneration || raw.ready && (desiredCertificateGeneration < 1 || certificateGeneration < desiredCertificateGeneration || appliedCertificateGeneration !== certificateGeneration)) fail(`${name} generations are inconsistent`);
    return Object.freeze({
      nodeID: resourceID(raw.node_id, `${name}.node_id`), name: nodeName(raw.name, `${name}.name`),
      certificateGeneration, appliedCertificateGeneration,
      appliedConfigRevision: integer(raw.applied_config_revision, `${name}.applied_config_revision`),
      desiredCertificateGeneration, ready: raw.ready,
    });
  }

  function validate(raw) {
    const keys = ['schema', 'network_id', 'request_id', 'phase', 'routed_subnets', 'config_revision', 'started_at', 'promoted_at', 'finished_at', 'source', 'target', 'available_actions'];
    exactObject(raw, keys, 'document');
    if (raw.schema !== SCHEMA || !PHASES.has(raw.phase)) fail('document schema or phase is invalid');
    const networkID = resourceID(raw.network_id, 'document.network_id');
    const requestID = resourceID(raw.request_id, 'document.request_id', true);
    if (requestID && (requestID.length < 16 || requestID.length > 128)) fail('document.request_id is invalid');
    const configRevision = integer(raw.config_revision, 'document.config_revision', 1);
    if (!Array.isArray(raw.routed_subnets)) fail('document.routed_subnets is invalid');
    const routedSubnets = raw.routed_subnets.map((value, index) => subnet(value, `document.routed_subnets[${index}]`));
    if (new Set(routedSubnets).size !== routedSubnets.length) fail('document.routed_subnets contains duplicates');
    if (!Array.isArray(raw.available_actions)) fail('document.available_actions is invalid');
    const availableActions = raw.available_actions.map((action, index) => {
      if (!ACTIONS.has(action) || raw.available_actions.indexOf(action) !== index) fail('document.available_actions is invalid');
      return action;
    });
    const startedAt = timestamp(raw.started_at, 'document.started_at');
    const promotedAt = timestamp(raw.promoted_at, 'document.promoted_at');
    const finishedAt = timestamp(raw.finished_at, 'document.finished_at');
    const source = nodeStatus(raw.source, 'document.source');
    const target = nodeStatus(raw.target, 'document.target');
    if (raw.phase === '') {
      if (requestID || routedSubnets.length || startedAt || promotedAt || finishedAt || source || target || availableActions.some((action) => action !== 'start')) fail('empty lifecycle metadata is inconsistent');
    } else {
      if (!requestID || routedSubnets.length < 1 || !startedAt) fail('transfer lifecycle metadata is incomplete');
      if (['preparing_target', 'cleaning_source', 'cleaning_target'].includes(raw.phase) && (!source || !target)) fail('active transfer participants are missing');
      if (raw.phase === 'preparing_target' && (promotedAt || finishedAt || source.desiredCertificateGeneration !== 0)) fail('prepare lifecycle metadata is inconsistent');
      if (raw.phase === 'cleaning_source' && (!promotedAt || finishedAt || source.desiredCertificateGeneration < 1)) fail('source cleanup metadata is inconsistent');
      if (raw.phase === 'cleaning_target' && (promotedAt || finishedAt || target.desiredCertificateGeneration < 1)) fail('target cleanup metadata is inconsistent');
      if (raw.phase === 'completed' && (!promotedAt || !finishedAt)) fail('completion metadata is inconsistent');
      if (raw.phase === 'cancelled' && (promotedAt || !finishedAt)) fail('cancellation metadata is inconsistent');
      if (availableActions.includes('advance') && !((raw.phase === 'preparing_target' && target.ready) || (raw.phase === 'cleaning_source' && source.ready))) fail('advance action is not backed by convergence');
      if (availableActions.includes('cancel') && raw.phase !== 'preparing_target' && !(raw.phase === 'cleaning_target' && target.ready)) fail('cancel action is not backed by lifecycle state');
      if (availableActions.includes('start') && raw.phase !== 'completed' && raw.phase !== 'cancelled') fail('start action is not terminal');
    }
    return Object.freeze({
      schema: SCHEMA, networkID, requestID, phase: raw.phase, routedSubnets: Object.freeze(routedSubnets),
      configRevision, startedAt, promotedAt, finishedAt, source, target, availableActions: Object.freeze(availableActions),
    });
  }

  return Object.freeze({ SCHEMA, PHASES, ACTIONS, validate });
}));
