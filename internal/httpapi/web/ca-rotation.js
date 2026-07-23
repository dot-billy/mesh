(function publishMeshCARotation(root, factory) {
  const adapter = factory();
  if (typeof module === 'object' && module.exports) module.exports = adapter;
  if (root) root.MeshCARotation = adapter;
}(typeof globalThis === 'undefined' ? this : globalThis, function buildMeshCARotationAdapter() {
  'use strict';

  const SCHEMA = 'mesh-network-ca-rotation-v1';
  const PHASES = new Set(['stable', 'prepared', 'rotating', 'finalizing', 'aborting']);
  const ACTIONS = new Set(['prepare', 'activate', 'finalize', 'abort', 'complete']);

  function fail(message) { throw new Error(`Invalid network CA rotation document: ${message}`); }
  function exactObject(value, required, name) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${name} must be an object`);
    const allowed = new Set(required);
    for (const key of required) if (!Object.prototype.hasOwnProperty.call(value, key)) fail(`${name}.${key} is required`);
    for (const key of Object.keys(value)) if (!allowed.has(key)) fail(`${name}.${key} is not allowed`);
  }
  function integer(value, name) {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${name} is invalid`);
    return value;
  }
  function resourceID(value, name) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/u.test(value) || value.length > 128) fail(`${name} is invalid`);
    return value;
  }
  function digest(value, name, empty = false) {
    if (empty && value === '') return '';
    if (typeof value !== 'string' || !/^[0-9a-f]{64}$/u.test(value)) fail(`${name} is invalid`);
    return value;
  }
  function timestamp(value, name, nullable = false) {
    if (nullable && value === null) return null;
    if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(value) || !Number.isFinite(Date.parse(value))) fail(`${name} is invalid`);
    return value;
  }
  function nodeName(value, name) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/u.test(value)) fail(`${name} is invalid`);
    return value;
  }

  function validate(raw) {
    const keys = ['schema', 'network_id', 'phase', 'current_trust_bundle_sha256', 'previous_trust_bundle_sha256', 'active_ca_certificate_sha256', 'target_ca_certificate_sha256', 'stage_config_revision', 'config_revision', 'config_updated_at', 'started_at', 'stage_started_at', 'active_nodes', 'converged_nodes', 'pending_recovery_replays', 'available_actions', 'nodes'];
    exactObject(raw, keys, 'document');
    if (raw.schema !== SCHEMA) fail('document.schema is unsupported');
    const networkID = resourceID(raw.network_id, 'document.network_id');
    if (!PHASES.has(raw.phase)) fail('document.phase is invalid');
    const currentTrustBundleSHA256 = digest(raw.current_trust_bundle_sha256, 'document.current_trust_bundle_sha256');
    const previousTrustBundleSHA256 = digest(raw.previous_trust_bundle_sha256, 'document.previous_trust_bundle_sha256', true);
    const activeCACertificateSHA256 = digest(raw.active_ca_certificate_sha256, 'document.active_ca_certificate_sha256');
    const targetCACertificateSHA256 = digest(raw.target_ca_certificate_sha256, 'document.target_ca_certificate_sha256', true);
    const stageConfigRevision = integer(raw.stage_config_revision, 'document.stage_config_revision');
    const configRevision = integer(raw.config_revision, 'document.config_revision');
    if (configRevision < 1 || stageConfigRevision > configRevision) fail('document revisions are inconsistent');
    const configUpdatedAt = timestamp(raw.config_updated_at, 'document.config_updated_at');
    const startedAt = timestamp(raw.started_at, 'document.started_at', true);
    const stageStartedAt = timestamp(raw.stage_started_at, 'document.stage_started_at', true);
    const activeNodes = integer(raw.active_nodes, 'document.active_nodes');
    const convergedNodes = integer(raw.converged_nodes, 'document.converged_nodes');
    const pendingRecoveryReplays = integer(raw.pending_recovery_replays, 'document.pending_recovery_replays');
    if (convergedNodes > activeNodes) fail('document convergence totals are inconsistent');
    if (!Array.isArray(raw.available_actions)) fail('document.available_actions is invalid');
    const availableActions = raw.available_actions.map((action, index) => {
      if (!ACTIONS.has(action) || raw.available_actions.indexOf(action) !== index) fail('document.available_actions is invalid');
      return action;
    });
    if (!Array.isArray(raw.nodes) || raw.nodes.length !== activeNodes) fail('document.nodes is inconsistent');
    const nodeIDs = new Set();
    const nodes = raw.nodes.map((node, index) => {
      const name = `document.nodes[${index}]`;
      exactObject(node, ['node_id', 'name', 'status', 'certificate_authority_sha256', 'certificate_generation', 'applied_certificate_generation', 'applied_config_revision', 'converged'], name);
      const nodeID = resourceID(node.node_id, `${name}.node_id`);
      if (nodeIDs.has(nodeID) || node.status !== 'active' || typeof node.converged !== 'boolean') fail(`${name} is invalid`);
      nodeIDs.add(nodeID);
      const certificateGeneration = integer(node.certificate_generation, `${name}.certificate_generation`);
      const appliedCertificateGeneration = integer(node.applied_certificate_generation, `${name}.applied_certificate_generation`);
      if (certificateGeneration < 1 || appliedCertificateGeneration > certificateGeneration) fail(`${name} certificate generations are inconsistent`);
      return Object.freeze({
        nodeID, name: nodeName(node.name, `${name}.name`), status: node.status,
        certificateAuthoritySHA256: digest(node.certificate_authority_sha256, `${name}.certificate_authority_sha256`),
        certificateGeneration, appliedCertificateGeneration,
        appliedConfigRevision: integer(node.applied_config_revision, `${name}.applied_config_revision`), converged: node.converged,
      });
    });
    if (nodes.filter((node) => node.converged).length !== convergedNodes) fail('document.converged_nodes does not match node evidence');
    if (raw.phase === 'stable') {
			const validActions = availableActions.length === 0 || (availableActions.length === 1 && availableActions[0] === 'prepare');
			if (previousTrustBundleSHA256 || targetCACertificateSHA256 || stageConfigRevision !== 0 || startedAt !== null || stageStartedAt !== null || !validActions || currentTrustBundleSHA256 !== activeCACertificateSHA256) fail('stable lifecycle metadata is inconsistent');
    } else if (!previousTrustBundleSHA256 || !targetCACertificateSHA256 || stageConfigRevision < 1 || startedAt === null || stageStartedAt === null || previousTrustBundleSHA256 === currentTrustBundleSHA256) {
      fail('transition lifecycle metadata is inconsistent');
    }
    return Object.freeze({
      schema: SCHEMA, networkID, phase: raw.phase, currentTrustBundleSHA256, previousTrustBundleSHA256,
      activeCACertificateSHA256, targetCACertificateSHA256, stageConfigRevision, configRevision, configUpdatedAt,
      startedAt, stageStartedAt, activeNodes, convergedNodes, pendingRecoveryReplays,
      availableActions: Object.freeze(availableActions), nodes: Object.freeze(nodes),
    });
  }

  return Object.freeze({ SCHEMA, PHASES, ACTIONS, validate });
}));
