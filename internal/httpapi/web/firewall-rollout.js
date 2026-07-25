(function publishMeshFirewallRollout(root, factory) {
  const adapter = factory();
  if (typeof module === 'object' && module.exports) module.exports = adapter;
  if (root) root.MeshFirewallRollout = adapter;
}(typeof globalThis === 'undefined' ? this : globalThis, function buildMeshFirewallRolloutAdapter() {
  'use strict';

  const SCHEMA = 'mesh-network-firewall-rollout-v5';
  const PHASES = new Set(['stable', 'canary', 'paused']);
  const ACTIONS = new Set(['start', 'promote', 'pause', 'resume', 'rollback']);
  const TRANSITION_ACTIONS = new Set(['started', 'canary_removed', 'paused', 'resumed', 'promoted', 'rolled_back', 'auto_rolled_back']);
  const TRANSITION_REASONS = new Set(['', 'canary_config_activation_failed', 'canary_target_runtime_stopped', 'last_canary_revoked']);
  const AUTOMATIC_ROLLBACK_GUARDS = Object.freeze(['activation_failed', 'target_runtime_stopped']);
  const MAX_CANARIES = 16;

  function fail(message) { throw new Error(`Invalid network firewall rollout document: ${message}`); }
  function exactObject(value, keys, name) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${name} must be an object`);
    const allowed = new Set(keys);
    for (const key of keys) if (!Object.prototype.hasOwnProperty.call(value, key)) fail(`${name}.${key} is required`);
    for (const key of Object.keys(value)) if (!allowed.has(key)) fail(`${name}.${key} is not allowed`);
  }
  function integer(value, name) {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${name} is invalid`);
    return value;
  }
  function text(value, name, pattern, allowEmpty = false) {
    if (typeof value !== 'string' || (!allowEmpty && value === '') || value.length > 128 || (value !== '' && !pattern.test(value))) fail(`${name} is invalid`);
    return value;
  }
  function resourceID(value, name) { return text(value, name, /^[A-Za-z0-9_-]+$/u); }
  function digest(value, name, allowEmpty = false) {
    if (allowEmpty && value === '') return '';
    if (typeof value !== 'string' || !/^[0-9a-f]{64}$/u.test(value)) fail(`${name} is invalid`);
    return value;
  }
  function timestamp(value, name, nullable = false) {
    if (nullable && value === null) return null;
    if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(value) || !Number.isFinite(Date.parse(value))) fail(`${name} is invalid`);
    return value;
  }
  function firewallRule(raw, name) {
    if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) fail(`${name} must be an object`);
    const selectors = ['group', 'host', 'peer_node_id'].filter((key) => Object.prototype.hasOwnProperty.call(raw, key));
    if (selectors.length !== 1) fail(`${name} peer selector is invalid`);
    const targets = ['target_group', 'target_node_id'].filter((key) => Object.prototype.hasOwnProperty.call(raw, key));
    if (targets.length > 1) fail(`${name} local target is invalid`);
    const selector = selectors[0];
    exactObject(raw, ['proto', 'port', selector, ...targets], name);
    if (!['any', 'icmp', 'tcp', 'udp'].includes(raw.proto)) fail(`${name}.proto is invalid`);
    if (typeof raw.port !== 'string' || !/^(?:any|[1-9]\d{0,4}(?:-[1-9]\d{0,4})?)$/u.test(raw.port)) fail(`${name}.port is invalid`);
    if (raw.proto === 'icmp' && raw.port !== 'any') fail(`${name}.port is invalid for ICMP`);
    const value = raw[selector];
    if (selector === 'group') {
      if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/u.test(value) || value === 'any') fail(`${name}.group is invalid`);
    } else if (selector === 'peer_node_id') {
      resourceID(value, `${name}.peer_node_id`);
    } else if (typeof value !== 'string' || value === '' || value.length > 32) fail(`${name}.host is invalid`);
    const result = { proto: raw.proto, port: raw.port, [selector]: value };
    if (targets[0] === 'target_group') {
      if (typeof raw.target_group !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/u.test(raw.target_group) || raw.target_group === 'all') fail(`${name}.target_group is invalid`);
      result.target_group = raw.target_group;
    } else if (targets[0] === 'target_node_id') {
      result.target_node_id = resourceID(raw.target_node_id, `${name}.target_node_id`);
    }
    return Object.freeze(result);
  }
  function effectiveNode(raw, name) {
    exactObject(raw, ['node_id', 'name', 'ip', 'groups', 'inbound', 'outbound', 'rendered_firewall', 'sha256'], name);
    if (!Array.isArray(raw.groups) || raw.groups.length < 1 || raw.groups.length > 64 || !Array.isArray(raw.inbound) || !Array.isArray(raw.outbound) || typeof raw.rendered_firewall !== 'string' || !raw.rendered_firewall.startsWith('firewall:\n') || raw.rendered_firewall.length > (4 << 20)) fail(`${name} is invalid`);
    const groups = raw.groups.map((group, index) => {
      if (typeof group !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/u.test(group) || index > 0 && raw.groups[index - 1] >= group) fail(`${name}.groups is invalid`);
      return group;
    });
    const validateEffectiveRule = (rule, index, direction) => {
      const validated = firewallRule(rule, `${name}.${direction}[${index}]`);
      if (validated.peer_node_id || validated.target_group || validated.target_node_id) fail(`${name}.${direction}[${index}] is not compiled`);
      return validated;
    };
    return Object.freeze({
      nodeID: resourceID(raw.node_id, `${name}.node_id`),
      name: text(raw.name, `${name}.name`, /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/u),
      ip: text(raw.ip, `${name}.ip`, /^\d{1,3}(?:\.\d{1,3}){3}$/u),
      groups: Object.freeze(groups),
      inbound: Object.freeze(raw.inbound.map((rule, index) => validateEffectiveRule(rule, index, 'inbound'))),
      outbound: Object.freeze(raw.outbound.map((rule, index) => validateEffectiveRule(rule, index, 'outbound'))),
      renderedFirewall: raw.rendered_firewall,
      sha256: digest(raw.sha256, `${name}.sha256`),
    });
  }
  function policy(raw, name) {
    exactObject(raw, ['mode', 'renderer_version', 'inbound', 'outbound', 'rendered_firewall', 'policy_sha256', 'effective_nodes'], name);
    if (raw.mode !== 'managed' || raw.renderer_version !== 2 || !Array.isArray(raw.inbound) || !Array.isArray(raw.outbound) || raw.inbound.length > 128 || raw.outbound.length > 128 || typeof raw.rendered_firewall !== 'string' || raw.rendered_firewall.length > (4 << 20) || raw.rendered_firewall !== '' && !raw.rendered_firewall.startsWith('firewall:\n') || !Array.isArray(raw.effective_nodes)) fail(`${name} is invalid`);
    return Object.freeze({
      mode: raw.mode, rendererVersion: raw.renderer_version,
      inbound: Object.freeze(raw.inbound.map((rule, index) => firewallRule(rule, `${name}.inbound[${index}]`))),
      outbound: Object.freeze(raw.outbound.map((rule, index) => firewallRule(rule, `${name}.outbound[${index}]`))),
      renderedFirewall: raw.rendered_firewall,
      policySHA256: digest(raw.policy_sha256, `${name}.policy_sha256`),
      effectiveNodes: Object.freeze(raw.effective_nodes.map((node, index) => effectiveNode(node, `${name}.effective_nodes[${index}]`))),
    });
  }

  function transition(raw, configUpdatedAt) {
    if (raw === null) return null;
    exactObject(raw, ['action', 'at', 'reason_code', 'node_id'], 'document.last_transition');
    if (!TRANSITION_ACTIONS.has(raw.action) || !TRANSITION_REASONS.has(raw.reason_code)) fail('document.last_transition is invalid');
    const at = timestamp(raw.at, 'document.last_transition.at');
    if (Date.parse(at) > Date.parse(configUpdatedAt)) fail('document.last_transition is newer than the network state');
    const nodeID = raw.node_id === '' ? '' : resourceID(raw.node_id, 'document.last_transition.node_id');
    if (raw.action === 'canary_removed' && nodeID === '') fail('document.last_transition node is required');
    if (raw.action !== 'auto_rolled_back' && raw.reason_code !== '') fail('document.last_transition reason is inconsistent');
    if (raw.reason_code !== '' && nodeID === '') fail('document.last_transition reason requires a node');
    return Object.freeze({ action: raw.action, at, reasonCode: raw.reason_code, nodeID });
  }

  function validate(raw) {
    const keys = ['schema', 'network_id', 'phase', 'config_revision', 'config_updated_at', 'stage_config_revision', 'started_at', 'paused_at', 'current_policy_sha256', 'target_policy_sha256', 'target_policy', 'active_nodes', 'canary_nodes', 'converged_canaries', 'available_actions', 'nodes', 'last_transition', 'automatic_rollback_guards'];
    exactObject(raw, keys, 'document');
    if (raw.schema !== SCHEMA || !PHASES.has(raw.phase)) fail('document schema or phase is unsupported');
    const networkID = resourceID(raw.network_id, 'document.network_id');
    const configRevision = integer(raw.config_revision, 'document.config_revision');
    const stageConfigRevision = integer(raw.stage_config_revision, 'document.stage_config_revision');
    if (configRevision < 1 || stageConfigRevision > configRevision) fail('document revisions are inconsistent');
    const configUpdatedAt = timestamp(raw.config_updated_at, 'document.config_updated_at');
    const lastTransition = transition(raw.last_transition, configUpdatedAt);
    if (!Array.isArray(raw.automatic_rollback_guards) || raw.automatic_rollback_guards.length !== AUTOMATIC_ROLLBACK_GUARDS.length || raw.automatic_rollback_guards.some((guard, index) => guard !== AUTOMATIC_ROLLBACK_GUARDS[index])) fail('document.automatic_rollback_guards is invalid');
    const startedAt = timestamp(raw.started_at, 'document.started_at', true);
    const pausedAt = timestamp(raw.paused_at, 'document.paused_at', true);
    const currentPolicySHA256 = digest(raw.current_policy_sha256, 'document.current_policy_sha256');
    const targetPolicySHA256 = digest(raw.target_policy_sha256, 'document.target_policy_sha256', true);
    const activeNodes = integer(raw.active_nodes, 'document.active_nodes');
    const canaryNodes = integer(raw.canary_nodes, 'document.canary_nodes');
    const convergedCanaries = integer(raw.converged_canaries, 'document.converged_canaries');
    if (canaryNodes > activeNodes || canaryNodes > MAX_CANARIES || convergedCanaries > canaryNodes) fail('document convergence totals are inconsistent');
    if (!Array.isArray(raw.available_actions)) fail('document.available_actions is invalid');
    const availableActions = raw.available_actions.map((action, index) => {
      if (!ACTIONS.has(action) || raw.available_actions.indexOf(action) !== index) fail('document.available_actions is invalid');
      return action;
    });
    if (!Array.isArray(raw.nodes) || raw.nodes.length !== activeNodes) fail('document.nodes is inconsistent');
    const nodeIDs = new Set();
    const nodes = raw.nodes.map((node, index) => {
      const name = `document.nodes[${index}]`;
      exactObject(node, ['node_id', 'name', 'ip', 'role', 'canary', 'applied_config_revision', 'applied_config_sha256', 'desired_config_sha256', 'certificate_generation', 'applied_certificate_generation', 'nebula_running', 'agent_status', 'converged'], name);
      const nodeID = resourceID(node.node_id, `${name}.node_id`);
      if (nodeIDs.has(nodeID) || typeof node.canary !== 'boolean' || typeof node.nebula_running !== 'boolean' || typeof node.converged !== 'boolean' || !['member', 'lighthouse'].includes(node.role)) fail(`${name} is invalid`);
      nodeIDs.add(nodeID);
      const certificateGeneration = integer(node.certificate_generation, `${name}.certificate_generation`);
      const appliedCertificateGeneration = integer(node.applied_certificate_generation, `${name}.applied_certificate_generation`);
      if (certificateGeneration < 1 || appliedCertificateGeneration > certificateGeneration) fail(`${name} certificate generations are inconsistent`);
      const appliedConfigSHA256 = digest(node.applied_config_sha256, `${name}.applied_config_sha256`, true);
      return Object.freeze({
        nodeID, name: text(node.name, `${name}.name`, /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/u),
        ip: text(node.ip, `${name}.ip`, /^\d{1,3}(?:\.\d{1,3}){3}$/u), role: node.role, canary: node.canary,
        appliedConfigRevision: integer(node.applied_config_revision, `${name}.applied_config_revision`), appliedConfigSHA256,
        desiredConfigSHA256: digest(node.desired_config_sha256, `${name}.desired_config_sha256`),
        certificateGeneration, appliedCertificateGeneration, nebulaRunning: node.nebula_running,
        agentStatus: text(node.agent_status, `${name}.agent_status`, /^[A-Za-z0-9._-]+$/u, true), converged: node.converged,
      });
    });
    if (nodes.filter((node) => node.canary).length !== canaryNodes || nodes.filter((node) => node.converged).length !== convergedCanaries || nodes.some((node) => node.converged && !node.canary)) fail('document node evidence does not match convergence totals');

    let targetPolicy = null;
    if (raw.phase === 'stable') {
      const validActions = availableActions.length === 0 || (availableActions.length === 1 && availableActions[0] === 'start');
      if (stageConfigRevision !== 0 || startedAt !== null || pausedAt !== null || targetPolicySHA256 !== '' || raw.target_policy !== null || canaryNodes !== 0 || convergedCanaries !== 0 || nodes.some((node) => node.canary || node.converged) || !validActions) fail('stable lifecycle metadata is inconsistent');
    } else if (raw.phase === 'canary') {
      targetPolicy = policy(raw.target_policy, 'document.target_policy');
      const validActions = availableActions.length === 2 && availableActions[0] === 'pause' && availableActions[1] === 'rollback' || availableActions.length === 3 && availableActions[0] === 'promote' && availableActions[1] === 'pause' && availableActions[2] === 'rollback';
      if (stageConfigRevision < 1 || startedAt === null || pausedAt !== null || !targetPolicySHA256 || targetPolicySHA256 === currentPolicySHA256 || canaryNodes < 1 || !validActions || (availableActions.includes('promote') !== (convergedCanaries === canaryNodes))) fail('canary lifecycle metadata is inconsistent');
    } else {
      targetPolicy = policy(raw.target_policy, 'document.target_policy');
      const validActions = availableActions.length === 2 && availableActions[0] === 'resume' && availableActions[1] === 'rollback';
      if (stageConfigRevision < 1 || startedAt === null || pausedAt === null || Date.parse(pausedAt) < Date.parse(startedAt) || Date.parse(pausedAt) > Date.parse(configUpdatedAt) || !targetPolicySHA256 || targetPolicySHA256 === currentPolicySHA256 || canaryNodes < 1 || convergedCanaries !== 0 || nodes.some((node) => node.converged) || !validActions) fail('paused lifecycle metadata is inconsistent');
    }
    return Object.freeze({
      schema: SCHEMA, networkID, phase: raw.phase, configRevision, configUpdatedAt, stageConfigRevision, startedAt, pausedAt,
      currentPolicySHA256, targetPolicySHA256, targetPolicy, activeNodes, canaryNodes, convergedCanaries,
      availableActions: Object.freeze(availableActions), nodes: Object.freeze(nodes), lastTransition,
      automaticRollbackGuards: AUTOMATIC_ROLLBACK_GUARDS,
    });
  }

  return Object.freeze({ SCHEMA, PHASES, ACTIONS, TRANSITION_ACTIONS, TRANSITION_REASONS, AUTOMATIC_ROLLBACK_GUARDS, MAX_CANARIES, validate });
}));
