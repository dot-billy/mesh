(function publishMeshSetupGuide(root, factory) {
  const guide = factory();
  if (typeof module === 'object' && module.exports) module.exports = guide;
  if (root) root.MeshSetupGuide = guide;
}(typeof globalThis === 'undefined' ? this : globalThis, function buildMeshSetupGuide() {
  'use strict';

  const MAX_NODES = 100000;

  function fail(message) {
    throw new Error(`Invalid network setup guide input: ${message}`);
  }

  function text(value, name, maximum) {
    if (typeof value !== 'string' || value.length === 0 || value.length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) fail(`${name} is invalid`);
    return value;
  }

  function node(raw, index) {
    if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) fail(`nodes[${index}] must be an object`);
    const id = text(raw.id, `nodes[${index}].id`, 128);
    if (!/^[A-Za-z0-9_-]+$/u.test(id)) fail(`nodes[${index}].id is invalid`);
    const name = text(raw.name, `nodes[${index}].name`, 128);
    if (raw.role !== 'lighthouse' && raw.role !== 'member') fail(`nodes[${index}].role is invalid`);
    if (!['pending', 'active', 'revoked'].includes(raw.lifecycleStatus)) fail(`nodes[${index}].lifecycleStatus is invalid`);
    if (typeof raw.operational !== 'boolean') fail(`nodes[${index}].operational is invalid`);
    if (raw.operational && raw.lifecycleStatus !== 'active') fail(`nodes[${index}] cannot be operational outside active lifecycle state`);
    return Object.freeze({ id, name, role: raw.role, lifecycleStatus: raw.lifecycleStatus, operational: raw.operational });
  }

  function compareNode(left, right) {
    return left.name < right.name ? -1 : left.name > right.name ? 1 : left.id < right.id ? -1 : left.id > right.id ? 1 : 0;
  }

  function stage(label, complete, current) {
    return Object.freeze({ label, state: complete ? 'complete' : current ? 'current' : 'pending' });
  }

  function action(kind, label, nodeID = '') {
    return Object.freeze({ kind, label, nodeID });
  }

  function project(rawNodes, requiredLighthouses) {
    if (!Array.isArray(rawNodes) || rawNodes.length > MAX_NODES) fail('nodes is invalid');
    if (!Number.isSafeInteger(requiredLighthouses) || requiredLighthouses < 1 || requiredLighthouses > 32) fail('requiredLighthouses is invalid');
    const nodes = rawNodes.map(node).sort(compareNode);
    const seen = new Set();
    for (const item of nodes) {
      if (seen.has(item.id)) fail('node IDs are not unique');
      seen.add(item.id);
    }

    const active = (role) => nodes.filter((item) => item.role === role && item.lifecycleStatus === 'active');
    const pending = (role) => nodes.filter((item) => item.role === role && item.lifecycleStatus === 'pending');
    const operational = (role) => active(role).filter((item) => item.operational);
    const operationalLighthouses = operational('lighthouse');
    const operationalMembers = operational('member');
    const firstLighthouseComplete = operationalLighthouses.length > 0;
    const firstMemberComplete = operationalMembers.length > 0;
    const redundancyComplete = operationalLighthouses.length >= requiredLighthouses;
    const completedStages = 1 + Number(firstLighthouseComplete) + Number(firstMemberComplete) + Number(redundancyComplete);

    let next;
    let detail;
    if (!firstLighthouseComplete) {
      const pendingNode = pending('lighthouse')[0];
      const activeNode = active('lighthouse')[0];
      if (pendingNode) {
        next = action('resume_node', 'Review pending lighthouse', pendingNode.id);
        detail = `${pendingNode.name} is awaiting enrollment. Use its saved one-time credential, or reissue it from the node row if that credential is unavailable.`;
      } else if (activeNode) {
        next = action('readiness', 'Diagnose lighthouse setup');
        detail = `${activeNode.name} is enrolled but is not operational in the current authenticated lifecycle snapshot. Open deployment checks before adding more machines.`;
      } else {
        next = action('add_lighthouse', 'Add first lighthouse');
        detail = 'Add a publicly reachable lighthouse, then install, enroll, and activate its managed agent.';
      }
    } else if (!firstMemberComplete) {
      const pendingNode = pending('member')[0];
      const activeNode = active('member')[0];
      if (pendingNode) {
        next = action('resume_node', 'Review pending member', pendingNode.id);
        detail = `${pendingNode.name} is awaiting enrollment. Use its saved one-time credential, or reissue it from the node row if that credential is unavailable.`;
      } else if (activeNode) {
        next = action('readiness', 'Diagnose member setup');
        detail = `${activeNode.name} is enrolled but is not operational in the current authenticated lifecycle snapshot. Open deployment checks before adding more machines.`;
      } else {
        next = action('add_member', 'Add first member');
        detail = 'The first lighthouse is operational. Add a member, then install, enroll, and activate its managed agent.';
      }
    } else if (!redundancyComplete) {
      const pendingNode = pending('lighthouse')[0];
      const activeNode = active('lighthouse').find((item) => !item.operational);
      if (pendingNode) {
        next = action('resume_node', 'Review pending lighthouse', pendingNode.id);
        detail = `${pendingNode.name} is awaiting enrollment. Complete it in a different failure domain to remove the single-lighthouse dependency.`;
      } else if (activeNode) {
        next = action('readiness', 'Diagnose lighthouse redundancy');
        detail = `${activeNode.name} is enrolled but not operational. Open deployment checks before creating another redundant lighthouse.`;
      } else {
        next = action('add_redundancy', 'Add redundant lighthouse');
        detail = `Core member traffic has an operational lighthouse. Add ${requiredLighthouses - operationalLighthouses.length} more in a different failure domain before final verification.`;
      }
    } else {
      next = action('readiness', 'Run deployment readiness');
      detail = 'The core topology and required lighthouse count are operational in the current lifecycle snapshot. Run deployment checks to verify placement, DNS, route overlap, and current member-reported UDP evidence.';
    }

    const stages = Object.freeze([
      stage('Network created', true, false),
      stage('First lighthouse operational', firstLighthouseComplete, !firstLighthouseComplete),
      stage('First member operational', firstMemberComplete, firstLighthouseComplete && !firstMemberComplete),
      stage(`${requiredLighthouses} operational lighthouses`, redundancyComplete, firstLighthouseComplete && firstMemberComplete && !redundancyComplete),
    ]);

    return Object.freeze({
      completedStages,
      totalStages: stages.length,
      stages,
      detail,
      action: next,
      scope: 'Authenticated lifecycle state only; peer reachability is not inferred.',
    });
  }

  return Object.freeze({ project });
}));
