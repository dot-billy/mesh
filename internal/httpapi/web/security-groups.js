(function publishMeshSecurityGroups(root, factory) {
  const groups = factory();
  if (typeof module === 'object' && module.exports) module.exports = groups;
  if (root) root.MeshSecurityGroups = groups;
}(typeof globalThis === 'undefined' ? this : globalThis, function buildMeshSecurityGroups() {
  'use strict';

  const MAX_GROUPS = 257;
  const GROUP_NAME = /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/u;

  function fail(message) {
    throw new Error(`Invalid security-group document: ${message}`);
  }

  function integer(value, name) {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${name} is invalid`);
    return value;
  }

  function text(value, name, maximum, empty = false) {
    if (typeof value !== 'string' || (!empty && value.length === 0) || value.length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) fail(`${name} is invalid`);
    return value;
  }

  function validate(raw, expectedNetworkID = '') {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) fail('root must be an object');
    const networkID = text(raw.network_id, 'network_id', 128);
    if (expectedNetworkID && networkID !== expectedNetworkID) fail('network_id does not match the selected network');
    if (!Array.isArray(raw.groups) || raw.groups.length === 0 || raw.groups.length > MAX_GROUPS) fail('groups is invalid');
    const names = new Set();
    const groups = raw.groups.map((item, index) => {
      if (!item || typeof item !== 'object' || Array.isArray(item)) fail(`groups[${index}] must be an object`);
      const name = text(item.name, `groups[${index}].name`, 32);
      if (!GROUP_NAME.test(name) || name === 'any' || names.has(name)) fail(`groups[${index}].name is invalid`);
      names.add(name);
      if (typeof item.builtin !== 'boolean' || item.builtin !== (name === 'all')) fail(`groups[${index}].builtin is invalid`);
      const description = text(item.description ?? '', `groups[${index}].description`, 256, true);
      if (!Array.isArray(item.member_node_ids) || item.member_node_ids.some((id) => typeof id !== 'string' || id.length === 0 || id.length > 128) || new Set(item.member_node_ids).size !== item.member_node_ids.length) {
        fail(`groups[${index}].member_node_ids is invalid`);
      }
      const members = item.member_node_ids.slice().sort();
      return Object.freeze({
        name, description, builtin: item.builtin, memberNodeIDs: Object.freeze(members),
        activeMembers: integer(item.active_members, `groups[${index}].active_members`),
        pendingMembers: integer(item.pending_members, `groups[${index}].pending_members`),
        peerRuleReferences: integer(item.peer_rule_references, `groups[${index}].peer_rule_references`),
        targetRuleReferences: integer(item.target_rule_references, `groups[${index}].target_rule_references`),
        createdAt: item.created_at || '', updatedAt: item.updated_at || '',
      });
    });
    if (groups[0].name !== 'all' || groups.slice(1).some((group, index) => index > 0 && groups[index].name >= group.name)) fail('groups must start with all and custom groups must be sorted');
    return Object.freeze({ networkID, groups: Object.freeze(groups) });
  }

  function group(document, name) {
    return document?.groups?.find((candidate) => candidate.name === name) || null;
  }

  function groupsForNode(document, nodeID) {
    if (!document || !Array.isArray(document.groups) || typeof nodeID !== 'string' || nodeID.length === 0) fail('membership inputs are invalid');
    const result = document.groups.filter((candidate) => candidate.name === 'all' || candidate.memberNodeIDs.includes(nodeID)).map((candidate) => candidate.name);
    return result.sort();
  }

  function membershipChanges(document, nodes, groupName, selectedNodeIDs) {
    const selectedGroup = group(document, groupName);
    if (!selectedGroup || selectedGroup.builtin) fail('managed group is invalid');
    if (!Array.isArray(nodes) || !Array.isArray(selectedNodeIDs) || new Set(selectedNodeIDs).size !== selectedNodeIDs.length) fail('membership inputs are invalid');
    const activeNodes = nodes.filter((node) => node && node.status === 'active');
    const activeIDs = new Set(activeNodes.map((node) => node.id));
    if (selectedNodeIDs.some((nodeID) => !activeIDs.has(nodeID))) fail('selected membership includes a non-active node');
    const selected = new Set(selectedNodeIDs);
    const current = new Set(selectedGroup.memberNodeIDs);
    return activeNodes.filter((node) => selected.has(node.id) !== current.has(node.id)).map((node) => {
      const groups = groupsForNode(document, node.id).filter((name) => name !== groupName);
      if (selected.has(node.id)) groups.push(groupName);
      groups.sort();
      return Object.freeze({ nodeID: node.id, nodeName: node.name, groups: Object.freeze(groups), add: selected.has(node.id) });
    });
  }

  return Object.freeze({ GROUP_NAME, validate, group, groupsForNode, membershipChanges });
}));
