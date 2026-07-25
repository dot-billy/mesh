'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const model = require('../web/security-groups.js');

function document() {
  return {
    network_id: 'net-1',
    groups: [
      { name: 'all', builtin: true, member_node_ids: ['a', 'b', 'p'], active_members: 2, pending_members: 1, peer_rule_references: 1, target_rule_references: 0 },
      { name: 'clients', description: 'Client devices', builtin: false, member_node_ids: ['b'], active_members: 1, pending_members: 0, peer_rule_references: 0, target_rule_references: 1, created_at: '2026-07-24T00:00:00Z', updated_at: '2026-07-24T00:00:00Z' },
      { name: 'operators', builtin: false, member_node_ids: ['a', 'p'], active_members: 1, pending_members: 1, peer_rule_references: 1, target_rule_references: 0, created_at: '2026-07-24T00:00:00Z', updated_at: '2026-07-24T00:00:00Z' },
    ],
  };
}

test('validates the catalog and reconstructs complete per-node membership', () => {
  const validated = model.validate(document(), 'net-1');
  assert.equal(validated.groups[1].description, 'Client devices');
  assert.deepEqual(model.groupsForNode(validated, 'a'), ['all', 'operators']);
  assert.deepEqual(model.groupsForNode(validated, 'b'), ['all', 'clients']);
  assert.ok(Object.isFrozen(validated));
  assert.ok(Object.isFrozen(validated.groups));
});

test('plans only active certificate changes and preserves every other group', () => {
  const validated = model.validate(document(), 'net-1');
  const nodes = [
    { id: 'a', name: 'alpha', status: 'active' },
    { id: 'b', name: 'beta', status: 'active' },
    { id: 'p', name: 'pending', status: 'pending' },
  ];
  const changes = model.membershipChanges(validated, nodes, 'operators', ['b']);
  assert.deepEqual(changes, [
    { nodeID: 'a', nodeName: 'alpha', groups: ['all'], add: false },
    { nodeID: 'b', nodeName: 'beta', groups: ['all', 'clients', 'operators'], add: true },
  ]);
  assert.throws(() => model.membershipChanges(validated, nodes, 'operators', ['p']), /non-active node/);
  assert.throws(() => model.membershipChanges(validated, nodes, 'all', ['a']), /managed group/);
});

test('rejects duplicate, unsorted, malformed, and cross-network documents', () => {
  assert.throws(() => model.validate(document(), 'net-2'), /does not match/);
  const duplicate = document();
  duplicate.groups.push({ ...duplicate.groups[1] });
  assert.throws(() => model.validate(duplicate, 'net-1'), /name is invalid/);
  const unsorted = document();
  [unsorted.groups[1], unsorted.groups[2]] = [unsorted.groups[2], unsorted.groups[1]];
  assert.throws(() => model.validate(unsorted, 'net-1'), /sorted/);
  const malformed = document();
  malformed.groups[1].active_members = -1;
  assert.throws(() => model.validate(malformed, 'net-1'), /active_members/);
});

test('dashboard loads the security-group model before application code', () => {
  const index = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
  const app = fs.readFileSync(path.join(__dirname, '../web/app.js'), 'utf8');
  assert.ok(index.indexOf('src="/security-groups.js"') < index.indexOf('src="/app.js"'));
  assert.match(app, /const securityGroupsModel = globalThis\.MeshSecurityGroups;/);
});
