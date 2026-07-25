'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const guide = require('../web/setup-guide.js');

function node(id, name, role, lifecycleStatus, operational = false) {
  return { id, name, role, lifecycleStatus, operational, ignored_health_field: 'already validated upstream' };
}

test('guides a new network through first lighthouse, member, redundancy, and explicit readiness', () => {
  const empty = guide.project([], 2);
  assert.equal(empty.completedStages, 1);
  assert.equal(empty.action.kind, 'add_lighthouse');
  assert.deepEqual(empty.stages.map((item) => item.state), ['complete', 'current', 'pending', 'pending']);

  const lighthouse = guide.project([node('lh1', 'lighthouse-01', 'lighthouse', 'active', true)], 2);
  assert.equal(lighthouse.completedStages, 2);
  assert.equal(lighthouse.action.kind, 'add_member');

  const member = guide.project([
    node('lh1', 'lighthouse-01', 'lighthouse', 'active', true),
    node('m1', 'member-01', 'member', 'active', true),
  ], 2);
  assert.equal(member.completedStages, 3);
  assert.equal(member.action.kind, 'add_redundancy');
  assert.match(member.detail, /different failure domain/);

  const redundant = guide.project([
    node('lh1', 'lighthouse-01', 'lighthouse', 'active', true),
    node('lh2', 'lighthouse-02', 'lighthouse', 'active', true),
    node('m1', 'member-01', 'member', 'active', true),
  ], 2);
  assert.equal(redundant.completedStages, 4);
  assert.equal(redundant.action.kind, 'readiness');
  assert.equal(redundant.action.label, 'Run deployment readiness');
  assert.match(redundant.scope, /peer reachability is not inferred/);
  assert.ok(Object.isFrozen(redundant));
  assert.ok(Object.isFrozen(redundant.stages));
});

test('resumes deterministic pending nodes without pretending their credential can be redisplayed', () => {
  const pendingLighthouse = guide.project([
    node('z', 'z-lighthouse', 'lighthouse', 'pending'),
    node('a', 'a-lighthouse', 'lighthouse', 'pending'),
  ], 2);
  assert.deepEqual(pendingLighthouse.action, { kind: 'resume_node', label: 'Review pending lighthouse', nodeID: 'a' });
  assert.match(pendingLighthouse.detail, /saved one-time credential/);
  assert.match(pendingLighthouse.detail, /reissue/);

  const pendingMember = guide.project([
    node('lh', 'lighthouse', 'lighthouse', 'active', true),
    node('member', 'member', 'member', 'pending'),
  ], 2);
  assert.equal(pendingMember.action.kind, 'resume_node');
  assert.equal(pendingMember.action.nodeID, 'member');

  const pendingRedundancy = guide.project([
    node('lh', 'lighthouse', 'lighthouse', 'active', true),
    node('member', 'member', 'member', 'active', true),
    node('lh2', 'lighthouse-02', 'lighthouse', 'pending'),
  ], 2);
  assert.equal(pendingRedundancy.action.kind, 'resume_node');
  assert.match(pendingRedundancy.detail, /different failure domain/);
});

test('sends enrolled but nonoperational nodes to diagnosis instead of claiming progress', () => {
  const lighthouse = guide.project([node('lh', 'lighthouse', 'lighthouse', 'active')], 2);
  assert.equal(lighthouse.completedStages, 1);
  assert.equal(lighthouse.action.kind, 'readiness');
  assert.equal(lighthouse.action.label, 'Diagnose lighthouse setup');

  const member = guide.project([
    node('lh', 'lighthouse', 'lighthouse', 'active', true),
    node('member', 'member', 'member', 'active'),
  ], 2);
  assert.equal(member.completedStages, 2);
  assert.equal(member.action.label, 'Diagnose member setup');

  const redundant = guide.project([
    node('lh', 'lighthouse', 'lighthouse', 'active', true),
    node('member', 'member', 'member', 'active', true),
    node('lh2', 'lighthouse-02', 'lighthouse', 'active'),
  ], 2);
  assert.equal(redundant.completedStages, 3);
  assert.equal(redundant.action.label, 'Diagnose lighthouse redundancy');
});

test('ignores revoked inventory and validates every field it relies on', () => {
  const result = guide.project([
    node('old-lh', 'old-lighthouse', 'lighthouse', 'revoked'),
    node('old-member', 'old-member', 'member', 'revoked'),
  ], 2);
  assert.equal(result.action.kind, 'add_lighthouse');

  const invalid = [
    [null, 2],
    [new Array(100001).fill({}), 2],
    [[], 0],
    [[], 33],
    [[null], 2],
    [[node('bad id', 'node', 'member', 'pending')], 2],
    [[node('a', '', 'member', 'pending')], 2],
    [[node('a', 'node', 'router', 'pending')], 2],
    [[node('a', 'node', 'member', 'unknown')], 2],
    [[{ ...node('a', 'node', 'member', 'active'), operational: 'yes' }], 2],
    [[node('a', 'node', 'member', 'pending', true)], 2],
    [[node('a', 'one', 'member', 'pending'), node('a', 'two', 'member', 'pending')], 2],
  ];
  for (const [nodes, required] of invalid) assert.throws(() => guide.project(nodes, required), /Invalid network setup guide input/);
});

test('dashboard loads the guide before app code and exposes only explicit actions', () => {
  const index = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
  const app = fs.readFileSync(path.join(__dirname, '../web/app.js'), 'utf8');
  const setupGuide = fs.readFileSync(path.join(__dirname, '../web/setup-guide.js'), 'utf8');
  assert.ok(index.indexOf('src="/setup-guide.js"') < index.indexOf('src="/app.js"'));
  assert.match(app, /const setupGuideModel = globalThis\.MeshSetupGuide;/);
  assert.match(app, /setupGuideModel\.project\(nodes, state\.fleet\.policy\.required_healthy_lighthouses\)/);
  assert.match(setupGuide, /Authenticated lifecycle state only/);
  assert.doesNotMatch(app, /setup.*reachable|reachable.*setup/iu);
});
