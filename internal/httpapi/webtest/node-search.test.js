'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const search = require('../web/node-search.js');

const nodes = [
  {
    id: 'node-alpha', name: 'web-prod-01', ip: '10.40.0.10', role: 'member',
    site: 'New York', failure_domain: 'rack-a', status: 'active',
    lifecycleStatus: 'active', phase: 'online', severity: 'healthy',
    operational: true, runtime_state: 'running', nebula_running: true, routed_subnets: ['172.20.0.0/16'],
    alerts: [],
  },
  {
    id: 'node-beta', name: 'lighthouse-west', ip: '10.40.0.2', role: 'lighthouse',
    site: 'Los Angeles', failure_domain: 'zone-2', status: 'pending',
    lifecycleStatus: 'pending', phase: 'setup', severity: 'warning',
    operational: false, runtime_state: 'unknown', nebula_running: false, routed_subnets: [],
    alerts: [{ code: 'heartbeat_missing', severity: 'critical', message: 'No heartbeat yet' }],
  },
];

test('searches node identity, address, role, placement, lifecycle, routes, and health evidence', () => {
  for (const query of ['web-prod', '10.40.0.10', 'member', 'new york', 'rack-a', 'online', '172.20']) {
    assert.deepEqual(search.filter(nodes, query).map((node) => node.id), ['node-alpha'], query);
  }
  for (const query of ['lighthouse', 'los angeles', 'zone-2', 'pending', 'heartbeat missing', 'critical']) {
    assert.deepEqual(search.filter(nodes, query).map((node) => node.id), ['node-beta'], query);
  }
});

test('uses AND matching across normalized query terms without mutating inventory', () => {
  const before = structuredClone(nodes);
  assert.deepEqual(search.filter(nodes, 'active new york').map((node) => node.id), ['node-alpha']);
  assert.deepEqual(search.filter(nodes, 'active los angeles'), []);
  assert.deepEqual(search.filter(nodes, '  WEB-PROD   MEMBER  ').map((node) => node.id), ['node-alpha']);
  assert.deepEqual(search.filter(nodes, ''), nodes);
  assert.deepEqual(nodes, before);
});

test('rejects malformed or unbounded inputs', () => {
  assert.throws(() => search.filter({}, 'node'), /Invalid node inventory/);
  assert.throws(() => search.filter([null], 'node'), /Invalid searchable node/);
  assert.throws(() => search.filter(nodes, 'x'.repeat(257)), /Invalid node search query/);
  assert.throws(() => search.filter(nodes, 'bad\u0000query'), /Invalid node search query/);
});

test('dashboard loads node search before application code', () => {
  const index = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
  const app = fs.readFileSync(path.join(__dirname, '../web/app.js'), 'utf8');
  assert.ok(index.indexOf('src="/node-search.js"') < index.indexOf('src="/app.js"'));
  assert.match(app, /const nodeSearchModel = globalThis\.MeshNodeSearch;/);
});
