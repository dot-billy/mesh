'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const guide = require('../web/install-guide.js');

const clone = (value) => JSON.parse(JSON.stringify(value));

function configured() {
  return {
    schema: guide.SCHEMA,
    linux: {
      online_available: true,
      bundle_url: 'https://releases.example/channels/stable/bundle.json',
      bootstrap_handoff_url: 'https://releases.example/bootstrap/stable/bootstrap-handoff.json',
    },
  };
}

function unavailable() {
  return {
    schema: guide.SCHEMA,
    linux: { online_available: false },
  };
}

function handoffOnly() {
  return {
    schema: guide.SCHEMA,
    linux: {
      online_available: false,
      bootstrap_handoff_url: 'https://releases.example/bootstrap/stable/bootstrap-handoff.json',
    },
  };
}

test('validates and freezes the exact online, handoff-only, and external variants', () => {
  const online = guide.validate(configured());
  assert.deepEqual(online, {
    schema: guide.SCHEMA,
    linux: {
      onlineAvailable: true,
      bundleURL: 'https://releases.example/channels/stable/bundle.json',
      bootstrapHandoffURL: 'https://releases.example/bootstrap/stable/bootstrap-handoff.json',
    },
  });
  assert.ok(Object.isFrozen(online));
  assert.ok(Object.isFrozen(online.linux));

  const external = guide.validate(unavailable());
  assert.deepEqual(external, {
    schema: guide.SCHEMA,
    linux: { onlineAvailable: false, bundleURL: null, bootstrapHandoffURL: null },
  });
  assert.ok(Object.isFrozen(external));
  assert.ok(Object.isFrozen(external.linux));

  const handoff = guide.validate(handoffOnly());
  assert.deepEqual(handoff, {
    schema: guide.SCHEMA,
    linux: {
      onlineAvailable: false,
      bundleURL: null,
      bootstrapHandoffURL: 'https://releases.example/bootstrap/stable/bootstrap-handoff.json',
    },
  });
  assert.ok(Object.isFrozen(handoff));
  assert.ok(Object.isFrozen(handoff.linux));
});

test('rejects every schema, key, and type ambiguity', () => {
  const invalid = [
    null,
    [],
    {},
    { linux: { online_available: false } },
    { schema: guide.SCHEMA },
    { schema: 'mesh-install-guide-v1', linux: { online_available: false } },
    { schema: guide.SCHEMA, linux: { online_available: false }, extra: true },
    { schema: guide.SCHEMA, linux: null },
    { schema: guide.SCHEMA, linux: {} },
    { schema: guide.SCHEMA, linux: { online_available: 'true' } },
    { schema: guide.SCHEMA, linux: { online_available: false, bundle_url: 'https://releases.example/bundle.json' } },
    { schema: guide.SCHEMA, linux: { online_available: false, extra: true } },
    { schema: guide.SCHEMA, linux: { online_available: true } },
    { schema: guide.SCHEMA, linux: { online_available: true, bundle_url: 7 } },
    { schema: guide.SCHEMA, linux: { online_available: true, bundle_url: 'https://releases.example/bundle.json', extra: true } },
    { schema: guide.SCHEMA, linux: { online_available: false, bootstrap_handoff_url: 7 } },
    { schema: guide.SCHEMA, linux: { online_available: false, bootstrap_handoff_url: 'http://releases.example/bootstrap-handoff.json' } },
  ];
  for (const value of invalid) assert.throws(() => guide.validate(value), /Invalid install guide/);
});

test('requires the same canonical public HTTPS object URL as the server', () => {
  const invalidURLs = [
    'http://releases.example/bundle.json',
    'https://releases.example/bundle.json?x=1',
    'https://releases.example/bundle.json#fragment',
    'https://RELEASES.example/bundle.json',
    'https://releases.example:443/bundle.json',
    'https://releases.example/a/../bundle.json',
    "https://releases.example/channel's/bundle.json",
    'https://releases.example/',
    'https://releases.example/a//bundle.json',
    'https://releases.example/%62undle.json',
    ' https://releases.example/bundle.json',
    'https://user@releases.example/bundle.json',
  ];
  for (const raw of invalidURLs) {
    const value = configured();
    value.linux.bundle_url = raw;
    assert.throws(() => guide.validate(value), /bundle_url/);

    const handoffValue = handoffOnly();
    handoffValue.linux.bootstrap_handoff_url = raw;
    assert.throws(() => guide.validate(handoffValue), /bootstrap_handoff_url/);
  }

  for (const raw of [
    'https://releases.example/bundle.json',
    'https://releases.example:8443/channels/stable/bundle.json',
    'https://127.0.0.1:8443/bundle.json',
  ]) {
    const value = configured();
    value.linux.bundle_url = raw;
    assert.equal(guide.validate(value).linux.bundleURL, raw);

    const handoffValue = handoffOnly();
    handoffValue.linux.bootstrap_handoff_url = raw;
    assert.equal(guide.validate(handoffValue).linux.bootstrapHandoffURL, raw);
  }
});

test('constructs token-free shell-safe install, enroll, and activate commands', () => {
  const commands = guide.commands('https://mesh.example', guide.validate(configured()));
  assert.equal(commands.install, "sudo ./mesh-install install-online 'https://releases.example/channels/stable/bundle.json'");
  assert.match(commands.enroll, /--token-file -/);
  assert.match(commands.enroll, /meshctl enroll --server 'https:\/\/mesh\.example' --token-file -/);
  assert.doesNotMatch(commands.enroll, /&& --/);
  assert.match(commands.enroll, /MESH_TOKEN_INPUT/);
  assert.match(commands.enroll, /MESH_ENROLL_STATUS=\$\?/);
  assert.match(commands.enroll, /unset MESH_TOKEN_INPUT/);
  assert.ok(commands.enroll.endsWith('test "$MESH_ENROLL_STATUS" -eq 0'));
  assert.doesNotMatch(commands.enroll, /MESH_ENROLL_TOKEN=/);
  assert.doesNotMatch(commands.enroll, /enrollment_token|Bearer/);
  assert.doesNotMatch(commands.enroll, /sudo env/);
  assert.equal(commands.activate, 'sudo /usr/local/bin/mesh-install activate');
  assert.deepEqual(Object.keys(commands).sort(), ['activate', 'enroll', 'install']);
  assert.ok(Object.isFrozen(commands));
});

test('preserves external installation while keeping enrollment and activation independent', () => {
  const commands = guide.commands('http://127.0.0.1:8080', guide.validate(unavailable()));
  assert.equal(commands.install, null);
  assert.match(commands.enroll, /--server 'http:\/\/127\.0\.0\.1:8080'/);
  assert.equal(commands.activate, 'sudo /usr/local/bin/mesh-install activate');
});

test('quotes shell values and rejects noncanonical control-plane origins', () => {
  assert.equal(guide.shellQuote("a'b"), "'a'\\''b'");
  assert.equal(guide.shellQuote(''), "''");
  for (const origin of [
    'https://MESH.example',
    'https://mesh.example/',
    'https://user@mesh.example',
    'file:///tmp/mesh',
    ' https://mesh.example',
  ]) {
    assert.throws(() => guide.commands(origin, guide.validate(clone(configured()))), /origin/);
  }
});

test('renders one complete three-step enrollment workflow and loads its guide', () => {
  const index = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
  const app = fs.readFileSync(path.join(__dirname, '../web/app.js'), 'utf8');
  const requiredIDs = [
    'install-step',
    'bootstrap-handoff-guidance',
    'bootstrap-handoff-link',
    'bootstrap-handoff-unavailable',
    'install-command',
    'copy-install-command',
    'enroll-command',
    'copy-enroll-command',
    'activate-command',
    'copy-activate-command',
  ];
  for (const id of requiredIDs) {
    assert.equal((index.match(new RegExp(`id=["']${id}["']`, 'g')) || []).length, 1, `${id} must occur exactly once`);
  }

  assert.ok(index.indexOf('src="/install-guide.js"') < index.indexOf('src="/app.js"'));
  assert.match(app, /const installGuideModel = globalThis\.MeshInstallGuide;/);
  assert.match(app, /api\('\/api\/v1\/install-guide'\)/);
  assert.match(app, /error\.status !== 404/);
  assert.match(app, /installGuideModel\.commands\(location\.origin, state\.installGuide\)/);
  assert.match(app, /handoffLink\.href = handoffURL/);
  assert.match(app, /bootstrap-handoff-guidance/);
  assert.match(app, /Promise\.all\(\[loadAuthenticationContext\(\), loadInstallGuide\(\), loadNetworks\(\)\]\)/);
  assert.match(index, /Before generating keys or consuming the token/);
  assert.match(index, /does not claim public UDP reachability/);
  assert.match(index, /independently transferred bootstrap anchor \(preferred\)/);
  assert.match(index, /dashboard, the origin, and TLS cannot supply that authority/);
  assert.doesNotMatch(app, /sudo env MESH_ENROLL_TOKEN/);
  assert.doesNotMatch(app, /systemctl enable --now mesh-agent\.service/);
});
