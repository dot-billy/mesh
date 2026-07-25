'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const model = require('../web/desktop-authorization.js');

const requestID = `desktop_${'a'.repeat(43)}`;

function capture(href) {
  const replacements = [];
  const result = model.captureLaunch(href, {
    replaceState(state, title, value) { replacements.push({ state, title, value }); },
  });
  return { result, replacements };
}

test('captures one exact public request ID and immediately removes it from browser history', () => {
  const { result, replacements } = capture(`https://mesh.example/?view=networks&mesh_desktop_request=${requestID}#fleet`);
  assert.deepEqual(result, { requestID, invalid: false });
  assert.deepEqual(replacements, [{ state: null, title: '', value: '/?view=networks#fleet' }]);
  assert.equal(JSON.stringify(replacements).includes(requestID), false);
});

test('rejects malformed and duplicate request IDs while scrubbing every captured value', () => {
  for (const href of [
    'https://mesh.example/?mesh_desktop_request=desktop_short',
    `https://mesh.example/?mesh_desktop_request=${requestID}&mesh_desktop_request=${requestID}`,
    `https://mesh.example/?mesh_desktop_request=${encodeURIComponent(`${requestID}/extra`)}`,
  ]) {
    const { result, replacements } = capture(href);
    assert.deepEqual(result, { requestID: '', invalid: true });
    assert.equal(replacements.length, 1);
    assert.equal(replacements[0].value.includes('mesh_desktop_request'), false);
    assert.equal(replacements[0].value.includes('desktop_'), false);
  }
});

test('fails closed and strips poll-secret-shaped parameters without returning or retaining their values', () => {
  const secret = 'super-sensitive-poll-secret';
  const { result, replacements } = capture(`https://mesh.example/app?mesh_desktop_request=${requestID}&poll_secret=${secret}&safe=1`);
  assert.deepEqual(result, { requestID: '', invalid: true });
  assert.deepEqual(replacements, [{ state: null, title: '', value: '/app?safe=1' }]);
  assert.equal(JSON.stringify({ result, replacements }).includes(secret), false);

  const fragment = capture(`https://mesh.example/app?mesh_desktop_request=${requestID}#poll_secret=${secret}`);
  assert.deepEqual(fragment.result, { requestID: '', invalid: true });
  assert.deepEqual(fragment.replacements, [{ state: null, title: '', value: '/app' }]);
  assert.equal(JSON.stringify(fragment).includes(secret), false);
});

test('builds a safe OIDC return path with only the public request ID', () => {
  assert.equal(
    model.oidcReturnPath('https://mesh.example/?safe=1&poll_secret=bad#login', requestID),
    `/?safe=1&mesh_desktop_request=${requestID}#login`,
  );
  assert.throws(() => model.oidcReturnPath('https://mesh.example/', 'desktop_short'), /request is invalid/);
});

test('requires authentication and submits exact approve and deny decisions', async () => {
  assert.throws(
    () => model.createApprovalFlow({ requestID, authenticated: false, decide() {} }),
    /authenticated browser session is required/,
  );
  for (const decision of ['approve', 'deny']) {
    const calls = [];
    const flow = model.createApprovalFlow({
      requestID, authenticated: true,
      decide: async (path, submitted) => { calls.push({ path, submitted }); },
    });
    const result = await flow.submit(decision);
    assert.deepEqual(result, { state: decision === 'approve' ? 'approved' : 'denied' });
    assert.deepEqual(calls, [{
      path: `/api/v1/auth/desktop/${requestID}/decision`,
      submitted: decision,
    }]);
  }
});

test('coalesces duplicate clicks and maps missing or expired records to a terminal result', async () => {
  let calls = 0;
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const flow = model.createApprovalFlow({
    requestID, authenticated: true,
    decide: async () => { calls += 1; await gate; },
  });
  const first = flow.submit('approve');
  const duplicate = flow.submit('approve');
  assert.equal(calls, 1);
  release();
  assert.deepEqual(await first, { state: 'approved' });
  assert.deepEqual(await duplicate, { state: 'approved' });
  assert.equal(calls, 1);
  await assert.rejects(() => flow.submit('approve'), /already complete/);

  for (const status of [404, 409]) {
    const expired = model.createApprovalFlow({
      requestID, authenticated: true,
      decide: async () => { const error = new Error('unavailable'); error.status = status; throw error; },
    });
    assert.deepEqual(await expired.submit('deny'), { state: 'expired' });
  }
});
