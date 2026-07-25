(function publishMeshDesktopAuthorization(root, factory) {
  const adapter = factory();
  if (typeof module === 'object' && module.exports) module.exports = adapter;
  if (root) root.MeshDesktopAuthorization = adapter;
}(typeof globalThis === 'undefined' ? this : globalThis, function buildMeshDesktopAuthorizationAdapter() {
  'use strict';

  const requestParameter = 'mesh_desktop_request';
  const requestIDPattern = /^desktop_[A-Za-z0-9_-]{43}$/u;

  function validRequestID(value) {
    return typeof value === 'string' && requestIDPattern.test(value);
  }

  function secretParameter(name) {
    return typeof name === 'string' && /(?:poll.*secret|secret.*poll)/iu.test(name.replace(/[^A-Za-z]/gu, ''));
  }

  function cleanURL(input) {
    const current = new URL(input);
    const requestValues = current.searchParams.getAll(requestParameter);
    let containsSecret = secretParameter(current.hash);
    if (containsSecret) current.hash = '';
    for (const key of [...current.searchParams.keys()]) {
      if (secretParameter(key)) {
        containsSecret = true;
        current.searchParams.delete(key);
      }
    }
    current.searchParams.delete(requestParameter);
    return { current, requestValues, containsSecret };
  }

  function relativeURL(value) {
    return `${value.pathname}${value.search}${value.hash}`;
  }

  function captureLaunch(href, browserHistory) {
    if (!browserHistory || typeof browserHistory.replaceState !== 'function') throw new Error('Desktop authorization history cleanup is unavailable');
    const { current, requestValues, containsSecret } = cleanURL(href);
    if (requestValues.length > 0 || containsSecret) browserHistory.replaceState(null, '', relativeURL(current));
    if (requestValues.length === 0) return Object.freeze({ requestID: '', invalid: containsSecret });
    const valid = requestValues.length === 1 && validRequestID(requestValues[0]) && !containsSecret;
    return Object.freeze({ requestID: valid ? requestValues[0] : '', invalid: !valid });
  }

  function oidcReturnPath(href, requestID) {
    const { current } = cleanURL(href);
    if (requestID !== '') {
      if (!validRequestID(requestID)) throw new Error('Desktop authorization request is invalid');
      current.searchParams.set(requestParameter, requestID);
    }
    return relativeURL(current);
  }

  function decisionPath(requestID) {
    if (!validRequestID(requestID)) throw new Error('Desktop authorization request is invalid');
    return `/api/v1/auth/desktop/${encodeURIComponent(requestID)}/decision`;
  }

  function createApprovalFlow({ requestID, authenticated, decide }) {
    if (!validRequestID(requestID)) throw new Error('Desktop authorization request is invalid');
    if (authenticated !== true) throw new Error('An authenticated browser session is required');
    if (typeof decide !== 'function') throw new Error('Desktop authorization decision transport is unavailable');
    let pending = null;
    let completed = false;
    async function submit(decision) {
      if (decision !== 'approve' && decision !== 'deny') throw new Error('Desktop authorization decision is invalid');
      if (completed) throw new Error('Desktop authorization request is already complete');
      if (pending) return pending;
      pending = (async () => {
        try {
          await decide(decisionPath(requestID), decision);
          completed = true;
          return Object.freeze({ state: decision === 'approve' ? 'approved' : 'denied' });
        } catch (error) {
          if (error && (error.status === 404 || error.status === 409)) {
            completed = true;
            return Object.freeze({ state: 'expired' });
          }
          throw error;
        } finally {
          pending = null;
        }
      })();
      return pending;
    }
    return Object.freeze({ submit });
  }

  return Object.freeze({
    REQUEST_PARAMETER: requestParameter,
    captureLaunch,
    createApprovalFlow,
    decisionPath,
    oidcReturnPath,
    validRequestID,
  });
}));
