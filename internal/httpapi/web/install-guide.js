(function publishMeshInstallGuide(root, factory) {
  const guide = factory();
  if (typeof module === 'object' && module.exports) module.exports = guide;
  if (root) root.MeshInstallGuide = guide;
}(typeof globalThis === 'undefined' ? this : globalThis, function buildMeshInstallGuide() {
  'use strict';

  const SCHEMA = 'mesh-install-guide-v2';

  function fail(message) {
    throw new Error(`Invalid install guide: ${message}`);
  }

  function isRecord(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }

  function exactObject(value, required, optional, name) {
    if (!isRecord(value)) fail(`${name} must be an object`);
    const allowed = new Set([...required, ...optional]);
    for (const key of required) {
      if (!Object.prototype.hasOwnProperty.call(value, key)) fail(`${name}.${key} is required`);
    }
    for (const key of Object.keys(value)) {
      if (!allowed.has(key)) fail(`${name}.${key} is not allowed`);
    }
    return value;
  }

  function canonicalObjectURL(raw, field) {
    if (typeof raw !== 'string' || raw.length === 0 || raw.length > 4096 || /[\s\u0000-\u001f\u007f]/u.test(raw)) {
      fail(`${field} is invalid`);
    }

    let parsed;
    try {
      parsed = new URL(raw);
    } catch (_) {
      fail(`${field} is invalid`);
    }
    if (parsed.protocol !== 'https:' || parsed.username !== '' || parsed.password !== '' ||
      parsed.search !== '' || parsed.hash !== '' || parsed.hostname === '' ||
      parsed.pathname === '' || parsed.pathname === '/' || parsed.pathname.endsWith('/') ||
      parsed.pathname.includes('//') || raw.includes('%') || raw.includes("'") || parsed.href !== raw) {
      fail(`${field} must be one canonical HTTPS object URL`);
    }

    const authorityEnd = raw.indexOf('/', 'https://'.length);
    const authority = authorityEnd === -1 ? '' : raw.slice('https://'.length, authorityEnd);
    if (authority === '' || authority !== authority.toLowerCase() || authority.endsWith(':') || parsed.port === '443') {
      fail(`${field} authority is not canonical`);
    }
    return raw;
  }

  function canonicalBundleURL(raw) {
    return canonicalObjectURL(raw, 'linux.bundle_url');
  }

  function canonicalBootstrapHandoffURL(raw) {
    return canonicalObjectURL(raw, 'linux.bootstrap_handoff_url');
  }

  function validate(raw) {
    exactObject(raw, ['schema', 'linux'], [], 'response');
    if (raw.schema !== SCHEMA) fail('schema is unsupported');
    const optional = ['bootstrap_handoff_url'];
    if (raw.linux && raw.linux.online_available === true) optional.push('bundle_url');
    exactObject(raw.linux, ['online_available'], optional, 'linux');
    if (typeof raw.linux.online_available !== 'boolean') fail('linux.online_available is invalid');

    let bundleURL = null;
    if (raw.linux.online_available) {
      if (!Object.prototype.hasOwnProperty.call(raw.linux, 'bundle_url')) fail('linux.bundle_url is required');
      bundleURL = canonicalBundleURL(raw.linux.bundle_url);
    }
    const bootstrapHandoffURL = Object.prototype.hasOwnProperty.call(raw.linux, 'bootstrap_handoff_url')
      ? canonicalBootstrapHandoffURL(raw.linux.bootstrap_handoff_url)
      : null;
    return Object.freeze({
      schema: SCHEMA,
      linux: Object.freeze({ onlineAvailable: raw.linux.online_available, bundleURL, bootstrapHandoffURL }),
    });
  }

  function shellQuote(value) {
    if (typeof value !== 'string' || value.includes('\u0000')) fail('shell value is invalid');
    return `'${value.replaceAll("'", "'\\''")}'`;
  }

  function canonicalOrigin(raw) {
    if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2048 || /[\s\u0000-\u001f\u007f]/u.test(raw)) {
      fail('origin is invalid');
    }
    let parsed;
    try {
      parsed = new URL(raw);
    } catch (_) {
      fail('origin is invalid');
    }
    if ((parsed.protocol !== 'https:' && parsed.protocol !== 'http:') || parsed.username !== '' ||
      parsed.password !== '' || parsed.search !== '' || parsed.hash !== '' || parsed.hostname === '' ||
      parsed.pathname !== '/' || parsed.origin !== raw) {
      fail('origin must be one canonical HTTP or HTTPS origin');
    }
    return raw;
  }

  function validatedModel(model) {
    exactObject(model, ['schema', 'linux'], [], 'model');
    if (model.schema !== SCHEMA) fail('model.schema is unsupported');
    exactObject(model.linux, ['onlineAvailable', 'bundleURL', 'bootstrapHandoffURL'], [], 'model.linux');
    if (typeof model.linux.onlineAvailable !== 'boolean') fail('model.linux.onlineAvailable is invalid');
    if (model.linux.onlineAvailable) canonicalBundleURL(model.linux.bundleURL);
    else if (model.linux.bundleURL !== null) fail('model.linux.bundleURL must be null when online installation is unavailable');
    if (model.linux.bootstrapHandoffURL !== null) canonicalBootstrapHandoffURL(model.linux.bootstrapHandoffURL);
    return model;
  }

  function commands(origin, model) {
    const server = canonicalOrigin(origin);
    const guide = validatedModel(model);
    const install = guide.linux.onlineAvailable
      ? `sudo ./mesh-install install-online ${shellQuote(guide.linux.bundleURL)}`
      : null;
    const enrollInvocation = [
      "printf '%s\\n' \"$MESH_TOKEN_INPUT\" | sudo /usr/local/bin/meshctl enroll",
      `--server ${shellQuote(server)}`,
      '--token-file -',
      '--state /var/lib/mesh-agent/state.json',
      '--output /var/lib/mesh-agent/nebula',
      '--nebula /usr/local/bin/nebula',
      '--nebula-cert /usr/local/bin/nebula-cert',
    ].join(' ');
    const enroll = [
      "read -rsp 'Enrollment token: ' MESH_TOKEN_INPUT",
      "printf '\\n'",
      enrollInvocation,
    ].join(' && ');
    return Object.freeze({
      install,
      enroll: `${enroll}; MESH_ENROLL_STATUS=$?; unset MESH_TOKEN_INPUT; test "$MESH_ENROLL_STATUS" -eq 0`,
      activate: 'sudo /usr/local/bin/mesh-install activate',
    });
  }

  return Object.freeze({ SCHEMA, validate, shellQuote, commands });
}));
