(function publishMeshHealth(root, factory) {
  const adapter = factory();
  if (typeof module === 'object' && module.exports) module.exports = adapter;
  if (root) root.MeshHealth = adapter;
}(typeof globalThis === 'undefined' ? this : globalThis, function buildMeshHealthAdapter() {
  'use strict';

  const MAX_SNAPSHOT_AGE_MS = 60 * 1000;
  const MAX_FUTURE_SKEW_MS = 30 * 1000;
  const severityRank = Object.freeze({ healthy: 0, warning: 1, critical: 2 });
  const alertDefinitions = Object.freeze({
    agent_degraded: { label: 'Lifecycle agent reports degraded', short: 'Degraded', scope: 'node', severities: ['critical'] },
    agent_error: { label: 'Lifecycle agent reports an error', short: 'Agent error', scope: 'node', severities: ['warning'] },
    certificate_expired: { label: 'Nebula certificate has expired', short: 'Cert expired', scope: 'node', severities: ['critical'] },
    certificate_fingerprint_drift: { label: 'Running certificate identity differs from desired state', short: 'Cert identity drift', scope: 'node', severities: ['critical'] },
    certificate_generation_drift: { label: 'Certificate generation has not converged', short: 'Cert syncing', scope: 'node', severities: ['warning'] },
    certificate_metadata_missing: { label: 'Certificate lifecycle metadata is missing', short: 'Cert metadata missing', scope: 'node', severities: ['critical'] },
    certificate_renewal_due: { label: 'Nebula certificate is eligible for renewal', short: 'Renewal due', scope: 'node', severities: ['warning'] },
    config_digest_drift: { label: 'Applied configuration digest does not match the signed desired state', short: 'Config integrity drift', scope: 'node', severities: ['critical'] },
    config_drift: { label: 'Configuration revision has not converged', short: 'Config syncing', scope: 'node', severities: ['warning'] },
    control_time_invalid: { label: 'Control-plane configuration time is invalid', short: 'Control time invalid', scope: 'network', severities: ['critical'] },
    credential_expired: { label: 'Lifecycle agent credential has expired', short: 'Credential expired', scope: 'node', severities: ['critical'] },
    credential_expiring: { label: 'Lifecycle agent credential is nearing expiry', short: 'Credential expiring', scope: 'node', severities: ['warning'] },
    credential_metadata_missing: { label: 'Lifecycle agent credential expiry is missing', short: 'Credential metadata missing', scope: 'node', severities: ['critical'] },
    heartbeat_late: { label: 'Lifecycle heartbeat is late', short: 'Heartbeat late', scope: 'node', severities: ['warning'] },
    heartbeat_missing: { label: 'Lifecycle heartbeat has not been observed', short: 'Heartbeat missing', scope: 'node', severities: ['warning', 'critical'] },
    heartbeat_offline: { label: 'Lifecycle heartbeat is offline', short: 'Offline', scope: 'node', severities: ['critical'] },
    heartbeat_time_invalid: { label: 'Lifecycle heartbeat time is invalid', short: 'Telemetry time invalid', scope: 'node', severities: ['critical'] },
    lighthouse_single: { label: 'Only one operational lighthouse is available', short: 'Single lighthouse', scope: 'network', severities: ['warning'] },
    lighthouse_unavailable: { label: 'No operational lighthouse is available', short: 'No lighthouse', scope: 'network', severities: ['critical'] },
    nebula_stopped: { label: 'Nebula is not running', short: 'Nebula stopped', scope: 'node', severities: ['critical'] },
    projection_limit_exceeded: { label: 'Fleet health projection limit was exceeded', short: 'Projection limit exceeded', scope: 'network', severities: ['critical'] },
    stale_revocation: { label: 'A node has not applied a confirmed revocation update', short: 'Revocation stale', scope: 'node', severities: ['critical'] },
    telemetry_invalid: { label: 'Lifecycle telemetry is invalid', short: 'Telemetry invalid', scope: 'node', severities: ['critical'] },
  });
  const evidenceKeys = Object.freeze([
    'since_at', 'last_seen_at', 'age_seconds', 'threshold_seconds',
    'desired_config_revision', 'applied_config_revision',
    'desired_certificate_generation', 'applied_certificate_generation',
    'expires_at', 'renew_after', 'reported_status', 'nebula_running',
    'error_reported', 'active_lighthouses', 'healthy_lighthouses',
    'required_lighthouses', 'active_revocations', 'revocation_at', 'control_time_at',
    'observed_lighthouses', 'projection_limit',
  ]);
  const evidenceTimeKeys = new Set(['since_at', 'last_seen_at', 'expires_at', 'renew_after', 'revocation_at', 'control_time_at']);
  const evidenceIntegerKeys = new Set([
    'age_seconds', 'threshold_seconds', 'desired_config_revision', 'applied_config_revision',
    'desired_certificate_generation', 'applied_certificate_generation', 'active_lighthouses',
    'healthy_lighthouses', 'required_lighthouses', 'active_revocations', 'observed_lighthouses', 'projection_limit',
  ]);
  const evidenceBooleanKeys = new Set(['nebula_running', 'error_reported']);

  function fail(message) {
    throw new Error(`Invalid authoritative fleet health snapshot: ${message}`);
  }

  function isRecord(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }

  function exactObject(value, required, optional, name) {
    if (!isRecord(value)) fail(`${name} must be an object`);
    const allowed = new Set([...required, ...optional]);
    for (const key of required) if (!Object.prototype.hasOwnProperty.call(value, key)) fail(`${name}.${key} is required`);
    for (const key of Object.keys(value)) if (!allowed.has(key)) fail(`${name}.${key} is not allowed`);
    return value;
  }

  function text(value, name, maximum = 256) {
    if (typeof value !== 'string' || value.length === 0 || value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)) fail(`${name} is invalid`);
    return value;
  }

  function integer(value, name, maximum = Number.MAX_SAFE_INTEGER) {
    if (!Number.isSafeInteger(value) || value < 0 || value > maximum) fail(`${name} is invalid`);
    return value;
  }

  function routedSubnet(value, name) {
    text(value, name, 18);
    const match = /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\/(\d|[12]\d|3[0-2])$/u.exec(value);
    if (!match) fail(`${name} is not a canonical IPv4 CIDR`);
    const octets = match.slice(1, 5).map(Number);
    const bits = Number(match[5]);
    if (bits < 1 || octets.some((octet) => octet > 255)) fail(`${name} is not a routed unicast prefix`);
    const address = (((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3]) >>> 0;
    const mask = (0xffffffff << (32 - bits)) >>> 0;
    if ((address & mask) >>> 0 !== address || octets[0] === 0 || octets[0] === 127 || octets[0] >= 224 || (octets[0] === 169 && octets[1] === 254)) fail(`${name} is not a canonical routed unicast prefix`);
    return value;
  }

  function compareRoutedSubnets(left, right) {
    const parts = (value) => {
      const [address, bits] = value.split('/');
      const octets = address.split('.').map(Number);
      return [(((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3]) >>> 0, Number(bits)];
    };
    const leftParts = parts(left);
    const rightParts = parts(right);
    return leftParts[0] - rightParts[0] || leftParts[1] - rightParts[1];
  }

  function boolean(value, name) {
    if (typeof value !== 'boolean') fail(`${name} is invalid`);
    return value;
  }

  function severity(value, name) {
    if (!Object.prototype.hasOwnProperty.call(severityRank, value)) fail(`${name} is invalid`);
    return value;
  }

  function timestamp(value, name) {
    if (typeof value !== 'string' || value.length > 64) fail(`${name} is invalid`);
    const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/.exec(value);
    if (!match) fail(`${name} is invalid`);
    const year = Number(match[1]);
    const month = Number(match[2]);
    const day = Number(match[3]);
    const hour = Number(match[4]);
    const minute = Number(match[5]);
    const second = Number(match[6]);
    const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    const daysInMonth = [0, 31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    const offsetHour = match[10] === undefined ? 0 : Number(match[10]);
    const offsetMinute = match[11] === undefined ? 0 : Number(match[11]);
    if (month < 1 || month > 12 || day < 1 || day > daysInMonth[month] || hour > 23 || minute > 59 || second > 59 || offsetHour > 23 || offsetMinute > 59) fail(`${name} is invalid`);
    const milliseconds = Date.parse(value);
    if (!Number.isFinite(milliseconds)) fail(`${name} is invalid`);
    return Object.freeze({ value, milliseconds });
  }

  function optionalTimestamp(value, name) {
    return value === undefined ? null : timestamp(value, name);
  }

  // HTTP Date gives the server clock at header emission. Add the monotonic time
  // spent receiving and parsing the body so large responses cannot get a fresh
  // 60-second budget only after their contents finally arrive.
  function responseAdjustedNow(responseDateMS, headersReceivedAtMS, bodyParsedAtMS) {
    if (!Number.isFinite(responseDateMS) || !Number.isFinite(headersReceivedAtMS) || !Number.isFinite(bodyParsedAtMS) ||
      headersReceivedAtMS < 0 || bodyParsedAtMS < headersReceivedAtMS) fail('response timing is invalid');
    const adjusted = responseDateMS + (bodyParsedAtMS - headersReceivedAtMS);
    if (!Number.isFinite(adjusted)) fail('response timing is invalid');
    return adjusted;
  }

  function isGoZeroTimestamp(value) {
    return value !== null && value.milliseconds === Date.parse('0001-01-01T00:00:00Z');
  }

  function array(value, name, maximum = 100000) {
    if (!Array.isArray(value) || value.length > maximum) fail(`${name} is invalid`);
    return value;
  }

  function compareText(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
  }

  function expectedSeverity(alerts) {
    let result = 'healthy';
    for (const alert of alerts) if (severityRank[alert.severity] > severityRank[result]) result = alert.severity;
    return result;
  }

  function validateEvidence(raw, name) {
    exactObject(raw, [], evidenceKeys, name);
    const result = {};
    for (const key of Object.keys(raw)) {
      if (evidenceTimeKeys.has(key)) result[key] = timestamp(raw[key], `${name}.${key}`).value;
      else if (evidenceIntegerKeys.has(key)) result[key] = integer(raw[key], `${name}.${key}`);
      else if (evidenceBooleanKeys.has(key)) result[key] = boolean(raw[key], `${name}.${key}`);
      else if (key === 'reported_status') {
        if (raw[key] !== 'healthy' && raw[key] !== 'degraded') fail(`${name}.${key} is invalid`);
        result[key] = raw[key];
      }
    }
    return Object.freeze(result);
  }

  function validateEvidenceForCode(code, evidence, name) {
    const rules = {
      agent_degraded: [['reported_status'], []],
      agent_error: [['error_reported'], []],
      certificate_expired: [['expires_at'], []],
      certificate_fingerprint_drift: [['desired_certificate_generation', 'applied_certificate_generation'], []],
      certificate_generation_drift: [['desired_certificate_generation', 'applied_certificate_generation'], []],
      certificate_metadata_missing: [[], []],
      certificate_renewal_due: [['expires_at', 'renew_after'], []],
      config_digest_drift: [['desired_config_revision', 'applied_config_revision'], []],
      config_drift: [['desired_config_revision', 'applied_config_revision'], []],
      control_time_invalid: [['control_time_at'], []],
      credential_expired: [['expires_at'], []],
      credential_expiring: [['expires_at', 'threshold_seconds'], []],
      credential_metadata_missing: [[], []],
      heartbeat_late: [['since_at', 'age_seconds', 'threshold_seconds'], []],
      heartbeat_missing: [['threshold_seconds'], ['since_at', 'age_seconds']],
      heartbeat_offline: [['since_at', 'age_seconds', 'threshold_seconds'], []],
      heartbeat_time_invalid: [[], ['last_seen_at', 'since_at']],
      lighthouse_single: [['active_lighthouses', 'healthy_lighthouses', 'required_lighthouses'], []],
      lighthouse_unavailable: [['active_lighthouses', 'healthy_lighthouses', 'required_lighthouses'], []],
      nebula_stopped: [['nebula_running'], []],
      projection_limit_exceeded: [['observed_lighthouses', 'projection_limit'], []],
      stale_revocation: [['last_seen_at', 'desired_config_revision', 'applied_config_revision', 'active_revocations', 'revocation_at'], []],
      telemetry_invalid: [[], []],
    };
    const rule = rules[code];
    if (!rule) fail(`${name} has no evidence contract`);
    const [required, optional] = rule;
    const allowed = new Set([...required, ...optional]);
    for (const key of required) if (!Object.prototype.hasOwnProperty.call(evidence, key)) fail(`${name}.${key} is required`);
    for (const key of Object.keys(evidence)) if (!allowed.has(key)) fail(`${name}.${key} is not valid for ${code}`);
    if (code === 'agent_degraded' && evidence.reported_status !== 'degraded') fail(`${name}.reported_status must be degraded`);
    if (code === 'agent_error' && evidence.error_reported !== true) fail(`${name}.error_reported must be true`);
    if (code === 'nebula_stopped' && evidence.nebula_running !== false) fail(`${name}.nebula_running must be false`);
    if (code === 'heartbeat_missing' && ((evidence.since_at === undefined) !== (evidence.age_seconds === undefined))) fail(`${name} has incomplete heartbeat evidence`);
    if (code === 'heartbeat_time_invalid' && (Boolean(evidence.last_seen_at) === Boolean(evidence.since_at))) fail(`${name} must carry exactly one invalid time`);
  }

  function validateAlert(raw, name, expectedNodeID = '') {
    exactObject(raw, ['severity', 'code', 'scope', 'evidence'], ['node_id'], name);
    const code = text(raw.code, `${name}.code`, 64);
    if (!Object.prototype.hasOwnProperty.call(alertDefinitions, code)) fail(`${name}.code is not allowlisted`);
    const definition = alertDefinitions[code];
    const alertSeverity = severity(raw.severity, `${name}.severity`);
    if (!definition.severities.includes(alertSeverity)) fail(`${name}.severity does not match its code`);
    if (raw.scope !== definition.scope) fail(`${name}.scope does not match its code`);
    let nodeID = '';
    if (definition.scope === 'node') {
      nodeID = text(raw.node_id, `${name}.node_id`, 128);
      if (expectedNodeID && nodeID !== expectedNodeID) fail(`${name}.node_id does not match its node`);
    } else if (raw.node_id !== undefined) {
      fail(`${name}.node_id is not valid for a network alert`);
    }
    const evidence = validateEvidence(raw.evidence, `${name}.evidence`);
    validateEvidenceForCode(code, evidence, `${name}.evidence`);
    return Object.freeze({ severity: alertSeverity, code, scope: definition.scope, nodeID, evidence });
  }

  function alertKey(alert) {
    const evidence = Object.keys(alert.evidence).sort(compareText).map((key) => `${key}=${String(alert.evidence[key])}`).join('&');
    return `${alert.severity}\u0000${alert.code}\u0000${alert.scope}\u0000${alert.nodeID}\u0000${evidence}`;
  }

  function assertAlertOrder(alerts, name) {
    for (let index = 1; index < alerts.length; index += 1) {
      const previous = alerts[index - 1];
      const current = alerts[index];
      const outOfOrder = severityRank[previous.severity] < severityRank[current.severity] ||
        (previous.severity === current.severity && (
          compareText(previous.code, current.code) > 0 ||
          (previous.code === current.code && (compareText(previous.scope, current.scope) > 0 ||
            (previous.scope === current.scope && compareText(previous.nodeID, current.nodeID) > 0)))));
      if (outOfOrder) fail(`${name} is not deterministically ordered`);
    }
  }

  function validateNode(raw, name, desiredRevision, generatedAtMS, policy) {
    const required = [
      'id', 'name', 'ip', 'routed_subnets', 'site', 'failure_domain', 'role', 'lifecycle_status', 'heartbeat_sequence', 'phase', 'severity', 'operational', 'rollout_current',
      'nebula_running', 'desired_config_revision', 'applied_config_revision', 'desired_certificate_generation',
      'applied_certificate_generation', 'alerts',
    ];
    const optional = ['last_seen_at', 'agent_status', 'certificate_expires_at', 'certificate_renew_after', 'agent_credential_expires_at'];
    exactObject(raw, required, optional, name);
    const id = text(raw.id, `${name}.id`, 128);
		const routedSubnets = array(raw.routed_subnets, `${name}.routed_subnets`, 8).map((entry, index) => routedSubnet(entry, `${name}.routed_subnets[${index}]`));
		for (let index = 1; index < routedSubnets.length; index += 1) if (compareRoutedSubnets(routedSubnets[index - 1], routedSubnets[index]) >= 0) fail(`${name}.routed_subnets is not deterministically ordered`);
		const site = text(raw.site, `${name}.site`, 63);
		const failureDomain = text(raw.failure_domain, `${name}.failure_domain`, 63);
		if (!/^[a-z0-9][a-z0-9._-]{0,62}$/u.test(site) || !/^[a-z0-9][a-z0-9._-]{0,62}$/u.test(failureDomain)) fail(`${name} topology metadata is invalid`);
    const lifecycleStatus = raw.lifecycle_status;
    if (!['pending', 'active', 'revoked'].includes(lifecycleStatus)) fail(`${name}.lifecycle_status is invalid`);
    const phase = raw.phase;
    if (!['setup', 'active', 'revoked'].includes(phase)) fail(`${name}.phase is invalid`);
    if ((lifecycleStatus === 'pending' && phase !== 'setup') || (lifecycleStatus === 'revoked' && phase !== 'revoked') || (lifecycleStatus === 'active' && phase === 'revoked')) fail(`${name}.phase conflicts with lifecycle status`);
    const nodeSeverity = severity(raw.severity, `${name}.severity`);
    const alerts = array(raw.alerts, `${name}.alerts`, 64).map((entry, index) => validateAlert(entry, `${name}.alerts[${index}]`, id));
    assertAlertOrder(alerts, `${name}.alerts`);
    if (expectedSeverity(alerts) !== nodeSeverity) fail(`${name}.severity does not match alerts`);
    const desiredConfigRevision = integer(raw.desired_config_revision, `${name}.desired_config_revision`);
    if (desiredConfigRevision !== desiredRevision) fail(`${name}.desired_config_revision does not match its network`);
    const lastSeen = optionalTimestamp(raw.last_seen_at, `${name}.last_seen_at`);
    const heartbeatSequence = integer(raw.heartbeat_sequence, `${name}.heartbeat_sequence`);
    if (lifecycleStatus === 'pending' && heartbeatSequence !== 0) fail(`${name}.heartbeat_sequence conflicts with pending lifecycle state`);
    if (lifecycleStatus === 'active' && ((lastSeen === null) !== (heartbeatSequence === 0))) fail(`${name}.heartbeat_sequence conflicts with lifecycle heartbeat evidence`);
    let agentStatus = '';
    if (raw.agent_status !== undefined) {
      if (raw.agent_status !== 'healthy' && raw.agent_status !== 'degraded') fail(`${name}.agent_status is invalid`);
      agentStatus = raw.agent_status;
    }
    const operational = boolean(raw.operational, `${name}.operational`);
    const rolloutCurrent = boolean(raw.rollout_current, `${name}.rollout_current`);
    const nebulaRunning = boolean(raw.nebula_running, `${name}.nebula_running`);
    const appliedConfigRevision = integer(raw.applied_config_revision, `${name}.applied_config_revision`);
    const desiredCertificateGeneration = integer(raw.desired_certificate_generation, `${name}.desired_certificate_generation`);
    const appliedCertificateGeneration = integer(raw.applied_certificate_generation, `${name}.applied_certificate_generation`);
    const certificateExpiresAt = optionalTimestamp(raw.certificate_expires_at, `${name}.certificate_expires_at`);
    const certificateRenewAfter = optionalTimestamp(raw.certificate_renew_after, `${name}.certificate_renew_after`);
    const agentCredentialExpiresAt = optionalTimestamp(raw.agent_credential_expires_at, `${name}.agent_credential_expires_at`);
    const hasAlert = (code) => alerts.some((alert) => alert.code === code);
    const telemetryInvalid = hasAlert('telemetry_invalid');
    const certificateLifecycleValid = Boolean(certificateExpiresAt && certificateRenewAfter &&
      !isGoZeroTimestamp(certificateRenewAfter) && certificateRenewAfter.milliseconds < certificateExpiresAt.milliseconds);
    if (lifecycleStatus === 'active') {
      if (lastSeen) {
        const heartbeatAgeMS = generatedAtMS - lastSeen.milliseconds;
        const expectedHeartbeatCode = heartbeatAgeMS < 0 ? 'heartbeat_time_invalid' : heartbeatAgeMS >= policy.heartbeat_offline_after_seconds * 1000 ? 'heartbeat_offline' : heartbeatAgeMS >= policy.heartbeat_warning_after_seconds * 1000 ? 'heartbeat_late' : '';
        for (const code of ['heartbeat_time_invalid', 'heartbeat_offline', 'heartbeat_late']) if (hasAlert(code) !== (code === expectedHeartbeatCode)) fail(`${name} heartbeat alerts are inconsistent`);
        if (hasAlert('agent_degraded') !== (agentStatus === 'degraded')) fail(`${name} agent_degraded is inconsistent`);
        if (hasAlert('nebula_stopped') !== !nebulaRunning) fail(`${name} nebula_stopped is inconsistent`);
        const revisionDrift = appliedConfigRevision !== desiredRevision;
        if (hasAlert('config_drift') && !revisionDrift) fail(`${name} config_drift is inconsistent`);
        if (!hasAlert('config_drift') && revisionDrift && !telemetryInvalid) fail(`${name} config_drift is inconsistent`);
        if (hasAlert('certificate_generation_drift') !== (appliedCertificateGeneration !== desiredCertificateGeneration)) fail(`${name} certificate_generation_drift is inconsistent`);
      }
      const certificateMetadataMissing = !certificateLifecycleValid;
      const expectedCertificateCode = certificateMetadataMissing ? 'certificate_metadata_missing' : certificateExpiresAt.milliseconds <= generatedAtMS ? 'certificate_expired' : certificateRenewAfter.milliseconds <= generatedAtMS ? 'certificate_renewal_due' : '';
      for (const code of ['certificate_metadata_missing', 'certificate_expired', 'certificate_renewal_due']) if (hasAlert(code) !== (code === expectedCertificateCode)) fail(`${name} certificate lifecycle alerts are inconsistent`);
      const expectedCredentialCode = !agentCredentialExpiresAt ? 'credential_metadata_missing' : agentCredentialExpiresAt.milliseconds <= generatedAtMS ? 'credential_expired' : agentCredentialExpiresAt.milliseconds - generatedAtMS <= policy.credential_warning_before_seconds * 1000 ? 'credential_expiring' : '';
      for (const code of ['credential_metadata_missing', 'credential_expired', 'credential_expiring']) if (hasAlert(code) !== (code === expectedCredentialCode)) fail(`${name} credential lifecycle alerts are inconsistent`);
    }
    if ((operational || rolloutCurrent) && lifecycleStatus !== 'active') fail(`${name} reports active state for a non-active node`);
    if (operational && phase !== 'active') fail(`${name}.operational conflicts with phase`);
    if (operational && agentStatus !== 'healthy') fail(`${name}.operational requires healthy agent status`);
    if (operational && (!lastSeen || lastSeen.milliseconds > generatedAtMS || generatedAtMS - lastSeen.milliseconds >= policy.heartbeat_offline_after_seconds * 1000 || !nebulaRunning || !rolloutCurrent || nodeSeverity === 'critical' || !certificateLifecycleValid || certificateExpiresAt.milliseconds <= generatedAtMS || !agentCredentialExpiresAt || agentCredentialExpiresAt.milliseconds <= generatedAtMS)) fail(`${name}.operational is internally inconsistent`);
    const rolloutEvidenceInvalid = lifecycleStatus !== 'active' || !lastSeen || lastSeen.milliseconds > generatedAtMS ||
      generatedAtMS - lastSeen.milliseconds >= policy.heartbeat_offline_after_seconds * 1000 || agentStatus === '' ||
      !nebulaRunning || appliedConfigRevision !== desiredRevision || appliedCertificateGeneration !== desiredCertificateGeneration ||
      hasAlert('config_digest_drift') || hasAlert('certificate_fingerprint_drift') || !certificateLifecycleValid ||
      certificateExpiresAt.milliseconds <= generatedAtMS || !agentCredentialExpiresAt || agentCredentialExpiresAt.milliseconds <= generatedAtMS;
    if (rolloutCurrent && rolloutEvidenceInvalid) fail(`${name}.rollout_current conflicts with authoritative state`);
    if (lifecycleStatus === 'active' && phase === 'active' && nodeSeverity === 'healthy' && alerts.length === 0 && (!operational || !lastSeen || generatedAtMS - lastSeen.milliseconds >= policy.heartbeat_warning_after_seconds * 1000 || certificateRenewAfter.milliseconds <= generatedAtMS || agentCredentialExpiresAt.milliseconds - generatedAtMS <= policy.credential_warning_before_seconds * 1000)) fail(`${name} is falsely healthy`);
    if (lifecycleStatus === 'active' && lastSeen !== null && agentStatus === '') {
      if (!telemetryInvalid || operational) fail(`${name}.agent_status is required after a heartbeat unless telemetry is explicitly invalid`);
    }
    if (rolloutCurrent && lastSeen === null) fail(`${name}.rollout_current requires a heartbeat`);
    return Object.freeze({
      id,
      name: text(raw.name, `${name}.name`, 128),
      ip: text(raw.ip, `${name}.ip`, 64),
		routed_subnets: Object.freeze(routedSubnets),
		site,
		failure_domain: failureDomain,
      role: raw.role === 'member' || raw.role === 'lighthouse' ? raw.role : fail(`${name}.role is invalid`),
      status: lifecycleStatus,
      lifecycleStatus,
      heartbeat_sequence: heartbeatSequence,
      phase,
      severity: nodeSeverity,
      operational,
      rolloutCurrent,
      last_seen_at: lastSeen === null ? '' : lastSeen.value,
      agent_status: agentStatus,
      nebula_running: nebulaRunning,
      desiredConfigRevision,
      applied_config_revision: appliedConfigRevision,
      certificate_generation: desiredCertificateGeneration,
      applied_certificate_generation: appliedCertificateGeneration,
      certificate_expires_at: certificateExpiresAt?.value || '',
      certificate_renew_after: certificateRenewAfter?.value || '',
      agent_credential_expires_at: agentCredentialExpiresAt?.value || '',
      alerts: Object.freeze(alerts),
    });
  }

  function validateNetwork(raw, name) {
		exactObject(raw, ['id', 'name', 'cidr', 'listen_port', 'dns_settings', 'relay_settings', 'desired_config_revision', 'config_updated_at'], [], name);
    const listenPort = integer(raw.listen_port, `${name}.listen_port`, 65535);
    if (listenPort === 0) fail(`${name}.listen_port is invalid`);
		exactObject(raw.dns_settings, ['enabled', 'listen_port'], ['native_resolver', 'search_domain'], `${name}.dns_settings`);
		const dnsEnabled = boolean(raw.dns_settings.enabled, `${name}.dns_settings.enabled`);
		const dnsListenPort = integer(raw.dns_settings.listen_port, `${name}.dns_settings.listen_port`, 65535);
		if (dnsListenPort === 0 || (!dnsEnabled && dnsListenPort !== 53) || (dnsEnabled && dnsListenPort === listenPort)) fail(`${name}.dns_settings is invalid`);
		const nativeResolver = Object.prototype.hasOwnProperty.call(raw.dns_settings, 'native_resolver') ? boolean(raw.dns_settings.native_resolver, `${name}.dns_settings.native_resolver`) : false;
		const searchDomain = Object.prototype.hasOwnProperty.call(raw.dns_settings, 'search_domain') ? raw.dns_settings.search_domain : '';
		if (typeof searchDomain !== 'string' || (!nativeResolver && searchDomain !== '') || (nativeResolver && (!dnsEnabled || searchDomain.length < 1 || searchDomain.length > 253 || searchDomain !== searchDomain.toLowerCase() || searchDomain.endsWith('.') || searchDomain === 'local' || searchDomain.endsWith('.local') || searchDomain.split('.').some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))))) fail(`${name}.dns_settings native resolver is invalid`);
		exactObject(raw.relay_settings, ['enabled', 'relay_node_ids'], [], `${name}.relay_settings`);
		const relayEnabled = boolean(raw.relay_settings.enabled, `${name}.relay_settings.enabled`);
		const relayNodeIDs = array(raw.relay_settings.relay_node_ids, `${name}.relay_settings.relay_node_ids`, 8).map((nodeID, index) => text(nodeID, `${name}.relay_settings.relay_node_ids[${index}]`, 128));
		if ((!relayEnabled && relayNodeIDs.length !== 0) || (relayEnabled && relayNodeIDs.length === 0)) fail(`${name}.relay_settings is inconsistent`);
		for (let index = 0; index < relayNodeIDs.length; index += 1) {
			if (!/^[A-Za-z0-9_-]+$/u.test(relayNodeIDs[index]) || (index > 0 && compareText(relayNodeIDs[index - 1], relayNodeIDs[index]) >= 0)) fail(`${name}.relay_settings.relay_node_ids are not uniquely ordered`);
		}
    const configUpdatedAt = timestamp(raw.config_updated_at, `${name}.config_updated_at`);
    return Object.freeze({
      id: text(raw.id, `${name}.id`, 128),
      name: text(raw.name, `${name}.name`, 128),
      cidr: text(raw.cidr, `${name}.cidr`, 64),
      listen_port: listenPort,
		dns_settings: Object.freeze({ enabled: dnsEnabled, listen_port: dnsListenPort, native_resolver: nativeResolver, search_domain: searchDomain }),
		relay_settings: Object.freeze({ enabled: relayEnabled, relay_node_ids: Object.freeze(relayNodeIDs) }),
      config_revision: integer(raw.desired_config_revision, `${name}.desired_config_revision`),
      config_updated_at: configUpdatedAt.value,
      configUpdatedAtMS: configUpdatedAt.milliseconds,
    });
  }

  function validateNetworkSummary(raw, name) {
    const keys = ['overall', 'total_nodes', 'pending_nodes', 'active_nodes', 'revoked_nodes', 'setup_nodes', 'healthy_nodes', 'warning_nodes', 'critical_nodes', 'active_lighthouses', 'healthy_lighthouses'];
    exactObject(raw, keys, [], name);
    const result = { overall: severity(raw.overall, `${name}.overall`) };
    for (const key of keys.slice(1)) result[key] = integer(raw[key], `${name}.${key}`);
    return Object.freeze(result);
  }

  function validateCollectionSummary(raw, name) {
    const keys = ['overall', 'total_networks', 'healthy_networks', 'warning_networks', 'critical_networks', 'total_nodes', 'setup_nodes', 'active_nodes', 'revoked_nodes', 'healthy_nodes', 'warning_nodes', 'critical_nodes'];
    exactObject(raw, keys, [], name);
    const result = { overall: severity(raw.overall, `${name}.overall`) };
    for (const key of keys.slice(1)) result[key] = integer(raw[key], `${name}.${key}`);
    return Object.freeze(result);
  }

  function validateRollout(raw, name, desiredRevision) {
    const required = desiredRevision === undefined ? ['eligible_nodes', 'converged_nodes', 'drifted_nodes', 'unreported_nodes', 'percent'] : ['desired_config_revision', 'eligible_nodes', 'converged_nodes', 'drifted_nodes', 'unreported_nodes', 'percent'];
    exactObject(raw, required, [], name);
    if (desiredRevision !== undefined && integer(raw.desired_config_revision, `${name}.desired_config_revision`) !== desiredRevision) fail(`${name}.desired_config_revision does not match its network`);
    const result = {
      eligible_nodes: integer(raw.eligible_nodes, `${name}.eligible_nodes`),
      converged_nodes: integer(raw.converged_nodes, `${name}.converged_nodes`),
      drifted_nodes: integer(raw.drifted_nodes, `${name}.drifted_nodes`),
      unreported_nodes: integer(raw.unreported_nodes, `${name}.unreported_nodes`),
      percent: integer(raw.percent, `${name}.percent`, 100),
    };
    if (result.converged_nodes + result.drifted_nodes + result.unreported_nodes !== result.eligible_nodes) fail(`${name} categories do not sum to eligible nodes`);
    const expectedPercent = result.eligible_nodes === 0 ? 100 : Math.floor((100 * result.converged_nodes) / result.eligible_nodes);
    if (result.percent !== expectedPercent) fail(`${name}.percent is inconsistent`);
    if (result.eligible_nodes > 0 && result.percent === 100 && result.converged_nodes !== result.eligible_nodes) fail(`${name}.percent claims false convergence`);
    return Object.freeze(result);
  }

  function validatePolicy(raw, name) {
    const keys = ['heartbeat_warning_after_seconds', 'heartbeat_offline_after_seconds', 'credential_warning_before_seconds', 'required_healthy_lighthouses', 'evidence_source', 'overlay_reachability_observed'];
    exactObject(raw, keys, [], name);
    const result = {
      heartbeat_warning_after_seconds: integer(raw.heartbeat_warning_after_seconds, `${name}.heartbeat_warning_after_seconds`),
      heartbeat_offline_after_seconds: integer(raw.heartbeat_offline_after_seconds, `${name}.heartbeat_offline_after_seconds`),
      credential_warning_before_seconds: integer(raw.credential_warning_before_seconds, `${name}.credential_warning_before_seconds`),
      required_healthy_lighthouses: integer(raw.required_healthy_lighthouses, `${name}.required_healthy_lighthouses`, 32),
      evidence_source: text(raw.evidence_source, `${name}.evidence_source`, 64),
      overlay_reachability_observed: boolean(raw.overlay_reachability_observed, `${name}.overlay_reachability_observed`),
    };
    if (result.heartbeat_warning_after_seconds === 0 || result.heartbeat_offline_after_seconds <= result.heartbeat_warning_after_seconds || result.credential_warning_before_seconds === 0 || result.required_healthy_lighthouses === 0) fail(`${name} thresholds are invalid`);
    if (result.evidence_source !== 'authenticated_agent_heartbeat') fail(`${name}.evidence_source is not recognized`);
    return Object.freeze(result);
  }

  function validateNetworkReport(raw, name, policy, generatedAtMS) {
    exactObject(raw, ['network', 'summary', 'rollout', 'nodes', 'alerts'], [], name);
    const network = validateNetwork(raw.network, `${name}.network`);
    const summary = validateNetworkSummary(raw.summary, `${name}.summary`);
    const rollout = validateRollout(raw.rollout, `${name}.rollout`, network.config_revision);
    const nodes = array(raw.nodes, `${name}.nodes`).map((entry, index) => validateNode(entry, `${name}.nodes[${index}]`, network.config_revision, generatedAtMS, policy));
    for (let index = 1; index < nodes.length; index += 1) {
      const previous = nodes[index - 1];
      const current = nodes[index];
      if (compareText(previous.name, current.name) > 0 || (previous.name === current.name && compareText(previous.id, current.id) >= 0)) fail(`${name}.nodes are not uniquely and deterministically ordered`);
    }
    const nodeIDs = new Set(nodes.map((node) => node.id));
    if (nodeIDs.size !== nodes.length) fail(`${name}.nodes contain duplicate IDs`);
    const nodesByID = new Map(nodes.map((node) => [node.id, node]));
    for (const relayNodeID of network.relay_settings.relay_node_ids) {
      const relayNode = nodesByID.get(relayNodeID);
      if (!relayNode || relayNode.lifecycleStatus === 'revoked') fail(`${name}.network.relay_settings selects an unavailable node`);
    }
    const alerts = array(raw.alerts, `${name}.alerts`, 100000).map((entry, index) => validateAlert(entry, `${name}.alerts[${index}]`));
    assertAlertOrder(alerts, `${name}.alerts`);
    for (const alert of alerts) if (alert.scope === 'node' && !nodeIDs.has(alert.nodeID)) fail(`${name}.alerts references an unknown node`);
    const embeddedNodeAlerts = nodes.flatMap((node) => node.alerts).map(alertKey).sort(compareText);
    const reportNodeAlerts = alerts.filter((alert) => alert.scope === 'node').map(alertKey).sort(compareText);
    if (embeddedNodeAlerts.length !== reportNodeAlerts.length || embeddedNodeAlerts.some((key, index) => key !== reportNodeAlerts[index])) fail(`${name}.alerts does not match node alerts`);
    if (expectedSeverity(alerts) !== summary.overall) fail(`${name}.summary.overall does not match alerts`);
    if (network.configUpdatedAtMS > generatedAtMS) {
      const controlAlerts = alerts.filter((alert) => alert.code === 'control_time_invalid');
      if (controlAlerts.length !== 1 || Date.parse(controlAlerts[0].evidence.control_time_at) < network.configUpdatedAtMS) fail(`${name}.alerts does not cover invalid control time`);
    }

    const pendingNodes = nodes.filter((node) => node.lifecycleStatus === 'pending').length;
    const activeNodes = nodes.filter((node) => node.lifecycleStatus === 'active').length;
    const revokedNodes = nodes.filter((node) => node.lifecycleStatus === 'revoked').length;
    const setupNodes = nodes.filter((node) => node.phase === 'setup').length;
    const evaluatedActive = nodes.filter((node) => node.lifecycleStatus === 'active' && node.phase !== 'setup');
    const activeLighthouses = nodes.filter((node) => node.lifecycleStatus === 'active' && node.role === 'lighthouse').length;
    const healthyLighthouses = nodes.filter((node) => node.lifecycleStatus === 'active' && node.role === 'lighthouse' && node.operational).length;
    const expected = {
      total_nodes: nodes.length, pending_nodes: pendingNodes, active_nodes: activeNodes, revoked_nodes: revokedNodes,
      setup_nodes: setupNodes, healthy_nodes: evaluatedActive.filter((node) => node.severity === 'healthy').length,
      warning_nodes: evaluatedActive.filter((node) => node.severity === 'warning').length,
      critical_nodes: evaluatedActive.filter((node) => node.severity === 'critical').length,
      active_lighthouses: activeLighthouses, healthy_lighthouses: healthyLighthouses,
    };
    for (const [key, value] of Object.entries(expected)) if (summary[key] !== value) fail(`${name}.summary.${key} is inconsistent`);

    const lighthouseAlerts = alerts.filter((alert) => alert.code === 'lighthouse_unavailable' || alert.code === 'lighthouse_single');
    const expectedLighthouseCode = healthyLighthouses === 0 ? 'lighthouse_unavailable' : healthyLighthouses < policy.required_healthy_lighthouses ? 'lighthouse_single' : '';
    if ((expectedLighthouseCode === '' && lighthouseAlerts.length !== 0) || (expectedLighthouseCode !== '' && (lighthouseAlerts.length !== 1 || lighthouseAlerts[0].code !== expectedLighthouseCode))) fail(`${name}.alerts does not match lighthouse redundancy`);
    if (expectedLighthouseCode !== '') {
      const evidence = lighthouseAlerts[0].evidence;
      if (evidence.active_lighthouses !== activeLighthouses || evidence.healthy_lighthouses !== healthyLighthouses || evidence.required_lighthouses !== policy.required_healthy_lighthouses) fail(`${name}.lighthouse alert evidence is inconsistent`);
    }

    const active = nodes.filter((node) => node.lifecycleStatus === 'active');
    const expectedRollout = {
      eligible_nodes: active.length,
      converged_nodes: active.filter((node) => node.last_seen_at && node.rolloutCurrent).length,
      drifted_nodes: active.filter((node) => node.last_seen_at && !node.rolloutCurrent).length,
      unreported_nodes: active.filter((node) => !node.last_seen_at).length,
    };
    for (const [key, value] of Object.entries(expectedRollout)) if (rollout[key] !== value) fail(`${name}.rollout.${key} is inconsistent`);

    return Object.freeze({ network, summary, rollout, nodes: Object.freeze(nodes), alerts: Object.freeze(alerts) });
  }

  function validateFleetSnapshot(raw, nowMS = Date.now()) {
    exactObject(raw, ['generated_at', 'policy', 'summary', 'rollout', 'networks'], [], 'snapshot');
    if (!Number.isFinite(nowMS)) fail('validation time is invalid');
    const generatedAt = timestamp(raw.generated_at, 'snapshot.generated_at');
    if (generatedAt.milliseconds < nowMS - MAX_SNAPSHOT_AGE_MS) fail('snapshot.generated_at is stale');
    if (generatedAt.milliseconds > nowMS + MAX_FUTURE_SKEW_MS) fail('snapshot.generated_at is too far in the future');
    const policy = validatePolicy(raw.policy, 'snapshot.policy');
    const summary = validateCollectionSummary(raw.summary, 'snapshot.summary');
    const rollout = validateRollout(raw.rollout, 'snapshot.rollout');
    const reports = array(raw.networks, 'snapshot.networks').map((entry, index) => validateNetworkReport(entry, `snapshot.networks[${index}]`, policy, generatedAt.milliseconds));
    const networkIDs = new Set();
    const globalNodeIDs = new Set();
    for (const report of reports) {
      if (networkIDs.has(report.network.id)) fail('snapshot.networks contain duplicate IDs');
      networkIDs.add(report.network.id);
      for (const node of report.nodes) {
        if (globalNodeIDs.has(node.id)) fail('snapshot contains a duplicate node ID');
        globalNodeIDs.add(node.id);
      }
    }
    for (let index = 1; index < reports.length; index += 1) {
      const previous = reports[index - 1].network;
      const current = reports[index].network;
      if (compareText(previous.name, current.name) > 0 || (previous.name === current.name && compareText(previous.id, current.id) >= 0)) fail('snapshot.networks are not uniquely and deterministically ordered');
    }

    const expectedSummary = {
      total_networks: reports.length,
      healthy_networks: reports.filter((report) => report.summary.overall === 'healthy').length,
      warning_networks: reports.filter((report) => report.summary.overall === 'warning').length,
      critical_networks: reports.filter((report) => report.summary.overall === 'critical').length,
      total_nodes: reports.reduce((sum, report) => sum + report.summary.total_nodes, 0),
      setup_nodes: reports.reduce((sum, report) => sum + report.summary.setup_nodes, 0),
      active_nodes: reports.reduce((sum, report) => sum + report.summary.active_nodes, 0),
      revoked_nodes: reports.reduce((sum, report) => sum + report.summary.revoked_nodes, 0),
      healthy_nodes: reports.reduce((sum, report) => sum + report.summary.healthy_nodes, 0),
      warning_nodes: reports.reduce((sum, report) => sum + report.summary.warning_nodes, 0),
      critical_nodes: reports.reduce((sum, report) => sum + report.summary.critical_nodes, 0),
    };
    for (const [key, value] of Object.entries(expectedSummary)) if (summary[key] !== value) fail(`snapshot.summary.${key} is inconsistent`);
    const overall = summary.critical_networks > 0 ? 'critical' : summary.warning_networks > 0 ? 'warning' : 'healthy';
    if (summary.overall !== overall) fail('snapshot.summary.overall is inconsistent');

    const expectedRollout = {
      eligible_nodes: reports.reduce((sum, report) => sum + report.rollout.eligible_nodes, 0),
      converged_nodes: reports.reduce((sum, report) => sum + report.rollout.converged_nodes, 0),
      drifted_nodes: reports.reduce((sum, report) => sum + report.rollout.drifted_nodes, 0),
      unreported_nodes: reports.reduce((sum, report) => sum + report.rollout.unreported_nodes, 0),
    };
    for (const [key, value] of Object.entries(expectedRollout)) if (rollout[key] !== value) fail(`snapshot.rollout.${key} is inconsistent`);

    const networks = Object.freeze(reports.map((report) => report.network));
    const nodesByNetwork = new Map(reports.map((report) => [report.network.id, report.nodes]));
    const reportsByNetwork = new Map(reports.map((report) => [report.network.id, report]));
    return Object.freeze({
      generatedAt: generatedAt.value,
      generatedAtMS: generatedAt.milliseconds,
      policy,
      summary,
      rollout,
      reports: Object.freeze(reports),
      reportsByNetwork,
      networks,
      nodesByNetwork,
    });
  }

  function utc(value) {
    return new Date(value).toISOString().replace('T', ' ').replace('.000Z', 'Z');
  }

  function duration(seconds) {
    if (seconds % 86400 === 0) return `${seconds / 86400}d`;
    if (seconds % 3600 === 0) return `${seconds / 3600}h`;
    if (seconds % 60 === 0) return `${seconds / 60}m`;
    return `${seconds}s`;
  }

  function alertEvidenceText(alert) {
    const evidence = alert.evidence;
    switch (alert.code) {
    case 'config_drift':
    case 'config_digest_drift':
      return `applied revision ${evidence.applied_config_revision}, desired ${evidence.desired_config_revision}`;
    case 'certificate_generation_drift':
    case 'certificate_fingerprint_drift':
      return `applied generation ${evidence.applied_certificate_generation}, desired ${evidence.desired_certificate_generation}`;
    case 'certificate_expired':
    case 'credential_expired':
    case 'credential_expiring':
      return evidence.expires_at ? `expires ${utc(evidence.expires_at)}` : '';
    case 'certificate_renewal_due':
      return evidence.renew_after && evidence.expires_at ? `renew after ${utc(evidence.renew_after)}; expires ${utc(evidence.expires_at)}` : '';
    case 'heartbeat_late':
    case 'heartbeat_missing':
    case 'heartbeat_offline': {
      const parts = [];
      if (evidence.age_seconds !== undefined) parts.push(`age ${duration(evidence.age_seconds)}`);
      if (evidence.threshold_seconds !== undefined) parts.push(`threshold ${duration(evidence.threshold_seconds)}`);
      if (evidence.since_at) parts.push(`since ${utc(evidence.since_at)}`);
      return parts.join('; ');
    }
    case 'heartbeat_time_invalid':
      return evidence.last_seen_at ? `reported ${utc(evidence.last_seen_at)}` : evidence.since_at ? `reported ${utc(evidence.since_at)}` : '';
    case 'control_time_invalid':
      return evidence.control_time_at ? `reported ${utc(evidence.control_time_at)}` : '';
    case 'lighthouse_single':
    case 'lighthouse_unavailable':
      return `operational ${evidence.healthy_lighthouses}/${evidence.required_lighthouses}; active ${evidence.active_lighthouses}`;
    case 'projection_limit_exceeded':
      return `observed ${evidence.observed_lighthouses} lighthouses; limit ${evidence.projection_limit}`;
    case 'stale_revocation': {
      const parts = [];
      if (evidence.active_revocations !== undefined) parts.push(`${evidence.active_revocations} active revocation${evidence.active_revocations === 1 ? '' : 's'}`);
      if (evidence.applied_config_revision !== undefined) parts.push(`applied revision ${evidence.applied_config_revision}, desired ${evidence.desired_config_revision}`);
      if (evidence.revocation_at) parts.push(`revoked ${utc(evidence.revocation_at)}`);
      return parts.join('; ');
    }
    case 'agent_degraded':
      return evidence.reported_status ? `reported ${evidence.reported_status}` : '';
    default:
      return '';
    }
  }

  function alertPresentation(alert) {
    const definition = alertDefinitions[alert.code];
    if (!definition) fail('alert presentation received an unknown code');
    return Object.freeze({ label: definition.label, short: definition.short, evidence: alertEvidenceText(alert) });
  }

  function nodeStatusLabel(node) {
    if (node.lifecycleStatus === 'pending') return 'Pending enrollment';
    if (node.lifecycleStatus === 'revoked') return 'Revoked';
    if (node.alerts.length) return alertPresentation(node.alerts[0]).short;
    if (node.phase === 'setup') return 'Awaiting first heartbeat';
    if (node.operational) return 'Operational';
    return node.rolloutCurrent ? 'Not operational' : 'Syncing';
  }

  function createRefreshCoordinator(loader) {
    if (typeof loader !== 'function') throw new TypeError('refresh loader must be a function');
    let inFlight = null;
    let requestedGeneration = 0;
    let completedGeneration = 0;
    function start() {
      const current = (async () => {
        do {
          const targetGeneration = requestedGeneration;
          await loader();
          completedGeneration = targetGeneration;
        } while (completedGeneration < requestedGeneration);
      })();
      inFlight = current.finally(() => {
        if (inFlight === wrapped) inFlight = null;
      });
      const wrapped = inFlight;
      return wrapped;
    }
    function refresh(force = false) {
      if (force) requestedGeneration += 1;
      if (!inFlight) return start();
      return inFlight;
    }
    return Object.freeze({ refresh });
  }

  return Object.freeze({
    MAX_SNAPSHOT_AGE_MS,
    MAX_FUTURE_SKEW_MS,
    validateFleetSnapshot,
    responseAdjustedNow,
    alertPresentation,
    nodeStatusLabel,
    createRefreshCoordinator,
  });
}));
