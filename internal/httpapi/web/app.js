const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const healthModel = globalThis.MeshHealth;
const setupGuideModel = globalThis.MeshSetupGuide;
const runtimeTelemetryModel = globalThis.MeshRuntimeTelemetry;
const readinessModel = globalThis.MeshReadiness;
const installGuideModel = globalThis.MeshInstallGuide;
const dnsSettingsModel = globalThis.MeshDNSSettings;
const relaySettingsModel = globalThis.MeshRelaySettings;
const caRotationModel = globalThis.MeshCARotation;
const routeTransferModel = globalThis.MeshRouteTransfer;
const routeProfileModel = globalThis.MeshRouteProfile;
const routePoliciesModel = globalThis.MeshRoutePolicies;
const firewallRolloutModel = globalThis.MeshFirewallRollout;
const certificateRotationModel = globalThis.MeshCertificateRotation;
const nodeRevocationModel = globalThis.MeshNodeRevocation;
const READINESS_REFRESH_INTERVAL_MS = 10000;
const NODE_ARCHIVE_CERTIFICATE_SAFETY_MARGIN_MS = 5 * 60 * 1000;
const CERTIFICATE_ROTATION_STORAGE_PREFIX = 'mesh-certificate-rotation:';
const NODE_REVOCATION_STORAGE_PREFIX = 'mesh-node-revocation:';
const ACCESS_PERMISSIONS = new Set(['networks.read', 'networks.write', 'networks.security', 'identity.manage', 'audit.read']);

if (!healthModel) throw new Error('Fleet health model is unavailable');
if (!setupGuideModel) throw new Error('Network setup guide is unavailable');
if (!runtimeTelemetryModel) throw new Error('Runtime telemetry model is unavailable');
if (!readinessModel) throw new Error('Deployment readiness model is unavailable');
if (!installGuideModel) throw new Error('Install guide model is unavailable');
if (!dnsSettingsModel) throw new Error('Network DNS model is unavailable');
if (!relaySettingsModel) throw new Error('Network relay model is unavailable');
if (!caRotationModel) throw new Error('Network CA rotation model is unavailable');
if (!routeTransferModel) throw new Error('Network route transfer model is unavailable');
if (!routeProfileModel) throw new Error('Node route profile model is unavailable');
if (!routePoliciesModel) throw new Error('Network route policies model is unavailable');
if (!firewallRolloutModel) throw new Error('Network firewall rollout model is unavailable');
if (!certificateRotationModel) throw new Error('Certificate rotation model is unavailable');
if (!nodeRevocationModel) throw new Error('Node revocation model is unavailable');

const state = {
  networks: [],
  nodes: new Map(),
  fleet: null,
  fleetLoadedAtMS: 0,
  fleetInitialAgeMS: 0,
  fleetExpiryTimer: null,
  healthUnavailable: 'Authoritative fleet health has not loaded.',
  runtimeTelemetry: null,
  runtimeTelemetryResponseNowMS: 0,
  runtimeTelemetryLoadedAtMS: 0,
  networkView: 'auto',
  selectedNetworkID: '',
  certificateRotationRequests: restoreCertificateRotationRequests(),
  nodeRevocationRequests: restoreNodeRevocationRequests(),
  readiness: { networkID: '', network: null, requestID: 0, busy: false, refreshTimer: null },
	retirement: { networkID: '', networkName: '', networkCIDR: '', expectedRevision: 0, nodeCount: 0, saving: false },
	dns: { networkID: '', networkCIDR: '', baseRevision: 0, requestID: 0, busy: false, saving: false, document: null },
	relays: { networkID: '', networkCIDR: '', baseRevision: 0, requestID: 0, busy: false, saving: false, document: null },
	caRotation: { networkID: '', baseRevision: 0, requestID: 0, busy: false, action: '', document: null, refreshTimer: null },
	routeTransfer: { networkID: '', networkName: '', nodes: [], requestID: 0, mutationID: '', busy: false, document: null, refreshTimer: null },
	routeProfile: { networkID: '', nodeID: '', nodeName: '', requestID: 0, mutationID: '', busy: false, formSeeded: false, document: null, refreshTimer: null },
	routePolicies: { networkID: '', networkName: '', requestID: 0, mutationID: '', busy: false, document: null, selectedPrefix: '' },
	nodeSecurity: { networkID: '', nodeID: '', requestID: '', expectedRevision: 0, busy: false, currentGroups: [] },
  enrollmentNextNetworkID: '',
  enrollmentNextAction: '',
  installGuide: installGuideModel.validate({
    schema: installGuideModel.SCHEMA,
    linux: { online_available: false },
  }),
  policy: {
    networkID: '',
    networkCIDR: '',
    baseRevision: 0,
    previewFingerprint: '',
    previewCanonicalFingerprint: '',
    previewWouldChange: false,
    requestID: 0,
    busy: false,
    loaded: false,
		rollout: null,
		refreshTimer: null,
		action: '',
		defaultTargetNodeID: '',
  },
  authMethods: { oidc: false, legacy_browser_login: false, break_glass: false },
  currentSession: null,
  recoveryDraft: null,
};
let authenticated = false;

function validateSessionAccess(session) {
  if (!session || session.authenticated !== true || !session.principal || typeof session.principal.kind !== 'string') throw new Error('Invalid session response');
  if (!['viewer', 'operator', 'admin'].includes(session.role) || !Array.isArray(session.permissions) || session.permissions.some((permission) => typeof permission !== 'string' || !ACCESS_PERMISSIONS.has(permission)) || new Set(session.permissions).size !== session.permissions.length) throw new Error('Invalid session access policy');
  return session;
}

function hasPermission(permission) {
  return Array.isArray(state.currentSession?.permissions) && state.currentSession.permissions.includes(permission);
}

function renderAccessState() {
  const role = state.currentSession?.role;
  const canWriteNetworks = hasPermission('networks.write');
  $('#access-role').textContent = role ? `${role[0].toUpperCase()}${role.slice(1)} access` : 'Authenticated access';
  $('#new-network').classList.toggle('hidden', !canWriteNetworks);
  $$('.open-network-modal').forEach((button) => button.classList.toggle('hidden', !canWriteNetworks));
  const empty = $('#network-empty');
  if (empty) {
    $('h3', empty).textContent = canWriteNetworks ? 'Create your first private network' : 'No networks yet';
    $('p', empty).textContent = canWriteNetworks
      ? 'Mesh generates the certificate authority and keeps its private key encrypted. Add a lighthouse next, then enroll members.'
      : 'A network operator or administrator can create the first private network.';
  }
}
let policyRuleSequence = 0;
const oidcErrorParameter = 'mesh_auth_error';

function certificateRotationStorage() {
	try {
		const storage = globalThis.sessionStorage;
		if (!storage || typeof storage.getItem !== 'function' || typeof storage.setItem !== 'function' || typeof storage.removeItem !== 'function') return null;
		return storage;
	} catch (_) { return null; }
}

function restoreCertificateRotationRequests() {
	const restored = new Map();
	const storage = certificateRotationStorage();
	if (!storage) return restored;
	let keys;
	try {
		keys = Array.from({ length: storage.length }, (_, index) => storage.key(index)).filter((key) => typeof key === 'string' && key.startsWith(CERTIFICATE_ROTATION_STORAGE_PREFIX));
	} catch (_) { return restored; }
	for (const key of keys) {
		try {
			const expected = certificateRotationModel.restoreExpected(JSON.parse(storage.getItem(key)));
			if (key !== `${CERTIFICATE_ROTATION_STORAGE_PREFIX}${expected.nodeID}`) throw new Error('stored node binding is inconsistent');
			restored.set(expected.nodeID, expected);
		} catch (_) {
			try { storage.removeItem(key); } catch (_) { /* unavailable storage remains fail-closed on the next mutation */ }
		}
	}
	return restored;
}

function rememberCertificateRotationRequest(expected) {
	const storage = certificateRotationStorage();
	if (!storage) throw new Error('Session-safe certificate-rotation replay is unavailable in this browser.');
	const key = `${CERTIFICATE_ROTATION_STORAGE_PREFIX}${expected.nodeID}`;
	const serialized = JSON.stringify(expected);
	try {
		storage.setItem(key, serialized);
		if (storage.getItem(key) !== serialized) throw new Error('request identity could not be verified after storage');
	} catch (_) {
		try { storage.removeItem(key); } catch (_) { /* preserve the original fail-closed result */ }
		throw new Error('Session-safe certificate-rotation replay could not be persisted.');
	}
	state.certificateRotationRequests.set(expected.nodeID, expected);
}

function forgetCertificateRotationRequest(nodeID) {
	state.certificateRotationRequests.delete(nodeID);
	const storage = certificateRotationStorage();
	if (storage) {
		try { storage.removeItem(`${CERTIFICATE_ROTATION_STORAGE_PREFIX}${nodeID}`); } catch (_) { /* in-memory state is already cleared */ }
	}
}

function restoreNodeRevocationRequests() {
	const restored = new Map();
	const storage = certificateRotationStorage();
	if (!storage) return restored;
	let keys;
	try {
		keys = Array.from({ length: storage.length }, (_, index) => storage.key(index)).filter((key) => typeof key === 'string' && key.startsWith(NODE_REVOCATION_STORAGE_PREFIX));
	} catch (_) { return restored; }
	for (const key of keys) {
		try {
			const expected = nodeRevocationModel.restoreExpected(JSON.parse(storage.getItem(key)));
			if (key !== `${NODE_REVOCATION_STORAGE_PREFIX}${expected.nodeID}`) throw new Error('stored node binding is inconsistent');
			restored.set(expected.nodeID, expected);
		} catch (_) {
			try { storage.removeItem(key); } catch (_) { /* unavailable storage remains fail-closed on the next mutation */ }
		}
	}
	return restored;
}

function rememberNodeRevocationRequest(expected) {
	const storage = certificateRotationStorage();
	if (!storage) throw new Error('Session-safe node-revocation replay is unavailable in this browser.');
	const key = `${NODE_REVOCATION_STORAGE_PREFIX}${expected.nodeID}`;
	const serialized = JSON.stringify(expected);
	try {
		storage.setItem(key, serialized);
		if (storage.getItem(key) !== serialized) throw new Error('request identity could not be verified after storage');
	} catch (_) {
		try { storage.removeItem(key); } catch (_) { /* preserve the original fail-closed result */ }
		throw new Error('Session-safe node-revocation replay could not be persisted.');
	}
	state.nodeRevocationRequests.set(expected.nodeID, expected);
}

function forgetNodeRevocationRequest(nodeID) {
	state.nodeRevocationRequests.delete(nodeID);
	const storage = certificateRotationStorage();
	if (storage) {
		try { storage.removeItem(`${NODE_REVOCATION_STORAGE_PREFIX}${nodeID}`); } catch (_) { /* in-memory state is already cleared */ }
	}
}

function csrf() {
  const names = ['__Host-mesh_csrf=', 'mesh_csrf='];
  const entries = document.cookie.split('; ');
  for (const name of names) {
    const entry = entries.find((value) => value.startsWith(name));
    if (entry) return decodeURIComponent(entry.split('=').slice(1).join('='));
  }
  return '';
}

function validResourceID(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value);
}

async function api(path, options = {}) {
  const { timeoutMS = 12000, withMetadata = false, ...requestOptions } = options;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMS);
  try {
    const response = await fetch(path, {
      ...requestOptions,
      signal: controller.signal,
      headers: { 'Content-Type': 'application/json', 'X-Mesh-CSRF': csrf(), ...(requestOptions.headers || {}) },
    });
    const headersReceivedAtMS = withMetadata && globalThis.performance && typeof globalThis.performance.now === 'function' ? globalThis.performance.now() : Number.NaN;
    const payload = response.status === 204 ? null : await response.json().catch(() => ({}));
    const bodyParsedAtMS = withMetadata && globalThis.performance && typeof globalThis.performance.now === 'function' ? globalThis.performance.now() : Number.NaN;
    if (!response.ok) {
      const error = new Error(payload.error || `Request failed (${response.status})`);
      error.status = response.status;
      throw error;
    }
    if (withMetadata) return { payload, responseDate: response.headers.get('Date') || '', headersReceivedAtMS, bodyParsedAtMS };
    return payload;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('Request timed out');
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function boot() {
  const callbackFailed = consumeOIDCCallbackError();
  try {
    state.currentSession = await api('/api/v1/session');
    authenticated = true;
  } catch {
    await showLogin(callbackFailed);
    return;
  }
  try {
    await showApp();
  } catch {}
}

async function showLogin(callbackFailed) {
  authenticated = false;
  state.currentSession = null;
  renderAccessState();
  scrubRecoveryDraft();
  clearFleet('Authoritative fleet health is unavailable while signed out.');
  renderNetworksSafely();
  $('#app-view').classList.add('hidden');
  $('#login-view').classList.remove('hidden');
  try {
    const methods = await api('/api/v1/auth/methods');
    if (typeof methods.oidc !== 'boolean' || typeof methods.legacy_browser_login !== 'boolean' || typeof methods.break_glass !== 'boolean') throw new Error('Invalid authentication configuration');
    state.authMethods = methods;
    $('#oidc-login-panel').classList.toggle('hidden', !methods.oidc);
    $('#login-form').classList.toggle('hidden', !methods.legacy_browser_login);
    $('#break-glass-login-form').classList.toggle('hidden', !methods.break_glass);
    $('#login-divider-oidc').classList.toggle('hidden', !(methods.oidc && (methods.legacy_browser_login || methods.break_glass)));
    $('#login-divider-recovery').classList.toggle('hidden', !(methods.legacy_browser_login && methods.break_glass));
    if (methods.legacy_browser_login) $('#admin-token').focus();
    else if (methods.break_glass) $('#break-glass-code').focus();
    if (!methods.oidc && !methods.legacy_browser_login && !methods.break_glass) $('#login-error').textContent = 'No browser sign-in method is available.';
  } catch {
    $('#login-error').textContent = 'Sign-in is temporarily unavailable.';
  }
  if (callbackFailed) $('#login-error').textContent = 'Single sign-on could not be completed. Please try again.';
}

function consumeOIDCCallbackError() {
  const current = new URL(location.href);
  if (!current.searchParams.has(oidcErrorParameter)) return false;
  current.searchParams.delete(oidcErrorParameter);
  history.replaceState(null, '', `${current.pathname}${current.search}${current.hash}`);
  return true;
}

async function showApp() {
  clearFleet('Loading authoritative fleet health. No inventory or health is inferred yet.');
  renderNetworksSafely();
  $('#login-view').classList.add('hidden');
  $('#app-view').classList.remove('hidden');
  await Promise.all([loadAuthenticationContext(), loadInstallGuide(), loadNetworks()]);
}

async function loadAuthenticationContext() {
  const [session, methods] = await Promise.all([api('/api/v1/session'), api('/api/v1/auth/methods')]);
  validateSessionAccess(session);
  if (!methods || typeof methods.oidc !== 'boolean' || typeof methods.legacy_browser_login !== 'boolean' || typeof methods.break_glass !== 'boolean') throw new Error('Invalid authentication configuration');
  state.currentSession = session;
  state.authMethods = methods;
  renderAccessState();
  renderRecoveryAvailability();
}

async function loadInstallGuide() {
  try {
    state.installGuide = installGuideModel.validate(await api('/api/v1/install-guide'));
  } catch (error) {
    if (error.status !== 404) flash('Online installation guidance is temporarily unavailable.');
    state.installGuide = installGuideModel.validate({
      schema: installGuideModel.SCHEMA,
      linux: { online_available: false },
    });
  }
}

$('#login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = $('button[type=submit]', form);
  button.disabled = true;
  $('#login-error').textContent = '';
  try {
    state.currentSession = await api('/api/v1/session', { method: 'POST', body: JSON.stringify({ token: form.token.value }) });
    authenticated = true;
    form.reset();
    await showApp();
  } catch (error) {
    $('#login-error').textContent = error.message;
  } finally { button.disabled = false; }
});

$('#break-glass-login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = $('button[type=submit]', form);
  button.disabled = true;
  $('#login-error').textContent = '';
  try {
    state.currentSession = await api('/api/v1/auth/break-glass', { method: 'POST', body: JSON.stringify({ code: form.code.value }) });
    authenticated = true;
    form.reset();
    await showApp();
  } catch (error) {
    $('#login-error').textContent = error.message;
  } finally { button.disabled = false; }
});

$('#oidc-login').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  button.setAttribute('aria-busy', 'true');
  $('#login-error').textContent = '';
  try {
    const result = await api('/api/v1/auth/oidc/start', { method: 'POST', body: JSON.stringify({ return_path: `${location.pathname}${location.search}` }) });
    if (typeof result.authorization_url !== 'string' || !result.authorization_url) throw new Error('Invalid sign-in response');
    location.assign(result.authorization_url);
  } catch {
    $('#login-error').textContent = 'Single sign-on could not be started. Please try again.';
    button.disabled = false;
    button.removeAttribute('aria-busy');
  }
});

$('#logout').addEventListener('click', async () => {
  authenticated = false;
  state.currentSession = null;
  scrubRecoveryDraft();
  clearFleet('Authoritative fleet health is unavailable while signed out.');
  renderNetworksSafely();
  await api('/api/v1/session', { method: 'DELETE' });
  location.reload();
});

const fleetRefresh = healthModel.createRefreshCoordinator(refreshFleetSnapshot);

function loadNetworks(force = false) {
  return fleetRefresh.refresh(force);
}

async function refreshFleetSnapshot() {
  if (!authenticated) return;
  let response;
  try {
    response = await api('/api/v1/fleet/health', { withMetadata: true, timeoutMS: 10000 });
  } catch (error) {
    clearFleet('Authoritative fleet health is unavailable. Inventory and health status were cleared; retrying on the next refresh.');
    renderNetworksSafely();
    if (error.status === 401) await showLogin(false);
    if (error.status === 401) throw error;
    return;
  }
  try {
    const responseDateMS = Date.parse(response.responseDate);
    if (!Number.isFinite(responseDateMS)) throw new Error('Health response did not include a valid server date');
    const responseNowMS = healthModel.responseAdjustedNow(responseDateMS, response.headersReceivedAtMS, response.bodyParsedAtMS);
    const fleet = healthModel.validateFleetSnapshot(response.payload, responseNowMS);
    state.fleet = fleet;
    state.networks = fleet.networks;
    state.nodes = fleet.nodesByNetwork;
    state.fleetLoadedAtMS = Date.now();
    state.fleetInitialAgeMS = Math.max(0, responseNowMS - fleet.generatedAtMS);
    state.healthUnavailable = '';
    scheduleFleetExpiry();
  } catch {
    clearFleet('Authoritative fleet health could not be verified. Inventory and health status were cleared; retrying on the next refresh.');
  }
  renderNetworksSafely();
  if (!state.fleet) return;
  await refreshRuntimeTelemetry();
  renderNetworksSafely();
}

async function refreshRuntimeTelemetry() {
  let response;
  try {
    response = await api('/api/v1/fleet/runtime-telemetry', { withMetadata: true, timeoutMS: 10000 });
  } catch (error) {
    clearRuntimeTelemetry();
    if (error.status === 401) await showLogin(false);
    return;
  }
  try {
    const responseDateMS = Date.parse(response.responseDate);
    if (!Number.isFinite(responseDateMS)) throw new Error('Runtime telemetry response did not include a valid server date');
    const responseNowMS = healthModel.responseAdjustedNow(responseDateMS, response.headersReceivedAtMS, response.bodyParsedAtMS);
    state.runtimeTelemetry = runtimeTelemetryModel.validateFleetProjection(response.payload, responseNowMS);
    // HTTP Date is second-granularity. Clamp to the validated server-generated
    // timestamp so a report from later in that same second is not treated as
    // future evidence.
    state.runtimeTelemetryResponseNowMS = Math.max(responseNowMS, state.runtimeTelemetry.generatedAtMS);
    state.runtimeTelemetryLoadedAtMS = Date.now();
  } catch {
    clearRuntimeTelemetry();
  }
}

function clearRuntimeTelemetry() {
  state.runtimeTelemetry = null;
  state.runtimeTelemetryResponseNowMS = 0;
  state.runtimeTelemetryLoadedAtMS = 0;
}

function clearFleet(reason) {
  if (state.fleetExpiryTimer !== null) clearTimeout(state.fleetExpiryTimer);
  state.fleet = null;
  state.networks = [];
  state.nodes = new Map();
  state.fleetLoadedAtMS = 0;
  state.fleetInitialAgeMS = 0;
  state.fleetExpiryTimer = null;
  state.healthUnavailable = reason;
  clearRuntimeTelemetry();
}

function renderNetworksSafely() {
  try {
    renderNetworks();
  } catch {
    clearFleet('Authoritative fleet health could not be rendered safely. Inventory and health status were cleared.');
    setNetworkWorkspaceChrome(false);
    $('#network-grid').replaceChildren();
    $('#network-empty').classList.add('hidden');
    renderFleetUnavailable(state.healthUnavailable);
  }
}

function meshIcon(name) {
  const icon = document.createElement('i');
  icon.className = `fa fa-${name}`;
  icon.setAttribute('aria-hidden', 'true');
  return icon;
}

function appendIconLabel(element, iconName, label) {
  element.append(meshIcon(iconName), document.createTextNode(label));
  return element;
}

function setNetworkWorkspaceChrome(workspaceOpen) {
  $('#app-page-header').classList.toggle('hidden', workspaceOpen);
  $('#fleet-health').classList.toggle('hidden', workspaceOpen);
  $('#new-network').classList.toggle('hidden', workspaceOpen || !$('#activity-view').classList.contains('hidden') || !hasPermission('networks.write'));
  $('#networks-view').classList.toggle('workspace-open', workspaceOpen);
}

function selectedNetworkReport(fleet) {
  if (state.networkView === 'directory') return null;
  if (state.selectedNetworkID) {
    const selected = fleet.reports.find((report) => report.network.id === state.selectedNetworkID);
    if (selected) return selected;
    state.selectedNetworkID = '';
    state.networkView = 'auto';
  }
  if (state.networkView === 'auto' && fleet.reports.length === 1) {
    state.selectedNetworkID = fleet.reports[0].network.id;
    return fleet.reports[0];
  }
  return null;
}

function setupStatus(setup, health) {
  if (setup.completedStages < setup.totalStages) return { label: 'Setup in progress', tone: 'warning' };
  return { label: severityLabel(health.summary.overall), tone: health.summary.overall };
}

function setupActionLabel(setup) {
  if (setup.action.kind === 'resume_node') return 'Continue enrollment';
  if (setup.action.kind === 'add_lighthouse') return 'Add lighthouse';
  if (setup.action.kind === 'add_member') return 'Add member';
  if (setup.action.kind === 'add_redundancy') return 'Add lighthouse';
  return 'Run readiness checks';
}

function setupActionDescription(setup, nodes) {
  if (setup.action.kind === 'resume_node') {
    const node = nodes.find((candidate) => candidate.id === setup.action.nodeID);
    if (node?.role === 'lighthouse') return 'Complete enrollment to bring your lighthouse online and make the network operational.';
    if (node?.role === 'member') return 'Complete enrollment to bring your first member online and verify the private network path.';
  }
  if (setup.action.kind === 'add_lighthouse') return 'Add a public lighthouse so members have a stable entry point to this network.';
  if (setup.action.kind === 'add_member') return 'Add the first member machine and enroll it through the operational lighthouse.';
  if (setup.action.kind === 'add_redundancy') return 'Add a second lighthouse in a different failure domain before final verification.';
  return setup.detail;
}

function focusManagedNode(nodeList, nodeID) {
  const row = [...nodeList.children].find((item) => item.dataset.nodeId === nodeID);
  if (!row) {
    flash('The selected machine changed. Refresh authoritative inventory before continuing.');
    return;
  }
  const management = nodeList.closest('details');
  if (management) management.open = true;
  row.classList.add('node-row-highlighted');
  row.scrollIntoView({ block: 'center', behavior: 'smooth' });
  const action = row.querySelector('.reissue, .placement, button');
  action?.focus({ preventScroll: true });
  setTimeout(() => row.classList.remove('node-row-highlighted'), 2400);
}

function performSetupAction(setup, network, nodeList) {
  if (setup.action.kind !== 'readiness' && !hasPermission('networks.write')) {
    flash('Operator access is required for this setup action.');
    return;
  }
  if (setup.action.kind === 'add_lighthouse') openNode(network.id, true, 'lighthouse');
  else if (setup.action.kind === 'add_member') openNode(network.id, false, 'member');
  else if (setup.action.kind === 'add_redundancy') openNode(network.id, true, 'redundancy');
  else if (setup.action.kind === 'readiness') openReadiness(network);
  else if (setup.action.kind === 'resume_node') {
    focusManagedNode(nodeList, setup.action.nodeID);
    flash('Pending enrollment selected. Use the saved credential, or reissue it if that credential is unavailable.');
  }
}

function topologyNodePresentation(node) {
  if (node.lifecycleStatus === 'revoked') return { label: 'Revoked', tone: 'revoked' };
  if (node.lifecycleStatus === 'pending') return { label: 'Pending enrollment', tone: 'pending' };
  if (node.operational) return { label: 'Online', tone: 'online' };
  if (node.severity === 'critical') return { label: 'Needs attention', tone: 'critical' };
  return { label: 'Starting', tone: 'warning' };
}

function heartbeatEvidence(node, className) {
  const evidence = document.createElement('span');
  evidence.className = className;
  const indicator = document.createElement('span');
  indicator.className = `heartbeat-indicator ${node.last_seen_at ? 'live' : 'missing'}`;
  indicator.setAttribute('aria-hidden', 'true');
  const copy = document.createElement('span');
  copy.className = 'heartbeat-copy';
  evidence.append(indicator, copy);
  if (!node.last_seen_at || node.heartbeat_sequence === 0) {
    const primary = document.createElement('span');
    primary.className = 'heartbeat-primary';
    primary.textContent = 'No authenticated heartbeat yet';
    copy.append(primary);
    return evidence;
  }
  const received = new Date(node.last_seen_at);
  const time = document.createElement('time');
  time.dateTime = node.last_seen_at;
  time.textContent = className === 'topology-node-heartbeat'
    ? received.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', second: '2-digit' })
    : received.toLocaleString();
  const agent = node.agent_status === 'healthy' ? 'Agent healthy' : node.agent_status === 'degraded' ? 'Agent degraded' : 'Agent status unavailable';
  const nebula = node.nebula_running ? 'Nebula running' : 'Nebula stopped';
  const primary = document.createElement('span');
  primary.className = 'heartbeat-primary';
  primary.append(
    document.createTextNode(`Heartbeat #${node.heartbeat_sequence} · `),
    time,
  );
  const state = document.createElement('span');
  state.className = 'heartbeat-state';
  state.textContent = `${agent} · ${nebula}`;
  copy.append(primary, state);
  evidence.title = `Last authenticated heartbeat ${received.toISOString()}`;
  evidence.setAttribute('aria-label', `Heartbeat ${node.heartbeat_sequence}. Last received ${received.toLocaleString()}. ${agent}. ${nebula}.`);
  return evidence;
}

function renderTopologyNode(node, nodeList) {
  const presentation = topologyNodePresentation(node);
  const button = document.createElement('button');
  button.type = 'button';
  button.className = `topology-node topology-node-${presentation.tone}`;
  button.setAttribute('aria-label', `${node.name}, ${node.role}, ${presentation.label}. Open node management.`);
  const icon = document.createElement('span');
  icon.className = 'topology-node-icon';
  icon.append(meshIcon(node.role === 'lighthouse' ? 'compass' : 'server'));
  const name = document.createElement('strong'); name.textContent = node.name;
  const role = document.createElement('span'); role.className = 'topology-node-role'; role.textContent = node.role === 'lighthouse' ? 'Lighthouse' : 'Member';
  const status = document.createElement('span'); status.className = 'topology-node-status'; status.textContent = presentation.label;
  button.append(icon, name, role, status);
  if (node.lifecycleStatus === 'active') button.append(heartbeatEvidence(node, 'topology-node-heartbeat'));
  button.addEventListener('click', () => focusManagedNode(nodeList, node.id));
  return button;
}

function renderTopologyPlaceholder(role, enabled, network) {
  const actionable = enabled && hasPermission('networks.write');
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'topology-node topology-node-placeholder';
  button.disabled = !actionable;
  const icon = document.createElement('span'); icon.className = 'topology-node-icon'; icon.append(meshIcon('plus'));
  const name = document.createElement('strong'); name.textContent = role === 'lighthouse' ? 'Add lighthouse' : 'Add member';
  const detail = document.createElement('span'); detail.className = 'topology-node-status'; detail.textContent = actionable ? 'Add now' : enabled ? 'Operator access required' : 'Coming next';
  button.append(icon, name, detail);
  if (actionable) button.addEventListener('click', () => openNode(network.id, role === 'lighthouse', role));
  return button;
}

function settingsButton(label, iconName, handler, className = '') {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = className;
  appendIconLabel(button, iconName, label);
  button.addEventListener('click', () => {
    button.closest('details')?.removeAttribute('open');
    handler();
  });
  return button;
}

function renderNetworkSettings(network, nodes) {
  const settings = document.createElement('details'); settings.className = 'network-settings';
  const summary = document.createElement('summary');
  summary.append(meshIcon('cog'), document.createTextNode('Settings'), meshIcon('angle-down'));
  const menu = document.createElement('div'); menu.className = 'network-settings-menu';
  const nodeCount = document.createElement('p'); nodeCount.className = 'network-settings-heading'; nodeCount.textContent = 'Network lifecycle';
  menu.append(nodeCount);
  if (hasPermission('networks.write')) menu.append(settingsButton('Add node', 'plus', () => openNode(network.id, nodes.length === 0, nodes.length === 0 ? 'lighthouse' : '')));
  menu.append(settingsButton('Deployment readiness', 'check-circle-o', () => openReadiness(network)));
  if (hasPermission('networks.write')) {
    const services = document.createElement('p'); services.className = 'network-settings-heading'; services.textContent = 'Services and policy';
    menu.append(services,
      settingsButton('Network DNS', 'globe', () => openDNS(network)),
      settingsButton('Network relays', 'exchange', () => openRelays(network)),
      settingsButton('Firewall policy', 'shield', () => openPolicy(network)),
      settingsButton('Route policies', 'random', () => openRoutePolicies(network)),
      settingsButton('Transfer routes', 'share-alt', () => openRouteTransfer(network, nodes)),
    );
  }
  if (hasPermission('networks.security')) {
    const trust = document.createElement('p'); trust.className = 'network-settings-heading'; trust.textContent = 'Trust domain';
    menu.append(trust,
      settingsButton('Rotate certificate authority', 'refresh', () => openCARotation(network)),
      settingsButton('Retire network', 'trash-o', () => openNetworkRetirement(network, nodes), 'danger'),
    );
  }
  settings.append(summary, menu);
  return settings;
}

function renderSetupProgress(setup) {
  const list = document.createElement('ol'); list.className = 'workspace-setup-progress'; list.setAttribute('aria-label', 'Network setup progress');
  setup.stages.forEach((stage, index) => {
    const item = document.createElement('li'); item.className = `workspace-setup-stage ${stage.state}`;
    const marker = document.createElement('span'); marker.className = 'workspace-stage-marker';
    if (stage.state === 'complete') marker.append(meshIcon('check'));
    else marker.textContent = String(index + 1);
    const copy = document.createElement('div');
    const title = document.createElement('strong'); title.textContent = stage.label;
    const stateLabel = document.createElement('span'); stateLabel.textContent = stage.state === 'complete' ? 'Completed' : stage.state === 'current' ? 'In progress' : 'Pending';
    copy.append(title, stateLabel); item.append(marker, copy); list.append(item);
  });
  return list;
}

function renderNetworkWorkspace(grid, health) {
  const { network, nodes } = health;
  const setup = setupGuideModel.project(nodes, state.fleet.policy.required_healthy_lighthouses);
  const status = setupStatus(setup, health);
  const workspace = document.createElement('section'); workspace.className = 'network-workspace'; workspace.setAttribute('aria-labelledby', 'workspace-network-title');

  const back = document.createElement('button'); back.type = 'button'; back.className = 'workspace-back'; appendIconLabel(back, 'arrow-left', 'Back to networks');
  back.addEventListener('click', () => {
    state.networkView = 'directory';
    state.selectedNetworkID = '';
    renderNetworksSafely();
    requestAnimationFrame(() => $('.network-directory-open')?.focus());
  });

  const heading = document.createElement('div'); heading.className = 'workspace-heading';
  const identity = document.createElement('div'); identity.className = 'workspace-identity';
  const titleRow = document.createElement('div'); titleRow.className = 'workspace-title-row';
  const title = document.createElement('h2'); title.id = 'workspace-network-title'; title.textContent = network.name;
  const badge = document.createElement('span'); badge.className = `workspace-status ${status.tone}`; badge.textContent = status.label;
  titleRow.append(title, badge);
  const meta = document.createElement('p'); meta.textContent = `${network.cidr} · Updated ${new Date(network.config_updated_at).toLocaleString()}`;
  identity.append(titleRow, meta);
  heading.append(identity, renderNetworkSettings(network, nodes));

  const nodeManagement = document.createElement('details'); nodeManagement.className = 'workspace-node-management';
  const managementSummary = document.createElement('summary'); managementSummary.append(meshIcon('server'), document.createTextNode(`Manage nodes (${nodes.length})`), meshIcon('angle-down'));
  const nodeList = document.createElement('ul'); nodeList.className = 'node-list'; nodeList.setAttribute('aria-label', `${network.name} nodes`);
  if (!nodes.length) {
    const empty = document.createElement('li'); empty.className = 'node-row node-row-empty'; empty.textContent = 'No nodes yet'; nodeList.append(empty);
  } else {
    for (const node of nodes) nodeList.append(nodeRow(node, network));
  }
  nodeManagement.append(managementSummary, nodeList);

  const primary = document.createElement('div'); primary.className = 'workspace-primary';
  const topology = document.createElement('section'); topology.className = 'topology-panel'; topology.setAttribute('aria-labelledby', 'topology-title');
  const topologyHeading = document.createElement('div'); topologyHeading.className = 'topology-heading';
  const topologyCopy = document.createElement('div');
  const topologyTitle = document.createElement('h3'); topologyTitle.id = 'topology-title'; topologyTitle.textContent = 'Topology';
  const topologySummary = document.createElement('p');
  const lighthouseCount = nodes.filter((node) => node.role === 'lighthouse' && node.lifecycleStatus !== 'revoked').length;
  const memberCount = nodes.filter((node) => node.role === 'member' && node.lifecycleStatus !== 'revoked').length;
  topologySummary.textContent = `${lighthouseCount} ${lighthouseCount === 1 ? 'lighthouse' : 'lighthouses'} · ${memberCount} ${memberCount === 1 ? 'member' : 'members'}`;
  topologyCopy.append(topologyTitle, topologySummary); topologyHeading.append(topologyCopy);

  const canvas = document.createElement('div'); canvas.className = 'topology-canvas';
  const hub = document.createElement('div'); hub.className = 'topology-hub';
  const hubIcon = document.createElement('span'); hubIcon.className = 'topology-hub-icon'; hubIcon.append(meshIcon('sitemap'));
  const hubName = document.createElement('strong'); hubName.textContent = network.name;
  const hubCIDR = document.createElement('span'); hubCIDR.textContent = network.cidr;
  hub.append(hubIcon, hubName, hubCIDR);
  const direction = meshIcon('long-arrow-down'); direction.classList.add('topology-direction');
  const machines = document.createElement('div'); machines.className = 'topology-machines';
  const topologyNodes = nodes
    .filter((candidate) => candidate.lifecycleStatus !== 'revoked')
    .sort((left, right) => {
      const roleOrder = Number(left.role !== 'lighthouse') - Number(right.role !== 'lighthouse');
      return roleOrder || left.name.localeCompare(right.name);
    });
  for (const node of topologyNodes) machines.append(renderTopologyNode(node, nodeList));
  if (!nodes.some((node) => node.role === 'lighthouse' && node.lifecycleStatus !== 'revoked')) machines.append(renderTopologyPlaceholder('lighthouse', true, network));
  if (!nodes.some((node) => node.role === 'member' && node.lifecycleStatus !== 'revoked')) machines.append(renderTopologyPlaceholder('member', setup.stages[1].state === 'complete', network));
  canvas.append(hub, direction, machines);
  const legend = document.createElement('div'); legend.className = 'topology-legend'; legend.setAttribute('aria-label', 'Topology status legend');
  for (const [tone, label] of [['network', 'Network'], ['pending', 'Pending'], ['online', 'Online'], ['offline', 'Offline']]) {
    const item = document.createElement('span'); item.className = `topology-legend-${tone}`; item.append(meshIcon('circle'), document.createTextNode(label)); legend.append(item);
  }
  topology.append(topologyHeading, canvas, legend);

  const next = document.createElement('section'); next.className = 'workspace-next-action'; next.setAttribute('aria-labelledby', 'workspace-next-title');
  const nextEyebrow = document.createElement('p'); nextEyebrow.className = 'eyebrow'; nextEyebrow.textContent = 'Next action';
  const nextTitle = document.createElement('h3'); nextTitle.id = 'workspace-next-title'; nextTitle.textContent = setup.action.kind === 'resume_node' && nodes.find((node) => node.id === setup.action.nodeID)?.role === 'lighthouse' ? 'Enroll your lighthouse' : setup.action.label;
  const nextDetail = document.createElement('p'); nextDetail.className = 'workspace-next-detail'; nextDetail.textContent = setupActionDescription(setup, nodes);
  const setupActionPermitted = setup.action.kind === 'readiness' || hasPermission('networks.write');
  const nextButton = document.createElement('button'); nextButton.type = 'button'; nextButton.className = 'workspace-primary-action'; nextButton.textContent = setupActionPermitted ? setupActionLabel(setup) : 'Operator access required'; nextButton.disabled = !setupActionPermitted;
  nextButton.addEventListener('click', () => performSetupAction(setup, network, nodeList));
  const progressHeading = document.createElement('div'); progressHeading.className = 'workspace-progress-heading';
  const progressTitle = document.createElement('strong'); progressTitle.textContent = 'Setup progress';
  const progressCount = document.createElement('span'); progressCount.textContent = `${setup.completedStages} of ${setup.totalStages} stages complete`;
  progressHeading.append(progressTitle, progressCount);
  next.append(nextEyebrow, nextTitle, nextDetail, nextButton, progressHeading, renderSetupProgress(setup));
  const scope = document.createElement('p'); scope.className = 'workspace-evidence-scope'; scope.textContent = setup.scope; next.append(scope);
  primary.append(topology, next);

  workspace.append(back, heading, primary, nodeManagement);
  if (health.alerts.length) {
    const alerts = document.createElement('details'); alerts.className = 'workspace-health-alerts';
    const summary = document.createElement('summary'); summary.append(meshIcon('exclamation-triangle'), document.createTextNode(`${health.alerts.length} authoritative health ${health.alerts.length === 1 ? 'alert' : 'alerts'}`), meshIcon('angle-down'));
    const list = document.createElement('ul');
    const nodeNames = new Map(nodes.map((node) => [node.id, node.name]));
    for (const alert of health.alerts) list.append(warningItem(alert, '', nodeNames.get(alert.nodeID) || ''));
    alerts.append(summary, list); workspace.append(alerts);
  }
  grid.append(workspace);
}

function renderNetworkDirectory(grid, fleet) {
  renderFleetHealth(fleet);
  const directoryHeader = document.createElement('div');
  directoryHeader.className = 'network-directory-header';
  directoryHeader.setAttribute('aria-hidden', 'true');
  for (const label of ['Network', 'Status', 'Node health', 'Next action', '']) {
    const column = document.createElement('span');
    column.textContent = label;
    directoryHeader.append(column);
  }
  grid.append(directoryHeader);
  for (const health of fleet.reports) {
    const { network, nodes } = health;
    const setup = setupGuideModel.project(nodes, fleet.policy.required_healthy_lighthouses);
    const status = setupStatus(setup, health);
    const article = document.createElement('article'); article.className = `network-directory-row severity-${health.summary.overall}`;
    const open = document.createElement('button'); open.type = 'button'; open.className = 'network-directory-open';
    const identity = document.createElement('span'); identity.className = 'network-directory-identity';
    const name = document.createElement('strong'); name.textContent = network.name;
    const cidr = document.createElement('span'); cidr.textContent = network.cidr;
    identity.append(name, cidr);
    const networkStatus = document.createElement('span'); networkStatus.className = `network-directory-status ${status.tone}`; networkStatus.textContent = status.label;
    const nodeCount = document.createElement('span'); nodeCount.className = 'network-directory-stat';
    nodeCount.append(document.createTextNode(`${health.summary.active_nodes} online`), document.createElement('small'));
    nodeCount.lastElementChild.textContent = `${health.summary.total_nodes} total nodes`;
    const next = document.createElement('span'); next.className = 'network-directory-next';
    const nextLabel = document.createElement('small'); nextLabel.textContent = 'Next action';
    const nextValue = document.createElement('strong'); nextValue.textContent = setupActionLabel(setup);
    next.append(nextLabel, nextValue);
    const chevron = meshIcon('chevron-right'); chevron.classList.add('network-directory-chevron');
    open.append(identity, networkStatus, nodeCount, next, chevron);
    open.addEventListener('click', () => {
      state.networkView = 'workspace';
      state.selectedNetworkID = network.id;
      renderNetworksSafely();
      window.scrollTo(0, 0);
      requestAnimationFrame(() => $('.workspace-back')?.focus({ preventScroll: true }));
    });
    article.append(open); grid.append(article);
  }
}

function renderNetworks() {
  const grid = $('#network-grid');
  grid.replaceChildren();
  if (!state.fleet) {
    setNetworkWorkspaceChrome(false);
    grid.className = 'network-grid network-directory';
    $('#network-empty').classList.add('hidden');
    renderFleetUnavailable(state.healthUnavailable);
    return;
  }
  const fleet = state.fleet;
  const workspace = selectedNetworkReport(fleet);
  setNetworkWorkspaceChrome(Boolean(workspace));
  $('#network-empty').classList.toggle('hidden', fleet.networks.length !== 0 || Boolean(workspace));
  if (workspace) {
    grid.className = 'network-grid network-workspace-grid';
    renderNetworkWorkspace(grid, workspace);
  } else {
    grid.className = 'network-grid network-directory';
    renderNetworkDirectory(grid, fleet);
  }
}

function renderNetworksLegacy() {
  const grid = $('#network-grid');
  grid.replaceChildren();
  if (!state.fleet) {
    $('#network-empty').classList.add('hidden');
    renderFleetUnavailable(state.healthUnavailable);
    return;
  }
  const fleet = state.fleet;
  $('#network-empty').classList.toggle('hidden', fleet.networks.length !== 0);
  renderFleetHealth(fleet);
  for (const health of fleet.reports) {
    const { network, nodes } = health;
    const card = document.createElement('article');
    card.className = `network-card severity-${health.summary.overall}`;
    const head = document.createElement('div'); head.className = 'network-card-head';
    const titleRow = document.createElement('div'); titleRow.className = 'network-title-row';
    const title = document.createElement('div');
    const h3 = document.createElement('h3'); h3.textContent = network.name;
    const activeResolvers = nodes.filter((node) => node.role === 'lighthouse' && node.status === 'active').length;
		const dnsSummary = network.dns_settings.enabled ? `DNS UDP ${network.dns_settings.listen_port} · ${activeResolvers} active ${activeResolvers === 1 ? 'resolver' : 'resolvers'}` : 'DNS disabled';
		const relaySummary = network.relay_settings.enabled ? `${network.relay_settings.relay_node_ids.length} managed ${network.relay_settings.relay_node_ids.length === 1 ? 'relay' : 'relays'}` : 'Relays disabled';
		const meta = document.createElement('p'); meta.className = 'network-meta'; meta.textContent = `${network.cidr} · Nebula UDP ${network.listen_port} · ${dnsSummary} · ${relaySummary} · revision ${network.config_revision}`;
    title.append(h3, meta);
    const networkLabel = severityLabel(health.summary.overall);
    const badge = document.createElement('span'); badge.className = `health-badge ${health.summary.overall}`; badge.textContent = networkLabel; badge.setAttribute('aria-label', `${network.name} health: ${networkLabel}`);
    titleRow.append(title, badge); head.append(titleRow); card.append(head);

    const setup = setupGuideModel.project(nodes, state.fleet.policy.required_healthy_lighthouses);
    const setupGuide = document.createElement('section'); setupGuide.className = 'network-setup-guide'; setupGuide.setAttribute('aria-label', `${network.name} guided setup`);
    const setupHeading = document.createElement('div'); setupHeading.className = 'network-setup-heading';
    const setupTitle = document.createElement('div');
    const setupEyebrow = document.createElement('p'); setupEyebrow.className = 'eyebrow'; setupEyebrow.textContent = 'Resume guided setup';
    const setupProgress = document.createElement('h4'); setupProgress.textContent = `${setup.completedStages} of ${setup.totalStages} lifecycle stages complete`;
    setupTitle.append(setupEyebrow, setupProgress);
    const setupAction = document.createElement('button'); setupAction.type = 'button'; setupAction.className = 'setup-next-action'; setupAction.textContent = setup.action.label;
    setupHeading.append(setupTitle, setupAction);
    const setupSteps = document.createElement('ol'); setupSteps.className = 'network-setup-steps'; setupSteps.setAttribute('aria-label', 'Lifecycle setup stages');
    for (const step of setup.stages) {
      const item = document.createElement('li'); item.className = `setup-step ${step.state}`; item.textContent = step.label; setupSteps.append(item);
    }
    const setupDetail = document.createElement('p'); setupDetail.className = 'network-setup-detail'; setupDetail.textContent = setup.detail;
    const setupScope = document.createElement('p'); setupScope.className = 'network-setup-scope'; setupScope.textContent = setup.scope;
    setupAction.addEventListener('click', () => {
      if (setup.action.kind === 'add_lighthouse') openNode(network.id, true, 'lighthouse');
      else if (setup.action.kind === 'add_member') openNode(network.id, false, 'member');
      else if (setup.action.kind === 'add_redundancy') openNode(network.id, true, 'redundancy');
      else if (setup.action.kind === 'readiness') openReadiness(network);
      else if (setup.action.kind === 'resume_node') {
        const pendingRow = [...list.children].find((item) => item.dataset.nodeId === setup.action.nodeID);
        const reissue = pendingRow?.querySelector('.reissue');
        if (!pendingRow || !reissue) {
          flash('The pending machine changed. Refresh authoritative inventory before continuing.');
          return;
        }
        pendingRow.scrollIntoView({ block: 'center', behavior: 'smooth' });
        reissue.focus({ preventScroll: true });
        flash('Pending enrollment selected. Use the saved credential, or choose Reissue enrollment if it is unavailable.');
      }
    });
    setupGuide.append(setupHeading, setupSteps, setupDetail, setupScope); card.append(setupGuide);

    const stats = document.createElement('div'); stats.className = 'network-stats';
    stats.append(
      stat(health.summary.active_nodes, 'Active nodes'),
      stat(health.summary.healthy_nodes, 'Healthy nodes'),
      stat(`${health.summary.healthy_lighthouses}/${health.summary.active_lighthouses}`, 'Operational lighthouses'),
    );
    card.append(stats);

    const rollout = document.createElement('div'); rollout.className = 'network-rollout';
    const rolloutCopy = document.createElement('div');
    const rolloutLabel = document.createElement('strong'); rolloutLabel.textContent = 'Rollout';
    const rolloutValue = document.createElement('span'); rolloutValue.textContent = `${health.rollout.converged_nodes} of ${health.rollout.eligible_nodes} active nodes current`;
    rolloutCopy.append(rolloutLabel, rolloutValue);
    const rolloutProgress = document.createElement('progress'); rolloutProgress.max = 100; rolloutProgress.value = health.rollout.percent; rolloutProgress.textContent = `${health.rollout.percent}%`;
    rolloutProgress.setAttribute('aria-label', `${network.name} rollout: ${health.rollout.converged_nodes} of ${health.rollout.eligible_nodes} active nodes current, ${health.rollout.percent} percent`);
    rollout.append(rolloutCopy, rolloutProgress); card.append(rollout);

    const warningPanel = document.createElement('section'); warningPanel.className = `network-warning-panel ${health.alerts.length ? health.summary.overall : 'healthy'}`;
    warningPanel.setAttribute('aria-label', `${network.name} health details`);
    if (health.alerts.length) {
      const warningTitle = document.createElement('h4'); warningTitle.textContent = 'Authoritative health alerts';
      const warningList = document.createElement('ul');
      const nodeNames = new Map(nodes.map((node) => [node.id, node.name]));
      for (const alert of health.alerts) warningList.append(warningItem(alert, '', nodeNames.get(alert.nodeID) || ''));
      warningPanel.append(warningTitle, warningList);
    } else {
      const healthy = document.createElement('p'); healthy.textContent = 'No active health warnings.'; warningPanel.append(healthy);
    }
    card.append(warningPanel);

    const list = document.createElement('ul'); list.className = 'node-list'; list.setAttribute('aria-label', `${network.name} nodes`);
    if (!nodes.length) {
      const empty = document.createElement('li'); empty.className = 'node-row node-row-empty'; empty.textContent = 'No nodes yet'; list.append(empty);
    }
    for (const node of nodes) list.append(nodeRow(node, network));
    card.append(list);
    const actions = document.createElement('div'); actions.className = 'network-actions';
    const readiness = document.createElement('button'); readiness.type = 'button'; readiness.className = 'check-readiness'; readiness.textContent = 'Deployment readiness';
    readiness.addEventListener('click', () => openReadiness(network)); actions.append(readiness);
		const dns = document.createElement('button'); dns.type = 'button'; dns.className = 'manage-dns'; dns.textContent = 'Network DNS';
		dns.addEventListener('click', () => openDNS(network)); actions.append(dns);
		const relays = document.createElement('button'); relays.type = 'button'; relays.className = 'manage-relays'; relays.textContent = 'Network relays';
		relays.addEventListener('click', () => openRelays(network)); actions.append(relays);
		const caRotation = document.createElement('button'); caRotation.type = 'button'; caRotation.className = 'manage-ca-rotation'; caRotation.textContent = 'Rotate CA';
		caRotation.addEventListener('click', () => openCARotation(network)); actions.append(caRotation);
		const routeTransfer = document.createElement('button'); routeTransfer.type = 'button'; routeTransfer.className = 'manage-route-transfer'; routeTransfer.textContent = 'Transfer routes';
		routeTransfer.addEventListener('click', () => openRouteTransfer(network, nodes)); actions.append(routeTransfer);
		const routePolicies = document.createElement('button'); routePolicies.type = 'button'; routePolicies.className = 'manage-route-policies'; routePolicies.textContent = 'Route policies';
		routePolicies.addEventListener('click', () => openRoutePolicies(network)); actions.append(routePolicies);
    const policy = document.createElement('button'); policy.type = 'button'; policy.className = 'manage-policy'; policy.textContent = 'Firewall policy';
    policy.addEventListener('click', () => openPolicy(network)); actions.append(policy);
    const add = document.createElement('button'); appendIconLabel(add, 'plus', nodes.length ? 'Add node' : 'Add your first lighthouse');
    add.addEventListener('click', () => openNode(network.id, nodes.length === 0, nodes.length === 0 ? 'lighthouse' : '')); actions.append(add);
		const retire = document.createElement('button'); retire.type = 'button'; retire.className = 'retire-network-button'; retire.textContent = 'Retire network';
		retire.addEventListener('click', () => openNetworkRetirement(network, nodes)); actions.append(retire); card.append(actions);
    grid.append(card);
  }
}

function renderFleetHealth(fleet) {
  $('#fleet-healthy-networks').textContent = fleet.summary.healthy_networks;
  $('#fleet-warning-networks').textContent = fleet.summary.warning_networks;
  $('#fleet-critical-networks').textContent = fleet.summary.critical_networks;
  $('#fleet-critical-nodes').textContent = fleet.summary.critical_nodes;
  $('#fleet-setup-nodes').textContent = fleet.summary.setup_nodes;

  const badge = $('#fleet-health-badge');
  badge.className = `health-badge ${fleet.summary.overall}`;
  const label = fleet.summary.total_networks === 0 ? 'No networks' : severityLabel(fleet.summary.overall);
  badge.textContent = label;
  badge.setAttribute('aria-label', fleet.summary.total_networks === 0 ? 'Fleet health: no networks' : `Fleet health: ${label}`);

  const rolloutHasEligibleNodes = fleet.rollout.eligible_nodes > 0;
  const rolloutCopy = rolloutHasEligibleNodes
    ? `${fleet.rollout.converged_nodes} of ${fleet.rollout.eligible_nodes} active nodes current`
    : 'Awaiting active nodes';
  $('#fleet-rollout-value').textContent = rolloutCopy;
  const progress = $('#fleet-rollout-progress');
  progress.max = 100;
  progress.value = rolloutHasEligibleNodes ? fleet.rollout.percent : 0;
  progress.textContent = rolloutHasEligibleNodes ? `${fleet.rollout.percent}%` : 'Awaiting active nodes';
  progress.setAttribute('aria-label', rolloutHasEligibleNodes
    ? `Fleet rollout: ${fleet.rollout.converged_nodes} of ${fleet.rollout.eligible_nodes} active nodes current, ${fleet.rollout.percent} percent`
    : 'Fleet rollout: awaiting active nodes');

  const generated = $('#fleet-generated-at');
  generated.dateTime = fleet.generatedAt;
  generated.textContent = new Date(fleet.generatedAt).toLocaleString();
  $('#fleet-health-freshness').textContent = `Authoritative snapshot generated ${generated.textContent}. Heartbeats warn after ${formatDuration(fleet.policy.heartbeat_warning_after_seconds)} and become offline after ${formatDuration(fleet.policy.heartbeat_offline_after_seconds)}. Lifecycle health remains separate from the aggregate runtime observations shown below; those observations are not end-to-end reachability results.`;

  const warnings = [];
  for (const report of fleet.reports) {
    const nodeNames = new Map(report.nodes.map((node) => [node.id, node.name]));
    for (const alert of report.alerts) warnings.push({ network: report.network.name, node: nodeNames.get(alert.nodeID) || '', alert });
  }
  const panel = $('#fleet-warning-panel');
  const list = $('#fleet-warning-list');
  list.replaceChildren();
  for (const entry of warnings) {
    const item = warningItem(entry.alert, entry.network, entry.node);
    list.append(item);
  }
  const warningCount = $('#fleet-warning-count');
  warningCount.textContent = `${warnings.length} ${warnings.length === 1 ? 'alert' : 'alerts'}`;
  panel.classList.toggle('hidden', warnings.length === 0);
  $('#fleet-healthy-copy').classList.toggle('hidden', warnings.length !== 0);
}

function renderFleetUnavailable(message) {
  $('#fleet-healthy-networks').textContent = '—';
  $('#fleet-warning-networks').textContent = '—';
  $('#fleet-critical-networks').textContent = '—';
  $('#fleet-critical-nodes').textContent = '—';
  $('#fleet-setup-nodes').textContent = '—';
  const badge = $('#fleet-health-badge'); badge.className = 'health-badge critical'; badge.textContent = 'Unavailable'; badge.setAttribute('aria-label', 'Fleet health unavailable');
  $('#fleet-rollout-value').textContent = 'Authoritative rollout unavailable';
  const progress = $('#fleet-rollout-progress'); progress.max = 1; progress.value = 0; progress.textContent = 'Unavailable'; progress.setAttribute('aria-label', 'Fleet rollout unavailable');
  $('#fleet-generated-at').removeAttribute('datetime'); $('#fleet-generated-at').textContent = 'unavailable';
  $('#fleet-health-freshness').textContent = 'No health or inventory is inferred when the authoritative snapshot is unavailable.';
  const panel = $('#fleet-warning-panel'); panel.classList.remove('hidden');
  $('#fleet-warning-count').textContent = '1 alert';
  const list = $('#fleet-warning-list'); list.replaceChildren();
  const item = document.createElement('li'); item.className = 'health-warning critical';
  const severity = document.createElement('span'); severity.className = 'warning-severity'; severity.textContent = 'critical';
  const text = document.createElement('span'); text.textContent = message;
  item.append(severity, text); list.append(item);
  $('#fleet-healthy-copy').classList.add('hidden');
}

function warningItem(alert, networkName = '', nodeName = '') {
  const presentation = healthModel.alertPresentation(alert);
  const item = document.createElement('li'); item.className = `health-warning ${alert.severity}`;
  const severity = document.createElement('span'); severity.className = 'warning-severity'; severity.textContent = alert.severity;
  const text = document.createElement('span');
  const prefix = networkName ? `${networkName}: ` : '';
  const affected = nodeName ? ` — ${nodeName}` : '';
  const evidence = presentation.evidence ? ` (${presentation.evidence})` : '';
  text.textContent = `${prefix}${presentation.label}${affected}${evidence}`;
  item.append(severity, text);
  return item;
}

function severityLabel(value) { return value === 'critical' ? 'Critical' : value === 'warning' ? 'Warning' : 'Healthy'; }

function formatDuration(seconds) {
  if (seconds % 86400 === 0) return `${seconds / 86400} days`;
  if (seconds % 60 === 0) return `${seconds / 60} minutes`;
  return `${seconds} seconds`;
}

function stat(value, label) { const box = document.createElement('div'); box.className = 'stat'; const strong = document.createElement('strong'); strong.textContent = value; const span = document.createElement('span'); span.textContent = label; box.append(strong, span); return box; }

function runtimeObservationPresentation(node) {
  try {
    const estimatedNowMS = state.runtimeTelemetry ? runtimeTelemetryModel.estimatedServerNow(
      state.runtimeTelemetryResponseNowMS, state.runtimeTelemetryLoadedAtMS, Date.now(),
    ) : 0;
    return runtimeTelemetryModel.presentation(node, state.runtimeTelemetry, estimatedNowMS);
  } catch {
    // Observation rendering is deliberately best effort. A local clock jump or
    // adapter failure must never clear or reclassify authoritative lifecycle
    // health and inventory.
    return runtimeTelemetryModel.presentation(node, null, 0);
  }
}

function validatePendingCancellationReceipt(result, node, network) {
	if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('Pending enrollment cancellation returned an invalid receipt.');
	const expectedKeys = [
		'node_id', 'network_id', 'name', 'ip', 'role', 'cancelled_at', 'enrollment_records_invalidated',
		'relay_assignment_removed', 'routed_subnet_reservations_released', 'config_revision',
	];
	const keys = Object.keys(result).sort();
	if (keys.length !== expectedKeys.length || expectedKeys.some((key) => !keys.includes(key))) throw new Error('Pending enrollment cancellation returned an invalid receipt.');
	if (result.node_id !== node.id || result.network_id !== network.id || result.name !== node.name || result.ip !== node.ip || result.role !== node.role) throw new Error('Pending enrollment cancellation receipt did not match the selected node.');
	if (!Number.isInteger(result.enrollment_records_invalidated) || result.enrollment_records_invalidated < 1 || typeof result.relay_assignment_removed !== 'boolean' || result.routed_subnet_reservations_released !== node.routed_subnets.length || !Number.isInteger(result.config_revision) || result.config_revision < network.config_revision) throw new Error('Pending enrollment cancellation returned invalid cleanup evidence.');
	if (typeof result.cancelled_at !== 'string' || !Number.isFinite(Date.parse(result.cancelled_at))) throw new Error('Pending enrollment cancellation returned an invalid timestamp.');
	return result;
}

function validateNodeArchivalReceipt(result, node, network) {
	if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('Revoked node archival returned an invalid receipt.');
	const enrolled = Boolean(node.certificate_expires_at);
	const expectedKeys = [
		'node_id', 'network_id', 'name', 'ip', 'role', 'revoked_at', 'archived_at',
		'enrollment_records_removed', 'agent_recovery_records_removed', 'certificate_issuances_removed',
		'revocations_removed', 'blocklist_entries_removed', 'routed_subnet_reservations_released', 'config_revision',
		'runtime_telemetry_record_removed', 'runtime_telemetry_cleanup_complete',
	];
	if (enrolled) expectedKeys.push('last_certificate_expired_at');
	const keys = Object.keys(result).sort();
	if (keys.length !== expectedKeys.length || expectedKeys.some((key) => !keys.includes(key))) throw new Error('Revoked node archival returned an invalid receipt.');
	if (result.node_id !== node.id || result.network_id !== network.id || result.name !== node.name || result.ip !== node.ip || result.role !== node.role) throw new Error('Revoked node archival receipt did not match the selected node.');
	if (![result.revoked_at, result.archived_at].every((value) => typeof value === 'string' && Number.isFinite(Date.parse(value))) || Date.parse(result.archived_at) < Date.parse(result.revoked_at)) throw new Error('Revoked node archival returned invalid lifecycle timestamps.');
	for (const key of ['enrollment_records_removed', 'agent_recovery_records_removed', 'certificate_issuances_removed', 'revocations_removed', 'blocklist_entries_removed', 'routed_subnet_reservations_released']) {
		if (!Number.isInteger(result[key]) || result[key] < 0) throw new Error('Revoked node archival returned invalid removal counts.');
	}
	if (result.enrollment_records_removed < 1 || result.routed_subnet_reservations_released !== node.routed_subnets.length || result.blocklist_entries_removed !== result.revocations_removed || typeof result.runtime_telemetry_record_removed !== 'boolean' || typeof result.runtime_telemetry_cleanup_complete !== 'boolean') throw new Error('Revoked node archival returned invalid cleanup evidence.');
	const expectedRevision = network.config_revision + (enrolled ? 1 : 0);
	if (result.config_revision !== expectedRevision) throw new Error('Revoked node archival returned an invalid configuration revision transition.');
	if (enrolled) {
		const lastExpiryMS = Date.parse(result.last_certificate_expired_at);
		if (!Number.isFinite(lastExpiryMS) || lastExpiryMS < Date.parse(node.certificate_expires_at) || Date.parse(result.archived_at) < lastExpiryMS + NODE_ARCHIVE_CERTIFICATE_SAFETY_MARGIN_MS || result.certificate_issuances_removed < 1 || result.revocations_removed < 1) throw new Error('Revoked node archival returned invalid certificate-expiry evidence.');
	} else if (result.certificate_issuances_removed !== 0 || result.revocations_removed !== 0 || result.blocklist_entries_removed !== 0) {
		throw new Error('Never-enrolled revoked node archival returned unexpected certificate history.');
	}
	return result;
}

function certificateRotationIsAuthoritative(expected, receipt) {
	if (!state.fleet) return false;
	const network = state.networks.find((candidate) => candidate.id === expected.networkID);
	const node = (state.nodes.get(expected.networkID) || []).find((candidate) => candidate.id === expected.nodeID);
	return Boolean(network && node && node.status === 'active' && network.config_revision >= receipt.config_revision && node.certificate_generation >= receipt.certificate_generation);
}

function nodeRevocationIsAuthoritative(expected, receipt) {
	if (!state.fleet) return false;
	const network = state.networks.find((candidate) => candidate.id === expected.networkID);
	const node = (state.nodes.get(expected.networkID) || []).find((candidate) => candidate.id === expected.nodeID);
	return Boolean(network && node && node.status === 'revoked' && network.config_revision >= receipt.config_revision);
}

function authoritativeNodeIsAbsent(networkID, nodeID) {
	return state.fleet !== null && !(state.nodes.get(networkID) || []).some((node) => node.id === nodeID);
}

function nodeRow(node, network) {
  const row = document.createElement('li'); row.className = 'node-row';
  row.dataset.nodeId = node.id;
  const info = document.createElement('div'); const name = document.createElement('div'); name.className = 'node-name'; name.textContent = node.name;
  const revision = node.status === 'active' ? ` · config ${node.applied_config_revision}/${network.config_revision}` : '';
  const certificate = node.status === 'active' ? ` · cert g${node.applied_certificate_generation || 0}/g${node.certificate_generation || 0}` : '';
  const detail = document.createElement('div'); detail.className = 'node-detail'; detail.textContent = `${node.ip} · ${node.role} · ${node.site} / ${node.failure_domain}${revision}${certificate}`; info.append(name, detail);
  if (node.status === 'active') info.append(heartbeatEvidence(node, 'node-heartbeat-detail'));
  if (node.routed_subnets.length) {
    const routes = document.createElement('p'); routes.className = 'node-route-detail';
    routes.textContent = `Routes via this certificate: ${node.routed_subnets.join(', ')}`;
    info.append(routes);
  }
  if (node.status === 'active') {
    const observation = runtimeObservationPresentation(node);
    const observationDetail = document.createElement('p'); observationDetail.className = `node-observation-detail ${observation.state}`;
    observationDetail.textContent = `${observation.label}: ${observation.detail}`;
    if (observation.receivedAt) observationDetail.title = `Aggregate report received ${new Date(observation.receivedAt).toLocaleString()}`;
    info.append(observationDetail);
  }
  if (node.alerts.length) {
    const issues = document.createElement('p'); issues.className = `node-health-detail ${node.severity}`; issues.textContent = node.alerts.map((alert) => {
      const presentation = healthModel.alertPresentation(alert);
      return `${presentation.label}${presentation.evidence ? ` (${presentation.evidence})` : ''}`;
    }).join(' · '); info.append(issues);
  }
  const statusClass = node.lifecycleStatus === 'revoked' ? 'revoked' : node.phase === 'setup' && node.severity === 'healthy' ? 'setup' : node.severity;
  const statusLabel = healthModel.nodeStatusLabel(node);
  const status = document.createElement('span'); status.className = `status ${statusClass}`; status.textContent = statusLabel;
  status.setAttribute('aria-label', `${node.name}: ${statusLabel}${node.alerts.length ? `. ${node.alerts.map((alert) => healthModel.alertPresentation(alert).label).join('. ')}` : ''}`);
  const statusDetails = [];
  if (node.last_seen_at) statusDetails.push(`Last seen ${new Date(node.last_seen_at).toLocaleString()}`);
  if (node.certificate_expires_at) statusDetails.push(`Certificate expires ${new Date(node.certificate_expires_at).toLocaleString()}`);
  if (node.certificate_renew_after) statusDetails.push(`Renewal eligible ${new Date(node.certificate_renew_after).toLocaleString()}`);
  if (node.agent_credential_expires_at) statusDetails.push(`Agent credential expires ${new Date(node.agent_credential_expires_at).toLocaleString()}`);
  if (statusDetails.length) status.title = statusDetails.join('\n');
	if (node.status === 'revoked' && node.certificate_expires_at) {
		const archiveEligibleAtMS = Date.parse(node.certificate_expires_at) + NODE_ARCHIVE_CERTIFICATE_SAFETY_MARGIN_MS;
		const archival = document.createElement('p'); archival.className = 'node-archive-detail';
		archival.textContent = state.fleet && state.fleet.generatedAtMS >= archiveEligibleAtMS
			? 'Certificate authority expired; this inventory record can be archived.'
			: `Blocklist retained until ${new Date(archiveEligibleAtMS).toLocaleString()}.`;
		info.append(archival);
	}
  row.append(info, status);

  const actions = document.createElement('div'); actions.className = 'node-actions';
	if (node.status !== 'revoked' && hasPermission('networks.write')) {
		const placement = document.createElement('button'); placement.className = 'placement'; placement.textContent = 'Edit placement'; placement.title = `Update site and failure domain for ${node.name}`;
		placement.addEventListener('click', () => {
			const form = $('#topology-form'); form.reset(); form.node_id.value = node.id; form.site.value = node.site; form.failure_domain.value = node.failure_domain;
			$('#topology-node-name').textContent = node.name; $('.form-error', form).textContent = ''; $('#topology-dialog').showModal(); form.site.focus();
		});
		actions.append(placement);
	}
  if (node.status === 'pending' && hasPermission('networks.write')) {
    const reissue = document.createElement('button'); reissue.className = 'reissue'; reissue.textContent = 'Reissue enrollment'; reissue.title = `Replace the enrollment token for ${node.name}`;
    reissue.addEventListener('click', async () => {
      if (!confirm(`Replace the enrollment token for ${node.name}? Any previously issued token will stop working immediately.`)) return;
      reissue.disabled = true;
      try {
        const result = await api(`/api/v1/nodes/${node.id}/enrollment/reissue`, { method: 'POST', body: '{}' });
        showEnrollment(result);
        await loadNetworks(true);
        flash(`${node.name} received a replacement one-time enrollment token`);
      } catch (error) {
        flash(`Could not reissue enrollment: ${error.message}`);
      } finally { reissue.disabled = false; }
    });
    actions.append(reissue);

		const cancel = document.createElement('button'); cancel.className = 'cancel-enrollment'; cancel.textContent = 'Cancel enrollment'; cancel.title = `Remove the never-enrolled pending node ${node.name}`;
		cancel.addEventListener('click', async () => {
			if (!confirm(`Cancel the pending enrollment for ${node.name}? Every issued enrollment token will stop working immediately, and its IP and routed-subnet reservations will be released. No certificate identity has been created; you can add the machine again later.`)) return;
			$$('button', actions).forEach((button) => { button.disabled = true; });
			try {
				const result = validatePendingCancellationReceipt(await api(`/api/v1/nodes/${node.id}/enrollment/cancel`, {
					method: 'POST', body: JSON.stringify({ confirmation_name: node.name }),
				}), node, network);
				await loadNetworks(true);
				if (!authoritativeNodeIsAbsent(network.id, node.id)) throw new Error('Cancellation committed, but authoritative inventory removal could not be verified. Refresh before continuing.');
				flash(`${node.name} pending enrollment cancelled; ${result.enrollment_records_invalidated} one-time credential${result.enrollment_records_invalidated === 1 ? '' : 's'} invalidated`);
			} catch (error) {
				await loadNetworks(true).catch(() => {});
				if (authoritativeNodeIsAbsent(network.id, node.id)) flash(`${node.name} is absent from authoritative inventory. Its pending enrollment ended despite an interrupted or invalid response.`);
				else flash(`Could not cancel enrollment: ${error.message}`);
			} finally { $$('button', actions).forEach((button) => { button.disabled = false; }); }
		});
		actions.append(cancel);
  }
  if (node.status === 'active') {
		const security = document.createElement('button'); security.className = 'node-security'; security.textContent = 'Security & access'; security.title = `Manage certificate groups and effective firewall rules for ${node.name}`;
		security.addEventListener('click', () => openNodeSecurity(network, node));
		if (hasPermission('networks.security')) actions.append(security);

		const editRoutes = document.createElement('button'); editRoutes.className = 'edit-routes'; editRoutes.textContent = 'Edit routes'; editRoutes.title = `Safely replace the routed-subnet certificate profile for ${node.name}`;
		editRoutes.addEventListener('click', () => openRouteProfile(network, node));
		if (hasPermission('networks.write')) actions.append(editRoutes);

    const recover = document.createElement('button'); recover.className = 'recover'; recover.textContent = 'Recover agent'; recover.title = `Issue a one-time agent recovery token for ${node.name}`;
    recover.addEventListener('click', async () => {
      if (!confirm(`Issue an agent recovery token for ${node.name}? This replaces any earlier recovery token, but it does not invalidate the current agent credential. The credential changes only when recovery succeeds.`)) return;
      recover.disabled = true;
      try {
        const result = await api(`/api/v1/nodes/${node.id}/agent-recovery`, { method: 'POST', body: '{}' });
        showAgentRecovery(result);
        flash(`${node.name} received a one-time agent recovery token`);
      } catch (error) {
        flash(`Could not issue agent recovery: ${error.message}`);
      } finally { recover.disabled = false; }
    });
    if (hasPermission('networks.security')) actions.append(recover);

		const pendingRotation = state.certificateRotationRequests.get(node.id);
		const rotateCertificate = document.createElement('button'); rotateCertificate.className = 'rotate-certificate'; rotateCertificate.textContent = pendingRotation ? 'Verify rotation' : 'Rotate certificate'; rotateCertificate.title = pendingRotation ? `Retry the exact pending certificate-rotation request for ${node.name}` : `Issue a same-key replacement certificate for ${node.name} and blocklist its current certificate`;
		rotateCertificate.addEventListener('click', async () => {
			const existing = state.certificateRotationRequests.get(node.id);
			if (!existing) {
				if (!confirm(`Rotate the host certificate for ${node.name}? Mesh will issue a replacement for its existing public key, blocklist the current certificate through its expiry, invalidate outstanding agent-recovery tokens, and deploy one signed revision. The node may briefly disconnect while installing it. This does not replace the private key; use Replace identity if that key is lost or may be compromised.`)) return;
				let requestID;
				try { requestID = certificateRotationModel.newRequestID(globalThis.crypto); } catch (error) { flash(error.message); return; }
				let expected;
				try { expected = certificateRotationModel.expected(node, network, requestID); } catch (error) { flash(`Could not rotate certificate: ${error.message}`); return; }
				try { rememberCertificateRotationRequest(expected); } catch (error) { flash(`Could not rotate certificate: ${error.message}`); return; }
			} else if (!confirm(`Retry verification of the exact prior certificate-rotation request for ${node.name}? This reuses its idempotency key and cannot issue a second replacement.`)) return;
			const expected = state.certificateRotationRequests.get(node.id);
			const requestBody = JSON.stringify({ expected_config_revision: expected.expectedConfigRevision, confirmation_name: expected.name, request_id: expected.requestID });
			$$('button', actions).forEach((button) => { button.disabled = true; });
			let receipt = null;
			let failure = null;
			for (let attempt = 0; attempt < 2 && !receipt; attempt += 1) {
				try {
					receipt = certificateRotationModel.validateReceipt(await api(`/api/v1/nodes/${expected.nodeID}/certificate/rotate`, { method: 'POST', body: requestBody, timeoutMS: 30000 }), expected);
				} catch (error) {
					failure = error;
					if ([400, 403, 404, 409, 422].includes(error.status)) break;
				}
			}
			try {
				if (!receipt) {
					if ([400, 403, 404, 409, 422].includes(failure?.status)) {
						forgetCertificateRotationRequest(node.id);
						flash(`Could not rotate certificate: ${failure.message}`);
					} else {
						flash(`${node.name} certificate-rotation outcome is still unknown. Use Verify rotation to replay the exact request safely.`);
					}
					await loadNetworks(true).catch(() => {});
					return;
				}
				forgetCertificateRotationRequest(node.id);
				await loadNetworks(true);
				if (!certificateRotationIsAuthoritative(expected, receipt)) throw new Error('The receipt was valid, but authoritative generation and revision readback did not confirm it.');
				flash(`${node.name} certificate rotated to generation ${receipt.certificate_generation}; waiting for its agent and peers to converge on revision ${receipt.config_revision}`);
			} catch (error) {
				flash(`Certificate rotation committed, but readback could not be verified: ${error.message}`);
			} finally { $$('button', actions).forEach((button) => { button.disabled = false; }); }
		});
		if (hasPermission('networks.security')) actions.append(rotateCertificate);

		const replaceIdentity = document.createElement('button'); replaceIdentity.className = 'replace-identity'; replaceIdentity.textContent = 'Replace identity'; replaceIdentity.title = `Replace the lost Nebula private-key identity for ${node.name}`;
		replaceIdentity.addEventListener('click', async () => {
			const confirmed = confirm(`Replace the Nebula identity for ${node.name}? Use this only when its Nebula private key is lost. The current identity will be revoked and blocklisted immediately, and connectivity will stop until the replacement enrolls. Its name, role, groups, placement, endpoint, and routed subnets will carry forward to a new node ID and IP.`);
			if (!confirmed) return;
			$$('button', actions).forEach((button) => { button.disabled = true; });
			try {
				const result = await api(`/api/v1/nodes/${node.id}/replace`, {
					method: 'POST', body: JSON.stringify({ expected_config_revision: network.config_revision }),
				});
				if (!result || result.revoked_node_id !== node.id || !validResourceID(result?.node?.id) || result.node.id === node.id || result.node.network_id !== network.id || result.node.status !== 'pending' || typeof result.enrollment_token !== 'string' || result.enrollment_token.length < 32 || result.config_revision !== network.config_revision + 1) {
					throw new Error('The identity changed, but its one-time response could not be verified');
				}
				showEnrollment(result);
				await loadNetworks(true);
				flash(`${node.name} has a new pending identity; enroll it to restore connectivity`);
			} catch (error) {
				await loadNetworks(true).catch(() => {});
				const pendingReplacement = (state.nodes.get(network.id) || []).find((candidate) => candidate.id !== node.id && candidate.name === node.name && candidate.status === 'pending');
				if (pendingReplacement) {
					flash(`${node.name} was replaced, but the one-time response was interrupted. Use Reissue enrollment on its pending identity.`);
				} else {
					flash(`Could not replace identity: ${error.message}`);
				}
			} finally { $$('button', actions).forEach((button) => { button.disabled = false; }); }
		});
		if (hasPermission('networks.security')) actions.append(replaceIdentity);
  }
	const pendingRevocation = state.nodeRevocationRequests.get(node.id);
	if ((node.status === 'active' || pendingRevocation) && hasPermission('networks.security')) {
		const revoke = document.createElement('button'); revoke.className = 'revoke'; revoke.textContent = pendingRevocation ? 'Verify revocation' : 'Revoke'; revoke.title = pendingRevocation ? `Replay the exact pending revocation request for ${node.name}` : `Revoke ${node.name}`;
		revoke.addEventListener('click', async () => {
			const existing = state.nodeRevocationRequests.get(node.id);
			if (!existing) {
				if (!confirm(`Revoke ${node.name}? Mesh will immediately invalidate its enrollment, agent, and recovery credentials; blocklist every applicable certificate; release routed-subnet reservations; and deploy one signed revision. This trust cutoff cannot be undone.`)) return;
				let requestID;
				try { requestID = nodeRevocationModel.newRequestID(globalThis.crypto); } catch (error) { flash(error.message); return; }
				let expected;
				try { expected = nodeRevocationModel.expected(node, network, requestID); } catch (error) { flash(`Could not revoke node: ${error.message}`); return; }
				try { rememberNodeRevocationRequest(expected); } catch (error) { flash(`Could not revoke node: ${error.message}`); return; }
			} else if (!confirm(`Retry verification of the exact prior revocation request for ${node.name}? This reuses its idempotency key and cannot perform a second trust cutoff.`)) return;
			const expected = state.nodeRevocationRequests.get(node.id);
			const requestBody = JSON.stringify({ expected_config_revision: expected.expectedConfigRevision, confirmation_name: expected.name, request_id: expected.requestID });
			$$('button', actions).forEach((button) => { button.disabled = true; });
			let receipt = null;
			let failure = null;
			for (let attempt = 0; attempt < 2 && !receipt; attempt += 1) {
				try {
					receipt = nodeRevocationModel.validateReceipt(await api(`/api/v1/nodes/${expected.nodeID}/revocation`, { method: 'POST', body: requestBody, timeoutMS: 30000 }), expected);
				} catch (error) {
					failure = error;
					if ([400, 403, 404, 409, 422].includes(error.status)) break;
				}
			}
			try {
				if (!receipt) {
					if ([400, 403, 404, 409, 422].includes(failure?.status)) {
						forgetNodeRevocationRequest(node.id);
						await loadNetworks(true).catch(() => {});
						const current = (state.nodes.get(expected.networkID) || []).find((candidate) => candidate.id === expected.nodeID);
						if (current?.status === 'revoked') flash(`${node.name} is authoritatively revoked, but this request could not recover its exact receipt.`);
						else flash(`Could not revoke node: ${failure.message}`);
					} else {
						flash(`${node.name} revocation outcome is still unknown. Use Verify revocation to replay the exact request safely.`);
						await loadNetworks(true).catch(() => {});
					}
					return;
				}
				forgetNodeRevocationRequest(node.id);
				await loadNetworks(true);
				if (!nodeRevocationIsAuthoritative(expected, receipt)) throw new Error('The receipt was valid, but authoritative inventory and revision readback did not confirm it.');
				flash(`${node.name} revoked; ${receipt.blocklist_entries_added} certificate fingerprint${receipt.blocklist_entries_added === 1 ? '' : 's'} added to revision ${receipt.config_revision}`);
			} catch (error) {
				flash(`Node revocation committed, but readback could not be verified: ${error.message}`);
			} finally { $$('button', actions).forEach((button) => { button.disabled = false; }); }
		});
		actions.append(revoke);
	}
	if (node.status === 'revoked' && hasPermission('networks.security')) {
		const certificateExpiryMS = node.certificate_expires_at ? Date.parse(node.certificate_expires_at) : 0;
		const archiveEligibleAtMS = certificateExpiryMS ? certificateExpiryMS + NODE_ARCHIVE_CERTIFICATE_SAFETY_MARGIN_MS : 0;
		const archiveEligible = !archiveEligibleAtMS || Boolean(state.fleet && state.fleet.generatedAtMS >= archiveEligibleAtMS);
		const archive = document.createElement('button'); archive.className = 'archive-node'; archive.textContent = archiveEligible ? 'Archive record' : 'Archive after certificate expiry';
		archive.disabled = !archiveEligible;
		archive.title = archiveEligible
			? `Remove the expired certificate history and revoked inventory record for ${node.name}`
			: `The certificate blocklist remains required through ${new Date(archiveEligibleAtMS).toLocaleString()}, five minutes after expiry`;
		archive.addEventListener('click', async () => {
			if (!confirm(`Archive the revoked record for ${node.name}? This removes its expired certificate history and inventory record. It does not perform revocation: its credentials are already invalid. Its name, IP, and routed subnets can be reused only by creating a fresh identity and enrollment token.`)) return;
			$$('button', actions).forEach((button) => { button.disabled = true; });
			try {
				const result = validateNodeArchivalReceipt(await api(`/api/v1/nodes/${node.id}/archive`, {
					method: 'POST', body: JSON.stringify({ expected_config_revision: network.config_revision, confirmation_name: node.name }),
				}), node, network);
				await loadNetworks(true);
				if (!authoritativeNodeIsAbsent(network.id, node.id)) throw new Error('Archival committed, but authoritative inventory removal could not be verified. Refresh before continuing.');
				flash(result.runtime_telemetry_cleanup_complete
					? `${node.name} archived; expired certificate history and inventory removed`
					: `${node.name} archived, but runtime telemetry cleanup failed and may require operator attention`);
			} catch (error) {
				await loadNetworks(true).catch(() => {});
				if (authoritativeNodeIsAbsent(network.id, node.id)) flash(`${node.name} is absent from authoritative inventory. Archival completed despite an interrupted or invalid response; runtime telemetry cleanup could not be verified.`);
				else flash(`Could not archive revoked node: ${error.message}`);
			} finally { $$('button', actions).forEach((button) => { button.disabled = false; }); }
		});
		actions.append(archive);
	}
  if (actions.childElementCount) row.append(actions);
  return row;
}

function renderSecurityGroupChips(groups) {
	const container = $('#node-security-current-groups'); container.replaceChildren();
	for (const group of groups) {
		const chip = document.createElement('span'); chip.className = 'security-group-chip'; chip.textContent = group; container.append(chip);
	}
}

function effectivePeerLabel(rule) {
	if (rule.group) return `group:${rule.group}`;
	if (rule.host) return rule.host === 'any' ? 'any peer' : rule.host;
	return 'unresolved peer';
}

function renderNodeEffectivePolicy(effectiveDocument) {
	const container = $('#node-effective-policy'); container.replaceChildren();
	if (!effectiveDocument) {
		const unavailable = window.document.createElement('p');
		unavailable.className = 'node-effective-empty'; unavailable.textContent = 'No effective policy was returned for this active node.'; container.append(unavailable); return;
	}
	const summary = window.document.createElement('p'); summary.className = 'field-hint';
	summary.textContent = `Compiled policy ${effectiveDocument.sha256.slice(0, 12)}… · ${effectiveDocument.inbound.length} inbound · ${effectiveDocument.outbound.length} outbound`;
	const directions = window.document.createElement('div'); directions.className = 'node-effective-directions';
	for (const [key, label] of [['inbound', 'Inbound'], ['outbound', 'Outbound']]) {
		const section = window.document.createElement('div'); section.className = 'node-effective-direction';
		const title = window.document.createElement('h5'); title.textContent = label; section.append(title);
		if (effectiveDocument[key].length === 0) {
			const empty = window.document.createElement('p'); empty.className = 'node-effective-empty'; empty.textContent = 'Default deny — no traffic allowed.'; section.append(empty);
		} else {
			for (const rule of effectiveDocument[key]) {
				const row = window.document.createElement('div'); row.className = 'node-effective-rule';
				const proto = window.document.createElement('span'); proto.textContent = rule.proto.toUpperCase();
				const port = window.document.createElement('span'); port.textContent = rule.port;
				const peer = window.document.createElement('span'); peer.textContent = effectivePeerLabel(rule);
				row.append(proto, port, peer); section.append(row);
			}
		}
		directions.append(section);
	}
	const rendered = window.document.createElement('details'); rendered.className = 'policy-rendered';
	const renderedSummary = window.document.createElement('summary'); renderedSummary.textContent = 'Exact rendered Nebula firewall';
	const pre = window.document.createElement('pre'); const code = window.document.createElement('code'); code.textContent = effectiveDocument.rendered_firewall; pre.append(code); rendered.append(renderedSummary, pre);
	container.append(summary, directions, rendered);
}

function renderNodeSecurityAudit(events, nodeID) {
	const list = $('#node-security-audit'); list.replaceChildren();
	const filtered = events.filter((event) => event.resource === 'node' && event.resource_id === nodeID).slice(0, 8);
	if (filtered.length === 0) {
		const empty = document.createElement('li'); empty.textContent = 'No recent node-specific audit events are in the retained window.'; list.append(empty); return;
	}
	for (const event of filtered) {
		const item = document.createElement('li');
		const action = document.createElement('span'); action.textContent = event.action.replaceAll('.', ' ');
		const at = document.createElement('time'); at.dateTime = event.at; at.textContent = new Date(event.at).toLocaleString();
		item.append(action, at); list.append(item);
	}
}

function canonicalGroupsFromInput(value) {
	const result = [...new Set(value.split(',').map((group) => group.trim()).filter(Boolean))];
	for (const group of result) {
		if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/u.test(group)) throw new Error(`“${group}” is not a valid certificate group.`);
	}
	if (!result.includes('all')) result.push('all');
	result.sort();
	if (result.length > 64) throw new Error('A node can have at most 64 groups including all.');
	return result;
}

function newNodeGroupsRequestID() {
	const bytes = new Uint8Array(16); globalThis.crypto.getRandomValues(bytes);
	return `node-groups-${[...bytes].map((value) => value.toString(16).padStart(2, '0')).join('')}`;
}

async function openNodeSecurity(network, node) {
	state.nodeSecurity = { networkID: network.id, nodeID: node.id, requestID: '', expectedRevision: network.config_revision, busy: false, currentGroups: [] };
	$('#node-security-name').textContent = node.name;
	$('#node-security-ip').textContent = node.ip;
	$('#node-security-config').textContent = `r${node.applied_config_revision}/r${network.config_revision}`;
	$('#node-security-certificate').textContent = `g${node.applied_certificate_generation || 0}/g${node.certificate_generation || 0}`;
	$('#node-security-runtime').textContent = node.operational ? 'Current' : node.nebula_running ? 'Converging' : 'Stopped';
	$('#node-security-confirmation-name').textContent = node.name;
	$('#node-security-confirmation').value = '';
	$('#node-security-groups-error').textContent = '';
	$('#node-security-groups').value = '';
	renderSecurityGroupChips(['all']);
	const loadingPolicy = document.createElement('p'); loadingPolicy.className = 'field-hint'; loadingPolicy.textContent = 'Loading effective policy…'; $('#node-effective-policy').replaceChildren(loadingPolicy);
	const loadingAudit = document.createElement('li'); loadingAudit.textContent = 'Loading audit history…'; $('#node-security-audit').replaceChildren(loadingAudit);
	$('#node-security-dialog').showModal();
	try {
		const reads = [api(`/api/v1/networks/${network.id}/firewall`)];
		if (hasPermission('audit.read')) reads.push(api('/api/v1/audit'));
		const [policy, events = []] = await Promise.all(reads);
		if (state.nodeSecurity.nodeID !== node.id) return;
		const effective = (policy.effective_nodes || []).find((candidate) => candidate.node_id === node.id);
		if (effective?.groups) {
			state.nodeSecurity.currentGroups = [...effective.groups];
			$('#node-security-groups').value = effective.groups.filter((group) => group !== 'all').join(', ');
			renderSecurityGroupChips(effective.groups);
		}
		renderNodeEffectivePolicy(effective);
		renderNodeSecurityAudit(events, node.id);
	} catch (error) {
		if (state.nodeSecurity.nodeID !== node.id) return;
		$('#node-effective-policy').replaceChildren();
		const message = document.createElement('p'); message.className = 'form-error'; message.textContent = `Could not load effective security state: ${error.message}`; $('#node-effective-policy').append(message);
	}
	$('#edit-node-policy').onclick = () => {
		$('#node-security-dialog').close();
		openPolicy(network, node.id);
	};
}

$('#node-groups-form').addEventListener('submit', async (event) => {
	event.preventDefault();
	const network = state.networks.find((candidate) => candidate.id === state.nodeSecurity.networkID);
	const node = (state.nodes.get(state.nodeSecurity.networkID) || []).find((candidate) => candidate.id === state.nodeSecurity.nodeID);
	if (!network || !node || state.nodeSecurity.busy) return;
	const errorBox = $('#node-security-groups-error'); errorBox.textContent = '';
	let groups;
	try { groups = canonicalGroupsFromInput($('#node-security-groups').value); } catch (error) { errorBox.textContent = error.message; return; }
	if ($('#node-security-confirmation').value !== node.name) {
		errorBox.textContent = `Type ${node.name} exactly to confirm this certificate replacement.`; $('#node-security-confirmation').focus(); return;
	}
	const currentGroups = [...state.nodeSecurity.currentGroups].sort();
	if (currentGroups.length === 0) {
		errorBox.textContent = 'Current certificate groups have not loaded yet. Close and reopen this screen before saving.'; return;
	}
	if (JSON.stringify(groups) === JSON.stringify(currentGroups)) {
		errorBox.textContent = 'Those groups are already embedded in the node certificate.'; return;
	}
	if (!state.nodeSecurity.requestID) state.nodeSecurity.requestID = newNodeGroupsRequestID();
	state.nodeSecurity.busy = true;
	$$('input, button', $('#node-groups-form')).forEach((control) => { control.disabled = true; });
	try {
		const receipt = await api(`/api/v1/nodes/${node.id}/groups`, {
			method: 'PUT', timeoutMS: 30000,
			body: JSON.stringify({
				expected_config_revision: state.nodeSecurity.expectedRevision,
				confirmation_name: node.name, request_id: state.nodeSecurity.requestID, groups,
			}),
		});
		if (receipt.node_id !== node.id || receipt.network_id !== network.id || receipt.request_id !== state.nodeSecurity.requestID || receipt.config_revision !== state.nodeSecurity.expectedRevision + 1 || !Array.isArray(receipt.groups) || JSON.stringify(receipt.groups) !== JSON.stringify(groups) || receipt.certificate_generation !== node.certificate_generation + 1 || receipt.previous_certificate_blocklisted !== true) throw new Error('The group update returned an invalid transition receipt.');
		await loadNetworks(true);
		const currentNetwork = state.networks.find((candidate) => candidate.id === network.id);
		const currentNode = (state.nodes.get(network.id) || []).find((candidate) => candidate.id === node.id);
		if (!currentNetwork || !currentNode || currentNetwork.config_revision < receipt.config_revision || currentNode.certificate_generation < receipt.certificate_generation) throw new Error('The update committed, but authoritative readback has not confirmed it yet.');
		$('#node-security-dialog').close();
		flash(`${node.name} groups updated; certificate generation ${receipt.certificate_generation} is converging on revision ${receipt.config_revision}`);
		await openNodeSecurity(currentNetwork, currentNode);
	} catch (error) {
		errorBox.textContent = [400, 403, 404, 409, 422].includes(error.status)
			? `Could not update groups: ${error.message}`
			: `The outcome is not yet known. Retry this button to replay the exact request safely: ${error.message}`;
	} finally {
		state.nodeSecurity.busy = false;
		$$('input, button', $('#node-groups-form')).forEach((control) => { control.disabled = false; });
	}
});

class PolicyInputError extends Error {
  constructor(message, field) {
    super(message);
    this.field = field;
  }
}

function policyField(row, name) {
  return $(`[data-policy-field="${name}"]`, row);
}

function policyContainer(direction) {
  return $(`#policy-${direction}-rules`);
}

function resetPolicyFeedback() {
  $('#policy-error').textContent = '';
  $('#policy-warnings').classList.add('hidden');
  $('#policy-warning-list').replaceChildren();
  $('#policy-preview').classList.add('hidden');
  $('#policy-preview-title').textContent = 'Preview ready';
  $('#policy-preview-summary').textContent = '';
  $('#policy-rendered').open = false;
  $('#policy-rendered-firewall').textContent = '';
  $('#policy-effective-preview').replaceChildren();
  $('#policy-next-revision').textContent = '—';
  $$('[aria-invalid="true"]', $('#policy-form')).forEach((field) => field.removeAttribute('aria-invalid'));
}

function clearPolicyEditor() {
  policyContainer('inbound').replaceChildren();
  policyContainer('outbound').replaceChildren();
  updatePolicyEmptyStates();
  resetPolicyFeedback();
}

function policyRolloutActive() {
  return state.policy.rollout?.phase === 'canary' || state.policy.rollout?.phase === 'paused';
}

function selectedPolicyCanaryIDs() {
  return $$('input[data-policy-canary-id]:checked', $('#policy-canary-list')).map((input) => input.dataset.policyCanaryId).sort();
}

function clearPolicyRefreshTimer() {
  if (state.policy.refreshTimer !== null) clearTimeout(state.policy.refreshTimer);
  state.policy.refreshTimer = null;
}

function schedulePolicyRolloutRefresh() {
  clearPolicyRefreshTimer();
  if (!policyRolloutActive() || !state.policy.networkID || $('#policy-dialog').open === false || document.visibilityState === 'hidden') return;
  state.policy.refreshTimer = setTimeout(() => refreshPolicyRollout(false), 5000);
}

function setPolicyBusy(busy) {
  state.policy.busy = busy;
  const form = $('#policy-form');
  form.setAttribute('aria-busy', String(busy));
  $$('input, select, button', form).forEach((control) => {
    control.disabled = busy;
  });
  if (!busy) {
    $$('.policy-rule', form).forEach(updatePolicyRowFields);
  }
	if (policyRolloutActive()) {
		$$('.policy-direction input, .policy-direction select, .policy-direction button', form).forEach((control) => { control.disabled = true; });
	}
	updatePolicyActionState();
}

function updatePolicyActionState() {
  const unavailable = state.policy.busy || !state.policy.loaded;
	const active = policyRolloutActive();
	const selected = selectedPolicyCanaryIDs();
	$('#policy-canary-count').textContent = `${selected.length} selected`;
	$('#add-inbound-rule').disabled = unavailable || active;
	$('#add-outbound-rule').disabled = unavailable || active;
	$('#preview-policy').disabled = unavailable || active;
	$('#save-policy').disabled = unavailable || active || selected.length === 0 || !state.policy.previewFingerprint || !state.policy.previewWouldChange;
	$('#save-policy').textContent = state.policy.busy && state.policy.action === 'start' ? 'Starting canary…' : 'Start canary rollout';
	const rollout = state.policy.rollout;
	$('#promote-policy').disabled = state.policy.busy || !rollout?.availableActions.includes('promote');
	$('#pause-policy').disabled = state.policy.busy || !rollout?.availableActions.includes('pause');
	$('#resume-policy').disabled = state.policy.busy || !rollout?.availableActions.includes('resume');
	$('#pause-policy').classList.toggle('hidden', !rollout?.availableActions.includes('pause'));
	$('#resume-policy').classList.toggle('hidden', !rollout?.availableActions.includes('resume'));
	$('#promote-policy').classList.toggle('hidden', !rollout?.availableActions.includes('promote'));
	$('#rollback-policy').disabled = state.policy.busy || !rollout?.availableActions.includes('rollback');
	for (const input of $$('input[data-policy-canary-id]', $('#policy-canary-list'))) input.disabled = unavailable || active || (!input.checked && selected.length >= firewallRolloutModel.MAX_CANARIES);
}

function showPolicyError(message, field) {
  const error = $('#policy-error');
  error.textContent = message;
  if (field) {
    field.setAttribute('aria-invalid', 'true');
    field.focus();
  } else {
    error.focus();
  }
}

function policyPortParts(port) {
  if (port === 'any') return { kind: 'any', start: '', end: '' };
  const range = String(port || '').match(/^(\d+)-(\d+)$/);
  if (range) return { kind: 'range', start: range[1], end: range[2] };
  return { kind: 'single', start: String(port || ''), end: '' };
}

function updatePolicyRowFields(row) {
  const proto = policyField(row, 'proto');
  const portKind = policyField(row, 'port-kind');
  const portStart = policyField(row, 'port-start');
  const portEnd = policyField(row, 'port-end');
  const icmp = proto.value === 'icmp';
  if (icmp) portKind.value = 'any';
  portKind.disabled = state.policy.busy || icmp;
  portKind.title = icmp ? 'Nebula ICMP rules require any port' : '';

  const showStart = !icmp && (portKind.value === 'single' || portKind.value === 'range');
  const showEnd = !icmp && portKind.value === 'range';
  portStart.closest('.policy-field').classList.toggle('hidden', !showStart);
  portEnd.closest('.policy-field').classList.toggle('hidden', !showEnd);
  portStart.required = showStart;
  portEnd.required = showEnd;

  const selectorKind = policyField(row, 'selector-kind');
  const selectorValue = policyField(row, 'selector-value');
  const selectorField = selectorValue.closest('.policy-field');
  const selectorNode = policyField(row, 'selector-node');
  const selectorNodeField = selectorNode.closest('.policy-field');
  const selectorLabel = $('label', selectorField);
  const selectorHint = $('.policy-selector-hint', selectorField);
  const hasValue = selectorKind.value === 'group' || selectorKind.value === 'host';
  selectorField.classList.toggle('hidden', !hasValue);
  selectorNodeField.classList.toggle('hidden', selectorKind.value !== 'node');
  selectorValue.required = hasValue;
  selectorNode.required = selectorKind.value === 'node';
  if (selectorKind.value === 'group') {
    selectorLabel.textContent = 'Security group';
    selectorValue.placeholder = 'servers';
    selectorHint.textContent = 'Use a group assigned to peer certificates.';
  } else if (selectorKind.value === 'host') {
    selectorLabel.textContent = 'IPv4 host or CIDR';
    selectorValue.placeholder = '10.42.0.10 or 10.42.0.0/24';
    selectorHint.textContent = 'Use a canonical IPv4 address or network.';
  } else {
    selectorLabel.textContent = 'Selector value';
    selectorValue.placeholder = '';
    selectorHint.textContent = '';
  }

  const targetKind = policyField(row, 'target-kind');
  const targetGroup = policyField(row, 'target-group');
  const targetNode = policyField(row, 'target-node');
  targetGroup.closest('.policy-field').classList.toggle('hidden', targetKind.value !== 'group');
  targetNode.closest('.policy-field').classList.toggle('hidden', targetKind.value !== 'node');
  targetGroup.required = targetKind.value === 'group';
  targetNode.required = targetKind.value === 'node';
}

function renumberPolicyRules(direction) {
  const label = direction === 'inbound' ? 'Inbound' : 'Outbound';
  $$('.policy-rule', policyContainer(direction)).forEach((row, index) => {
    $('.policy-rule-legend', row).textContent = `${label} rule ${index + 1}`;
    $('.policy-remove-rule', row).setAttribute('aria-label', `Remove ${label.toLowerCase()} rule ${index + 1}`);
  });
}

function addPolicyRule(direction, rule = null, focus = true) {
  const row = $('#policy-rule-template').content.firstElementChild.cloneNode(true);
  const prefix = `policy-${direction}-${++policyRuleSequence}`;
  row.dataset.direction = direction;
  $$('[data-policy-field]', row).forEach((field) => {
    field.id = `${prefix}-${field.dataset.policyField}`;
    const label = $('label', field.closest('.policy-field'));
    label.htmlFor = field.id;
  });
  const selectorValue = policyField(row, 'selector-value');
  const selectorHint = $('.policy-selector-hint', row);
  selectorHint.id = `${prefix}-selector-hint`;
  selectorValue.setAttribute('aria-describedby', selectorHint.id);
  const nodes = (state.nodes.get(state.policy.networkID) || []).filter((node) => node.status === 'active');
  for (const fieldName of ['selector-node', 'target-node']) {
    const select = policyField(row, fieldName); select.replaceChildren();
    for (const node of nodes) {
      const option = document.createElement('option'); option.value = node.id; option.textContent = `${node.name} · ${node.ip}`; select.append(option);
    }
  }

  const initial = rule || {
    proto: 'tcp', port: '', group: '',
    ...(state.policy.defaultTargetNodeID ? { target_node_id: state.policy.defaultTargetNodeID } : {}),
  };
  policyField(row, 'proto').value = initial.proto || 'any';
  const port = policyPortParts(initial.port);
  policyField(row, 'port-kind').value = port.kind;
  policyField(row, 'port-start').value = port.start;
  policyField(row, 'port-end').value = port.end;
  if (initial.peer_node_id) {
    policyField(row, 'selector-kind').value = 'node';
    policyField(row, 'selector-node').value = initial.peer_node_id;
    selectorValue.value = '';
  } else if (Object.prototype.hasOwnProperty.call(initial, 'group')) {
    policyField(row, 'selector-kind').value = 'group';
    selectorValue.value = initial.group || '';
  } else if (initial.host === 'any' || !initial.host) {
    policyField(row, 'selector-kind').value = 'any';
    selectorValue.value = '';
  } else {
    policyField(row, 'selector-kind').value = 'host';
    selectorValue.value = initial.host;
  }
  if (initial.target_node_id) {
    policyField(row, 'target-kind').value = 'node';
    policyField(row, 'target-node').value = initial.target_node_id;
  } else if (initial.target_group) {
    policyField(row, 'target-kind').value = 'group';
    policyField(row, 'target-group').value = initial.target_group;
  } else {
    policyField(row, 'target-kind').value = 'all';
  }

  row.addEventListener('input', () => {
    updatePolicyRowFields(row);
    invalidatePolicyPreview();
  });
  $('.policy-remove-rule', row).addEventListener('click', () => {
    row.remove();
    renumberPolicyRules(direction);
    updatePolicyEmptyStates();
    invalidatePolicyPreview();
  });
  policyContainer(direction).append(row);
  updatePolicyRowFields(row);
  renumberPolicyRules(direction);
  updatePolicyEmptyStates();
  if (focus) policyField(row, 'proto').focus();
}

function updatePolicyEmptyStates() {
  for (const direction of ['inbound', 'outbound']) {
    $(`#policy-${direction}-empty`).classList.toggle('hidden', policyContainer(direction).childElementCount !== 0);
  }
}

function canonicalIPv4Parts(value) {
  const pieces = value.split('/');
  if (pieces.length > 2 || !pieces[0]) return null;
  const octets = pieces[0].split('.');
  if (octets.length !== 4 || octets.some((octet) => !/^(0|[1-9]\d{0,2})$/.test(octet) || Number(octet) > 255)) return null;
  const prefixText = pieces.length === 1 ? '32' : pieces[1];
  if (!/^(0|[1-9]|[12]\d|3[0-2])$/.test(prefixText)) return null;
  const prefix = Number(prefixText);
  const address = (((Number(octets[0]) << 24) >>> 0) + (Number(octets[1]) << 16) + (Number(octets[2]) << 8) + Number(octets[3])) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  if (pieces.length === 2 && ((address & mask) >>> 0) !== address) return null;
  return { address, prefix };
}

function validCanonicalIPv4Selector(value) {
  const selector = canonicalIPv4Parts(value);
  const network = canonicalIPv4Parts(state.policy.networkCIDR);
  if (!selector || !network || selector.prefix < network.prefix) return false;
  const networkMask = network.prefix === 0 ? 0 : (0xffffffff << (32 - network.prefix)) >>> 0;
  return ((selector.address & networkMask) >>> 0) === network.address;
}

function policyPort(row, directionLabel, ruleNumber) {
  const kind = policyField(row, 'port-kind').value;
  if (kind === 'any') return 'any';
  const startField = policyField(row, 'port-start');
  if (!/^[1-9]\d{0,4}$/.test(startField.value) || Number(startField.value) > 65535) {
    throw new PolicyInputError(`${directionLabel} rule ${ruleNumber}: port must be an integer from 1 to 65535.`, startField);
  }
  if (kind === 'single') return String(Number(startField.value));
  const endField = policyField(row, 'port-end');
  if (!/^[1-9]\d{0,4}$/.test(endField.value) || Number(endField.value) > 65535) {
    throw new PolicyInputError(`${directionLabel} rule ${ruleNumber}: end port must be an integer from 1 to 65535.`, endField);
  }
  if (Number(endField.value) <= Number(startField.value)) {
    throw new PolicyInputError(`${directionLabel} rule ${ruleNumber}: end port must be greater than the start port.`, endField);
  }
  return `${Number(startField.value)}-${Number(endField.value)}`;
}

function collectPolicyRule(row, directionLabel, ruleNumber) {
  const proto = policyField(row, 'proto').value;
  if (!['any', 'tcp', 'udp', 'icmp'].includes(proto)) {
    throw new PolicyInputError(`${directionLabel} rule ${ruleNumber}: choose a supported protocol.`, policyField(row, 'proto'));
  }
  const port = policyPort(row, directionLabel, ruleNumber);
  if (proto === 'icmp' && port !== 'any') {
    throw new PolicyInputError(`${directionLabel} rule ${ruleNumber}: ICMP requires any port.`, policyField(row, 'port-kind'));
  }
  const rule = { proto, port };
  const selectorKind = policyField(row, 'selector-kind').value;
  const selectorField = policyField(row, 'selector-value');
  const selectorValue = selectorField.value.trim();
  if (selectorKind === 'any') {
    rule.host = 'any';
  } else if (selectorKind === 'group') {
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/.test(selectorValue) || selectorValue === 'any') {
      throw new PolicyInputError(`${directionLabel} rule ${ruleNumber}: group must be 1–32 letters, numbers, underscores, or hyphens and cannot be “any”.`, selectorField);
    }
    rule.group = selectorValue;
  } else if (selectorKind === 'host') {
    if (!validCanonicalIPv4Selector(selectorValue)) {
      throw new PolicyInputError(`${directionLabel} rule ${ruleNumber}: enter a canonical IPv4 host or CIDR inside ${state.policy.networkCIDR}.`, selectorField);
    }
    rule.host = selectorValue;
  } else if (selectorKind === 'node') {
    const peerNodeID = policyField(row, 'selector-node').value;
    if (!validResourceID(peerNodeID)) {
      throw new PolicyInputError(`${directionLabel} rule ${ruleNumber}: choose an active peer node.`, policyField(row, 'selector-node'));
    }
    rule.peer_node_id = peerNodeID;
  } else {
    throw new PolicyInputError(`${directionLabel} rule ${ruleNumber}: choose one peer selector.`, policyField(row, 'selector-kind'));
  }
  const targetKind = policyField(row, 'target-kind').value;
  if (targetKind === 'group') {
    const targetGroup = policyField(row, 'target-group').value.trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/u.test(targetGroup) || targetGroup === 'all') {
      throw new PolicyInputError(`${directionLabel} rule ${ruleNumber}: local target group must be 1–32 letters, numbers, underscores, or hyphens and cannot be “all”.`, policyField(row, 'target-group'));
    }
    rule.target_group = targetGroup;
  } else if (targetKind === 'node') {
    const targetNodeID = policyField(row, 'target-node').value;
    if (!validResourceID(targetNodeID)) {
      throw new PolicyInputError(`${directionLabel} rule ${ruleNumber}: choose an active local node.`, policyField(row, 'target-node'));
    }
    rule.target_node_id = targetNodeID;
  } else if (targetKind !== 'all') {
    throw new PolicyInputError(`${directionLabel} rule ${ruleNumber}: choose where the rule is installed.`, policyField(row, 'target-kind'));
  }
  return rule;
}

function collectPolicyDraft() {
  const draft = { inbound: [], outbound: [] };
  for (const direction of ['inbound', 'outbound']) {
    const label = direction === 'inbound' ? 'Inbound' : 'Outbound';
    $$('.policy-rule', policyContainer(direction)).forEach((row, index) => {
      draft[direction].push(collectPolicyRule(row, label, index + 1));
    });
  }
  return draft;
}

function policyFingerprint(draft) {
  return JSON.stringify(draft);
}

function policyWarnings(draft) {
  const warnings = [];
  for (const direction of ['inbound', 'outbound']) {
    const label = direction === 'inbound' ? 'Inbound' : 'Outbound';
    if (draft[direction].length === 0) {
      warnings.push(`No ${direction} rules: all ${direction} overlay traffic will be denied.`);
      continue;
    }
    draft[direction].forEach((rule, index) => {
      const broad = [];
      if (rule.proto === 'any') broad.push('every protocol');
      if (rule.port === 'any') broad.push('every port');
      if (rule.host === 'any' || rule.host === state.policy.networkCIDR) broad.push('every peer');
      if (rule.group === 'all') broad.push('the built-in all group');
      if (broad.length) warnings.push(`${label} rule ${index + 1} includes ${broad.join(', ')}.`);
    });
  }
  return warnings;
}

function renderPolicyWarnings(draft) {
  const warnings = policyWarnings(draft);
  const list = $('#policy-warning-list');
  list.replaceChildren();
  for (const warning of warnings) {
    const item = document.createElement('li');
    item.textContent = warning;
    list.append(item);
  }
  $('#policy-warnings').classList.toggle('hidden', warnings.length === 0);
}

function invalidatePolicyPreview() {
  state.policy.previewFingerprint = '';
  state.policy.previewCanonicalFingerprint = '';
  state.policy.previewWouldChange = false;
  $('#policy-preview').classList.add('hidden');
  $('#policy-rendered').open = false;
  $('#policy-rendered-firewall').textContent = '';
  $('#policy-effective-preview').replaceChildren();
  $('#policy-next-revision').textContent = '—';
  $('#policy-error').textContent = '';
  $$('[aria-invalid="true"]', $('#policy-form')).forEach((field) => field.removeAttribute('aria-invalid'));
  try {
    renderPolicyWarnings(collectPolicyDraft());
  } catch {
    $('#policy-warnings').classList.add('hidden');
    $('#policy-warning-list').replaceChildren();
  }
  updatePolicyActionState();
}

function renderPolicyDocument(document) {
  policyContainer('inbound').replaceChildren();
  policyContainer('outbound').replaceChildren();
  for (const rule of document.inbound || []) addPolicyRule('inbound', rule, false);
  for (const rule of document.outbound || []) addPolicyRule('outbound', rule, false);
  state.policy.baseRevision = document.config_revision;
  $('#policy-current-revision').textContent = document.config_revision;
  $('#policy-next-revision').textContent = '—';
  $('#policy-mode').textContent = document.mode === 'legacy-default' ? 'Legacy default' : 'Managed';
  $('#policy-mode').title = document.mode === 'legacy-default' ? 'Stored without an explicit policy; effective legacy-compatible rules are shown.' : 'Explicit per-network firewall policy.';
  renderPolicyWarnings({ inbound: document.inbound || [], outbound: document.outbound || [] });
  updatePolicyEmptyStates();
}

function policyDocumentFromRolloutTarget(rollout) {
	if (!rollout.targetPolicy) return null;
	return {
		mode: rollout.targetPolicy.mode,
		inbound: rollout.targetPolicy.inbound,
		outbound: rollout.targetPolicy.outbound,
		effective_nodes: rollout.targetPolicy.effectiveNodes,
		policy_sha256: rollout.targetPolicy.policySHA256,
		config_revision: rollout.configRevision,
	};
}

function renderPolicyCanarySelection(rollout) {
	const list = $('#policy-canary-list'); list.replaceChildren();
	if (rollout.nodes.length === 0) {
		const empty = document.createElement('p'); empty.className = 'policy-canary-empty'; empty.textContent = 'Enroll and activate at least one node before starting a canary rollout.'; list.append(empty); return;
	}
	for (const node of rollout.nodes) {
		const label = document.createElement('label'); label.className = 'policy-canary-option';
		const input = document.createElement('input'); input.type = 'checkbox'; input.dataset.policyCanaryId = node.nodeID;
		input.addEventListener('change', updatePolicyActionState);
		const name = document.createElement('strong'); name.textContent = node.name;
		const detail = document.createElement('small'); detail.textContent = `${node.role} · ${node.ip}`;
		label.append(input, name, detail); list.append(label);
	}
}

function renderPolicyRollout(rollout) {
	state.policy.rollout = rollout;
	state.policy.baseRevision = rollout.configRevision;
	$('#policy-rollout-guards').textContent = 'Automatic rollback protects selected canaries when the exact signed target cannot activate or when an exact fresh target heartbeat reports the managed Nebula runtime stopped. Missing, stale, or generic degraded telemetry never triggers rollback.';
	$('#policy-current-revision').textContent = rollout.configRevision;
	$('#policy-rollout-phase').textContent = rollout.phase === 'canary' ? 'Canary active' : rollout.phase === 'paused' ? 'Paused' : 'Stable';
	$('#policy-rollout-convergence').textContent = rollout.phase === 'canary' ? `${rollout.convergedCanaries} of ${rollout.canaryNodes}` : rollout.phase === 'paused' ? `0 of ${rollout.canaryNodes}` : 'Not started';
	const selection = $('#policy-canary-selection');
	const nodeList = $('#policy-rollout-node-list');
	const actions = $('#policy-rollout-actions');
	const notice = $('#policy-rollout-notice');
	notice.classList.add('hidden'); notice.textContent = '';
	if (rollout.phase === 'stable' && rollout.lastTransition?.action === 'auto_rolled_back') {
		const failedNode = rollout.nodes.find((node) => node.nodeID === rollout.lastTransition.nodeID);
		const nodeLabel = failedNode?.name || rollout.lastTransition.nodeID || 'the selected canary';
		notice.textContent = rollout.lastTransition.reasonCode === 'canary_config_activation_failed'
			? `${nodeLabel} reported that the exact signed target could not be activated. Mesh automatically restored the retained policy at revision ${rollout.configRevision}.`
			: rollout.lastTransition.reasonCode === 'canary_target_runtime_stopped'
				? `${nodeLabel} reported the exact signed target and certificate but its managed Nebula process was stopped. Mesh automatically restored the retained policy at revision ${rollout.configRevision}.`
			: rollout.lastTransition.reasonCode === 'last_canary_revoked'
				? `The final selected canary was revoked. Mesh automatically discarded the staged policy at revision ${rollout.configRevision}.`
				: `Mesh automatically rolled back the staged firewall policy at revision ${rollout.configRevision}.`;
		notice.classList.remove('hidden');
	}
	if (rollout.phase === 'stable') {
		$('#policy-rollout-copy').textContent = rollout.availableActions.includes('start')
			? 'Select a small active cohort. Only those nodes receive the target policy until exact signed-config convergence unlocks promotion.'
			: rollout.activeNodes === 0 ? 'Add and activate a node before staging a firewall change.' : 'Another protected network transition is active; finish it before staging a firewall change.';
		selection.classList.remove('hidden'); nodeList.classList.add('hidden'); actions.classList.add('hidden'); nodeList.replaceChildren();
		renderPolicyCanarySelection(rollout);
	} else if (rollout.phase === 'canary') {
		const pending = rollout.canaryNodes - rollout.convergedCanaries;
		$('#policy-rollout-copy').textContent = pending === 0
			? 'Every canary proves the exact target revision, digest, certificate identity, and running Nebula process. Promotion is now available.'
			: `${pending} canary ${pending === 1 ? 'node still needs' : 'nodes still need'} to prove the exact signed target config. Rollback remains available now.`;
		selection.classList.add('hidden'); nodeList.classList.remove('hidden'); actions.classList.remove('hidden'); nodeList.replaceChildren();
		for (const node of rollout.nodes.filter((candidate) => candidate.canary)) {
			const item = document.createElement('li'); item.className = `readiness-check ${node.converged ? 'pass' : 'pending'}`;
			const copy = document.createElement('span'); copy.className = 'ca-rotation-node-copy';
			const name = document.createElement('strong'); name.textContent = node.name;
			const detail = document.createElement('small'); detail.textContent = `config r${node.appliedConfigRevision}/r${rollout.configRevision} · cert g${node.appliedCertificateGeneration}/g${node.certificateGeneration} · Nebula ${node.nebulaRunning ? 'running' : 'stopped'}`;
			copy.append(name, detail); item.append(copy); nodeList.append(item);
		}
	} else {
		$('#policy-rollout-copy').textContent = `The ${rollout.canaryNodes} selected ${rollout.canaryNodes === 1 ? 'canary is' : 'canaries are'} being returned to the retained known-good policy. The staged target and cohort are preserved; resuming issues a new signed revision and requires fresh convergence.`;
		selection.classList.add('hidden'); nodeList.classList.remove('hidden'); actions.classList.remove('hidden'); nodeList.replaceChildren();
		for (const node of rollout.nodes.filter((candidate) => candidate.canary)) {
			const item = document.createElement('li'); item.className = 'readiness-check pending';
			const copy = document.createElement('span'); copy.className = 'ca-rotation-node-copy';
			const name = document.createElement('strong'); name.textContent = node.name;
			const detail = document.createElement('small'); detail.textContent = `retained policy r${rollout.configRevision} requested · applied r${node.appliedConfigRevision} · Nebula ${node.nebulaRunning ? 'running' : 'stopped'}`;
			copy.append(name, detail); item.append(copy); nodeList.append(item);
		}
	}
	updatePolicyActionState();
	schedulePolicyRolloutRefresh();
}

async function openPolicy(network, defaultTargetNodeID = '') {
	clearPolicyRefreshTimer();
  const requestID = ++state.policy.requestID;
  state.policy.networkID = network.id;
  state.policy.networkCIDR = network.cidr;
  state.policy.baseRevision = network.config_revision;
  state.policy.previewFingerprint = '';
  state.policy.previewCanonicalFingerprint = '';
  state.policy.previewWouldChange = false;
  state.policy.defaultTargetNodeID = defaultTargetNodeID;
  state.policy.loaded = false;
	state.policy.rollout = null;
	state.policy.action = '';
  const form = $('#policy-form');
  form.reset();
  form.network_id.value = network.id;
  clearPolicyEditor();
  $('#policy-network-name').textContent = network.name;
  $('#policy-current-revision').textContent = network.config_revision;
  $('#policy-mode').textContent = 'Loading…';
	$('#policy-rollout-phase').textContent = 'Loading';
	$('#policy-rollout-convergence').textContent = '—';
	$('#policy-rollout-copy').textContent = 'Loading authoritative rollout state…';
	$('#policy-rollout-guards').textContent = 'Automatic rollback guards are loading…';
	$('#policy-rollout-notice').textContent = ''; $('#policy-rollout-notice').classList.add('hidden');
	$('#policy-canary-list').replaceChildren(); $('#policy-rollout-node-list').replaceChildren();
	$('#policy-canary-selection').classList.remove('hidden'); $('#policy-rollout-node-list').classList.add('hidden'); $('#policy-rollout-actions').classList.add('hidden');
  const affected = (state.nodes.get(network.id) || []).filter((node) => node.status === 'active').length;
  $('#policy-node-count').textContent = affected;
  $('#policy-dialog').showModal();
  setPolicyBusy(true);
  try {
		const [document, rawRollout] = await Promise.all([
			api(`/api/v1/networks/${network.id}/firewall`),
			api(`/api/v1/networks/${network.id}/firewall-rollout`),
		]);
    if (requestID !== state.policy.requestID) return;
		const rollout = firewallRolloutModel.validate(rawRollout);
		if (rollout.networkID !== network.id || document.network_id !== network.id || document.config_revision !== rollout.configRevision) throw new Error('Firewall policy and rollout state did not match the selected network revision.');
		renderPolicyDocument(policyDocumentFromRolloutTarget(rollout) || document);
		renderPolicyRollout(rollout);
    state.policy.loaded = true;
  } catch (error) {
    if (requestID !== state.policy.requestID) return;
    showPolicyError(`Could not load firewall policy: ${error.message}`);
  } finally {
    if (requestID === state.policy.requestID) setPolicyBusy(false);
  }
}

function renderPolicyEffectivePreview(nodes) {
	const container = $('#policy-effective-preview'); container.replaceChildren();
	for (const node of nodes || []) {
		const details = document.createElement('details'); details.className = 'policy-effective-node';
		const summary = document.createElement('summary');
		const name = document.createElement('strong'); name.textContent = node.name;
		const counts = document.createElement('small'); counts.textContent = `${node.inbound.length} inbound · ${node.outbound.length} outbound · ${node.sha256.slice(0, 10)}…`;
		summary.append(name, counts);
		const pre = document.createElement('pre'); const code = document.createElement('code'); code.textContent = node.rendered_firewall; pre.append(code);
		details.append(summary, pre); container.append(details);
	}
}

async function previewPolicy() {
  let draft;
  try {
    draft = collectPolicyDraft();
  } catch (error) {
    if (error instanceof PolicyInputError) showPolicyError(error.message, error.field);
    else showPolicyError(error.message);
    return;
  }
  const fingerprint = policyFingerprint(draft);
  const requestID = state.policy.requestID;
  state.policy.previewFingerprint = '';
  state.policy.previewCanonicalFingerprint = '';
  state.policy.previewWouldChange = false;
  $('#policy-preview').classList.add('hidden');
  $('#policy-next-revision').textContent = '—';
  setPolicyBusy(true);
  $('#policy-error').textContent = '';
  try {
    const networkID = state.policy.networkID;
    const preview = await api(`/api/v1/networks/${networkID}/firewall/preview`, { method: 'PUT', body: JSON.stringify(draft) });
    if (requestID !== state.policy.requestID) return;
    state.policy.baseRevision = preview.config_revision;
    state.policy.previewFingerprint = fingerprint;
    state.policy.previewCanonicalFingerprint = policyFingerprint({ inbound: preview.inbound || [], outbound: preview.outbound || [] });
    state.policy.previewWouldChange = Boolean(preview.would_change);
    $('#policy-current-revision').textContent = preview.config_revision;
    const proposedRevision = Number.isInteger(preview.proposed_config_revision) ? preview.proposed_config_revision : preview.config_revision + (preview.would_change ? 1 : 0);
    $('#policy-next-revision').textContent = proposedRevision;
    $('#policy-preview-title').textContent = preview.would_change ? 'Deployment preview ready' : 'No deployment needed';
		const affected = selectedPolicyCanaryIDs().length;
    if (preview.would_change) {
			$('#policy-preview-summary').textContent = affected > 0
				? `${affected} selected ${affected === 1 ? 'canary' : 'canaries'} will receive revision ${proposedRevision}; every other node retains the current policy until promotion.`
				: `Select at least one active canary. Other nodes will retain the current policy until promotion.`;
    } else {
      $('#policy-preview-summary').textContent = `This draft is equivalent to the policy at revision ${preview.config_revision}; saving would make no change.`;
    }
    $('#policy-rendered-firewall').textContent = preview.rendered_firewall || '';
    $('#policy-rendered').classList.toggle('hidden', !preview.rendered_firewall);
    renderPolicyEffectivePreview(preview.effective_nodes || []);
    $('#policy-preview').classList.remove('hidden');
    renderPolicyWarnings(draft);
  } catch (error) {
    if (requestID !== state.policy.requestID) return;
    state.policy.previewFingerprint = '';
    state.policy.previewCanonicalFingerprint = '';
    state.policy.previewWouldChange = false;
    showPolicyError(`Could not preview firewall policy: ${error.message}`);
  } finally {
    if (requestID === state.policy.requestID) setPolicyBusy(false);
  }
}

async function savePolicy(event) {
  event.preventDefault();
  let draft;
  try {
    draft = collectPolicyDraft();
  } catch (error) {
    if (error instanceof PolicyInputError) showPolicyError(error.message, error.field);
    else showPolicyError(error.message);
    return;
  }
  if (!state.policy.previewFingerprint || policyFingerprint(draft) !== state.policy.previewFingerprint) {
    invalidatePolicyPreview();
    showPolicyError('The policy changed after its preview. Preview the current rules before saving.');
    return;
  }
  if (!state.policy.previewWouldChange) {
    showPolicyError('This policy is already active; there is nothing to deploy.');
    return;
  }
	const canaryNodeIDs = selectedPolicyCanaryIDs();
	if (canaryNodeIDs.length === 0) {
		showPolicyError('Select at least one active canary before starting the rollout.');
		return;
	}
  const requestID = state.policy.requestID;
  const expectedRevision = state.policy.baseRevision;
  const proposedFingerprint = state.policy.previewCanonicalFingerprint;
	state.policy.action = 'start';
  setPolicyBusy(true);
  $('#policy-error').textContent = '';
  try {
		const updated = firewallRolloutModel.validate(await api(`/api/v1/networks/${state.policy.networkID}/firewall-rollout`, {
			method: 'POST',
			body: JSON.stringify({ action: 'start', expected_config_revision: expectedRevision, canary_node_ids: canaryNodeIDs, ...draft }),
		}));
    if (requestID !== state.policy.requestID) return;
		if (!policyStartedAsExpected(updated, expectedRevision, proposedFingerprint, canaryNodeIDs)) throw new Error('Firewall rollout returned an unexpected network, target, canary set, or revision transition.');
		completePolicyCanaryStart(updated, false);
  } catch (error) {
    if (requestID !== state.policy.requestID) return;
		if (error.status === 401) { $('#policy-dialog').close(); await showLogin(false); return; }
		try {
			const readback = firewallRolloutModel.validate(await api(`/api/v1/networks/${state.policy.networkID}/firewall-rollout`));
			if (requestID !== state.policy.requestID) return;
			if (policyStartedAsExpected(readback, expectedRevision, proposedFingerprint, canaryNodeIDs)) {
				completePolicyCanaryStart(readback, true); return;
			}
			renderPolicyRollout(readback);
			if ((readback.phase === 'canary' || readback.phase === 'paused') && readback.targetPolicy) renderPolicyDocument(policyDocumentFromRolloutTarget(readback));
			state.policy.previewFingerprint = '';
			state.policy.previewCanonicalFingerprint = '';
			state.policy.previewWouldChange = false;
			$('#policy-preview').classList.add('hidden'); $('#policy-next-revision').textContent = '—';
			showPolicyError(error.status === 409
				? `Network configuration changed to revision ${readback.configRevision}. Review the authoritative rollout state before retrying.`
				: `Could not start firewall canary: ${error.message}`);
		} catch (readbackError) {
			showPolicyError(`The canary outcome is unknown because both the action response and authoritative readback failed (${readbackError.message}). Reopen this network before retrying.`);
		}
  } finally {
		if (requestID === state.policy.requestID) { state.policy.action = ''; setPolicyBusy(false); }
  }
}

function rolloutCanaryIDs(rollout) {
	return rollout.nodes.filter((node) => node.canary).map((node) => node.nodeID).sort();
}

function policyStartedAsExpected(rollout, expectedRevision, proposedFingerprint, canaryNodeIDs) {
	return rollout.networkID === state.policy.networkID && rollout.phase === 'canary' && rollout.configRevision === expectedRevision + 1 &&
		rollout.targetPolicy && policyFingerprint({ inbound: rollout.targetPolicy.inbound, outbound: rollout.targetPolicy.outbound }) === proposedFingerprint &&
		JSON.stringify(rolloutCanaryIDs(rollout)) === JSON.stringify(canaryNodeIDs);
}

function completePolicyCanaryStart(rollout, interrupted) {
	state.policy.previewFingerprint = '';
	state.policy.previewCanonicalFingerprint = '';
	state.policy.previewWouldChange = false;
	$('#policy-preview').classList.add('hidden'); $('#policy-next-revision').textContent = '—';
	renderPolicyDocument(policyDocumentFromRolloutTarget(rollout));
	renderPolicyRollout(rollout);
	const networkName = state.networks.find((network) => network.id === rollout.networkID)?.name || rollout.networkID;
	flash(interrupted
		? `The response was interrupted, but firewall canary revision ${rollout.configRevision} is verified active on ${networkName}`
		: `Firewall canary revision ${rollout.configRevision} started on ${rollout.canaryNodes} ${rollout.canaryNodes === 1 ? 'node' : 'nodes'} in ${networkName}`);
	loadNetworks(true).catch(() => flash('Firewall canary started, but fleet health could not be refreshed.'));
}

async function refreshPolicyRollout(showErrors = true) {
	const networkID = state.policy.networkID;
	const requestID = state.policy.requestID;
	if (!networkID || state.policy.busy) return;
	try {
		const previousPhase = state.policy.rollout?.phase || '';
		const rollout = firewallRolloutModel.validate(await api(`/api/v1/networks/${networkID}/firewall-rollout`));
		if (requestID !== state.policy.requestID || rollout.networkID !== networkID) return;
		if ((previousPhase === 'canary' || previousPhase === 'paused') && rollout.phase === 'stable') {
			const active = await api(`/api/v1/networks/${networkID}/firewall`);
			if (requestID !== state.policy.requestID || active.network_id !== networkID || active.config_revision !== rollout.configRevision) return;
			renderPolicyDocument(active);
			if (rollout.lastTransition?.action === 'auto_rolled_back') {
				flash(`Firewall canaries were automatically rolled back at revision ${rollout.configRevision}`);
				loadNetworks(true).catch(() => flash('Firewall rollback completed, but fleet health could not be refreshed.'));
			}
		} else if ((rollout.phase === 'canary' || rollout.phase === 'paused') && rollout.targetPolicy) renderPolicyDocument(policyDocumentFromRolloutTarget(rollout));
		renderPolicyRollout(rollout);
	} catch (error) {
		if (requestID === state.policy.requestID && showErrors) showPolicyError(`Could not refresh firewall rollout: ${error.message}`);
		schedulePolicyRolloutRefresh();
	}
}

async function applyPolicyRolloutAction(action) {
	const current = state.policy.rollout;
	if (!current || !current.availableActions.includes(action)) return;
	const confirmations = {
		promote: 'Promote this firewall policy to every active node? The canaries have proved the exact signed target config, but all remaining nodes will now be asked to apply it.',
		pause: 'Pause this rollout? Selected canaries will receive a new signed revision containing the retained known-good policy. The target and cohort will remain staged.',
		resume: 'Resume this rollout? Selected canaries will receive the staged target in a new signed revision and must prove fresh convergence before promotion.',
		rollback: 'Roll back the canaries to the current fleet policy? The staged target will be discarded.',
	};
	const confirmation = confirmations[action];
	if (!confirm(confirmation)) return;
	const requestID = state.policy.requestID;
	const expectedRevision = current.configRevision;
	const expectedPolicySHA256 = action === 'promote' ? current.targetPolicySHA256 : current.currentPolicySHA256;
	const expectedPhase = action === 'pause' ? 'paused' : action === 'resume' ? 'canary' : 'stable';
	clearPolicyRefreshTimer(); state.policy.action = action; setPolicyBusy(true); $('#policy-error').textContent = '';
	try {
		const updated = firewallRolloutModel.validate(await api(`/api/v1/networks/${state.policy.networkID}/firewall-rollout`, {
			method: 'POST', body: JSON.stringify({ action, expected_config_revision: expectedRevision }),
		}));
		if (requestID !== state.policy.requestID) return;
		if (updated.networkID !== state.policy.networkID || updated.phase !== expectedPhase || updated.configRevision !== expectedRevision + 1 || updated.currentPolicySHA256 !== expectedPolicySHA256) throw new Error('Firewall rollout returned an unexpected policy or revision transition.');
		await completePolicyRolloutAction(updated, action, false, requestID);
	} catch (error) {
		if (requestID !== state.policy.requestID) return;
		if (error.status === 401) { $('#policy-dialog').close(); await showLogin(false); return; }
		try {
			const readback = firewallRolloutModel.validate(await api(`/api/v1/networks/${state.policy.networkID}/firewall-rollout`));
			if (requestID !== state.policy.requestID) return;
			if (readback.phase === expectedPhase && readback.configRevision === expectedRevision + 1 && readback.currentPolicySHA256 === expectedPolicySHA256) {
				await completePolicyRolloutAction(readback, action, true, requestID); return;
			}
			renderPolicyRollout(readback);
			if ((readback.phase === 'canary' || readback.phase === 'paused') && readback.targetPolicy) renderPolicyDocument(policyDocumentFromRolloutTarget(readback));
			showPolicyError(error.status === 409 ? `Firewall rollout changed to ${readback.phase} at revision ${readback.configRevision}. Review the current state before retrying.` : `Could not ${action} firewall rollout: ${error.message}`);
		} catch (readbackError) {
			showPolicyError(`The ${action} outcome is unknown because both the action response and authoritative readback failed (${readbackError.message}). Reopen this network before retrying.`);
		}
	} finally {
		if (requestID === state.policy.requestID) { state.policy.action = ''; setPolicyBusy(false); schedulePolicyRolloutRefresh(); }
	}
}

async function completePolicyRolloutAction(rollout, action, interrupted, requestID) {
	const active = await api(`/api/v1/networks/${rollout.networkID}/firewall`);
	if (requestID !== state.policy.requestID) return;
	if (active.network_id !== rollout.networkID || active.config_revision !== rollout.configRevision) throw new Error('Authoritative firewall readback did not match the completed rollout revision.');
	renderPolicyDocument(rollout.targetPolicy ? policyDocumentFromRolloutTarget(rollout) : active); renderPolicyRollout(rollout);
	const outcome = action === 'promote' ? 'promoted to every node' : action === 'rollback' ? 'rolled back' : action === 'pause' ? 'paused on the retained policy' : 'resumed for fresh convergence';
	flash(interrupted
		? `The response was interrupted, but firewall ${action} is verified complete at revision ${rollout.configRevision}`
		: `Firewall rollout ${outcome} at revision ${rollout.configRevision}`);
	loadNetworks(true).catch(() => flash('Firewall rollout completed, but fleet health could not be refreshed.'));
}

$('#add-inbound-rule').addEventListener('click', () => { addPolicyRule('inbound'); invalidatePolicyPreview(); });
$('#add-outbound-rule').addEventListener('click', () => { addPolicyRule('outbound'); invalidatePolicyPreview(); });
$('#preview-policy').addEventListener('click', previewPolicy);
$('#promote-policy').addEventListener('click', () => applyPolicyRolloutAction('promote'));
$('#pause-policy').addEventListener('click', () => applyPolicyRolloutAction('pause'));
$('#resume-policy').addEventListener('click', () => applyPolicyRolloutAction('resume'));
$('#rollback-policy').addEventListener('click', () => applyPolicyRolloutAction('rollback'));
$('#policy-form').addEventListener('submit', savePolicy);
$('#policy-dialog').addEventListener('cancel', (event) => {
  // A rollout action may already have committed when the browser receives the
  // response. Keep Escape from making that action appear canceled before
  // the client can reconcile and report its definitive result.
  if (state.policy.busy) event.preventDefault();
});
$('#policy-dialog').addEventListener('close', () => {
	clearPolicyRefreshTimer();
  state.policy.requestID += 1;
  state.policy.networkID = '';
  state.policy.networkCIDR = '';
  state.policy.baseRevision = 0;
  state.policy.previewFingerprint = '';
  state.policy.previewCanonicalFingerprint = '';
  state.policy.previewWouldChange = false;
  state.policy.loaded = false;
  state.policy.busy = false;
	state.policy.rollout = null;
	state.policy.action = '';
  $('#policy-form').removeAttribute('aria-busy');
  $('#policy-form').reset();
  $('#policy-network-name').textContent = '';
  clearPolicyEditor();
});
	document.addEventListener('visibilitychange', () => {
		if (document.visibilityState === 'visible' && state.policy.networkID && policyRolloutActive()) refreshPolicyRollout(false);
		else if (document.visibilityState === 'hidden') clearPolicyRefreshTimer();
	});

function desiredDNSSettings() {
	const enabled = $('#dns-enabled').checked;
	const listenPort = enabled ? Number($('#dns-listen-port').value) : 53;
	if (!Number.isSafeInteger(listenPort) || listenPort < 1 || listenPort > 65535) throw new Error('DNS UDP port must be a whole number from 1 through 65535.');
	const nativeResolver = enabled && $('#dns-native-resolver').checked;
	const searchDomain = nativeResolver ? $('#dns-search-domain').value.trim().toLowerCase() : '';
	if (nativeResolver && (!searchDomain || searchDomain.length > 253 || searchDomain.endsWith('.') || searchDomain === 'local' || searchDomain.endsWith('.local') || searchDomain.split('.').some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label)))) throw new Error('Search domain must be a lowercase DNS name and cannot use .local.');
	return { enabled, listenPort, nativeResolver, searchDomain };
}

function updateDNSActionState() {
	const document = state.dns.document;
	let unchanged = false;
	try {
		const desired = desiredDNSSettings();
		unchanged = Boolean(document) && dnsSettingsModel.sameDesired(document, desired.enabled, desired.listenPort, desired.nativeResolver, desired.searchDomain);
	} catch {}
	$('#save-dns').disabled = state.dns.busy || !document || unchanged;
	$('#save-dns').textContent = state.dns.busy ? (state.dns.saving ? 'Deploying…' : 'Loading…') : unchanged ? 'No changes' : 'Save and deploy';
	$('#dns-enabled').disabled = state.dns.busy;
	$('#dns-listen-port').disabled = state.dns.busy || !$('#dns-enabled').checked;
	$('#dns-native-resolver').disabled = state.dns.busy || !$('#dns-enabled').checked;
	$('#dns-search-domain').disabled = state.dns.busy || !$('#dns-enabled').checked || !$('#dns-native-resolver').checked;
}

function setDNSBusy(busy, saving = false) {
	state.dns.busy = busy;
	state.dns.saving = busy && saving;
	$('#dns-form').setAttribute('aria-busy', busy ? 'true' : 'false');
	updateDNSActionState();
}

function renderDNSDocument(dnsDocument) {
	state.dns.document = dnsDocument;
	state.dns.baseRevision = dnsDocument.configRevision;
	$('#dns-current-revision').textContent = dnsDocument.configRevision;
	$('#dns-enabled').checked = dnsDocument.enabled;
	$('#dns-listen-port').value = dnsDocument.listenPort;
	$('#dns-native-resolver').checked = dnsDocument.nativeResolver;
	$('#dns-search-domain').value = dnsDocument.searchDomain;
	const firewall = $('#dns-firewall-state');
	firewall.textContent = dnsDocument.firewallReady ? `Firewall permits UDP ${dnsDocument.listenPort} from all managed nodes` : `Add inbound UDP ${dnsDocument.listenPort} from group all before enabling`;
	firewall.className = dnsDocument.firewallReady ? 'dns-firewall-ready' : 'dns-firewall-required';
	const list = $('#dns-resolver-list');
	list.replaceChildren();
	if (!dnsDocument.enabled) {
		const item = document.createElement('li');
		item.className = 'dns-resolver-empty';
		item.textContent = 'DNS is disabled; no resolver address is published.';
		list.append(item);
	} else if (dnsDocument.resolvers.length === 0) {
		const item = document.createElement('li');
		item.className = 'dns-resolver-empty';
		item.textContent = 'No active lighthouse is available yet.';
		list.append(item);
	} else {
		for (const resolver of dnsDocument.resolvers) {
			const item = document.createElement('li');
			const name = document.createElement('strong'); name.textContent = resolver.name;
			const address = document.createElement('code'); address.textContent = `${resolver.ip}:${dnsDocument.listenPort}`;
			item.append(name, address); list.append(item);
		}
	}
	$('#dns-error').textContent = '';
	updateDNSActionState();
}

async function openDNS(network) {
	const requestID = ++state.dns.requestID;
	state.dns.networkID = network.id;
	state.dns.networkCIDR = network.cidr;
	state.dns.baseRevision = network.config_revision;
	state.dns.document = null;
	state.dns.saving = false;
	const form = $('#dns-form');
	form.reset();
	form.network_id.value = network.id;
	$('#dns-network-name').textContent = network.name;
	$('#dns-current-revision').textContent = network.config_revision;
	$('#dns-firewall-state').textContent = 'Firewall access unknown';
	$('#dns-firewall-state').className = '';
	$('#dns-resolver-list').replaceChildren();
	$('#dns-error').textContent = '';
	$('#dns-dialog').showModal();
	setDNSBusy(true, false);
	try {
		const document = dnsSettingsModel.validate(await api(`/api/v1/networks/${network.id}/dns`));
		if (requestID !== state.dns.requestID) return;
		if (document.networkID !== network.id || document.networkCIDR !== network.cidr) throw new Error('DNS settings did not match the selected network.');
		renderDNSDocument(document);
	} catch (error) {
		if (requestID === state.dns.requestID) $('#dns-error').textContent = `Could not load network DNS: ${error.message}`;
	} finally {
		if (requestID === state.dns.requestID) setDNSBusy(false, false);
	}
}

function completeDNSDeployment(document, interrupted) {
	const networkName = state.networks.find((network) => network.id === state.dns.networkID)?.name || state.dns.networkID;
	$('#dns-dialog').close();
	flash(interrupted
		? `The response was interrupted, but network DNS is verified ${document.enabled ? 'enabled' : 'disabled'} as revision ${document.configRevision} on ${networkName}`
		: `Network DNS ${document.enabled ? 'enabled' : 'disabled'} as revision ${document.configRevision} on ${networkName}`);
	loadNetworks(true).catch(() => flash('Network DNS was deployed, but authoritative fleet health could not be refreshed.'));
}

async function saveDNS(event) {
	event.preventDefault();
	let desired;
	try {
		desired = desiredDNSSettings();
	} catch (error) {
		$('#dns-error').textContent = error.message;
		return;
	}
	if (!state.dns.document || dnsSettingsModel.sameDesired(state.dns.document, desired.enabled, desired.listenPort, desired.nativeResolver, desired.searchDomain)) return;
	const requestID = state.dns.requestID;
	const expectedRevision = state.dns.baseRevision;
	setDNSBusy(true, true);
	$('#dns-error').textContent = '';
	try {
		const updated = dnsSettingsModel.validate(await api(`/api/v1/networks/${state.dns.networkID}/dns`, {
			method: 'PUT',
			body: JSON.stringify({ expected_config_revision: expectedRevision, enabled: desired.enabled, listen_port: desired.listenPort, native_resolver: desired.nativeResolver, search_domain: desired.searchDomain }),
		}));
		if (requestID !== state.dns.requestID) return;
		if (updated.networkID !== state.dns.networkID || updated.networkCIDR !== state.dns.networkCIDR || updated.configRevision !== expectedRevision + 1 || !dnsSettingsModel.sameDesired(updated, desired.enabled, desired.listenPort, desired.nativeResolver, desired.searchDomain)) throw new Error('DNS update returned a different network, desired state, or revision transition.');
		completeDNSDeployment(updated, false);
	} catch (error) {
		if (requestID !== state.dns.requestID) return;
		if (error.status === 401) {
			$('#dns-dialog').close();
			await showLogin(false);
			return;
		}
		if (error.status === 400 || error.status === 403 || error.status === 404 || error.status === 422) {
			$('#dns-error').textContent = `Could not deploy network DNS: ${error.message}`;
			return;
		}
		try {
			const current = dnsSettingsModel.validate(await api(`/api/v1/networks/${state.dns.networkID}/dns`));
			if (requestID !== state.dns.requestID) return;
			if (current.networkID !== state.dns.networkID || current.networkCIDR !== state.dns.networkCIDR) throw new Error('readback did not match the selected network');
			if (dnsSettingsModel.sameDesired(current, desired.enabled, desired.listenPort, desired.nativeResolver, desired.searchDomain)) {
				completeDNSDeployment(current, true);
				return;
			}
			renderDNSDocument(current);
			$('#dns-error').textContent = error.status === 409
				? `Network configuration changed to revision ${current.configRevision}. Review the current DNS settings before retrying.`
				: `The deployment response was interrupted. Readback found revision ${current.configRevision} with different DNS settings, so no outcome is inferred.`;
		} catch (readbackError) {
			$('#dns-error').textContent = `The DNS deployment outcome is unknown because both the update response and authoritative readback failed (${readbackError.message}). Reopen these settings when connectivity returns before retrying.`;
		}
	} finally {
		if (requestID === state.dns.requestID) setDNSBusy(false, false);
	}
}

$('#dns-enabled').addEventListener('change', () => {
	if (!$('#dns-enabled').checked) {
		$('#dns-listen-port').value = 53;
		$('#dns-native-resolver').checked = false;
	}
	$('#dns-error').textContent = '';
	updateDNSActionState();
});
$('#dns-listen-port').addEventListener('input', () => { $('#dns-error').textContent = ''; updateDNSActionState(); });
$('#dns-native-resolver').addEventListener('change', () => {
	if ($('#dns-native-resolver').checked && !$('#dns-search-domain').value.trim()) $('#dns-search-domain').value = 'mesh';
	$('#dns-error').textContent = '';
	updateDNSActionState();
});
$('#dns-search-domain').addEventListener('input', () => { $('#dns-error').textContent = ''; updateDNSActionState(); });
$('#dns-form').addEventListener('submit', saveDNS);
$('#dns-dialog').addEventListener('cancel', (event) => { if (state.dns.saving) event.preventDefault(); });
$('#dns-dialog').addEventListener('close', () => {
	state.dns.requestID += 1;
	state.dns.networkID = '';
	state.dns.networkCIDR = '';
	state.dns.baseRevision = 0;
	state.dns.busy = false;
	state.dns.saving = false;
	state.dns.document = null;
	$('#dns-form').reset();
	$('#dns-form').removeAttribute('aria-busy');
	$('#dns-network-name').textContent = '';
	$('#dns-resolver-list').replaceChildren();
	$('#dns-error').textContent = '';
});

function selectedRelayNodeIDs() {
	return $$('input[data-relay-node-id]:checked', $('#relay-candidate-list')).map((input) => input.dataset.relayNodeId).sort();
}

function desiredRelaySettings() {
	const enabled = $('#relay-enabled').checked;
	const relayNodeIDs = enabled ? selectedRelayNodeIDs() : [];
	if (enabled && relayNodeIDs.length === 0) throw new Error('Select at least one managed machine to enable relays.');
	if (relayNodeIDs.length > relaySettingsModel.MAX_RELAY_NODES) throw new Error(`Select no more than ${relaySettingsModel.MAX_RELAY_NODES} relay machines.`);
	return { enabled, relayNodeIDs };
}

function updateRelayActionState() {
	const selected = selectedRelayNodeIDs();
	$('#relay-selection-count').textContent = `${selected.length} of ${relaySettingsModel.MAX_RELAY_NODES} selected`;
	let unchanged = false;
	try {
		const desired = desiredRelaySettings();
		unchanged = Boolean(state.relays.document) && relaySettingsModel.sameDesired(state.relays.document, desired.enabled, desired.relayNodeIDs);
	} catch {}
	$('#save-relays').disabled = state.relays.busy || !state.relays.document || unchanged;
	$('#save-relays').textContent = state.relays.busy ? (state.relays.saving ? 'Deploying…' : 'Loading…') : unchanged ? 'No changes' : 'Save and deploy';
	$('#relay-enabled').disabled = state.relays.busy;
	for (const input of $$('input[data-relay-node-id]', $('#relay-candidate-list'))) input.disabled = state.relays.busy || !$('#relay-enabled').checked || (!input.checked && selected.length >= relaySettingsModel.MAX_RELAY_NODES);
}

function setRelayBusy(busy, saving = false) {
	state.relays.busy = busy;
	state.relays.saving = busy && saving;
	$('#relay-form').setAttribute('aria-busy', busy ? 'true' : 'false');
	updateRelayActionState();
}

function renderRelayCandidates(relayDocument) {
	const selected = new Set(relayDocument.relayNodeIDs);
	const list = $('#relay-candidate-list');
	list.replaceChildren();
	const candidates = (state.nodes.get(relayDocument.networkID) || []).filter((node) => node.status === 'pending' || node.status === 'active');
	if (candidates.length === 0) {
		const empty = document.createElement('p'); empty.className = 'relay-candidate-empty'; empty.textContent = 'Add a managed node before enabling relays.'; list.append(empty); return;
	}
	for (const node of candidates) {
		const label = document.createElement('label'); label.className = 'relay-candidate';
		const input = document.createElement('input'); input.type = 'checkbox'; input.dataset.relayNodeId = node.id; input.checked = selected.has(node.id);
		const copy = document.createElement('span');
		const name = document.createElement('strong'); name.textContent = node.name;
		const detail = document.createElement('small'); detail.textContent = `${node.role} · ${node.status} · ${node.site}/${node.failure_domain} · ${node.ip}`;
		copy.append(name, detail); label.append(input, copy); list.append(label);
	}
}

function renderRelayDocument(relayDocument) {
	state.relays.document = relayDocument;
	state.relays.baseRevision = relayDocument.configRevision;
	$('#relay-current-revision').textContent = relayDocument.configRevision;
	$('#relay-enabled').checked = relayDocument.enabled;
	renderRelayCandidates(relayDocument);
	const stateCopy = $('#relay-active-state');
	stateCopy.textContent = relayDocument.enabled ? `${relayDocument.activeRelays.length} of ${relayDocument.relayNodeIDs.length} selected relays active` : 'Managed relays disabled';
	const list = $('#relay-active-list'); list.replaceChildren();
	if (!relayDocument.enabled) {
		const item = document.createElement('li'); item.className = 'dns-resolver-empty'; item.textContent = 'Relays are disabled; no relay address is advertised.'; list.append(item);
	} else if (relayDocument.activeRelays.length === 0) {
		const item = document.createElement('li'); item.className = 'dns-resolver-empty'; item.textContent = 'No selected relay is active yet.'; list.append(item);
	} else {
		for (const relay of relayDocument.activeRelays) {
			const item = document.createElement('li');
			const name = document.createElement('strong'); name.textContent = relay.name;
			const address = document.createElement('code'); address.textContent = `${relay.ip} · ${relay.role}`;
			item.append(name, address); list.append(item);
		}
	}
	$('#relay-error').textContent = '';
	updateRelayActionState();
}

async function openRelays(network) {
	const requestID = ++state.relays.requestID;
	state.relays.networkID = network.id; state.relays.networkCIDR = network.cidr; state.relays.baseRevision = network.config_revision;
	state.relays.document = null; state.relays.saving = false;
	const form = $('#relay-form'); form.reset(); form.network_id.value = network.id;
	$('#relay-network-name').textContent = network.name; $('#relay-current-revision').textContent = network.config_revision;
	$('#relay-active-state').textContent = 'Active relays unknown'; $('#relay-candidate-list').replaceChildren(); $('#relay-active-list').replaceChildren(); $('#relay-error').textContent = '';
	$('#relay-dialog').showModal(); setRelayBusy(true, false);
	try {
		const relayDocument = relaySettingsModel.validate(await api(`/api/v1/networks/${network.id}/relays`));
		if (requestID !== state.relays.requestID) return;
		if (relayDocument.networkID !== network.id || relayDocument.networkCIDR !== network.cidr) throw new Error('Relay settings did not match the selected network.');
		renderRelayDocument(relayDocument);
	} catch (error) {
		if (requestID === state.relays.requestID) $('#relay-error').textContent = `Could not load network relays: ${error.message}`;
	} finally {
		if (requestID === state.relays.requestID) setRelayBusy(false, false);
	}
}

function completeRelayDeployment(relayDocument, interrupted) {
	const networkName = state.networks.find((network) => network.id === state.relays.networkID)?.name || state.relays.networkID;
	$('#relay-dialog').close();
	flash(interrupted
		? `The response was interrupted, but network relays are verified ${relayDocument.enabled ? 'enabled' : 'disabled'} as revision ${relayDocument.configRevision} on ${networkName}`
		: `Network relays ${relayDocument.enabled ? 'enabled' : 'disabled'} as revision ${relayDocument.configRevision} on ${networkName}`);
	loadNetworks(true).catch(() => flash('Network relays were deployed, but authoritative fleet health could not be refreshed.'));
}

async function saveRelays(event) {
	event.preventDefault();
	let desired;
	try { desired = desiredRelaySettings(); } catch (error) { $('#relay-error').textContent = error.message; return; }
	if (!state.relays.document || relaySettingsModel.sameDesired(state.relays.document, desired.enabled, desired.relayNodeIDs)) return;
	const requestID = state.relays.requestID; const expectedRevision = state.relays.baseRevision;
	setRelayBusy(true, true); $('#relay-error').textContent = '';
	try {
		const updated = relaySettingsModel.validate(await api(`/api/v1/networks/${state.relays.networkID}/relays`, {
			method: 'PUT', body: JSON.stringify({ expected_config_revision: expectedRevision, enabled: desired.enabled, relay_node_ids: desired.relayNodeIDs }),
		}));
		if (requestID !== state.relays.requestID) return;
		if (updated.networkID !== state.relays.networkID || updated.networkCIDR !== state.relays.networkCIDR || updated.configRevision !== expectedRevision + 1 || !relaySettingsModel.sameDesired(updated, desired.enabled, desired.relayNodeIDs)) throw new Error('Relay update returned a different network, desired state, or revision transition.');
		completeRelayDeployment(updated, false);
	} catch (error) {
		if (requestID !== state.relays.requestID) return;
		if (error.status === 401) { $('#relay-dialog').close(); await showLogin(false); return; }
		if (error.status === 400 || error.status === 403 || error.status === 404 || error.status === 422) { $('#relay-error').textContent = `Could not deploy network relays: ${error.message}`; return; }
		try {
			const current = relaySettingsModel.validate(await api(`/api/v1/networks/${state.relays.networkID}/relays`));
			if (requestID !== state.relays.requestID) return;
			if (current.networkID !== state.relays.networkID || current.networkCIDR !== state.relays.networkCIDR) throw new Error('readback did not match the selected network');
			if (relaySettingsModel.sameDesired(current, desired.enabled, desired.relayNodeIDs)) { completeRelayDeployment(current, true); return; }
			renderRelayDocument(current);
			$('#relay-error').textContent = error.status === 409
				? `Network configuration changed to revision ${current.configRevision}. Review the current relay settings before retrying.`
				: `The deployment response was interrupted. Readback found revision ${current.configRevision} with different relay settings, so no outcome is inferred.`;
		} catch (readbackError) {
			$('#relay-error').textContent = `The relay deployment outcome is unknown because both the update response and authoritative readback failed (${readbackError.message}). Reopen these settings when connectivity returns before retrying.`;
		}
	} finally {
		if (requestID === state.relays.requestID) setRelayBusy(false, false);
	}
}

$('#relay-enabled').addEventListener('change', () => {
	if (!$('#relay-enabled').checked) for (const input of $$('input[data-relay-node-id]', $('#relay-candidate-list'))) input.checked = false;
	$('#relay-error').textContent = ''; updateRelayActionState();
});
$('#relay-candidate-list').addEventListener('change', () => { $('#relay-error').textContent = ''; updateRelayActionState(); });
$('#relay-form').addEventListener('submit', saveRelays);
$('#relay-dialog').addEventListener('cancel', (event) => { if (state.relays.saving) event.preventDefault(); });
$('#relay-dialog').addEventListener('close', () => {
	state.relays.requestID += 1; state.relays.networkID = ''; state.relays.networkCIDR = ''; state.relays.baseRevision = 0;
	state.relays.busy = false; state.relays.saving = false; state.relays.document = null;
	$('#relay-form').reset(); $('#relay-form').removeAttribute('aria-busy'); $('#relay-network-name').textContent = '';
	$('#relay-candidate-list').replaceChildren(); $('#relay-active-list').replaceChildren(); $('#relay-error').textContent = '';
});

function setRoutePoliciesBusy(busy) {
	state.routePolicies.busy = busy;
	$('#route-policies-dialog').setAttribute('aria-busy', String(busy));
	$('#route-policies-prefix').disabled = busy;
	$('#route-policies-mtu').disabled = busy;
	$('#route-policies-metric').disabled = busy;
	$('#save-route-policy').disabled = busy || !state.routePolicies.document || !state.routePolicies.document.availableActions.includes('update') || !state.routePolicies.selectedPrefix;
	for (const input of $$('input[data-route-policy-gateway]', $('#route-policies-gateways'))) input.disabled = busy;
}

function selectedRoutePolicy() {
	const control = state.routePolicies.document;
	return control ? control.policies.find((policy) => policy.prefix === state.routePolicies.selectedPrefix) || null : null;
}

function updateRoutePolicyShares() {
	const inputs = $$('input[data-route-policy-gateway]', $('#route-policies-gateways'));
	const weights = inputs.map((input) => Number.parseInt(input.value, 10));
	const total = weights.every((weight) => Number.isInteger(weight) && weight >= 1 && weight <= 1000) ? weights.reduce((sum, weight) => sum + weight, 0) : 0;
	inputs.forEach((input, index) => {
		const output = input.closest('label').querySelector('[data-route-policy-share]');
		output.textContent = total ? `${Math.round((weights[index] / total) * 1000) / 10}%` : 'Invalid';
	});
	$('#save-route-policy').disabled = state.routePolicies.busy || !total || !state.routePolicies.document || !state.routePolicies.document.availableActions.includes('update');
}

function renderSelectedRoutePolicy() {
	const policy = selectedRoutePolicy();
	const list = $('#route-policies-gateways'); list.replaceChildren();
	$('#route-policies-empty').classList.toggle('hidden', Boolean(policy));
	$('#route-policies-editor').classList.toggle('hidden', !policy);
	if (!policy) { setRoutePoliciesBusy(false); return; }
	for (const gateway of policy.gateways) {
		const label = document.createElement('label'); label.className = 'route-policy-gateway';
		const copy = document.createElement('span');
		const name = document.createElement('strong'); name.textContent = gateway.name;
		const address = document.createElement('small'); address.textContent = gateway.ip;
		copy.append(name, address);
		const weight = document.createElement('input'); weight.type = 'number'; weight.min = '1'; weight.max = '1000'; weight.step = '1'; weight.value = String(gateway.weight); weight.dataset.routePolicyGateway = gateway.nodeID; weight.setAttribute('aria-label', `${gateway.name} relative route weight`);
		const share = document.createElement('output'); share.dataset.routePolicyShare = ''; share.textContent = `${Math.round(gateway.share * 1000) / 10}%`;
		label.append(copy, weight, share); list.append(label);
	}
	$('#route-policies-mtu').value = String(policy.mtu);
	$('#route-policies-metric').value = String(policy.metric);
	$('#route-policies-receipt').textContent = policy.lastRequestID ? `Last direct update deployed in revision ${policy.policyRevision}.` : 'Using server-derived defaults until the first direct policy update.';
	setRoutePoliciesBusy(false); updateRoutePolicyShares();
}

function renderRoutePolicies(control) {
	state.routePolicies.document = control;
	$('#route-policies-revision').textContent = control.configRevision;
	const select = $('#route-policies-prefix');
	const previous = state.routePolicies.selectedPrefix;
	select.replaceChildren();
	for (const policy of control.policies) {
		const option = document.createElement('option'); option.value = policy.prefix; option.textContent = `${policy.prefix} · ${policy.gateways.length} gateway${policy.gateways.length === 1 ? '' : 's'}`; select.append(option);
	}
	state.routePolicies.selectedPrefix = control.policies.some((policy) => policy.prefix === previous) ? previous : (control.policies[0]?.prefix || '');
	select.value = state.routePolicies.selectedPrefix;
	$('#route-policies-error').textContent = '';
	renderSelectedRoutePolicy();
}

async function refreshRoutePolicies(showErrors = true) {
	const networkID = state.routePolicies.networkID;
	const requestID = state.routePolicies.requestID;
	if (!networkID || state.routePolicies.busy) return;
	try {
		const control = routePoliciesModel.validate(await api(`/api/v1/networks/${networkID}/route-policies`));
		if (requestID !== state.routePolicies.requestID || control.networkID !== networkID) return;
		renderRoutePolicies(control);
	} catch (error) {
		if (requestID === state.routePolicies.requestID && showErrors) $('#route-policies-error').textContent = `Could not load route policies: ${error.message}`;
	}
}

async function openRoutePolicies(network) {
	state.routePolicies.requestID += 1; state.routePolicies.networkID = network.id; state.routePolicies.networkName = network.name;
	state.routePolicies.mutationID = ''; state.routePolicies.busy = false; state.routePolicies.document = null; state.routePolicies.selectedPrefix = '';
	$('#route-policies-network-name').textContent = network.name; $('#route-policies-revision').textContent = network.config_revision;
	$('#route-policies-prefix').replaceChildren(); $('#route-policies-gateways').replaceChildren(); $('#route-policies-editor').classList.add('hidden'); $('#route-policies-empty').classList.add('hidden'); $('#route-policies-error').textContent = '';
	$('#route-policies-dialog').showModal(); await refreshRoutePolicies(true);
}

function newRoutePolicyMutationID() {
	if (globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') return `route-policy-${globalThis.crypto.randomUUID()}`;
	if (!globalThis.crypto || typeof globalThis.crypto.getRandomValues !== 'function') throw new Error('Secure browser randomness is unavailable.');
	const bytes = new Uint8Array(18); globalThis.crypto.getRandomValues(bytes);
	return `route-policy-${[...bytes].map((value) => value.toString(16).padStart(2, '0')).join('')}`;
}

async function saveRoutePolicy() {
	const current = state.routePolicies.document;
	const policy = selectedRoutePolicy();
	if (!current || !policy || state.routePolicies.busy || !current.availableActions.includes('update')) return;
	const gateways = $$('input[data-route-policy-gateway]', $('#route-policies-gateways')).map((input) => ({ node_id: input.dataset.routePolicyGateway, weight: Number.parseInt(input.value, 10) }));
	const mtu = Number.parseInt($('#route-policies-mtu').value, 10);
	const metric = Number.parseInt($('#route-policies-metric').value, 10);
	if (!gateways.every((gateway) => Number.isInteger(gateway.weight) && gateway.weight >= 1 && gateway.weight <= 1000) || !Number.isInteger(mtu) || (mtu !== 0 && (mtu < 500 || mtu > 65535)) || !Number.isInteger(metric) || metric < 0 || metric > 2147483647) {
		$('#route-policies-error').textContent = 'Use weights 1–1000, MTU 0 or 500–65535, and metric 0–2147483647.'; return;
	}
	state.routePolicies.mutationID ||= newRoutePolicyMutationID();
	const body = { prefix: policy.prefix, gateways, mtu, metric, expected_config_revision: current.configRevision, request_id: state.routePolicies.mutationID };
	if (!confirm(`Deploy weights and route controls for ${policy.prefix}? This advances the signed configuration for the entire network.`)) return;
	const viewRequestID = state.routePolicies.requestID;
	setRoutePoliciesBusy(true); $('#route-policies-error').textContent = '';
	try {
		const updated = routePoliciesModel.validate(await api(`/api/v1/networks/${state.routePolicies.networkID}/route-policies`, { method: 'POST', body: JSON.stringify(body), timeoutMS: 15000 }));
		if (viewRequestID !== state.routePolicies.requestID) return;
		state.routePolicies.mutationID = ''; renderRoutePolicies(updated); flash(`Route policy deployed at revision ${updated.configRevision}.`); loadNetworks(true).catch(() => {});
	} catch (error) {
		if (viewRequestID !== state.routePolicies.requestID) return;
		if (error.status === 401) { $('#route-policies-dialog').close(); await showLogin(false); return; }
		try {
			const readback = routePoliciesModel.validate(await api(`/api/v1/networks/${state.routePolicies.networkID}/route-policies`));
			if (viewRequestID !== state.routePolicies.requestID) return;
			const recovered = readback.policies.some((candidate) => candidate.prefix === body.prefix && candidate.lastRequestID === body.request_id);
			if (recovered) { state.routePolicies.mutationID = ''; renderRoutePolicies(readback); flash('The response was interrupted, but the deployed route policy was recovered.'); return; }
			renderRoutePolicies(readback); $('#route-policies-error').textContent = `Could not update route policy: ${error.message}`;
		} catch (readbackError) {
			$('#route-policies-error').textContent = `The update outcome is unknown because authoritative readback also failed (${readbackError.message}). Keep this dialog open and retry the same save when connectivity returns.`;
		}
	} finally {
		if (viewRequestID === state.routePolicies.requestID) setRoutePoliciesBusy(false);
	}
}

$('#route-policies-prefix').addEventListener('change', () => { state.routePolicies.selectedPrefix = $('#route-policies-prefix').value; renderSelectedRoutePolicy(); });
$('#route-policies-gateways').addEventListener('input', updateRoutePolicyShares);
$('#save-route-policy').addEventListener('click', saveRoutePolicy);
$('#route-policies-dialog').addEventListener('cancel', (event) => { if (state.routePolicies.busy) event.preventDefault(); });
$('#route-policies-dialog').addEventListener('close', () => {
	state.routePolicies.requestID += 1; state.routePolicies.networkID = ''; state.routePolicies.networkName = ''; state.routePolicies.mutationID = ''; state.routePolicies.busy = false; state.routePolicies.document = null; state.routePolicies.selectedPrefix = '';
	$('#route-policies-gateways').replaceChildren(); $('#route-policies-error').textContent = '';
});

const routeTransferPresentation = Object.freeze({
	'': { label: 'No active transfer', copy: 'Choose the current gateway, the replacement gateway, and the exact routes to move.' },
	preparing_target: { label: 'Preparing target', copy: 'The source remains published. Wait for the target agent to install and report its expanded certificate profile.' },
	cleaning_source: { label: 'Cleaning source', copy: 'Routes now point to the target. Wait for the source agent to install and report a certificate without the transferred prefixes.' },
	cleaning_target: { label: 'Cancelling safely', copy: 'The source remains published. Wait for the target to remove the staged certificate authorization before completing cancellation.' },
	completed: { label: 'Completed', copy: 'Ownership moved and both gateway certificate profiles are converged. You may start another transfer.' },
	cancelled: { label: 'Cancelled', copy: 'The source kept ownership and the target has no staged route authorization. You may start another transfer.' },
});

function clearRouteTransferTimer() {
	if (state.routeTransfer.refreshTimer !== null) clearTimeout(state.routeTransfer.refreshTimer);
	state.routeTransfer.refreshTimer = null;
}

function scheduleRouteTransferRefresh() {
	clearRouteTransferTimer();
	if (!state.routeTransfer.networkID || !$('#route-transfer-dialog').open || document.visibilityState === 'hidden') return;
	state.routeTransfer.refreshTimer = setTimeout(() => refreshRouteTransfer(false), 5000);
}

function setRouteTransferBusy(busy) {
	state.routeTransfer.busy = busy;
	$('#route-transfer-dialog').setAttribute('aria-busy', String(busy));
	$('#route-transfer-primary').disabled = busy;
	$('#route-transfer-cancel').disabled = busy;
	$('#route-transfer-source').disabled = busy;
	$('#route-transfer-target').disabled = busy;
	for (const input of $$('input[data-route-transfer-subnet]', $('#route-transfer-route-list'))) input.disabled = busy;
}

function routeTransferActiveNodes() {
	return state.routeTransfer.nodes.filter((node) => node.status === 'active');
}

function populateRouteTransferGateways() {
	const source = $('#route-transfer-source');
	const target = $('#route-transfer-target');
	const previousSource = source.value;
	const previousTarget = target.value;
	source.replaceChildren(); target.replaceChildren();
	const active = routeTransferActiveNodes();
	for (const node of active.filter((candidate) => Array.isArray(candidate.routed_subnets) && candidate.routed_subnets.length > 0)) {
		const option = document.createElement('option'); option.value = node.id; option.textContent = `${node.name} · ${node.routed_subnets.length} route${node.routed_subnets.length === 1 ? '' : 's'}`; source.append(option);
	}
	if (previousSource && [...source.options].some((option) => option.value === previousSource)) source.value = previousSource;
	const sourceID = source.value;
	for (const node of active.filter((candidate) => candidate.id !== sourceID)) {
		const option = document.createElement('option'); option.value = node.id; option.textContent = node.name; target.append(option);
	}
	if (previousTarget && [...target.options].some((option) => option.value === previousTarget)) target.value = previousTarget;
	renderRouteTransferChoices();
}

function renderRouteTransferChoices() {
	const sourceID = $('#route-transfer-source').value;
	const source = routeTransferActiveNodes().find((node) => node.id === sourceID);
	const list = $('#route-transfer-route-list'); list.replaceChildren();
	if (!source || !source.routed_subnets.length) {
		const empty = document.createElement('p'); empty.className = 'field-hint'; empty.textContent = 'No active gateway currently owns a routed subnet.'; list.append(empty);
	} else {
		for (const route of source.routed_subnets) {
			const label = document.createElement('label');
			const input = document.createElement('input'); input.type = 'checkbox'; input.checked = true; input.dataset.routeTransferSubnet = route;
			const code = document.createElement('code'); code.textContent = route; label.append(input, code); list.append(label);
		}
	}
	updateRouteTransferStartState();
}

function updateRouteTransferStartState() {
	const control = state.routeTransfer.document;
	if (!control || !control.availableActions.includes('start')) return;
	const selected = $$('input[data-route-transfer-subnet]:checked', $('#route-transfer-route-list'));
	$('#route-transfer-primary').disabled = state.routeTransfer.busy || !$('#route-transfer-source').value || !$('#route-transfer-target').value || selected.length === 0;
}

function renderRouteTransfer(control) {
	state.routeTransfer.document = control;
	const presentation = routeTransferPresentation[control.phase];
	$('#route-transfer-phase').textContent = presentation.label;
	$('#route-transfer-revision').textContent = control.configRevision;
	$('#route-transfer-next-copy').textContent = presentation.copy;
	$('#route-transfer-source-status').textContent = control.source ? `${control.source.name} · ${control.source.ready ? 'ready' : `cert g${control.source.appliedCertificateGeneration}/g${control.source.certificateGeneration}`}` : '—';
	$('#route-transfer-target-status').textContent = control.target ? `${control.target.name} · ${control.target.ready ? 'ready' : `cert g${control.target.appliedCertificateGeneration}/g${control.target.certificateGeneration}`}` : '—';
	const canStart = control.availableActions.includes('start');
	$('#route-transfer-form').classList.toggle('hidden', !canStart);
	if (canStart) populateRouteTransferGateways();
	const list = $('#route-transfer-node-list'); list.replaceChildren();
	if (!canStart) {
		for (const [role, node] of [['Source', control.source], ['Target', control.target]]) {
			if (!node) continue;
			const item = document.createElement('li'); item.className = `readiness-check ${node.ready ? 'pass' : 'pending'}`;
			const copy = document.createElement('span'); copy.className = 'ca-rotation-node-copy';
			const name = document.createElement('strong'); name.textContent = `${role}: ${node.name}`;
			const detail = document.createElement('small'); detail.textContent = `config r${node.appliedConfigRevision} · cert g${node.appliedCertificateGeneration}/g${node.certificateGeneration} · required g${node.desiredCertificateGeneration || '—'}`;
			copy.append(name, detail); item.append(copy); list.append(item);
		}
	}
	const primary = $('#route-transfer-primary');
	if (canStart) { primary.textContent = 'Start safe transfer'; primary.dataset.action = 'start'; }
	else { primary.textContent = control.phase === 'cleaning_source' ? 'Complete transfer' : 'Promote target'; primary.dataset.action = 'advance'; }
	primary.classList.toggle('hidden', !(canStart || control.availableActions.includes('advance')));
	const cancel = $('#route-transfer-cancel'); cancel.classList.toggle('hidden', !control.availableActions.includes('cancel'));
	$('#route-transfer-error').textContent = '';
	setRouteTransferBusy(false); updateRouteTransferStartState(); scheduleRouteTransferRefresh();
}

async function refreshRouteTransfer(showErrors = true) {
	const networkID = state.routeTransfer.networkID;
	const requestID = state.routeTransfer.requestID;
	if (!networkID || state.routeTransfer.busy) return;
	try {
		const control = routeTransferModel.validate(await api(`/api/v1/networks/${networkID}/route-transfer`));
		if (requestID !== state.routeTransfer.requestID || control.networkID !== networkID) return;
		renderRouteTransfer(control);
	} catch (error) {
		if (requestID === state.routeTransfer.requestID && showErrors) $('#route-transfer-error').textContent = `Could not load route transfer: ${error.message}`;
		scheduleRouteTransferRefresh();
	}
}

async function openRouteTransfer(network, nodes) {
	clearRouteTransferTimer();
	state.routeTransfer.requestID += 1; state.routeTransfer.networkID = network.id; state.routeTransfer.networkName = network.name;
	state.routeTransfer.nodes = nodes; state.routeTransfer.document = null; state.routeTransfer.mutationID = ''; state.routeTransfer.busy = false;
	$('#route-transfer-network-name').textContent = network.name; $('#route-transfer-phase').textContent = 'Loading'; $('#route-transfer-revision').textContent = network.config_revision;
	$('#route-transfer-source-status').textContent = '—'; $('#route-transfer-target-status').textContent = '—'; $('#route-transfer-next-copy').textContent = 'Loading authoritative transfer state…';
	$('#route-transfer-form').classList.add('hidden'); $('#route-transfer-node-list').replaceChildren(); $('#route-transfer-error').textContent = ''; $('#route-transfer-primary').classList.add('hidden'); $('#route-transfer-cancel').classList.add('hidden');
	$('#route-transfer-dialog').showModal(); await refreshRouteTransfer(true);
}

function newRouteTransferMutationID() {
	if (globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') return `route-transfer-${globalThis.crypto.randomUUID()}`;
	if (!globalThis.crypto || typeof globalThis.crypto.getRandomValues !== 'function') throw new Error('Secure browser randomness is unavailable.');
	const bytes = new Uint8Array(18); globalThis.crypto.getRandomValues(bytes);
	return `route-transfer-${[...bytes].map((value) => value.toString(16).padStart(2, '0')).join('')}`;
}

async function applyRouteTransfer(action) {
	const current = state.routeTransfer.document;
	if (!current || state.routeTransfer.busy) return;
	let endpoint = `/api/v1/networks/${state.routeTransfer.networkID}/route-transfer`;
	let body;
	if (action === 'start') {
		if (!current.availableActions.includes('start')) return;
		const sourceNodeID = $('#route-transfer-source').value;
		const targetNodeID = $('#route-transfer-target').value;
		const routedSubnets = $$('input[data-route-transfer-subnet]:checked', $('#route-transfer-route-list')).map((input) => input.dataset.routeTransferSubnet);
		if (!sourceNodeID || !targetNodeID || routedSubnets.length === 0) return;
		state.routeTransfer.mutationID ||= newRouteTransferMutationID();
		body = { source_node_id: sourceNodeID, target_node_id: targetNodeID, routed_subnets: routedSubnets, expected_config_revision: current.configRevision, request_id: state.routeTransfer.mutationID };
		if (!confirm(`Stage ${routedSubnets.join(', ')} from the current gateway to the replacement? The source remains published until target convergence is proven.`)) return;
	} else {
		if (!current.availableActions.includes('advance')) return;
		endpoint += '/advance';
		body = { expected_config_revision: current.configRevision, request_id: current.requestID };
		const message = current.phase === 'preparing_target' ? 'Promote the converged replacement gateway? Peer routes will switch now and source certificate cleanup will begin.' : 'Complete this transfer after verified source certificate cleanup?';
		if (!confirm(message)) return;
	}
	const viewRequestID = state.routeTransfer.requestID;
	clearRouteTransferTimer(); setRouteTransferBusy(true); $('#route-transfer-error').textContent = '';
	try {
		const updated = routeTransferModel.validate(await api(endpoint, { method: 'POST', body: JSON.stringify(body), timeoutMS: 15000 }));
		if (viewRequestID !== state.routeTransfer.requestID) return;
		state.routeTransfer.mutationID = ''; renderRouteTransfer(updated); flash(`Route transfer is now ${routeTransferPresentation[updated.phase].label.toLowerCase()} at revision ${updated.configRevision}.`);
		loadNetworks(true).catch(() => flash('Route lifecycle advanced, but fleet health could not be refreshed.'));
	} catch (error) {
		if (viewRequestID !== state.routeTransfer.requestID) return;
		if (error.status === 401) { $('#route-transfer-dialog').close(); await showLogin(false); return; }
		try {
			const readback = routeTransferModel.validate(await api(`/api/v1/networks/${state.routeTransfer.networkID}/route-transfer`));
			if (viewRequestID !== state.routeTransfer.requestID) return;
			const committed = action === 'start' ? readback.requestID === body.request_id : readback.requestID === body.request_id && readback.phase !== current.phase;
			if (committed) { state.routeTransfer.mutationID = ''; renderRouteTransfer(readback); flash('The response was interrupted, but authoritative route-transfer state was recovered.'); return; }
			renderRouteTransfer(readback); $('#route-transfer-error').textContent = `Could not ${action} route transfer: ${error.message}`;
		} catch (readbackError) {
			$('#route-transfer-error').textContent = `The transfer outcome is unknown because both the mutation response and authoritative readback failed (${readbackError.message}). Keep this dialog open and retry the same action when connectivity returns.`;
		}
	} finally {
		if (viewRequestID === state.routeTransfer.requestID) setRouteTransferBusy(false);
	}
}

async function cancelRouteTransfer() {
	const current = state.routeTransfer.document;
	if (!current || !current.availableActions.includes('cancel') || state.routeTransfer.busy || !confirm('Cancel this transfer safely? If the target certificate was already expanded, Mesh will require a cleanup renewal before cancellation completes.')) return;
	const viewRequestID = state.routeTransfer.requestID;
	clearRouteTransferTimer(); setRouteTransferBusy(true); $('#route-transfer-error').textContent = '';
	try {
		const updated = routeTransferModel.validate(await api(`/api/v1/networks/${state.routeTransfer.networkID}/route-transfer/cancel`, {
			method: 'POST', body: JSON.stringify({ expected_config_revision: current.configRevision, request_id: current.requestID }), timeoutMS: 15000,
		}));
		if (viewRequestID !== state.routeTransfer.requestID) return;
		renderRouteTransfer(updated); flash(`Route transfer is now ${routeTransferPresentation[updated.phase].label.toLowerCase()}.`); loadNetworks(true).catch(() => {});
	} catch (error) {
		if (viewRequestID !== state.routeTransfer.requestID) return;
		$('#route-transfer-error').textContent = `Could not cancel route transfer: ${error.message}`;
		scheduleRouteTransferRefresh();
	} finally {
		if (viewRequestID === state.routeTransfer.requestID) setRouteTransferBusy(false);
	}
}

$('#route-transfer-source').addEventListener('change', populateRouteTransferGateways);
$('#route-transfer-target').addEventListener('change', updateRouteTransferStartState);
$('#route-transfer-route-list').addEventListener('change', updateRouteTransferStartState);
$('#route-transfer-primary').addEventListener('click', () => applyRouteTransfer($('#route-transfer-primary').dataset.action));
$('#route-transfer-cancel').addEventListener('click', cancelRouteTransfer);
$('#route-transfer-dialog').addEventListener('cancel', (event) => { if (state.routeTransfer.busy) event.preventDefault(); });
$('#route-transfer-dialog').addEventListener('close', () => {
	clearRouteTransferTimer(); state.routeTransfer.requestID += 1; state.routeTransfer.networkID = ''; state.routeTransfer.networkName = ''; state.routeTransfer.nodes = [];
	state.routeTransfer.document = null; state.routeTransfer.mutationID = ''; state.routeTransfer.busy = false; $('#route-transfer-error').textContent = ''; $('#route-transfer-route-list').replaceChildren();
});
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible' && state.routeTransfer.networkID) refreshRouteTransfer(false); else clearRouteTransferTimer(); });

const routeProfilePresentation = Object.freeze({
	'': { label: 'No active edit', copy: 'Enter the gateway’s complete desired routed-subnet set. Mesh will derive the additions and removals.' },
	preparing_owner: { label: 'Preparing certificate', copy: 'Existing peer routes remain unchanged. Wait for the gateway to install and report a certificate authorized for every old and new prefix.' },
	cleaning_owner: { label: 'Cleaning certificate', copy: 'Peers now use only the final route set. Wait for the gateway to install and report a certificate with removed prefixes deleted.' },
	cleaning_cancelled_owner: { label: 'Cancelling safely', copy: 'Peer routes never changed. Wait for the gateway to remove staged certificate authorization before completing cancellation.' },
	completed: { label: 'Completed', copy: 'Peer routes and the gateway certificate have converged on the requested prefix set. You may start another edit.' },
	cancelled: { label: 'Cancelled', copy: 'The original peer routes and gateway certificate authorization are restored. You may start another edit.' },
});

function clearRouteProfileTimer() {
	if (state.routeProfile.refreshTimer !== null) clearTimeout(state.routeProfile.refreshTimer);
	state.routeProfile.refreshTimer = null;
}

function scheduleRouteProfileRefresh() {
	clearRouteProfileTimer();
	const control = state.routeProfile.document;
	if (!state.routeProfile.nodeID || !$('#route-profile-dialog').open || document.visibilityState === 'hidden' || !control || !['preparing_owner', 'cleaning_owner', 'cleaning_cancelled_owner'].includes(control.phase)) return;
	state.routeProfile.refreshTimer = setTimeout(() => refreshRouteProfile(false), 5000);
}

function setRouteProfileBusy(busy) {
	state.routeProfile.busy = busy;
	$('#route-profile-dialog').setAttribute('aria-busy', String(busy));
	$('#route-profile-primary').disabled = busy;
	$('#route-profile-cancel').disabled = busy;
	$('#route-profile-subnets').disabled = busy;
}

function parsedRouteProfileSubnets() {
	return $('#route-profile-subnets').value.split(/[\n,]+/u).map((value) => value.trim()).filter(Boolean);
}

function routeProfileCurrentSubnets(control) {
	return control.phase === 'cancelled' ? control.originalRoutedSubnets : control.desiredRoutedSubnets;
}

function updateRouteProfileStartState() {
	const control = state.routeProfile.document;
	if (!control || !control.availableActions.includes('start')) return;
	const values = parsedRouteProfileSubnets();
	const current = routeProfileCurrentSubnets(control);
	const unchanged = values.length === current.length && values.every((value, index) => value === current[index]);
	$('#route-profile-primary').disabled = state.routeProfile.busy || values.length > 8 || unchanged;
}

function renderRouteProfile(control) {
	state.routeProfile.document = control;
	const presentation = routeProfilePresentation[control.phase];
	$('#route-profile-phase').textContent = presentation.label;
	$('#route-profile-revision').textContent = control.configRevision;
	$('#route-profile-next-copy').textContent = presentation.copy;
	$('#route-profile-certificate-status').textContent = control.owner.ready ? 'ready' : `applied g${control.owner.appliedCertificateGeneration} · issued g${control.owner.certificateGeneration} · required g${control.owner.desiredCertificateGeneration || '—'}`;
	$('#route-profile-additions').textContent = control.additions.length ? control.additions.join(', ') : 'None';
	$('#route-profile-removals').textContent = control.removals.length ? control.removals.join(', ') : 'None';
	const canStart = control.availableActions.includes('start');
	$('#route-profile-form').classList.toggle('hidden', !canStart);
	if (canStart && !state.routeProfile.formSeeded) {
		$('#route-profile-subnets').value = routeProfileCurrentSubnets(control).join('\n');
		state.routeProfile.formSeeded = true;
	}
	const list = $('#route-profile-node-list'); list.replaceChildren();
	if (!canStart) {
		const item = document.createElement('li'); item.className = `readiness-check ${control.owner.ready ? 'pass' : 'pending'}`;
		const copy = document.createElement('span'); copy.className = 'ca-rotation-node-copy';
		const name = document.createElement('strong'); name.textContent = control.owner.name;
		const detail = document.createElement('small'); detail.textContent = `config r${control.owner.appliedConfigRevision} · cert g${control.owner.appliedCertificateGeneration}/g${control.owner.certificateGeneration} · required g${control.owner.desiredCertificateGeneration || '—'}`;
		copy.append(name, detail); item.append(copy); list.append(item);
	}
	const primary = $('#route-profile-primary');
	if (canStart) { primary.textContent = 'Start safe edit'; primary.dataset.action = 'start'; }
	else if (control.phase === 'preparing_owner') { primary.textContent = control.removals.length ? 'Publish final routes' : 'Publish added routes'; primary.dataset.action = 'advance'; }
	else { primary.textContent = 'Complete certificate cleanup'; primary.dataset.action = 'advance'; }
	primary.classList.toggle('hidden', !(canStart || control.availableActions.includes('advance')));
	const cancel = $('#route-profile-cancel'); cancel.classList.toggle('hidden', !control.availableActions.includes('cancel'));
	$('#route-profile-error').textContent = '';
	setRouteProfileBusy(false); updateRouteProfileStartState(); scheduleRouteProfileRefresh();
}

async function refreshRouteProfile(showErrors = true) {
	const nodeID = state.routeProfile.nodeID;
	const requestID = state.routeProfile.requestID;
	if (!nodeID || state.routeProfile.busy) return;
	try {
		const control = routeProfileModel.validate(await api(`/api/v1/nodes/${nodeID}/route-profile`));
		if (requestID !== state.routeProfile.requestID || control.nodeID !== nodeID) return;
		renderRouteProfile(control);
	} catch (error) {
		if (requestID === state.routeProfile.requestID && showErrors) $('#route-profile-error').textContent = `Could not load route profile: ${error.message}`;
		scheduleRouteProfileRefresh();
	}
}

async function openRouteProfile(network, node) {
	clearRouteProfileTimer();
	state.routeProfile.requestID += 1; state.routeProfile.networkID = network.id; state.routeProfile.nodeID = node.id; state.routeProfile.nodeName = node.name;
	state.routeProfile.document = null; state.routeProfile.mutationID = ''; state.routeProfile.busy = false; state.routeProfile.formSeeded = false;
	$('#route-profile-node-name').textContent = node.name; $('#route-profile-phase').textContent = 'Loading'; $('#route-profile-revision').textContent = network.config_revision;
	$('#route-profile-certificate-status').textContent = '—'; $('#route-profile-next-copy').textContent = 'Loading authoritative route-profile state…';
	$('#route-profile-additions').textContent = '—'; $('#route-profile-removals').textContent = '—'; $('#route-profile-subnets').value = '';
	$('#route-profile-form').classList.add('hidden'); $('#route-profile-node-list').replaceChildren(); $('#route-profile-error').textContent = ''; $('#route-profile-primary').classList.add('hidden'); $('#route-profile-cancel').classList.add('hidden');
	$('#route-profile-dialog').showModal(); await refreshRouteProfile(true);
}

function newRouteProfileMutationID() {
	if (globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') return `route-profile-${globalThis.crypto.randomUUID()}`;
	if (!globalThis.crypto || typeof globalThis.crypto.getRandomValues !== 'function') throw new Error('Secure browser randomness is unavailable.');
	const bytes = new Uint8Array(18); globalThis.crypto.getRandomValues(bytes);
	return `route-profile-${[...bytes].map((value) => value.toString(16).padStart(2, '0')).join('')}`;
}

async function applyRouteProfile(action) {
	const current = state.routeProfile.document;
	if (!current || state.routeProfile.busy) return;
	let endpoint = `/api/v1/nodes/${state.routeProfile.nodeID}/route-profile`;
	let body;
	if (action === 'start') {
		if (!current.availableActions.includes('start')) return;
		const routedSubnets = parsedRouteProfileSubnets();
		if (routedSubnets.length > 8) { $('#route-profile-error').textContent = 'A node may own at most eight routed subnets.'; return; }
		state.routeProfile.mutationID ||= newRouteProfileMutationID();
		body = { routed_subnets: routedSubnets, expected_config_revision: current.configRevision, request_id: state.routeProfile.mutationID };
		const before = routeProfileCurrentSubnets(current);
		const additions = routedSubnets.filter((value) => !before.includes(value));
		const removals = before.filter((value) => !routedSubnets.includes(value));
		const summary = [additions.length ? `add ${additions.join(', ')}` : '', removals.length ? `remove ${removals.join(', ')}` : ''].filter(Boolean).join('; ');
		if (!summary || !confirm(`Start a safe route-profile edit for ${state.routeProfile.nodeName}: ${summary}? Additions become certificate-authorized before publication; removals stop being published before certificate cleanup.`)) return;
	} else {
		if (!current.availableActions.includes('advance')) return;
		endpoint += '/advance';
		body = { expected_config_revision: current.configRevision, request_id: current.requestID };
		const message = current.phase === 'preparing_owner'
			? 'Publish the final route set now that the gateway’s expanded certificate and signed configuration are proven active? Any removed routes will stop being published immediately and certificate cleanup will begin.'
			: 'Complete this edit after verified gateway certificate cleanup?';
		if (!confirm(message)) return;
	}
	const viewRequestID = state.routeProfile.requestID;
	clearRouteProfileTimer(); setRouteProfileBusy(true); $('#route-profile-error').textContent = '';
	try {
		const updated = routeProfileModel.validate(await api(endpoint, { method: 'POST', body: JSON.stringify(body), timeoutMS: 15000 }));
		if (viewRequestID !== state.routeProfile.requestID) return;
		state.routeProfile.mutationID = ''; state.routeProfile.formSeeded = false; renderRouteProfile(updated);
		flash(`Route profile is now ${routeProfilePresentation[updated.phase].label.toLowerCase()} at revision ${updated.configRevision}.`);
		loadNetworks(true).catch(() => flash('Route profile advanced, but fleet health could not be refreshed.'));
	} catch (error) {
		if (viewRequestID !== state.routeProfile.requestID) return;
		if (error.status === 401) { $('#route-profile-dialog').close(); await showLogin(false); return; }
		try {
			const readback = routeProfileModel.validate(await api(`/api/v1/nodes/${state.routeProfile.nodeID}/route-profile`));
			if (viewRequestID !== state.routeProfile.requestID) return;
			const committed = action === 'start' ? readback.requestID === body.request_id : readback.requestID === body.request_id && readback.phase !== current.phase;
			if (committed) { state.routeProfile.mutationID = ''; state.routeProfile.formSeeded = false; renderRouteProfile(readback); flash('The response was interrupted, but authoritative route-profile state was recovered.'); return; }
			renderRouteProfile(readback); $('#route-profile-error').textContent = `Could not ${action} route profile: ${error.message}`;
		} catch (readbackError) {
			$('#route-profile-error').textContent = `The edit outcome is unknown because both the mutation response and authoritative readback failed (${readbackError.message}). Keep this dialog open and retry the same action when connectivity returns.`;
		}
	} finally {
		if (viewRequestID === state.routeProfile.requestID) setRouteProfileBusy(false);
	}
}

async function cancelRouteProfile() {
	const current = state.routeProfile.document;
	if (!current || !current.availableActions.includes('cancel') || state.routeProfile.busy || !confirm('Cancel this route-profile edit safely? If the expanded certificate was already issued, Mesh will require a cleanup renewal before cancellation completes.')) return;
	const viewRequestID = state.routeProfile.requestID;
	clearRouteProfileTimer(); setRouteProfileBusy(true); $('#route-profile-error').textContent = '';
	try {
		const updated = routeProfileModel.validate(await api(`/api/v1/nodes/${state.routeProfile.nodeID}/route-profile/cancel`, {
			method: 'POST', body: JSON.stringify({ expected_config_revision: current.configRevision, request_id: current.requestID }), timeoutMS: 15000,
		}));
		if (viewRequestID !== state.routeProfile.requestID) return;
		state.routeProfile.formSeeded = false; renderRouteProfile(updated); flash(`Route profile is now ${routeProfilePresentation[updated.phase].label.toLowerCase()}.`); loadNetworks(true).catch(() => {});
	} catch (error) {
		if (viewRequestID !== state.routeProfile.requestID) return;
		if (error.status === 401) { $('#route-profile-dialog').close(); await showLogin(false); return; }
		try {
			const readback = routeProfileModel.validate(await api(`/api/v1/nodes/${state.routeProfile.nodeID}/route-profile`));
			if (viewRequestID !== state.routeProfile.requestID) return;
			if (readback.requestID === current.requestID && readback.phase !== current.phase) {
				state.routeProfile.formSeeded = false; renderRouteProfile(readback); flash('The response was interrupted, but authoritative route-profile cancellation state was recovered.'); return;
			}
			renderRouteProfile(readback); $('#route-profile-error').textContent = `Could not cancel route profile: ${error.message}`;
		} catch (readbackError) {
			$('#route-profile-error').textContent = `The cancellation outcome is unknown because both the mutation response and authoritative readback failed (${readbackError.message}). Keep this dialog open and retry cancellation when connectivity returns.`;
		}
	} finally {
		if (viewRequestID === state.routeProfile.requestID) setRouteProfileBusy(false);
	}
}

$('#route-profile-subnets').addEventListener('input', updateRouteProfileStartState);
$('#route-profile-primary').addEventListener('click', () => applyRouteProfile($('#route-profile-primary').dataset.action));
$('#route-profile-cancel').addEventListener('click', cancelRouteProfile);
$('#route-profile-dialog').addEventListener('cancel', (event) => { if (state.routeProfile.busy) event.preventDefault(); });
$('#route-profile-dialog').addEventListener('close', () => {
	clearRouteProfileTimer(); state.routeProfile.requestID += 1; state.routeProfile.networkID = ''; state.routeProfile.nodeID = ''; state.routeProfile.nodeName = '';
	state.routeProfile.document = null; state.routeProfile.mutationID = ''; state.routeProfile.busy = false; state.routeProfile.formSeeded = false; $('#route-profile-error').textContent = ''; $('#route-profile-subnets').value = ''; $('#route-profile-node-list').replaceChildren();
});
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible' && state.routeProfile.nodeID) refreshRouteProfile(false); else clearRouteProfileTimer(); });

const caRotationPresentation = Object.freeze({
	stable: { label: 'Stable', action: 'prepare', button: 'Prepare replacement CA', copy: 'Generate a replacement CA and deploy an overlapping old-plus-new trust bundle. No node certificate changes in this step.' },
	prepared: { label: 'Trust prepared', action: 'activate', button: 'Activate certificate rotation', copy: 'Wait until every active node has applied the dual trust bundle, then activate early certificate renewal under the replacement CA.' },
	rotating: { label: 'Reissuing certificates', action: 'finalize', button: 'Finalize replacement CA', copy: 'Agents renew early under the replacement CA. Finalization stays unavailable until every active node reports the new certificate generation.' },
	finalizing: { label: 'Removing old trust', action: 'complete', button: 'Complete rotation', copy: 'The old CA key is gone and the replacement CA is active. Wait for every active node to apply the replacement-only trust bundle.' },
	aborting: { label: 'Restoring old trust', action: 'complete', button: 'Complete abort', copy: 'The unused replacement CA key is gone. Wait for every active node to return to the original trust bundle.' },
});

function clearCARotationTimer() {
	if (state.caRotation.refreshTimer !== null) clearTimeout(state.caRotation.refreshTimer);
	state.caRotation.refreshTimer = null;
}

function scheduleCARotationRefresh() {
	clearCARotationTimer();
	if (!state.caRotation.networkID || $('#ca-rotation-dialog').open === false || document.visibilityState === 'hidden') return;
	state.caRotation.refreshTimer = setTimeout(() => refreshCARotation(false), 5000);
}

function setCARotationBusy(busy, action = '') {
	state.caRotation.busy = busy; state.caRotation.action = action;
	$('#ca-rotation-dialog').setAttribute('aria-busy', String(busy));
	$('#ca-rotation-primary').disabled = busy; $('#ca-rotation-abort').disabled = busy;
	if (busy && action) $('#ca-rotation-primary').textContent = 'Applying safe transition…';
}

function renderCARotation(document) {
	state.caRotation.document = document; state.caRotation.baseRevision = document.configRevision;
	const presentation = caRotationPresentation[document.phase];
	$('#ca-rotation-phase').textContent = presentation.label;
	$('#ca-rotation-revision').textContent = document.configRevision;
	$('#ca-rotation-convergence').textContent = `${document.convergedNodes} of ${document.activeNodes}`;
	$('#ca-rotation-recoveries').textContent = document.pendingRecoveryReplays;
	$('#ca-rotation-current-digest').textContent = document.currentTrustBundleSHA256;
	$('#ca-rotation-current-digest').title = document.currentTrustBundleSHA256;
	$('#ca-rotation-target-digest').textContent = document.targetCACertificateSHA256 || 'Not prepared';
	$('#ca-rotation-target-digest').title = document.targetCACertificateSHA256 || '';
	const actionAvailable = document.availableActions.includes(presentation.action);
	let nextCopy = presentation.copy;
	if (!actionAvailable && document.phase === 'stable') nextCopy = 'Finish the active firewall canary rollout before preparing a CA replacement.';
	if (!actionAvailable && document.phase !== 'stable') {
		nextCopy += document.pendingRecoveryReplays > 0
			? ` ${document.pendingRecoveryReplays} in-flight recovery replay(s) must expire before the trust bundle can change.`
			: ` ${document.activeNodes - document.convergedNodes} active node(s) still need to converge.`;
	}
	$('#ca-rotation-next-copy').textContent = nextCopy;
	const list = $('#ca-rotation-node-list'); list.replaceChildren();
	if (document.nodes.length === 0) {
		const item = document.createElement('li'); item.className = 'readiness-check pending'; item.textContent = 'No active nodes; lifecycle gates can advance immediately.'; list.append(item);
	} else {
		for (const node of document.nodes) {
			const item = document.createElement('li'); item.className = `readiness-check ${node.converged ? 'pass' : 'pending'}`;
			const copy = document.createElement('span'); copy.className = 'ca-rotation-node-copy';
			const name = document.createElement('strong'); name.textContent = node.name;
			const detail = document.createElement('small'); detail.textContent = `config r${node.appliedConfigRevision} · cert g${node.appliedCertificateGeneration}/g${node.certificateGeneration}`;
			copy.append(name, detail); item.append(copy); list.append(item);
		}
	}
	const primary = $('#ca-rotation-primary'); primary.dataset.action = presentation.action; primary.textContent = presentation.button;
	primary.classList.toggle('hidden', !actionAvailable); primary.disabled = state.caRotation.busy;
	const abort = $('#ca-rotation-abort'); abort.classList.toggle('hidden', !document.availableActions.includes('abort')); abort.disabled = state.caRotation.busy;
	$('#ca-rotation-error').textContent = '';
	scheduleCARotationRefresh();
}

async function refreshCARotation(showErrors = true) {
	const networkID = state.caRotation.networkID;
	const requestID = state.caRotation.requestID;
	if (!networkID || state.caRotation.busy) return;
	try {
		const document = caRotationModel.validate(await api(`/api/v1/networks/${networkID}/ca-rotation`));
		if (requestID !== state.caRotation.requestID || document.networkID !== networkID) return;
		renderCARotation(document);
	} catch (error) {
		if (requestID === state.caRotation.requestID && showErrors) $('#ca-rotation-error').textContent = `Could not load CA rotation: ${error.message}`;
		scheduleCARotationRefresh();
	}
}

async function openCARotation(network) {
	clearCARotationTimer();
	state.caRotation.requestID += 1; state.caRotation.networkID = network.id; state.caRotation.baseRevision = network.config_revision;
	state.caRotation.document = null; state.caRotation.busy = false; state.caRotation.action = '';
	$('#ca-rotation-network-name').textContent = network.name; $('#ca-rotation-phase').textContent = 'Loading'; $('#ca-rotation-revision').textContent = network.config_revision;
	$('#ca-rotation-convergence').textContent = '—'; $('#ca-rotation-recoveries').textContent = '—'; $('#ca-rotation-current-digest').textContent = '—'; $('#ca-rotation-target-digest').textContent = 'Not prepared';
	$('#ca-rotation-node-list').replaceChildren(); $('#ca-rotation-error').textContent = ''; $('#ca-rotation-primary').classList.add('hidden'); $('#ca-rotation-abort').classList.add('hidden');
	$('#ca-rotation-dialog').showModal(); setCARotationBusy(false); await refreshCARotation(true);
}

function caRotationConfirmation(action) {
	return ({
		prepare: 'Prepare a replacement CA? Mesh will encrypt the new private key and deploy overlapping trust before any certificate changes.',
		activate: 'Activate CA rotation? Every active agent will renew its Nebula certificate early under the replacement CA while both roots remain trusted.',
		finalize: 'Finalize the replacement CA? Mesh will remove the old CA private key from authoritative state and deploy replacement-only trust. This is allowed only after every active node has installed a replacement certificate.',
		abort: 'Abort this prepared rotation? The unused replacement CA private key will be removed from authoritative state and nodes will return to the original trust bundle.',
		complete: 'Complete this converged CA transition and clear its temporary lifecycle metadata?',
	})[action] || 'Apply this CA lifecycle action?';
}

function caRotationExpectedPhase(action, currentPhase) {
	if (action === 'prepare') return 'prepared';
	if (action === 'activate') return 'rotating';
	if (action === 'finalize') return 'finalizing';
	if (action === 'abort') return 'aborting';
	if (action === 'complete' && (currentPhase === 'finalizing' || currentPhase === 'aborting')) return 'stable';
	return '';
}

async function applyCARotationAction(action) {
	const current = state.caRotation.document;
	if (!current || !current.availableActions.includes(action) || !confirm(caRotationConfirmation(action))) return;
	const requestID = state.caRotation.requestID; const expectedRevision = current.configRevision; const expectedPhase = caRotationExpectedPhase(action, current.phase);
	clearCARotationTimer(); setCARotationBusy(true, action); $('#ca-rotation-error').textContent = '';
	try {
		const updated = caRotationModel.validate(await api(`/api/v1/networks/${state.caRotation.networkID}/ca-rotation`, {
			method: 'POST', body: JSON.stringify({ action, expected_config_revision: expectedRevision }), timeoutMS: action === 'prepare' ? 30000 : 12000,
		}));
		if (requestID !== state.caRotation.requestID) return;
		if (updated.networkID !== state.caRotation.networkID || updated.phase !== expectedPhase || updated.configRevision !== expectedRevision + 1) throw new Error('CA rotation returned an unexpected network, phase, or revision transition.');
		renderCARotation(updated); flash(`CA lifecycle advanced to ${caRotationPresentation[updated.phase].label.toLowerCase()} at revision ${updated.configRevision}`);
		loadNetworks(true).catch(() => flash('CA lifecycle advanced, but fleet health could not be refreshed.'));
	} catch (error) {
		if (requestID !== state.caRotation.requestID) return;
		if (error.status === 401) { $('#ca-rotation-dialog').close(); await showLogin(false); return; }
		try {
			const readback = caRotationModel.validate(await api(`/api/v1/networks/${state.caRotation.networkID}/ca-rotation`));
			if (requestID !== state.caRotation.requestID) return;
			if (readback.phase === expectedPhase && readback.configRevision === expectedRevision + 1) {
				renderCARotation(readback); flash(`The response was interrupted, but CA lifecycle revision ${readback.configRevision} is verified in phase ${readback.phase}.`); return;
			}
			renderCARotation(readback);
			$('#ca-rotation-error').textContent = error.status === 409 ? `Lifecycle state changed to ${readback.phase} at revision ${readback.configRevision}. Review convergence before retrying.` : `Could not ${action} CA rotation: ${error.message}`;
		} catch (readbackError) {
			$('#ca-rotation-error').textContent = `The CA lifecycle outcome is unknown because both the action response and authoritative readback failed (${readbackError.message}). Reopen this view before retrying.`;
		}
	} finally {
		if (requestID === state.caRotation.requestID) { setCARotationBusy(false); if (state.caRotation.document) renderCARotation(state.caRotation.document); }
	}
}

$('#ca-rotation-primary').addEventListener('click', () => applyCARotationAction($('#ca-rotation-primary').dataset.action));
$('#ca-rotation-abort').addEventListener('click', () => applyCARotationAction('abort'));
$('#ca-rotation-dialog').addEventListener('cancel', (event) => { if (state.caRotation.busy) event.preventDefault(); });
$('#ca-rotation-dialog').addEventListener('close', () => {
	clearCARotationTimer(); state.caRotation.requestID += 1; state.caRotation.networkID = ''; state.caRotation.baseRevision = 0;
	state.caRotation.busy = false; state.caRotation.action = ''; state.caRotation.document = null; $('#ca-rotation-network-name').textContent = ''; $('#ca-rotation-error').textContent = '';
});
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible' && state.caRotation.networkID) refreshCARotation(false); else clearCARotationTimer(); });

function openNode(networkID, lighthouse, onboardingStep = '') {
  const form = $('#node-form');
  form.reset();
  form.network_id.value = networkID;
  form.role.value = lighthouse ? 'lighthouse' : 'member';
  form.role.disabled = onboardingStep !== '';
  form.dataset.onboardingStep = onboardingStep;
  $('#node-dialog-eyebrow').textContent = onboardingStep === 'lighthouse' ? 'Step 2 of 3' : onboardingStep === 'member' ? 'Step 3 of 3' : onboardingStep === 'redundancy' ? 'Readiness remediation' : 'Add a machine';
  $('#node-dialog-title').textContent = onboardingStep === 'lighthouse' ? 'Add your first lighthouse' : onboardingStep === 'member' ? 'Add your first member' : onboardingStep === 'redundancy' ? 'Add a second lighthouse' : 'New node';
  $('#node-dialog-copy').textContent = onboardingStep === 'lighthouse'
    ? 'Publish the UDP endpoint that new members will use, then place this lighthouse in its real site and failure domain.'
    : onboardingStep === 'member'
      ? 'Place a member in its real site and failure domain so Mesh can verify the first authenticated path.'
      : onboardingStep === 'redundancy'
        ? 'Place this lighthouse in a different failure domain and publish the independent UDP endpoint members will use.'
        : 'Create a one-time enrollment for a lighthouse or member.';
  $('#node-cancel').textContent = onboardingStep === 'lighthouse' || onboardingStep === 'member' ? 'Finish later' : 'Cancel';
  toggleEndpoint();
  $('#node-dialog').showModal();
  $('#node-name').focus();
}

function readinessBadgeClass(value) {
  if (value === 'ready') return 'healthy';
  if (value === 'verification_required') return 'warning';
  return 'critical';
}

function readinessCheckBadgeClass(value) {
  if (value === 'pass') return 'healthy';
  if (value === 'warning' || value === 'unknown') return 'warning';
  return 'critical';
}

function clearReadinessPresentation() {
  $('#readiness-overall').className = 'health-badge critical';
  $('#readiness-overall').textContent = 'Unavailable';
  $('#readiness-generated').textContent = 'No readiness result is inferred until the checks complete.';
  $('#readiness-error').textContent = '';
  $('#readiness-check-list').replaceChildren();
	$('#readiness-site-list').replaceChildren();
	$('#readiness-site-section').classList.add('hidden');
  $('#readiness-lighthouse-list').replaceChildren();
  $('#readiness-lighthouse-section').classList.add('hidden');
  $('#readiness-add-lighthouse').classList.add('hidden');
}

function setReadinessBusy(busy) {
  state.readiness.busy = busy;
  $('#refresh-readiness').disabled = busy;
  $('#refresh-readiness').textContent = busy ? 'Running checks…' : 'Run checks now';
  $('#readiness-dialog').setAttribute('aria-busy', busy ? 'true' : 'false');
}

function clearReadinessRefreshTimer() {
  if (state.readiness.refreshTimer !== null) clearTimeout(state.readiness.refreshTimer);
  state.readiness.refreshTimer = null;
  delete $('#readiness-dialog').dataset.autoRefreshScheduled;
}

function readinessCanAutoRefresh() {
  return authenticated && document.visibilityState === 'visible' && $('#readiness-dialog').open && state.readiness.networkID !== '' && !state.readiness.busy;
}

function scheduleReadinessRefresh() {
  clearReadinessRefreshTimer();
  if (!readinessCanAutoRefresh()) return;
  state.readiness.refreshTimer = setTimeout(() => {
    state.readiness.refreshTimer = null;
    delete $('#readiness-dialog').dataset.autoRefreshScheduled;
    runNetworkReadiness().catch(() => {});
  }, READINESS_REFRESH_INTERVAL_MS);
  $('#readiness-dialog').dataset.autoRefreshScheduled = 'true';
}

function readinessCheckItem(label, check) {
  const item = document.createElement('li'); item.className = `readiness-check status-${check.status}`;
  const heading = document.createElement('div'); heading.className = 'readiness-check-heading';
  const title = document.createElement('strong'); title.textContent = label;
  const badge = document.createElement('span'); badge.className = `health-badge ${readinessCheckBadgeClass(check.status)}`; badge.textContent = readinessModel.statusLabel(check.status);
  heading.append(title, badge);
  const summary = document.createElement('p'); summary.textContent = check.summary;
  const action = document.createElement('p'); action.className = 'readiness-action'; action.textContent = check.action;
  const source = document.createElement('span'); source.className = 'readiness-source';
  source.textContent = `Evidence: ${check.evidenceSource.replaceAll('_', ' ')}${check.evidenceAt ? ` · observed ${new Date(check.evidenceAt).toLocaleString()}` : ''}`;
  item.append(heading, summary, action, source);
  return item;
}

function renderReadiness(report) {
  const overall = $('#readiness-overall');
  overall.className = `health-badge ${readinessBadgeClass(report.overall)}`;
  overall.textContent = readinessModel.overallLabel(report.overall);
  const generated = new Date(report.generatedAt).toLocaleString();
  const projection = report.projection.complete ? `${report.projection.observedLighthouses} lighthouse records checked` : `${report.projection.includedLighthouses} of ${report.projection.observedLighthouses} lighthouse records checked`;
  $('#readiness-generated').textContent = `Generated ${generated} · ${projection}. Control-plane DNS is shown separately; member DNS, route, and public UDP evidence is accepted only from fresh, exact-heartbeat authenticated node reports.`;

  const checks = [
    ['Managed CIDR collision', report.checks.managedRouteOverlap],
    ['Client route collision', report.checks.clientRouteOverlap],
    ['Lighthouse redundancy', report.checks.lighthouseRedundancy],
		['Site and failure-domain diversity', report.checks.topologyDiversity],
    ['Lighthouse DNS', report.checks.dnsResolution],
		['Member-side DNS', report.checks.memberDNSResolution],
    ['Public UDP reachability', report.checks.publicUDPReachability],
  ];
  const list = $('#readiness-check-list');
  list.replaceChildren(...checks.map(([label, check]) => readinessCheckItem(label, check)));

	const siteList = $('#readiness-site-list');
	siteList.replaceChildren();
	for (const site of report.sites) {
		const item = document.createElement('li'); item.className = 'readiness-site';
		const identity = document.createElement('div');
		const name = document.createElement('strong'); name.textContent = site.name;
		const domains = document.createElement('code'); domains.textContent = site.failureDomains.join(', ');
		identity.append(name, domains);
		const counts = document.createElement('span'); counts.textContent = `${site.activeNodes}/${site.configuredNodes} active · ${site.activeLighthouses} lighthouse${site.activeLighthouses === 1 ? '' : 's'} · ${site.activeMembers} member${site.activeMembers === 1 ? '' : 's'}`;
		item.append(identity, counts); siteList.append(item);
	}
	$('#readiness-site-section').classList.toggle('hidden', report.sites.length === 0);

  const lighthouseList = $('#readiness-lighthouse-list');
  lighthouseList.replaceChildren();
  for (const lighthouse of report.lighthouses) {
    const item = document.createElement('li'); item.className = 'readiness-lighthouse';
    const identity = document.createElement('div');
    const name = document.createElement('strong'); name.textContent = lighthouse.name;
    const endpoint = document.createElement('code'); endpoint.textContent = lighthouse.publicEndpoint;
    identity.append(name, endpoint);
    const evidence = document.createElement('span');
    if (lighthouse.dnsResolution === 'resolved') evidence.textContent = `DNS resolved to ${lighthouse.resolvedAddressCount} address${lighthouse.resolvedAddressCount === 1 ? '' : 'es'} from the control plane`;
    else if (lighthouse.dnsResolution === 'unresolved') evidence.textContent = 'DNS did not resolve from the control plane';
    else evidence.textContent = `${lighthouse.endpointHostType.toUpperCase()} literal; DNS not required`;
    const lifecycle = document.createElement('span'); lifecycle.className = `status ${lighthouse.lifecycleStatus}`; lifecycle.textContent = lighthouse.lifecycleStatus;
    item.append(identity, evidence, lifecycle); lighthouseList.append(item);
  }
  $('#readiness-lighthouse-section').classList.toggle('hidden', report.lighthouses.length === 0);
  const addLighthouse = $('#readiness-add-lighthouse');
  const configured = report.checks.lighthouseRedundancy.configuredLighthouses;
  addLighthouse.textContent = configured === 0 ? 'Add lighthouse' : 'Add second lighthouse';
  addLighthouse.classList.toggle('hidden', configured >= report.checks.lighthouseRedundancy.requiredLighthouses);
}

async function runNetworkReadiness() {
  const networkID = state.readiness.networkID;
  if (!networkID || state.readiness.busy) return;
  clearReadinessRefreshTimer();
  const requestID = ++state.readiness.requestID;
  clearReadinessPresentation();
  setReadinessBusy(true);
  try {
    const report = readinessModel.validate(await api(`/api/v1/networks/${networkID}/readiness`, { timeoutMS: 8000 }));
    if (requestID !== state.readiness.requestID || networkID !== state.readiness.networkID) return;
    if (report.network.id !== networkID) throw new Error('Readiness network identity mismatch');
    renderReadiness(report);
  } catch (error) {
    if (error.status === 401 && requestID === state.readiness.requestID && networkID === state.readiness.networkID) {
      $('#readiness-dialog').close();
      await showLogin(false);
      return;
    }
    if (requestID === state.readiness.requestID && networkID === state.readiness.networkID) {
      clearReadinessPresentation();
      $('#readiness-error').textContent = 'Deployment readiness could not be verified. No result is inferred.';
    }
  } finally {
    if (requestID === state.readiness.requestID && networkID === state.readiness.networkID) {
      setReadinessBusy(false);
      scheduleReadinessRefresh();
    }
  }
}

function openReadiness(network) {
  state.readiness.requestID += 1;
  state.readiness.networkID = network.id;
  state.readiness.network = network;
  state.readiness.busy = false;
  clearReadinessRefreshTimer();
  $('#readiness-network-name').textContent = network.name;
  clearReadinessPresentation();
  setReadinessBusy(false);
  $('#readiness-dialog').showModal();
  runNetworkReadiness();
}

$('#refresh-readiness').addEventListener('click', runNetworkReadiness);
$('#readiness-add-lighthouse').addEventListener('click', () => {
  const network = state.readiness.network;
  if (!network) return;
  $('#readiness-dialog').close();
  openNode(network.id, true, 'redundancy');
});
$('#readiness-dialog').addEventListener('close', () => {
  clearReadinessRefreshTimer();
  state.readiness.requestID += 1;
  state.readiness.networkID = '';
  state.readiness.network = null;
  state.readiness.busy = false;
  clearReadinessPresentation();
  setReadinessBusy(false);
});

function toggleEndpoint() { $('#endpoint-field').classList.toggle('hidden', $('#node-role').value !== 'lighthouse'); $('#node-endpoint').required = $('#node-role').value === 'lighthouse'; }
$('#node-role').addEventListener('change', toggleEndpoint);

function openNetworkRetirement(network, nodes) {
	if (!network || !validResourceID(network.id) || !Number.isInteger(network.config_revision) || network.config_revision < 1 || !Array.isArray(nodes)) return;
	const form = $('#retire-network-form');
	form.reset();
	form.network_id.value = network.id;
	form.expected_config_revision.value = String(network.config_revision);
	$('.form-error', form).textContent = '';
	state.retirement = {
		networkID: network.id,
		networkName: network.name,
		networkCIDR: network.cidr,
		expectedRevision: network.config_revision,
		nodeCount: nodes.length,
		saving: false,
	};
	$('#retire-network-name').textContent = network.name;
	$('#retire-confirmation-name').textContent = network.name;
	$('#retire-network-cidr').textContent = network.cidr;
	$('#retire-network-revision').textContent = network.config_revision;
	$('#retire-network-node-count').textContent = `${nodes.length} node${nodes.length === 1 ? '' : 's'}`;
	$('#retire-network-dialog').showModal();
	$('#retire-confirmation').focus();
}

function authoritativeNetworkIsAbsent(networkID) {
	return state.fleet !== null && !state.networks.some((network) => network.id === networkID);
}

function validateNetworkRetirementReceipt(result, expected) {
	if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('Network retirement returned an invalid receipt.');
	const expectedKeys = [
		'network_id', 'name', 'cidr', 'config_revision', 'retired_at', 'node_count', 'pending_nodes', 'active_nodes', 'revoked_nodes',
		'credentials_invalidated', 'encrypted_key_material_removed', 'name_cidr_permanently_reserved',
		'runtime_telemetry_records_removed', 'runtime_telemetry_cleanup_complete',
	];
	const keys = Object.keys(result).sort();
	if (keys.length !== expectedKeys.length || expectedKeys.some((key) => !keys.includes(key))) throw new Error('Network retirement returned an invalid receipt.');
	const counts = ['node_count', 'pending_nodes', 'active_nodes', 'revoked_nodes', 'runtime_telemetry_records_removed'];
	if (result.network_id !== expected.networkID || result.name !== expected.networkName || result.cidr !== expected.networkCIDR || result.config_revision !== expected.expectedRevision || result.node_count !== expected.nodeCount) throw new Error('Network retirement receipt did not match the confirmed network.');
	if (!counts.every((key) => Number.isInteger(result[key]) && result[key] >= 0) || result.pending_nodes + result.active_nodes + result.revoked_nodes !== result.node_count || result.runtime_telemetry_records_removed > result.node_count) throw new Error('Network retirement returned invalid removal counts.');
	if (typeof result.retired_at !== 'string' || !Number.isFinite(Date.parse(result.retired_at))) throw new Error('Network retirement returned an invalid timestamp.');
	if (result.credentials_invalidated !== true || result.encrypted_key_material_removed !== true || result.name_cidr_permanently_reserved !== true || typeof result.runtime_telemetry_cleanup_complete !== 'boolean') throw new Error('Network retirement receipt did not prove required cleanup.');
	return result;
}

$('#new-network').addEventListener('click', () => $('#network-dialog').showModal());
$$('.open-network-modal').forEach((button) => button.addEventListener('click', () => $('#network-dialog').showModal()));
$$('.close-dialog').forEach((button) => button.addEventListener('click', () => {
	const dialog = button.closest('dialog');
	if (dialog?.id === 'dns-dialog' && state.dns.saving) return;
	if (dialog?.id === 'relay-dialog' && state.relays.saving) return;
	if (dialog?.id === 'retire-network-dialog' && state.retirement.saving) return;
	dialog?.close();
}));

$('#network-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const form = event.currentTarget; const button = $('button[type=submit]', form); button.disabled = true; $('.form-error', form).textContent = '';
  try {
    const network = await api('/api/v1/networks', { method: 'POST', body: JSON.stringify({ name: form.name.value, cidr: form.cidr.value }) });
    if (!network || !validResourceID(network.id)) throw new Error('Network was created, but its onboarding response was invalid. Refresh before continuing.');
    state.networkView = 'workspace'; state.selectedNetworkID = network.id;
    form.reset(); form.cidr.value = '10.42.0.0/24'; $('#network-dialog').close(); await loadNetworks(true);
    openNode(network.id, true, 'lighthouse');
    flash('Network created. Configure its first public lighthouse to finish setup.');
  }
  catch (error) { $('.form-error', form).textContent = error.message; } finally { button.disabled = false; }
});

$('#retire-network-form').addEventListener('submit', async (event) => {
	event.preventDefault();
	const form = event.currentTarget;
	const button = $('button[type=submit]', form);
	const expected = { ...state.retirement };
	$('.form-error', form).textContent = '';
	if (form.confirmation_name.value !== expected.networkName) {
		$('.form-error', form).textContent = `Type ${expected.networkName} exactly to confirm retirement.`;
		form.confirmation_name.focus();
		return;
	}
	state.retirement.saving = true;
	button.disabled = true;
	try {
		const result = validateNetworkRetirementReceipt(await api(`/api/v1/networks/${expected.networkID}/retire`, {
			method: 'POST',
			body: JSON.stringify({ expected_config_revision: expected.expectedRevision, confirmation_name: expected.networkName }),
		}), expected);
		await loadNetworks(true);
		if (!authoritativeNetworkIsAbsent(expected.networkID)) throw new Error('Retirement committed, but authoritative inventory removal could not be verified. Refresh before continuing.');
		$('#retire-network-dialog').close();
		if (result.runtime_telemetry_cleanup_complete) flash(`${expected.networkName} retired. Credentials and encrypted key material were removed; its name and CIDR remain reserved.`);
		else flash(`${expected.networkName} retired and credentials invalidated. Some reconstructible runtime telemetry could not be cleaned up; control-plane retirement is complete.`);
	} catch (error) {
		await loadNetworks(true).catch(() => {});
		if (authoritativeNetworkIsAbsent(expected.networkID)) {
			$('#retire-network-dialog').close();
			flash(`${expected.networkName} is absent from authoritative inventory. Retirement completed despite an interrupted or invalid response.`);
		} else {
			$('.form-error', form).textContent = error.message;
		}
	} finally {
		state.retirement.saving = false;
		button.disabled = false;
	}
});

$('#retire-network-dialog').addEventListener('close', () => {
	$('#retire-network-form').reset();
	$('.form-error', $('#retire-network-form')).textContent = '';
	state.retirement = { networkID: '', networkName: '', networkCIDR: '', expectedRevision: 0, nodeCount: 0, saving: false };
});

$('#node-dialog').addEventListener('close', () => {
  const form = $('#node-form');
  form.dataset.onboardingStep = '';
  form.role.disabled = false;
  $('#node-dialog-eyebrow').textContent = 'Add a machine';
  $('#node-dialog-title').textContent = 'New node';
  $('#node-dialog-copy').textContent = 'Create a one-time enrollment for a lighthouse or member.';
  $('#node-cancel').textContent = 'Cancel';
});

$('#node-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const form = event.currentTarget; const button = $('button[type=submit]', form); button.disabled = true; $('.form-error', form).textContent = '';
  const onboardingStep = form.dataset.onboardingStep;
  const nextAction = onboardingStep === 'lighthouse' && form.role.value === 'lighthouse'
    ? 'member'
    : (onboardingStep === 'member' && form.role.value === 'member') || (onboardingStep === 'redundancy' && form.role.value === 'lighthouse') ? 'readiness' : '';
  try {
    const result = await api(`/api/v1/networks/${form.network_id.value}/nodes`, { method: 'POST', body: JSON.stringify({ name: form.name.value, site: form.site.value, failure_domain: form.failure_domain.value, role: form.role.value, public_endpoint: form.public_endpoint.value, groups: form.groups.value.split(',').map((group) => group.trim()).filter(Boolean), routed_subnets: form.routed_subnets.value.split(/[\n,]+/u).map((subnet) => subnet.trim()).filter(Boolean) }) });
    $('#node-dialog').close(); showEnrollment(result, nextAction); await loadNetworks(true);
  } catch (error) { $('.form-error', form).textContent = error.message; } finally { button.disabled = false; }
});

$('#topology-form').addEventListener('submit', async (event) => {
	event.preventDefault(); const form = event.currentTarget; const button = $('button[type=submit]', form); button.disabled = true; $('.form-error', form).textContent = '';
	try {
		await api(`/api/v1/nodes/${form.node_id.value}/topology`, { method: 'PUT', body: JSON.stringify({ site: form.site.value, failure_domain: form.failure_domain.value }) });
		$('#topology-dialog').close(); await loadNetworks(true); flash('Node placement updated. Signed Nebula configuration was unchanged.');
	} catch (error) { $('.form-error', form).textContent = error.message; } finally { button.disabled = false; }
});

function showEnrollment(result, nextAction = '') {
  const commands = installGuideModel.commands(location.origin, state.installGuide);
  const handoffURL = state.installGuide.linux.bootstrapHandoffURL;
  const handoffLink = $('#bootstrap-handoff-link');
  $('#enroll-node-name').textContent = result.node.name;
  handoffLink.textContent = handoffURL || '';
  if (handoffURL === null) handoffLink.removeAttribute('href');
  else handoffLink.href = handoffURL;
  $('#bootstrap-handoff-guidance').classList.toggle('hidden', handoffURL === null);
  $('#bootstrap-handoff-unavailable').classList.toggle('hidden', handoffURL !== null);
  $('#install-command').textContent = commands.install || '';
  $('#enroll-command').textContent = commands.enroll;
  $('#activate-command').textContent = commands.activate;
  $('#install-command-row').classList.toggle('hidden', commands.install === null);
  $('#install-unavailable').classList.toggle('hidden', commands.install !== null);
  $('#enroll-token').textContent = result.enrollment_token;
  const canContinue = (nextAction === 'member' || nextAction === 'readiness') && validResourceID(result?.node?.network_id);
  state.enrollmentNextNetworkID = canContinue ? result.node.network_id : '';
  state.enrollmentNextAction = canContinue ? nextAction : '';
  const next = $('#enroll-next');
  next.textContent = nextAction === 'member' ? 'I saved this — add first member' : 'I saved this — check readiness';
  next.classList.toggle('hidden', !canContinue);
  $('#enroll-dialog').showModal();
}

$('#enroll-next').addEventListener('click', () => {
  const networkID = state.enrollmentNextNetworkID;
  const nextAction = state.enrollmentNextAction;
  if (!validResourceID(networkID) || (nextAction !== 'member' && nextAction !== 'readiness')) return;
  const network = nextAction === 'readiness' ? state.networks.find((candidate) => candidate.id === networkID) : null;
  if (nextAction === 'readiness' && !network) return;
  $('#enroll-dialog').close();
  if (nextAction === 'member') openNode(networkID, false, 'member');
  else openReadiness(network);
});

$('#enroll-dialog').addEventListener('close', () => {
  state.enrollmentNextNetworkID = '';
  state.enrollmentNextAction = '';
  $('#enroll-next').classList.add('hidden');
  $('#enroll-node-name').textContent = '';
  $('#bootstrap-handoff-link').textContent = '';
  $('#bootstrap-handoff-link').removeAttribute('href');
  $('#install-command').textContent = '';
  $('#enroll-command').textContent = '';
  $('#activate-command').textContent = '';
  $('#enroll-token').textContent = '';
});

function showAgentRecovery(result) {
  const command = `(sudo systemctl stop mesh-agent.service && read -rsp 'Agent recovery token: ' MESH_AGENT_RECOVERY_TOKEN && printf '\\n' && trap 'unset MESH_AGENT_RECOVERY_TOKEN' EXIT && printf '%s\\n' "$MESH_AGENT_RECOVERY_TOKEN" | sudo /usr/local/bin/meshctl recover-agent --token-file - --state /var/lib/mesh-agent/state.json --nebula /usr/local/bin/nebula --nebula-cert /usr/local/bin/nebula-cert --quarantine-service mesh-nebula.service && sudo systemctl start mesh-agent.service)`;
  $('#recovery-node-name').textContent = result.node.name;
  $('#recovery-command').textContent = command;
  $('#recovery-token').textContent = result.recovery_token;
  $('#recovery-expires-at').textContent = new Date(result.expires_at).toLocaleString();
  $('#recovery-dialog').showModal();
}

async function copyText(button, element) {
  await navigator.clipboard.writeText(element.textContent);
  button.textContent = 'Copied';
  setTimeout(() => { button.textContent = 'Copy'; }, 1600);
}

$('#copy-install-command').addEventListener('click', (event) => copyText(event.currentTarget, $('#install-command')));
$('#copy-enroll-command').addEventListener('click', (event) => copyText(event.currentTarget, $('#enroll-command')));
$('#copy-activate-command').addEventListener('click', (event) => copyText(event.currentTarget, $('#activate-command')));
$('#copy-recovery-command').addEventListener('click', (event) => copyText(event.currentTarget, $('#recovery-command')));
$('#recovery-dialog').addEventListener('close', () => {
  $('#recovery-node-name').textContent = '';
  $('#recovery-command').textContent = '';
  $('#recovery-token').textContent = '';
  $('#recovery-expires-at').textContent = '';
});

function canManageRecoveryCodes() {
  return state.authMethods.break_glass === true && hasPermission('identity.manage') && state.currentSession?.principal?.kind !== 'break_glass';
}

function renderRecoveryAvailability() {
  $('#recovery-codes-panel').classList.toggle('hidden', !canManageRecoveryCodes());
}

function randomRecoveryToken() {
  if (!globalThis.crypto || typeof globalThis.crypto.getRandomValues !== 'function') throw new Error('Secure browser randomness is unavailable.');
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  let binary = '';
  for (const value of bytes) binary += String.fromCharCode(value);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function newRecoveryDraft() {
  const id = `bg_${randomRecoveryToken()}`;
  return {
    code: `mesh-bg-v1.${id}.${randomRecoveryToken()}`,
    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
    registered: false,
  };
}

function showRecoveryDraft() {
  const draft = state.recoveryDraft;
  if (!draft) return;
  $('#recovery-code-plaintext').textContent = draft.code;
  $('#recovery-code-stored').checked = false;
  $('#recovery-code-stored').disabled = true;
  $('#finish-recovery-code').disabled = true;
  $('#retry-recovery-registration').classList.add('hidden');
  $('#recovery-code-error').textContent = '';
  $('#recovery-code-registration-state').textContent = 'Registering the credential hash with Mesh…';
  $('#recovery-code-dialog').showModal();
}

async function registerRecoveryDraft() {
  const draft = state.recoveryDraft;
  if (!draft) return;
  const retry = $('#retry-recovery-registration');
  retry.disabled = true;
  retry.classList.add('hidden');
  $('#recovery-code-error').textContent = '';
  $('#recovery-code-registration-state').textContent = 'Registering the credential hash with Mesh…';
  let summary;
  try {
    summary = validateRecoverySummary(await api('/api/v1/break-glass-codes', { method: 'POST', body: JSON.stringify({ code: draft.code, expires_at: draft.expiresAt }) }));
    if (summary.state !== 'usable') throw new Error('Mesh returned an invalid recovery-code confirmation.');
  } catch (error) {
    $('#recovery-code-registration-state').textContent = 'Registration confirmation was not received. Keep this dialog open and retry the exact same code.';
    $('#recovery-code-error').textContent = error.message;
    retry.classList.remove('hidden');
    retry.disabled = false;
    return;
  } finally {
    retry.disabled = false;
  }
  draft.registered = true;
  $('#recovery-code-registration-state').textContent = `Registered until ${new Date(summary.expires_at).toLocaleString()}.`;
  $('#recovery-code-stored').disabled = false;
  try { await loadRecoveryCodes(); } catch (error) { $('#recovery-codes-error').textContent = error.message; }
}

function scrubRecoveryDraft() {
  state.recoveryDraft = null;
  const dialog = $('#recovery-code-dialog');
  if (!dialog) return;
  if (dialog.open) dialog.close();
  $('#recovery-code-plaintext').textContent = '';
  $('#recovery-code-registration-state').textContent = '';
  $('#recovery-code-error').textContent = '';
  $('#recovery-code-stored').checked = false;
  $('#recovery-code-stored').disabled = true;
  $('#finish-recovery-code').disabled = true;
  $('#retry-recovery-registration').classList.add('hidden');
}

async function loadRecoveryCodes() {
  if (!canManageRecoveryCodes()) {
    renderRecoveryAvailability();
    return;
  }
  const inventory = await api('/api/v1/break-glass-codes');
  if (!inventory || typeof inventory !== 'object' || Array.isArray(inventory) || Object.keys(inventory).sort().join(',') !== 'codes,minimum_usable_codes,usable_codes' || !Array.isArray(inventory.codes) || !Number.isInteger(inventory.minimum_usable_codes) || inventory.minimum_usable_codes < 2 || inventory.minimum_usable_codes > 32 || !Number.isInteger(inventory.usable_codes) || inventory.usable_codes < 0) throw new Error('Invalid recovery-code inventory.');
  const codes = inventory.codes.map(validateRecoverySummary);
  const usable = codes.filter((code) => code.state === 'usable').length;
  if (inventory.usable_codes !== usable) throw new Error('Invalid recovery-code inventory.');
  renderRecoveryCodes(codes, inventory.minimum_usable_codes, usable);
}

function validateRecoveryTime(value) {
  return typeof value === 'string' && value.endsWith('Z') && Number.isFinite(Date.parse(value));
}

function validateRecoverySummary(code) {
  if (!code || typeof code !== 'object' || Array.isArray(code)) throw new Error('Invalid recovery-code inventory.');
  const keys = Object.keys(code).sort();
  const allowed = ['created_at', 'expires_at', 'id', 'revoked_at', 'state', 'used_at'];
  if (keys.some((key) => !allowed.includes(key)) || !/^bg_[A-Za-z0-9_-]{43}$/.test(code.id) || !validateRecoveryTime(code.created_at) || !validateRecoveryTime(code.expires_at) || !['usable', 'used', 'revoked', 'expired'].includes(code.state)) throw new Error('Invalid recovery-code inventory.');
  const used = Object.hasOwn(code, 'used_at');
  const revoked = Object.hasOwn(code, 'revoked_at');
  if ((used && !validateRecoveryTime(code.used_at)) || (revoked && !validateRecoveryTime(code.revoked_at)) || (code.state === 'used') !== used || (code.state === 'revoked') !== revoked || (used && revoked)) throw new Error('Invalid recovery-code inventory.');
  return code;
}

function renderRecoveryCodes(codes, minimum, usable) {
  const ready = usable >= minimum;
  const status = $('#recovery-inventory-status');
  status.className = `health-badge ${ready ? 'healthy' : 'critical'}`;
  status.textContent = ready ? 'Restart ready' : 'Below floor';
  $('#recovery-inventory-summary').textContent = ready
    ? `${usable} usable recovery ${usable === 1 ? 'code' : 'codes'} · configured minimum ${minimum}. OIDC-only cutover or restart has its required recovery inventory.`
    : `${usable} usable recovery ${usable === 1 ? 'code' : 'codes'} · configured minimum ${minimum}. Create ${minimum - usable} replacement ${minimum - usable === 1 ? 'code' : 'codes'} before OIDC-only cutover or restart.`;
  const list = $('#recovery-codes-list');
  list.replaceChildren();
  if (codes.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'recovery-code-empty';
    empty.textContent = 'No recovery codes are registered. Create at least two before switching to OIDC-only mode.';
    list.append(empty);
    return;
  }
  for (const code of codes) {
    const row = document.createElement('div'); row.className = 'recovery-code-row';
    const body = document.createElement('div');
    const id = document.createElement('div'); id.className = 'recovery-code-id'; id.textContent = code.id;
    const detail = document.createElement('div'); detail.className = 'recovery-code-detail'; detail.textContent = `Expires ${new Date(code.expires_at).toLocaleString()}`;
    body.append(id, detail);
    const status = document.createElement('span'); status.className = `recovery-code-state ${code.state}`; status.textContent = code.state;
    row.append(body, status);
    if (code.state === 'usable') {
      const revoke = document.createElement('button'); revoke.type = 'button'; revoke.className = 'secondary'; revoke.textContent = 'Revoke';
      revoke.addEventListener('click', async () => {
        if (!confirm(`Revoke recovery code ${code.id}?`)) return;
        revoke.disabled = true;
        try {
          await api(`/api/v1/break-glass-codes/${encodeURIComponent(code.id)}`, { method: 'DELETE' });
          await loadRecoveryCodes();
        } catch (error) {
          $('#recovery-codes-error').textContent = error.message;
          revoke.disabled = false;
        }
      });
      row.append(revoke);
    } else {
      row.append(document.createElement('span'));
    }
    list.append(row);
  }
}

$('#create-recovery-code').addEventListener('click', async () => {
  $('#recovery-codes-error').textContent = '';
  try {
    state.recoveryDraft = newRecoveryDraft();
    showRecoveryDraft();
    await registerRecoveryDraft();
  } catch (error) {
    scrubRecoveryDraft();
    $('#recovery-codes-error').textContent = error.message;
  }
});

$('#retry-recovery-registration').addEventListener('click', registerRecoveryDraft);
$('#copy-recovery-code').addEventListener('click', (event) => copyText(event.currentTarget, $('#recovery-code-plaintext')));
$('#download-recovery-code').addEventListener('click', () => {
  if (!state.recoveryDraft) return;
  const blob = new Blob([`${state.recoveryDraft.code}\n`], { type: 'text/plain' });
  const link = document.createElement('a');
  const url = URL.createObjectURL(blob);
  link.href = url;
  link.download = `mesh-recovery-code-${new Date().toISOString().slice(0, 10)}.txt`;
  link.click();
  URL.revokeObjectURL(url);
});
$('#recovery-code-stored').addEventListener('change', (event) => {
  $('#finish-recovery-code').disabled = !(state.recoveryDraft?.registered && event.currentTarget.checked);
});
$('#finish-recovery-code').addEventListener('click', () => {
  if (!state.recoveryDraft?.registered || !$('#recovery-code-stored').checked) return;
  $('#recovery-code-dialog').close();
});
$('#recovery-code-dialog').addEventListener('cancel', (event) => event.preventDefault());
$('#recovery-code-dialog').addEventListener('close', scrubRecoveryDraft);

$$('.nav-item').forEach((button) => button.addEventListener('click', async () => {
  $$('.nav-item').forEach((item) => item.classList.toggle('active', item === button));
  const activity = button.dataset.view === 'activity';
  $('#networks-view').classList.toggle('hidden', activity);
  $('#activity-view').classList.toggle('hidden', !activity);
  $('#page-title').textContent = activity ? 'Activity' : 'Networks';
  if (activity) {
    $('#app-page-header').classList.remove('hidden');
    $('#new-network').classList.add('hidden');
    await loadActivity();
  } else {
    renderNetworksSafely();
    await refreshVisibleFleet();
  }
}));

async function loadActivity() {
  $('#recovery-codes-error').textContent = '';
  const events = await api('/api/v1/audit');
  if (canManageRecoveryCodes()) {
    try { await loadRecoveryCodes(); } catch (error) {
      $('#recovery-inventory-status').className = 'health-badge critical';
      $('#recovery-inventory-status').textContent = 'Unavailable';
      $('#recovery-inventory-summary').textContent = 'No recovery posture is inferred because the authenticated inventory read failed.';
      $('#recovery-codes-error').textContent = error.message;
    }
  }
  const list = $('#activity-list'); list.replaceChildren();
  if (events.length === 0) {
    const empty = document.createElement('div'); empty.className = 'activity-empty';
    const icon = document.createElement('span'); icon.className = 'activity-empty-icon'; icon.append(meshIcon('check-circle-o'));
    const title = document.createElement('strong'); title.textContent = 'No security activity yet';
    const detail = document.createElement('span'); detail.textContent = 'Lifecycle and identity events will appear here as they occur.';
    empty.append(icon, title, detail); list.append(empty);
    return;
  }
  for (const event of events) {
    const row = document.createElement('div'); row.className = 'activity-item';
    const icon = document.createElement('div'); icon.className = 'activity-icon';
    icon.append(meshIcon(event.action.includes('revoked') ? 'exclamation' : 'check'));
    const body = document.createElement('div');
    const action = document.createElement('div'); action.className = 'activity-action'; action.textContent = event.action.replace('.', ' ');
    const resource = document.createElement('div'); resource.className = 'activity-resource'; resource.textContent = `${event.resource} · ${event.resource_id}`;
    body.append(action, resource);
    const time = document.createElement('time'); time.className = 'activity-time'; time.textContent = new Date(event.at).toLocaleString();
    row.append(icon, body, time); list.append(row);
  }
}

function flash(message) { const box = $('#flash'); box.textContent = message; box.classList.remove('hidden'); setTimeout(() => box.classList.add('hidden'), 4000); }

function fleetViewCanRefresh() {
  return authenticated && document.visibilityState === 'visible' && !$('#app-view').classList.contains('hidden') && !$('#networks-view').classList.contains('hidden');
}

function cachedFleetIsStale() {
  if (!state.fleet || state.fleetLoadedAtMS === 0) return true;
  const elapsed = Math.max(0, Date.now() - state.fleetLoadedAtMS);
  return state.fleetInitialAgeMS + elapsed >= healthModel.MAX_SNAPSHOT_AGE_MS;
}

function scheduleFleetExpiry() {
  if (state.fleetExpiryTimer !== null) clearTimeout(state.fleetExpiryTimer);
  const remaining = Math.max(0, healthModel.MAX_SNAPSHOT_AGE_MS - state.fleetInitialAgeMS);
  state.fleetExpiryTimer = setTimeout(() => {
    state.fleetExpiryTimer = null;
    if (!state.fleet || !cachedFleetIsStale()) return;
    clearFleet('The authoritative fleet snapshot expired. Inventory and health status were cleared while awaiting the next refresh.');
    renderNetworksSafely();
  }, remaining + 25);
}

async function refreshVisibleFleet(force = false) {
  if (!fleetViewCanRefresh()) return;
  if (cachedFleetIsStale()) {
    clearFleet('The previous authoritative fleet snapshot is stale. Inventory and health status were cleared while a fresh snapshot is requested.');
    renderNetworksSafely();
  }
  try { await loadNetworks(force); } catch {}
}

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') {
    refreshVisibleFleet().catch(() => {});
    if ($('#readiness-dialog').open && !state.readiness.busy) runNetworkReadiness().catch(() => {});
  } else {
    clearReadinessRefreshTimer();
    scrubRecoveryDraft();
  }
});
window.addEventListener('pageshow', () => {
  refreshVisibleFleet().catch(() => {});
  if ($('#readiness-dialog').open && !state.readiness.busy) runNetworkReadiness().catch(() => {});
});

boot();
setInterval(() => {
  refreshVisibleFleet().catch(() => {});
}, 15000);
