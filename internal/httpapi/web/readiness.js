(function publishMeshReadiness(root, factory) {
  const readiness = factory();
  if (typeof module === 'object' && module.exports) module.exports = readiness;
  if (root) root.MeshReadiness = readiness;
}(typeof globalThis === 'undefined' ? this : globalThis, function buildMeshReadiness() {
  'use strict';

  const SCHEMA = 'mesh-network-readiness-v6';
  const LIGHTHOUSE_LIMIT = 64;
  const REQUIRED_LIGHTHOUSES = 2;
  const MAX_RESOLVED_ADDRESSES = 16;
  const MAX_ACTIVE_PROBE_TARGETS = 8;
  const ACTIVE_PROBE_FRESHNESS_SECONDS = 30;
  const ROUTE_FRESHNESS_SECONDS = 90;
	const MEMBER_DNS_FRESHNESS_SECONDS = 90;
  const STATUSES = new Set(['pass', 'warning', 'blocked', 'unknown']);
  const OVERALL = new Set(['blocked', 'verification_required', 'ready']);

  function fail(message) {
    throw new Error(`Invalid deployment readiness: ${message}`);
  }

  function isRecord(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }

  function exactObject(value, required, name) {
    if (!isRecord(value)) fail(`${name} must be an object`);
    const allowed = new Set(required);
    for (const key of required) {
      if (!Object.prototype.hasOwnProperty.call(value, key)) fail(`${name}.${key} is required`);
    }
    for (const key of Object.keys(value)) {
      if (!allowed.has(key)) fail(`${name}.${key} is not allowed`);
    }
    return value;
  }

  function text(value, name, maximum, allowEmpty = false) {
    if (typeof value !== 'string' || value.length > maximum || (!allowEmpty && value.length === 0) ||
      value.trim() !== value || /[\u0000-\u001f\u007f]/u.test(value)) fail(`${name} is invalid`);
    return value;
  }

  function integer(value, name, maximum = 1_000_000) {
    if (!Number.isSafeInteger(value) || value < 0 || value > maximum) fail(`${name} is invalid`);
    return value;
  }

  function boolean(value, name) {
    if (typeof value !== 'boolean') fail(`${name} is invalid`);
    return value;
  }

  function oneOf(value, allowed, name) {
    if (typeof value !== 'string' || !allowed.has(value)) fail(`${name} is invalid`);
    return value;
  }

  function timestamp(value, name) {
    text(value, name, 64);
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(value) || !Number.isFinite(Date.parse(value))) fail(`${name} is invalid`);
    return value;
  }

  function status(value, name) {
    return oneOf(value, STATUSES, name);
  }

  function commonCheck(raw, name, evidenceSource) {
    if (status(raw.status, `${name}.status`) === undefined || raw.evidence_source !== evidenceSource) fail(`${name}.evidence_source is invalid`);
    return {
      status: raw.status,
      evidenceSource,
      summary: text(raw.summary, `${name}.summary`, 512),
      action: text(raw.action, `${name}.action`, 512),
    };
  }

  function validateRouteCheck(raw) {
    const name = 'checks.managed_route_overlap';
    exactObject(raw, ['status', 'evidence_source', 'overlapping_network_count', 'summary', 'action'], name);
    const result = commonCheck(raw, name, 'control_inventory');
    const count = integer(raw.overlapping_network_count, `${name}.overlapping_network_count`);
    if (result.status !== (count === 0 ? 'pass' : 'blocked')) fail(`${name}.status is inconsistent`);
    return Object.freeze({ ...result, overlappingNetworkCount: count });
  }

  function validateClientRouteCheck(raw, generatedAt) {
    const name = 'checks.client_route_overlap';
    exactObject(raw, ['status', 'evidence_source', 'observed_nodes', 'required_nodes', 'overlapping_nodes', 'freshness_window_seconds', 'evidence_at', 'summary', 'action'], name);
    const checkStatus = oneOf(raw.status, new Set(['pass', 'blocked', 'unknown']), `${name}.status`);
    const source = oneOf(raw.evidence_source, new Set(['authenticated_node_route_inventory', 'not_observed']), `${name}.evidence_source`);
    const observed = integer(raw.observed_nodes, `${name}.observed_nodes`);
    const required = integer(raw.required_nodes, `${name}.required_nodes`);
    const overlapping = integer(raw.overlapping_nodes, `${name}.overlapping_nodes`);
    const freshness = integer(raw.freshness_window_seconds, `${name}.freshness_window_seconds`, ROUTE_FRESHNESS_SECONDS);
    if (freshness !== ROUTE_FRESHNESS_SECONDS || observed > required || overlapping > observed) fail(`${name} counts are inconsistent`);
    let evidenceAt = null;
    if (checkStatus === 'pass') {
      if (source !== 'authenticated_node_route_inventory' || required < 1 || observed !== required || overlapping !== 0) fail(`${name} passing evidence is inconsistent`);
      evidenceAt = timestamp(raw.evidence_at, `${name}.evidence_at`);
    } else if (checkStatus === 'blocked') {
      if (source !== 'authenticated_node_route_inventory' || observed < 1 || overlapping < 1) fail(`${name} blocking evidence is inconsistent`);
      evidenceAt = timestamp(raw.evidence_at, `${name}.evidence_at`);
    } else if (source !== 'not_observed' || observed !== 0 || overlapping !== 0 || raw.evidence_at !== null) {
      fail(`${name} unknown evidence is inconsistent`);
    }
    if (evidenceAt !== null) {
      const evidenceAgeMS = Date.parse(generatedAt) - Date.parse(evidenceAt);
      if (evidenceAgeMS < 0 || evidenceAgeMS > freshness * 1000) fail(`${name}.evidence_at is outside its freshness window`);
    }
    return Object.freeze({
      status: checkStatus,
      evidenceSource: source,
      observedNodes: observed,
      requiredNodes: required,
      overlappingNodes: overlapping,
      freshnessWindowSeconds: freshness,
      evidenceAt,
      summary: text(raw.summary, `${name}.summary`, 512),
      action: text(raw.action, `${name}.action`, 512),
    });
  }

  function validateRedundancyCheck(raw, observed) {
    const name = 'checks.lighthouse_redundancy';
    exactObject(raw, ['status', 'evidence_source', 'configured_lighthouses', 'active_lighthouses', 'required_lighthouses', 'summary', 'action'], name);
    const result = commonCheck(raw, name, 'control_inventory');
    const configured = integer(raw.configured_lighthouses, `${name}.configured_lighthouses`);
    const active = integer(raw.active_lighthouses, `${name}.active_lighthouses`);
    const required = integer(raw.required_lighthouses, `${name}.required_lighthouses`, 32);
    if (configured !== observed || active > configured || required !== REQUIRED_LIGHTHOUSES) fail(`${name} counts are inconsistent`);
    const expected = active === 0 ? 'blocked' : active < required ? 'warning' : 'pass';
    if (result.status !== expected) fail(`${name}.status is inconsistent`);
    return Object.freeze({ ...result, configuredLighthouses: configured, activeLighthouses: active, requiredLighthouses: required });
  }

	function placementLabel(value, name) {
		const label = text(value, name, 63);
		if (!/^[a-z0-9][a-z0-9._-]{0,62}$/u.test(label)) fail(`${name} is invalid`);
		return label;
	}

	function validateTopologyCheck(raw, activeLighthouses) {
		const name = 'checks.topology_diversity';
		exactObject(raw, ['status', 'evidence_source', 'configured_sites', 'active_sites', 'active_nodes', 'assigned_active_nodes', 'active_lighthouses', 'assigned_active_lighthouses', 'distinct_lighthouse_failure_domains', 'required_lighthouse_failure_domains', 'summary', 'action'], name);
		const result = commonCheck(raw, name, 'control_inventory');
		if (result.status !== 'pass' && result.status !== 'warning') fail(`${name}.status is inconsistent`);
		const configuredSites = integer(raw.configured_sites, `${name}.configured_sites`);
		const activeSites = integer(raw.active_sites, `${name}.active_sites`, configuredSites);
		const activeNodes = integer(raw.active_nodes, `${name}.active_nodes`);
		const assignedActiveNodes = integer(raw.assigned_active_nodes, `${name}.assigned_active_nodes`, activeNodes);
		const topologyLighthouses = integer(raw.active_lighthouses, `${name}.active_lighthouses`, activeNodes);
		const assignedActiveLighthouses = integer(raw.assigned_active_lighthouses, `${name}.assigned_active_lighthouses`, topologyLighthouses);
		const distinctLighthouseFailureDomains = integer(raw.distinct_lighthouse_failure_domains, `${name}.distinct_lighthouse_failure_domains`, assignedActiveLighthouses);
		const requiredLighthouseFailureDomains = integer(raw.required_lighthouse_failure_domains, `${name}.required_lighthouse_failure_domains`, 32);
		if (topologyLighthouses !== activeLighthouses || requiredLighthouseFailureDomains !== REQUIRED_LIGHTHOUSES) fail(`${name} policy is inconsistent`);
		const expected = assignedActiveNodes === activeNodes && topologyLighthouses >= REQUIRED_LIGHTHOUSES && distinctLighthouseFailureDomains >= REQUIRED_LIGHTHOUSES ? 'pass' : 'warning';
		if (result.status !== expected) fail(`${name}.status is inconsistent`);
		return Object.freeze({ ...result, configuredSites, activeSites, activeNodes, assignedActiveNodes, activeLighthouses: topologyLighthouses, assignedActiveLighthouses, distinctLighthouseFailureDomains, requiredLighthouseFailureDomains });
	}

  function validateDNSCheck(raw, projectionComplete, included) {
    const name = 'checks.dns_resolution';
    exactObject(raw, ['status', 'evidence_source', 'dns_names', 'resolved_dns_names', 'unresolved_dns_names', 'summary', 'action'], name);
    const result = commonCheck(raw, name, 'control_plane_dns');
    const names = integer(raw.dns_names, `${name}.dns_names`, included);
    const resolved = integer(raw.resolved_dns_names, `${name}.resolved_dns_names`, names);
    const unresolved = integer(raw.unresolved_dns_names, `${name}.unresolved_dns_names`, names);
    if (resolved + unresolved !== names) fail(`${name} counts are inconsistent`);
    const expected = !projectionComplete || unresolved !== 0 ? 'blocked' : 'pass';
    if (result.status !== expected) fail(`${name}.status is inconsistent`);
    return Object.freeze({ ...result, dnsNames: names, resolvedDNSNames: resolved, unresolvedDNSNames: unresolved });
  }

  function validateMemberDNSCheck(raw, generatedAt) {
    const name = 'checks.member_dns_resolution';
    exactObject(raw, ['status', 'evidence_source', 'observed_members', 'required_members', 'failing_members', 'dns_names', 'freshness_window_seconds', 'evidence_at', 'summary', 'action'], name);
    const checkStatus = oneOf(raw.status, new Set(['pass', 'blocked', 'unknown']), `${name}.status`);
    const source = oneOf(raw.evidence_source, new Set(['authenticated_member_dns_resolution', 'not_observed']), `${name}.evidence_source`);
    const observed = integer(raw.observed_members, `${name}.observed_members`);
    const required = integer(raw.required_members, `${name}.required_members`);
    const failing = integer(raw.failing_members, `${name}.failing_members`);
    const names = integer(raw.dns_names, `${name}.dns_names`, LIGHTHOUSE_LIMIT);
    const freshness = integer(raw.freshness_window_seconds, `${name}.freshness_window_seconds`, MEMBER_DNS_FRESHNESS_SECONDS);
    if (freshness !== MEMBER_DNS_FRESHNESS_SECONDS || observed > required || failing > observed) fail(`${name} counts are inconsistent`);
    let evidenceAt = null;
    if (checkStatus === 'pass') {
      if (source !== 'authenticated_member_dns_resolution' || required < 1 || observed !== required || failing !== 0) fail(`${name} passing evidence is inconsistent`);
      evidenceAt = timestamp(raw.evidence_at, `${name}.evidence_at`);
    } else if (checkStatus === 'blocked') {
      if (source !== 'authenticated_member_dns_resolution' || observed < 1 || failing < 1) fail(`${name} blocking evidence is inconsistent`);
      evidenceAt = timestamp(raw.evidence_at, `${name}.evidence_at`);
    } else if (source !== 'not_observed' || observed !== 0 || failing !== 0 || raw.evidence_at !== null) {
      fail(`${name} unknown evidence is inconsistent`);
    }
    if (evidenceAt !== null) {
      const evidenceAgeMS = Date.parse(generatedAt) - Date.parse(evidenceAt);
      if (evidenceAgeMS < 0 || evidenceAgeMS > freshness * 1000) fail(`${name}.evidence_at is outside its freshness window`);
    }
    return Object.freeze({
      status: checkStatus,
      evidenceSource: source,
      observedMembers: observed,
      requiredMembers: required,
      failingMembers: failing,
      dnsNames: names,
      freshnessWindowSeconds: freshness,
      evidenceAt,
      summary: text(raw.summary, `${name}.summary`, 512),
      action: text(raw.action, `${name}.action`, 512),
    });
  }

  function validateUDPCheck(raw, activeLighthouses, generatedAt) {
    const name = 'checks.public_udp_reachability';
    exactObject(raw, ['status', 'evidence_source', 'observed_members', 'required_members', 'verified_lighthouses', 'required_lighthouses', 'freshness_window_seconds', 'evidence_at', 'summary', 'action'], name);
    const checkStatus = oneOf(raw.status, new Set(['pass', 'unknown']), `${name}.status`);
    const source = oneOf(raw.evidence_source, new Set(['authenticated_member_active_probe', 'not_observed']), `${name}.evidence_source`);
    const observed = integer(raw.observed_members, `${name}.observed_members`);
    const requiredMembers = integer(raw.required_members, `${name}.required_members`);
    const verified = integer(raw.verified_lighthouses, `${name}.verified_lighthouses`);
    const required = integer(raw.required_lighthouses, `${name}.required_lighthouses`);
    const freshness = integer(raw.freshness_window_seconds, `${name}.freshness_window_seconds`, ACTIVE_PROBE_FRESHNESS_SECONDS);
    if (observed > requiredMembers || required !== activeLighthouses || freshness !== ACTIVE_PROBE_FRESHNESS_SECONDS) fail(`${name} policy is inconsistent`);
    let evidenceAt = null;
    if (checkStatus === 'pass') {
      if (source !== 'authenticated_member_active_probe' || requiredMembers < 1 || observed !== requiredMembers || required < 1 || required > MAX_ACTIVE_PROBE_TARGETS || verified !== required) fail(`${name} passing evidence is inconsistent`);
      evidenceAt = timestamp(raw.evidence_at, `${name}.evidence_at`);
      const evidenceAgeMS = Date.parse(generatedAt) - Date.parse(evidenceAt);
      if (evidenceAgeMS < 0 || evidenceAgeMS > freshness * 1000) fail(`${name}.evidence_at is outside its freshness window`);
    } else if (source !== 'not_observed' || observed !== 0 || verified !== 0 || raw.evidence_at !== null) {
      fail(`${name} unknown evidence is inconsistent`);
    }
    return Object.freeze({
      status: checkStatus,
      evidenceSource: source,
      observedMembers: observed,
      requiredMembers,
      verifiedLighthouses: verified,
      requiredLighthouses: required,
      freshnessWindowSeconds: freshness,
      evidenceAt,
      summary: text(raw.summary, `${name}.summary`, 512),
      action: text(raw.action, `${name}.action`, 512),
    });
  }

  function validateLighthouse(raw, index) {
    const name = `lighthouses[${index}]`;
    exactObject(raw, ['id', 'name', 'site', 'failure_domain', 'lifecycle_status', 'public_endpoint', 'endpoint_host_type', 'dns_resolution', 'resolved_address_count'], name);
    const hostType = oneOf(raw.endpoint_host_type, new Set(['dns', 'ipv4', 'ipv6']), `${name}.endpoint_host_type`);
    const resolution = oneOf(raw.dns_resolution, new Set(['resolved', 'unresolved', 'not_applicable']), `${name}.dns_resolution`);
    const count = integer(raw.resolved_address_count, `${name}.resolved_address_count`, MAX_RESOLVED_ADDRESSES);
    if (hostType === 'dns') {
      if ((resolution === 'resolved') !== (count > 0) || resolution === 'not_applicable') fail(`${name} DNS evidence is inconsistent`);
    } else if (resolution !== 'not_applicable' || count !== 0) {
      fail(`${name} IP-literal evidence is inconsistent`);
    }
    return Object.freeze({
      id: text(raw.id, `${name}.id`, 128),
      name: text(raw.name, `${name}.name`, 63),
		site: placementLabel(raw.site, `${name}.site`),
		failureDomain: placementLabel(raw.failure_domain, `${name}.failure_domain`),
      lifecycleStatus: oneOf(raw.lifecycle_status, new Set(['pending', 'active']), `${name}.lifecycle_status`),
      publicEndpoint: text(raw.public_endpoint, `${name}.public_endpoint`, 261),
      endpointHostType: hostType,
      dnsResolution: resolution,
      resolvedAddressCount: count,
    });
  }

	function validateSite(raw, index) {
		const name = `sites[${index}]`;
		exactObject(raw, ['name', 'configured_nodes', 'active_nodes', 'active_members', 'active_lighthouses', 'failure_domains'], name);
		const siteName = placementLabel(raw.name, `${name}.name`);
		const configuredNodes = integer(raw.configured_nodes, `${name}.configured_nodes`);
		const activeNodes = integer(raw.active_nodes, `${name}.active_nodes`, configuredNodes);
		const activeMembers = integer(raw.active_members, `${name}.active_members`, activeNodes);
		const activeLighthouses = integer(raw.active_lighthouses, `${name}.active_lighthouses`, activeNodes);
		if (configuredNodes < 1 || activeMembers + activeLighthouses !== activeNodes) fail(`${name} counts are inconsistent`);
		if (!Array.isArray(raw.failure_domains) || raw.failure_domains.length < 1 || raw.failure_domains.length > configuredNodes) fail(`${name}.failure_domains is invalid`);
		const failureDomains = raw.failure_domains.map((value, domainIndex) => placementLabel(value, `${name}.failure_domains[${domainIndex}]`));
		for (let domainIndex = 1; domainIndex < failureDomains.length; domainIndex += 1) if (failureDomains[domainIndex - 1] >= failureDomains[domainIndex]) fail(`${name}.failure_domains are not canonically ordered`);
		return Object.freeze({ name: siteName, configuredNodes, activeNodes, activeMembers, activeLighthouses, failureDomains: Object.freeze(failureDomains) });
	}

  function validate(raw) {
    exactObject(raw, ['schema', 'generated_at', 'overall', 'network', 'projection', 'checks', 'lighthouses', 'sites'], 'response');
    if (raw.schema !== SCHEMA) fail('schema is unsupported');
    const generatedAt = timestamp(raw.generated_at, 'generated_at');
    const overall = oneOf(raw.overall, OVERALL, 'overall');

    exactObject(raw.network, ['id', 'name', 'cidr', 'listen_port'], 'network');
    const network = Object.freeze({
      id: text(raw.network.id, 'network.id', 128),
      name: text(raw.network.name, 'network.name', 63),
      cidr: text(raw.network.cidr, 'network.cidr', 43),
      listenPort: integer(raw.network.listen_port, 'network.listen_port', 65535),
    });
    if (network.listenPort === 0) fail('network.listen_port is invalid');

    exactObject(raw.projection, ['complete', 'observed_lighthouses', 'included_lighthouses', 'lighthouse_limit'], 'projection');
    const projection = Object.freeze({
      complete: boolean(raw.projection.complete, 'projection.complete'),
      observedLighthouses: integer(raw.projection.observed_lighthouses, 'projection.observed_lighthouses'),
      includedLighthouses: integer(raw.projection.included_lighthouses, 'projection.included_lighthouses', LIGHTHOUSE_LIMIT),
      lighthouseLimit: integer(raw.projection.lighthouse_limit, 'projection.lighthouse_limit', LIGHTHOUSE_LIMIT),
    });
    if (projection.lighthouseLimit !== LIGHTHOUSE_LIMIT || projection.includedLighthouses > projection.observedLighthouses ||
      projection.complete !== (projection.includedLighthouses === projection.observedLighthouses)) fail('projection is inconsistent');

    if (!Array.isArray(raw.lighthouses) || raw.lighthouses.length !== projection.includedLighthouses) fail('lighthouses are inconsistent with projection');
    const lighthouses = raw.lighthouses.map(validateLighthouse);
    const identities = new Set();
    for (let index = 0; index < lighthouses.length; index += 1) {
      const lighthouse = lighthouses[index];
      if (identities.has(lighthouse.id)) fail('lighthouse IDs are not unique');
      identities.add(lighthouse.id);
      if (index > 0) {
        const previous = lighthouses[index - 1];
        if (previous.name > lighthouse.name || (previous.name === lighthouse.name && previous.id >= lighthouse.id)) fail('lighthouses are not canonically ordered');
      }
    }
		if (!Array.isArray(raw.sites)) fail('sites must be an array');
		const sites = raw.sites.map(validateSite);
		for (let index = 1; index < sites.length; index += 1) if (sites[index - 1].name >= sites[index].name) fail('sites are not canonically ordered');

    exactObject(raw.checks, ['managed_route_overlap', 'client_route_overlap', 'lighthouse_redundancy', 'topology_diversity', 'dns_resolution', 'member_dns_resolution', 'public_udp_reachability'], 'checks');
    const lighthouseRedundancy = validateRedundancyCheck(raw.checks.lighthouse_redundancy, projection.observedLighthouses);
		const topologyDiversity = validateTopologyCheck(raw.checks.topology_diversity, lighthouseRedundancy.activeLighthouses);
    const checks = Object.freeze({
      managedRouteOverlap: validateRouteCheck(raw.checks.managed_route_overlap),
      clientRouteOverlap: validateClientRouteCheck(raw.checks.client_route_overlap, generatedAt),
      lighthouseRedundancy,
		topologyDiversity,
      dnsResolution: validateDNSCheck(raw.checks.dns_resolution, projection.complete, projection.includedLighthouses),
      memberDNSResolution: validateMemberDNSCheck(raw.checks.member_dns_resolution, generatedAt),
      publicUDPReachability: validateUDPCheck(raw.checks.public_udp_reachability, lighthouseRedundancy.activeLighthouses, generatedAt),
    });
		if (sites.length !== topologyDiversity.configuredSites || sites.filter((site) => site.activeNodes > 0).length !== topologyDiversity.activeSites || sites.reduce((sum, site) => sum + site.activeNodes, 0) !== topologyDiversity.activeNodes || sites.reduce((sum, site) => sum + site.activeLighthouses, 0) !== topologyDiversity.activeLighthouses) fail('sites are inconsistent with topology check');
		if (projection.complete) {
			const active = lighthouses.filter((lighthouse) => lighthouse.lifecycleStatus === 'active');
			const assigned = active.filter((lighthouse) => lighthouse.site !== 'unassigned' && lighthouse.failureDomain !== 'unassigned');
			const domains = new Set(assigned.map((lighthouse) => lighthouse.failureDomain));
			if (active.length !== topologyDiversity.activeLighthouses || assigned.length !== topologyDiversity.assignedActiveLighthouses || domains.size !== topologyDiversity.distinctLighthouseFailureDomains) fail('lighthouses are inconsistent with topology check');
		}
    const dnsEndpointCount = lighthouses.filter((lighthouse) => lighthouse.endpointHostType === 'dns').length;
    if (checks.dnsResolution.dnsNames > dnsEndpointCount) fail('checks.dns_resolution exceeds projected DNS endpoints');
	if (checks.memberDNSResolution.dnsNames > checks.dnsResolution.dnsNames) fail('checks.member_dns_resolution exceeds configured DNS names');

    const statuses = [checks.managedRouteOverlap.status, checks.clientRouteOverlap.status, checks.lighthouseRedundancy.status, checks.topologyDiversity.status, checks.dnsResolution.status, checks.memberDNSResolution.status, checks.publicUDPReachability.status];
    const expectedOverall = statuses.includes('blocked') ? 'blocked' : statuses.some((value) => value === 'warning' || value === 'unknown') ? 'verification_required' : 'ready';
    if (overall !== expectedOverall) fail('overall is inconsistent with checks');

    return Object.freeze({ schema: SCHEMA, generatedAt, overall, network, projection, checks, lighthouses: Object.freeze(lighthouses), sites: Object.freeze(sites) });
  }

  function statusLabel(statusValue) {
    return ({ pass: 'Pass', warning: 'Needs attention', blocked: 'Blocked', unknown: 'Not observed' })[statusValue] || 'Unavailable';
  }

  function overallLabel(overallValue) {
    return ({ ready: 'Ready', verification_required: 'External verification required', blocked: 'Blocked' })[overallValue] || 'Unavailable';
  }

  return Object.freeze({ SCHEMA, validate, statusLabel, overallLabel });
}));
