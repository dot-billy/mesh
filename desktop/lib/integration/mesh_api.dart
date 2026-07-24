import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:mesh_desktop/core/auth/session_models.dart';
import 'package:mesh_desktop/core/connection/connection_profile.dart';
import 'package:mesh_desktop/core/transport/json_transport.dart';

final class MeshApi {
  MeshApi({
    required this.profile,
    required this.transport,
    Random? secureRandom,
  }) : _secureRandom = secureRandom ?? Random.secure();

  final ConnectionProfile profile;
  final JsonTransport transport;
  final Random _secureRandom;

  Future<AuthenticationMethods> authenticationMethods() async {
    final body = await _object(
      method: 'GET',
      path: '/api/v1/auth/methods',
      authenticated: false,
    );
    return AuthenticationMethods(
      oidc: _boolean(body, 'oidc'),
      legacyBrowserLogin: _boolean(body, 'legacy_browser_login'),
      breakGlass: _boolean(body, 'break_glass'),
    );
  }

  Future<SessionContext> currentSession() async {
    final body = await _object(method: 'GET', path: '/api/v1/session');
    return SessionContext.fromJson(body);
  }

  Future<SessionContext> loginWithLegacyToken(String token) async {
    _credential(token, 'administrator token');
    final body = await _object(
      method: 'POST',
      path: '/api/v1/session',
      body: <String, Object?>{'token': token},
      authenticated: false,
      sameOriginJson: true,
    );
    return SessionContext.fromJson(body);
  }

  Future<SessionContext> loginWithBreakGlassCode(String code) async {
    _credential(code, 'recovery code');
    final body = await _object(
      method: 'POST',
      path: '/api/v1/auth/break-glass',
      body: <String, Object?>{'code': code},
      authenticated: false,
      sameOriginJson: true,
    );
    return SessionContext.fromJson(body);
  }

  Future<void> logout() async {
    await _request(method: 'DELETE', path: '/api/v1/session');
  }

  Future<DesktopAuthorizationAttempt> startDesktopAuthorization() async {
    final body = await _object(
      method: 'POST',
      path: '/api/v1/auth/desktop/start',
      body: const <String, Object?>{},
      authenticated: false,
      sameOriginJson: true,
    );
    final requestId = _identifier(body, 'request_id', desktop: true);
    final pollSecret = _opaqueCredential(body, 'poll_secret');
    final verificationUrl = _absoluteUri(body, 'verification_url');
    if (verificationUrl.origin != profile.originString ||
        verificationUrl.path != '/' ||
        verificationUrl.fragment.isNotEmpty) {
      throw const MeshApiProtocolException(
        'Desktop verification URL did not use the selected control plane.',
      );
    }
    final expiresAt = _time(body, 'expires_at');
    final intervalSeconds = _integer(body, 'interval_seconds');
    if (intervalSeconds < 1 || intervalSeconds > 30) {
      throw const MeshApiProtocolException(
        'Desktop authorization polling interval is invalid.',
      );
    }
    return DesktopAuthorizationAttempt(
      requestId: requestId,
      pollSecret: pollSecret,
      verificationUrl: verificationUrl,
      expiresAt: expiresAt,
      pollInterval: Duration(seconds: intervalSeconds),
    );
  }

  Future<DesktopAuthorizationResult> completeDesktopAuthorization(
    DesktopAuthorizationAttempt attempt,
  ) async {
    if (attempt.isExpiredAt(DateTime.now().toUtc())) {
      return const DesktopAuthorizationResult(
        state: DesktopAuthorizationState.expired,
      );
    }
    final body = await _object(
      method: 'POST',
      path: '/api/v1/auth/desktop/complete',
      body: <String, Object?>{
        'request_id': attempt.requestId,
        'poll_secret': attempt.pollSecret,
      },
      authenticated: false,
      sameOriginJson: true,
    );
    final state = DesktopAuthorizationState.parse(_string(body, 'state'));
    final sessionValue = body['session'];
    if (state == DesktopAuthorizationState.authorized) {
      if (sessionValue == null) {
        throw const MeshApiProtocolException(
          'Authorized desktop response did not contain a session.',
        );
      }
      return DesktopAuthorizationResult(
        state: state,
        session: SessionContext.fromJson(sessionValue),
      );
    }
    if (sessionValue != null) {
      throw const MeshApiProtocolException(
        'Pending desktop response unexpectedly contained a session.',
      );
    }
    return DesktopAuthorizationResult(state: state);
  }

  Future<List<Map<String, Object?>>> networks() =>
      _list(method: 'GET', path: '/api/v1/networks');

  Future<Map<String, Object?>> fleetHealth() =>
      _object(method: 'GET', path: '/api/v1/fleet/health');

  Future<Map<String, Object?>?> runtimeTelemetry() async {
    final response = await _request(
      method: 'GET',
      path: '/api/v1/fleet/runtime-telemetry',
      acceptedStatuses: const <int>{200, 404},
    );
    if (response.statusCode == 404) {
      return null;
    }
    return _asObject(response.body, 'runtime telemetry');
  }

  Future<List<Map<String, Object?>>> nodes(String networkId) => _list(
    method: 'GET',
    path: '/api/v1/networks/${_resourceID(networkId)}/nodes',
  );

  Future<Map<String, Object?>> readiness(String networkId) => _object(
    method: 'GET',
    path: '/api/v1/networks/${_resourceID(networkId)}/readiness',
  );

  Future<Map<String, Object?>> firewall(String networkId) => _object(
    method: 'GET',
    path: '/api/v1/networks/${_resourceID(networkId)}/firewall',
  );

  Future<Map<String, Object?>> dns(String networkId) => _object(
    method: 'GET',
    path: '/api/v1/networks/${_resourceID(networkId)}/dns',
  );

  Future<Map<String, Object?>> relays(String networkId) => _object(
    method: 'GET',
    path: '/api/v1/networks/${_resourceID(networkId)}/relays',
  );

  Future<Map<String, Object?>> routePolicies(String networkId) => _object(
    method: 'GET',
    path: '/api/v1/networks/${_resourceID(networkId)}/route-policies',
  );

  Future<Map<String, Object?>> caRotation(String networkId) => _object(
    method: 'GET',
    path: '/api/v1/networks/${_resourceID(networkId)}/ca-rotation',
  );

  Future<List<Map<String, Object?>>> auditEvents() =>
      _list(method: 'GET', path: '/api/v1/audit');

  Future<List<Map<String, Object?>>> sessions() =>
      _list(method: 'GET', path: '/api/v1/sessions');

  Future<Map<String, Object?>> breakGlassInventory() =>
      _object(method: 'GET', path: '/api/v1/break-glass-codes');

  Future<MeshNetwork> createNetwork({
    required String name,
    required String cidr,
    int? listenPort,
    int? certificateTtlHours,
  }) async {
    _name(name, 'Network name');
    _canonicalIPv4CIDR(cidr, minimumPrefix: 16, maximumPrefix: 28);
    if (listenPort != null && (listenPort < 1 || listenPort > 65535)) {
      throw const MeshApiProtocolException('Listen port is invalid.');
    }
    if (certificateTtlHours != null &&
        (certificateTtlHours < 24 || certificateTtlHours > 8760)) {
      throw const MeshApiProtocolException('Certificate lifetime is invalid.');
    }
    final request = <String, Object?>{'name': name, 'cidr': cidr};
    if (listenPort != null) request['listen_port'] = listenPort;
    if (certificateTtlHours != null) {
      request['certificate_ttl_hours'] = certificateTtlHours;
    }
    final body = await _object(
      method: 'POST',
      path: '/api/v1/networks',
      body: request,
      acceptedStatuses: const <int>{201},
    );
    final network = MeshNetwork.fromJson(body);
    if (network.name != name || network.cidr != cidr) {
      throw const MeshApiProtocolException(
        'Created network did not match the request.',
      );
    }
    return network;
  }

  Future<NodeEnrollment> createNode({
    required String networkId,
    required String name,
    String role = 'member',
    String? ip,
    List<String> routedSubnets = const <String>[],
    String? site,
    String? failureDomain,
    List<String> groups = const <String>[],
    String? publicEndpoint,
  }) async {
    final canonicalNetworkId = _resourceID(networkId);
    _name(name, 'Node name');
    if (role != 'member' && role != 'lighthouse') {
      throw const MeshApiProtocolException('Node role is invalid.');
    }
    if (ip != null) _canonicalIPv4(ip, 'Node IP');
    final canonicalRoutes = _canonicalRoutedSubnets(routedSubnets);
    final canonicalGroups = _canonicalGroups(groups);
    if (site != null) _topologyLabel(site, 'Site');
    if (failureDomain != null) {
      _topologyLabel(failureDomain, 'Failure domain');
    }
    if (publicEndpoint != null) _publicEndpoint(publicEndpoint);
    if (role == 'lighthouse' && publicEndpoint == null) {
      throw const MeshApiProtocolException(
        'A lighthouse requires a public endpoint.',
      );
    }
    final request = <String, Object?>{'name': name, 'role': role};
    if (ip != null) request['ip'] = ip;
    if (canonicalRoutes.isNotEmpty) {
      request['routed_subnets'] = canonicalRoutes;
    }
    if (site != null) request['site'] = site;
    if (failureDomain != null) request['failure_domain'] = failureDomain;
    if (canonicalGroups.isNotEmpty) request['groups'] = canonicalGroups;
    if (publicEndpoint != null) request['public_endpoint'] = publicEndpoint;
    final body = await _object(
      method: 'POST',
      path: '/api/v1/networks/$canonicalNetworkId/nodes',
      body: request,
      acceptedStatuses: const <int>{201},
    );
    final enrollment = NodeEnrollment.fromJson(body);
    if (enrollment.node.networkId != canonicalNetworkId ||
        enrollment.node.name != name ||
        enrollment.node.role != role ||
        enrollment.node.status != 'pending') {
      throw const MeshApiProtocolException(
        'Created node did not match the request.',
      );
    }
    return enrollment;
  }

  Future<NodeEnrollment> reissuePendingEnrollment(String nodeId) async {
    final canonicalNodeId = _resourceID(nodeId);
    final body = await _object(
      method: 'POST',
      path: '/api/v1/nodes/$canonicalNodeId/enrollment/reissue',
      acceptedStatuses: const <int>{200},
    );
    final enrollment = NodeEnrollment.fromJson(body);
    if (enrollment.node.id != canonicalNodeId ||
        enrollment.node.status != 'pending') {
      throw const MeshApiProtocolException(
        'Reissued enrollment did not match the pending node.',
      );
    }
    return enrollment;
  }

  Future<NodeCertificateRotationReceipt> rotateNodeCertificate({
    required String nodeId,
    required int expectedConfigRevision,
    required String confirmationName,
    required String requestId,
  }) async {
    final canonicalNodeId = _resourceID(nodeId);
    _positiveRevision(expectedConfigRevision);
    _name(confirmationName, 'Confirmation name');
    _mutationRequestID(requestId);
    final body = await _object(
      method: 'POST',
      path: '/api/v1/nodes/$canonicalNodeId/certificate/rotate',
      body: <String, Object?>{
        'expected_config_revision': expectedConfigRevision,
        'confirmation_name': confirmationName,
        'request_id': requestId,
      },
      acceptedStatuses: const <int>{200},
    );
    return NodeCertificateRotationReceipt.fromJson(
      body,
      expectedNodeId: canonicalNodeId,
      expectedConfigRevision: expectedConfigRevision,
      expectedName: confirmationName,
      expectedRequestId: requestId,
    );
  }

  Future<NodeRevocationReceipt> revokeNode({
    required String nodeId,
    required int expectedConfigRevision,
    required String confirmationName,
    required String requestId,
  }) async {
    final canonicalNodeId = _resourceID(nodeId);
    _positiveRevision(expectedConfigRevision);
    _name(confirmationName, 'Confirmation name');
    _mutationRequestID(requestId);
    final body = await _object(
      method: 'POST',
      path: '/api/v1/nodes/$canonicalNodeId/revocation',
      body: <String, Object?>{
        'expected_config_revision': expectedConfigRevision,
        'confirmation_name': confirmationName,
        'request_id': requestId,
      },
      acceptedStatuses: const <int>{200},
    );
    return NodeRevocationReceipt.fromJson(
      body,
      expectedNodeId: canonicalNodeId,
      expectedConfigRevision: expectedConfigRevision,
      expectedName: confirmationName,
      expectedRequestId: requestId,
    );
  }

  Future<void> revokeSession(String sessionId) async {
    final response = await _request(
      method: 'DELETE',
      path: '/api/v1/sessions/${_resourceID(sessionId)}',
      acceptedStatuses: const <int>{204},
    );
    if (response.body != null) {
      throw const MeshApiProtocolException(
        'Session revocation unexpectedly returned a body.',
      );
    }
  }

  Future<RecoveryAccessRegistration> createRecoveryAccess({
    required DateTime expiresAt,
  }) async {
    final now = DateTime.now().toUtc();
    final expiry = expiresAt.toUtc();
    final lifetime = expiry.difference(now);
    if (lifetime < const Duration(minutes: 10) ||
        lifetime > const Duration(days: 90)) {
      throw const MeshApiProtocolException(
        'Recovery access expiry must be between 10 minutes and 90 days.',
      );
    }
    final id = 'bg_${_newOpaqueToken()}';
    final credential = 'mesh-bg-v1.$id.${_newOpaqueToken()}';
    final body = await _object(
      method: 'POST',
      path: '/api/v1/break-glass-codes',
      body: <String, Object?>{
        'code': credential,
        'expires_at': expiry.toIso8601String(),
      },
      acceptedStatuses: const <int>{200, 201},
    );
    final summary = RecoveryAccessSummary.fromJson(body);
    if (summary.id != id ||
        summary.state != RecoveryAccessState.usable ||
        !summary.expiresAt.isAtSameMomentAs(expiry)) {
      throw const MeshApiProtocolException(
        'Registered recovery access did not match the local credential.',
      );
    }
    return RecoveryAccessRegistration(credential: credential, summary: summary);
  }

  String _newOpaqueToken() {
    final bytes = List<int>.generate(32, (_) => _secureRandom.nextInt(256));
    return base64UrlEncode(bytes).replaceAll('=', '');
  }

  Future<JsonApiResponse> _request({
    required String method,
    required String path,
    Object? body,
    bool authenticated = true,
    bool sameOriginJson = false,
    Set<int>? acceptedStatuses,
  }) async {
    final response = await transport.send(
      method: method,
      path: path,
      body: body,
      hasBody: body != null,
      authenticated: authenticated,
      sameOriginJson: sameOriginJson,
    );
    final accepted =
        acceptedStatuses ??
        <int>{for (var status = 200; status < 300; status++) status};
    if (!accepted.contains(response.statusCode)) {
      throw MeshApiException(
        statusCode: response.statusCode,
        message: _errorMessage(response.body, response.statusCode),
      );
    }
    return response;
  }

  Future<Map<String, Object?>> _object({
    required String method,
    required String path,
    Object? body,
    bool authenticated = true,
    bool sameOriginJson = false,
    Set<int>? acceptedStatuses,
  }) async {
    final response = await _request(
      method: method,
      path: path,
      body: body,
      authenticated: authenticated,
      sameOriginJson: sameOriginJson,
      acceptedStatuses: acceptedStatuses,
    );
    return _asObject(response.body, path);
  }

  Future<List<Map<String, Object?>>> _list({
    required String method,
    required String path,
  }) async {
    final response = await _request(method: method, path: path);
    final body = response.body;
    if (body is! List<Object?>) {
      throw MeshApiProtocolException('$path did not return a JSON array.');
    }
    return List<Map<String, Object?>>.unmodifiable(
      body.map((value) => _asObject(value, '$path item')),
    );
  }
}

final class MeshNetwork {
  const MeshNetwork({
    required this.id,
    required this.name,
    required this.cidr,
    required this.listenPort,
    required this.certificateTtlHours,
    required this.configRevision,
    required this.configUpdatedAt,
    required this.createdAt,
  });

  factory MeshNetwork.fromJson(Map<String, Object?> body) {
    _exactObject(
      body,
      required: const <String>{
        'id',
        'name',
        'cidr',
        'dns_settings',
        'relay_settings',
        'ca_rotation',
        'firewall_rollout',
        'route_transfer',
        'route_profile_edit',
        'firewall_policy',
        'listen_port',
        'certificate_ttl_hours',
        'ca_certificate',
        'config_signing_public_key',
        'config_revision',
        'config_updated_at',
        'created_at',
      },
      optional: const <String>{'route_policies'},
      name: 'network',
    );
    for (final field in const <String>[
      'dns_settings',
      'relay_settings',
      'ca_rotation',
      'firewall_rollout',
      'route_transfer',
      'route_profile_edit',
      'firewall_policy',
    ]) {
      _asObject(body[field], 'network.$field');
    }
    if (body.containsKey('route_policies')) {
      _objectList(body['route_policies'], 'network.route_policies');
    }
    _string(body, 'ca_certificate');
    _string(body, 'config_signing_public_key');
    final listenPort = _integer(body, 'listen_port');
    final certificateTtlHours = _integer(body, 'certificate_ttl_hours');
    final configRevision = _integer(body, 'config_revision');
    if (listenPort < 1 ||
        listenPort > 65535 ||
        certificateTtlHours < 24 ||
        certificateTtlHours > 8760 ||
        configRevision < 1) {
      throw const MeshApiProtocolException(
        'Network lifecycle metadata is invalid.',
      );
    }
    final name = _string(body, 'name');
    final cidr = _string(body, 'cidr');
    _name(name, 'Network name');
    _canonicalIPv4CIDR(cidr, minimumPrefix: 16, maximumPrefix: 28);
    return MeshNetwork(
      id: _identifier(body, 'id'),
      name: name,
      cidr: cidr,
      listenPort: listenPort,
      certificateTtlHours: certificateTtlHours,
      configRevision: configRevision,
      configUpdatedAt: _time(body, 'config_updated_at'),
      createdAt: _time(body, 'created_at'),
    );
  }

  final String id;
  final String name;
  final String cidr;
  final int listenPort;
  final int certificateTtlHours;
  final int configRevision;
  final DateTime configUpdatedAt;
  final DateTime createdAt;
}

final class MeshNode {
  const MeshNode({
    required this.id,
    required this.networkId,
    required this.name,
    required this.ip,
    required this.routedSubnets,
    required this.groups,
    required this.role,
    required this.status,
    required this.certificateGeneration,
    required this.createdAt,
  });

  factory MeshNode.fromJson(Object? value) {
    final body = _asObject(value, 'node');
    _exactObject(
      body,
      required: const <String>{
        'id',
        'network_id',
        'name',
        'ip',
        'groups',
        'role',
        'status',
        'certificate_generation',
        'applied_config_revision',
        'applied_certificate_generation',
        'nebula_running',
        'heartbeat_sequence',
        'agent_credential_generation',
        'created_at',
      },
      optional: const <String>{
        'routed_subnets',
        'site',
        'failure_domain',
        'public_endpoint',
        'certificate',
        'certificate_fingerprint',
        'certificate_authority_sha256',
        'certificate_expires_at',
        'certificate_renew_after',
        'applied_config_sha256',
        'reported_certificate_fingerprint',
        'native_dns_active',
        'agent_version',
        'nebula_version',
        'agent_status',
        'agent_boot_id',
        'last_error',
        'last_seen_at',
        'agent_credential_expires_at',
        'agent_credential_last_used_at',
        'last_renewed_at',
        'enrolled_at',
        'revoked_at',
      },
      name: 'node',
    );
    final name = _string(body, 'name');
    final ip = _string(body, 'ip');
    final role = _string(body, 'role');
    final status = _string(body, 'status');
    _name(name, 'Node name');
    _canonicalIPv4(ip, 'Node IP');
    if ((role != 'member' && role != 'lighthouse') ||
        (status != 'pending' && status != 'active' && status != 'revoked')) {
      throw const MeshApiProtocolException('Node lifecycle is invalid.');
    }
    final groups = _requiredStringList(body, 'groups');
    if (groups.isEmpty ||
        groups.length > 64 ||
        !groups.contains('all') ||
        !_strictlySortedUnique(groups) ||
        groups.any((group) => !_groupPattern.hasMatch(group))) {
      throw const MeshApiProtocolException('Node groups are invalid.');
    }
    final routedSubnets = body.containsKey('routed_subnets')
        ? _requiredStringList(body, 'routed_subnets')
        : const <String>[];
    _validateCanonicalRoutedSubnetResponse(routedSubnets);
    for (final field in const <String>[
      'certificate_expires_at',
      'certificate_renew_after',
      'last_seen_at',
      'agent_credential_expires_at',
      'agent_credential_last_used_at',
      'last_renewed_at',
      'enrolled_at',
      'revoked_at',
    ]) {
      if (body.containsKey(field)) _time(body, field);
    }
    for (final field in const <String>[
      'site',
      'failure_domain',
      'public_endpoint',
      'certificate',
      'certificate_fingerprint',
      'certificate_authority_sha256',
      'applied_config_sha256',
      'reported_certificate_fingerprint',
      'agent_version',
      'nebula_version',
      'agent_status',
      'agent_boot_id',
      'last_error',
    ]) {
      if (body.containsKey(field)) _string(body, field);
    }
    if (body.containsKey('native_dns_active')) {
      _boolean(body, 'native_dns_active');
    }
    final certificateGeneration = _nonNegativeInteger(
      body,
      'certificate_generation',
    );
    for (final field in const <String>[
      'applied_config_revision',
      'applied_certificate_generation',
      'heartbeat_sequence',
      'agent_credential_generation',
    ]) {
      _nonNegativeInteger(body, field);
    }
    _boolean(body, 'nebula_running');
    return MeshNode(
      id: _identifier(body, 'id'),
      networkId: _identifier(body, 'network_id'),
      name: name,
      ip: ip,
      routedSubnets: routedSubnets,
      groups: groups,
      role: role,
      status: status,
      certificateGeneration: certificateGeneration,
      createdAt: _time(body, 'created_at'),
    );
  }

  final String id;
  final String networkId;
  final String name;
  final String ip;
  final List<String> routedSubnets;
  final List<String> groups;
  final String role;
  final String status;
  final int certificateGeneration;
  final DateTime createdAt;
}

final class NodeEnrollment {
  const NodeEnrollment({
    required this.node,
    required this.enrollmentToken,
    required this.expiresAt,
  });

  factory NodeEnrollment.fromJson(Map<String, Object?> body) {
    _exactObject(
      body,
      required: const <String>{'node', 'enrollment_token', 'expires_at'},
      name: 'node enrollment',
    );
    final node = MeshNode.fromJson(body['node']);
    final token = _opaqueCredential(body, 'enrollment_token');
    final expiresAt = _time(body, 'expires_at');
    if (!expiresAt.isAfter(node.createdAt)) {
      throw const MeshApiProtocolException('Enrollment expiry is invalid.');
    }
    return NodeEnrollment(
      node: node,
      enrollmentToken: token,
      expiresAt: expiresAt,
    );
  }

  final MeshNode node;
  final String enrollmentToken;
  final DateTime expiresAt;

  @override
  String toString() =>
      'NodeEnrollment(node: ${node.id}, token: [redacted], expiresAt: $expiresAt)';
}

final class NodeCertificateRotationReceipt {
  const NodeCertificateRotationReceipt({
    required this.requestId,
    required this.nodeId,
    required this.networkId,
    required this.name,
    required this.rotatedAt,
    required this.certificateGeneration,
    required this.configRevision,
  });

  factory NodeCertificateRotationReceipt.fromJson(
    Map<String, Object?> body, {
    required String expectedNodeId,
    required int expectedConfigRevision,
    required String expectedName,
    required String expectedRequestId,
  }) {
    _exactObject(
      body,
      required: const <String>{
        'request_id',
        'node_id',
        'network_id',
        'name',
        'ip',
        'role',
        'rotated_at',
        'previous_certificate_expires_at',
        'certificate_expires_at',
        'certificate_renew_after',
        'previous_certificate_generation',
        'certificate_generation',
        'agent_recovery_records_invalidated',
        'certificate_issuances_added',
        'blocklist_entries_added',
        'previous_certificate_blocklisted',
        'config_revision',
      },
      name: 'certificate rotation receipt',
    );
    final requestId = _string(body, 'request_id');
    final nodeId = _identifier(body, 'node_id');
    final networkId = _identifier(body, 'network_id');
    final name = _string(body, 'name');
    _name(name, 'Rotated node name');
    _canonicalIPv4(_string(body, 'ip'), 'Rotated node IP');
    _nodeRole(_string(body, 'role'));
    final rotatedAt = _time(body, 'rotated_at');
    final previousExpiresAt = _time(body, 'previous_certificate_expires_at');
    final expiresAt = _time(body, 'certificate_expires_at');
    final renewAfter = _time(body, 'certificate_renew_after');
    final previousGeneration = _positiveInteger(
      body,
      'previous_certificate_generation',
    );
    final generation = _positiveInteger(body, 'certificate_generation');
    final configRevision = _positiveInteger(body, 'config_revision');
    _nonNegativeInteger(body, 'agent_recovery_records_invalidated');
    final issuances = _nonNegativeInteger(body, 'certificate_issuances_added');
    final blocklist = _nonNegativeInteger(body, 'blocklist_entries_added');
    final blocklisted = _boolean(body, 'previous_certificate_blocklisted');
    if (requestId != expectedRequestId ||
        nodeId != expectedNodeId ||
        name != expectedName ||
        configRevision != expectedConfigRevision + 1 ||
        generation != previousGeneration + 1 ||
        issuances != 1 ||
        blocklist != 1 ||
        !blocklisted ||
        !previousExpiresAt.isAfter(rotatedAt) ||
        !renewAfter.isAfter(rotatedAt) ||
        !expiresAt.isAfter(renewAfter)) {
      throw const MeshApiProtocolException(
        'Certificate rotation receipt did not prove the requested transition.',
      );
    }
    return NodeCertificateRotationReceipt(
      requestId: requestId,
      nodeId: nodeId,
      networkId: networkId,
      name: name,
      rotatedAt: rotatedAt,
      certificateGeneration: generation,
      configRevision: configRevision,
    );
  }

  final String requestId;
  final String nodeId;
  final String networkId;
  final String name;
  final DateTime rotatedAt;
  final int certificateGeneration;
  final int configRevision;
}

final class NodeRevocationReceipt {
  const NodeRevocationReceipt({
    required this.requestId,
    required this.nodeId,
    required this.networkId,
    required this.name,
    required this.revokedAt,
    required this.wasEnrolled,
    required this.configRevision,
  });

  factory NodeRevocationReceipt.fromJson(
    Map<String, Object?> body, {
    required String expectedNodeId,
    required int expectedConfigRevision,
    required String expectedName,
    required String expectedRequestId,
  }) {
    _exactObject(
      body,
      required: const <String>{
        'request_id',
        'node_id',
        'network_id',
        'name',
        'ip',
        'role',
        'revoked_at',
        'was_enrolled',
        'enrollment_records_invalidated',
        'agent_recovery_records_invalidated',
        'blocklist_entries_added',
        'relay_assignment_removed',
        'firewall_canary_removed',
        'firewall_rollout_auto_rolled_back',
        'credentials_invalidated',
        'routed_subnet_reservations_released',
        'config_revision',
      },
      name: 'node revocation receipt',
    );
    final requestId = _string(body, 'request_id');
    final nodeId = _identifier(body, 'node_id');
    final networkId = _identifier(body, 'network_id');
    final name = _string(body, 'name');
    _name(name, 'Revoked node name');
    _canonicalIPv4(_string(body, 'ip'), 'Revoked node IP');
    _nodeRole(_string(body, 'role'));
    final wasEnrolled = _boolean(body, 'was_enrolled');
    _nonNegativeInteger(body, 'enrollment_records_invalidated');
    _nonNegativeInteger(body, 'agent_recovery_records_invalidated');
    final blocklist = _nonNegativeInteger(body, 'blocklist_entries_added');
    _boolean(body, 'relay_assignment_removed');
    final canaryRemoved = _boolean(body, 'firewall_canary_removed');
    final autoRolledBack = _boolean(body, 'firewall_rollout_auto_rolled_back');
    final credentialsInvalidated = _boolean(body, 'credentials_invalidated');
    final routesReleased = _nonNegativeInteger(
      body,
      'routed_subnet_reservations_released',
    );
    final configRevision = _positiveInteger(body, 'config_revision');
    if (requestId != expectedRequestId ||
        nodeId != expectedNodeId ||
        name != expectedName ||
        configRevision != expectedConfigRevision + 1 ||
        !credentialsInvalidated ||
        (wasEnrolled ? blocklist < 1 : blocklist != 0) ||
        (autoRolledBack && !canaryRemoved)) {
      throw const MeshApiProtocolException(
        'Node revocation receipt did not prove the requested trust cutoff.',
      );
    }
    // Reading every count and boolean is deliberate even when it is not
    // surfaced by the compact result. It prevents partial receipt acceptance.
    if (routesReleased > 8) {
      throw const MeshApiProtocolException(
        'Node revocation route evidence is inconsistent.',
      );
    }
    return NodeRevocationReceipt(
      requestId: requestId,
      nodeId: nodeId,
      networkId: networkId,
      name: name,
      revokedAt: _time(body, 'revoked_at'),
      wasEnrolled: wasEnrolled,
      configRevision: configRevision,
    );
  }

  final String requestId;
  final String nodeId;
  final String networkId;
  final String name;
  final DateTime revokedAt;
  final bool wasEnrolled;
  final int configRevision;
}

enum RecoveryAccessState {
  usable,
  used,
  revoked,
  expired;

  static RecoveryAccessState parse(String value) => switch (value) {
    'usable' => usable,
    'used' => used,
    'revoked' => revoked,
    'expired' => expired,
    _ => throw const MeshApiProtocolException(
      'Recovery access state is invalid.',
    ),
  };
}

final class RecoveryAccessSummary {
  const RecoveryAccessSummary({
    required this.id,
    required this.createdAt,
    required this.expiresAt,
    required this.state,
    this.usedAt,
    this.revokedAt,
  });

  factory RecoveryAccessSummary.fromJson(Map<String, Object?> body) {
    _exactObject(
      body,
      required: const <String>{'id', 'created_at', 'expires_at', 'state'},
      optional: const <String>{'used_at', 'revoked_at'},
      name: 'recovery access summary',
    );
    final id = _string(body, 'id');
    if (!_breakGlassIDPattern.hasMatch(id)) {
      throw const MeshApiProtocolException(
        'Recovery access identifier is invalid.',
      );
    }
    final createdAt = _time(body, 'created_at');
    final expiresAt = _time(body, 'expires_at');
    final usedAt = body.containsKey('used_at') ? _time(body, 'used_at') : null;
    final revokedAt = body.containsKey('revoked_at')
        ? _time(body, 'revoked_at')
        : null;
    final state = RecoveryAccessState.parse(_string(body, 'state'));
    if (!expiresAt.isAfter(createdAt) ||
        usedAt != null && revokedAt != null ||
        state == RecoveryAccessState.used && usedAt == null ||
        state == RecoveryAccessState.revoked && revokedAt == null ||
        state == RecoveryAccessState.usable &&
            (usedAt != null || revokedAt != null)) {
      throw const MeshApiProtocolException(
        'Recovery access lifecycle is invalid.',
      );
    }
    return RecoveryAccessSummary(
      id: id,
      createdAt: createdAt,
      expiresAt: expiresAt,
      state: state,
      usedAt: usedAt,
      revokedAt: revokedAt,
    );
  }

  final String id;
  final DateTime createdAt;
  final DateTime expiresAt;
  final RecoveryAccessState state;
  final DateTime? usedAt;
  final DateTime? revokedAt;
}

final class RecoveryAccessRegistration {
  const RecoveryAccessRegistration({
    required this.credential,
    required this.summary,
  });

  final String credential;
  final RecoveryAccessSummary summary;

  @override
  String toString() =>
      'RecoveryAccessRegistration(credential: [redacted], id: ${summary.id})';
}

final class AuthenticationMethods {
  const AuthenticationMethods({
    required this.oidc,
    required this.legacyBrowserLogin,
    required this.breakGlass,
  });

  final bool oidc;
  final bool legacyBrowserLogin;
  final bool breakGlass;
}

final class DesktopAuthorizationAttempt {
  DesktopAuthorizationAttempt({
    required this.requestId,
    required this.pollSecret,
    required this.verificationUrl,
    required this.expiresAt,
    required this.pollInterval,
  });

  final String requestId;
  final String pollSecret;
  final Uri verificationUrl;
  final DateTime expiresAt;
  final Duration pollInterval;

  bool isExpiredAt(DateTime now) => !now.toUtc().isBefore(expiresAt);

  @override
  String toString() =>
      'DesktopAuthorizationAttempt(request: [redacted], secret: [redacted], url: [redacted])';
}

enum DesktopAuthorizationState {
  pending,
  denied,
  expired,
  authorized;

  static DesktopAuthorizationState parse(String value) => switch (value) {
    'pending' => pending,
    'denied' => denied,
    'expired' => expired,
    'authorized' => authorized,
    _ => throw MeshApiProtocolException(
      'Unsupported desktop authorization state "$value".',
    ),
  };
}

final class DesktopAuthorizationResult {
  const DesktopAuthorizationResult({required this.state, this.session});

  final DesktopAuthorizationState state;
  final SessionContext? session;
}

final class MeshApiException implements Exception {
  const MeshApiException({required this.statusCode, required this.message});

  final int statusCode;
  final String message;

  @override
  String toString() => 'MeshApiException($statusCode): $message';
}

final class MeshApiProtocolException implements Exception {
  const MeshApiProtocolException(this.message);

  final String message;

  @override
  String toString() => 'MeshApiProtocolException: $message';
}

Map<String, Object?> _asObject(Object? value, String name) {
  if (value is! Map<String, Object?>) {
    throw MeshApiProtocolException('$name did not return a JSON object.');
  }
  return value;
}

String _string(Map<String, Object?> object, String field) {
  final value = object[field];
  if (value is! String || value.isEmpty) {
    throw MeshApiProtocolException('"$field" is missing or invalid.');
  }
  return value;
}

void _exactObject(
  Map<String, Object?> object, {
  required Set<String> required,
  Set<String> optional = const <String>{},
  required String name,
}) {
  for (final field in required) {
    if (!object.containsKey(field)) {
      throw MeshApiProtocolException('$name is missing "$field".');
    }
  }
  final allowed = <String>{...required, ...optional};
  for (final field in object.keys) {
    if (!allowed.contains(field)) {
      throw MeshApiProtocolException(
        '$name contains unsupported field "$field".',
      );
    }
  }
}

bool _boolean(Map<String, Object?> object, String field) {
  final value = object[field];
  if (value is! bool) {
    throw MeshApiProtocolException('"$field" is missing or invalid.');
  }
  return value;
}

int _integer(Map<String, Object?> object, String field) {
  final value = object[field];
  if (value is! int) {
    throw MeshApiProtocolException('"$field" is missing or invalid.');
  }
  return value;
}

int _nonNegativeInteger(Map<String, Object?> object, String field) {
  final value = _integer(object, field);
  if (value < 0) {
    throw MeshApiProtocolException('"$field" is invalid.');
  }
  return value;
}

int _positiveInteger(Map<String, Object?> object, String field) {
  final value = _integer(object, field);
  if (value < 1) {
    throw MeshApiProtocolException('"$field" is invalid.');
  }
  return value;
}

DateTime _time(Map<String, Object?> object, String field) {
  final value = _string(object, field);
  final parsed = DateTime.tryParse(value);
  if (parsed == null || !parsed.isUtc || !value.endsWith('Z')) {
    throw MeshApiProtocolException('"$field" is not a UTC timestamp.');
  }
  return parsed;
}

Uri _absoluteUri(Map<String, Object?> object, String field) {
  final value = _string(object, field);
  final parsed = Uri.tryParse(value);
  if (parsed == null ||
      !parsed.isAbsolute ||
      parsed.userInfo.isNotEmpty ||
      parsed.hasFragment) {
    throw MeshApiProtocolException('"$field" is not a safe absolute URL.');
  }
  return parsed;
}

String _identifier(
  Map<String, Object?> object,
  String field, {
  bool desktop = false,
}) {
  final value = _string(object, field);
  final pattern = desktop
      ? RegExp(r'^desktop_[A-Za-z0-9_-]{43}$')
      : RegExp(r'^[A-Za-z0-9_-]{1,128}$');
  if (!pattern.hasMatch(value)) {
    throw MeshApiProtocolException('"$field" is not a valid identifier.');
  }
  return value;
}

String _opaqueCredential(Map<String, Object?> object, String field) {
  final value = _string(object, field);
  if (!_validOpaqueValue(value)) {
    throw MeshApiProtocolException('"$field" is not a valid opaque value.');
  }
  return value;
}

bool _validOpaqueValue(String value) {
  if (!RegExp(r'^[A-Za-z0-9_-]{43}$').hasMatch(value)) return false;
  try {
    final decoded = base64Url.decode('$value=');
    return decoded.length == 32 &&
        base64UrlEncode(decoded).replaceAll('=', '') == value;
  } on FormatException {
    return false;
  }
}

String _resourceID(String value) {
  if (!RegExp(r'^[A-Za-z0-9_-]{1,128}$').hasMatch(value)) {
    throw const MeshApiProtocolException('Resource ID is invalid.');
  }
  return value;
}

List<Map<String, Object?>> _objectList(Object? value, String name) {
  if (value is! List<Object?>) {
    throw MeshApiProtocolException('$name is not a JSON array.');
  }
  return List<Map<String, Object?>>.unmodifiable(
    value.map((item) => _asObject(item, '$name item')),
  );
}

List<String> _requiredStringList(Map<String, Object?> object, String field) {
  final value = object[field];
  if (value is! List<Object?> ||
      value.any((item) => item is! String || item.isEmpty)) {
    throw MeshApiProtocolException('"$field" is missing or invalid.');
  }
  return List<String>.unmodifiable(value.cast<String>());
}

void _name(String value, String label) {
  if (!_namePattern.hasMatch(value)) {
    throw MeshApiProtocolException('$label is invalid.');
  }
}

void _nodeRole(String value) {
  if (value != 'member' && value != 'lighthouse') {
    throw const MeshApiProtocolException('Node role is invalid.');
  }
}

void _positiveRevision(int value) {
  if (value < 1) {
    throw const MeshApiProtocolException(
      'Expected configuration revision is invalid.',
    );
  }
}

void _mutationRequestID(String value) {
  if (value.length < 16 ||
      value.length > 128 ||
      !_resourcePattern.hasMatch(value)) {
    throw const MeshApiProtocolException('Mutation request ID is invalid.');
  }
}

void _topologyLabel(String value, String label) {
  if (!_topologyLabelPattern.hasMatch(value)) {
    throw MeshApiProtocolException('$label is invalid.');
  }
}

List<String> _canonicalGroups(List<String> groups) {
  if (groups.length > 64 ||
      groups.any((group) => !_groupPattern.hasMatch(group))) {
    throw const MeshApiProtocolException('Node groups are invalid.');
  }
  final canonical = groups.toSet().toList()..sort();
  if (canonical.length != groups.length) {
    throw const MeshApiProtocolException('Node groups contain duplicates.');
  }
  return List<String>.unmodifiable(canonical);
}

List<String> _canonicalRoutedSubnets(List<String> values) {
  if (values.length > 8) {
    throw const MeshApiProtocolException('Too many routed subnets.');
  }
  final parsed = <({String value, int address, int prefix})>[];
  for (final value in values) {
    final prefix = _canonicalIPv4CIDR(
      value,
      minimumPrefix: 1,
      maximumPrefix: 32,
    );
    parsed.add((value: value, address: prefix.address, prefix: prefix.prefix));
  }
  parsed.sort((left, right) {
    final address = left.address.compareTo(right.address);
    return address != 0 ? address : left.prefix.compareTo(right.prefix);
  });
  for (var index = 1; index < parsed.length; index++) {
    final previous = parsed[index - 1];
    final current = parsed[index];
    final previousSize = 1 << (32 - previous.prefix);
    if (current.address < previous.address + previousSize) {
      throw const MeshApiProtocolException(
        'Routed subnets overlap or are duplicated.',
      );
    }
  }
  return List<String>.unmodifiable(parsed.map((entry) => entry.value));
}

void _validateCanonicalRoutedSubnetResponse(List<String> values) {
  final canonical = _canonicalRoutedSubnets(values);
  for (var index = 0; index < values.length; index++) {
    if (values[index] != canonical[index]) {
      throw const MeshApiProtocolException(
        'Node routed subnets are not canonical.',
      );
    }
  }
}

({int address, int prefix}) _canonicalIPv4CIDR(
  String value, {
  required int minimumPrefix,
  required int maximumPrefix,
}) {
  final parts = value.split('/');
  if (parts.length != 2) {
    throw const MeshApiProtocolException('IPv4 CIDR is invalid.');
  }
  final address = _canonicalIPv4(parts[0], 'IPv4 CIDR');
  final prefix = int.tryParse(parts[1]);
  if (prefix == null ||
      prefix < minimumPrefix ||
      prefix > maximumPrefix ||
      prefix.toString() != parts[1]) {
    throw const MeshApiProtocolException('IPv4 CIDR prefix is invalid.');
  }
  final mask = prefix == 0 ? 0 : (0xffffffff << (32 - prefix)) & 0xffffffff;
  if ((address & mask) != address) {
    throw const MeshApiProtocolException('IPv4 CIDR is not canonical.');
  }
  return (address: address, prefix: prefix);
}

int _canonicalIPv4(String value, String label) {
  final parts = value.split('.');
  if (parts.length != 4) {
    throw MeshApiProtocolException('$label is invalid.');
  }
  var result = 0;
  for (final part in parts) {
    final octet = int.tryParse(part);
    if (octet == null || octet < 0 || octet > 255 || octet.toString() != part) {
      throw MeshApiProtocolException('$label is invalid.');
    }
    result = (result << 8) | octet;
  }
  return result;
}

void _publicEndpoint(String value) {
  if (value.isEmpty ||
      value.length > 261 ||
      value.trim() != value ||
      value.contains(RegExp(r'[\x00-\x20]'))) {
    throw const MeshApiProtocolException('Public endpoint is invalid.');
  }
  String portText;
  if (value.startsWith('[')) {
    final closing = value.lastIndexOf(']:');
    if (closing < 2) {
      throw const MeshApiProtocolException('Public endpoint is invalid.');
    }
    portText = value.substring(closing + 2);
  } else {
    final separator = value.lastIndexOf(':');
    if (separator < 1 || value.substring(0, separator).contains(':')) {
      throw const MeshApiProtocolException('Public endpoint is invalid.');
    }
    portText = value.substring(separator + 1);
  }
  final port = int.tryParse(portText);
  if (port == null || port < 1 || port > 65535 || port.toString() != portText) {
    throw const MeshApiProtocolException('Public endpoint port is invalid.');
  }
}

bool _strictlySortedUnique(List<String> values) {
  for (var index = 1; index < values.length; index++) {
    if (values[index - 1].compareTo(values[index]) >= 0) return false;
  }
  return true;
}

void _credential(String value, String name) {
  if (value.isEmpty || value.length > 4096 || value.trim() != value) {
    throw MeshApiProtocolException('$name is invalid.');
  }
}

String _errorMessage(Object? body, int statusCode) {
  if (body is Map<String, Object?>) {
    final value = body['error'];
    if (value is String && value.isNotEmpty && value.length <= 512) {
      return value;
    }
  }
  return 'Mesh returned HTTP $statusCode.';
}

final RegExp _namePattern = RegExp(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$');
final RegExp _groupPattern = RegExp(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$');
final RegExp _topologyLabelPattern = RegExp(r'^[a-z0-9][a-z0-9._-]{0,62}$');
final RegExp _resourcePattern = RegExp(r'^[A-Za-z0-9_-]{1,128}$');
final RegExp _breakGlassIDPattern = RegExp(r'^bg_[A-Za-z0-9_-]{43}$');
