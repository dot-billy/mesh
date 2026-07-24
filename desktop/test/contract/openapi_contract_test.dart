import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  late Map<String, Object?> openApi;

  setUpAll(() {
    final file = _repositoryFile('docs/openapi.json');
    final decoded = jsonDecode(file.readAsStringSync());
    openApi = _object(decoded, 'OpenAPI document');
  });

  test('desktop route inventory and OpenAPI operations stay synchronized', () {
    final source = _repositoryFile(
      'desktop/lib/integration/mesh_api.dart',
    ).readAsStringSync();
    final usedOperations = <String>{
      for (final match in RegExp(
        r"method:\s*'([A-Z]+)',\s*path:\s*'([^']+)'",
        multiLine: true,
      ).allMatches(source))
        '${match.group(1)!} ${_normalizeSourcePath(match.group(2)!)}',
    };
    final contractedOperations = <String>{
      for (final contract in _operations) '${contract.method} ${contract.path}',
    };

    expect(
      usedOperations,
      contractedOperations,
      reason:
          'Update the desktop/OpenAPI contract whenever MeshApi adds, removes, or changes a route.',
    );

    for (final contract in _operations) {
      final operation = _operation(openApi, contract);
      _expectSecurity(operation, authenticated: contract.authenticated);
      if (contract.requestSchema case final requestSchema?) {
        expect(
          _requestSchemaReference(operation),
          '#/components/schemas/$requestSchema',
          reason: '${contract.method} ${contract.path} request body drifted',
        );
      }
      _expectResponse(operation, contract);
    }

    final completion = _operation(
      openApi,
      const _OperationContract(
        method: 'POST',
        path: '/api/v1/auth/desktop/complete',
        status: '200',
        response: _ObjectResponse('DesktopAuthorizationCompletionResponse'),
      ),
    );
    final responses = _object(completion['responses'], 'desktop responses');
    final rateLimited = _object(responses['429'], 'desktop 429 response');
    final headers = _object(rateLimited['headers'], 'desktop 429 headers');
    final retryAfter = _object(headers['Retry-After'], 'Retry-After');
    expect(retryAfter['required'], isTrue);
    final retrySchema = _object(retryAfter['schema'], 'Retry-After schema');
    expect(retrySchema['type'], 'integer');
    expect(retrySchema['minimum'], 1);
    expect(retrySchema['maximum'], 3600);

    final telemetry = _operation(
      openApi,
      const _OperationContract(
        method: 'GET',
        path: '/api/v1/fleet/runtime-telemetry',
        status: '200',
        response: _ObjectResponse('FleetProjection'),
      ),
    );
    expect(
      _object(telemetry['responses'], 'runtime telemetry responses'),
      contains('404'),
      reason: 'The desktop treats unavailable runtime telemetry as optional.',
    );
  });

  test('response fields consumed by the desktop remain typed and available', () {
    for (final contract in _schemas) {
      final schema = _schema(openApi, contract.name);
      expect(
        schema['type'],
        'object',
        reason: '${contract.name} must remain an object',
      );
      if (_closedResponseSchemas.contains(contract.name)) {
        expect(
          schema['additionalProperties'],
          isFalse,
          reason:
              '${contract.name} is parsed as an exact closed object by the desktop',
        );
      }
      final required = _stringSet(schema['required']);
      final properties = _object(schema['properties'], contract.name);
      for (final entry in contract.properties.entries) {
        final field = entry.key;
        final expected = entry.value;
        expect(
          properties,
          contains(field),
          reason: '${contract.name}.$field is consumed by the desktop',
        );
        if (expected.required) {
          expect(
            required,
            contains(field),
            reason: '${contract.name}.$field must remain required',
          );
        }
        _expectProperty(
          _object(properties[field], '${contract.name}.$field'),
          expected,
          '${contract.name}.$field',
        );
      }
    }
  });

  test('the desktop authorization start body remains exactly empty', () {
    final schema = _schema(openApi, 'DesktopAuthorizationStartRequest');
    expect(schema['type'], 'object');
    expect(schema['additionalProperties'], isFalse);
    expect(_object(schema['properties'], 'desktop start properties'), isEmpty);
  });
}

File _repositoryFile(String path) {
  var directory = Directory.current.absolute;
  while (true) {
    final candidate = File('${directory.path}/$path');
    if (candidate.existsSync()) {
      return candidate;
    }
    final parent = directory.parent;
    if (parent.path == directory.path) {
      throw StateError('Unable to locate repository file $path.');
    }
    directory = parent;
  }
}

String _normalizeSourcePath(String path) => path
    .replaceAll(r'${_resourceID(networkId)}', '{networkID}')
    .replaceAll(r'${_resourceID(sessionId)}', '{sessionID}')
    .replaceAll(r'$canonicalNetworkId', '{networkID}')
    .replaceAll(r'$canonicalNodeId', '{nodeID}');

Map<String, Object?> _operation(
  Map<String, Object?> document,
  _OperationContract contract,
) {
  final paths = _object(document['paths'], 'OpenAPI paths');
  final path = _object(paths[contract.path], contract.path);
  return _object(path[contract.method.toLowerCase()], contract.method);
}

String? _requestSchemaReference(Map<String, Object?> operation) {
  final requestBody = _object(operation['requestBody'], 'requestBody');
  final content = _object(requestBody['content'], 'requestBody.content');
  final json = _object(content['application/json'], 'application/json');
  return _object(json['schema'], 'request schema')['\$ref'] as String?;
}

void _expectResponse(
  Map<String, Object?> operation,
  _OperationContract contract,
) {
  final responses = _object(operation['responses'], 'responses');
  expect(
    responses,
    contains(contract.status),
    reason: '${contract.method} ${contract.path} status drifted',
  );
  final response = _object(
    responses[contract.status],
    '${contract.method} ${contract.path} response',
  );
  final shape = contract.response;
  if (shape == null) {
    expect(
      response.containsKey('content'),
      isFalse,
      reason: '${contract.method} ${contract.path} must remain bodyless',
    );
    return;
  }
  final content = _object(response['content'], 'response content');
  final json = _object(content['application/json'], 'application/json');
  final schema = _object(json['schema'], 'response schema');
  switch (shape) {
    case _ObjectResponse(:final schemaName):
      expect(schema['\$ref'], '#/components/schemas/$schemaName');
    case _ArrayResponse(:final itemSchemaName):
      expect(schema['type'], 'array');
      expect(
        _object(schema['items'], 'array items')['\$ref'],
        '#/components/schemas/$itemSchemaName',
      );
  }
}

void _expectSecurity(
  Map<String, Object?> operation, {
  required bool authenticated,
}) {
  final security = operation['security'];
  if (!authenticated) {
    expect(security, isA<List<Object?>>());
    expect(security, isEmpty);
    return;
  }
  expect(security, isA<List<Object?>>());
  final schemes = <String>{};
  for (final requirement in (security! as List<Object?>)) {
    schemes.addAll(_object(requirement, 'security requirement').keys);
  }
  expect(schemes, <String>{'cookieSession', 'legacyAdminBearer'});
}

Map<String, Object?> _schema(Map<String, Object?> document, String name) {
  final components = _object(document['components'], 'components');
  final schemas = _object(components['schemas'], 'components.schemas');
  return _object(schemas[name], name);
}

void _expectProperty(
  Map<String, Object?> actual,
  _PropertyContract expected,
  String name,
) {
  if (expected.ref case final reference?) {
    expect(actual['\$ref'], '#/components/schemas/$reference', reason: name);
    return;
  }
  expect(actual['type'], expected.type, reason: name);
  if (expected.itemRef case final itemReference?) {
    expect(
      _object(actual['items'], '$name items')['\$ref'],
      '#/components/schemas/$itemReference',
      reason: name,
    );
  }
  if (expected.itemType case final itemType?) {
    expect(
      _object(actual['items'], '$name items')['type'],
      itemType,
      reason: name,
    );
  }
}

Map<String, Object?> _object(Object? value, String name) {
  if (value is! Map<String, Object?>) {
    throw FormatException('$name must be an object.');
  }
  return value;
}

Set<String> _stringSet(Object? value) {
  if (value == null) {
    return const <String>{};
  }
  if (value is! List<Object?> || value.any((item) => item is! String)) {
    throw const FormatException('Required fields must be a string array.');
  }
  return value.cast<String>().toSet();
}

sealed class _ResponseShape {
  const _ResponseShape();
}

final class _ObjectResponse extends _ResponseShape {
  const _ObjectResponse(this.schemaName);

  final String schemaName;
}

final class _ArrayResponse extends _ResponseShape {
  const _ArrayResponse(this.itemSchemaName);

  final String itemSchemaName;
}

final class _OperationContract {
  const _OperationContract({
    required this.method,
    required this.path,
    required this.status,
    required this.response,
    this.authenticated = true,
    this.requestSchema,
  });

  final String method;
  final String path;
  final String status;
  final _ResponseShape? response;
  final bool authenticated;
  final String? requestSchema;
}

final class _SchemaContract {
  const _SchemaContract(this.name, this.properties);

  final String name;
  final Map<String, _PropertyContract> properties;
}

final class _PropertyContract {
  const _PropertyContract.type(this.type, {this.required = true, this.itemType})
    : ref = null,
      itemRef = null;

  const _PropertyContract.ref(this.ref, {this.required = true})
    : type = null,
      itemRef = null,
      itemType = null;

  const _PropertyContract.arrayRef(this.itemRef, {this.required = true})
    : type = 'array',
      ref = null,
      itemType = null;

  final String? type;
  final String? ref;
  final String? itemRef;
  final String? itemType;
  final bool required;
}

const _boolean = _PropertyContract.type('boolean');
const _integer = _PropertyContract.type('integer');
const _string = _PropertyContract.type('string');
const _optionalInteger = _PropertyContract.type('integer', required: false);
const _optionalString = _PropertyContract.type('string', required: false);
const _stringArray = _PropertyContract.type('array', itemType: 'string');
const _optionalStringArray = _PropertyContract.type(
  'array',
  itemType: 'string',
  required: false,
);

const Set<String> _closedResponseSchemas = <String>{
  'SessionResponse',
  'Principal',
  'Network',
  'Node',
  'CreatedNode',
  'ReissuedEnrollment',
  'RotatedNodeCertificate',
  'RevokedNodeReceipt',
  'BreakGlassCodeSummary',
};

const List<_OperationContract> _operations = <_OperationContract>[
  _OperationContract(
    method: 'GET',
    path: '/api/v1/auth/methods',
    status: '200',
    response: _ObjectResponse('AuthMethodsResponse'),
    authenticated: false,
  ),
  _OperationContract(
    method: 'GET',
    path: '/api/v1/session',
    status: '200',
    response: _ObjectResponse('SessionResponse'),
  ),
  _OperationContract(
    method: 'POST',
    path: '/api/v1/session',
    status: '200',
    response: _ObjectResponse('SessionResponse'),
    authenticated: false,
    requestSchema: 'LegacyLoginRequest',
  ),
  _OperationContract(
    method: 'POST',
    path: '/api/v1/auth/break-glass',
    status: '200',
    response: _ObjectResponse('SessionResponse'),
    authenticated: false,
    requestSchema: 'BreakGlassLoginRequest',
  ),
  _OperationContract(
    method: 'DELETE',
    path: '/api/v1/session',
    status: '204',
    response: null,
  ),
  _OperationContract(
    method: 'POST',
    path: '/api/v1/auth/desktop/start',
    status: '201',
    response: _ObjectResponse('DesktopAuthorizationStartResponse'),
    authenticated: false,
    requestSchema: 'DesktopAuthorizationStartRequest',
  ),
  _OperationContract(
    method: 'POST',
    path: '/api/v1/auth/desktop/complete',
    status: '200',
    response: _ObjectResponse('DesktopAuthorizationCompletionResponse'),
    authenticated: false,
    requestSchema: 'DesktopAuthorizationCompleteRequest',
  ),
  _OperationContract(
    method: 'GET',
    path: '/api/v1/networks',
    status: '200',
    response: _ArrayResponse('NetworkSummary'),
  ),
  _OperationContract(
    method: 'GET',
    path: '/api/v1/fleet/health',
    status: '200',
    response: _ObjectResponse('FleetHealthCollection'),
  ),
  _OperationContract(
    method: 'GET',
    path: '/api/v1/fleet/runtime-telemetry',
    status: '200',
    response: _ObjectResponse('FleetProjection'),
  ),
  _OperationContract(
    method: 'GET',
    path: '/api/v1/networks/{networkID}/nodes',
    status: '200',
    response: _ArrayResponse('Node'),
  ),
  _OperationContract(
    method: 'GET',
    path: '/api/v1/networks/{networkID}/readiness',
    status: '200',
    response: _ObjectResponse('NetworkReadinessReport'),
  ),
  _OperationContract(
    method: 'GET',
    path: '/api/v1/networks/{networkID}/firewall',
    status: '200',
    response: _ObjectResponse('FirewallPolicyDocument'),
  ),
  _OperationContract(
    method: 'GET',
    path: '/api/v1/networks/{networkID}/dns',
    status: '200',
    response: _ObjectResponse('NetworkDNSDocument'),
  ),
  _OperationContract(
    method: 'GET',
    path: '/api/v1/networks/{networkID}/relays',
    status: '200',
    response: _ObjectResponse('NetworkRelaysDocument'),
  ),
  _OperationContract(
    method: 'GET',
    path: '/api/v1/networks/{networkID}/route-policies',
    status: '200',
    response: _ObjectResponse('NetworkRoutePoliciesDocument'),
  ),
  _OperationContract(
    method: 'GET',
    path: '/api/v1/networks/{networkID}/ca-rotation',
    status: '200',
    response: _ObjectResponse('NetworkCARotationDocument'),
  ),
  _OperationContract(
    method: 'GET',
    path: '/api/v1/audit',
    status: '200',
    response: _ArrayResponse('AuditResponseEvent'),
  ),
  _OperationContract(
    method: 'GET',
    path: '/api/v1/sessions',
    status: '200',
    response: _ArrayResponse('SessionSummary'),
  ),
  _OperationContract(
    method: 'GET',
    path: '/api/v1/break-glass-codes',
    status: '200',
    response: _ObjectResponse('BreakGlassInventoryResponse'),
  ),
  _OperationContract(
    method: 'DELETE',
    path: '/api/v1/sessions/{sessionID}',
    status: '204',
    response: null,
  ),
  _OperationContract(
    method: 'POST',
    path: '/api/v1/networks',
    status: '201',
    response: _ObjectResponse('Network'),
    requestSchema: 'CreateNetworkRequest',
  ),
  _OperationContract(
    method: 'POST',
    path: '/api/v1/networks/{networkID}/nodes',
    status: '201',
    response: _ObjectResponse('CreatedNode'),
    requestSchema: 'CreateNodeInput',
  ),
  _OperationContract(
    method: 'POST',
    path: '/api/v1/nodes/{nodeID}/enrollment/reissue',
    status: '200',
    response: _ObjectResponse('ReissuedEnrollment'),
  ),
  _OperationContract(
    method: 'POST',
    path: '/api/v1/nodes/{nodeID}/certificate/rotate',
    status: '200',
    response: _ObjectResponse('RotatedNodeCertificate'),
    requestSchema: 'RotateNodeCertificateInput',
  ),
  _OperationContract(
    method: 'POST',
    path: '/api/v1/nodes/{nodeID}/revocation',
    status: '200',
    response: _ObjectResponse('RevokedNodeReceipt'),
    requestSchema: 'RevokeNodeInput',
  ),
  _OperationContract(
    method: 'POST',
    path: '/api/v1/break-glass-codes',
    status: '201',
    response: _ObjectResponse('BreakGlassCodeSummary'),
    requestSchema: 'BreakGlassCodeRegistrationRequest',
  ),
];

const List<_SchemaContract> _schemas = <_SchemaContract>[
  _SchemaContract('AuthMethodsResponse', <String, _PropertyContract>{
    'oidc': _boolean,
    'legacy_browser_login': _boolean,
    'break_glass': _boolean,
  }),
  _SchemaContract('LegacyLoginRequest', <String, _PropertyContract>{
    'token': _string,
  }),
  _SchemaContract('BreakGlassLoginRequest', <String, _PropertyContract>{
    'code': _string,
  }),
  _SchemaContract(
    'DesktopAuthorizationStartRequest',
    <String, _PropertyContract>{},
  ),
  _SchemaContract(
    'DesktopAuthorizationCompleteRequest',
    <String, _PropertyContract>{'request_id': _string, 'poll_secret': _string},
  ),
  _SchemaContract(
    'DesktopAuthorizationStartResponse',
    <String, _PropertyContract>{
      'request_id': _string,
      'poll_secret': _string,
      'verification_url': _string,
      'expires_at': _string,
      'interval_seconds': _integer,
    },
  ),
  _SchemaContract(
    'DesktopAuthorizationCompletionResponse',
    <String, _PropertyContract>{
      'state': _string,
      'expires_at': _string,
      'interval_seconds': _integer,
      'session': _PropertyContract.ref('SessionResponse', required: false),
    },
  ),
  _SchemaContract('SessionResponse', <String, _PropertyContract>{
    'authenticated': _boolean,
    'principal': _PropertyContract.ref('Principal'),
    'auth_method': _string,
    'role': _string,
    'permissions': _stringArray,
    'session_id': _optionalString,
    'created_at': _optionalString,
    'last_seen_at': _optionalString,
    'idle_expires_at': _optionalString,
    'absolute_expires_at': _optionalString,
  }),
  _SchemaContract('Principal', <String, _PropertyContract>{
    'id': _string,
    'kind': _string,
    'auth_time': _string,
    'issuer': _optionalString,
    'subject': _optionalString,
    'display_name': _optionalString,
    'email': _optionalString,
    'groups': _optionalStringArray,
    'acr': _optionalString,
    'amr': _optionalStringArray,
  }),
  _SchemaContract('NetworkSummary', <String, _PropertyContract>{
    'id': _string,
    'name': _string,
    'cidr': _string,
    'node_count': _integer,
    'active_nodes': _integer,
    'config_revision': _integer,
    'config_updated_at': _string,
  }),
  _SchemaContract('FleetHealthCollection', <String, _PropertyContract>{
    'generated_at': _string,
    'summary': _PropertyContract.ref('FleetHealthCollectionSummary'),
    'rollout': _PropertyContract.ref('FleetRolloutSummary'),
    'networks': _PropertyContract.arrayRef('FleetNetworkHealthReport'),
  }),
  _SchemaContract('FleetHealthCollectionSummary', <String, _PropertyContract>{
    'overall': _string,
    'total_networks': _integer,
    'active_nodes': _integer,
    'total_nodes': _integer,
    'warning_nodes': _integer,
    'critical_nodes': _integer,
    'revoked_nodes': _integer,
  }),
  _SchemaContract('FleetRolloutSummary', <String, _PropertyContract>{
    'percent': _integer,
    'converged_nodes': _integer,
    'eligible_nodes': _integer,
  }),
  _SchemaContract('FleetNetworkHealthReport', <String, _PropertyContract>{
    'network': _PropertyContract.ref('FleetHealthNetwork'),
    'summary': _PropertyContract.ref('FleetHealthSummary'),
    'alerts': _PropertyContract.arrayRef('FleetHealthAlert'),
    'nodes': _PropertyContract.arrayRef('FleetNodeHealth'),
  }),
  _SchemaContract('FleetHealthNetwork', <String, _PropertyContract>{
    'id': _string,
  }),
  _SchemaContract('FleetHealthSummary', <String, _PropertyContract>{
    'overall': _string,
  }),
  _SchemaContract('FleetNodeHealth', <String, _PropertyContract>{
    'id': _string,
    'name': _string,
    'desired_config_revision': _integer,
    'severity': _string,
  }),
  _SchemaContract('FleetHealthAlert', <String, _PropertyContract>{
    'code': _string,
    'severity': _string,
    'node_id': _optionalString,
    'evidence': _PropertyContract.ref('FleetHealthEvidence'),
  }),
  _SchemaContract('FleetHealthEvidence', <String, _PropertyContract>{
    'reported_status': _optionalString,
    'age_seconds': _optionalInteger,
    'threshold_seconds': _optionalInteger,
    'active_lighthouses': _optionalInteger,
    'required_lighthouses': _optionalInteger,
    'applied_config_revision': _optionalInteger,
    'desired_config_revision': _optionalInteger,
    'expires_at': _optionalString,
  }),
  _SchemaContract('Node', <String, _PropertyContract>{
    'id': _string,
    'name': _string,
    'role': _string,
    'status': _string,
    'ip': _string,
    'groups': _stringArray,
    'nebula_running': _boolean,
    'applied_config_revision': _integer,
    'site': _optionalString,
    'failure_domain': _optionalString,
    'last_seen_at': _optionalString,
    'certificate_expires_at': _optionalString,
    'agent_status': _optionalString,
    'routed_subnets': _optionalStringArray,
    'revoked_at': _optionalString,
  }),
  _SchemaContract('NetworkReadinessReport', <String, _PropertyContract>{
    'overall': _string,
    'generated_at': _string,
    'sites': _PropertyContract.arrayRef('ReadinessSite'),
    'lighthouses': _PropertyContract.arrayRef('ReadinessLighthouse'),
    'schema': _string,
  }),
  _SchemaContract('FirewallPolicyDocument', <String, _PropertyContract>{
    'inbound': _PropertyContract.arrayRef('FirewallRule'),
    'outbound': _PropertyContract.arrayRef('FirewallRule'),
    'mode': _string,
    'config_revision': _integer,
    'config_updated_at': _string,
    'effective_nodes': _PropertyContract.arrayRef(
      'EffectiveFirewallPolicyDocument',
    ),
    'policy_sha256': _string,
  }),
  _SchemaContract('NetworkDNSDocument', <String, _PropertyContract>{
    'enabled': _boolean,
    'firewall_ready': _boolean,
    'search_domain': _string,
    'config_updated_at': _string,
    'resolvers': _PropertyContract.arrayRef('NetworkDNSResolver'),
    'native_resolver': _boolean,
  }),
  _SchemaContract('NetworkRelaysDocument', <String, _PropertyContract>{
    'enabled': _boolean,
    'active_relays': _PropertyContract.arrayRef('NetworkRelay'),
    'config_updated_at': _string,
    'relay_node_ids': _stringArray,
    'max_relay_nodes': _integer,
    'config_revision': _integer,
  }),
  _SchemaContract('NetworkRoutePoliciesDocument', <String, _PropertyContract>{
    'policies': _PropertyContract.arrayRef('NetworkRoutePolicyDocument'),
    'config_revision': _integer,
    'available_actions': _stringArray,
  }),
  _SchemaContract('NetworkRoutePolicyDocument', <String, _PropertyContract>{
    'prefix': _string,
  }),
  _SchemaContract('NetworkCARotationDocument', <String, _PropertyContract>{
    'phase': _string,
    'active_nodes': _integer,
    'converged_nodes': _integer,
    'config_updated_at': _string,
    'config_revision': _integer,
    'available_actions': _stringArray,
  }),
  _SchemaContract('AuditResponseEvent', <String, _PropertyContract>{
    'id': _string,
    'action': _string,
    'resource': _string,
    'resource_id': _string,
    'at': _string,
    'actor': _PropertyContract.ref('AuditActorResponse', required: false),
    'details': _PropertyContract.type('object', required: false),
  }),
  _SchemaContract('AuditActorResponse', <String, _PropertyContract>{
    'kind': _string,
    'id': _string,
  }),
  _SchemaContract('SessionSummary', <String, _PropertyContract>{
    'id': _string,
    'principal': _PropertyContract.ref('Principal'),
    'auth_method': _string,
    'created_at': _string,
    'absolute_expires_at': _string,
    'idle_expires_at': _string,
  }),
  _SchemaContract('BreakGlassInventoryResponse', <String, _PropertyContract>{
    'usable_codes': _integer,
    'minimum_usable_codes': _integer,
    'codes': _PropertyContract.arrayRef('BreakGlassCodeSummary'),
  }),
  _SchemaContract('CreateNetworkRequest', <String, _PropertyContract>{
    'name': _string,
    'cidr': _string,
    'listen_port': _optionalInteger,
    'certificate_ttl_hours': _optionalInteger,
  }),
  _SchemaContract('Network', <String, _PropertyContract>{
    'id': _string,
    'name': _string,
    'cidr': _string,
    'dns_settings': _PropertyContract.ref('NetworkDNSSettings'),
    'relay_settings': _PropertyContract.ref('NetworkRelaySettings'),
    'ca_rotation': _PropertyContract.ref('NetworkCARotation'),
    'firewall_rollout': _PropertyContract.ref('NetworkFirewallRollout'),
    'route_transfer': _PropertyContract.ref('NetworkRouteTransfer'),
    'route_profile_edit': _PropertyContract.ref('NetworkRouteProfileEdit'),
    'firewall_policy': _PropertyContract.ref('FirewallPolicy'),
    'listen_port': _integer,
    'certificate_ttl_hours': _integer,
    'ca_certificate': _string,
    'config_signing_public_key': _string,
    'config_revision': _integer,
    'config_updated_at': _string,
    'created_at': _string,
    'route_policies': _PropertyContract.arrayRef(
      'NetworkRoutePolicy',
      required: false,
    ),
  }),
  _SchemaContract('CreateNodeInput', <String, _PropertyContract>{
    'name': _string,
    'role': _string,
    'ip': _optionalString,
    'routed_subnets': _optionalStringArray,
    'site': _optionalString,
    'failure_domain': _optionalString,
    'groups': _optionalStringArray,
    'public_endpoint': _optionalString,
  }),
  _SchemaContract('CreatedNode', <String, _PropertyContract>{
    'node': _PropertyContract.ref('Node'),
    'enrollment_token': _string,
    'expires_at': _string,
  }),
  _SchemaContract('ReissuedEnrollment', <String, _PropertyContract>{
    'node': _PropertyContract.ref('Node'),
    'enrollment_token': _string,
    'expires_at': _string,
  }),
  _SchemaContract('RotateNodeCertificateInput', <String, _PropertyContract>{
    'expected_config_revision': _integer,
    'confirmation_name': _string,
    'request_id': _string,
  }),
  _SchemaContract('RotatedNodeCertificate', <String, _PropertyContract>{
    'request_id': _string,
    'node_id': _string,
    'network_id': _string,
    'name': _string,
    'ip': _string,
    'role': _string,
    'rotated_at': _string,
    'previous_certificate_expires_at': _string,
    'certificate_expires_at': _string,
    'certificate_renew_after': _string,
    'previous_certificate_generation': _integer,
    'certificate_generation': _integer,
    'agent_recovery_records_invalidated': _integer,
    'certificate_issuances_added': _integer,
    'blocklist_entries_added': _integer,
    'previous_certificate_blocklisted': _boolean,
    'config_revision': _integer,
  }),
  _SchemaContract('RevokeNodeInput', <String, _PropertyContract>{
    'expected_config_revision': _integer,
    'confirmation_name': _string,
    'request_id': _string,
  }),
  _SchemaContract('RevokedNodeReceipt', <String, _PropertyContract>{
    'request_id': _string,
    'node_id': _string,
    'network_id': _string,
    'name': _string,
    'ip': _string,
    'role': _string,
    'revoked_at': _string,
    'was_enrolled': _boolean,
    'enrollment_records_invalidated': _integer,
    'agent_recovery_records_invalidated': _integer,
    'blocklist_entries_added': _integer,
    'relay_assignment_removed': _boolean,
    'firewall_canary_removed': _boolean,
    'firewall_rollout_auto_rolled_back': _boolean,
    'credentials_invalidated': _boolean,
    'routed_subnet_reservations_released': _integer,
    'config_revision': _integer,
  }),
  _SchemaContract(
    'BreakGlassCodeRegistrationRequest',
    <String, _PropertyContract>{'code': _string, 'expires_at': _string},
  ),
  _SchemaContract('BreakGlassCodeSummary', <String, _PropertyContract>{
    'id': _string,
    'created_at': _string,
    'expires_at': _string,
    'state': _string,
    'used_at': _optionalString,
    'revoked_at': _optionalString,
  }),
];
