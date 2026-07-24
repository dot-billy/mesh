import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/core/connection/connection_profile.dart';
import 'package:mesh_desktop/core/transport/json_transport.dart';
import 'package:mesh_desktop/integration/mesh_api.dart';

void main() {
  group('MeshApi user-visible mutations', () {
    test(
      'creates a network with an exact payload and strict response',
      () async {
        final transport = _RecordingTransport()
          ..respond(
            (_) => JsonApiResponse(
              statusCode: 201,
              body: _network(name: 'operations', cidr: '10.80.0.0/24'),
            ),
          );
        final api = _api(transport);

        final network = await api.createNetwork(
          name: 'operations',
          cidr: '10.80.0.0/24',
          listenPort: 4242,
          certificateTtlHours: 24,
        );

        expect(network.id, 'network_1');
        expect(network.configRevision, 1);
        expect(
          transport.single,
          _matchesCall(
            method: 'POST',
            path: '/api/v1/networks',
            body: <String, Object?>{
              'name': 'operations',
              'cidr': '10.80.0.0/24',
              'listen_port': 4242,
              'certificate_ttl_hours': 24,
            },
          ),
        );

        final forged = _RecordingTransport()
          ..respond((_) {
            final body = _network(name: 'operations', cidr: '10.80.0.0/24')
              ..['private_key'] = 'must-not-be-accepted';
            return JsonApiResponse(statusCode: 201, body: body);
          });
        await expectLater(
          _api(forged).createNetwork(name: 'operations', cidr: '10.80.0.0/24'),
          throwsA(isA<MeshApiProtocolException>()),
        );
      },
    );

    test(
      'creates and reissues pending enrollment without exposing its secret',
      () async {
        final transport = _RecordingTransport()
          ..respond(
            (_) => JsonApiResponse(
              statusCode: 201,
              body: _enrollment(token: 'A' * 43),
            ),
          )
          ..respond(
            (_) => JsonApiResponse(
              statusCode: 200,
              body: _enrollment(token: 'E' * 43),
            ),
          );
        final api = _api(transport);

        final created = await api.createNode(
          networkId: 'network_1',
          name: 'gateway-1',
          routedSubnets: const <String>['192.168.50.0/24', '172.20.0.0/16'],
          site: 'site-a',
          failureDomain: 'rack-a',
          groups: const <String>['routers', 'operators'],
        );
        expect(created.node.id, 'node_1');
        expect(created.enrollmentToken, 'A' * 43);
        expect(created.toString(), isNot(contains('A' * 43)));
        expect(transport.calls.first.body, <String, Object?>{
          'name': 'gateway-1',
          'role': 'member',
          'routed_subnets': <String>['172.20.0.0/16', '192.168.50.0/24'],
          'site': 'site-a',
          'failure_domain': 'rack-a',
          'groups': <String>['operators', 'routers'],
        });

        final reissued = await api.reissuePendingEnrollment('node_1');
        expect(reissued.enrollmentToken, 'E' * 43);
        expect(
          transport.calls.last,
          _matchesCall(
            method: 'POST',
            path: '/api/v1/nodes/node_1/enrollment/reissue',
            body: null,
          ),
        );
      },
    );

    test(
      'binds certificate rotation to revision, name, and request ID',
      () async {
        const requestId = 'rotate-request-0001';
        final transport = _RecordingTransport()
          ..respond(
            (_) => const JsonApiResponse(
              statusCode: 200,
              body: <String, Object?>{
                'request_id': requestId,
                'node_id': 'node_1',
                'network_id': 'network_1',
                'name': 'gateway-1',
                'ip': '10.80.0.2',
                'role': 'member',
                'rotated_at': '2026-07-23T12:00:00Z',
                'previous_certificate_expires_at': '2026-08-01T12:00:00Z',
                'certificate_expires_at': '2027-07-23T12:00:00Z',
                'certificate_renew_after': '2027-06-23T12:00:00Z',
                'previous_certificate_generation': 2,
                'certificate_generation': 3,
                'agent_recovery_records_invalidated': 1,
                'certificate_issuances_added': 1,
                'blocklist_entries_added': 1,
                'previous_certificate_blocklisted': true,
                'config_revision': 8,
              },
            ),
          );

        final receipt = await _api(transport).rotateNodeCertificate(
          nodeId: 'node_1',
          expectedConfigRevision: 7,
          confirmationName: 'gateway-1',
          requestId: requestId,
        );
        expect(receipt.certificateGeneration, 3);
        expect(receipt.configRevision, 8);
        expect(transport.single.body, const <String, Object?>{
          'expected_config_revision': 7,
          'confirmation_name': 'gateway-1',
          'request_id': requestId,
        });
      },
    );

    test(
      'uses the durable node revocation endpoint and verifies its receipt',
      () async {
        const requestId = 'revoke-request-0001';
        final transport = _RecordingTransport()
          ..respond(
            (_) => const JsonApiResponse(
              statusCode: 200,
              body: <String, Object?>{
                'request_id': requestId,
                'node_id': 'node_1',
                'network_id': 'network_1',
                'name': 'gateway-1',
                'ip': '10.80.0.2',
                'role': 'member',
                'revoked_at': '2026-07-23T12:00:00Z',
                'was_enrolled': true,
                'enrollment_records_invalidated': 1,
                'agent_recovery_records_invalidated': 1,
                'blocklist_entries_added': 1,
                'relay_assignment_removed': false,
                'firewall_canary_removed': true,
                'firewall_rollout_auto_rolled_back': true,
                'credentials_invalidated': true,
                'routed_subnet_reservations_released': 1,
                'config_revision': 12,
              },
            ),
          );

        final receipt = await _api(transport).revokeNode(
          nodeId: 'node_1',
          expectedConfigRevision: 11,
          confirmationName: 'gateway-1',
          requestId: requestId,
        );
        expect(receipt.wasEnrolled, isTrue);
        expect(receipt.configRevision, 12);
        expect(transport.single.path, '/api/v1/nodes/node_1/revocation');
        expect(transport.single.body, const <String, Object?>{
          'expected_config_revision': 11,
          'confirmation_name': 'gateway-1',
          'request_id': requestId,
        });
      },
    );

    test('revokes one session with the exact bodyless contract', () async {
      final transport = _RecordingTransport()
        ..respond((_) => const JsonApiResponse(statusCode: 204, body: null));

      await _api(transport).revokeSession('session_1');

      expect(
        transport.single,
        _matchesCall(
          method: 'DELETE',
          path: '/api/v1/sessions/session_1',
          body: null,
        ),
      );
    });

    test(
      'creates recovery access locally and registers only its verifier input',
      () async {
        final expiresAt = DateTime.now().toUtc().add(const Duration(days: 1));
        final transport = _RecordingTransport()
          ..respond((call) {
            final body = call.body! as Map<String, Object?>;
            final credential = body['code']! as String;
            final id = credential.split('.')[1];
            return JsonApiResponse(
              statusCode: 201,
              body: <String, Object?>{
                'id': id,
                'created_at': DateTime.now().toUtc().toIso8601String(),
                'expires_at': body['expires_at'],
                'state': 'usable',
              },
            );
          });
        final registration = await _api(
          transport,
          secureRandom: Random(7),
        ).createRecoveryAccess(expiresAt: expiresAt);

        expect(
          registration.credential,
          matches(
            RegExp(r'^mesh-bg-v1\.bg_[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$'),
          ),
        );
        expect(
          registration.toString(),
          isNot(contains(registration.credential)),
        );
        expect(
          transport.single.body,
          containsPair('code', registration.credential),
        );
        expect(transport.single.authenticated, isTrue);
        expect(transport.single.sameOriginJson, isFalse);
      },
    );

    test(
      'rejects malformed revision and idempotency inputs before transport',
      () async {
        final transport = _RecordingTransport();
        final api = _api(transport);

        await expectLater(
          api.rotateNodeCertificate(
            nodeId: 'node_1',
            expectedConfigRevision: 0,
            confirmationName: 'gateway-1',
            requestId: 'too-short',
          ),
          throwsA(isA<MeshApiProtocolException>()),
        );
        await expectLater(
          api.revokeNode(
            nodeId: '../node',
            expectedConfigRevision: 1,
            confirmationName: 'gateway-1',
            requestId: 'revoke-request-0001',
          ),
          throwsA(isA<MeshApiProtocolException>()),
        );
        expect(transport.calls, isEmpty);
      },
    );
  });
}

MeshApi _api(_RecordingTransport transport, {Random? secureRandom}) => MeshApi(
  profile: ConnectionProfile.parse('https://mesh.example'),
  transport: transport,
  secureRandom: secureRandom,
);

Map<String, Object?> _network({required String name, required String cidr}) =>
    <String, Object?>{
      'id': 'network_1',
      'name': name,
      'cidr': cidr,
      'dns_settings': <String, Object?>{},
      'relay_settings': <String, Object?>{},
      'ca_rotation': <String, Object?>{},
      'firewall_rollout': <String, Object?>{},
      'route_transfer': <String, Object?>{},
      'route_profile_edit': <String, Object?>{},
      'firewall_policy': <String, Object?>{},
      'listen_port': 4242,
      'certificate_ttl_hours': 24,
      'ca_certificate': 'public-ca',
      'config_signing_public_key': 'public-signing-key',
      'config_revision': 1,
      'config_updated_at': '2026-07-23T12:00:00Z',
      'created_at': '2026-07-23T12:00:00Z',
    };

Map<String, Object?> _enrollment({required String token}) => <String, Object?>{
  'node': <String, Object?>{
    'id': 'node_1',
    'network_id': 'network_1',
    'name': 'gateway-1',
    'ip': '10.80.0.2',
    'routed_subnets': <String>['172.20.0.0/16', '192.168.50.0/24'],
    'site': 'site-a',
    'failure_domain': 'rack-a',
    'groups': <String>['all', 'operators', 'routers'],
    'role': 'member',
    'status': 'pending',
    'certificate_generation': 0,
    'applied_config_revision': 0,
    'applied_certificate_generation': 0,
    'nebula_running': false,
    'heartbeat_sequence': 0,
    'agent_credential_generation': 0,
    'created_at': '2026-07-23T12:00:00Z',
  },
  'enrollment_token': token,
  'expires_at': '2026-07-23T12:30:00Z',
};

Matcher _matchesCall({
  required String method,
  required String path,
  required Object? body,
}) => predicate<_ApiCall>(
  (call) =>
      call.method == method && call.path == path && call.body == body ||
      call.method == method && call.path == path && _deepEqual(call.body, body),
  'call $method $path with exact body $body',
);

bool _deepEqual(Object? left, Object? right) {
  if (left is Map && right is Map) {
    if (left.length != right.length) return false;
    return left.keys.every(
      (key) => right.containsKey(key) && _deepEqual(left[key], right[key]),
    );
  }
  if (left is List && right is List) {
    if (left.length != right.length) return false;
    for (var index = 0; index < left.length; index++) {
      if (!_deepEqual(left[index], right[index])) return false;
    }
    return true;
  }
  return left == right;
}

typedef _Responder = JsonApiResponse Function(_ApiCall call);

final class _RecordingTransport implements JsonTransport {
  final List<_ApiCall> calls = <_ApiCall>[];
  final List<_Responder> _responders = <_Responder>[];

  _ApiCall get single => calls.single;

  void respond(_Responder responder) => _responders.add(responder);

  @override
  Future<JsonApiResponse> send({
    required String method,
    required String path,
    Map<String, String>? queryParameters,
    Object? body,
    bool hasBody = false,
    bool authenticated = true,
    bool sameOriginJson = false,
  }) async {
    final call = _ApiCall(
      method: method,
      path: path,
      queryParameters: queryParameters,
      body: body,
      hasBody: hasBody,
      authenticated: authenticated,
      sameOriginJson: sameOriginJson,
    );
    calls.add(call);
    if (_responders.isEmpty) {
      throw StateError('No response queued for $method $path');
    }
    return _responders.removeAt(0)(call);
  }
}

final class _ApiCall {
  const _ApiCall({
    required this.method,
    required this.path,
    required this.queryParameters,
    required this.body,
    required this.hasBody,
    required this.authenticated,
    required this.sameOriginJson,
  });

  final String method;
  final String path;
  final Map<String, String>? queryParameters;
  final Object? body;
  final bool hasBody;
  final bool authenticated;
  final bool sameOriginJson;
}
