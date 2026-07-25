import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/core/connection/connection_profile.dart';
import 'package:mesh_desktop/core/transport/json_transport.dart';
import 'package:mesh_desktop/integration/mesh_api.dart';

const _requestId = 'desktop_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const _pollSecret = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE';
const _expiry = '2099-07-23T12:05:00Z';

void main() {
  group('MeshApi desktop browser authorization', () {
    test(
      'starts with an exact request and accepts only the public request URL',
      () async {
        final transport = _QueueTransport()
          ..add(
            const JsonApiResponse(
              statusCode: 201,
              body: <String, Object?>{
                'request_id': _requestId,
                'poll_secret': _pollSecret,
                'verification_url':
                    'https://mesh.example/?mesh_desktop_request=$_requestId',
                'expires_at': _expiry,
                'interval_seconds': 5,
              },
            ),
          );

        final attempt = await _api(transport).startDesktopAuthorization();

        expect(attempt.requestId, _requestId);
        expect(attempt.pollSecret, _pollSecret);
        expect(attempt.pollInterval, const Duration(seconds: 5));
        expect(attempt.toString(), isNot(contains(_pollSecret)));
        expect(
          transport.single,
          _matchesCall(
            method: 'POST',
            path: '/api/v1/auth/desktop/start',
            body: const <String, Object?>{},
          ),
        );
        expect(transport.single.authenticated, isFalse);
        expect(transport.single.sameOriginJson, isTrue);
      },
    );

    test(
      'rejects query drift and never exposes a poll secret in a browser URL',
      () async {
        final unsafeUrls = <String>[
          'https://other.example/?mesh_desktop_request=$_requestId',
          'https://mesh.example/?mesh_desktop_request=$_requestId&poll_secret=$_pollSecret',
          'https://mesh.example/?mesh_desktop_request=$_requestId&mesh_desktop_request=$_requestId',
          'https://mesh.example/?mesh_desktop_request=desktop_${'C' * 43}',
          'https://mesh.example/?mesh_desktop_request=$_requestId#poll_secret=$_pollSecret',
        ];

        for (final url in unsafeUrls) {
          final transport = _QueueTransport()
            ..add(
              JsonApiResponse(
                statusCode: 201,
                body: <String, Object?>{
                  'request_id': _requestId,
                  'poll_secret': _pollSecret,
                  'verification_url': url,
                  'expires_at': _expiry,
                  'interval_seconds': 5,
                },
              ),
            );
          final failure = await _captureFailure(
            _api(transport).startDesktopAuthorization(),
          );
          expect(failure, isA<MeshApiProtocolException>());
          expect(failure.toString(), isNot(contains(_pollSecret)));
        }
      },
    );

    test(
      'polls with the secret only in JSON and validates terminal metadata',
      () async {
        final startTransport = _QueueTransport()
          ..add(
            const JsonApiResponse(
              statusCode: 201,
              body: <String, Object?>{
                'request_id': _requestId,
                'poll_secret': _pollSecret,
                'verification_url':
                    'https://mesh.example/?mesh_desktop_request=$_requestId',
                'expires_at': _expiry,
                'interval_seconds': 5,
              },
            ),
          );
        final attempt = await _api(startTransport).startDesktopAuthorization();
        final pollTransport = _QueueTransport()
          ..add(
            const JsonApiResponse(
              statusCode: 200,
              body: <String, Object?>{
                'state': 'denied',
                'expires_at': _expiry,
                'interval_seconds': 5,
              },
            ),
          );

        final result = await _api(
          pollTransport,
        ).completeDesktopAuthorization(attempt);

        expect(result.state, DesktopAuthorizationState.denied);
        expect(pollTransport.single.body, const <String, Object?>{
          'request_id': _requestId,
          'poll_secret': _pollSecret,
        });
        expect(pollTransport.single.path, '/api/v1/auth/desktop/complete');
        expect(pollTransport.single.authenticated, isFalse);
        expect(pollTransport.single.sameOriginJson, isTrue);
      },
    );

    test(
      'rejects completion drift and credentials in non-authorized states',
      () async {
        final attempt = DesktopAuthorizationAttempt(
          requestId: _requestId,
          pollSecret: _pollSecret,
          verificationUrl: Uri.parse(
            'https://mesh.example/?mesh_desktop_request=$_requestId',
          ),
          expiresAt: DateTime.parse(_expiry),
          pollInterval: const Duration(seconds: 5),
        );
        final invalidBodies = <Map<String, Object?>>[
          <String, Object?>{
            'state': 'pending',
            'expires_at': _expiry,
            'interval_seconds': 6,
          },
          <String, Object?>{
            'state': 'pending',
            'expires_at': _expiry,
            'interval_seconds': 5,
            'session': _session(),
          },
          <String, Object?>{
            'state': 'denied',
            'expires_at': _expiry,
            'interval_seconds': 5,
            'unexpected': true,
          },
        ];

        for (final body in invalidBodies) {
          final transport = _QueueTransport()
            ..add(JsonApiResponse(statusCode: 200, body: body));
          await expectLater(
            _api(transport).completeDesktopAuthorization(attempt),
            throwsA(isA<MeshApiProtocolException>()),
          );
        }
      },
    );

    test('accepts an approved exact session contract', () async {
      final attempt = DesktopAuthorizationAttempt(
        requestId: _requestId,
        pollSecret: _pollSecret,
        verificationUrl: Uri.parse(
          'https://mesh.example/?mesh_desktop_request=$_requestId',
        ),
        expiresAt: DateTime.parse(_expiry),
        pollInterval: const Duration(seconds: 5),
      );
      final transport = _QueueTransport()
        ..add(
          JsonApiResponse(
            statusCode: 200,
            body: <String, Object?>{
              'state': 'authorized',
              'expires_at': _expiry,
              'interval_seconds': 5,
              'session': _session(),
            },
          ),
        );

      final result = await _api(
        transport,
      ).completeDesktopAuthorization(attempt);

      expect(result.state, DesktopAuthorizationState.authorized);
      expect(result.session?.sessionId, 'session_approved');
      expect(result.session?.role.wireValue, 'viewer');
    });
  });
}

MeshApi _api(JsonTransport transport) => MeshApi(
  profile: ConnectionProfile.parse('https://mesh.example'),
  transport: transport,
);

Map<String, Object?> _session() => <String, Object?>{
  'authenticated': true,
  'session_id': 'session_approved',
  'principal': <String, Object?>{
    'id': 'principal_viewer',
    'kind': 'oidc_admin',
    'auth_time': '2099-07-23T12:00:00Z',
  },
  'auth_method': 'oidc',
  'role': 'viewer',
  'permissions': <Object?>['networks.read', 'audit.read'],
  'created_at': '2099-07-23T12:00:00Z',
  'idle_expires_at': '2099-07-23T12:30:00Z',
  'absolute_expires_at': '2099-07-23T20:00:00Z',
};

Future<Object> _captureFailure(Future<Object?> future) async {
  try {
    await future;
  } catch (error) {
    return error;
  }
  throw StateError('Expected operation to fail.');
}

final class _Call {
  const _Call({
    required this.method,
    required this.path,
    required this.body,
    required this.authenticated,
    required this.sameOriginJson,
  });

  final String method;
  final String path;
  final Object? body;
  final bool authenticated;
  final bool sameOriginJson;
}

final class _QueueTransport implements JsonTransport {
  final List<JsonApiResponse> _responses = <JsonApiResponse>[];
  final List<_Call> calls = <_Call>[];

  _Call get single => calls.single;

  void add(JsonApiResponse response) => _responses.add(response);

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
    expect(queryParameters, isNull);
    expect(hasBody, body != null);
    calls.add(
      _Call(
        method: method,
        path: path,
        body: body,
        authenticated: authenticated,
        sameOriginJson: sameOriginJson,
      ),
    );
    return _responses.removeAt(0);
  }
}

Matcher _matchesCall({
  required String method,
  required String path,
  required Object? body,
}) => isA<_Call>()
    .having((call) => call.method, 'method', method)
    .having((call) => call.path, 'path', path)
    .having((call) => call.body, 'body', body);
