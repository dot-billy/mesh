import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/core/connection/connection_profile.dart';
import 'package:mesh_desktop/core/transport/json_transport.dart';
import 'package:mesh_desktop/core/transport/legacy_admin_bearer.dart';

void main() {
  test('sends exact JSON then applies session cookies and CSRF', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    final seen = <Map<String, Object?>>[];
    final handled = Completer<void>();
    server.listen((request) async {
      final bytes = await request.fold<List<int>>(
        <int>[],
        (all, chunk) => all..addAll(chunk),
      );
      seen.add(<String, Object?>{
        'path': request.uri.path,
        'content_type': request.headers.value(HttpHeaders.contentTypeHeader),
        'accept': request.headers.value(HttpHeaders.acceptHeader),
        'cookie': request.headers.value(HttpHeaders.cookieHeader),
        'csrf': request.headers.value('X-Mesh-CSRF'),
        'origin': request.headers.value('Origin'),
        'body': bytes.isEmpty ? null : utf8.decode(bytes),
      });
      request.response.headers.contentType = ContentType.json;
      if (request.uri.path == '/api/v1/session') {
        request.response.cookies.add(
          Cookie('mesh_session', 'A' * 43)
            ..path = '/'
            ..httpOnly = true,
        );
        request.response.cookies.add(
          Cookie('mesh_csrf', 'B' * 43)
            ..path = '/'
            ..httpOnly = false,
        );
        request.response.write('{"authenticated":true}');
      } else {
        request.response.write('{"created":true}');
        handled.complete();
      }
      await request.response.close();
    });
    final profile = ConnectionProfile.parse(
      'http://127.0.0.1:${server.port}',
      allowInsecureLoopback: true,
    );
    final transport = DartIoJsonTransport(profile: profile);
    addTearDown(() => transport.close(force: true));

    await transport.send(
      method: 'POST',
      path: '/api/v1/session',
      body: <String, Object?>{'token': 'placeholder'},
      hasBody: true,
      authenticated: false,
      sameOriginJson: true,
    );
    await transport.send(
      method: 'POST',
      path: '/api/v1/networks',
      body: <String, Object?>{'name': 'lab'},
      hasBody: true,
    );
    await handled.future;

    expect(seen, hasLength(2));
    expect(seen.first['content_type'], 'application/json');
    expect(seen.first['accept'], 'application/json');
    expect(seen.first['body'], '{"token":"placeholder"}');
    expect(seen.first['cookie'], isNull);
    expect(seen.first['origin'], profile.originString);
    expect(seen.last['cookie'], contains('mesh_session=${'A' * 43}'));
    expect(seen.last['cookie'], contains('mesh_csrf=${'B' * 43}'));
    expect(seen.last['csrf'], 'B' * 43);
    expect(seen.last['origin'], profile.originString);
    expect(seen.last['body'], '{"name":"lab"}');
  });

  test(
    'supports an explicit in-memory legacy administrator fallback',
    () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() => server.close(force: true));
      final header = Completer<String?>();
      server.listen((request) async {
        header.complete(request.headers.value(HttpHeaders.authorizationHeader));
        request.response.headers.contentType = ContentType.json;
        request.response.write('{"ok":true}');
        await request.response.close();
      });
      final credential = LegacyAdministratorBearer('legacy-admin-token');
      final transport = DartIoJsonTransport(
        profile: ConnectionProfile.parse(
          'http://127.0.0.1:${server.port}',
          allowInsecureLoopback: true,
        ),
        legacyBearerProvider: () async => credential,
      );
      addTearDown(() => transport.close(force: true));

      final response = await transport.send(
        method: 'GET',
        path: '/api/v1/session',
      );

      expect(response.isSuccess, isTrue);
      expect(await header.future, 'Bearer legacy-admin-token');
      expect(credential.toString(), isNot(contains('legacy-admin-token')));
    },
  );

  test('rejects redirects, encoded bodies, and oversized responses', () async {
    Future<void> expectProtocolFailure(
      void Function(HttpResponse response) configure, {
      int maximumResponseBytes = 1024,
    }) async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      final handled = Completer<void>();
      server.listen((request) async {
        configure(request.response);
        await request.response.close();
        handled.complete();
      });
      final transport = DartIoJsonTransport(
        profile: ConnectionProfile.parse(
          'http://127.0.0.1:${server.port}',
          allowInsecureLoopback: true,
        ),
        maximumResponseBytes: maximumResponseBytes,
      );
      try {
        await expectLater(
          transport.send(method: 'GET', path: '/api/v1/test'),
          throwsA(isA<ApiProtocolException>()),
        );
        await handled.future;
      } finally {
        transport.close(force: true);
        await server.close(force: true);
      }
    }

    await expectProtocolFailure((response) {
      response
        ..statusCode = HttpStatus.found
        ..headers.set(HttpHeaders.locationHeader, '/elsewhere')
        ..write('redirect');
    });
    await expectProtocolFailure((response) {
      response.headers
        ..contentType = ContentType.json
        ..set(HttpHeaders.contentEncodingHeader, 'gzip');
      response.write('{"ok":true}');
    });
    await expectProtocolFailure((response) {
      response.headers.contentType = ContentType.json;
      response.write('{"value":"${'x' * 128}"}');
    }, maximumResponseBytes: 32);
  });

  test('rejects non-JSON responses without disclosing their body', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    server.listen((request) async {
      request.response.headers.contentType = ContentType.text;
      request.response.write('secret diagnostic body');
      await request.response.close();
    });
    final transport = DartIoJsonTransport(
      profile: ConnectionProfile.parse(
        'http://127.0.0.1:${server.port}',
        allowInsecureLoopback: true,
      ),
    );
    addTearDown(() => transport.close(force: true));

    final failure = await _captureFailure(
      transport.send(method: 'GET', path: '/api/v1/test'),
    );

    expect(failure, isA<ApiProtocolException>());
    expect(failure.toString(), isNot(contains('secret diagnostic body')));
  });

  test('exposes only a bounded delta-seconds Retry-After hint', () async {
    Future<Duration?> requestWith(List<String> values) async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      server.listen((request) async {
        request.response.headers.contentType = ContentType.json;
        for (final value in values) {
          request.response.headers.add(HttpHeaders.retryAfterHeader, value);
        }
        request.response
          ..statusCode = HttpStatus.tooManyRequests
          ..write('{"error":"wait"}');
        await request.response.close();
      });
      final transport = DartIoJsonTransport(
        profile: ConnectionProfile.parse(
          'http://127.0.0.1:${server.port}',
          allowInsecureLoopback: true,
        ),
      );
      try {
        final response = await transport.send(
          method: 'POST',
          path: '/api/v1/auth/desktop/complete',
          body: <String, Object?>{'request_id': 'opaque'},
          hasBody: true,
          authenticated: false,
          sameOriginJson: true,
        );
        return response.retryAfter;
      } finally {
        transport.close(force: true);
        await server.close(force: true);
      }
    }

    expect(await requestWith(<String>['5']), const Duration(seconds: 5));
    expect(await requestWith(<String>['5', '6']), isNull);
    expect(await requestWith(<String>['0']), isNull);
    expect(await requestWith(<String>['3601']), isNull);
    expect(
      await requestWith(<String>['Wed, 21 Oct 2015 07:28:00 GMT']),
      isNull,
    );
  });
}

Future<Object> _captureFailure(Future<Object?> future) async {
  try {
    await future;
  } catch (error) {
    return error;
  }
  throw StateError('Expected operation to fail.');
}
