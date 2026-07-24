import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/core/connection/connection_profile.dart';
import 'package:mesh_desktop/core/transport/mesh_cookie_jar.dart';

void main() {
  test('accepts the exact development cookie pair in memory', () {
    final jar = MeshCookieJar(
      ConnectionProfile.parse(
        'http://127.0.0.1:8080',
        allowInsecureLoopback: true,
      ),
    );

    jar.capture(<Cookie>[
      Cookie('mesh_session', 'A' * 43)
        ..path = '/'
        ..httpOnly = true,
      Cookie('mesh_csrf', 'B' * 43)
        ..path = '/'
        ..httpOnly = false,
    ]);

    expect(jar.hasSession, isTrue);
    expect(jar.isComplete, isTrue);
    expect(jar.csrfToken, 'B' * 43);
    final snapshot = jar.snapshot();
    expect(snapshot.session, 'A' * 43);
    expect(snapshot.csrf, 'B' * 43);
    expect(snapshot.toString(), isNot(contains('AAAA')));
    expect(jar.toString(), isNot(contains('AAAA')));
    expect(jar.toString(), isNot(contains('BBBB')));

    final restored = MeshCookieJar(jar.profile)..restore(snapshot);
    expect(restored.snapshot().session, 'A' * 43);
    expect(restored.snapshot().csrf, 'B' * 43);
  });

  test('rejects secure-cookie downgrade and unsafe attributes', () {
    final jar = MeshCookieJar(ConnectionProfile.parse('https://mesh.example'));

    expect(
      () => jar.capture(<Cookie>[
        Cookie('mesh_session', 'A' * 43)
          ..path = '/'
          ..httpOnly = true,
      ]),
      throwsA(isA<MeshCookieException>()),
    );
    expect(
      () => jar.capture(<Cookie>[
        Cookie('__Host-mesh_session', 'A' * 43)
          ..path = '/other'
          ..secure = true
          ..httpOnly = true,
      ]),
      throwsA(isA<MeshCookieException>()),
    );
  });

  test('cookie updates are transactional when one cookie is invalid', () {
    final jar = MeshCookieJar(
      ConnectionProfile.parse(
        'http://localhost:8080',
        allowInsecureLoopback: true,
      ),
    );

    expect(
      () => jar.capture(<Cookie>[
        Cookie('mesh_session', 'A' * 43)
          ..path = '/'
          ..httpOnly = true,
        Cookie('mesh_csrf', 'invalid')
          ..path = '/'
          ..httpOnly = false,
      ]),
      throwsA(isA<MeshCookieException>()),
    );
    expect(jar.hasSession, isFalse);
    expect(jar.csrfToken, isNull);
  });
}
