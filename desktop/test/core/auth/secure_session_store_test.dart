import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/core/auth/secure_session_store.dart';
import 'package:mesh_desktop/core/connection/connection_profile.dart';
import 'package:mesh_desktop/core/transport/mesh_cookie_jar.dart';

void main() {
  final now = DateTime.parse('2026-07-23T12:00:00Z');

  PersistedDesktopSession session({
    String? sessionCookie,
    String? csrfCookie,
    DateTime? expiresAt,
  }) => PersistedDesktopSession(
    profile: ConnectionProfile.parse('https://mesh.example'),
    cookies: MeshCookiePair(
      session: sessionCookie ?? 'A' * 43,
      csrf: csrfCookie ?? 'B' * 43,
    ),
    issuedAt: now,
    expiresAt: expiresAt ?? now.add(const Duration(hours: 8)),
  );

  test(
    'round-trips only the scoped cookie session in secure storage',
    () async {
      final storage = MemorySecretStorage();
      final store = SecureSessionStore(storage, now: () => now);
      final expected = session();

      await store.save(expected);
      final encoded = storage.values[SecureSessionStore.storageKey]!;
      expect(encoded, contains('"schema":"mesh-desktop-session-v1"'));
      expect(encoded, contains('"session_cookie":"${'A' * 43}"'));
      expect(encoded, contains('"csrf_cookie":"${'B' * 43}"'));
      expect(encoded, isNot(contains('authorization_scheme')));
      expect(encoded, isNot(contains('enrollment')));
      expect(encoded, isNot(contains('recovery')));

      final loaded = await store.load();
      expect(loaded?.profile, expected.profile);
      expect(loaded?.cookies.session, 'A' * 43);
      expect(loaded?.cookies.csrf, 'B' * 43);
      expect(loaded.toString(), isNot(contains('AAAA')));
      expect(loaded?.cookies.toString(), isNot(contains('BBBB')));

      final cookieJar = MeshCookieJar(expected.profile);
      loaded?.restoreInto(cookieJar);
      expect(cookieJar.snapshot().session, 'A' * 43);
      expect(cookieJar.snapshot().csrf, 'B' * 43);
    },
  );

  test('clears an expired session without returning its credential', () async {
    final storage = MemorySecretStorage();
    final store = SecureSessionStore(
      storage,
      now: () => now.add(const Duration(days: 1)),
    );
    storage.values[SecureSessionStore.storageKey] = jsonEncode(
      session().toJson(),
    );

    expect(await store.load(), isNull);
    expect(storage.values, isEmpty);
  });

  test('fails closed on malformed secure storage', () async {
    final storage = MemorySecretStorage()
      ..values[SecureSessionStore.storageKey] =
          '{"schema":"mesh-desktop-session-v1","session_token":"secret"}';
    final store = SecureSessionStore(storage, now: () => now);

    await expectLater(
      store.load(),
      throwsA(isA<SessionPersistenceException>()),
    );
    expect(
      (await _captureFailure(store.load())).toString(),
      isNot(contains('secret')),
    );
  });

  test('refuses to save an already expired session', () async {
    final storage = MemorySecretStorage();
    final store = SecureSessionStore(storage, now: () => now);
    final expired = PersistedDesktopSession(
      profile: ConnectionProfile.parse('https://mesh.example'),
      cookies: MeshCookiePair(session: 'A' * 43, csrf: 'B' * 43),
      issuedAt: now.subtract(const Duration(hours: 2)),
      expiresAt: now.subtract(const Duration(hours: 1)),
    );

    await expectLater(
      store.save(expired),
      throwsA(isA<SessionPersistenceException>()),
    );
    expect(storage.values, isEmpty);
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

final class MemorySecretStorage implements SecretStorage {
  final Map<String, String> values = <String, String>{};

  @override
  Future<void> delete(String key) async {
    values.remove(key);
  }

  @override
  Future<String?> read(String key) async => values[key];

  @override
  Future<void> write(String key, String value) async {
    values[key] = value;
  }
}
