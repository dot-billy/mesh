import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
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

  test('round-trips canonical saved connection profiles separately', () async {
    final storage = MemorySecretStorage();
    final store = SecureSessionStore(storage, now: () => now);
    final profiles = <PersistedConnectionProfile>[
      PersistedConnectionProfile(
        displayName: 'Production control plane',
        profile: ConnectionProfile.parse('https://mesh.example'),
      ),
      PersistedConnectionProfile(
        displayName: 'Recovery control plane',
        profile: ConnectionProfile.parse('https://recovery.mesh.example:8443'),
      ),
    ];

    await store.saveConnectionProfiles(profiles);

    final encoded =
        storage.values[SecureSessionStore.connectionProfilesStorageKey]!;
    expect(encoded, contains('"schema":"mesh-desktop-connection-profiles-v1"'));
    expect(encoded, contains('"display_name":"Production control plane"'));
    expect(encoded, isNot(contains('session_cookie')));
    expect(encoded, isNot(contains('csrf_cookie')));

    final loaded = await store.loadConnectionProfiles();
    expect(loaded.map((profile) => profile.displayName), [
      'Production control plane',
      'Recovery control plane',
    ]);
    expect(loaded.map((profile) => profile.profile.originString), [
      'https://mesh.example',
      'https://recovery.mesh.example:8443',
    ]);
  });

  test(
    'current Admin loads and preserves frozen v1 Keychain state from an earlier build',
    () async {
      final sessionCookie = 'A' * 43;
      final csrfCookie = 'B' * 43;
      final frozenSession =
          '{"schema":"mesh-desktop-session-v1","profile":{"origin":"https://mesh.example","allow_insecure_loopback":false},"session_cookie":"$sessionCookie","csrf_cookie":"$csrfCookie","issued_at":"2026-07-23T12:00:00.000Z","expires_at":"2026-08-23T12:00:00.000Z"}';
      const frozenProfiles =
          '{"schema":"mesh-desktop-connection-profiles-v1","profiles":[{"display_name":"Production control plane","profile":{"origin":"https://mesh.example","allow_insecure_loopback":false}},{"display_name":"Recovery control plane","profile":{"origin":"https://recovery.mesh.example:8443","allow_insecure_loopback":false}}]}';
      final storage = MemorySecretStorage()
        ..values[SecureSessionStore.storageKey] = frozenSession
        ..values[SecureSessionStore.connectionProfilesStorageKey] =
            frozenProfiles;
      final store = SecureSessionStore(storage, now: () => now);

      final loadedSession = await store.load();
      final loadedProfiles = await store.loadConnectionProfiles();

      expect(loadedSession?.profile.originString, 'https://mesh.example');
      expect(loadedSession?.cookies.session, sessionCookie);
      expect(loadedSession?.cookies.csrf, csrfCookie);
      expect(loadedProfiles.map((profile) => profile.displayName), <String>[
        'Production control plane',
        'Recovery control plane',
      ]);
      await store.save(loadedSession!);
      await store.saveConnectionProfiles(loadedProfiles);
      expect(storage.values[SecureSessionStore.storageKey], frozenSession);
      expect(
        storage.values[SecureSessionStore.connectionProfilesStorageKey],
        frozenProfiles,
      );
    },
  );

  test(
    'future or unknown local-state schemas fail closed during upgrade',
    () async {
      final storage = MemorySecretStorage()
        ..values[SecureSessionStore.storageKey] =
            '{"schema":"mesh-desktop-session-v2"}'
        ..values[SecureSessionStore.connectionProfilesStorageKey] =
            '{"schema":"mesh-desktop-connection-profiles-v2","profiles":[]}';
      final store = SecureSessionStore(storage, now: () => now);

      await expectLater(
        store.load(),
        throwsA(isA<SessionPersistenceException>()),
      );
      await expectLater(
        store.loadConnectionProfiles(),
        throwsA(isA<SessionPersistenceException>()),
      );
      expect(
        storage.values[SecureSessionStore.storageKey],
        '{"schema":"mesh-desktop-session-v2"}',
      );
      expect(
        storage.values[SecureSessionStore.connectionProfilesStorageKey],
        '{"schema":"mesh-desktop-connection-profiles-v2","profiles":[]}',
      );
    },
  );

  test('clearing a session preserves saved connection profiles', () async {
    final storage = MemorySecretStorage();
    final store = SecureSessionStore(storage, now: () => now);
    await store.save(session());
    await store.saveConnectionProfiles([
      PersistedConnectionProfile(
        displayName: 'Production control plane',
        profile: ConnectionProfile.parse('https://mesh.example'),
      ),
    ]);

    await store.clear();

    expect(storage.values, isNot(contains(SecureSessionStore.storageKey)));
    expect(
      storage.values,
      contains(SecureSessionStore.connectionProfilesStorageKey),
    );
    expect(await store.loadConnectionProfiles(), hasLength(1));
  });

  test(
    'clearAll attempts and deletes both exact secure-storage records',
    () async {
      final storage = MemorySecretStorage();
      final store = SecureSessionStore(storage, now: () => now);
      await store.save(session());
      await store.saveConnectionProfiles([
        PersistedConnectionProfile(
          displayName: 'Production control plane',
          profile: ConnectionProfile.parse('https://mesh.example'),
        ),
      ]);

      await store.clearAll();

      expect(storage.values, isEmpty);
    },
  );

  test(
    'clearAll still attempts the second record after a delete failure',
    () async {
      final storage = _FailingDeleteSecretStorage(
        failingKey: SecureSessionStore.storageKey,
      );
      final store = SecureSessionStore(storage, now: () => now);

      await expectLater(
        store.clearAll(),
        throwsA(
          isA<SessionPersistenceException>().having(
            (error) => error.toString(),
            'redacted message',
            isNot(contains('test-only-delete-cause')),
          ),
        ),
      );
      expect(storage.deleteAttempts, [
        SecureSessionStore.storageKey,
        SecureSessionStore.connectionProfilesStorageKey,
      ]);
    },
  );

  test(
    'fails closed on malformed saved profiles without exposing data',
    () async {
      final storage = MemorySecretStorage()
        ..values[SecureSessionStore.connectionProfilesStorageKey] =
            '{"schema":"mesh-desktop-connection-profiles-v1","profiles":[{"display_name":"secret-profile-name","profile":{"origin":"http://not-allowed.example"}}]}';
      final store = SecureSessionStore(storage, now: () => now);

      await expectLater(
        store.loadConnectionProfiles(),
        throwsA(isA<SessionPersistenceException>()),
      );
      expect(
        (await _captureFailure(store.loadConnectionProfiles())).toString(),
        isNot(contains('secret-profile-name')),
      );
    },
  );

  test('refuses duplicate or excessive saved connection profiles', () async {
    final storage = MemorySecretStorage();
    final store = SecureSessionStore(storage, now: () => now);
    final duplicate = PersistedConnectionProfile(
      displayName: 'Duplicate',
      profile: ConnectionProfile.parse('https://mesh.example'),
    );

    await expectLater(
      store.saveConnectionProfiles([duplicate, duplicate]),
      throwsA(isA<SessionPersistenceException>()),
    );
    final excessive = List<PersistedConnectionProfile>.generate(
      SecureSessionStore.maximumConnectionProfiles + 1,
      (index) => PersistedConnectionProfile(
        displayName: 'Control plane $index',
        profile: ConnectionProfile.parse('https://mesh$index.example'),
      ),
    );
    await expectLater(
      store.saveConnectionProfiles(excessive),
      throwsA(isA<SessionPersistenceException>()),
    );
    expect(storage.values, isEmpty);
  });

  test('macOS Keychain options are app-only, device-only, and explicit', () {
    const options = FlutterSecretStorage.macosOptions;
    expect(options.accountName, 'io.rw0.mesh.admin.session.v1');
    expect(options.groupId, isNull);
    expect(options.accessibility, KeychainAccessibility.unlocked_this_device);
    expect(options.synchronizable, isFalse);
    expect(options.usesDataProtectionKeychain, isTrue);
    expect(options.useSecureEnclave, isFalse);
  });

  test('iOS Keychain options are app-only, device-only, and explicit', () {
    const options = FlutterSecretStorage.iosOptions;
    expect(options.accountName, 'io.rw0.mesh.admin.session.v1');
    expect(options.groupId, isNull);
    expect(options.accessibility, KeychainAccessibility.unlocked_this_device);
    expect(options.synchronizable, isFalse);
    expect(options.useSecureEnclave, isFalse);
  });

  test('refuses to restore a session into a different exact origin', () {
    final persisted = session();
    final otherOriginJar = MeshCookieJar(
      ConnectionProfile.parse('https://mesh.example:8443'),
    );

    expect(
      () => persisted.restoreInto(otherOriginJar),
      throwsA(isA<SessionPersistenceException>()),
    );
    expect(otherOriginJar.hasSession, isFalse);
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

final class _FailingDeleteSecretStorage implements SecretStorage {
  _FailingDeleteSecretStorage({required this.failingKey});

  final String failingKey;
  final List<String> deleteAttempts = <String>[];

  @override
  Future<void> delete(String key) async {
    deleteAttempts.add(key);
    if (key == failingKey) {
      throw StateError('test-only-delete-cause');
    }
  }

  @override
  Future<String?> read(String key) async => null;

  @override
  Future<void> write(String key, String value) async {}
}
