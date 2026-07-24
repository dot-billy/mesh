import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:mesh_desktop/core/connection/connection_profile.dart';
import 'package:mesh_desktop/core/transport/mesh_cookie_jar.dart';

abstract interface class SecretStorage {
  Future<String?> read(String key);

  Future<void> write(String key, String value);

  Future<void> delete(String key);
}

final class FlutterSecretStorage implements SecretStorage {
  FlutterSecretStorage({FlutterSecureStorage? storage})
    : _storage = storage ?? const FlutterSecureStorage();

  final FlutterSecureStorage _storage;

  @override
  Future<String?> read(String key) => _storage.read(key: key);

  @override
  Future<void> write(String key, String value) =>
      _storage.write(key: key, value: value);

  @override
  Future<void> delete(String key) => _storage.delete(key: key);
}

final class PersistedDesktopSession {
  PersistedDesktopSession({
    required this.profile,
    required this.cookies,
    required this.issuedAt,
    required this.expiresAt,
  }) {
    if (!issuedAt.isUtc || !expiresAt.isUtc || !issuedAt.isBefore(expiresAt)) {
      throw const FormatException(
        'Persisted desktop session has invalid lifetime.',
      );
    }
  }

  final ConnectionProfile profile;
  final MeshCookiePair cookies;
  final DateTime issuedAt;
  final DateTime expiresAt;

  bool isExpiredAt(DateTime now) => !now.toUtc().isBefore(expiresAt);

  void restoreInto(MeshCookieJar cookieJar) {
    if (cookieJar.profile != profile) {
      throw const SessionPersistenceException(
        'Stored desktop session belongs to a different control plane.',
      );
    }
    cookieJar.restore(cookies);
  }

  Map<String, Object?> toJson() => <String, Object?>{
    'schema': 'mesh-desktop-session-v1',
    'profile': profile.toJson(),
    'session_cookie': cookies.session,
    'csrf_cookie': cookies.csrf,
    'issued_at': issuedAt.toIso8601String(),
    'expires_at': expiresAt.toIso8601String(),
  };

  static PersistedDesktopSession fromJson(Object? value) {
    const fields = <String>{
      'schema',
      'profile',
      'session_cookie',
      'csrf_cookie',
      'issued_at',
      'expires_at',
    };
    if (value is! Map<String, Object?> ||
        value.length != fields.length ||
        !value.keys.toSet().containsAll(fields) ||
        value['schema'] != 'mesh-desktop-session-v1') {
      throw const FormatException(
        'Persisted desktop session is not canonical.',
      );
    }
    final sessionCookie = value['session_cookie'];
    final csrfCookie = value['csrf_cookie'];
    final issued = value['issued_at'];
    final expires = value['expires_at'];
    if (sessionCookie is! String ||
        csrfCookie is! String ||
        issued is! String ||
        expires is! String) {
      throw const FormatException(
        'Persisted desktop session has invalid fields.',
      );
    }
    final issuedAt = DateTime.tryParse(issued);
    final expiresAt = DateTime.tryParse(expires);
    if (issuedAt == null ||
        expiresAt == null ||
        !issuedAt.isUtc ||
        !expiresAt.isUtc ||
        !issued.endsWith('Z') ||
        !expires.endsWith('Z')) {
      throw const FormatException(
        'Persisted desktop session timestamps must be UTC.',
      );
    }
    return PersistedDesktopSession(
      profile: ConnectionProfile.fromJson(value['profile']),
      cookies: MeshCookiePair(session: sessionCookie, csrf: csrfCookie),
      issuedAt: issuedAt,
      expiresAt: expiresAt,
    );
  }

  @override
  String toString() =>
      'PersistedDesktopSession(origin: ${profile.originString}, cookies: [redacted], expiresAt: $expiresAt)';
}

final class SecureSessionStore {
  SecureSessionStore(this._storage, {DateTime Function()? now})
    : _now = now ?? DateTime.now;

  static const String storageKey = 'mesh.desktop.current-session.v1';

  final SecretStorage _storage;
  final DateTime Function() _now;

  Future<PersistedDesktopSession?> load() async {
    final encoded = await _storage.read(storageKey);
    if (encoded == null) {
      return null;
    }
    try {
      final session = PersistedDesktopSession.fromJson(jsonDecode(encoded));
      if (session.isExpiredAt(_now().toUtc())) {
        await clear();
        return null;
      }
      return session;
    } on FormatException catch (error) {
      throw SessionPersistenceException(
        'Stored desktop session is invalid.',
        error,
      );
    }
  }

  Future<void> save(PersistedDesktopSession session) async {
    if (session.isExpiredAt(_now().toUtc())) {
      throw const SessionPersistenceException(
        'Refusing to persist an expired desktop session.',
      );
    }
    await _storage.write(storageKey, jsonEncode(session.toJson()));
  }

  Future<void> clear() => _storage.delete(storageKey);
}

final class SessionPersistenceException implements Exception {
  const SessionPersistenceException(this.message, [this.cause]);

  final String message;
  final Object? cause;

  @override
  String toString() => 'SessionPersistenceException: $message';
}
