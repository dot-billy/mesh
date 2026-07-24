import 'dart:io';

import 'package:mesh_desktop/core/connection/connection_profile.dart';

/// In-memory handling for the existing Mesh browser-cookie contract.
///
/// Browser session and CSRF cookies are never persisted by this class.
final class MeshCookieJar {
  MeshCookieJar(this.profile);

  final ConnectionProfile profile;

  String? _session;
  String? _csrf;

  bool get hasSession => _session != null;
  bool get isComplete => _session != null && _csrf != null;
  String? get csrfToken => _csrf;

  MeshCookiePair snapshot() {
    final session = _session;
    final csrf = _csrf;
    if (session == null || csrf == null) {
      throw const MeshCookieException(
        'Mesh session cookie pair is incomplete.',
      );
    }
    return MeshCookiePair(session: session, csrf: csrf);
  }

  void restore(MeshCookiePair pair) {
    _session = pair.session;
    _csrf = pair.csrf;
  }

  String get _sessionName =>
      profile.isSecure ? '__Host-mesh_session' : 'mesh_session';
  String get _csrfName => profile.isSecure ? '__Host-mesh_csrf' : 'mesh_csrf';

  void capture(Iterable<Cookie> cookies, {DateTime? now}) {
    var nextSession = _session;
    var nextCsrf = _csrf;
    final currentTime = (now ?? DateTime.now()).toUtc();
    for (final cookie in cookies) {
      if (_isAlternateMeshCookie(cookie.name)) {
        throw const MeshCookieException(
          'Server attempted to downgrade the Mesh cookie contract.',
        );
      }
      if (cookie.name != _sessionName && cookie.name != _csrfName) {
        continue;
      }
      if ((cookie.domain?.isNotEmpty ?? false) ||
          cookie.path != '/' ||
          profile.isSecure && !cookie.secure) {
        throw const MeshCookieException(
          'Server returned a Mesh cookie with unsafe scope.',
        );
      }
      final isSession = cookie.name == _sessionName;
      if (isSession != cookie.httpOnly) {
        throw const MeshCookieException(
          'Server returned a Mesh cookie with an invalid HttpOnly policy.',
        );
      }
      final deletion =
          cookie.maxAge != null && cookie.maxAge! <= 0 ||
          cookie.expires != null &&
              !cookie.expires!.toUtc().isAfter(currentTime);
      if (deletion) {
        if (isSession) {
          nextSession = null;
        } else {
          nextCsrf = null;
        }
        continue;
      }
      if (!_opaqueToken.hasMatch(cookie.value)) {
        throw const MeshCookieException(
          'Server returned an invalid Mesh cookie value.',
        );
      }
      if (isSession) {
        nextSession = cookie.value;
      } else {
        nextCsrf = cookie.value;
      }
    }
    _session = nextSession;
    _csrf = nextCsrf;
  }

  void applyTo(HttpClientRequest request) {
    final session = _session;
    final csrf = _csrf;
    if (session != null) {
      request.cookies.add(Cookie(_sessionName, session));
    }
    if (csrf != null) {
      request.cookies.add(Cookie(_csrfName, csrf));
    }
  }

  void clear() {
    _session = null;
    _csrf = null;
  }

  bool _isAlternateMeshCookie(String name) {
    const known = <String>{
      'mesh_session',
      'mesh_csrf',
      '__Host-mesh_session',
      '__Host-mesh_csrf',
    };
    return known.contains(name) && name != _sessionName && name != _csrfName;
  }

  static final RegExp _opaqueToken = RegExp(r'^[A-Za-z0-9_-]{43}$');

  @override
  String toString() =>
      'MeshCookieJar(session: ${_session != null}, csrf: ${_csrf != null})';
}

final class MeshCookieException implements Exception {
  const MeshCookieException(this.message);

  final String message;

  @override
  String toString() => 'MeshCookieException: $message';
}

final class MeshCookiePair {
  MeshCookiePair({required this.session, required this.csrf}) {
    if (!_opaqueToken.hasMatch(session) || !_opaqueToken.hasMatch(csrf)) {
      throw const FormatException('Mesh cookie pair is invalid.');
    }
  }

  static final RegExp _opaqueToken = RegExp(r'^[A-Za-z0-9_-]{43}$');

  final String session;
  final String csrf;

  @override
  String toString() => 'MeshCookiePair([redacted])';
}
