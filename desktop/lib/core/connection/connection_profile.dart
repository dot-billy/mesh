import 'dart:io';

/// A validated control-plane origin.
///
/// Production profiles require HTTPS. Plain HTTP is available only when the
/// caller explicitly enables development mode and the host is a literal
/// loopback address or the exact `localhost` name.
final class ConnectionProfile {
  ConnectionProfile._(this.origin, this.allowInsecureLoopback);

  factory ConnectionProfile.parse(
    String value, {
    bool allowInsecureLoopback = false,
  }) {
    if (value.isEmpty || value.trim() != value) {
      throw const FormatException(
        'Control-plane URL must not be empty or contain surrounding whitespace.',
      );
    }
    final uri = Uri.tryParse(value);
    if (uri == null ||
        !uri.hasScheme ||
        uri.host.isEmpty ||
        uri.userInfo.isNotEmpty ||
        uri.hasQuery ||
        uri.hasFragment ||
        (uri.path.isNotEmpty && uri.path != '/')) {
      throw const FormatException(
        'Control-plane URL must be an absolute origin without credentials, a path, query, or fragment.',
      );
    }
    if (uri.scheme != 'https') {
      if (uri.scheme != 'http' ||
          !allowInsecureLoopback ||
          !_isLoopbackHost(uri.host)) {
        throw const FormatException(
          'Control-plane URL must use HTTPS; HTTP is allowed only for an explicitly enabled loopback development profile.',
        );
      }
    }
    if (uri.hasPort && (uri.port < 1 || uri.port > 65535)) {
      throw const FormatException('Control-plane URL has an invalid port.');
    }
    final normalized = Uri(
      scheme: uri.scheme,
      host: uri.host,
      port: uri.hasPort ? uri.port : null,
      path: '/',
    );
    return ConnectionProfile._(normalized, allowInsecureLoopback);
  }

  final Uri origin;
  final bool allowInsecureLoopback;

  bool get isSecure => origin.scheme == 'https';

  String get originString => origin.origin;

  Uri endpoint(String path, {Map<String, String>? queryParameters}) {
    final parsed = Uri.tryParse(path);
    if (parsed == null ||
        !path.startsWith('/') ||
        path.startsWith('//') ||
        parsed.hasScheme ||
        parsed.hasAuthority ||
        parsed.hasQuery ||
        parsed.hasFragment) {
      throw const FormatException(
        'API path must be one absolute path without an origin, query, or fragment.',
      );
    }
    return origin.replace(
      path: parsed.path,
      queryParameters: queryParameters?.isEmpty ?? true
          ? null
          : Map<String, String>.unmodifiable(queryParameters!),
    );
  }

  Map<String, Object?> toJson() => <String, Object?>{
    'origin': originString,
    'allow_insecure_loopback': allowInsecureLoopback,
  };

  static ConnectionProfile fromJson(Object? value) {
    if (value is! Map<String, Object?> ||
        value.length != 2 ||
        !value.containsKey('origin') ||
        !value.containsKey('allow_insecure_loopback')) {
      throw const FormatException('Connection profile is not canonical.');
    }
    final origin = value['origin'];
    final allow = value['allow_insecure_loopback'];
    if (origin is! String || allow is! bool) {
      throw const FormatException('Connection profile has invalid fields.');
    }
    return ConnectionProfile.parse(origin, allowInsecureLoopback: allow);
  }

  @override
  bool operator ==(Object other) =>
      other is ConnectionProfile &&
      other.origin == origin &&
      other.allowInsecureLoopback == allowInsecureLoopback;

  @override
  int get hashCode => Object.hash(origin, allowInsecureLoopback);

  @override
  String toString() => 'ConnectionProfile($originString)';
}

bool _isLoopbackHost(String host) {
  if (host.toLowerCase() == 'localhost') {
    return true;
  }
  final address = InternetAddress.tryParse(host);
  return address?.isLoopback ?? false;
}
