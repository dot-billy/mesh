/// Explicit, in-memory fallback for deployments that enable the legacy
/// administrator bearer.
///
/// Normal desktop login uses the server's session and CSRF cookie pair. This
/// recovery authority must never be persisted by the desktop application.
final class LegacyAdministratorBearer {
  LegacyAdministratorBearer(this.secret) {
    if (secret.isEmpty ||
        secret.length > 4096 ||
        secret.codeUnits.any((unit) => unit < 0x21 || unit > 0x7e)) {
      throw const FormatException('Legacy administrator bearer is invalid.');
    }
  }

  /// An opaque recovery credential. Never log or persist this value.
  final String secret;

  String get headerValue => 'Bearer $secret';

  @override
  String toString() => 'LegacyAdministratorBearer([redacted])';
}

typedef LegacyAdministratorBearerProvider =
    Future<LegacyAdministratorBearer?> Function();
