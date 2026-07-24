import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/core/connection/connection_profile.dart';

void main() {
  group('ConnectionProfile', () {
    test('accepts and normalizes a production HTTPS origin', () {
      final profile = ConnectionProfile.parse('https://mesh.example:8443/');

      expect(profile.originString, 'https://mesh.example:8443');
      expect(profile.isSecure, isTrue);
      expect(
        profile.endpoint(
          '/api/v1/fleet/health',
          queryParameters: const <String, String>{'view': 'compact'},
        ),
        Uri.parse('https://mesh.example:8443/api/v1/fleet/health?view=compact'),
      );
    });

    test('requires explicit development mode for HTTP loopback', () {
      expect(
        () => ConnectionProfile.parse('http://127.0.0.1:8080'),
        throwsFormatException,
      );
      expect(
        ConnectionProfile.parse(
          'http://127.0.0.1:8080',
          allowInsecureLoopback: true,
        ).originString,
        'http://127.0.0.1:8080',
      );
      expect(
        ConnectionProfile.parse(
          'http://[::1]:8080',
          allowInsecureLoopback: true,
        ).originString,
        'http://[::1]:8080',
      );
      expect(
        ConnectionProfile.parse(
          'http://localhost:8080',
          allowInsecureLoopback: true,
        ).originString,
        'http://localhost:8080',
      );
    });

    test('rejects insecure non-loopback and ambiguous origins', () {
      for (final value in <String>[
        'http://mesh.example',
        'http://localhost.example',
        'https://user@mesh.example',
        'https://mesh.example/control',
        'https://mesh.example?token=x',
        'https://mesh.example/#fragment',
        ' https://mesh.example',
      ]) {
        expect(
          () => ConnectionProfile.parse(value, allowInsecureLoopback: true),
          throwsFormatException,
          reason: value,
        );
      }
    });

    test('round-trips an exact non-secret profile document', () {
      final profile = ConnectionProfile.parse('https://mesh.example');

      expect(ConnectionProfile.fromJson(profile.toJson()), profile);
      expect(
        () => ConnectionProfile.fromJson(<String, Object?>{
          ...profile.toJson(),
          'extra': false,
        }),
        throwsFormatException,
      );
    });

    test('rejects paths that can change the selected origin', () {
      final profile = ConnectionProfile.parse('https://mesh.example');

      for (final path in <String>[
        'api/v1/networks',
        '//other.example/api',
        '/api/v1/networks?secret=x',
        'https://other.example/api',
        '/api/v1/networks#fragment',
      ]) {
        expect(() => profile.endpoint(path), throwsFormatException);
      }
    });
  });
}
