import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/core/auth/native_login.dart';

void main() {
  test('native-login attempts redact browser state and expire exactly', () {
    final attempt = NativeLoginAttempt(
      id: 'AAAAAAAAAAAAAAAA',
      approvalUri: Uri.parse(
        'https://id.example/authorize?state=sensitive-state',
      ),
      expiresAt: DateTime.parse('2026-07-23T12:05:00Z'),
    );

    expect(attempt.toString(), isNot(contains('sensitive-state')));
    expect(
      attempt.isExpiredAt(DateTime.parse('2026-07-23T12:04:59Z')),
      isFalse,
    );
    expect(attempt.isExpiredAt(DateTime.parse('2026-07-23T12:05:00Z')), isTrue);
  });

  test('native login requires HTTPS outside an explicit loopback profile', () {
    expect(
      () => NativeLoginAttempt(
        id: 'AAAAAAAAAAAAAAAA',
        approvalUri: Uri.parse('http://id.example/authorize'),
        expiresAt: DateTime.parse('2026-07-23T12:05:00Z'),
      ),
      throwsFormatException,
    );
    expect(
      NativeLoginAttempt(
        id: 'BBBBBBBBBBBBBBBB',
        approvalUri: Uri.parse(
          'http://127.0.0.1:8080/?mesh_desktop_request=desktop_example',
        ),
        expiresAt: DateTime.parse('2026-07-23T12:05:00Z'),
      ),
      isA<NativeLoginAttempt>(),
    );
  });
}
