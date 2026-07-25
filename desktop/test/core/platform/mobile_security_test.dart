import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/core/platform/mobile_security.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test(
    'iOS secret copy is local-only and expiration is native-enforced',
    () async {
      debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
      addTearDown(() {
        debugDefaultTargetPlatformOverride = null;
      });
      MethodCall? received;
      const channel = MethodChannel(
        MethodChannelProtectedDataEvents.channelName,
      );
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            received = call;
            return null;
          });
      addTearDown(() {
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, null);
      });

      await const ExpiringSecretClipboard().copy('test-only-secret');

      expect(received?.method, 'copyExpiringSecret');
      expect(received?.arguments, <String, Object?>{
        'value': 'test-only-secret',
      });
    },
  );

  test('secret clipboard rejects empty and oversized values', () async {
    await expectLater(
      const ExpiringSecretClipboard().copy(''),
      throwsArgumentError,
    );
    await expectLater(
      const ExpiringSecretClipboard().copy('x' * 16_385),
      throwsArgumentError,
    );
  });

  test(
    'iOS secret copy fails closed when the native bridge is absent',
    () async {
      debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
      addTearDown(() {
        debugDefaultTargetPlatformOverride = null;
      });
      const channel = MethodChannel(
        MethodChannelProtectedDataEvents.channelName,
      );
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null);

      await expectLater(
        const ExpiringSecretClipboard().copy('must-not-reach-clipboard'),
        throwsA(
          isA<StateError>().having(
            (error) => error.message,
            'message',
            contains('nothing was copied'),
          ),
        ),
      );
      expect(
        await Clipboard.getData(Clipboard.kTextPlain),
        isNot(
          isA<ClipboardData>().having(
            (data) => data.text,
            'text',
            'must-not-reach-clipboard',
          ),
        ),
      );
    },
  );
}
