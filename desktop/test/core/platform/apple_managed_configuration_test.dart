import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/core/connection/connection_profile.dart';
import 'package:mesh_desktop/core/platform/apple_managed_configuration.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('accepts the exact bounded non-secret managed policy', () {
    final configuration =
        AppleManagedConfiguration.fromPlatformValue(const <String, Object?>{
          'MeshManagedSchema': 'mesh-apple-managed-configuration-v1',
          'ControlPlaneOrigin': 'https://mesh.example.com',
          'AllowOriginChanges': false,
          'ReleaseChannel': 'stable',
          'UpdateRing': 'pilot',
          'ShowLocalStatus': false,
          'NotificationsEnabled': true,
        });

    expect(
      configuration.controlPlaneOrigin?.origin,
      Uri.parse('https://mesh.example.com/'),
    );
    expect(configuration.allowOriginChanges, isFalse);
    expect(configuration.releaseChannel, 'stable');
    expect(configuration.updateRing, 'pilot');
    expect(configuration.showLocalStatus, isFalse);
    expect(configuration.notificationsEnabled, isTrue);
  });

  test('rejects unknown, secret-like, malformed, and unsafe fields', () {
    final invalid = <Map<String, Object?>>[
      const <String, Object?>{
        'MeshManagedSchema': 'mesh-apple-managed-configuration-v1',
        'EnrollmentToken': 'must-never-be-accepted',
      },
      const <String, Object?>{
        'MeshManagedSchema': 'mesh-apple-managed-configuration-v2',
      },
      const <String, Object?>{
        'MeshManagedSchema': 'mesh-apple-managed-configuration-v1',
        'ControlPlaneOrigin': 'http://mesh.example.com',
      },
      const <String, Object?>{
        'MeshManagedSchema': 'mesh-apple-managed-configuration-v1',
        'ControlPlaneOrigin': 'https://user@mesh.example.com',
      },
      const <String, Object?>{
        'MeshManagedSchema': 'mesh-apple-managed-configuration-v1',
        'AllowOriginChanges': false,
      },
      const <String, Object?>{
        'MeshManagedSchema': 'mesh-apple-managed-configuration-v1',
        'ReleaseChannel': '../latest',
      },
      const <String, Object?>{
        'MeshManagedSchema': 'mesh-apple-managed-configuration-v1',
        'NotificationsEnabled': 'true',
      },
    ];

    for (final value in invalid) {
      expect(
        () => AppleManagedConfiguration.fromPlatformValue(value),
        throwsA(isA<AppleManagedConfigurationException>()),
        reason: '$value',
      );
    }
  });

  test('locked origin rejects a different callback-supplied profile', () {
    final configuration = AppleManagedConfiguration(
      controlPlaneOrigin: ConnectionProfile.parse('https://mesh.example.com'),
      allowOriginChanges: false,
      releaseChannel: 'stable',
      updateRing: 'pilot',
      showLocalStatus: false,
      notificationsEnabled: true,
    );

    expect(
      () => configuration.enforceControlPlaneOrigin(
        ConnectionProfile.parse('https://other.example.com'),
      ),
      throwsA(isA<FormatException>()),
    );
    expect(
      () => configuration.enforceControlPlaneOrigin(
        ConnectionProfile.parse('https://mesh.example.com'),
      ),
      returnsNormally,
    );
  });

  test('Apple bridge fails closed when the native handler is absent', () async {
    debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
    try {
      const channel = MethodChannel(
        MethodChannelAppleManagedConfigurationSource.channelName,
      );
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null);

      await expectLater(
        const MethodChannelAppleManagedConfigurationSource().load(),
        throwsA(isA<AppleManagedConfigurationException>()),
      );
    } finally {
      debugDefaultTargetPlatformOverride = null;
    }
  });

  test('Apple bridge accepts only the exact read method result', () async {
    debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
    const channel = MethodChannel(
      MethodChannelAppleManagedConfigurationSource.channelName,
    );
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          expect(call.method, 'readManagedConfiguration');
          expect(call.arguments, isNull);
          return const <String, Object?>{
            'MeshManagedSchema': 'mesh-apple-managed-configuration-v1',
            'ControlPlaneOrigin': 'https://mesh.example.com',
            'AllowOriginChanges': false,
          };
        });
    try {
      final configuration =
          await const MethodChannelAppleManagedConfigurationSource().load();
      expect(configuration?.allowOriginChanges, isFalse);
      expect(
        configuration?.controlPlaneOrigin?.origin,
        Uri.parse('https://mesh.example.com/'),
      );
    } finally {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null);
      debugDefaultTargetPlatformOverride = null;
    }
  });
}
