import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/core/platform/mobile_security.dart';
import 'package:mesh_desktop/core/platform/apple_managed_configuration.dart';
import 'package:mesh_desktop/integration/mesh_app_controller.dart';

final class _MemoryClipboard implements SecretClipboard {
  String? value;

  @override
  Future<void> copy(String value) async {
    this.value = value;
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test(
    'controller creates diagnostics only through explicit Apple copy',
    () async {
      debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
      addTearDown(() {
        debugDefaultTargetPlatformOverride = null;
      });
      final clipboard = _MemoryClipboard();
      final controller = MeshAppController(
        managedConfigurationSource: const NoAppleManagedConfigurationSource(),
        diagnosticClipboard: clipboard,
        diagnosticApplicationVersion: '0.1.0',
        diagnosticApplicationBuild: '7',
        diagnosticReleaseIdentity: List.filled(40, 'b').join(),
        now: () => DateTime.utc(2026, 7, 24, 12),
      );
      addTearDown(controller.dispose);

      expect(clipboard.value, isNull);
      controller.copyDiagnosticBundle();
      await pumpEventQueue();

      final encoded = clipboard.value;
      expect(encoded, isNotNull);
      final decoded = jsonDecode(encoded!) as Map<String, Object?>;
      expect(decoded['schema'], 'mesh-apple-admin-diagnostic-v2');
      expect(decoded['application'], {
        'product': 'mesh-admin',
        'platform': 'ios',
        'version': '0.1.0',
        'build': '7',
        'release_identity': List.filled(40, 'b').join(),
      });
      expect(decoded['session'], {'state': 'signed-out', 'role': null});
      expect(
        controller.value.receipt?.title,
        'Bounded diagnostic bundle copied',
      );
      expect(
        controller.value.receipt?.summary,
        contains('expires after two minutes'),
      );
      expect(
        controller.value.receipt?.summary,
        contains('Delete recipient copies'),
      );
    },
  );
}
