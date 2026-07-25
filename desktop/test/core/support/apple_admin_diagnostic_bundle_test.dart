import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/core/support/apple_admin_diagnostic_bundle.dart';

AppleAdminDiagnosticBundle bundle({
  AppleAdminDiagnosticSessionState sessionState =
      AppleAdminDiagnosticSessionState.signedIn,
  AppleAdminDiagnosticRole? role = AppleAdminDiagnosticRole.viewer,
  String? releaseIdentity,
}) {
  return AppleAdminDiagnosticBundle(
    createdAt: DateTime.utc(2026, 7, 24, 12),
    platform: AppleAdminDiagnosticPlatform.ios,
    applicationVersion: '0.1.0',
    applicationBuild: '1',
    releaseIdentity: releaseIdentity ?? List.filled(40, 'a').join(),
    sessionState: sessionState,
    role: role,
    connectionState: AppleAdminDiagnosticLoadState.ready,
    fleetState: AppleAdminDiagnosticLoadState.error,
    networkState: AppleAdminDiagnosticLoadState.initial,
    activityState: AppleAdminDiagnosticLoadState.loading,
    accessState: AppleAdminDiagnosticLoadState.empty,
    profileCount: 2,
    networkCount: 17,
    alertCount: 3,
    fleetEvidenceAgeSeconds: 41,
    oneTimeSecretVisible: true,
    operationReceiptVisible: false,
    notificationsRequested: false,
    backgroundMonitoringRequested: false,
  );
}

void main() {
  test(
    'diagnostic bundle is bounded, exact, and contains only aggregate state',
    () {
      final encoded = bundle().encode();
      expect(utf8.encode(encoded).length, lessThanOrEqualTo(16 * 1024));
      final decoded = jsonDecode(encoded) as Map<String, Object?>;
      expect(decoded.keys.toSet(), {
        'schema',
        'created_at',
        'collection',
        'application',
        'session',
        'state',
        'error_catalog',
        'excluded',
      });
      expect(decoded['schema'], 'mesh-apple-admin-diagnostic-v2');
      expect(decoded['collection'], {
        'initiated_by': 'operator',
        'automatic_collection': false,
        'automatic_upload': false,
        'application_persistence': false,
        'maximum_bytes': 16384,
        'copy_boundary': {
          'channel': 'local-only-pasteboard',
          'expires_after_seconds': 120,
          'local_deletion': 'automatic-item-expiration',
        },
        'recipient_retention': 'delete-after-approved-support-case-closes',
        'recipient_deletion_enforced_by_mesh': false,
      });
      expect(decoded['application'], {
        'product': 'mesh-admin',
        'platform': 'ios',
        'version': '0.1.0',
        'build': '1',
        'release_identity': List.filled(40, 'a').join(),
      });
      expect(decoded['session'], {'state': 'signed-in', 'role': 'viewer'});
      expect(decoded['state'], {
        'connection': 'ready',
        'fleet': 'error',
        'selected_network': 'initial',
        'activity': 'loading',
        'access': 'empty',
        'profile_count': 2,
        'network_count': 17,
        'alert_count': 3,
        'fleet_evidence_age_seconds': 41,
        'one_time_secret_visible': true,
        'operation_receipt_visible': false,
        'notifications_requested': false,
        'background_monitoring_requested': false,
      });
      expect(
        (decoded['error_catalog'] as List<Object?>)
            .cast<Map<String, Object?>>()
            .map((entry) => entry['code']),
        AppleAdminSupportError.values.map((error) => error.code),
      );
    },
  );

  test('macOS diagnostics disclose manual clipboard deletion', () {
    final decoded =
        jsonDecode(
              AppleAdminDiagnosticBundle(
                createdAt: DateTime.utc(2026, 7, 24, 12),
                platform: AppleAdminDiagnosticPlatform.macos,
                applicationVersion: '0.1.0',
                applicationBuild: '1',
                releaseIdentity: 'unavailable',
                sessionState: AppleAdminDiagnosticSessionState.signedOut,
                connectionState: AppleAdminDiagnosticLoadState.ready,
                fleetState: AppleAdminDiagnosticLoadState.empty,
                networkState: AppleAdminDiagnosticLoadState.initial,
                activityState: AppleAdminDiagnosticLoadState.initial,
                accessState: AppleAdminDiagnosticLoadState.initial,
                profileCount: 0,
                networkCount: 0,
                alertCount: 0,
                oneTimeSecretVisible: false,
                operationReceiptVisible: false,
                notificationsRequested: false,
                backgroundMonitoringRequested: false,
              ).encode(),
            )
            as Map<String, Object?>;
    final collection = decoded['collection'] as Map<String, Object?>;
    expect(collection['copy_boundary'], {
      'channel': 'system-clipboard',
      'expires_after_seconds': null,
      'local_deletion':
          'operator-must-clear-or-replace-clipboard-after-transfer',
    });
    expect(collection['recipient_deletion_enforced_by_mesh'], isFalse);
  });

  test('diagnostic identity and session-role combinations fail closed', () {
    expect(() => bundle(releaseIdentity: 'not-a-digest'), throwsArgumentError);
    expect(
      () => bundle(
        sessionState: AppleAdminDiagnosticSessionState.signedOut,
        role: AppleAdminDiagnosticRole.admin,
      ),
      throwsArgumentError,
    );
    expect(
      () => bundle(
        sessionState: AppleAdminDiagnosticSessionState.signedIn,
        role: null,
      ),
      throwsArgumentError,
    );
  });
}
