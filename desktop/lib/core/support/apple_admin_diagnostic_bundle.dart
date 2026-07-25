import 'dart:convert';

enum AppleAdminDiagnosticPlatform {
  macos('macos'),
  ios('ios');

  const AppleAdminDiagnosticPlatform(this.value);

  final String value;

  Map<String, Object?> get copyBoundary => switch (this) {
    AppleAdminDiagnosticPlatform.macos => const <String, Object?>{
      'channel': 'system-clipboard',
      'expires_after_seconds': null,
      'local_deletion':
          'operator-must-clear-or-replace-clipboard-after-transfer',
    },
    AppleAdminDiagnosticPlatform.ios => const <String, Object?>{
      'channel': 'local-only-pasteboard',
      'expires_after_seconds': 120,
      'local_deletion': 'automatic-item-expiration',
    },
  };
}

enum AppleAdminDiagnosticSessionState {
  signedOut('signed-out'),
  authorizing('authorizing'),
  signedIn('signed-in');

  const AppleAdminDiagnosticSessionState(this.value);

  final String value;
}

enum AppleAdminDiagnosticRole {
  viewer('viewer'),
  operator('operator'),
  admin('admin');

  const AppleAdminDiagnosticRole(this.value);

  final String value;
}

enum AppleAdminDiagnosticLoadState {
  initial('initial'),
  loading('loading'),
  ready('ready'),
  empty('empty'),
  error('error');

  const AppleAdminDiagnosticLoadState(this.value);

  final String value;
}

enum AppleAdminSupportError {
  configurationInvalid(
    'configuration-invalid',
    'support.configuration.review',
    'Review the approved control-plane origin and signed configuration.',
  ),
  authorizationDenied(
    'authorization-denied',
    'support.authorization.review',
    'Confirm the signed-in role and ask an administrator to review access.',
  ),
  controlPlaneUnavailable(
    'control-plane-unavailable',
    'support.control_plane.retry',
    'Check trusted network access, then retry without changing Mesh policy.',
  ),
  signedStateStale(
    'signed-state-stale',
    'support.signed_state.refresh',
    'Wait for fresh signed lifecycle evidence before interpreting health.',
  ),
  localServiceUnavailable(
    'local-service-unavailable',
    'support.local_service.verify',
    'Verify the separately installed local service through its approved tools.',
  ),
  tunnelUnavailable(
    'tunnel-unavailable',
    'support.tunnel.verify',
    'Inspect Packet Tunnel status without assuming that packets are flowing.',
  ),
  peerEvidenceUnavailable(
    'peer-evidence-unavailable',
    'support.peer_evidence.wait',
    'Wait for authenticated peer evidence before claiming connectivity.',
  ),
  relayObserved(
    'relay-observed',
    'support.relay.review',
    'Traffic is relayed; review direct-path prerequisites before remediation.',
  ),
  packetPathUnverified(
    'packet-path-unverified',
    'support.packet_path.prove',
    'Run an approved packet proof before claiming end-to-end reachability.',
  );

  const AppleAdminSupportError(
    this.code,
    this.remediationKey,
    this.remediation,
  );

  final String code;
  final String remediationKey;
  final String remediation;
}

final class AppleAdminDiagnosticBundle {
  AppleAdminDiagnosticBundle({
    required this.createdAt,
    required this.platform,
    required this.applicationVersion,
    required this.applicationBuild,
    required this.releaseIdentity,
    required this.sessionState,
    required this.connectionState,
    required this.fleetState,
    required this.networkState,
    required this.activityState,
    required this.accessState,
    required this.profileCount,
    required this.networkCount,
    required this.alertCount,
    required this.oneTimeSecretVisible,
    required this.operationReceiptVisible,
    required this.notificationsRequested,
    required this.backgroundMonitoringRequested,
    this.role,
    this.fleetEvidenceAgeSeconds,
  }) {
    if (!createdAt.isUtc) {
      throw ArgumentError.value(createdAt, 'createdAt', 'must be UTC');
    }
    _requireIdentity(applicationVersion, 'applicationVersion', maximum: 32);
    _requireIdentity(applicationBuild, 'applicationBuild', maximum: 32);
    if (releaseIdentity != 'unavailable' &&
        !RegExp(r'^[0-9a-f]{40}$').hasMatch(releaseIdentity) &&
        !RegExp(r'^[0-9a-f]{64}$').hasMatch(releaseIdentity)) {
      throw ArgumentError.value(
        releaseIdentity,
        'releaseIdentity',
        'must be unavailable or one lowercase source/release digest',
      );
    }
    for (final entry in <String, int>{
      'profileCount': profileCount,
      'networkCount': networkCount,
      'alertCount': alertCount,
    }.entries) {
      if (entry.value < 0 || entry.value > 100000) {
        throw ArgumentError.value(
          entry.value,
          entry.key,
          'must be between 0 and 100000',
        );
      }
    }
    if (fleetEvidenceAgeSeconds case final age?
        when age < 0 || age > 31_536_000) {
      throw ArgumentError.value(
        age,
        'fleetEvidenceAgeSeconds',
        'must be between 0 and 31536000',
      );
    }
    if (sessionState == AppleAdminDiagnosticSessionState.signedIn &&
        role == null) {
      throw ArgumentError('A signed-in diagnostic requires a role.');
    }
    if (sessionState != AppleAdminDiagnosticSessionState.signedIn &&
        role != null) {
      throw ArgumentError('A signed-out diagnostic cannot contain a role.');
    }
  }

  static const schema = 'mesh-apple-admin-diagnostic-v2';
  static const maximumBytes = 16 * 1024;

  final DateTime createdAt;
  final AppleAdminDiagnosticPlatform platform;
  final String applicationVersion;
  final String applicationBuild;
  final String releaseIdentity;
  final AppleAdminDiagnosticSessionState sessionState;
  final AppleAdminDiagnosticRole? role;
  final AppleAdminDiagnosticLoadState connectionState;
  final AppleAdminDiagnosticLoadState fleetState;
  final AppleAdminDiagnosticLoadState networkState;
  final AppleAdminDiagnosticLoadState activityState;
  final AppleAdminDiagnosticLoadState accessState;
  final int profileCount;
  final int networkCount;
  final int alertCount;
  final int? fleetEvidenceAgeSeconds;
  final bool oneTimeSecretVisible;
  final bool operationReceiptVisible;
  final bool notificationsRequested;
  final bool backgroundMonitoringRequested;

  String encode() {
    final encoded = jsonEncode(<String, Object?>{
      'schema': schema,
      'created_at': createdAt.toIso8601String(),
      'collection': <String, Object>{
        'initiated_by': 'operator',
        'automatic_collection': false,
        'automatic_upload': false,
        'application_persistence': false,
        'maximum_bytes': maximumBytes,
        'copy_boundary': platform.copyBoundary,
        'recipient_retention': 'delete-after-approved-support-case-closes',
        'recipient_deletion_enforced_by_mesh': false,
      },
      'application': <String, Object>{
        'product': 'mesh-admin',
        'platform': platform.value,
        'version': applicationVersion,
        'build': applicationBuild,
        'release_identity': releaseIdentity,
      },
      'session': <String, Object?>{
        'state': sessionState.value,
        'role': role?.value,
      },
      'state': <String, Object>{
        'connection': connectionState.value,
        'fleet': fleetState.value,
        'selected_network': networkState.value,
        'activity': activityState.value,
        'access': accessState.value,
        'profile_count': profileCount,
        'network_count': networkCount,
        'alert_count': alertCount,
        'fleet_evidence_age_seconds': ?fleetEvidenceAgeSeconds,
        'one_time_secret_visible': oneTimeSecretVisible,
        'operation_receipt_visible': operationReceiptVisible,
        'notifications_requested': notificationsRequested,
        'background_monitoring_requested': backgroundMonitoringRequested,
      },
      'error_catalog': AppleAdminSupportError.values
          .map(
            (error) => <String, String>{
              'code': error.code,
              'remediation_key': error.remediationKey,
              'remediation': error.remediation,
            },
          )
          .toList(growable: false),
      'excluded': const <String>[
        'control-plane-origin',
        'user-and-organization-identifiers',
        'network-and-node-identifiers',
        'request-and-revision-identifiers',
        'sessions-and-csrf-values',
        'browser-poll-secrets',
        'enrollment-and-recovery-secrets',
        'private-keys-and-certificates',
        'signed-configuration-bodies',
        'raw-error-text',
        'logs-and-arbitrary-files',
      ],
    });
    if (utf8.encode(encoded).length > maximumBytes) {
      throw StateError('The diagnostic bundle exceeded its fixed size bound.');
    }
    return encoded;
  }

  static void _requireIdentity(
    String value,
    String name, {
    required int maximum,
  }) {
    if (value.isEmpty ||
        value.length > maximum ||
        !RegExp(r'^[0-9A-Za-z][0-9A-Za-z.+_-]*$').hasMatch(value)) {
      throw ArgumentError.value(value, name, 'contains an invalid identity');
    }
  }
}
