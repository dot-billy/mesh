import 'dart:io';

import 'package:mesh_desktop/core/auth/session_models.dart';
import 'package:mesh_desktop/core/connection/connection_profile.dart';

/// Backend-independent contract for native browser approval.
///
/// Endpoint paths and JSON envelopes are intentionally absent. An adapter can
/// map the final `/api/v1/auth/desktop/*` contract into this start, poll, and
/// complete sequence without exposing transport details to the UI.
abstract interface class NativeLoginFlow {
  Future<NativeLoginAttempt> start(ConnectionProfile profile);

  Future<NativeLoginPollStatus> poll(String attemptId);

  /// Completes an approved attempt. The HTTP transport captures the normal
  /// Mesh session and CSRF cookies returned by the control plane.
  Future<SessionContext> complete(String attemptId);

  Future<void> cancel(String attemptId);
}

final class NativeLoginAttempt {
  NativeLoginAttempt({
    required this.id,
    required this.approvalUri,
    required this.expiresAt,
  }) {
    if (!_opaqueId.hasMatch(id)) {
      throw const FormatException('Native login attempt ID is invalid.');
    }
    final secure = approvalUri.scheme == 'https';
    final loopbackDevelopment =
        approvalUri.scheme == 'http' && _isLoopbackHost(approvalUri.host);
    if ((!secure && !loopbackDevelopment) ||
        approvalUri.host.isEmpty ||
        approvalUri.userInfo.isNotEmpty ||
        approvalUri.hasFragment) {
      throw const FormatException(
        'Native login approval URL must use HTTPS, except for an explicit loopback development origin.',
      );
    }
    if (!expiresAt.isUtc) {
      throw const FormatException(
        'Native login expiry must be a UTC timestamp.',
      );
    }
  }

  static final RegExp _opaqueId = RegExp(r'^[A-Za-z0-9_-]{16,256}$');

  final String id;

  /// May contain protocol state. Never log or persist this URL.
  final Uri approvalUri;
  final DateTime expiresAt;

  bool isExpiredAt(DateTime now) => !now.toUtc().isBefore(expiresAt);

  @override
  String toString() => 'NativeLoginAttempt(id: [redacted], url: [redacted])';
}

bool _isLoopbackHost(String host) {
  if (host.toLowerCase() == 'localhost') return true;
  return InternetAddress.tryParse(host)?.isLoopback ?? false;
}

enum NativeLoginPollStatus { pending, approved, denied, expired }
