import 'package:flutter/material.dart';

import '../models/presentation_models.dart';

@immutable
class ConnectionRequest {
  const ConnectionRequest({required this.displayName, required this.origin});

  final String displayName;
  final Uri origin;
}

@immutable
class CreateNetworkRequest {
  const CreateNetworkRequest({required this.name, required this.cidr});

  final String name;
  final String cidr;
}

@immutable
class CreateNodeEnrollmentRequest {
  const CreateNodeEnrollmentRequest({
    required this.networkId,
    required this.name,
    required this.role,
    required this.site,
    required this.failureDomain,
    this.groups = const [],
    this.publicEndpoint,
  });

  final String networkId;
  final String name;
  final MeshNodeRole role;
  final String site;
  final String failureDomain;
  final List<String> groups;
  final String? publicEndpoint;
}

@immutable
class ReissueEnrollmentRequest {
  const ReissueEnrollmentRequest({
    required this.networkId,
    required this.nodeId,
    required this.nodeName,
  });

  final String networkId;
  final String nodeId;
  final String nodeName;
}

@immutable
class RevokeSessionRequest {
  const RevokeSessionRequest({
    required this.sessionId,
    required this.principal,
    required this.current,
  });

  final String sessionId;
  final String principal;
  final bool current;
}

@immutable
class RotateNodeCertificateRequest {
  const RotateNodeCertificateRequest({
    required this.networkId,
    required this.nodeId,
    required this.nodeName,
  });

  final String networkId;
  final String nodeId;
  final String nodeName;
}

@immutable
class RevokeNodeRequest {
  const RevokeNodeRequest({
    required this.networkId,
    required this.nodeId,
    required this.nodeName,
    required this.confirmedName,
  });

  final String networkId;
  final String nodeId;
  final String nodeName;
  final String confirmedName;
}

@immutable
class MutationSubmissionResult {
  const MutationSubmissionResult.succeeded() : succeeded = true, message = null;

  const MutationSubmissionResult.failed(this.message) : succeeded = false;

  final bool succeeded;
  final String? message;
}

/// Typed, awaitable mutation boundary implemented by the application
/// controller. Presentation code treats an absent implementation as
/// unavailable and keeps mutation controls disabled.
abstract interface class MeshMutationCallbacks {
  Future<MutationSubmissionResult> createNetwork(CreateNetworkRequest request);

  Future<MutationSubmissionResult> createNodeEnrollment(
    CreateNodeEnrollmentRequest request,
  );

  Future<MutationSubmissionResult> reissueEnrollment(
    ReissueEnrollmentRequest request,
  );

  Future<MutationSubmissionResult> revokeAccessSession(
    RevokeSessionRequest request,
  );

  Future<MutationSubmissionResult> createRecoveryAccess();

  Future<MutationSubmissionResult> rotateNodeCertificate(
    RotateNodeCertificateRequest request,
  );

  Future<MutationSubmissionResult> revokeNode(RevokeNodeRequest request);
}

abstract interface class MeshPresentationCallbacks {
  void addConnection(ConnectionRequest request);
  void selectConnection(String profileId);
  void authenticate(AuthenticationMethod method, {String? credential});
  void signOut();

  void refreshFleet();
  void selectNetwork(String networkId);
  void clearSelectedNetwork();
  void runNextNetworkAction(String networkId);
  void selectNode(String networkId, String nodeId);
  void invokeNodeAction(String networkId, String nodeId, String action);
  void invokeNetworkAction(String networkId, String action);

  void refreshActivity();
  void revokeSession(String sessionId);
  void createRecoveryCode();

  void updateThemeMode(ThemeMode mode);
  void updateNotifications(bool enabled);
  void updateBackgroundMonitoring(bool enabled);

  void openPublicDocumentation();
  void openAPIReference();
  void openSystemSettings();

  void acknowledgeOneTimeSecret();
  void scrubOneTimeSecret();
  void dismissReceipt();
}

class NoopMeshPresentationCallbacks implements MeshPresentationCallbacks {
  const NoopMeshPresentationCallbacks();

  @override
  void acknowledgeOneTimeSecret() {}

  @override
  void addConnection(ConnectionRequest request) {}

  @override
  void authenticate(AuthenticationMethod method, {String? credential}) {}

  @override
  void clearSelectedNetwork() {}

  @override
  void createRecoveryCode() {}

  @override
  void dismissReceipt() {}

  @override
  void invokeNetworkAction(String networkId, String action) {}

  @override
  void invokeNodeAction(String networkId, String nodeId, String action) {}

  @override
  void openAPIReference() {}

  @override
  void openPublicDocumentation() {}

  @override
  void openSystemSettings() {}

  @override
  void refreshActivity() {}

  @override
  void refreshFleet() {}

  @override
  void revokeSession(String sessionId) {}

  @override
  void runNextNetworkAction(String networkId) {}

  @override
  void scrubOneTimeSecret() {}

  @override
  void selectConnection(String profileId) {}

  @override
  void selectNetwork(String networkId) {}

  @override
  void selectNode(String networkId, String nodeId) {}

  @override
  void signOut() {}

  @override
  void updateBackgroundMonitoring(bool enabled) {}

  @override
  void updateNotifications(bool enabled) {}

  @override
  void updateThemeMode(ThemeMode mode) {}
}
