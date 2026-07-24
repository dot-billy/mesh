import 'package:flutter/material.dart';

enum MeshRole { viewer, operator, admin }

enum MeshPermission {
  networksRead,
  networksWrite,
  networksSecurity,
  identityManage,
  auditRead,
}

extension MeshRolePresentation on MeshRole {
  String get label => switch (this) {
    MeshRole.viewer => 'Viewer',
    MeshRole.operator => 'Operator',
    MeshRole.admin => 'Admin',
  };

  Set<MeshPermission> get permissions => switch (this) {
    MeshRole.viewer => const {
      MeshPermission.networksRead,
      MeshPermission.auditRead,
    },
    MeshRole.operator => const {
      MeshPermission.networksRead,
      MeshPermission.networksWrite,
      MeshPermission.auditRead,
    },
    MeshRole.admin => MeshPermission.values.toSet(),
  };

  bool allows(MeshPermission permission) => permissions.contains(permission);
}

enum EvidenceTone {
  healthy,
  warning,
  critical,
  setup,
  unavailable,
  information,
}

extension EvidenceTonePresentation on EvidenceTone {
  String get label => switch (this) {
    EvidenceTone.healthy => 'Healthy',
    EvidenceTone.warning => 'Warning',
    EvidenceTone.critical => 'Critical',
    EvidenceTone.setup => 'Setup in progress',
    EvidenceTone.unavailable => 'Unavailable',
    EvidenceTone.information => 'Information',
  };

  IconData get icon => switch (this) {
    EvidenceTone.healthy => Icons.check_circle_outline,
    EvidenceTone.warning => Icons.warning_amber_rounded,
    EvidenceTone.critical => Icons.error_outline,
    EvidenceTone.setup => Icons.pending_outlined,
    EvidenceTone.unavailable => Icons.cloud_off_outlined,
    EvidenceTone.information => Icons.info_outline,
  };
}

enum LoadPhase { initial, loading, ready, empty, error }

@immutable
class LoadableViewModel<T> {
  const LoadableViewModel._({required this.phase, this.data, this.message});

  const LoadableViewModel.initial() : this._(phase: LoadPhase.initial);

  const LoadableViewModel.loading({String? message})
    : this._(phase: LoadPhase.loading, message: message);

  const LoadableViewModel.ready(T data)
    : this._(phase: LoadPhase.ready, data: data);

  const LoadableViewModel.empty({String? message})
    : this._(phase: LoadPhase.empty, message: message);

  const LoadableViewModel.error(String message)
    : this._(phase: LoadPhase.error, message: message);

  final LoadPhase phase;
  final T? data;
  final String? message;
}

enum AuthenticationMethod { oidc, legacyToken, breakGlass }

extension AuthenticationMethodPresentation on AuthenticationMethod {
  String get label => switch (this) {
    AuthenticationMethod.oidc => 'Single sign-on',
    AuthenticationMethod.legacyToken => 'Administrator token',
    AuthenticationMethod.breakGlass => 'Recovery code',
  };

  IconData get icon => switch (this) {
    AuthenticationMethod.oidc => Icons.verified_user_outlined,
    AuthenticationMethod.legacyToken => Icons.key_outlined,
    AuthenticationMethod.breakGlass => Icons.emergency_outlined,
  };
}

@immutable
class ConnectionProfileViewModel {
  const ConnectionProfileViewModel({
    required this.id,
    required this.displayName,
    required this.origin,
    required this.tlsTrusted,
  });

  final String id;
  final String displayName;
  final Uri origin;
  final bool tlsTrusted;
}

@immutable
class ConnectionViewModel {
  const ConnectionViewModel({
    this.profiles = const [],
    this.selectedProfileId,
    this.methods = const [],
    this.phase = LoadPhase.initial,
    this.message,
  });

  final List<ConnectionProfileViewModel> profiles;
  final String? selectedProfileId;
  final List<AuthenticationMethod> methods;
  final LoadPhase phase;
  final String? message;

  ConnectionProfileViewModel? get selectedProfile {
    for (final profile in profiles) {
      if (profile.id == selectedProfileId) return profile;
    }
    return null;
  }
}

@immutable
class AccessContextViewModel {
  const AccessContextViewModel({
    required this.displayName,
    required this.role,
    required this.controlPlaneName,
    required this.origin,
  });

  final String displayName;
  final MeshRole role;
  final String controlPlaneName;
  final Uri origin;
}

@immutable
class FleetMetricViewModel {
  const FleetMetricViewModel({required this.label, required this.value});

  final String label;
  final String value;
}

@immutable
class AlertViewModel {
  const AlertViewModel({
    required this.id,
    required this.title,
    required this.detail,
    required this.tone,
    this.resourceLabel,
  });

  final String id;
  final String title;
  final String detail;
  final EvidenceTone tone;
  final String? resourceLabel;
}

@immutable
class NetworkSummaryViewModel {
  const NetworkSummaryViewModel({
    required this.id,
    required this.name,
    required this.cidr,
    required this.tone,
    required this.statusLabel,
    required this.onlineNodes,
    required this.totalNodes,
    required this.nextAction,
  });

  final String id;
  final String name;
  final String cidr;
  final EvidenceTone tone;
  final String statusLabel;
  final int onlineNodes;
  final int totalNodes;
  final String nextAction;
}

@immutable
class FleetViewModel {
  const FleetViewModel({
    required this.tone,
    required this.generatedAt,
    required this.metrics,
    required this.rolloutLabel,
    required this.rolloutFraction,
    required this.alerts,
    required this.networks,
  });

  final EvidenceTone tone;
  final DateTime generatedAt;
  final List<FleetMetricViewModel> metrics;
  final String rolloutLabel;
  final double? rolloutFraction;
  final List<AlertViewModel> alerts;
  final List<NetworkSummaryViewModel> networks;
}

enum MeshNodeRole { lighthouse, member }

extension MeshNodeRolePresentation on MeshNodeRole {
  String get label => this == MeshNodeRole.lighthouse ? 'Lighthouse' : 'Member';

  IconData get icon =>
      this == MeshNodeRole.lighthouse ? Icons.hub_outlined : Icons.dns_outlined;
}

enum NodeLifecycleStatus { pending, operational, warning, offline, revoked }

extension NodeLifecycleStatusPresentation on NodeLifecycleStatus {
  String get label => switch (this) {
    NodeLifecycleStatus.pending => 'Pending enrollment',
    NodeLifecycleStatus.operational => 'Operational',
    NodeLifecycleStatus.warning => 'Needs attention',
    NodeLifecycleStatus.offline => 'Offline',
    NodeLifecycleStatus.revoked => 'Revoked',
  };

  EvidenceTone get tone => switch (this) {
    NodeLifecycleStatus.pending => EvidenceTone.setup,
    NodeLifecycleStatus.operational => EvidenceTone.healthy,
    NodeLifecycleStatus.warning => EvidenceTone.warning,
    NodeLifecycleStatus.offline => EvidenceTone.critical,
    NodeLifecycleStatus.revoked => EvidenceTone.critical,
  };
}

@immutable
class NodeViewModel {
  const NodeViewModel({
    required this.id,
    required this.name,
    required this.role,
    required this.status,
    required this.overlayAddress,
    required this.site,
    required this.failureDomain,
    required this.groups,
    required this.desiredRevision,
    this.appliedRevision,
    this.lastHeartbeatAt,
    this.certificateExpiresAt,
    this.runtimeObservation,
    this.routedSubnets = const [],
  });

  final String id;
  final String name;
  final MeshNodeRole role;
  final NodeLifecycleStatus status;
  final String overlayAddress;
  final String site;
  final String failureDomain;
  final List<String> groups;
  final int desiredRevision;
  final int? appliedRevision;
  final DateTime? lastHeartbeatAt;
  final DateTime? certificateExpiresAt;
  final String? runtimeObservation;
  final List<String> routedSubnets;
}

@immutable
class SetupStageViewModel {
  const SetupStageViewModel({required this.label, required this.state});

  final String label;
  final EvidenceTone state;
}

@immutable
class NetworkOverviewViewModel {
  const NetworkOverviewViewModel({
    required this.network,
    required this.updatedAt,
    required this.nodes,
    required this.setupStages,
    required this.nextActionTitle,
    required this.nextActionDetail,
    required this.alerts,
    this.nextActionPermission,
    this.readiness = const LoadableViewModel.initial(),
    this.firewall = const LoadableViewModel.initial(),
    this.dns = const LoadableViewModel.initial(),
    this.relays = const LoadableViewModel.initial(),
    this.routing = const LoadableViewModel.initial(),
    this.caRotation = const LoadableViewModel.initial(),
  });

  final NetworkSummaryViewModel network;
  final DateTime updatedAt;
  final List<NodeViewModel> nodes;
  final List<SetupStageViewModel> setupStages;
  final String nextActionTitle;
  final String nextActionDetail;
  final MeshPermission? nextActionPermission;
  final List<AlertViewModel> alerts;
  final LoadableViewModel<OperationPanelViewModel> readiness;
  final LoadableViewModel<OperationPanelViewModel> firewall;
  final LoadableViewModel<OperationPanelViewModel> dns;
  final LoadableViewModel<OperationPanelViewModel> relays;
  final LoadableViewModel<OperationPanelViewModel> routing;
  final LoadableViewModel<OperationPanelViewModel> caRotation;
}

@immutable
class OperationFieldViewModel {
  const OperationFieldViewModel({required this.label, required this.value});

  final String label;
  final String value;
}

@immutable
class OperationPanelViewModel {
  const OperationPanelViewModel({
    required this.title,
    required this.summary,
    required this.tone,
    this.generatedAt,
    this.fields = const [],
    this.alerts = const [],
  });

  final String title;
  final String summary;
  final EvidenceTone tone;
  final DateTime? generatedAt;
  final List<OperationFieldViewModel> fields;
  final List<AlertViewModel> alerts;
}

@immutable
class ActivityEventViewModel {
  const ActivityEventViewModel({
    required this.id,
    required this.action,
    required this.resource,
    required this.actor,
    required this.occurredAt,
    this.detail,
    this.tone = EvidenceTone.information,
  });

  final String id;
  final String action;
  final String resource;
  final String actor;
  final DateTime occurredAt;
  final String? detail;
  final EvidenceTone tone;
}

@immutable
class AccessSessionViewModel {
  const AccessSessionViewModel({
    required this.id,
    required this.principal,
    required this.authMethod,
    required this.createdAt,
    required this.expiresAt,
    this.current = false,
  });

  final String id;
  final String principal;
  final String authMethod;
  final DateTime createdAt;
  final DateTime expiresAt;
  final bool current;
}

@Deprecated(
  'Use AccessSessionViewModel; sessions may originate on web or desktop.',
)
typedef BrowserSessionViewModel = AccessSessionViewModel;

@immutable
class RecoveryInventoryViewModel {
  const RecoveryInventoryViewModel({
    required this.usable,
    required this.minimumUsable,
    required this.total,
  });

  final int usable;
  final int minimumUsable;
  final int total;

  bool get restartReady => usable >= minimumUsable;
}

@immutable
class AccessManagementViewModel {
  const AccessManagementViewModel({
    required this.sessions,
    this.recoveryInventory,
  });

  final List<AccessSessionViewModel> sessions;
  final RecoveryInventoryViewModel? recoveryInventory;
}

@immutable
class PreferencesViewModel {
  const PreferencesViewModel({
    this.themeMode = ThemeMode.system,
    this.notificationsEnabled = false,
    this.backgroundMonitoringEnabled = false,
  });

  final ThemeMode themeMode;
  final bool notificationsEnabled;
  final bool backgroundMonitoringEnabled;
}

@immutable
class OneTimeSecretItemViewModel {
  const OneTimeSecretItemViewModel({
    required this.label,
    required this.value,
    required this.copyConfirmation,
    this.hiddenByDefault = true,
  });

  final String label;
  final String value;
  final String copyConfirmation;
  final bool hiddenByDefault;
}

@immutable
class OneTimeSecretViewModel {
  const OneTimeSecretViewModel({
    required this.id,
    required this.title,
    required this.detail,
    required this.items,
    required this.custodyLabel,
  });

  final String id;
  final String title;
  final String detail;
  final List<OneTimeSecretItemViewModel> items;
  final String custodyLabel;
}

@immutable
class OperationReceiptViewModel {
  const OperationReceiptViewModel({
    required this.title,
    required this.summary,
    required this.tone,
    this.requestId,
    this.revision,
    this.verification,
  });

  final String title;
  final String summary;
  final EvidenceTone tone;
  final String? requestId;
  final int? revision;
  final String? verification;
}

@immutable
class MeshDesktopViewModel {
  const MeshDesktopViewModel({
    required this.connection,
    this.accessContext,
    this.fleet = const LoadableViewModel.initial(),
    this.selectedNetwork = const LoadableViewModel.initial(),
    this.activity = const LoadableViewModel.initial(),
    this.accessManagement = const LoadableViewModel.initial(),
    this.preferences = const PreferencesViewModel(),
    this.oneTimeSecret,
    this.receipt,
  });

  final ConnectionViewModel connection;
  final AccessContextViewModel? accessContext;
  final LoadableViewModel<FleetViewModel> fleet;
  final LoadableViewModel<NetworkOverviewViewModel> selectedNetwork;
  final LoadableViewModel<List<ActivityEventViewModel>> activity;
  final LoadableViewModel<AccessManagementViewModel> accessManagement;
  final PreferencesViewModel preferences;
  final OneTimeSecretViewModel? oneTimeSecret;
  final OperationReceiptViewModel? receipt;

  bool get authenticated => accessContext != null;
}
