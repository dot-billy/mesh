import 'package:flutter/material.dart';
import 'package:mesh_desktop/app/app.dart';

class RecordingCallbacks extends NoopMeshPresentationCallbacks
    implements MeshMutationCallbacks {
  int refreshFleetCount = 0;
  int refreshActivityCount = 0;
  int secretAcknowledgedCount = 0;
  int secretScrubbedCount = 0;
  int recoveryAccessCreatedCount = 0;
  final List<ConnectionRequest> addedConnections = [];
  final List<String> selectedNetworks = [];
  final List<String> revokedSessions = [];
  final List<CreateNetworkRequest> createdNetworks = [];
  final List<CreateNodeEnrollmentRequest> createdEnrollments = [];
  final List<ReissueEnrollmentRequest> reissuedEnrollments = [];
  final List<RevokeSessionRequest> revokedAccessSessions = [];
  final List<RotateNodeCertificateRequest> rotatedCertificates = [];
  final List<RevokeNodeRequest> revokedNodes = [];
  ThemeMode? selectedThemeMode;

  @override
  void addConnection(ConnectionRequest request) =>
      addedConnections.add(request);

  @override
  Future<MutationSubmissionResult> createNetwork(
    CreateNetworkRequest request,
  ) async {
    createdNetworks.add(request);
    return const MutationSubmissionResult.succeeded();
  }

  @override
  Future<MutationSubmissionResult> createNodeEnrollment(
    CreateNodeEnrollmentRequest request,
  ) async {
    createdEnrollments.add(request);
    return const MutationSubmissionResult.succeeded();
  }

  @override
  Future<MutationSubmissionResult> createRecoveryAccess() async {
    recoveryAccessCreatedCount++;
    return const MutationSubmissionResult.succeeded();
  }

  @override
  void acknowledgeOneTimeSecret() => secretAcknowledgedCount++;

  @override
  void refreshActivity() => refreshActivityCount++;

  @override
  void refreshFleet() => refreshFleetCount++;

  @override
  Future<MutationSubmissionResult> reissueEnrollment(
    ReissueEnrollmentRequest request,
  ) async {
    reissuedEnrollments.add(request);
    return const MutationSubmissionResult.succeeded();
  }

  @override
  void revokeSession(String sessionId) => revokedSessions.add(sessionId);

  @override
  Future<MutationSubmissionResult> revokeAccessSession(
    RevokeSessionRequest request,
  ) async {
    revokedAccessSessions.add(request);
    return const MutationSubmissionResult.succeeded();
  }

  @override
  Future<MutationSubmissionResult> revokeNode(RevokeNodeRequest request) async {
    revokedNodes.add(request);
    return const MutationSubmissionResult.succeeded();
  }

  @override
  Future<MutationSubmissionResult> rotateNodeCertificate(
    RotateNodeCertificateRequest request,
  ) async {
    rotatedCertificates.add(request);
    return const MutationSubmissionResult.succeeded();
  }

  @override
  void scrubOneTimeSecret() => secretScrubbedCount++;

  @override
  void selectNetwork(String networkId) => selectedNetworks.add(networkId);

  @override
  void updateThemeMode(ThemeMode mode) => selectedThemeMode = mode;
}

MeshDesktopViewModel authenticatedModel({
  MeshRole role = MeshRole.admin,
  LoadableViewModel<FleetViewModel>? fleet,
  LoadableViewModel<NetworkOverviewViewModel>? selectedNetwork,
  LoadableViewModel<List<ActivityEventViewModel>>? activity,
  LoadableViewModel<AccessManagementViewModel>? accessManagement,
  OneTimeSecretViewModel? oneTimeSecret,
  OperationReceiptViewModel? receipt,
}) {
  return MeshDesktopViewModel(
    connection: const ConnectionViewModel(),
    accessContext: AccessContextViewModel(
      displayName: 'Casey Operator',
      role: role,
      controlPlaneName: 'Test control plane',
      origin: Uri.parse('https://mesh.example.test'),
    ),
    fleet: fleet ?? LoadableViewModel.ready(fleetModel()),
    selectedNetwork:
        selectedNetwork ??
        const LoadableViewModel<NetworkOverviewViewModel>.initial(),
    activity:
        activity ??
        LoadableViewModel.ready([
          ActivityEventViewModel(
            id: 'audit_1',
            action: 'node.created',
            resource: 'node · lighthouse-01',
            actor: 'Casey Operator',
            occurredAt: DateTime.utc(2026, 7, 23, 18),
            tone: EvidenceTone.healthy,
          ),
        ]),
    accessManagement:
        accessManagement ??
        LoadableViewModel.ready(
          AccessManagementViewModel(
            sessions: [
              AccessSessionViewModel(
                id: 'session_1',
                principal: 'Casey Operator',
                authMethod: 'OIDC',
                createdAt: DateTime.utc(2026, 7, 23, 17),
                expiresAt: DateTime.utc(2026, 7, 23, 21),
                current: true,
              ),
            ],
            recoveryInventory: const RecoveryInventoryViewModel(
              usable: 2,
              minimumUsable: 2,
              total: 2,
            ),
          ),
        ),
    oneTimeSecret: oneTimeSecret,
    receipt: receipt,
  );
}

FleetViewModel fleetModel() {
  return FleetViewModel(
    tone: EvidenceTone.warning,
    generatedAt: DateTime.utc(2026, 7, 23, 18),
    metrics: const [
      FleetMetricViewModel(label: 'Healthy networks', value: '1'),
      FleetMetricViewModel(label: 'Warnings', value: '1'),
      FleetMetricViewModel(label: 'Critical', value: '0'),
      FleetMetricViewModel(label: 'Critical nodes', value: '0'),
    ],
    rolloutLabel: '3 of 4 nodes current',
    rolloutFraction: 0.75,
    alerts: const [
      AlertViewModel(
        id: 'alert_1',
        title: 'Lighthouse redundancy',
        detail: 'Only one operational lighthouse is available.',
        tone: EvidenceTone.warning,
        resourceLabel: 'production-core',
      ),
    ],
    networks: const [
      NetworkSummaryViewModel(
        id: 'network_1',
        name: 'production-core',
        cidr: '10.42.0.0/24',
        tone: EvidenceTone.setup,
        statusLabel: 'Setup in progress',
        onlineNodes: 3,
        totalNodes: 4,
        nextAction: 'Enroll lighthouse',
      ),
    ],
  );
}

NetworkOverviewViewModel networkModel() {
  const network = NetworkSummaryViewModel(
    id: 'network_1',
    name: 'production-core',
    cidr: '10.42.0.0/24',
    tone: EvidenceTone.setup,
    statusLabel: 'Setup in progress',
    onlineNodes: 1,
    totalNodes: 2,
    nextAction: 'Enroll lighthouse',
  );
  return NetworkOverviewViewModel(
    network: network,
    updatedAt: DateTime.utc(2026, 7, 23, 18),
    nodes: [
      NodeViewModel(
        id: 'node_1',
        name: 'lighthouse-01',
        role: MeshNodeRole.lighthouse,
        status: NodeLifecycleStatus.operational,
        overlayAddress: '10.42.0.10',
        site: 'nyc-office',
        failureDomain: 'nyc-power-a',
        groups: const ['all', 'infrastructure'],
        desiredRevision: 4,
        appliedRevision: 4,
        lastHeartbeatAt: DateTime.utc(2026, 7, 23, 17, 59),
        runtimeObservation: 'One established lighthouse',
      ),
      const NodeViewModel(
        id: 'node_2',
        name: 'app-server-01',
        role: MeshNodeRole.member,
        status: NodeLifecycleStatus.pending,
        overlayAddress: '10.42.0.11',
        site: 'nyc-office',
        failureDomain: 'nyc-rack-7',
        groups: ['all', 'servers'],
        desiredRevision: 4,
      ),
    ],
    setupStages: const [
      SetupStageViewModel(
        label: 'Network created',
        state: EvidenceTone.healthy,
      ),
      SetupStageViewModel(
        label: 'First lighthouse operational',
        state: EvidenceTone.healthy,
      ),
      SetupStageViewModel(
        label: 'First member operational',
        state: EvidenceTone.setup,
      ),
    ],
    nextActionTitle: 'Enroll your first member',
    nextActionDetail:
        'Complete enrollment before applying additional network policy.',
    nextActionPermission: MeshPermission.networksWrite,
    alerts: const [],
    readiness: LoadableViewModel.ready(
      OperationPanelViewModel(
        title: 'Deployment readiness',
        summary: 'One verification remains.',
        tone: EvidenceTone.warning,
      ),
    ),
    firewall: const LoadableViewModel.empty(),
    dns: const LoadableViewModel.empty(),
    relays: const LoadableViewModel.empty(),
    routing: const LoadableViewModel.empty(),
    caRotation: const LoadableViewModel.empty(),
  );
}
