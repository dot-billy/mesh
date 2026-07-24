import 'dart:async';

import 'package:flutter/material.dart';
import 'package:mesh_desktop/app/app.dart';
import 'package:mesh_desktop/core/auth/secure_session_store.dart';
import 'package:mesh_desktop/core/auth/session_models.dart' as core;
import 'package:mesh_desktop/core/connection/connection_profile.dart';
import 'package:mesh_desktop/core/platform/system_browser.dart';
import 'package:mesh_desktop/core/polling/lifecycle_poller.dart';
import 'package:mesh_desktop/core/transport/json_transport.dart';
import 'package:mesh_desktop/core/transport/mesh_cookie_jar.dart';
import 'package:mesh_desktop/integration/mesh_api.dart';
import 'package:mesh_desktop/integration/presentation_mapper.dart';

final class MeshAppController extends ValueNotifier<MeshDesktopViewModel>
    implements MeshPresentationCallbacks, MeshMutationCallbacks {
  MeshAppController({
    SecureSessionStore? sessionStore,
    SystemBrowserLauncher? browser,
    LifecycleSource? lifecycle,
    this._mapper = const MeshPresentationMapper(),
  }) : _sessionStore =
           sessionStore ?? SecureSessionStore(FlutterSecretStorage()),
       _browser = browser ?? UrlLauncherSystemBrowser(),
       _ownsLifecycle = lifecycle == null,
       _lifecycle = lifecycle ?? WidgetsBindingLifecycleSource(),
       super(
         const MeshDesktopViewModel(
           connection: ConnectionViewModel(
             message: 'Add the Mesh control plane you want to manage.',
           ),
         ),
       );

  final SecureSessionStore _sessionStore;
  final SystemBrowserLauncher _browser;
  final bool _ownsLifecycle;
  final LifecycleSource _lifecycle;
  final MeshPresentationMapper _mapper;

  final List<_SavedProfile> _profiles = <_SavedProfile>[];
  DartIoJsonTransport? _transport;
  MeshApi? _api;
  core.SessionContext? _session;
  LifecyclePoller? _fleetPoller;
  List<Map<String, Object?>> _rawNetworks = const <Map<String, Object?>>[];
  Map<String, Object?>? _rawFleet;
  bool _fleetLoading = false;
  bool _disposed = false;
  int _authenticationGeneration = 0;
  int _profileSequence = 0;
  int _mutationSequence = 0;

  Future<void> initialize() async {
    late final PersistedDesktopSession? stored;
    try {
      stored = await _sessionStore.load();
    } on SessionPersistenceException {
      var removed = true;
      try {
        await _sessionStore.clear();
      } catch (_) {
        removed = false;
      }
      _update(
        connection: ConnectionViewModel(
          profiles: _profileViewModels(),
          phase: LoadPhase.ready,
          message: removed
              ? 'The saved session was invalid and has been removed. Sign in again.'
              : 'Secure session storage is unavailable. Unlock the operating system keyring, then restart Mesh Desktop. You can still sign in, but the session will not be saved.',
        ),
      );
      return;
    } catch (_) {
      _update(
        connection: ConnectionViewModel(
          profiles: _profileViewModels(),
          phase: LoadPhase.ready,
          message:
              'Secure session storage is unavailable. Unlock the operating system keyring, then restart Mesh Desktop. You can still sign in, but the session will not be saved.',
        ),
      );
      return;
    }
    if (stored == null) return;

    try {
      final saved = _addProfile(
        stored.profile,
        displayName: stored.profile.origin.host,
        tlsTrusted: true,
      );
      _select(saved);
      stored.restoreInto(_transport!.cookieJar);
      final session = await _api!.currentSession();
      await _authenticated(session, persist: false);
    } catch (error) {
      await _sessionStore.clear().catchError((_) {});
      _disconnect();
      _update(
        connection: ConnectionViewModel(
          profiles: _profileViewModels(),
          message:
              'The saved session could not be restored. Sign in again. ${_safeError(error)}',
          phase: LoadPhase.error,
        ),
        accessContext: null,
      );
    }
  }

  @override
  void addConnection(ConnectionRequest request) {
    unawaited(_addConnection(request));
  }

  Future<void> _addConnection(ConnectionRequest request) async {
    _update(
      connection: ConnectionViewModel(
        profiles: _profileViewModels(),
        phase: LoadPhase.loading,
        message: 'Checking the control-plane TLS and authentication methods…',
      ),
    );
    try {
      final insecureLoopback = request.origin.scheme == 'http';
      final profile = ConnectionProfile.parse(
        request.origin.toString(),
        allowInsecureLoopback: insecureLoopback,
      );
      final saved = _addProfile(
        profile,
        displayName: request.displayName,
        tlsTrusted: false,
      );
      _select(saved);
      final methods = await _api!.authenticationMethods();
      saved.tlsTrusted = true;
      saved.methods = _presentationMethods(methods);
      _update(
        connection: ConnectionViewModel(
          profiles: _profileViewModels(),
          selectedProfileId: saved.id,
          methods: saved.methods,
          phase: LoadPhase.ready,
          message: saved.methods.isEmpty
              ? 'This control plane did not advertise a supported desktop sign-in method.'
              : 'System TLS trust verified. Choose a sign-in method.',
        ),
      );
    } catch (error) {
      final selected = _selectedProfile;
      _update(
        connection: ConnectionViewModel(
          profiles: _profileViewModels(),
          selectedProfileId: selected?.id,
          methods: selected?.methods ?? const <AuthenticationMethod>[],
          phase: LoadPhase.error,
          message: _safeError(error),
        ),
      );
    }
  }

  @override
  void selectConnection(String profileId) {
    final saved = _profiles
        .where((profile) => profile.id == profileId)
        .firstOrNull;
    if (saved == null) return;
    _select(saved);
    _update(
      connection: ConnectionViewModel(
        profiles: _profileViewModels(),
        selectedProfileId: saved.id,
        methods: saved.methods,
        phase: LoadPhase.ready,
        message: saved.tlsTrusted
            ? 'System TLS trust verified. Choose a sign-in method.'
            : 'TLS trust has not been verified for this profile.',
      ),
    );
  }

  @override
  void authenticate(AuthenticationMethod method, {String? credential}) {
    unawaited(_authenticate(method, credential));
  }

  Future<void> _authenticate(
    AuthenticationMethod method,
    String? credential,
  ) async {
    final api = _api;
    final selected = _selectedProfile;
    if (api == null || selected == null) {
      _connectionError('Select a control plane before signing in.');
      return;
    }
    final generation = ++_authenticationGeneration;
    _update(
      connection: ConnectionViewModel(
        profiles: _profileViewModels(),
        selectedProfileId: selected.id,
        methods: selected.methods,
        phase: LoadPhase.loading,
        message: method == AuthenticationMethod.oidc
            ? 'Starting secure browser approval…'
            : 'Signing in…',
      ),
    );
    try {
      late final core.SessionContext session;
      switch (method) {
        case AuthenticationMethod.oidc:
          session = await _browserAuthorization(api, generation);
        case AuthenticationMethod.legacyToken:
          session = await api.loginWithLegacyToken(credential ?? '');
        case AuthenticationMethod.breakGlass:
          session = await api.loginWithBreakGlassCode(credential ?? '');
      }
      if (generation != _authenticationGeneration || _disposed) return;
      await _authenticated(session);
    } catch (error) {
      if (generation != _authenticationGeneration || _disposed) return;
      _connectionError(_safeError(error));
    }
  }

  Future<core.SessionContext> _browserAuthorization(
    MeshApi api,
    int generation,
  ) async {
    final attempt = await api.startDesktopAuthorization();
    await _browser.open(attempt.verificationUrl);
    _connectionMessage(
      'Approve this sign-in in the browser. Mesh Desktop will continue automatically.',
      phase: LoadPhase.loading,
    );
    while (generation == _authenticationGeneration &&
        !attempt.isExpiredAt(DateTime.now().toUtc())) {
      await Future<void>.delayed(attempt.pollInterval);
      if (generation != _authenticationGeneration) {
        throw const MeshApiProtocolException(
          'Desktop authorization was cancelled.',
        );
      }
      try {
        final result = await api.completeDesktopAuthorization(attempt);
        switch (result.state) {
          case DesktopAuthorizationState.pending:
            continue;
          case DesktopAuthorizationState.denied:
            throw const MeshApiException(
              statusCode: 403,
              message: 'The browser denied this desktop sign-in.',
            );
          case DesktopAuthorizationState.expired:
            throw const MeshApiException(
              statusCode: 410,
              message: 'Desktop sign-in expired. Start again.',
            );
          case DesktopAuthorizationState.authorized:
            return result.session!;
        }
      } on MeshApiException catch (error) {
        if (error.statusCode == 429) {
          continue;
        }
        rethrow;
      }
    }
    throw const MeshApiException(
      statusCode: 410,
      message: 'Desktop sign-in expired. Start again.',
    );
  }

  Future<void> _authenticated(
    core.SessionContext session, {
    bool persist = true,
  }) async {
    final selected = _selectedProfile;
    final transport = _transport;
    if (selected == null ||
        transport == null ||
        !transport.cookieJar.isComplete) {
      throw const MeshApiProtocolException(
        'Mesh did not return a complete desktop session.',
      );
    }
    _session = session;
    final role = _presentationRole(session.role.wireValue);
    _update(
      connection: ConnectionViewModel(
        profiles: _profileViewModels(),
        selectedProfileId: selected.id,
        methods: selected.methods,
        phase: LoadPhase.ready,
      ),
      accessContext: AccessContextViewModel(
        displayName: session.principal.label,
        role: role,
        controlPlaneName: selected.displayName,
        origin: selected.profile.origin,
      ),
      fleet: const LoadableViewModel.loading(
        message: 'Loading authoritative fleet evidence…',
      ),
      activity:
          session.permissions.any(
            (permission) => permission.wireValue == 'audit.read',
          )
          ? const LoadableViewModel.loading(message: 'Loading audit events…')
          : const LoadableViewModel.empty(
              message: 'This role cannot read audit events.',
            ),
      accessManagement: role == MeshRole.admin
          ? const LoadableViewModel.loading(
              message: 'Loading access inventory…',
            )
          : const LoadableViewModel.initial(),
    );
    if (persist) {
      try {
        final now = DateTime.now().toUtc();
        final expires =
            session.absoluteExpiresAt ??
            session.idleExpiresAt ??
            now.add(const Duration(hours: 1));
        await _sessionStore.save(
          PersistedDesktopSession(
            profile: selected.profile,
            cookies: transport.cookieJar.snapshot(),
            issuedAt: session.createdAt ?? now,
            expiresAt: expires,
          ),
        );
      } catch (_) {
        _update(
          receipt: const OperationReceiptViewModel(
            title: 'Session is not saved',
            summary:
                'Secure OS credential storage was unavailable. This session will end when Mesh Desktop closes.',
            tone: EvidenceTone.warning,
          ),
        );
      }
    }
    await Future.wait<void>(<Future<void>>[
      _refreshFleet(showLoading: false),
      _refreshActivity(),
      if (role == MeshRole.admin) _refreshAccess(),
    ]);
    _startFleetPolling();
  }

  @override
  void signOut() {
    unawaited(_signOut());
  }

  Future<void> _signOut({bool callServer = true}) async {
    ++_authenticationGeneration;
    await _fleetPoller?.dispose();
    _fleetPoller = null;
    if (callServer) {
      await _api?.logout().catchError((_) {});
    }
    await _sessionStore.clear().catchError((_) {});
    _transport?.cookieJar.clear();
    _session = null;
    final selected = _selectedProfile;
    _update(
      connection: ConnectionViewModel(
        profiles: _profileViewModels(),
        selectedProfileId: selected?.id,
        methods: selected?.methods ?? const <AuthenticationMethod>[],
        phase: selected == null ? LoadPhase.initial : LoadPhase.ready,
        message: selected == null
            ? 'Add the Mesh control plane you want to manage.'
            : 'Signed out. Choose a sign-in method.',
      ),
      accessContext: null,
      fleet: const LoadableViewModel.initial(),
      selectedNetwork: const LoadableViewModel.initial(),
      activity: const LoadableViewModel.initial(),
      accessManagement: const LoadableViewModel.initial(),
      oneTimeSecret: null,
      receipt: null,
    );
  }

  @override
  void refreshFleet() {
    unawaited(_refreshFleet());
  }

  Future<void> _refreshFleet({bool showLoading = false}) async {
    final api = _api;
    if (api == null || _session == null || _fleetLoading) return;
    _fleetLoading = true;
    if (showLoading || value.fleet.phase != LoadPhase.ready) {
      _update(
        fleet: const LoadableViewModel.loading(
          message: 'Loading authoritative fleet evidence…',
        ),
      );
    }
    try {
      final result = await Future.wait<Object>(<Future<Object>>[
        api.networks(),
        api.fleetHealth(),
      ]);
      _rawNetworks = result[0] as List<Map<String, Object?>>;
      _rawFleet = result[1] as Map<String, Object?>;
      final model = _mapper.fleet(_rawNetworks, _rawFleet!);
      _update(
        fleet: model.networks.isEmpty
            ? const LoadableViewModel.empty(
                message: 'No networks have been created.',
              )
            : LoadableViewModel<FleetViewModel>.ready(model),
      );
      final selected = value.selectedNetwork.data;
      if (selected != null) {
        await _loadNetwork(selected.network.id, showLoading: false);
      }
    } catch (error) {
      if (await _handleSessionError(error)) return;
      if (value.fleet.phase != LoadPhase.ready) {
        _update(fleet: LoadableViewModel.error(_safeError(error)));
      } else {
        _update(
          receipt: OperationReceiptViewModel(
            title: 'Fleet refresh failed',
            summary:
                '${_safeError(error)} Last successful evidence remains visible with its timestamp.',
            tone: EvidenceTone.warning,
          ),
        );
      }
    } finally {
      _fleetLoading = false;
    }
  }

  @override
  void selectNetwork(String networkId) {
    unawaited(_loadNetwork(networkId));
  }

  Future<void> _loadNetwork(String networkId, {bool showLoading = true}) async {
    final api = _api;
    if (api == null) return;
    final network = _rawNetworks
        .where((candidate) => candidate['id'] == networkId)
        .firstOrNull;
    if (network == null) {
      _update(
        selectedNetwork: const LoadableViewModel.error(
          'The selected network is no longer present.',
        ),
      );
      return;
    }
    if (showLoading) {
      _update(
        selectedNetwork: const LoadableViewModel.loading(
          message: 'Loading network evidence and policy…',
        ),
      );
    }
    try {
      final nodes = await api.nodes(networkId);
      final panels =
          await Future.wait<LoadableViewModel<OperationPanelViewModel>>(
            <Future<LoadableViewModel<OperationPanelViewModel>>>[
              _panel(() => api.readiness(networkId), _mapper.readiness),
              _panel(() => api.firewall(networkId), _mapper.firewall),
              _panel(() => api.dns(networkId), _mapper.dns),
              _panel(() => api.relays(networkId), _mapper.relays),
              _panel(() => api.routePolicies(networkId), _mapper.routing),
              _panel(() => api.caRotation(networkId), _mapper.caRotation),
            ],
          );
      final model = _mapper.networkOverview(
        network: network,
        nodes: nodes,
        healthReport: _healthReport(networkId),
        readiness: panels[0],
        firewall: panels[1],
        dns: panels[2],
        relays: panels[3],
        routing: panels[4],
        caRotation: panels[5],
      );
      _update(
        selectedNetwork: LoadableViewModel<NetworkOverviewViewModel>.ready(
          model,
        ),
      );
    } catch (error) {
      if (await _handleSessionError(error)) return;
      _update(selectedNetwork: LoadableViewModel.error(_safeError(error)));
    }
  }

  Future<LoadableViewModel<OperationPanelViewModel>> _panel(
    Future<Map<String, Object?>> Function() load,
    OperationPanelViewModel Function(Map<String, Object?>) map,
  ) async {
    try {
      return LoadableViewModel<OperationPanelViewModel>.ready(
        map(await load()),
      );
    } catch (error) {
      return LoadableViewModel<OperationPanelViewModel>.error(
        _safeError(error),
      );
    }
  }

  @override
  void clearSelectedNetwork() {
    _update(selectedNetwork: const LoadableViewModel.initial());
  }

  @override
  void runNextNetworkAction(String networkId) {
    _update(
      receipt: const OperationReceiptViewModel(
        title: 'Review required',
        summary:
            'This setup step has not been submitted. Mesh Desktop will add its guided review form before enabling the mutation.',
        tone: EvidenceTone.information,
      ),
    );
  }

  @override
  Future<MutationSubmissionResult> createNetwork(
    CreateNetworkRequest request,
  ) async {
    final api = _api;
    if (api == null || _session == null) {
      return const MutationSubmissionResult.failed(
        'Sign in before creating a network.',
      );
    }
    try {
      final network = await api.createNetwork(
        name: request.name,
        cidr: request.cidr,
      );
      await _refreshFleet(showLoading: false);
      _update(
        receipt: OperationReceiptViewModel(
          title: 'Network created',
          summary:
              '${network.name} now owns ${network.cidr}. Add a lighthouse enrollment next.',
          tone: EvidenceTone.healthy,
          revision: network.configRevision,
          verification: 'Confirmed by the control-plane create response.',
        ),
      );
      return const MutationSubmissionResult.succeeded();
    } catch (error) {
      if (await _handleSessionError(error)) {
        return const MutationSubmissionResult.failed(
          'The Mesh session expired. Sign in again.',
        );
      }
      return MutationSubmissionResult.failed(_safeError(error));
    }
  }

  @override
  Future<MutationSubmissionResult> createNodeEnrollment(
    CreateNodeEnrollmentRequest request,
  ) async {
    final api = _api;
    final origin = _selectedProfile?.profile.origin;
    if (api == null || _session == null || origin == null) {
      return const MutationSubmissionResult.failed(
        'Sign in before creating an enrollment.',
      );
    }
    try {
      final enrollment = await api.createNode(
        networkId: request.networkId,
        name: request.name,
        role: request.role == MeshNodeRole.lighthouse ? 'lighthouse' : 'member',
        site: request.site,
        failureDomain: request.failureDomain,
        groups: request.groups,
        publicEndpoint: request.publicEndpoint,
      );
      _showEnrollment(enrollment, origin);
      await _refreshFleet(showLoading: false);
      _update(
        receipt: OperationReceiptViewModel(
          title: 'Enrollment created',
          summary:
              '${enrollment.node.name} is pending. The one-time token is visible until you store or dismiss it.',
          tone: EvidenceTone.healthy,
          verification: 'Pending node identity confirmed by the control plane.',
        ),
      );
      return const MutationSubmissionResult.succeeded();
    } catch (error) {
      if (await _handleSessionError(error)) {
        return const MutationSubmissionResult.failed(
          'The Mesh session expired. Sign in again.',
        );
      }
      return MutationSubmissionResult.failed(_safeError(error));
    }
  }

  @override
  Future<MutationSubmissionResult> reissueEnrollment(
    ReissueEnrollmentRequest request,
  ) async {
    final api = _api;
    final origin = _selectedProfile?.profile.origin;
    if (api == null || _session == null || origin == null) {
      return const MutationSubmissionResult.failed(
        'Sign in before reissuing an enrollment.',
      );
    }
    try {
      final enrollment = await api.reissuePendingEnrollment(request.nodeId);
      if (enrollment.node.networkId != request.networkId ||
          enrollment.node.name != request.nodeName) {
        throw const MeshApiProtocolException(
          'Reissued enrollment did not match the selected node.',
        );
      }
      _showEnrollment(enrollment, origin);
      await _refreshFleet(showLoading: false);
      _update(
        receipt: OperationReceiptViewModel(
          title: 'Enrollment reissued',
          summary:
              'The previous token for ${request.nodeName} is invalid. Store the replacement before closing the custody view.',
          tone: EvidenceTone.healthy,
          verification:
              'Replacement pending enrollment confirmed by the control plane.',
        ),
      );
      return const MutationSubmissionResult.succeeded();
    } catch (error) {
      if (await _handleSessionError(error)) {
        return const MutationSubmissionResult.failed(
          'The Mesh session expired. Sign in again.',
        );
      }
      return MutationSubmissionResult.failed(_safeError(error));
    }
  }

  @override
  Future<MutationSubmissionResult> rotateNodeCertificate(
    RotateNodeCertificateRequest request,
  ) async {
    final api = _api;
    if (api == null || _session == null) {
      return const MutationSubmissionResult.failed(
        'Sign in before rotating a certificate.',
      );
    }
    try {
      final network = await _freshNetwork(api, request.networkId);
      final receipt = await api.rotateNodeCertificate(
        nodeId: request.nodeId,
        expectedConfigRevision: network.configRevision,
        confirmationName: request.nodeName,
        requestId: _nextMutationRequestId(),
      );
      await _refreshFleet(showLoading: false);
      _update(
        receipt: OperationReceiptViewModel(
          title: 'Certificate rotation committed',
          summary:
              '${receipt.name} has certificate generation ${receipt.certificateGeneration}. The node must check in to apply it.',
          tone: EvidenceTone.healthy,
          requestId: receipt.requestId,
          revision: receipt.configRevision,
          verification:
              'The old certificate was blocklisted and a replacement was issued.',
        ),
      );
      return const MutationSubmissionResult.succeeded();
    } catch (error) {
      if (await _handleSessionError(error)) {
        return const MutationSubmissionResult.failed(
          'The Mesh session expired. Sign in again.',
        );
      }
      return MutationSubmissionResult.failed(_safeError(error));
    }
  }

  @override
  Future<MutationSubmissionResult> revokeNode(RevokeNodeRequest request) async {
    final api = _api;
    if (api == null || _session == null) {
      return const MutationSubmissionResult.failed(
        'Sign in before revoking a node.',
      );
    }
    if (request.confirmedName != request.nodeName) {
      return const MutationSubmissionResult.failed(
        'The confirmation name did not match the selected node.',
      );
    }
    try {
      final network = await _freshNetwork(api, request.networkId);
      final receipt = await api.revokeNode(
        nodeId: request.nodeId,
        expectedConfigRevision: network.configRevision,
        confirmationName: request.confirmedName,
        requestId: _nextMutationRequestId(),
      );
      await _refreshFleet(showLoading: false);
      _update(
        receipt: OperationReceiptViewModel(
          title: 'Node permanently revoked',
          summary:
              '${receipt.name} can no longer authenticate or rejoin with its old identity.',
          tone: EvidenceTone.healthy,
          requestId: receipt.requestId,
          revision: receipt.configRevision,
          verification: receipt.wasEnrolled
              ? 'Credentials were invalidated and the certificate identity was blocklisted.'
              : 'Pending credentials were invalidated before enrollment.',
        ),
      );
      return const MutationSubmissionResult.succeeded();
    } catch (error) {
      if (await _handleSessionError(error)) {
        return const MutationSubmissionResult.failed(
          'The Mesh session expired. Sign in again.',
        );
      }
      return MutationSubmissionResult.failed(_safeError(error));
    }
  }

  @override
  void selectNode(String networkId, String nodeId) {}

  @override
  void invokeNodeAction(String networkId, String nodeId, String action) {
    _update(
      receipt: OperationReceiptViewModel(
        title: 'Action not submitted',
        summary:
            '${_actionLabel(action)} requires a dedicated review and confirmation flow. No control-plane state changed.',
        tone: EvidenceTone.information,
      ),
    );
  }

  @override
  void invokeNetworkAction(String networkId, String action) {
    _update(
      receipt: OperationReceiptViewModel(
        title: 'Action not submitted',
        summary:
            '${_actionLabel(action)} requires a dedicated review form. No control-plane state changed.',
        tone: EvidenceTone.information,
      ),
    );
  }

  @override
  void refreshActivity() {
    unawaited(_refreshActivity());
  }

  Future<void> _refreshActivity() async {
    final api = _api;
    final session = _session;
    if (api == null ||
        session == null ||
        !session.permissions.any(
          (permission) => permission.wireValue == 'audit.read',
        )) {
      return;
    }
    try {
      final events = _mapper.activity(await api.auditEvents());
      _update(
        activity: events.isEmpty
            ? const LoadableViewModel.empty(
                message: 'No audit events have been recorded.',
              )
            : LoadableViewModel<List<ActivityEventViewModel>>.ready(events),
      );
    } catch (error) {
      if (await _handleSessionError(error)) return;
      _update(activity: LoadableViewModel.error(_safeError(error)));
    }
  }

  Future<void> _refreshAccess() async {
    final api = _api;
    final session = _session;
    if (api == null || session == null) return;
    try {
      final results = await Future.wait<Object?>(<Future<Object?>>[
        api.sessions(),
        _optionalBreakGlassInventory(api),
      ]);
      final model = _mapper.access(
        sessions: results[0]! as List<Map<String, Object?>>,
        recovery: results[1] as Map<String, Object?>?,
        currentSessionId: session.sessionId,
      );
      _update(
        accessManagement: LoadableViewModel<AccessManagementViewModel>.ready(
          model,
        ),
      );
    } catch (error) {
      if (await _handleSessionError(error)) return;
      _update(accessManagement: LoadableViewModel.error(_safeError(error)));
    }
  }

  Future<Map<String, Object?>?> _optionalBreakGlassInventory(
    MeshApi api,
  ) async {
    try {
      return await api.breakGlassInventory();
    } catch (_) {
      return null;
    }
  }

  @override
  void revokeSession(String sessionId) {
    unawaited(_revokeSession(sessionId));
  }

  Future<void> _revokeSession(String sessionId) async {
    final api = _api;
    if (api == null) return;
    try {
      await api.revokeSession(sessionId);
      if (sessionId == _session?.sessionId) {
        await _signOut(callServer: false);
        return;
      }
      await _refreshAccess();
      _update(
        receipt: const OperationReceiptViewModel(
          title: 'Session revoked',
          summary: 'The selected browser session can no longer authenticate.',
          tone: EvidenceTone.healthy,
        ),
      );
    } catch (error) {
      if (await _handleSessionError(error)) return;
      _operationError('Session revocation failed', error);
    }
  }

  @override
  Future<MutationSubmissionResult> revokeAccessSession(
    RevokeSessionRequest request,
  ) async {
    final api = _api;
    if (api == null || _session == null) {
      return const MutationSubmissionResult.failed(
        'Sign in before revoking a session.',
      );
    }
    try {
      await api.revokeSession(request.sessionId);
      if (request.current || request.sessionId == _session?.sessionId) {
        await _signOut(callServer: false);
        return const MutationSubmissionResult.succeeded();
      }
      await _refreshAccess();
      _update(
        receipt: OperationReceiptViewModel(
          title: 'Session revoked',
          summary:
              'The web or desktop session for ${request.principal} can no longer authenticate.',
          tone: EvidenceTone.healthy,
          verification: 'The control plane removed the selected session.',
        ),
      );
      return const MutationSubmissionResult.succeeded();
    } catch (error) {
      if (await _handleSessionError(error)) {
        return const MutationSubmissionResult.failed(
          'The Mesh session expired. Sign in again.',
        );
      }
      return MutationSubmissionResult.failed(_safeError(error));
    }
  }

  @override
  void createRecoveryCode() {
    unawaited(createRecoveryAccess());
  }

  @override
  Future<MutationSubmissionResult> createRecoveryAccess() async {
    final api = _api;
    if (api == null || _session == null) {
      return const MutationSubmissionResult.failed(
        'Sign in before creating recovery access.',
      );
    }
    try {
      final registration = await api.createRecoveryAccess(
        expiresAt: DateTime.now().toUtc().add(const Duration(days: 7)),
      );
      _update(
        oneTimeSecret: OneTimeSecretViewModel(
          id: registration.summary.id,
          title: 'Recovery code created',
          detail:
              'This one-use recovery code expires ${_displayTime(registration.summary.expiresAt)}. It cannot be retrieved again.',
          items: <OneTimeSecretItemViewModel>[
            OneTimeSecretItemViewModel(
              label: 'Recovery code',
              value: registration.credential,
              copyConfirmation: 'Recovery code copied',
            ),
          ],
          custodyLabel:
              'I stored this recovery code outside the Mesh host and identity provider.',
        ),
        receipt: OperationReceiptViewModel(
          title: 'Recovery access registered',
          summary:
              '${registration.summary.id} is usable once until ${_displayTime(registration.summary.expiresAt)}.',
          tone: EvidenceTone.healthy,
          verification:
              'The locally generated credential was registered over the authenticated control-plane session.',
        ),
      );
      await _refreshAccess();
      return const MutationSubmissionResult.succeeded();
    } catch (error) {
      if (await _handleSessionError(error)) {
        return const MutationSubmissionResult.failed(
          'The Mesh session expired. Sign in again.',
        );
      }
      return MutationSubmissionResult.failed(_safeError(error));
    }
  }

  @override
  void updateThemeMode(ThemeMode mode) {
    _update(
      preferences: PreferencesViewModel(
        themeMode: mode,
        notificationsEnabled: value.preferences.notificationsEnabled,
        backgroundMonitoringEnabled:
            value.preferences.backgroundMonitoringEnabled,
      ),
    );
  }

  @override
  void updateNotifications(bool enabled) {
    _update(
      preferences: PreferencesViewModel(
        themeMode: value.preferences.themeMode,
        notificationsEnabled: enabled,
        backgroundMonitoringEnabled:
            value.preferences.backgroundMonitoringEnabled,
      ),
      receipt: OperationReceiptViewModel(
        title: enabled ? 'Notifications requested' : 'Notifications disabled',
        summary: enabled
            ? 'Mesh Desktop will request OS notification permission when alert delivery is implemented.'
            : 'Mesh Desktop will not deliver OS notifications.',
        tone: EvidenceTone.information,
      ),
    );
  }

  @override
  void updateBackgroundMonitoring(bool enabled) {
    _update(
      preferences: PreferencesViewModel(
        themeMode: value.preferences.themeMode,
        notificationsEnabled: value.preferences.notificationsEnabled,
        backgroundMonitoringEnabled: enabled,
      ),
      receipt: OperationReceiptViewModel(
        title: enabled
            ? 'Background monitoring not enabled'
            : 'Background monitoring disabled',
        summary: enabled
            ? 'Mesh Desktop quits when its window closes. No background process was started.'
            : 'Mesh Desktop stops polling when it is not active.',
        tone: EvidenceTone.information,
      ),
    );
  }

  @override
  void openPublicDocumentation() {
    final origin = _selectedProfile?.profile.origin;
    if (origin == null) return;
    unawaited(_open(origin.resolve('/docs.html')));
  }

  @override
  void openAPIReference() {
    final origin = _selectedProfile?.profile.origin;
    if (origin == null) return;
    unawaited(_open(origin.resolve('/api-docs.html')));
  }

  Future<void> _open(Uri uri) async {
    try {
      await _browser.open(uri);
    } catch (error) {
      _operationError('Could not open the system browser', error);
    }
  }

  @override
  void openSystemSettings() {
    _update(
      receipt: const OperationReceiptViewModel(
        title: 'Use system settings',
        summary:
            'Open your desktop environment settings to manage notifications and accessibility preferences.',
        tone: EvidenceTone.information,
      ),
    );
  }

  @override
  void acknowledgeOneTimeSecret() {
    _update(oneTimeSecret: null);
  }

  @override
  void scrubOneTimeSecret() {
    _update(oneTimeSecret: null);
  }

  @override
  void dismissReceipt() {
    _update(receipt: null);
  }

  void _startFleetPolling() {
    unawaited(_fleetPoller?.dispose());
    _fleetPoller = LifecyclePoller(
      lifecycle: _lifecycle,
      interval: const Duration(seconds: 15),
      poll: () => _refreshFleet(showLoading: false),
      onError: (_, _) {},
    )..start();
  }

  Future<MeshNetwork> _freshNetwork(MeshApi api, String networkId) async {
    final networks = await api.networks();
    _rawNetworks = networks;
    for (final candidate in networks) {
      if (candidate['id'] == networkId) {
        return MeshNetwork.fromJson(candidate);
      }
    }
    throw const MeshApiProtocolException(
      'The selected network is no longer present.',
    );
  }

  String _nextMutationRequestId() =>
      'desktop_${DateTime.now().toUtc().microsecondsSinceEpoch}_${++_mutationSequence}';

  void _showEnrollment(NodeEnrollment enrollment, Uri origin) {
    final command =
        "read -rsp 'Enrollment token: ' MESH_TOKEN_INPUT && "
        "printf '\\n' && "
        "printf '%s\\n' \"\$MESH_TOKEN_INPUT\" | "
        'sudo /usr/local/bin/meshctl enroll '
        "--server '${origin.toString()}' "
        '--token-file - '
        '--state /var/lib/mesh-agent/state.json '
        '--output /var/lib/mesh-agent/nebula '
        '--nebula /usr/local/bin/nebula '
        '--nebula-cert /usr/local/bin/nebula-cert';
    _update(
      oneTimeSecret: OneTimeSecretViewModel(
        id: 'enrollment_${enrollment.node.id}',
        title: 'Enroll ${enrollment.node.name}',
        detail:
            'Run this only on the target host after installing the authenticated Mesh runtime. The token expires ${_displayTime(enrollment.expiresAt)} and stops working after enrollment.',
        items: <OneTimeSecretItemViewModel>[
          OneTimeSecretItemViewModel(
            label: 'Enrollment token',
            value: enrollment.enrollmentToken,
            copyConfirmation: 'Enrollment token copied',
          ),
          OneTimeSecretItemViewModel(
            label: 'Enrollment command',
            value: command,
            copyConfirmation: 'Enrollment command copied',
            hiddenByDefault: false,
          ),
        ],
        custodyLabel:
            'I stored the token securely and will use it only on ${enrollment.node.name}.',
      ),
    );
  }

  Future<bool> _handleSessionError(Object error) async {
    if (error is MeshApiException && error.statusCode == 401) {
      await _signOut(callServer: false);
      _connectionError('The Mesh session expired. Sign in again.');
      return true;
    }
    return false;
  }

  void _select(_SavedProfile saved) {
    _disconnect();
    final cookieJar = MeshCookieJar(saved.profile);
    final transport = DartIoJsonTransport(
      profile: saved.profile,
      cookieJar: cookieJar,
    );
    _transport = transport;
    _api = MeshApi(profile: saved.profile, transport: transport);
  }

  _SavedProfile _addProfile(
    ConnectionProfile profile, {
    required String displayName,
    required bool tlsTrusted,
  }) {
    final existing = _profiles
        .where((candidate) => candidate.profile == profile)
        .firstOrNull;
    if (existing != null) {
      existing
        ..displayName = displayName
        ..tlsTrusted = tlsTrusted;
      return existing;
    }
    final saved = _SavedProfile(
      id: 'profile_${++_profileSequence}',
      displayName: displayName,
      profile: profile,
      tlsTrusted: tlsTrusted,
    );
    _profiles.add(saved);
    return saved;
  }

  _SavedProfile? get _selectedProfile {
    final selectedId = value.connection.selectedProfileId;
    return _profiles.where((profile) => profile.id == selectedId).firstOrNull;
  }

  List<ConnectionProfileViewModel> _profileViewModels() => List.unmodifiable(
    _profiles.map(
      (profile) => ConnectionProfileViewModel(
        id: profile.id,
        displayName: profile.displayName,
        origin: profile.profile.origin,
        tlsTrusted: profile.tlsTrusted,
      ),
    ),
  );

  Map<String, Object?>? _healthReport(String networkId) {
    final fleet = _rawFleet;
    if (fleet == null) return null;
    final networks = fleet['networks'];
    if (networks is! List<Object?>) return null;
    for (final value in networks) {
      if (value is! Map<String, Object?>) continue;
      final network = value['network'];
      if (network is Map<String, Object?> && network['id'] == networkId) {
        return value;
      }
    }
    return null;
  }

  void _disconnect() {
    _transport?.close(force: true);
    _transport = null;
    _api = null;
  }

  void _connectionMessage(String message, {required LoadPhase phase}) {
    final selected = _selectedProfile;
    _update(
      connection: ConnectionViewModel(
        profiles: _profileViewModels(),
        selectedProfileId: selected?.id,
        methods: selected?.methods ?? const <AuthenticationMethod>[],
        phase: phase,
        message: message,
      ),
    );
  }

  void _connectionError(String message) =>
      _connectionMessage(message, phase: LoadPhase.error);

  void _operationError(String title, Object error) {
    _update(
      receipt: OperationReceiptViewModel(
        title: title,
        summary: _safeError(error),
        tone: EvidenceTone.critical,
      ),
    );
  }

  String _safeError(Object error) {
    if (error is MeshApiException) {
      return switch (error.statusCode) {
        401 => 'Authentication was rejected or expired.',
        403 => '${error.message} Check the current role and request proof.',
        409 => '${error.message} Reload current state before trying again.',
        429 ||
        503 => '${error.message} Mesh is busy; retry after a short delay.',
        _ => error.message,
      };
    }
    if (error is MeshApiProtocolException) return error.message;
    if (error is ApiProtocolException) return error.message;
    if (error is BrowserLaunchException) return error.message;
    if (error is FormatException) return error.message;
    if (error is SessionPersistenceException) return error.message;
    return 'The Mesh request failed. Check the control-plane URL and network connection.';
  }

  void _update({
    ConnectionViewModel? connection,
    Object? accessContext = _unchanged,
    LoadableViewModel<FleetViewModel>? fleet,
    LoadableViewModel<NetworkOverviewViewModel>? selectedNetwork,
    LoadableViewModel<List<ActivityEventViewModel>>? activity,
    LoadableViewModel<AccessManagementViewModel>? accessManagement,
    PreferencesViewModel? preferences,
    Object? oneTimeSecret = _unchanged,
    Object? receipt = _unchanged,
  }) {
    if (_disposed) return;
    value = MeshDesktopViewModel(
      connection: connection ?? value.connection,
      accessContext: identical(accessContext, _unchanged)
          ? value.accessContext
          : accessContext as AccessContextViewModel?,
      fleet: fleet ?? value.fleet,
      selectedNetwork: selectedNetwork ?? value.selectedNetwork,
      activity: activity ?? value.activity,
      accessManagement: accessManagement ?? value.accessManagement,
      preferences: preferences ?? value.preferences,
      oneTimeSecret: identical(oneTimeSecret, _unchanged)
          ? value.oneTimeSecret
          : oneTimeSecret as OneTimeSecretViewModel?,
      receipt: identical(receipt, _unchanged)
          ? value.receipt
          : receipt as OperationReceiptViewModel?,
    );
  }

  @override
  void dispose() {
    _disposed = true;
    ++_authenticationGeneration;
    unawaited(_fleetPoller?.dispose());
    if (_ownsLifecycle) {
      (_lifecycle as WidgetsBindingLifecycleSource).dispose();
    }
    _disconnect();
    super.dispose();
  }
}

const Object _unchanged = Object();

final class _SavedProfile {
  _SavedProfile({
    required this.id,
    required this.displayName,
    required this.profile,
    required this.tlsTrusted,
  });

  final String id;
  String displayName;
  final ConnectionProfile profile;
  bool tlsTrusted;
  List<AuthenticationMethod> methods = const <AuthenticationMethod>[];
}

List<AuthenticationMethod> _presentationMethods(
  AuthenticationMethods methods,
) => <AuthenticationMethod>[
  if (methods.oidc) AuthenticationMethod.oidc,
  if (methods.legacyBrowserLogin) AuthenticationMethod.legacyToken,
  if (methods.breakGlass) AuthenticationMethod.breakGlass,
];

MeshRole _presentationRole(String value) => switch (value) {
  'viewer' => MeshRole.viewer,
  'operator' => MeshRole.operator,
  'admin' => MeshRole.admin,
  _ => throw FormatException('Unsupported Mesh role "$value".'),
};

String _actionLabel(String value) {
  final words = value.replaceAll('-', ' ').trim();
  if (words.isEmpty) return 'This action';
  return '${words[0].toUpperCase()}${words.substring(1)}';
}

String _displayTime(DateTime value) {
  final local = value.toLocal();
  String two(int part) => part.toString().padLeft(2, '0');
  return '${local.year}-${two(local.month)}-${two(local.day)} '
      '${two(local.hour)}:${two(local.minute)}';
}
