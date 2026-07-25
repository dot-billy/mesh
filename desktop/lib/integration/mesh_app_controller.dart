import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:mesh_desktop/app/app.dart';
import 'package:mesh_desktop/core/auth/rbac.dart' as auth;
import 'package:mesh_desktop/core/auth/secure_session_store.dart';
import 'package:mesh_desktop/core/auth/session_models.dart' as core;
import 'package:mesh_desktop/core/connection/connection_profile.dart';
import 'package:mesh_desktop/core/platform/apple_admin_notifications.dart';
import 'package:mesh_desktop/core/platform/apple_managed_configuration.dart';
import 'package:mesh_desktop/core/platform/system_browser.dart';
import 'package:mesh_desktop/core/platform/mobile_security.dart';
import 'package:mesh_desktop/core/polling/lifecycle_poller.dart';
import 'package:mesh_desktop/core/support/apple_admin_diagnostic_bundle.dart';
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
    ProtectedDataEvents? protectedDataEvents,
    AppleManagedConfigurationSource? managedConfigurationSource,
    AppleAdminNotificationSink? notificationSink,
    Future<void> Function(Duration)? delay,
    DateTime Function()? now,
    SecretClipboard? diagnosticClipboard,
    String? diagnosticApplicationVersion,
    String? diagnosticApplicationBuild,
    String? diagnosticReleaseIdentity,
    this._mapper = const MeshPresentationMapper(),
  }) : _sessionStore =
           sessionStore ?? SecureSessionStore(FlutterSecretStorage()),
       _browser = browser ?? UrlLauncherSystemBrowser(),
       _ownsLifecycle = lifecycle == null,
       _lifecycle = lifecycle ?? WidgetsBindingLifecycleSource(),
       _ownsProtectedDataEvents = protectedDataEvents == null,
       _protectedDataEvents =
           protectedDataEvents ?? MethodChannelProtectedDataEvents(),
       _managedConfigurationSource =
           managedConfigurationSource ??
           const MethodChannelAppleManagedConfigurationSource(),
       _notificationSink =
           notificationSink ?? const MethodChannelAppleAdminNotificationSink(),
       _delay = delay ?? Future<void>.delayed,
       _now = now ?? DateTime.now,
       _diagnosticClipboard =
           diagnosticClipboard ?? const ExpiringSecretClipboard(),
       _diagnosticApplicationVersion =
           diagnosticApplicationVersion ??
           const String.fromEnvironment(
             'MESH_APP_VERSION',
             defaultValue: '0.1.0',
           ),
       _diagnosticApplicationBuild =
           diagnosticApplicationBuild ??
           const String.fromEnvironment('MESH_APP_BUILD', defaultValue: '1'),
       _diagnosticReleaseIdentity =
           diagnosticReleaseIdentity ??
           const String.fromEnvironment(
             'MESH_SOURCE_COMMIT',
             defaultValue: 'unavailable',
           ),
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
  final bool _ownsProtectedDataEvents;
  final ProtectedDataEvents _protectedDataEvents;
  final AppleManagedConfigurationSource _managedConfigurationSource;
  final AppleAdminNotificationSink _notificationSink;
  final Future<void> Function(Duration) _delay;
  final DateTime Function() _now;
  final SecretClipboard _diagnosticClipboard;
  final String _diagnosticApplicationVersion;
  final String _diagnosticApplicationBuild;
  final String _diagnosticReleaseIdentity;
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
  StreamSubscription<AppLifecycleState>? _custodySubscription;
  AppleManagedConfiguration? _managedConfiguration;
  bool _managedConfigurationRejected = false;
  bool _managedConfigurationRefreshing = false;
  bool _localNotificationsEnabled = false;
  bool _notificationPermissionGranted = false;
  final AppleAdminNotificationTransition _notificationTransition =
      AppleAdminNotificationTransition();
  final StreamController<int> _authenticationChanges =
      StreamController<int>.broadcast(sync: true);

  Future<void> initialize() async {
    _startCustodyObservers();
    try {
      _applyManagedConfiguration(await _managedConfigurationSource.load());
    } on AppleManagedConfigurationException {
      await _rejectManagedConfiguration();
      return;
    }
    final profileStorageMessage = await _loadConnectionProfiles();
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
              : 'Secure session storage is unavailable. Unlock the device or operating-system credential store, then restart Mesh Admin. You can still sign in, but the session will not be saved.',
        ),
      );
      return;
    } catch (_) {
      _update(
        connection: ConnectionViewModel(
          profiles: _profileViewModels(),
          phase: LoadPhase.ready,
          message:
              'Secure session storage is unavailable. Unlock the device or operating-system credential store, then restart Mesh Admin. You can still sign in, but the session will not be saved.',
        ),
      );
      return;
    }
    if (stored == null) {
      if (_managedConfiguration?.controlPlaneOrigin != null) {
        await _connectManagedOriginIfPresent();
      } else if (_profiles.isNotEmpty) {
        final saved = _profiles.first;
        await _addConnection(
          ConnectionRequest(
            displayName: saved.displayName,
            origin: saved.profile.origin,
          ),
        );
      } else if (profileStorageMessage != null) {
        _update(
          connection: ConnectionViewModel(
            profiles: _profileViewModels(),
            phase: LoadPhase.ready,
            message: profileStorageMessage,
          ),
        );
      }
      return;
    }
    final restoredSession = stored;

    if (_managedOriginLocked &&
        restoredSession.profile.origin !=
            _managedConfiguration!.controlPlaneOrigin!.origin) {
      await _sessionStore.clear().catchError((_) {});
      await _connectManagedOriginIfPresent();
      return;
    }

    try {
      final existing = _profiles
          .where((profile) => profile.profile == restoredSession.profile)
          .firstOrNull;
      final saved = _addProfile(
        restoredSession.profile,
        displayName:
            existing?.displayName ?? restoredSession.profile.origin.host,
        tlsTrusted: true,
      );
      _update(
        connection: ConnectionViewModel(
          profiles: _profileViewModels(),
          selectedProfileId: saved.id,
          methods: saved.methods,
          phase: LoadPhase.loading,
          message: 'Restoring the saved Mesh session…',
        ),
      );
      _select(saved);
      restoredSession.restoreInto(_transport!.cookieJar);
      final session = await _api!.currentSession();
      try {
        saved.methods = _presentationMethods(
          await _api!.authenticationMethods(),
        );
      } catch (_) {
        // A valid restored session remains usable when the public discovery
        // endpoint is temporarily unavailable. A later launch can retry it.
      }
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
      _enforceManagedOrigin(profile);
      final saved = _addProfile(
        profile,
        displayName: request.displayName,
        tlsTrusted: false,
      );
      _select(saved);
      final methods = await _api!.authenticationMethods();
      saved.tlsTrusted = true;
      saved.methods = _presentationMethods(methods);
      final profilesPersisted = await _persistConnectionProfiles();
      _update(
        connection: ConnectionViewModel(
          profiles: _profileViewModels(),
          selectedProfileId: saved.id,
          methods: saved.methods,
          phase: LoadPhase.ready,
          message: saved.methods.isEmpty
              ? 'This control plane did not advertise a supported desktop sign-in method.'
              : profilesPersisted
              ? 'System TLS trust verified. Choose a sign-in method.'
              : 'System TLS trust verified, but the saved control-plane list could not be updated. Unlock the device or operating-system credential store before relaunching Mesh Admin.',
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
    try {
      _enforceManagedOrigin(saved.profile);
    } on FormatException catch (error) {
      _connectionError(error.message);
      return;
    }
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
    final generation = _invalidateAuthentication();
    _update(
      connection: ConnectionViewModel(
        profiles: _profileViewModels(),
        selectedProfileId: selected.id,
        methods: selected.methods,
        phase: LoadPhase.loading,
        canCancelAuthentication: method == AuthenticationMethod.oidc,
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
      'Approve this sign-in in the browser. Mesh Admin will continue automatically.',
      phase: LoadPhase.loading,
      canCancelAuthentication: true,
    );
    while (generation == _authenticationGeneration &&
        !attempt.isExpiredAt(_now().toUtc())) {
      await _waitForAuthorizationPoll(attempt.pollInterval, generation);
      await _waitForForegroundAuthorization(attempt, generation);
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
        if (error.statusCode == 429 || error.statusCode == 503) {
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

  @override
  void cancelAuthentication() {
    _invalidateAuthentication();
    _connectionMessage(
      'Desktop sign-in cancelled. No browser credential was stored.',
      phase: LoadPhase.ready,
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
    final permissions = _presentationPermissions(session.permissions);
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
        permissions: permissions,
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
              message: 'This session cannot read audit events.',
            ),
      accessManagement: permissions.contains(MeshPermission.identityManage)
          ? const LoadableViewModel.loading(
              message: 'Loading access inventory…',
            )
          : const LoadableViewModel.initial(),
    );
    if (persist) {
      final now = _now().toUtc();
      final expires =
          session.absoluteExpiresAt ??
          session.idleExpiresAt ??
          now.add(const Duration(hours: 1));
      final persisted = PersistedDesktopSession(
        profile: selected.profile,
        cookies: transport.cookieJar.snapshot(),
        issuedAt: session.createdAt ?? now,
        expiresAt: expires,
      );
      try {
        await _sessionStore.save(persisted);
      } catch (_) {
        _update(
          receipt: const OperationReceiptViewModel(
            title: 'Session is not saved',
            summary:
                'Secure OS credential storage was unavailable. This session will end when Mesh Admin closes.',
            tone: EvidenceTone.warning,
          ),
        );
      }
    }
    await _refreshFleet(showLoading: false);
    final authoritativeSession = _session;
    if (authoritativeSession != null) {
      await Future.wait<void>(<Future<void>>[
        if (authoritativeSession.permissions.contains(
          auth.MeshPermission.auditRead,
        ))
          _refreshActivity(),
        if (authoritativeSession.permissions.contains(
          auth.MeshPermission.identityManage,
        ))
          _refreshAccess(),
      ]);
    }
    if (_session == null) return;
    _startFleetPolling();
  }

  @override
  void signOut() {
    unawaited(_signOut());
  }

  Future<void> _signOut({bool callServer = true}) async {
    _invalidateAuthentication();
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
      final authority = await _refreshSessionAuthority(api);
      if (authority == null || _session == null) return;
      if (!_session!.permissions.contains(auth.MeshPermission.networksRead)) {
        _rawNetworks = const <Map<String, Object?>>[];
        _rawFleet = null;
        _update(
          fleet: const LoadableViewModel.empty(
            message: 'This session cannot read network inventory.',
          ),
          selectedNetwork: const LoadableViewModel.initial(),
        );
        return;
      }
      final result = await Future.wait<Object>(<Future<Object>>[
        api.networks(),
        api.fleetHealth(),
      ]);
      _rawNetworks = result[0] as List<Map<String, Object?>>;
      _rawFleet = result[1] as Map<String, Object?>;
      final model = _mapper.fleet(_rawNetworks, _rawFleet!);
      _considerFleetNotification(model);
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
      if (authority.auditReadGained) {
        await _refreshActivity();
      }
      if (authority.identityManageGained) {
        await _refreshAccess();
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

  Future<_AuthorityRefresh?> _refreshSessionAuthority(MeshApi api) async {
    late final core.SessionContext refreshed;
    try {
      refreshed = await api.currentSession();
    } on MeshApiException catch (error) {
      if (await _handleSessionError(error)) return null;
      rethrow;
    } on Object {
      await _signOut(callServer: false);
      _connectionError(
        'The Mesh session authority could not be verified. Sign in again.',
      );
      return null;
    }

    final previous = _session;
    if (previous == null) return null;
    if (!_sameSessionIdentity(previous, refreshed)) {
      await _signOut(callServer: false);
      _connectionError(
        'The Mesh session identity changed unexpectedly. Sign in again.',
      );
      return null;
    }

    final hadAudit = previous.permissions.contains(
      auth.MeshPermission.auditRead,
    );
    final hasAudit = refreshed.permissions.contains(
      auth.MeshPermission.auditRead,
    );
    final hadIdentity = previous.permissions.contains(
      auth.MeshPermission.identityManage,
    );
    final hasIdentity = refreshed.permissions.contains(
      auth.MeshPermission.identityManage,
    );
    final authorityChanged =
        previous.role != refreshed.role ||
        !_samePermissions(previous.permissions, refreshed.permissions);
    _session = refreshed;

    final selected = _selectedProfile;
    if (selected == null) {
      await _signOut(callServer: false);
      _connectionError(
        'The Mesh session origin could not be verified. Sign in again.',
      );
      return null;
    }
    if (authorityChanged) {
      _eraseOneTimeMaterial();
    }
    _update(
      accessContext: AccessContextViewModel(
        displayName: refreshed.principal.label,
        role: _presentationRole(refreshed.role.wireValue),
        permissions: _presentationPermissions(refreshed.permissions),
        controlPlaneName: selected.displayName,
        origin: selected.profile.origin,
      ),
      activity: hasAudit
          ? (!hadAudit
                ? const LoadableViewModel.loading(
                    message: 'Loading audit events…',
                  )
                : null)
          : const LoadableViewModel.empty(
              message: 'This session cannot read audit events.',
            ),
      accessManagement: hasIdentity
          ? (!hadIdentity
                ? const LoadableViewModel.loading(
                    message: 'Loading access inventory…',
                  )
                : null)
          : const LoadableViewModel.initial(),
    );
    return _AuthorityRefresh(
      auditReadGained: !hadAudit && hasAudit,
      identityManageGained: !hadIdentity && hasIdentity,
    );
  }

  @override
  void selectNetwork(String networkId) {
    _eraseOneTimeMaterial();
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
    _eraseOneTimeMaterial();
    _update(selectedNetwork: const LoadableViewModel.initial());
  }

  @override
  void runNextNetworkAction(String networkId) {
    _update(
      receipt: const OperationReceiptViewModel(
        title: 'Review required',
        summary:
            'This setup step has not been submitted. Mesh Admin will add its guided review form before enabling the mutation.',
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
  Future<MutationSubmissionResult> cancelPendingEnrollment(
    CancelPendingEnrollmentRequest request,
  ) async {
    final api = _api;
    if (api == null || _session == null) {
      return const MutationSubmissionResult.failed(
        'Sign in before cancelling a pending enrollment.',
      );
    }
    if (request.confirmedName != request.nodeName) {
      return const MutationSubmissionResult.failed(
        'The confirmation name did not match the selected node.',
      );
    }
    try {
      final network = await _freshNetwork(api, request.networkId);
      final receipt = await api.cancelPendingEnrollment(
        networkId: request.networkId,
        nodeId: request.nodeId,
        expectedConfigRevision: network.configRevision,
        confirmationName: request.confirmedName,
      );
      await _refreshFleet(showLoading: false);
      _update(
        receipt: OperationReceiptViewModel(
          title: 'Pending enrollment cancelled',
          summary:
              '${receipt.name} was removed and ${receipt.enrollmentRecordsInvalidated} one-time credential record${receipt.enrollmentRecordsInvalidated == 1 ? '' : 's'} invalidated.',
          tone: EvidenceTone.healthy,
          revision: receipt.configRevision,
          verification:
              'The control plane released ${receipt.routedSubnetReservationsReleased} routed-subnet reservation${receipt.routedSubnetReservationsReleased == 1 ? '' : 's'} and confirmed the pending identity no longer exists.',
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
      final current = _session;
      if (current == null ||
          current.sessionId != session.sessionId ||
          current.principal.id != session.principal.id ||
          !current.permissions.contains(auth.MeshPermission.auditRead)) {
        return;
      }
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
    if (api == null ||
        session == null ||
        !session.permissions.contains(auth.MeshPermission.identityManage)) {
      return;
    }
    try {
      final results = await Future.wait<Object?>(<Future<Object?>>[
        api.sessions(),
        _optionalBreakGlassInventory(api),
      ]);
      final current = _session;
      if (current == null ||
          current.sessionId != session.sessionId ||
          current.principal.id != session.principal.id ||
          !current.permissions.contains(auth.MeshPermission.identityManage)) {
        return;
      }
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
              'The web or Mesh Admin session for ${request.principal} can no longer authenticate.',
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
    if (_managedConfiguration?.notificationsEnabled != null) {
      _update(
        receipt: const OperationReceiptViewModel(
          title: 'Notifications managed by your organization',
          summary:
              'This setting cannot be changed locally while MDM policy supplies it.',
          tone: EvidenceTone.information,
        ),
      );
      return;
    }
    unawaited(_updateNotifications(enabled));
  }

  Future<void> _updateNotifications(bool enabled) async {
    final granted = enabled
        ? await _notificationSink.requestAuthorization()
        : false;
    _localNotificationsEnabled = enabled && granted;
    _notificationPermissionGranted = granted;
    _notificationTransition.reset();
    _update(
      preferences: PreferencesViewModel(
        themeMode: value.preferences.themeMode,
        notificationsEnabled: _localNotificationsEnabled,
        backgroundMonitoringEnabled:
            value.preferences.backgroundMonitoringEnabled,
      ),
      receipt: OperationReceiptViewModel(
        title: !enabled
            ? 'Notifications disabled'
            : granted
            ? 'Notifications enabled'
            : 'Notification permission unavailable',
        summary: !enabled
            ? 'Mesh Admin will not deliver OS notifications.'
            : granted
            ? 'Mesh Admin will notify only when fresh fleet evidence changes to a warning or critical state. Notifications contain no names, identifiers, or server text.'
            : 'The operating system did not grant notification permission. Mesh Admin will not deliver notifications.',
        tone: EvidenceTone.information,
      ),
    );
  }

  void _considerFleetNotification(FleetViewModel fleet) {
    if (!value.preferences.notificationsEnabled ||
        !_notificationPermissionGranted) {
      _notificationTransition.reset();
      return;
    }
    final event = _notificationTransition.observe(
      hasCritical: fleet.alerts.any(
        (alert) => alert.tone == EvidenceTone.critical,
      ),
      hasWarning: fleet.alerts.any(
        (alert) => alert.tone == EvidenceTone.warning,
      ),
    );
    if (event != null) {
      unawaited(_notificationSink.deliver(event).catchError((_) {}));
    }
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
            ? 'Mesh Admin quits when its window closes. No background process was started.'
            : 'Mesh Admin stops polling when it is not active.',
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
            'Open system settings to manage notifications and accessibility preferences.',
        tone: EvidenceTone.information,
      ),
    );
  }

  @override
  void copyDiagnosticBundle() {
    unawaited(_copyDiagnosticBundle());
  }

  @override
  void eraseLocalData() {
    unawaited(_eraseLocalData());
  }

  Future<void> _eraseLocalData() async {
    _invalidateAuthentication();
    await _fleetPoller?.dispose();
    _fleetPoller = null;
    final serverLogoutConfirmed = await _api
        ?.logout()
        .then((_) => true)
        .catchError((_) => false);
    _transport?.cookieJar.clear();
    _session = null;
    _eraseOneTimeMaterial();

    try {
      await _sessionStore.clearAll();
    } on SessionPersistenceException {
      _disconnect();
      _update(
        connection: ConnectionViewModel(
          profiles: _profileViewModels(),
          phase: LoadPhase.error,
          message:
              'Secure local data could not be fully erased. Unlock the device or operating-system credential store and retry before uninstalling.',
        ),
        accessContext: null,
        fleet: const LoadableViewModel.initial(),
        selectedNetwork: const LoadableViewModel.initial(),
        activity: const LoadableViewModel.initial(),
        accessManagement: const LoadableViewModel.initial(),
        preferences: PreferencesViewModel(
          notificationsEnabled:
              _managedConfiguration?.notificationsEnabled ?? false,
        ),
        oneTimeSecret: null,
        receipt: const OperationReceiptViewModel(
          title: 'Local data not fully erased',
          summary:
              'At least one exact Keychain item could not be deleted. Retry before removing the application.',
          tone: EvidenceTone.warning,
        ),
      );
      return;
    }

    _profiles.clear();
    _disconnect();
    _localNotificationsEnabled = false;
    _notificationPermissionGranted = false;
    _notificationTransition.reset();
    _update(
      connection: const ConnectionViewModel(
        phase: LoadPhase.ready,
        message:
            'Local Mesh Admin data erased. Organization-managed settings and operating-system permissions remain outside the app.',
      ),
      accessContext: null,
      fleet: const LoadableViewModel.initial(),
      selectedNetwork: const LoadableViewModel.initial(),
      activity: const LoadableViewModel.initial(),
      accessManagement: const LoadableViewModel.initial(),
      preferences: PreferencesViewModel(
        notificationsEnabled:
            _managedConfiguration?.notificationsEnabled ?? false,
      ),
      oneTimeSecret: null,
      receipt: OperationReceiptViewModel(
        title: 'Local Mesh Admin data erased',
        summary: serverLogoutConfirmed != true
            ? 'The Keychain session and saved control-plane profiles were deleted. Server-side session revocation could not be confirmed while offline.'
            : 'The Keychain session and saved control-plane profiles were deleted.',
        tone: serverLogoutConfirmed != true
            ? EvidenceTone.warning
            : EvidenceTone.healthy,
        verification:
            'Organization-managed profiles, operating-system permissions, server records, and any separately installed Mesh Node were not changed.',
      ),
    );
  }

  Future<void> _copyDiagnosticBundle() async {
    final platform = switch (defaultTargetPlatform) {
      TargetPlatform.macOS => AppleAdminDiagnosticPlatform.macos,
      TargetPlatform.iOS => AppleAdminDiagnosticPlatform.ios,
      _ => null,
    };
    if (platform == null) {
      _update(
        receipt: const OperationReceiptViewModel(
          title: 'Diagnostic bundle unavailable',
          summary:
              'The bounded Apple diagnostic bundle is available only in the macOS and iOS applications.',
          tone: EvidenceTone.unavailable,
        ),
      );
      return;
    }
    final now = _now().toUtc();
    final fleet = value.fleet.data;
    final age = fleet == null
        ? null
        : now
              .difference(fleet.generatedAt.toUtc())
              .inSeconds
              .clamp(0, 31_536_000);
    final role = switch (value.accessContext?.role) {
      MeshRole.viewer => AppleAdminDiagnosticRole.viewer,
      MeshRole.operator => AppleAdminDiagnosticRole.operator,
      MeshRole.admin => AppleAdminDiagnosticRole.admin,
      null => null,
    };
    final sessionState = value.authenticated
        ? AppleAdminDiagnosticSessionState.signedIn
        : value.connection.canCancelAuthentication
        ? AppleAdminDiagnosticSessionState.authorizing
        : AppleAdminDiagnosticSessionState.signedOut;
    try {
      final bundle = AppleAdminDiagnosticBundle(
        createdAt: now,
        platform: platform,
        applicationVersion: _diagnosticApplicationVersion,
        applicationBuild: _diagnosticApplicationBuild,
        releaseIdentity: _diagnosticReleaseIdentity,
        sessionState: sessionState,
        role: role,
        connectionState: _diagnosticLoadState(value.connection.phase),
        fleetState: _diagnosticLoadState(value.fleet.phase),
        networkState: _diagnosticLoadState(value.selectedNetwork.phase),
        activityState: _diagnosticLoadState(value.activity.phase),
        accessState: _diagnosticLoadState(value.accessManagement.phase),
        profileCount: value.connection.profiles.length,
        networkCount: fleet?.networks.length ?? 0,
        alertCount: fleet?.alerts.length ?? 0,
        fleetEvidenceAgeSeconds: age,
        oneTimeSecretVisible: value.oneTimeSecret != null,
        operationReceiptVisible: value.receipt != null,
        notificationsRequested: value.preferences.notificationsEnabled,
        backgroundMonitoringRequested:
            value.preferences.backgroundMonitoringEnabled,
      ).encode();
      await _diagnosticClipboard.copy(bundle);
      _update(
        receipt: OperationReceiptViewModel(
          title: 'Bounded diagnostic bundle copied',
          summary: platform == AppleAdminDiagnosticPlatform.ios
              ? 'The local-only iOS pasteboard item expires after two minutes. Mesh did not upload or persist it. Delete recipient copies when the approved support case closes.'
              : 'Mesh did not upload or persist the bundle, and the macOS clipboard does not expire automatically. Clear or replace it after transfer, and delete recipient copies when the approved support case closes.',
          tone: EvidenceTone.information,
          verification:
              'The schema excludes origins, names, IDs, credentials, raw errors, logs, and configuration bodies.',
        ),
      );
    } catch (_) {
      _update(
        receipt: const OperationReceiptViewModel(
          title: 'Diagnostic bundle not copied',
          summary:
              'The bounded diagnostic or expiring-copy boundary was unavailable. Mesh did not fall back to an unbounded export.',
          tone: EvidenceTone.unavailable,
        ),
      );
    }
  }

  AppleAdminDiagnosticLoadState _diagnosticLoadState(LoadPhase phase) {
    return switch (phase) {
      LoadPhase.initial => AppleAdminDiagnosticLoadState.initial,
      LoadPhase.loading => AppleAdminDiagnosticLoadState.loading,
      LoadPhase.ready => AppleAdminDiagnosticLoadState.ready,
      LoadPhase.empty => AppleAdminDiagnosticLoadState.empty,
      LoadPhase.error => AppleAdminDiagnosticLoadState.error,
    };
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
    )..start(pollImmediately: false);
  }

  void _startCustodyObservers() {
    if (_custodySubscription != null) {
      return;
    }
    _custodySubscription = _lifecycle.changes.listen((state) {
      if (state != AppLifecycleState.resumed) {
        _eraseOneTimeMaterial();
      } else {
        unawaited(_refreshManagedConfiguration());
      }
    });
    _protectedDataEvents.setUnavailableHandler(_eraseOneTimeMaterial);
  }

  void _eraseOneTimeMaterial() {
    if (!_disposed && value.oneTimeSecret != null) {
      _update(oneTimeSecret: null);
    }
  }

  int _invalidateAuthentication() {
    final generation = ++_authenticationGeneration;
    if (!_authenticationChanges.isClosed) {
      _authenticationChanges.add(generation);
    }
    return generation;
  }

  Future<void> _waitForForegroundAuthorization(
    DesktopAuthorizationAttempt attempt,
    int generation,
  ) async {
    while (_lifecycle.currentState != AppLifecycleState.resumed &&
        generation == _authenticationGeneration &&
        !attempt.isExpiredAt(_now().toUtc())) {
      final remaining = attempt.expiresAt.difference(_now().toUtc());
      await Future.any<void>(<Future<void>>[
        _lifecycle.changes
            .firstWhere((state) => state == AppLifecycleState.resumed)
            .then((_) {}),
        _authenticationChanges.stream
            .firstWhere((changed) => changed != generation)
            .then((_) {}),
        Future<void>.delayed(remaining),
      ]);
    }
    if (generation != _authenticationGeneration) {
      throw const MeshApiProtocolException(
        'Desktop authorization was cancelled.',
      );
    }
  }

  Future<void> _waitForAuthorizationPoll(
    Duration interval,
    int generation,
  ) async {
    await Future.any<void>(<Future<void>>[
      _delay(interval),
      _authenticationChanges.stream
          .firstWhere((changed) => changed != generation)
          .then((_) {}),
    ]);
    if (generation != _authenticationGeneration) {
      throw const MeshApiProtocolException(
        'Desktop authorization was cancelled.',
      );
    }
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
    final abandonsAuthorization =
        _session != null || value.connection.canCancelAuthentication;
    _invalidateAuthentication();
    _eraseOneTimeMaterial();
    if (abandonsAuthorization) {
      unawaited(_fleetPoller?.dispose());
      _fleetPoller = null;
      _transport?.cookieJar.clear();
      _session = null;
      unawaited(_sessionStore.clear().catchError((_) {}));
      _update(
        accessContext: null,
        fleet: const LoadableViewModel.initial(),
        selectedNetwork: const LoadableViewModel.initial(),
        activity: const LoadableViewModel.initial(),
        accessManagement: const LoadableViewModel.initial(),
        receipt: null,
      );
    }
    _disconnect();
    final cookieJar = MeshCookieJar(saved.profile);
    final transport = DartIoJsonTransport(
      profile: saved.profile,
      cookieJar: cookieJar,
    );
    _transport = transport;
    _api = MeshApi(profile: saved.profile, transport: transport, now: _now);
  }

  _SavedProfile _addProfile(
    ConnectionProfile profile, {
    required String displayName,
    required bool tlsTrusted,
  }) {
    final canonicalDisplayName = displayName.trim();
    if (canonicalDisplayName.isEmpty || canonicalDisplayName.length > 80) {
      throw const FormatException(
        'Control-plane display name must contain 1 to 80 characters.',
      );
    }
    final existing = _profiles
        .where((candidate) => candidate.profile == profile)
        .firstOrNull;
    if (existing != null) {
      existing
        ..displayName = canonicalDisplayName
        ..tlsTrusted = tlsTrusted;
      return existing;
    }
    if (_profiles.length >= SecureSessionStore.maximumConnectionProfiles) {
      throw const FormatException(
        'At most 8 control-plane profiles can be saved.',
      );
    }
    final saved = _SavedProfile(
      id: 'profile_${++_profileSequence}',
      displayName: canonicalDisplayName,
      profile: profile,
      tlsTrusted: tlsTrusted,
    );
    _profiles.add(saved);
    return saved;
  }

  bool get _managedOriginLocked =>
      _managedConfiguration != null &&
      !_managedConfiguration!.allowOriginChanges;

  void _enforceManagedOrigin(ConnectionProfile profile) {
    if (_managedConfigurationRejected) {
      throw const FormatException(
        'Organization-managed settings are invalid. Connection setup is disabled.',
      );
    }
    _managedConfiguration?.enforceControlPlaneOrigin(profile);
  }

  void _applyManagedConfiguration(AppleManagedConfiguration? configuration) {
    _managedConfiguration = configuration;
    _managedConfigurationRejected = false;
    _update(
      managedPolicy: configuration == null
          ? null
          : AppleManagedPolicyViewModel(
              valid: true,
              controlPlaneOrigin: configuration.controlPlaneOrigin?.origin,
              allowOriginChanges: configuration.allowOriginChanges,
              releaseChannel: configuration.releaseChannel,
              updateRing: configuration.updateRing,
              showLocalStatus: configuration.showLocalStatus,
              notificationsEnabled: configuration.notificationsEnabled,
            ),
      preferences: PreferencesViewModel(
        themeMode: value.preferences.themeMode,
        notificationsEnabled:
            configuration?.notificationsEnabled ?? _localNotificationsEnabled,
        backgroundMonitoringEnabled:
            value.preferences.backgroundMonitoringEnabled,
      ),
    );
    final managedNotifications = configuration?.notificationsEnabled;
    if (managedNotifications == false) {
      _notificationPermissionGranted = false;
      _notificationTransition.reset();
    } else if (managedNotifications == true &&
        !_notificationPermissionGranted) {
      unawaited(_enableManagedNotifications());
    }
  }

  Future<void> _enableManagedNotifications() async {
    final granted = await _notificationSink.requestAuthorization();
    if (_disposed || _managedConfiguration?.notificationsEnabled != true) {
      return;
    }
    _notificationPermissionGranted = granted;
    _notificationTransition.reset();
    if (!granted) {
      _update(
        receipt: const OperationReceiptViewModel(
          title: 'Managed notifications unavailable',
          summary:
              'Your organization enables notifications, but the operating system did not grant permission. No notification was delivered.',
          tone: EvidenceTone.warning,
        ),
      );
    }
  }

  Future<void> _refreshManagedConfiguration() async {
    if (_disposed || _managedConfigurationRefreshing) return;
    _managedConfigurationRefreshing = true;
    try {
      final configuration = await _managedConfigurationSource.load();
      if (_disposed) return;
      _applyManagedConfiguration(configuration);
      if (configuration != null &&
          !configuration.allowOriginChanges &&
          _selectedProfile?.profile.origin !=
              configuration.controlPlaneOrigin!.origin) {
        await _sessionStore.clear().catchError((_) {});
        if (_disposed) return;
        _profiles.removeWhere(
          (profile) =>
              profile.profile.origin !=
              configuration.controlPlaneOrigin!.origin,
        );
        await _persistConnectionProfiles();
        if (_disposed) return;
        _selectManagedOriginAfterPolicyChange();
        await _connectManagedOriginIfPresent();
      }
    } on AppleManagedConfigurationException {
      await _rejectManagedConfiguration();
    } finally {
      _managedConfigurationRefreshing = false;
    }
  }

  void _selectManagedOriginAfterPolicyChange() {
    _invalidateAuthentication();
    _eraseOneTimeMaterial();
    unawaited(_fleetPoller?.dispose());
    _fleetPoller = null;
    _transport?.cookieJar.clear();
    _session = null;
    _disconnect();
    _update(
      accessContext: null,
      fleet: const LoadableViewModel.initial(),
      selectedNetwork: const LoadableViewModel.initial(),
      activity: const LoadableViewModel.initial(),
      accessManagement: const LoadableViewModel.initial(),
      receipt: null,
    );
  }

  Future<void> _rejectManagedConfiguration() async {
    if (_disposed) return;
    _managedConfiguration = null;
    _managedConfigurationRejected = true;
    _selectManagedOriginAfterPolicyChange();
    await _sessionStore.clear().catchError((_) {});
    if (_disposed) return;
    _update(
      connection: ConnectionViewModel(
        profiles: _profileViewModels(),
        phase: LoadPhase.error,
        message:
            'Organization-managed settings are invalid. Ask your administrator to correct the application configuration.',
      ),
      managedPolicy: const AppleManagedPolicyViewModel.invalid(),
      preferences: PreferencesViewModel(
        themeMode: value.preferences.themeMode,
        notificationsEnabled: _localNotificationsEnabled,
        backgroundMonitoringEnabled:
            value.preferences.backgroundMonitoringEnabled,
      ),
    );
  }

  Future<void> _connectManagedOriginIfPresent() async {
    final profile = _managedConfiguration?.controlPlaneOrigin;
    if (profile == null) return;
    await _addConnection(
      ConnectionRequest(
        displayName: 'Organization-managed control plane',
        origin: profile.origin,
      ),
    );
  }

  Future<String?> _loadConnectionProfiles() async {
    late final List<PersistedConnectionProfile> persisted;
    try {
      persisted = await _sessionStore.loadConnectionProfiles();
    } on SessionPersistenceException {
      var removed = true;
      try {
        await _sessionStore.clearConnectionProfiles();
      } catch (_) {
        removed = false;
      }
      return removed
          ? 'The saved control-plane list was invalid and has been removed.'
          : 'Secure profile storage is unavailable. Unlock the device or operating-system credential store, then restart Mesh Admin.';
    } catch (_) {
      return 'Secure profile storage is unavailable. Unlock the device or operating-system credential store, then restart Mesh Admin.';
    }

    final managedOrigin = _managedOriginLocked
        ? _managedConfiguration!.controlPlaneOrigin!.origin
        : null;
    for (final persistedProfile in persisted) {
      if (managedOrigin != null &&
          persistedProfile.profile.origin != managedOrigin) {
        continue;
      }
      _addProfile(
        persistedProfile.profile,
        displayName: persistedProfile.displayName,
        tlsTrusted: false,
      );
    }
    if (_profiles.length != persisted.length) {
      final persistedFilteredProfiles = await _persistConnectionProfiles();
      if (!persistedFilteredProfiles) {
        return 'Organization-managed settings filtered the saved control-plane list, but secure profile storage could not be updated.';
      }
    }
    return null;
  }

  Future<bool> _persistConnectionProfiles() async {
    try {
      await _sessionStore.saveConnectionProfiles(
        _profiles
            .map(
              (profile) => PersistedConnectionProfile(
                displayName: profile.displayName,
                profile: profile.profile,
              ),
            )
            .toList(growable: false),
      );
      return true;
    } catch (_) {
      return false;
    }
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

  void _connectionMessage(
    String message, {
    required LoadPhase phase,
    bool canCancelAuthentication = false,
  }) {
    final selected = _selectedProfile;
    _update(
      connection: ConnectionViewModel(
        profiles: _profileViewModels(),
        selectedProfileId: selected?.id,
        methods: selected?.methods ?? const <AuthenticationMethod>[],
        phase: phase,
        message: message,
        canCancelAuthentication: canCancelAuthentication,
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
    Object? managedPolicy = _unchanged,
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
      managedPolicy: identical(managedPolicy, _unchanged)
          ? value.managedPolicy
          : managedPolicy as AppleManagedPolicyViewModel?,
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
    _invalidateAuthentication();
    unawaited(_fleetPoller?.dispose());
    unawaited(_custodySubscription?.cancel());
    _custodySubscription = null;
    if (_ownsProtectedDataEvents) {
      _protectedDataEvents.dispose();
    } else {
      _protectedDataEvents.setUnavailableHandler(null);
    }
    unawaited(_authenticationChanges.close());
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
  'member' => MeshRole.member,
  'viewer' => MeshRole.viewer,
  'operator' => MeshRole.operator,
  'admin' => MeshRole.admin,
  _ => throw FormatException('Unsupported Mesh role "$value".'),
};

Set<MeshPermission> _presentationPermissions(
  Set<auth.MeshPermission> permissions,
) => Set<MeshPermission>.unmodifiable(
  permissions.map(
    (permission) => switch (permission) {
      auth.MeshPermission.networksRead => MeshPermission.networksRead,
      auth.MeshPermission.networksWrite => MeshPermission.networksWrite,
      auth.MeshPermission.networksSecurity => MeshPermission.networksSecurity,
      auth.MeshPermission.identityManage => MeshPermission.identityManage,
      auth.MeshPermission.auditRead => MeshPermission.auditRead,
    },
  ),
);

bool _samePermissions(
  Set<auth.MeshPermission> first,
  Set<auth.MeshPermission> second,
) => first.length == second.length && first.containsAll(second);

bool _sameSessionIdentity(
  core.SessionContext previous,
  core.SessionContext refreshed,
) =>
    previous.sessionId == refreshed.sessionId &&
    previous.principal.id == refreshed.principal.id &&
    previous.principal.kind == refreshed.principal.kind &&
    previous.principal.issuer == refreshed.principal.issuer &&
    previous.principal.subject == refreshed.principal.subject &&
    previous.authMethod == refreshed.authMethod;

final class _AuthorityRefresh {
  const _AuthorityRefresh({
    required this.auditReadGained,
    required this.identityManageGained,
  });

  final bool auditReadGained;
  final bool identityManageGained;
}

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
