import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/app/app.dart';
import 'package:mesh_desktop/core/auth/secure_session_store.dart';
import 'package:mesh_desktop/core/platform/mobile_security.dart';
import 'package:mesh_desktop/core/platform/system_browser.dart';
import 'package:mesh_desktop/core/platform/apple_managed_configuration.dart';
import 'package:mesh_desktop/core/polling/lifecycle_poller.dart';
import 'package:mesh_desktop/integration/mesh_app_controller.dart';

void main() {
  test(
    'browser authorization can be cancelled before any poll secret is sent',
    () async {
      final fixture = await _BrowserControllerFixture.start();
      addTearDown(fixture.close);

      fixture.controller.authenticate(AuthenticationMethod.oidc);
      await _waitUntil(
        () =>
            fixture.browser.opened.isNotEmpty &&
            fixture.controller.value.connection.canCancelAuthentication,
      );
      expect(fixture.browser.opened.single.queryParameters, <String, String>{
        'mesh_desktop_request': _DesktopAuthorizationServer.requestId,
      });
      expect(
        fixture.browser.opened.single.toString(),
        isNot(contains(fixture.server.pollSecret)),
      );
      expect(fixture.delays, hasLength(1));

      fixture.controller.cancelAuthentication();
      await _waitUntil(
        () =>
            fixture.controller.value.connection.message?.contains(
              'cancelled',
            ) ??
            false,
      );

      expect(
        fixture.controller.value.connection.canCancelAuthentication,
        isFalse,
      );
      expect(fixture.server.completionRequests, 0);
      expect(
        await fixture.server.receivedPollSecret.timeout(
          const Duration(milliseconds: 30),
          onTimeout: () => null,
        ),
        isNull,
      );
    },
  );

  test(
    'origin change cancels authorization without polling the old origin',
    () async {
      final fixture = await _BrowserControllerFixture.start();
      final other = await _DesktopAuthorizationServer.start();
      addTearDown(() async {
        await other.close();
        await fixture.close();
      });

      fixture.controller.authenticate(AuthenticationMethod.oidc);
      await _waitUntil(
        () =>
            fixture.delays.isNotEmpty &&
            fixture.controller.value.connection.canCancelAuthentication,
      );

      fixture.controller.addConnection(
        ConnectionRequest(
          displayName: 'Replacement control plane',
          origin: other.origin,
        ),
      );
      await _waitUntil(() {
        final connection = fixture.controller.value.connection;
        final selected = connection.profiles
            .where((profile) => profile.id == connection.selectedProfileId)
            .firstOrNull;
        return selected?.origin.origin == other.origin.origin &&
            connection.phase == LoadPhase.ready;
      });

      expect(fixture.server.completionRequests, 0);
      expect(fixture.controller.value.accessContext, isNull);
      expect(
        fixture.controller.value.connection.canCancelAuthentication,
        isFalse,
      );
    },
  );

  test(
    'browser launch failure is redacted and does not begin polling',
    () async {
      final fixture = await _BrowserControllerFixture.start(
        browser: const _FailingBrowser(),
        delay: (_) => throw StateError('poll delay must not start'),
      );
      addTearDown(fixture.close);

      fixture.controller.authenticate(AuthenticationMethod.oidc);
      await _waitUntil(
        () => fixture.controller.value.connection.phase == LoadPhase.error,
      );

      expect(
        fixture.controller.value.connection.message,
        'The system browser could not be opened.',
      );
      expect(
        fixture.controller.value.connection.message,
        isNot(contains(fixture.server.pollSecret)),
      );
      expect(fixture.server.completionRequests, 0);
    },
  );

  test(
    'browser authorization pauses in the background and resumes while valid',
    () async {
      final fixture = await _BrowserControllerFixture.start(
        completionState: 'authorized',
      );
      addTearDown(fixture.close);
      fixture.lifecycle.setState(AppLifecycleState.paused);

      fixture.controller.authenticate(AuthenticationMethod.oidc);
      await _waitUntil(() => fixture.delays.isNotEmpty);
      fixture.delays.single.complete();
      await Future<void>.delayed(const Duration(milliseconds: 30));

      expect(fixture.server.completionRequests, 0);
      expect(
        fixture.controller.value.connection.canCancelAuthentication,
        isTrue,
      );

      fixture.lifecycle.setState(AppLifecycleState.resumed);
      await _waitUntil(() => fixture.controller.value.accessContext != null);

      expect(fixture.server.completionRequests, 1);
      expect(fixture.controller.value.accessContext?.role, MeshRole.viewer);
    },
  );

  test(
    'transient completion interruption retries within the original expiry',
    () async {
      final fixture = await _BrowserControllerFixture.start(
        completionState: 'authorized',
        transientCompletionFailures: 1,
      );
      addTearDown(fixture.close);

      fixture.controller.authenticate(AuthenticationMethod.oidc);
      await _waitUntil(() => fixture.delays.isNotEmpty);
      fixture.delays[0].complete();
      await _waitUntil(
        () =>
            fixture.server.completionRequests == 1 &&
            fixture.delays.length == 2,
      );

      expect(fixture.controller.value.accessContext, isNull);
      expect(fixture.controller.value.connection.phase, LoadPhase.loading);
      expect(
        fixture.controller.value.connection.canCancelAuthentication,
        isTrue,
      );

      fixture.delays[1].complete();
      await _waitUntil(() => fixture.controller.value.accessContext != null);

      expect(fixture.server.completionRequests, 2);
      expect(fixture.controller.value.accessContext?.role, MeshRole.viewer);
    },
  );

  test(
    'transient completion interruption cannot extend the original expiry',
    () async {
      final fixture = await _BrowserControllerFixture.start(
        completionState: 'authorized',
        transientCompletionFailures: 1,
      );
      addTearDown(fixture.close);

      fixture.controller.authenticate(AuthenticationMethod.oidc);
      await _waitUntil(() => fixture.delays.isNotEmpty);
      fixture.delays[0].complete();
      await _waitUntil(
        () =>
            fixture.server.completionRequests == 1 &&
            fixture.delays.length == 2,
      );

      fixture.clock.now = DateTime.parse('2026-07-23T12:06:00Z');
      fixture.delays[1].complete();
      await _waitUntil(
        () => fixture.controller.value.connection.phase == LoadPhase.error,
      );

      expect(fixture.server.completionRequests, 1);
      expect(
        fixture.controller.value.connection.message,
        'Desktop sign-in expired. Start again.',
      );
      expect(fixture.controller.value.accessContext, isNull);
    },
  );

  test(
    'browser denial and expiry are terminal, explicit, and redacted',
    () async {
      for (final scenario in <(String, String)>[
        ('denied', 'browser denied this desktop sign-in'),
        ('expired', 'Desktop sign-in expired'),
      ]) {
        final fixture = await _BrowserControllerFixture.start(
          completionState: scenario.$1,
        );
        try {
          fixture.controller.authenticate(AuthenticationMethod.oidc);
          await _waitUntil(() => fixture.delays.isNotEmpty);
          fixture.delays.single.complete();
          await _waitUntil(
            () => fixture.controller.value.connection.phase == LoadPhase.error,
          );

          expect(
            fixture.controller.value.connection.message,
            contains(scenario.$2),
          );
          expect(
            fixture.controller.value.connection.message,
            isNot(contains(fixture.server.pollSecret)),
          );
          expect(
            fixture.controller.value.connection.canCancelAuthentication,
            isFalse,
          );
          expect(fixture.server.completionRequests, 1);
          expect(
            await fixture.server.receivedPollSecret,
            fixture.server.pollSecret,
          );
        } finally {
          await fixture.close();
        }
      }
    },
  );

  test(
    'browser approval persists only the scoped cookie pair and logout erases it',
    () async {
      final fixture = await _BrowserControllerFixture.start(
        completionState: 'authorized',
      );
      addTearDown(fixture.close);

      fixture.controller.authenticate(AuthenticationMethod.oidc);
      await _waitUntil(() => fixture.delays.isNotEmpty);
      fixture.delays.single.complete();
      await _waitUntil(
        () =>
            fixture.controller.value.accessContext != null &&
            fixture.controller.value.fleet.phase == LoadPhase.empty,
      );

      expect(fixture.controller.value.accessContext?.role, MeshRole.viewer);
      expect(fixture.server.authorizedReadRequests, 2);
      final persisted =
          fixture.storage.values[SecureSessionStore.storageKey] ?? '';
      expect(
        persisted,
        contains('"schema":"mesh-desktop-session-v1"'),
        reason:
            '${fixture.controller.value.receipt?.title}: '
            '${fixture.controller.value.receipt?.summary}',
      );
      expect(persisted, contains(fixture.server.sessionCookie));
      expect(persisted, contains(fixture.server.csrfCookie));
      expect(persisted, contains(fixture.server.origin.toString()));
      expect(persisted, isNot(contains(fixture.server.pollSecret)));

      final denied = await fixture.controller.createNetwork(
        const CreateNetworkRequest(
          name: 'viewer-must-not-create',
          cidr: '10.90.0.0/24',
        ),
      );
      expect(denied.succeeded, isFalse);
      expect(denied.message, contains('viewer permission denied'));
      expect(denied.message, contains('Check the current role'));
      expect(fixture.server.deniedMutationRequests, 1);
      expect(fixture.server.deniedMutationHadCSRF, isTrue);
      expect(fixture.server.authoritativeNetworkCount, 0);

      fixture.controller.signOut();
      await _waitUntil(
        () =>
            fixture.controller.value.accessContext == null &&
            !fixture.storage.values.containsKey(SecureSessionStore.storageKey),
      );

      expect(fixture.server.logoutRequests, 1);
      expect(fixture.server.logoutHadCSRF, isTrue);
      expect(
        fixture.storage.values,
        contains(SecureSessionStore.connectionProfilesStorageKey),
      );
      expect(
        fixture.storage.values,
        isNot(contains(SecureSessionStore.storageKey)),
      );
      expect(
        fixture.controller.value.connection.message,
        'Signed out. Choose a sign-in method.',
      );
    },
  );

  test(
    'controller restart restores the selected profile and saved cookie session',
    () async {
      final fixture = await _BrowserControllerFixture.start(
        completionState: 'authorized',
      );
      var firstControllerDisposed = false;
      _TestLifecycleSource? restoredLifecycle;
      MeshAppController? restoredController;
      addTearDown(() async {
        restoredController?.dispose();
        await restoredLifecycle?.close();
        if (!firstControllerDisposed) {
          fixture.controller.dispose();
          await fixture.lifecycle.close();
        }
        await fixture.server.close();
      });

      fixture.controller.authenticate(AuthenticationMethod.oidc);
      await _waitUntil(() => fixture.delays.isNotEmpty);
      fixture.delays.single.complete();
      await _waitUntil(
        () =>
            fixture.controller.value.accessContext != null &&
            fixture.controller.value.fleet.phase == LoadPhase.empty,
      );
      expect(fixture.storage.values, contains(SecureSessionStore.storageKey));

      fixture.controller.dispose();
      await fixture.lifecycle.close();
      firstControllerDisposed = true;

      restoredLifecycle = _TestLifecycleSource();
      restoredController = MeshAppController(
        managedConfigurationSource: const NoAppleManagedConfigurationSource(),
        sessionStore: SecureSessionStore(
          fixture.storage,
          now: fixture.clock.call,
        ),
        lifecycle: restoredLifecycle,
        protectedDataEvents: _NoopProtectedDataEvents(),
        now: fixture.clock.call,
      );

      await restoredController.initialize();

      expect(restoredController.value.accessContext?.role, MeshRole.viewer);
      expect(restoredController.value.connection.selectedProfileId, isNotNull);
      expect(restoredController.value.connection.phase, LoadPhase.ready);
      expect(fixture.storage.values, contains(SecureSessionStore.storageKey));

      restoredController.signOut();
      await _waitUntil(
        () =>
            restoredController!.value.accessContext == null &&
            !fixture.storage.values.containsKey(SecureSessionStore.storageKey),
      );
      expect(
        restoredController.value.connection.methods,
        contains(AuthenticationMethod.oidc),
      );
    },
  );

  test(
    'authoritative refresh applies permission downgrade and erases one-time material',
    () async {
      final fixture = await _BrowserControllerFixture.start(
        completionState: 'authorized',
        role: 'admin',
        permissions: const <String>[
          'networks.read',
          'networks.write',
          'networks.security',
          'identity.manage',
          'audit.read',
        ],
      );
      addTearDown(fixture.close);

      fixture.controller.authenticate(AuthenticationMethod.oidc);
      await _waitUntil(() => fixture.delays.isNotEmpty);
      fixture.delays.single.complete();
      await _waitUntil(
        () =>
            fixture.controller.value.accessContext?.role == MeshRole.admin &&
            fixture.controller.value.fleet.phase == LoadPhase.empty,
      );
      fixture.controller.value = _withOneTimeSecret(fixture.controller.value);

      fixture.server.setAuthority(
        role: 'viewer',
        permissions: const <String>['networks.read'],
      );
      fixture.controller.refreshFleet();
      await _waitUntil(
        () => fixture.controller.value.accessContext?.role == MeshRole.viewer,
      );

      final access = fixture.controller.value.accessContext!;
      expect(access.permissions, <MeshPermission>{MeshPermission.networksRead});
      expect(access.allows(MeshPermission.identityManage), isFalse);
      expect(access.allows(MeshPermission.auditRead), isFalse);
      expect(
        fixture.controller.value.accessManagement.phase,
        LoadPhase.initial,
      );
      expect(fixture.controller.value.activity.phase, LoadPhase.empty);
      expect(fixture.controller.value.oneTimeSecret, isNull);
    },
  );

  test(
    'server-side session revocation signs out and erases local custody',
    () async {
      final fixture = await _BrowserControllerFixture.start(
        completionState: 'authorized',
      );
      addTearDown(fixture.close);

      fixture.controller.authenticate(AuthenticationMethod.oidc);
      await _waitUntil(() => fixture.delays.isNotEmpty);
      fixture.delays.single.complete();
      await _waitUntil(
        () =>
            fixture.controller.value.accessContext != null &&
            fixture.storage.values.isNotEmpty &&
            fixture.controller.value.fleet.phase == LoadPhase.empty,
      );
      fixture.controller.value = _withOneTimeSecret(fixture.controller.value);

      fixture.server.revokeSession();
      fixture.controller.refreshFleet();
      await _waitUntil(
        () =>
            fixture.controller.value.accessContext == null &&
            !fixture.storage.values.containsKey(SecureSessionStore.storageKey),
      );

      expect(fixture.controller.value.oneTimeSecret, isNull);
      expect(
        fixture.storage.values,
        contains(SecureSessionStore.connectionProfilesStorageKey),
      );
      expect(
        fixture.storage.values,
        isNot(contains(SecureSessionStore.storageKey)),
      );
      expect(fixture.controller.value.connection.phase, LoadPhase.error);
      expect(
        fixture.controller.value.connection.message,
        'The Mesh session expired. Sign in again.',
      );
    },
  );
}

final class _BrowserControllerFixture {
  _BrowserControllerFixture._({
    required this.server,
    required this.lifecycle,
    required this.browser,
    required this.controller,
    required this.delays,
    required this.storage,
    required this.clock,
  });

  final _DesktopAuthorizationServer server;
  final _TestLifecycleSource lifecycle;
  final _RecordingBrowser browser;
  final MeshAppController controller;
  final List<Completer<void>> delays;
  final _MemorySecretStorage storage;
  final _TestClock clock;

  static Future<_BrowserControllerFixture> start({
    SystemBrowserLauncher? browser,
    Future<void> Function(Duration)? delay,
    String completionState = 'pending',
    String role = 'viewer',
    List<String> permissions = const <String>['networks.read'],
    int transientCompletionFailures = 0,
  }) async {
    final server = await _DesktopAuthorizationServer.start(
      completionState: completionState,
      role: role,
      permissions: permissions,
      transientCompletionFailures: transientCompletionFailures,
    );
    final lifecycle = _TestLifecycleSource();
    final recordingBrowser = browser is _RecordingBrowser
        ? browser
        : _RecordingBrowser(delegate: browser);
    final delays = <Completer<void>>[];
    final storage = _MemorySecretStorage();
    final clock = _TestClock(DateTime.parse('2026-07-23T12:00:00Z'));
    final controller = MeshAppController(
      managedConfigurationSource: const NoAppleManagedConfigurationSource(),
      sessionStore: SecureSessionStore(storage, now: clock.call),
      browser: recordingBrowser,
      lifecycle: lifecycle,
      delay:
          delay ??
          (_) {
            final pending = Completer<void>();
            delays.add(pending);
            return pending.future;
          },
      now: clock.call,
    );
    controller.addConnection(
      ConnectionRequest(
        displayName: 'Disposable control plane',
        origin: server.origin,
      ),
    );
    await _waitUntil(
      () => controller.value.connection.methods.contains(
        AuthenticationMethod.oidc,
      ),
    );
    return _BrowserControllerFixture._(
      server: server,
      lifecycle: lifecycle,
      browser: recordingBrowser,
      controller: controller,
      delays: delays,
      storage: storage,
      clock: clock,
    );
  }

  Future<void> close() async {
    controller.dispose();
    await lifecycle.close();
    await server.close();
  }
}

final class _TestClock {
  _TestClock(this.now);

  DateTime now;

  DateTime call() => now;
}

final class _MemorySecretStorage implements SecretStorage {
  final Map<String, String> values = <String, String>{};

  @override
  Future<void> delete(String key) async {
    values.remove(key);
  }

  @override
  Future<String?> read(String key) async => values[key];

  @override
  Future<void> write(String key, String value) async {
    values[key] = value;
  }
}

final class _NoopProtectedDataEvents implements ProtectedDataEvents {
  @override
  void dispose() {}

  @override
  void setUnavailableHandler(VoidCallback? handler) {}
}

final class _RecordingBrowser implements SystemBrowserLauncher {
  _RecordingBrowser({this.delegate});

  final SystemBrowserLauncher? delegate;
  final List<Uri> opened = <Uri>[];

  @override
  Future<void> open(Uri uri) async {
    opened.add(uri);
    await delegate?.open(uri);
  }
}

final class _FailingBrowser implements SystemBrowserLauncher {
  const _FailingBrowser();

  @override
  Future<void> open(Uri uri) async {
    throw const BrowserLaunchException(
      'The system browser could not be opened.',
    );
  }
}

final class _DesktopAuthorizationServer {
  _DesktopAuthorizationServer._(
    this._server,
    this._completionState,
    this._role,
    this._permissions,
    this._transientCompletionFailures,
  );

  static const requestId =
      'desktop_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  static const _secret = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE';
  static const _expiresAt = '2026-07-23T12:05:00Z';

  final HttpServer _server;
  final String _completionState;
  String _role;
  List<String> _permissions;
  final int _transientCompletionFailures;
  bool _sessionRevoked = false;
  final Completer<String?> _receivedPollSecret = Completer<String?>();
  int completionRequests = 0;
  int authorizedReadRequests = 0;
  int deniedMutationRequests = 0;
  int logoutRequests = 0;
  int authoritativeNetworkCount = 0;
  bool deniedMutationHadCSRF = false;
  bool logoutHadCSRF = false;

  Uri get origin => Uri.parse('http://127.0.0.1:${_server.port}');
  String get pollSecret => _secret;
  String get sessionCookie => 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI';
  String get csrfCookie => 'AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM';
  Future<String?> get receivedPollSecret => _receivedPollSecret.future;

  static Future<_DesktopAuthorizationServer> start({
    String completionState = 'pending',
    String role = 'viewer',
    List<String> permissions = const <String>['networks.read'],
    int transientCompletionFailures = 0,
  }) async {
    if (!const <String>{
      'pending',
      'denied',
      'expired',
      'authorized',
    }.contains(completionState)) {
      throw ArgumentError.value(completionState, 'completionState');
    }
    final http = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final fixture = _DesktopAuthorizationServer._(
      http,
      completionState,
      role,
      List<String>.of(permissions),
      transientCompletionFailures,
    );
    http.listen(fixture._handle);
    return fixture;
  }

  Future<void> _handle(HttpRequest request) async {
    final response = request.response;
    response.headers.contentType = ContentType.json;
    switch (request.uri.path) {
      case '/api/v1/auth/methods':
        response.write(
          '{"oidc":true,"legacy_browser_login":false,"break_glass":false}',
        );
      case '/api/v1/auth/desktop/start':
        final body = await utf8.decoder.bind(request).join();
        if (body != '{}') {
          response
            ..statusCode = HttpStatus.badRequest
            ..write('{"error":"invalid start"}');
          break;
        }
        response
          ..statusCode = HttpStatus.created
          ..write(
            jsonEncode(<String, Object?>{
              'request_id': requestId,
              'poll_secret': _secret,
              'verification_url':
                  '${origin.toString()}/?mesh_desktop_request=$requestId',
              'expires_at': _expiresAt,
              'interval_seconds': 5,
            }),
          );
      case '/api/v1/auth/desktop/complete':
        completionRequests++;
        final body =
            jsonDecode(await utf8.decoder.bind(request).join())
                as Map<String, Object?>;
        if (!_receivedPollSecret.isCompleted) {
          _receivedPollSecret.complete(body['poll_secret'] as String?);
        }
        if (completionRequests <= _transientCompletionFailures) {
          response
            ..statusCode = HttpStatus.serviceUnavailable
            ..write('{"error":"temporary completion interruption"}');
          break;
        }
        if (_completionState == 'authorized') {
          response.cookies
            ..add(
              Cookie('mesh_session', sessionCookie)
                ..path = '/'
                ..httpOnly = true,
            )
            ..add(
              Cookie('mesh_csrf', csrfCookie)
                ..path = '/'
                ..httpOnly = false,
            );
          response.write(
            jsonEncode(<String, Object?>{
              'state': 'authorized',
              'expires_at': _expiresAt,
              'interval_seconds': 5,
              'session': _sessionDocument(),
            }),
          );
        } else {
          response.write(
            '{"state":"$_completionState","expires_at":"$_expiresAt","interval_seconds":5}',
          );
        }
      case '/api/v1/networks':
        _requireSessionCookies(request);
        if (request.method == 'GET') {
          authorizedReadRequests++;
          response.write('[]');
        } else if (request.method == 'POST') {
          deniedMutationRequests++;
          deniedMutationHadCSRF =
              request.headers.value('X-Mesh-CSRF') == csrfCookie &&
              request.headers.value('Origin') == origin.toString();
          response
            ..statusCode = HttpStatus.forbidden
            ..write('{"error":"viewer permission denied"}');
        } else {
          response
            ..statusCode = HttpStatus.methodNotAllowed
            ..write('{"error":"method not allowed"}');
        }
      case '/api/v1/fleet/health':
        authorizedReadRequests++;
        _requireSessionCookies(request);
        response.write(
          '{"generated_at":"2026-07-23T12:00:00Z",'
          '"summary":{"overall":"setup","total_networks":0,'
          '"total_nodes":0,"active_nodes":0,"warning_nodes":0,'
          '"critical_nodes":0,"revoked_nodes":0},'
          '"rollout":{"percent":0,"converged_nodes":0,"eligible_nodes":0},'
          '"networks":[]}',
        );
      case '/api/v1/session':
        if (request.method == 'GET') {
          _requireSessionCookies(request);
          if (_sessionRevoked) {
            response
              ..statusCode = HttpStatus.unauthorized
              ..write('{"error":"session revoked"}');
          } else {
            response.write(jsonEncode(_sessionDocument()));
          }
          break;
        }
        if (request.method != 'DELETE') {
          response
            ..statusCode = HttpStatus.methodNotAllowed
            ..write('{"error":"method not allowed"}');
          break;
        }
        logoutRequests++;
        _requireSessionCookies(request);
        logoutHadCSRF =
            request.headers.value('X-Mesh-CSRF') == csrfCookie &&
            request.headers.value('Origin') == origin.toString();
        response.statusCode = HttpStatus.noContent;
      default:
        response
          ..statusCode = HttpStatus.notFound
          ..write('{"error":"not found"}');
    }
    await response.close();
  }

  void _requireSessionCookies(HttpRequest request) {
    final cookies = <String, String>{
      for (final cookie in request.cookies) cookie.name: cookie.value,
    };
    if (cookies['mesh_session'] != sessionCookie ||
        cookies['mesh_csrf'] != csrfCookie) {
      request.response.statusCode = HttpStatus.unauthorized;
    }
  }

  Map<String, Object?> _sessionDocument() => <String, Object?>{
    'authenticated': true,
    'session_id': 'session_approved',
    'principal': <String, Object?>{
      'id': 'principal_viewer',
      'kind': 'oidc_admin',
      'display_name': 'Test Viewer',
      'auth_time': '2026-07-23T12:00:00Z',
    },
    'auth_method': 'oidc',
    'role': _role,
    'permissions': _permissions,
    'created_at': '2026-07-23T12:00:00Z',
    'idle_expires_at': _expiresAt,
    'absolute_expires_at': _expiresAt,
  };

  void setAuthority({required String role, required List<String> permissions}) {
    _role = role;
    _permissions = List<String>.of(permissions);
  }

  void revokeSession() {
    _sessionRevoked = true;
  }

  Future<void> close() async {
    if (!_receivedPollSecret.isCompleted) {
      _receivedPollSecret.complete(null);
    }
    await _server.close(force: true);
  }
}

MeshDesktopViewModel _withOneTimeSecret(MeshDesktopViewModel current) {
  return MeshDesktopViewModel(
    connection: current.connection,
    accessContext: current.accessContext,
    fleet: current.fleet,
    selectedNetwork: current.selectedNetwork,
    activity: current.activity,
    accessManagement: current.accessManagement,
    preferences: current.preferences,
    managedPolicy: current.managedPolicy,
    oneTimeSecret: const OneTimeSecretViewModel(
      id: 'test-secret',
      title: 'Test secret',
      detail: 'Test-only one-time material.',
      items: <OneTimeSecretItemViewModel>[
        OneTimeSecretItemViewModel(
          label: 'Value',
          value: 'must-be-erased',
          copyConfirmation: 'Copied',
        ),
      ],
      custodyLabel: 'Stored',
    ),
  );
}

Future<void> _waitUntil(bool Function() condition) async {
  final deadline = DateTime.now().add(const Duration(seconds: 3));
  while (!condition()) {
    if (DateTime.now().isAfter(deadline)) {
      throw StateError('Timed out waiting for controller state.');
    }
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
}

final class _TestLifecycleSource implements LifecycleSource {
  final StreamController<AppLifecycleState> _changes =
      StreamController<AppLifecycleState>.broadcast(sync: true);

  @override
  Stream<AppLifecycleState> get changes => _changes.stream;

  AppLifecycleState _state = AppLifecycleState.resumed;

  @override
  AppLifecycleState get currentState => _state;

  void setState(AppLifecycleState state) {
    _state = state;
    _changes.add(state);
  }

  Future<void> close() => _changes.close();
}
