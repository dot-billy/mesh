import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/core/auth/rbac.dart';
import 'package:mesh_desktop/core/auth/session_models.dart';
import 'package:mesh_desktop/core/connection/connection_profile.dart';
import 'package:mesh_desktop/core/transport/json_transport.dart';
import 'package:mesh_desktop/core/transport/mesh_cookie_jar.dart';
import 'package:mesh_desktop/integration/mesh_api.dart';

const _fixtureSchema = 'mesh-desktop-real-control-plane-fixture-v1';

void main() {
  test(
    'desktop API completes its supported workflows against the real control plane',
    () async {
      final fixture = await _RealControlPlaneFixture.start();
      addTearDown(fixture.close);

      final profile = ConnectionProfile.parse(
        fixture.origin,
        allowInsecureLoopback: true,
      );

      final browserTransport = DartIoJsonTransport(profile: profile);
      addTearDown(() => browserTransport.close(force: true));
      final browserApi = MeshApi(profile: profile, transport: browserTransport);
      final browserAttempt = await browserApi.startDesktopAuthorization();
      expect(browserAttempt.verificationUrl.queryParameters, <String, String>{
        'mesh_desktop_request': browserAttempt.requestId,
      });
      expect(
        browserAttempt.verificationUrl.toString(),
        isNot(contains(browserAttempt.pollSecret)),
      );
      await fixture.helper('/__fixture/desktop-decision', <String, Object?>{
        'request_id': browserAttempt.requestId,
        'decision': 'approve',
      });
      final browserResult = await browserApi.completeDesktopAuthorization(
        browserAttempt,
      );
      expect(browserResult.state, DesktopAuthorizationState.authorized);
      expect(browserResult.session?.role, MeshRole.admin);
      expect(browserTransport.cookieJar.isComplete, isTrue);
      expect(
        (await browserApi.currentSession()).sessionId,
        browserResult.session?.sessionId,
      );
      await expectLater(
        browserApi.completeDesktopAuthorization(browserAttempt),
        throwsA(
          isA<MeshApiException>().having(
            (error) => error.statusCode,
            'statusCode',
            HttpStatus.unauthorized,
          ),
        ),
      );
      await browserApi.logout();
      expect(browserTransport.cookieJar.isComplete, isFalse);

      final transport = DartIoJsonTransport(profile: profile);
      addTearDown(() => transport.close(force: true));
      final api = MeshApi(profile: profile, transport: transport);
      final methods = await api.authenticationMethods();
      expect(methods.oidc, isTrue);
      expect(methods.legacyBrowserLogin, isTrue);
      expect(methods.breakGlass, isTrue);

      final admin = await api.loginWithLegacyToken(fixture.adminToken);
      expect(admin.role, MeshRole.admin);
      expect(admin.principal.kind, PrincipalKind.legacyAdmin);
      expect(transport.cookieJar.isComplete, isTrue);
      expect((await api.currentSession()).sessionId, admin.sessionId);

      expect(await api.networks(), isEmpty);
      expect(await api.fleetHealth(), containsPair('networks', isEmpty));
      expect(await api.runtimeTelemetry(), isNotNull);

      final network = await api.createNetwork(
        name: 'desktop-e2e',
        cidr: '10.119.0.0/24',
        listenPort: 4242,
        certificateTtlHours: 24,
      );
      expect(network.name, 'desktop-e2e');
      expect(network.cidr, '10.119.0.0/24');

      final networkInventory = await api.networks();
      expect(networkInventory, hasLength(1));
      expect(networkInventory.single['id'], network.id);
      expect(await api.nodes(network.id), isEmpty);
      expect(await api.readiness(network.id), contains('network'));
      expect(await api.firewall(network.id), contains('config_revision'));
      expect(await api.dns(network.id), contains('config_revision'));
      expect(await api.relays(network.id), contains('config_revision'));
      expect(await api.routePolicies(network.id), contains('config_revision'));
      expect(await api.caRotation(network.id), contains('config_revision'));

      final pending = await api.createNode(
        networkId: network.id,
        name: 'pending-node',
        groups: const <String>['desktop'],
      );
      expect(pending.node.status, 'pending');
      final reissued = await api.reissuePendingEnrollment(pending.node.id);
      expect(reissued.node.id, pending.node.id);
      expect(reissued.enrollmentToken, isNot(pending.enrollmentToken));
      final revisionBeforeCancellation = _networkRevision(
        await api.networks(),
        network.id,
      );
      final cancellation = await api.cancelPendingEnrollment(
        networkId: network.id,
        nodeId: pending.node.id,
        expectedConfigRevision: revisionBeforeCancellation,
        confirmationName: pending.node.name,
      );
      expect(cancellation.enrollmentRecordsInvalidated, 1);
      expect(cancellation.configRevision, revisionBeforeCancellation);
      expect(await api.nodes(network.id), isEmpty);

      final active = await api.createNode(
        networkId: network.id,
        name: 'active-node',
        groups: const <String>['desktop'],
      );
      await fixture.helper('/__fixture/enroll', <String, Object?>{
        'enrollment_token': active.enrollmentToken,
      });
      final nodes = await api.nodes(network.id);
      expect(nodes, hasLength(1));
      expect(
        nodes.singleWhere((node) => node['id'] == active.node.id)['status'],
        'active',
      );

      final revisionBeforeRotation = _networkRevision(
        await api.networks(),
        network.id,
      );
      final rotation = await api.rotateNodeCertificate(
        nodeId: active.node.id,
        expectedConfigRevision: revisionBeforeRotation,
        confirmationName: active.node.name,
        requestId: 'desktop-e2e-rotation-0001',
      );
      expect(rotation.configRevision, revisionBeforeRotation + 1);
      expect(rotation.certificateGeneration, 2);

      final revocation = await api.revokeNode(
        nodeId: active.node.id,
        expectedConfigRevision: rotation.configRevision,
        confirmationName: active.node.name,
        requestId: 'desktop-e2e-revocation-0001',
      );
      expect(revocation.wasEnrolled, isTrue);
      expect(revocation.configRevision, rotation.configRevision + 1);

      final viewerDocument = await fixture.helper(
        '/__fixture/viewer-session',
        const <String, Object?>{},
      );
      expect(viewerDocument['schema'], _fixtureSchema);
      final viewerSessionID = viewerDocument['session_id'] as String;
      final viewerJar = MeshCookieJar(profile)
        ..restore(
          MeshCookiePair(
            session: viewerDocument['session_token'] as String,
            csrf: viewerDocument['csrf_token'] as String,
          ),
        );
      final viewerTransport = DartIoJsonTransport(
        profile: profile,
        cookieJar: viewerJar,
      );
      addTearDown(() => viewerTransport.close(force: true));
      final viewerApi = MeshApi(profile: profile, transport: viewerTransport);
      final viewer = await viewerApi.currentSession();
      expect(viewer.role, MeshRole.viewer);
      expect(viewer.allows(MeshPermission.networksRead), isTrue);
      expect(viewer.allows(MeshPermission.networksWrite), isFalse);

      final countBeforeDeniedMutation = (await api.networks()).length;
      await expectLater(
        viewerApi.createNetwork(
          name: 'viewer-must-not-create',
          cidr: '10.120.0.0/24',
        ),
        throwsA(
          isA<MeshApiException>().having(
            (error) => error.statusCode,
            'statusCode',
            HttpStatus.forbidden,
          ),
        ),
      );
      expect((await api.networks()).length, countBeforeDeniedMutation);

      final sessions = await api.sessions();
      expect(
        sessions.any((session) => session['id'] == viewerSessionID),
        isTrue,
      );
      await api.revokeSession(viewerSessionID);
      await expectLater(
        viewerApi.currentSession(),
        throwsA(
          isA<MeshApiException>().having(
            (error) => error.statusCode,
            'statusCode',
            HttpStatus.unauthorized,
          ),
        ),
      );

      final recovery = await api.createRecoveryAccess(
        expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
      );
      expect(recovery.summary.state, RecoveryAccessState.usable);
      expect((await api.authenticationMethods()).breakGlass, isTrue);
      expect(
        await api.breakGlassInventory(),
        containsPair('codes', isNotEmpty),
      );
      final recoveryTransport = DartIoJsonTransport(profile: profile);
      addTearDown(() => recoveryTransport.close(force: true));
      final recoveryApi = MeshApi(
        profile: profile,
        transport: recoveryTransport,
      );
      final recoverySession = await recoveryApi.loginWithBreakGlassCode(
        recovery.credential,
      );
      expect(recoverySession.principal.kind, PrincipalKind.breakGlass);
      await recoveryApi.logout();

      expect(await api.auditEvents(), isNotEmpty);
      expect(await api.sessions(), isNotEmpty);
      await api.logout();
      expect(transport.cookieJar.isComplete, isFalse);
      await expectLater(
        api.currentSession(),
        throwsA(
          isA<MeshApiException>().having(
            (error) => error.statusCode,
            'statusCode',
            HttpStatus.unauthorized,
          ),
        ),
      );
    },
    timeout: const Timeout(Duration(minutes: 2)),
    skip: !Platform.isMacOS
        ? 'The Apple real-control-plane gate runs only on native macOS.'
        : false,
  );
}

int _networkRevision(List<Map<String, Object?>> networks, String networkID) {
  final revision = networks.singleWhere(
    (network) => network['id'] == networkID,
  )['config_revision'];
  if (revision is! int || revision < 1) {
    throw StateError('real control plane returned an invalid revision');
  }
  return revision;
}

final class _RealControlPlaneFixture {
  _RealControlPlaneFixture._({
    required this.process,
    required this.origin,
    required this.adminToken,
    required this.fixtureToken,
    required this.stderr,
  });

  final Process process;
  final String origin;
  final String adminToken;
  final String fixtureToken;
  final StringBuffer stderr;
  final HttpClient _helperClient = HttpClient()
    ..autoUncompress = false
    ..connectionTimeout = const Duration(seconds: 10);
  bool _closed = false;

  static Future<_RealControlPlaneFixture> start() async {
    final process = await Process.start(
      'go',
      const <String>['run', '../internal/httpapi/cmd/desktop-e2e-fixture'],
      workingDirectory: Directory.current.path,
      environment: <String, String>{
        ...Platform.environment,
        'TMPDIR': Directory.systemTemp.resolveSymbolicLinksSync(),
      },
    );
    final stderr = StringBuffer();
    process.stderr.transform(utf8.decoder).listen((chunk) {
      if (stderr.length < 16 * 1024) {
        stderr.write(chunk);
      }
    });
    try {
      final line = await process.stdout
          .transform(utf8.decoder)
          .transform(const LineSplitter())
          .first
          .timeout(const Duration(seconds: 30));
      final decoded = jsonDecode(line);
      if (decoded is! Map<String, Object?> ||
          decoded.length != 4 ||
          decoded['schema'] != _fixtureSchema ||
          decoded['origin'] is! String ||
          decoded['admin_token'] is! String ||
          decoded['fixture_token'] is! String) {
        throw StateError('real control-plane fixture startup was invalid');
      }
      return _RealControlPlaneFixture._(
        process: process,
        origin: decoded['origin'] as String,
        adminToken: decoded['admin_token'] as String,
        fixtureToken: decoded['fixture_token'] as String,
        stderr: stderr,
      );
    } catch (error) {
      process.kill(ProcessSignal.sigterm);
      await process.exitCode.timeout(
        const Duration(seconds: 5),
        onTimeout: () {
          process.kill(ProcessSignal.sigkill);
          return -1;
        },
      );
      throw StateError(
        'real control-plane fixture did not start: $error; ${stderr.toString()}',
      );
    }
  }

  Future<Map<String, Object?>> helper(
    String path,
    Map<String, Object?> body,
  ) async {
    if (!path.startsWith('/__fixture/')) {
      throw ArgumentError.value(path, 'path', 'must be a fixture helper');
    }
    final encoded = utf8.encode(jsonEncode(body));
    final request = await _helperClient.postUrl(Uri.parse('$origin$path'));
    request.headers
      ..set(HttpHeaders.contentTypeHeader, 'application/json')
      ..set('X-Mesh-Fixture-Token', fixtureToken)
      ..contentLength = encoded.length;
    request.add(encoded);
    final response = await request.close().timeout(const Duration(seconds: 15));
    final bytes = await response.fold<List<int>>(
      <int>[],
      (result, chunk) => result..addAll(chunk),
    );
    if (response.statusCode != HttpStatus.ok) {
      throw StateError(
        'fixture helper $path returned ${response.statusCode}: '
        '${utf8.decode(bytes, allowMalformed: true)}',
      );
    }
    final decoded = jsonDecode(utf8.decode(bytes));
    if (decoded is! Map<String, Object?>) {
      throw StateError('fixture helper $path returned a non-object');
    }
    return decoded;
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    _helperClient.close(force: true);
    await process.stdin.close();
    final code = await process.exitCode.timeout(
      const Duration(seconds: 10),
      onTimeout: () {
        process.kill(ProcessSignal.sigterm);
        return process.exitCode.timeout(
          const Duration(seconds: 5),
          onTimeout: () {
            process.kill(ProcessSignal.sigkill);
            return -1;
          },
        );
      },
    );
    if (code != 0) {
      throw StateError(
        'real control-plane fixture exited with $code: ${stderr.toString()}',
      );
    }
  }
}
