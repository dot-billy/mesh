import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/core/connection/connection_profile.dart';
import 'package:mesh_desktop/core/transport/json_transport.dart';
import 'package:mesh_desktop/core/transport/legacy_admin_bearer.dart';
import 'package:mesh_desktop/integration/mesh_api.dart';

void main() {
  final environment = Platform.environment;
  final enabled = environment['MESH_APPLE_EXTERNAL_CONTROL_PLANE'] == '1';

  test(
    'desktop API reads the external test control plane without changing it',
    () async {
      final origin = _requiredEnvironment(environment, 'MESH_URL');
      final token = _requiredEnvironment(environment, 'MESH_ADMIN_TOKEN');
      expect(environment['MESH_AUTH_MODE'], 'hybrid-oidc');

      final profile = ConnectionProfile.parse(origin);
      final transport = DartIoJsonTransport(
        profile: profile,
        legacyBearerProvider: () async => LegacyAdministratorBearer(token),
      );
      addTearDown(() => transport.close(force: true));
      final api = MeshApi(profile: profile, transport: transport);

      final methods = await _liveStep(
        'authentication methods',
        api.authenticationMethods,
      );
      expect(methods.oidc, isTrue);
      expect(methods.legacyBrowserLogin, isFalse);
      expect(methods.breakGlass, isFalse);

      final session = await _liveStep(
        'legacy administrator bearer session',
        api.currentSession,
      );
      expect(session.permissions, isNotEmpty);
      expect(transport.cookieJar.isComplete, isFalse);

      final networks = await _liveStep('network inventory', api.networks);
      expect(await _liveStep('fleet health', api.fleetHealth), isNotEmpty);
      expect(
        await _liveStep('runtime telemetry', api.runtimeTelemetry),
        isNotNull,
      );
      for (final network in networks) {
        final networkId = network['id'];
        expect(networkId, isA<String>());
        final id = networkId! as String;
        expect(
          await _liveStep('node inventory', () => api.nodes(id)),
          isA<List<Map<String, Object?>>>(),
        );
        expect(
          await _liveStep('network readiness', () => api.readiness(id)),
          isNotEmpty,
        );
        expect(
          await _liveStep('firewall policy', () => api.firewall(id)),
          isNotEmpty,
        );
        expect(await _liveStep('DNS policy', () => api.dns(id)), isNotEmpty);
        expect(
          await _liveStep('relay policy', () => api.relays(id)),
          isNotEmpty,
        );
        expect(
          await _liveStep('route policy', () => api.routePolicies(id)),
          isNotEmpty,
        );
        expect(
          await _liveStep('CA rotation', () => api.caRotation(id)),
          isNotEmpty,
        );
      }
      expect(
        await _liveStep('audit events', api.auditEvents),
        isA<List<Map<String, Object?>>>(),
      );
      expect(
        await _liveStep('session inventory', api.sessions),
        isA<List<Map<String, Object?>>>(),
      );
      expect(transport.cookieJar.isComplete, isFalse);
    },
    skip: enabled
        ? false
        : 'Set MESH_APPLE_EXTERNAL_CONTROL_PLANE=1 for the opt-in live test.',
  );
}

String _requiredEnvironment(Map<String, String> environment, String name) {
  final value = environment[name];
  if (value == null || value.isEmpty) {
    throw StateError('$name is required for the external control-plane test.');
  }
  return value;
}

Future<T> _liveStep<T>(String name, Future<T> Function() operation) async {
  try {
    return await operation();
  } catch (error) {
    throw StateError('External control-plane step failed: $name ($error)');
  }
}
