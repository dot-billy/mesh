import 'dart:async';

import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/app/app.dart';
import 'package:mesh_desktop/core/auth/secure_session_store.dart';
import 'package:mesh_desktop/core/polling/lifecycle_poller.dart';
import 'package:mesh_desktop/integration/mesh_app_controller.dart';

void main() {
  testWidgets(
    'locked secure storage keeps connection setup usable and reports the right recovery',
    (tester) async {
      final lifecycle = _TestLifecycleSource();
      final controller = MeshAppController(
        sessionStore: SecureSessionStore(_LockedSecretStorage()),
        lifecycle: lifecycle,
      );
      addTearDown(() async {
        controller.dispose();
        await lifecycle.close();
      });

      await controller.initialize();

      expect(controller.value.connection.phase, LoadPhase.ready);
      expect(controller.value.connection.profiles, isEmpty);
      expect(
        controller.value.connection.message,
        contains('Unlock the operating system keyring'),
      );
      expect(
        controller.value.connection.message,
        isNot(contains('control-plane URL')),
      );
    },
  );

  testWidgets('invalid saved session is removed without exposing its cause', (
    tester,
  ) async {
    final lifecycle = _TestLifecycleSource();
    final storage = _InvalidSecretStorage();
    final controller = MeshAppController(
      sessionStore: SecureSessionStore(storage),
      lifecycle: lifecycle,
    );
    addTearDown(() async {
      controller.dispose();
      await lifecycle.close();
    });

    await controller.initialize();

    expect(storage.deleted, isTrue);
    expect(
      controller.value.connection.message,
      'The saved session was invalid and has been removed. Sign in again.',
    );
    expect(controller.value.connection.phase, LoadPhase.ready);
  });
}

final class _LockedSecretStorage implements SecretStorage {
  @override
  Future<void> delete(String key) async => throw StateError('keyring locked');

  @override
  Future<String?> read(String key) async => throw StateError('keyring locked');

  @override
  Future<void> write(String key, String value) async =>
      throw StateError('keyring locked');
}

final class _InvalidSecretStorage implements SecretStorage {
  bool deleted = false;

  @override
  Future<void> delete(String key) async {
    deleted = true;
  }

  @override
  Future<String?> read(String key) async =>
      '{"schema":"mesh-desktop-session-v1","secret":"must-not-leak"}';

  @override
  Future<void> write(String key, String value) async {}
}

final class _TestLifecycleSource implements LifecycleSource {
  final StreamController<AppLifecycleState> _changes =
      StreamController<AppLifecycleState>.broadcast(sync: true);

  @override
  Stream<AppLifecycleState> get changes => _changes.stream;

  @override
  AppLifecycleState get currentState => AppLifecycleState.paused;

  Future<void> close() => _changes.close();
}
