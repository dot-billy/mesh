import 'dart:async';

import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/app/app.dart';
import 'package:mesh_desktop/core/auth/secure_session_store.dart';
import 'package:mesh_desktop/core/connection/connection_profile.dart';
import 'package:mesh_desktop/core/platform/mobile_security.dart';
import 'package:mesh_desktop/core/platform/apple_managed_configuration.dart';
import 'package:mesh_desktop/core/polling/lifecycle_poller.dart';
import 'package:mesh_desktop/integration/mesh_app_controller.dart';

void main() {
  testWidgets(
    'locked secure storage keeps connection setup usable and reports the right recovery',
    (tester) async {
      final lifecycle = _TestLifecycleSource();
      final controller = MeshAppController(
        managedConfigurationSource: const NoAppleManagedConfigurationSource(),
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
        contains('Unlock the device or operating-system credential store'),
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
      managedConfigurationSource: const NoAppleManagedConfigurationSource(),
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

  test(
    'saved control plane survives sign-out and controller restart without a session',
    () async {
      final storage = _MemorySecretStorage();
      final store = SecureSessionStore(storage);
      final profile = ConnectionProfile.parse('https://saved.mesh.example');
      final origin = profile.origin;
      await store.saveConnectionProfiles([
        PersistedConnectionProfile(
          displayName: 'Local saved control plane',
          profile: profile,
        ),
      ]);

      final firstLifecycle = _TestLifecycleSource();
      final first = MeshAppController(
        managedConfigurationSource: const NoAppleManagedConfigurationSource(),
        sessionStore: store,
        lifecycle: firstLifecycle,
      );
      await first.initialize();
      expect(first.value.connection.profiles, hasLength(1));
      expect(first.value.connection.profiles.single.origin, origin);

      first.signOut();
      await Future<void>.delayed(const Duration(milliseconds: 100));
      expect(
        storage.values,
        contains(SecureSessionStore.connectionProfilesStorageKey),
      );
      expect(storage.values, isNot(contains(SecureSessionStore.storageKey)));
      first.dispose();
      await firstLifecycle.close();

      final secondLifecycle = _TestLifecycleSource();
      final second = MeshAppController(
        managedConfigurationSource: const NoAppleManagedConfigurationSource(),
        sessionStore: store,
        lifecycle: secondLifecycle,
      );
      addTearDown(() async {
        second.dispose();
        await secondLifecycle.close();
      });

      await second.initialize();

      expect(second.value.connection.profiles, hasLength(1));
      expect(
        second.value.connection.profiles.single.displayName,
        'Local saved control plane',
      );
      expect(second.value.connection.profiles.single.origin, origin);
      expect(second.value.accessContext, isNull);
    },
  );

  testWidgets(
    'lifecycle, protected-data, and network-context events erase one-time material',
    (tester) async {
      final lifecycle = _TestLifecycleSource();
      final protectedData = _TestProtectedDataEvents();
      final controller = MeshAppController(
        managedConfigurationSource: const NoAppleManagedConfigurationSource(),
        sessionStore: SecureSessionStore(_EmptySecretStorage()),
        lifecycle: lifecycle,
        protectedDataEvents: protectedData,
      );
      addTearDown(() async {
        controller.dispose();
        await lifecycle.close();
      });
      await controller.initialize();

      controller.value = _withSecret(controller.value);
      lifecycle.setState(AppLifecycleState.inactive);
      expect(controller.value.oneTimeSecret, isNull);

      controller.value = _withSecret(controller.value);
      protectedData.fire();
      expect(controller.value.oneTimeSecret, isNull);

      controller.value = _withSecret(controller.value);
      controller.selectNetwork('different-network');
      expect(controller.value.oneTimeSecret, isNull);

      controller.value = _withSecret(controller.value);
      controller.clearSelectedNetwork();
      expect(controller.value.oneTimeSecret, isNull);
    },
  );

  testWidgets(
    'confirmed local erasure removes both exact secure records and resets presentation',
    (tester) async {
      final lifecycle = _TestLifecycleSource();
      final storage = _MemorySecretStorage()
        ..values[SecureSessionStore.storageKey] = 'test-only-session'
        ..values[SecureSessionStore.connectionProfilesStorageKey] =
            'test-only-profiles';
      final controller = MeshAppController(
        managedConfigurationSource: const NoAppleManagedConfigurationSource(),
        sessionStore: SecureSessionStore(storage),
        lifecycle: lifecycle,
      );
      addTearDown(() async {
        controller.dispose();
        await lifecycle.close();
      });

      controller.value = _withSecret(controller.value);
      controller.eraseLocalData();
      await tester.pump();
      await tester.pump();

      expect(storage.values, isEmpty);
      expect(controller.value.oneTimeSecret, isNull);
      expect(controller.value.accessContext, isNull);
      expect(controller.value.connection.profiles, isEmpty);
      expect(controller.value.connection.phase, LoadPhase.ready);
      expect(
        controller.value.connection.message,
        contains('Local Mesh Admin data erased'),
      );
      expect(controller.value.receipt?.title, 'Local Mesh Admin data erased');
      expect(
        controller.value.receipt?.summary,
        contains('revocation could not be confirmed'),
      );
      expect(
        controller.value.receipt?.verification,
        contains('separately installed Mesh Node'),
      );
    },
  );

  testWidgets('invalid Apple managed configuration fails closed', (
    tester,
  ) async {
    final lifecycle = _TestLifecycleSource();
    final controller = MeshAppController(
      sessionStore: SecureSessionStore(_EmptySecretStorage()),
      lifecycle: lifecycle,
      managedConfigurationSource: const _InvalidManagedConfigurationSource(),
    );
    addTearDown(() async {
      controller.dispose();
      await lifecycle.close();
    });

    await controller.initialize();

    expect(controller.value.managedPolicy?.valid, isFalse);
    expect(controller.value.connection.phase, LoadPhase.error);
    expect(controller.value.connection.profiles, isEmpty);
    expect(
      controller.value.connection.message,
      contains('Organization-managed settings are invalid'),
    );

    controller.addConnection(
      ConnectionRequest(
        displayName: 'Direct callback bypass',
        origin: Uri.parse('http://localhost:8080'),
      ),
    );
    await tester.pump();

    expect(controller.value.connection.profiles, isEmpty);
    expect(
      controller.value.connection.message,
      contains('Connection setup is disabled'),
    );
  });

  testWidgets('managed notification policy cannot be changed locally', (
    tester,
  ) async {
    final lifecycle = _TestLifecycleSource();
    final controller = MeshAppController(
      sessionStore: SecureSessionStore(_EmptySecretStorage()),
      lifecycle: lifecycle,
      managedConfigurationSource: _StaticManagedConfigurationSource(
        AppleManagedConfiguration(
          controlPlaneOrigin: null,
          allowOriginChanges: true,
          releaseChannel: null,
          updateRing: null,
          showLocalStatus: null,
          notificationsEnabled: true,
        ),
      ),
    );
    addTearDown(() async {
      controller.dispose();
      await lifecycle.close();
    });

    await controller.initialize();
    controller.updateNotifications(false);

    expect(controller.value.preferences.notificationsEnabled, isTrue);
    expect(
      controller.value.receipt?.title,
      'Notifications managed by your organization',
    );
  });

  testWidgets('foregrounding revalidates changed managed policy', (
    tester,
  ) async {
    final lifecycle = _TestLifecycleSource();
    final source = _MutableManagedConfigurationSource();
    final controller = MeshAppController(
      sessionStore: SecureSessionStore(_EmptySecretStorage()),
      lifecycle: lifecycle,
      managedConfigurationSource: source,
    );
    addTearDown(() async {
      controller.dispose();
      await lifecycle.close();
    });

    await controller.initialize();
    expect(controller.value.managedPolicy, isNull);
    expect(controller.value.preferences.notificationsEnabled, isFalse);

    source.configuration = AppleManagedConfiguration(
      controlPlaneOrigin: null,
      allowOriginChanges: true,
      releaseChannel: 'stable',
      updateRing: 'pilot',
      showLocalStatus: false,
      notificationsEnabled: true,
    );
    lifecycle.setState(AppLifecycleState.inactive);
    lifecycle.setState(AppLifecycleState.resumed);
    await tester.pump();
    await tester.pump();

    expect(controller.value.managedPolicy?.releaseChannel, 'stable');
    expect(controller.value.preferences.notificationsEnabled, isTrue);

    source.invalid = true;
    lifecycle.setState(AppLifecycleState.inactive);
    lifecycle.setState(AppLifecycleState.resumed);
    await tester.pump();
    await tester.pump();

    expect(controller.value.managedPolicy?.valid, isFalse);
    expect(controller.value.connection.phase, LoadPhase.error);
    expect(controller.value.accessContext, isNull);
  });
}

final class _StaticManagedConfigurationSource
    implements AppleManagedConfigurationSource {
  const _StaticManagedConfigurationSource(this.configuration);

  final AppleManagedConfiguration configuration;

  @override
  Future<AppleManagedConfiguration?> load() async => configuration;
}

final class _InvalidManagedConfigurationSource
    implements AppleManagedConfigurationSource {
  const _InvalidManagedConfigurationSource();

  @override
  Future<AppleManagedConfiguration?> load() async {
    throw const AppleManagedConfigurationException('test-only-invalid');
  }
}

final class _MutableManagedConfigurationSource
    implements AppleManagedConfigurationSource {
  AppleManagedConfiguration? configuration;
  bool invalid = false;

  @override
  Future<AppleManagedConfiguration?> load() async {
    if (invalid) {
      throw const AppleManagedConfigurationException(
        'test-only-invalid-update',
      );
    }
    return configuration;
  }
}

MeshDesktopViewModel _withSecret(MeshDesktopViewModel current) {
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
      id: 'test-only',
      title: 'Test secret',
      detail: 'Test-only one-time material.',
      items: [
        OneTimeSecretItemViewModel(
          label: 'Value',
          value: 'test-only-secret',
          copyConfirmation: 'Copied',
        ),
      ],
      custodyLabel: 'Stored',
    ),
  );
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

final class _EmptySecretStorage implements SecretStorage {
  @override
  Future<void> delete(String key) async {}

  @override
  Future<String?> read(String key) async => null;

  @override
  Future<void> write(String key, String value) async {}
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

final class _TestProtectedDataEvents implements ProtectedDataEvents {
  VoidCallback? handler;

  @override
  void dispose() {
    handler = null;
  }

  void fire() => handler?.call();

  @override
  void setUnavailableHandler(VoidCallback? handler) {
    this.handler = handler;
  }
}
