import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/app/app.dart';
import 'package:mesh_desktop/core/platform/macos_admin_menu.dart';
import 'package:mesh_desktop/features/preferences/preferences_screen.dart';

import 'test_fixtures.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('uses extended and compact navigation at desktop breakpoints', (
    tester,
  ) async {
    final callbacks = RecordingCallbacks();
    final model = ValueNotifier(authenticatedModel());

    await tester.binding.setSurfaceSize(const Size(1280, 800));
    await tester.pumpWidget(
      MeshDesktopApp(viewModel: model, callbacks: callbacks),
    );
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('extended-navigation')), findsOneWidget);
    expect(tester.takeException(), isNull);

    await tester.binding.setSurfaceSize(const Size(900, 600));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('compact-navigation')), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('supports the macOS command-refresh shortcut', (tester) async {
    final callbacks = RecordingCallbacks();
    final model = ValueNotifier(authenticatedModel());

    await tester.binding.setSurfaceSize(const Size(1200, 760));
    await tester.pumpWidget(
      MeshDesktopApp(viewModel: model, callbacks: callbacks),
    );
    await tester.pumpAndSettle();

    await tester.sendKeyDownEvent(LogicalKeyboardKey.metaLeft);
    await tester.sendKeyEvent(LogicalKeyboardKey.keyR);
    await tester.sendKeyUpEvent(LogicalKeyboardKey.metaLeft);
    await tester.pump();

    expect(callbacks.refreshFleetCount, 1);
  });

  testWidgets('supports Command-comma keyboard navigation', (tester) async {
    final callbacks = RecordingCallbacks();
    final model = ValueNotifier(authenticatedModel());

    await tester.binding.setSurfaceSize(const Size(1200, 760));
    await tester.pumpWidget(
      MeshDesktopApp(viewModel: model, callbacks: callbacks),
    );
    await tester.pumpAndSettle();

    await tester.sendKeyDownEvent(LogicalKeyboardKey.metaLeft);
    await tester.sendKeyEvent(LogicalKeyboardKey.comma);
    await tester.sendKeyUpEvent(LogicalKeyboardKey.metaLeft);
    await tester.pump();

    expect(find.byType(PreferencesScreen), findsOneWidget);
  });

  testWidgets('fixed native macOS menu commands refresh and open preferences', (
    tester,
  ) async {
    final callbacks = RecordingCallbacks();
    final model = ValueNotifier(authenticatedModel());
    final menu = StreamController<MacAdminMenuCommand>.broadcast(sync: true);
    addTearDown(menu.close);

    await tester.binding.setSurfaceSize(const Size(1200, 760));
    await tester.pumpWidget(
      MeshDesktopApp(
        viewModel: model,
        callbacks: callbacks,
        menuCommands: menu.stream,
      ),
    );
    await tester.pumpAndSettle();

    menu.add(MacAdminMenuCommand.preferences);
    await tester.pump();
    expect(find.byType(PreferencesScreen), findsOneWidget);

    menu.add(MacAdminMenuCommand.refresh);
    await tester.pump();
    expect(callbacks.refreshFleetCount, 1);
  });

  testWidgets('remains usable with 200 percent text scaling', (tester) async {
    final callbacks = RecordingCallbacks();
    final model = ValueNotifier(authenticatedModel());
    tester.platformDispatcher.textScaleFactorTestValue = 2;
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);

    await tester.binding.setSurfaceSize(const Size(900, 700));
    await tester.pumpWidget(
      MeshDesktopApp(viewModel: model, callbacks: callbacks),
    );
    await tester.pumpAndSettle();

    expect(find.byKey(const Key('compact-navigation')), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets(
    'uses accessible compact navigation on iPhone and iPad split widths',
    (tester) async {
      final callbacks = RecordingCallbacks();
      final model = ValueNotifier(authenticatedModel(role: MeshRole.admin));

      for (final size in <Size>[const Size(390, 844), const Size(694, 1024)]) {
        await tester.binding.setSurfaceSize(size);
        await tester.pumpWidget(
          MeshDesktopApp(viewModel: model, callbacks: callbacks),
        );
        await tester.pumpAndSettle();

        expect(find.byKey(const Key('mobile-navigation')), findsOneWidget);
        expect(find.text('Admin access'), findsOneWidget);
        expect(tester.takeException(), isNull);

        await tester.tap(find.byTooltip('Open navigation menu'));
        await tester.pumpAndSettle();
        for (final label in <String>[
          'Fleet',
          'Networks',
          'Activity',
          'Access',
          'Preferences',
          'Help',
          'Sign out',
        ]) {
          expect(find.text(label), findsWidgets);
        }
        expect(tester.takeException(), isNull);
        await tester.tap(find.text('Activity').last);
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull);
      }
    },
  );

  testWidgets('iPhone navigation remains usable at 200 percent text scaling', (
    tester,
  ) async {
    final callbacks = RecordingCallbacks();
    final model = ValueNotifier(authenticatedModel(role: MeshRole.viewer));
    tester.platformDispatcher.textScaleFactorTestValue = 2;
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);

    await tester.binding.setSurfaceSize(const Size(430, 932));
    await tester.pumpWidget(
      MeshDesktopApp(viewModel: model, callbacks: callbacks),
    );
    await tester.pumpAndSettle();

    expect(find.byKey(const Key('mobile-navigation')), findsOneWidget);
    expect(find.text('Viewer access'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('iPhone selected-network navigation exposes overview and nodes', (
    tester,
  ) async {
    final callbacks = RecordingCallbacks();
    final model = ValueNotifier(
      authenticatedModel(
        role: MeshRole.admin,
        selectedNetwork: LoadableViewModel.ready(networkModel()),
      ),
    );

    await tester.binding.setSurfaceSize(const Size(390, 844));
    await tester.pumpWidget(
      MeshDesktopApp(viewModel: model, callbacks: callbacks),
    );
    await tester.pumpAndSettle();

    await tester.tap(find.byTooltip('Open navigation menu'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Networks').last);
    await tester.pumpAndSettle();

    for (final label in <String>[
      'Overview',
      'Nodes',
      'Firewall',
      'Readiness',
      'DNS',
      'Relays',
      'Routing',
      'Security',
    ]) {
      expect(find.text(label), findsOneWidget);
    }
    expect(tester.takeException(), isNull);

    await tester.tap(find.text('Nodes'));
    await tester.pumpAndSettle();

    expect(find.byKey(const Key('node-search')), findsOneWidget);
    expect(find.text('lighthouse-01'), findsOneWidget);
    await tester.drag(find.byType(ListView).last, const Offset(0, -160));
    await tester.pumpAndSettle();
    expect(find.text('app-server-01'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('iOS preferences expose foreground-only polling', (tester) async {
    final preferences = authenticatedModel().preferences;

    await tester.binding.setSurfaceSize(const Size(390, 844));
    await tester.pumpWidget(
      MaterialApp(
        theme: ThemeData(platform: TargetPlatform.iOS),
        home: Scaffold(
          body: PreferencesScreen(
            model: preferences,
            onThemeModeChanged: (_) {},
            onNotificationsChanged: (_) {},
            onBackgroundMonitoringChanged: (_) {},
            onOpenSystemSettings: () {},
            onCopyDiagnosticBundle: () {},
            onEraseLocalData: () {},
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('Foreground-only polling'), findsOneWidget);
    expect(find.text('Background monitoring'), findsNothing);
    expect(find.text('Copy bounded diagnostic bundle'), findsOneWidget);
    expect(find.textContaining('never uploaded automatically'), findsOneWidget);
    await tester.drag(find.byType(ListView), const Offset(0, -600));
    await tester.pumpAndSettle();
    expect(find.text('Before uninstalling'), findsOneWidget);
    expect(find.byKey(const Key('erase-local-data-button')), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Apple local-data erasure requires exact confirmation', (
    tester,
  ) async {
    var eraseCount = 0;

    await tester.pumpWidget(
      MaterialApp(
        theme: ThemeData(platform: TargetPlatform.macOS),
        home: Scaffold(
          body: PreferencesScreen(
            model: const PreferencesViewModel(),
            onThemeModeChanged: (_) {},
            onNotificationsChanged: (_) {},
            onBackgroundMonitoringChanged: (_) {},
            onOpenSystemSettings: () {},
            onCopyDiagnosticBundle: () {},
            onEraseLocalData: () => eraseCount++,
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    await tester.drag(find.byType(ListView), const Offset(0, -600));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('erase-local-data-button')));
    await tester.pumpAndSettle();
    expect(find.text('Erase local Mesh Admin data?'), findsOneWidget);
    expect(
      find.textContaining('separately installed Mesh Node'),
      findsOneWidget,
    );
    expect(eraseCount, 0);

    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
    expect(eraseCount, 0);

    await tester.tap(find.byKey(const Key('erase-local-data-button')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('confirm-erase-local-data-button')));
    await tester.pumpAndSettle();
    expect(eraseCount, 1);
  });

  testWidgets(
    'shows Access only to Admin and hides network creation from Viewer',
    (tester) async {
      final callbacks = RecordingCallbacks();
      final viewer = ValueNotifier(authenticatedModel(role: MeshRole.viewer));

      await tester.binding.setSurfaceSize(const Size(1280, 800));
      await tester.pumpWidget(
        MeshDesktopApp(viewModel: viewer, callbacks: callbacks),
      );
      await tester.pumpAndSettle();
      expect(find.text('Access'), findsNothing);

      await tester.tap(
        find.descendant(
          of: find.byType(NavigationRail),
          matching: find.text('Networks'),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('new-network-button')), findsNothing);

      final admin = ValueNotifier(authenticatedModel(role: MeshRole.admin));
      await tester.pumpWidget(
        MeshDesktopApp(viewModel: admin, callbacks: callbacks),
      );
      await tester.pumpAndSettle();
      expect(find.text('Access'), findsOneWidget);
    },
  );

  testWidgets(
    'exact server permissions override role-derived privileged affordances',
    (tester) async {
      final callbacks = RecordingCallbacks();
      final model = ValueNotifier(
        authenticatedModel(
          role: MeshRole.admin,
          permissions: const <MeshPermission>{MeshPermission.networksRead},
        ),
      );

      await tester.binding.setSurfaceSize(const Size(1280, 800));
      await tester.pumpWidget(
        MeshDesktopApp(viewModel: model, callbacks: callbacks),
      );
      await tester.pumpAndSettle();

      expect(find.text('Admin access'), findsOneWidget);
      expect(find.text('Access'), findsNothing);
      await tester.tap(
        find.descendant(
          of: find.byType(NavigationRail),
          matching: find.text('Networks'),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('new-network-button')), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'network shell exposes stable subnavigation and viewer read-only state',
    (tester) async {
      final callbacks = RecordingCallbacks();
      final model = ValueNotifier(
        authenticatedModel(
          role: MeshRole.viewer,
          selectedNetwork: LoadableViewModel.ready(networkModel()),
        ),
      );

      await tester.binding.setSurfaceSize(const Size(1280, 800));
      await tester.pumpWidget(
        MeshDesktopApp(viewModel: model, callbacks: callbacks),
      );
      await tester.pumpAndSettle();
      await tester.tap(
        find.descendant(
          of: find.byType(NavigationRail),
          matching: find.text('Networks'),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text('Overview'), findsOneWidget);
      expect(find.text('Nodes'), findsOneWidget);
      expect(find.text('Firewall'), findsOneWidget);
      expect(find.text('Readiness'), findsOneWidget);
      expect(find.text('DNS'), findsOneWidget);
      expect(find.text('Relays'), findsOneWidget);
      expect(find.text('Routing'), findsOneWidget);
      expect(find.text('Security'), findsOneWidget);

      await tester.tap(find.text('Security'));
      await tester.pumpAndSettle();
      expect(find.textContaining('Admin permission required'), findsOneWidget);
    },
  );
}
