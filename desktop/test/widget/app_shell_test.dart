import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/app/app.dart';

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
