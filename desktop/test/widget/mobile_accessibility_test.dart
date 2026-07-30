import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/app/app.dart';
import 'package:mesh_desktop/app/app_shell.dart';

import 'test_fixtures.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  testWidgets(
    'iPhone and iPad layouts remain operable across enlarged text sizes',
    (tester) async {
      debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
      try {
        final model = ValueNotifier(authenticatedModel(role: MeshRole.admin));
        addTearDown(model.dispose);

        for (final size in <Size>[
          const Size(390, 844),
          const Size(844, 390),
          const Size(694, 1024),
          const Size(1024, 1366),
          const Size(1366, 1024),
        ]) {
          for (final scale in <double>[1, 2, 3.2]) {
            await tester.binding.setSurfaceSize(size);
            tester.platformDispatcher.textScaleFactorTestValue = scale;
            await tester.pumpWidget(
              MeshDesktopApp(viewModel: model, callbacks: RecordingCallbacks()),
            );
            await tester.pumpAndSettle();

            expect(
              find.byKey(const Key('mobile-navigation')),
              size.width < 1100 || size.height < 600
                  ? findsOneWidget
                  : findsNothing,
              reason: 'size=$size scale=$scale',
            );
            expect(
              find.text('Admin access'),
              findsOneWidget,
              reason: 'size=$size scale=$scale',
            );
            final layoutError = tester.takeException();
            if (layoutError case final FlutterError error) {
              fail('size=$size scale=$scale\n${error.toStringDeep()}');
            }
            expect(layoutError, isNull, reason: 'size=$size scale=$scale');
          }
        }
      } finally {
        debugDefaultTargetPlatformOverride = null;
      }
    },
  );

  testWidgets(
    'iOS accessibility features preserve labeled, motion-reduced navigation',
    (tester) async {
      debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
      try {
        final model = ValueNotifier(authenticatedModel(role: MeshRole.viewer));
        addTearDown(model.dispose);
        tester.platformDispatcher.accessibilityFeaturesTestValue =
            FakeAccessibilityFeatures.allOn;
        addTearDown(
          tester.platformDispatcher.clearAccessibilityFeaturesTestValue,
        );
        await tester.binding.setSurfaceSize(const Size(390, 844));
        await tester.pumpWidget(
          MeshDesktopApp(viewModel: model, callbacks: RecordingCallbacks()),
        );
        await tester.pumpAndSettle();

        final appContext = tester.element(find.byType(MeshAppShell));
        final media = MediaQuery.of(appContext);
        expect(media.disableAnimations, isTrue);
        expect(media.boldText, isTrue);
        expect(media.highContrast, isTrue);
        expect(media.accessibleNavigation, isTrue);

        await tester.tap(find.byTooltip('Open navigation menu'));
        await tester.pumpAndSettle();

        expect(find.bySemanticsLabel('Primary navigation'), findsOneWidget);
        expect(find.text('Viewer access'), findsWidgets);
        expect(find.text('Access'), findsNothing);
        final layoutError = tester.takeException();
        if (layoutError case final FlutterError error) {
          fail(error.toStringDeep());
        }
        expect(layoutError, isNull);
        await expectLater(tester, meetsGuideline(labeledTapTargetGuideline));
        await expectLater(tester, meetsGuideline(iOSTapTargetGuideline));
        await expectLater(tester, meetsGuideline(textContrastGuideline));
      } finally {
        debugDefaultTargetPlatformOverride = null;
      }
    },
  );
}
