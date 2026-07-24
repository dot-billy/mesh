import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/shared/models/presentation_models.dart';
import 'package:mesh_desktop/shared/widgets/one_time_secret_panel.dart';

const _model = OneTimeSecretViewModel(
  id: 'enrollment_node_1',
  title: 'Enroll lighthouse-01',
  detail: 'This credential is displayed once.',
  items: [
    OneTimeSecretItemViewModel(
      label: 'Enrollment token',
      value: 'mesh-enrollment-secret-test-only',
      copyConfirmation: 'Enrollment token copied',
    ),
    OneTimeSecretItemViewModel(
      label: 'Enrollment command',
      value: 'meshctl enroll --token mesh-enrollment-secret-test-only',
      copyConfirmation: 'Enrollment command copied',
      hiddenByDefault: false,
    ),
  ],
  custodyLabel: 'I stored this credential in an approved secure location.',
);

void main() {
  testWidgets('requires custody acknowledgement and scrubs plaintext on Done', (
    tester,
  ) async {
    var acknowledged = 0;
    var scrubbed = 0;
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: OneTimeSecretPanel(
            model: _model,
            onAcknowledged: () => acknowledged++,
            onScrubbed: () => scrubbed++,
          ),
        ),
      ),
    );

    expect(find.text(_model.items.first.value), findsNothing);
    final done = find.byKey(const Key('one-time-secret-done'));
    expect(tester.widget<FilledButton>(done).onPressed, isNull);

    await tester.tap(find.byTooltip('Reveal enrollment token'));
    await tester.pump();
    expect(find.text(_model.items.first.value), findsOneWidget);

    await tester.tap(find.byType(CheckboxListTile));
    await tester.pump();
    expect(tester.widget<FilledButton>(done).onPressed, isNotNull);

    await tester.tap(done);
    await tester.pump();
    expect(acknowledged, 1);
    expect(scrubbed, 1);
    expect(find.text(_model.items.first.value), findsNothing);
    expect(find.textContaining('removed from this view'), findsOneWidget);
  });

  testWidgets('scrubs secret when the application is hidden', (tester) async {
    var scrubbed = 0;
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: OneTimeSecretPanel(
            model: _model,
            onAcknowledged: () {},
            onScrubbed: () => scrubbed++,
          ),
        ),
      ),
    );

    await tester.tap(find.byTooltip('Reveal enrollment token'));
    await tester.pump();
    expect(find.text(_model.items.first.value), findsOneWidget);

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
    await tester.pump();
    expect(scrubbed, 1);
    expect(find.text(_model.items.first.value), findsNothing);
    expect(find.textContaining('removed from this view'), findsOneWidget);

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
  });

  testWidgets('recovery custody exposes and copies only the recovery code', (
    tester,
  ) async {
    const recoveryCode = 'mesh-recovery-test-only';
    String? copied;
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
      SystemChannels.platform,
      (call) async {
        if (call.method == 'Clipboard.setData') {
          copied = (call.arguments as Map<Object?, Object?>)['text'] as String?;
        }
        return null;
      },
    );

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: OneTimeSecretPanel(
            model: const OneTimeSecretViewModel(
              id: 'recovery_1',
              title: 'Recovery code created',
              detail: 'This recovery code is displayed once.',
              items: [
                OneTimeSecretItemViewModel(
                  label: 'Recovery code',
                  value: recoveryCode,
                  copyConfirmation: 'Recovery code copied',
                ),
              ],
              custodyLabel:
                  'I stored this recovery code in an approved secure location.',
            ),
            onAcknowledged: () {},
            onScrubbed: () {},
          ),
        ),
      ),
    );

    expect(find.text('Enrollment command'), findsNothing);
    expect(find.text(recoveryCode), findsNothing);
    await tester.tap(find.byTooltip('Copy recovery code'));
    await tester.pump();
    expect(copied, recoveryCode);
    expect(find.textContaining('Recovery code copied'), findsOneWidget);

    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
      SystemChannels.platform,
      null,
    );
  });
}
