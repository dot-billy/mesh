import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/features/auth/connection_screen.dart';
import 'package:mesh_desktop/shared/models/presentation_models.dart';

import 'test_fixtures.dart';

Widget _host(RecordingCallbacks callbacks) {
  return MaterialApp(
    home: ConnectionScreen(
      model: const ConnectionViewModel(),
      callbacks: callbacks,
    ),
  );
}

void main() {
  testWidgets('offers an explicit browser sign-in cancellation action', (
    tester,
  ) async {
    final callbacks = RecordingCallbacks();
    await tester.pumpWidget(
      MaterialApp(
        home: ConnectionScreen(
          model: ConnectionViewModel(
            profiles: [
              ConnectionProfileViewModel(
                id: 'profile_1',
                displayName: 'Production',
                origin: _productionOrigin,
                tlsTrusted: true,
              ),
            ],
            selectedProfileId: 'profile_1',
            methods: [AuthenticationMethod.oidc],
            phase: LoadPhase.loading,
            message: 'Approve this sign-in in the browser.',
            canCancelAuthentication: true,
          ),
          callbacks: callbacks,
        ),
      ),
    );

    await tester.tap(find.byKey(const Key('cancel-desktop-sign-in')));
    await tester.pump();

    expect(callbacks.authenticationCancelledCount, 1);
  });

  testWidgets('accepts exact localhost HTTP for local development', (
    tester,
  ) async {
    final callbacks = RecordingCallbacks();
    await tester.pumpWidget(_host(callbacks));

    await tester.enterText(
      find.byKey(const Key('connection-name')),
      'Local development',
    );
    await tester.enterText(
      find.byKey(const Key('connection-origin')),
      'http://localhost:8080',
    );
    await tester.tap(find.byKey(const Key('add-control-plane')));
    await tester.pump();

    expect(callbacks.addedConnections, hasLength(1));
    expect(
      callbacks.addedConnections.single.origin,
      Uri.parse('http://localhost:8080'),
    );
  });

  testWidgets('rejects a non-loopback host containing localhost', (
    tester,
  ) async {
    final callbacks = RecordingCallbacks();
    await tester.pumpWidget(_host(callbacks));

    await tester.enterText(
      find.byKey(const Key('connection-name')),
      'Unsafe lookalike',
    );
    await tester.enterText(
      find.byKey(const Key('connection-origin')),
      'http://localhost.evil.example:8080',
    );
    await tester.tap(find.byKey(const Key('add-control-plane')));
    await tester.pump();

    expect(callbacks.addedConnections, isEmpty);
    expect(
      find.text('Use HTTPS. Cleartext HTTP is allowed only on loopback.'),
      findsOneWidget,
    );
  });

  testWidgets('locked managed origin removes the local connection form', (
    tester,
  ) async {
    final callbacks = RecordingCallbacks();
    await tester.pumpWidget(
      MaterialApp(
        home: ConnectionScreen(
          model: const ConnectionViewModel(),
          managedPolicy: AppleManagedPolicyViewModel(
            valid: true,
            controlPlaneOrigin: Uri.parse('https://mesh.example.com/'),
            allowOriginChanges: false,
          ),
          callbacks: callbacks,
        ),
      ),
    );

    expect(find.byKey(const Key('connection-name')), findsNothing);
    expect(find.byKey(const Key('connection-origin')), findsNothing);
    expect(
      find.textContaining('locks this app to https://mesh.example.com/'),
      findsOneWidget,
    );
  });

  testWidgets('invalid managed policy disables connection setup', (
    tester,
  ) async {
    final callbacks = RecordingCallbacks();
    await tester.pumpWidget(
      MaterialApp(
        home: ConnectionScreen(
          model: const ConnectionViewModel(),
          managedPolicy: const AppleManagedPolicyViewModel.invalid(),
          callbacks: callbacks,
        ),
      ),
    );

    expect(find.byKey(const Key('add-control-plane')), findsNothing);
    expect(find.textContaining('Connection setup is disabled'), findsOneWidget);
  });
}

final Uri _productionOrigin = Uri.parse('https://mesh.example');
