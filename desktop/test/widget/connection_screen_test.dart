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
}
