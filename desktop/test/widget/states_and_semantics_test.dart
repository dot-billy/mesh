import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/features/fleet/fleet_screen.dart';
import 'package:mesh_desktop/shared/models/presentation_models.dart';
import 'package:mesh_desktop/shared/theme/mesh_theme.dart';
import 'package:mesh_desktop/shared/widgets/evidence_badge.dart';

import 'test_fixtures.dart';

Widget _host(Widget child) {
  return MaterialApp(
    theme: MeshTheme.light(TargetPlatform.windows),
    home: Scaffold(body: child),
  );
}

void main() {
  testWidgets('evidence badge exposes status text and icon semantics', (
    tester,
  ) async {
    final semantics = tester.ensureSemantics();
    await tester.pumpWidget(
      _host(
        const Center(
          child: EvidenceBadge(
            tone: EvidenceTone.critical,
            label: 'Node offline',
          ),
        ),
      ),
    );

    expect(find.text('Node offline'), findsOneWidget);
    final node = tester.getSemantics(find.byType(EvidenceBadge));
    expect(node.label, contains('Status: Node offline'));
    expect(find.byIcon(Icons.error_outline), findsOneWidget);
    semantics.dispose();
  });

  testWidgets('fleet loading does not render false zero values', (
    tester,
  ) async {
    await tester.pumpWidget(
      _host(
        FleetScreen(
          state: const LoadableViewModel.loading(),
          onRefresh: () {},
          onSelectNetwork: (_) {},
        ),
      ),
    );
    expect(find.text('Loading authoritative fleet health'), findsOneWidget);
    expect(find.text('0'), findsNothing);
  });

  testWidgets('fleet empty and error states are explicit and recoverable', (
    tester,
  ) async {
    var retries = 0;
    await tester.pumpWidget(
      _host(
        FleetScreen(
          state: const LoadableViewModel.empty(
            message: 'No network inventory was returned.',
          ),
          onRefresh: () => retries++,
          onSelectNetwork: (_) {},
        ),
      ),
    );
    expect(find.text('No networks yet'), findsOneWidget);
    expect(find.text('No network inventory was returned.'), findsOneWidget);

    await tester.pumpWidget(
      _host(
        FleetScreen(
          state: const LoadableViewModel.error(
            'Control plane unavailable. Last state is not authoritative.',
          ),
          onRefresh: () => retries++,
          onSelectNetwork: (_) {},
        ),
      ),
    );
    expect(
      find.text('Control plane unavailable. Last state is not authoritative.'),
      findsOneWidget,
    );
    await tester.tap(find.text('Try again'));
    expect(retries, 1);
  });

  testWidgets('ready fleet announces exact network status in semantics', (
    tester,
  ) async {
    await tester.binding.setSurfaceSize(const Size(1200, 1600));
    final semantics = tester.ensureSemantics();
    await tester.pumpWidget(
      _host(
        FleetScreen(
          state: LoadableViewModel.ready(fleetModel()),
          onRefresh: () {},
          onSelectNetwork: (_) {},
        ),
      ),
    );
    await tester.pump();
    expect(
      find.bySemanticsLabel(
        RegExp(
          'production-core, 10.42.0.0/24, Setup in progress, '
          '3 of 4 nodes online',
        ),
      ),
      findsOneWidget,
    );
    semantics.dispose();
  });
}
