import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/app/app.dart';
import 'package:mesh_desktop/features/access/access_screen.dart';
import 'package:mesh_desktop/features/nodes/nodes_screen.dart';

import 'test_fixtures.dart';

Widget _host(Widget child) {
  return MaterialApp(home: Scaffold(body: child));
}

void main() {
  testWidgets('network creation submits validated typed input', (tester) async {
    final callbacks = RecordingCallbacks();
    final model = ValueNotifier(authenticatedModel());
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
    await tester.tap(find.byKey(const Key('new-network-button')));
    await tester.pumpAndSettle();

    await tester.enterText(
      find.byKey(const Key('create-network-name')),
      'engineering',
    );
    await tester.enterText(
      find.byKey(const Key('create-network-cidr')),
      '10.60.0.0/24',
    );
    await tester.tap(find.byKey(const Key('submit-create-network')));
    await tester.pumpAndSettle();

    expect(callbacks.createdNetworks, hasLength(1));
    expect(callbacks.createdNetworks.single.name, 'engineering');
    expect(callbacks.createdNetworks.single.cidr, '10.60.0.0/24');
    expect(find.byType(AlertDialog), findsNothing);
  });

  testWidgets('unwired mutation controls fail closed', (tester) async {
    final model = ValueNotifier(authenticatedModel());
    await tester.binding.setSurfaceSize(const Size(1280, 800));
    await tester.pumpWidget(
      MeshDesktopApp(
        viewModel: model,
        callbacks: const NoopMeshPresentationCallbacks(),
      ),
    );
    await tester.pumpAndSettle();

    await tester.tap(
      find.descendant(
        of: find.byType(NavigationRail),
        matching: find.text('Networks'),
      ),
    );
    await tester.pumpAndSettle();

    final button = tester.widget<FilledButton>(
      find.byKey(const Key('new-network-button')),
    );
    expect(button.onPressed, isNull);

    await tester.tap(
      find.descendant(
        of: find.byType(NavigationRail),
        matching: find.text('Access'),
      ),
    );
    await tester.pumpAndSettle();
    expect(
      tester
          .widget<FilledButton>(find.byKey(const Key('create-recovery-code')))
          .onPressed,
      isNull,
    );
    expect(
      tester
          .widget<OutlinedButton>(
            find.byKey(const Key('revoke-session-session_1')),
          )
          .onPressed,
      isNull,
    );
  });

  testWidgets('node creation and reissue use typed confirmation flows', (
    tester,
  ) async {
    final callbacks = RecordingCallbacks();
    final network = networkModel();
    await tester.binding.setSurfaceSize(const Size(1400, 900));
    await tester.pumpWidget(
      _host(
        NodesScreen(
          networkId: network.network.id,
          nodes: network.nodes,
          role: MeshRole.admin,
          mutationCallbacks: callbacks,
          onSelectNode: (_) {},
        ),
      ),
    );

    await tester.tap(find.byKey(const Key('new-node-button')));
    await tester.pumpAndSettle();
    await tester.enterText(
      find.byKey(const Key('create-node-name')),
      'worker-02',
    );
    await tester.enterText(
      find.byKey(const Key('create-node-site')),
      'nyc-office',
    );
    await tester.enterText(
      find.byKey(const Key('create-node-failure-domain')),
      'nyc-rack-8',
    );
    await tester.enterText(
      find.byKey(const Key('create-node-groups')),
      'servers, production, servers',
    );
    await tester.tap(find.byKey(const Key('submit-create-node')));
    await tester.pumpAndSettle();

    expect(callbacks.createdEnrollments, hasLength(1));
    final enrollment = callbacks.createdEnrollments.single;
    expect(enrollment.networkId, 'network_1');
    expect(enrollment.name, 'worker-02');
    expect(enrollment.role, MeshNodeRole.member);
    expect(enrollment.groups, ['servers', 'production']);
    expect(enrollment.publicEndpoint, isNull);

    await tester.tap(find.text('app-server-01'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('reissue-enrollment-button')));
    await tester.pumpAndSettle();
    expect(find.text('Reissue enrollment for app-server-01?'), findsOneWidget);
    await tester.tap(find.byKey(const Key('confirm-mutation')));
    await tester.pumpAndSettle();

    expect(callbacks.reissuedEnrollments, hasLength(1));
    expect(callbacks.reissuedEnrollments.single.nodeId, 'node_2');
  });

  testWidgets('lighthouse enrollment requires and submits a public endpoint', (
    tester,
  ) async {
    final callbacks = RecordingCallbacks();
    final network = networkModel();
    await tester.binding.setSurfaceSize(const Size(1400, 900));
    await tester.pumpWidget(
      _host(
        NodesScreen(
          networkId: network.network.id,
          nodes: network.nodes,
          role: MeshRole.admin,
          mutationCallbacks: callbacks,
          onSelectNode: (_) {},
        ),
      ),
    );

    await tester.tap(find.byKey(const Key('new-node-button')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('create-node-role')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Lighthouse').last);
    await tester.pumpAndSettle();
    expect(
      find.byKey(const Key('create-node-public-endpoint')),
      findsOneWidget,
    );

    await tester.enterText(
      find.byKey(const Key('create-node-name')),
      'lighthouse-02',
    );
    await tester.enterText(
      find.byKey(const Key('create-node-site')),
      'nyc-office',
    );
    await tester.enterText(
      find.byKey(const Key('create-node-failure-domain')),
      'nyc-rack-9',
    );
    await tester.tap(find.byKey(const Key('submit-create-node')));
    await tester.pumpAndSettle();
    expect(find.text('Enter the lighthouse public endpoint.'), findsOneWidget);
    expect(callbacks.createdEnrollments, isEmpty);

    await tester.enterText(
      find.byKey(const Key('create-node-public-endpoint')),
      'vpn.example.com:4242',
    );
    await tester.tap(find.byKey(const Key('submit-create-node')));
    await tester.pumpAndSettle();

    expect(callbacks.createdEnrollments, hasLength(1));
    expect(
      callbacks.createdEnrollments.single.publicEndpoint,
      'vpn.example.com:4242',
    );
  });

  testWidgets(
    'certificate rotation confirms and irreversible revocation requires exact name',
    (tester) async {
      final callbacks = RecordingCallbacks();
      final network = networkModel();
      await tester.binding.setSurfaceSize(const Size(1400, 900));
      await tester.pumpWidget(
        _host(
          NodesScreen(
            networkId: network.network.id,
            nodes: network.nodes,
            role: MeshRole.admin,
            mutationCallbacks: callbacks,
            onSelectNode: (_) {},
          ),
        ),
      );

      await tester.tap(find.text('lighthouse-01'));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('rotate-certificate-button')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('confirm-mutation')));
      await tester.pumpAndSettle();
      expect(callbacks.rotatedCertificates.single.nodeId, 'node_1');

      await tester.tap(find.byKey(const Key('revoke-node-button')));
      await tester.pumpAndSettle();
      final confirm = find.byKey(const Key('confirm-exact-name-mutation'));
      expect(tester.widget<FilledButton>(confirm).onPressed, isNull);

      await tester.enterText(
        find.byKey(const Key('exact-name-confirmation')),
        'lighthouse-1',
      );
      await tester.pump();
      expect(tester.widget<FilledButton>(confirm).onPressed, isNull);

      await tester.enterText(
        find.byKey(const Key('exact-name-confirmation')),
        'lighthouse-01',
      );
      await tester.pump();
      expect(tester.widget<FilledButton>(confirm).onPressed, isNotNull);
      await tester.tap(confirm);
      await tester.pumpAndSettle();

      expect(callbacks.revokedNodes, hasLength(1));
      expect(callbacks.revokedNodes.single.confirmedName, 'lighthouse-01');
    },
  );

  testWidgets('session wording and revocation cover web and desktop', (
    tester,
  ) async {
    final callbacks = RecordingCallbacks();
    final model = authenticatedModel().accessManagement.data!;
    await tester.binding.setSurfaceSize(const Size(1000, 800));
    await tester.pumpWidget(
      _host(
        AccessScreen(
          state: LoadableViewModel.ready(model),
          onRevokeSession: callbacks.revokeAccessSession,
          onCreateRecoveryCode: callbacks.createRecoveryAccess,
        ),
      ),
    );

    expect(
      find.text('Manage web and desktop sessions and one-use recovery access.'),
      findsOneWidget,
    );
    expect(find.text('Authenticated sessions'), findsOneWidget);
    await tester.tap(find.byKey(const Key('create-recovery-code')));
    await tester.pumpAndSettle();
    expect(find.text('Create a recovery code?'), findsOneWidget);
    await tester.tap(find.byKey(const Key('confirm-mutation')));
    await tester.pumpAndSettle();
    expect(callbacks.recoveryAccessCreatedCount, 1);

    await tester.tap(find.byKey(const Key('revoke-session-session_1')));
    await tester.pumpAndSettle();
    expect(find.text('Sign out this session?'), findsOneWidget);
    await tester.tap(find.byKey(const Key('confirm-mutation')));
    await tester.pumpAndSettle();

    expect(callbacks.revokedAccessSessions, hasLength(1));
    expect(callbacks.revokedAccessSessions.single.sessionId, 'session_1');
    expect(callbacks.revokedAccessSessions.single.current, isTrue);
  });

  testWidgets('failed async mutation remains open with explicit error', (
    tester,
  ) async {
    final model = authenticatedModel().accessManagement.data!;
    await tester.binding.setSurfaceSize(const Size(1000, 800));
    await tester.pumpWidget(
      _host(
        AccessScreen(
          state: LoadableViewModel.ready(model),
          onRevokeSession: (_) async => const MutationSubmissionResult.failed(
            'The session changed. Refresh and try again.',
          ),
          onCreateRecoveryCode: null,
        ),
      ),
    );

    await tester.tap(find.byKey(const Key('revoke-session-session_1')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('confirm-mutation')));
    await tester.pumpAndSettle();

    expect(find.byType(AlertDialog), findsOneWidget);
    expect(
      find.text('The session changed. Refresh and try again.'),
      findsOneWidget,
    );
  });
}
