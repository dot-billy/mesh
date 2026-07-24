import 'package:flutter/material.dart';

import '../../shared/callbacks/presentation_callbacks.dart';
import '../../shared/models/presentation_models.dart';
import '../../shared/widgets/async_state_view.dart';
import '../../shared/widgets/evidence_badge.dart';
import '../../shared/widgets/mutation_dialogs.dart';

class AccessScreen extends StatelessWidget {
  const AccessScreen({
    required this.state,
    required this.onRevokeSession,
    required this.onCreateRecoveryCode,
    super.key,
  });

  final LoadableViewModel<AccessManagementViewModel> state;
  final Future<MutationSubmissionResult> Function(RevokeSessionRequest request)?
  onRevokeSession;
  final Future<MutationSubmissionResult> Function()? onCreateRecoveryCode;

  Future<void> _confirmCreateRecoveryCode(BuildContext context) async {
    final callback = onCreateRecoveryCode;
    if (callback == null) return;
    await showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (context) => MutationConfirmationDialog(
        title: 'Create a recovery code?',
        detail:
            'A new one-use recovery code will be displayed once. Store it in '
            'an approved secure location before closing the custody view.',
        confirmLabel: 'Create recovery code',
        onConfirm: callback,
      ),
    );
  }

  Future<void> _confirmRevoke(
    BuildContext context,
    AccessSessionViewModel session,
  ) async {
    final callback = onRevokeSession;
    if (callback == null) return;
    await showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (context) => MutationConfirmationDialog(
        title: session.current
            ? 'Sign out this session?'
            : 'Revoke session for ${session.principal}?',
        detail: session.current
            ? 'This web or desktop session will end immediately. You will '
                  'need to authenticate again.'
            : 'The selected web or desktop session will lose access '
                  'immediately.',
        confirmLabel: session.current ? 'Sign out' : 'Revoke session',
        destructive: true,
        onConfirm: () => callback(
          RevokeSessionRequest(
            sessionId: session.id,
            principal: session.principal,
            current: session.current,
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return AsyncStateView<AccessManagementViewModel>(
      state: state,
      emptyTitle: 'No access inventory',
      emptyMessage:
          'No authenticated sessions or recovery inventory was returned.',
      builder: (context, model) => ListView(
        padding: const EdgeInsets.all(24),
        children: [
          Text('Access', style: Theme.of(context).textTheme.headlineMedium),
          const SizedBox(height: 6),
          const Text(
            'Manage web and desktop sessions and one-use recovery access.',
          ),
          if (model.recoveryInventory case final recovery?) ...[
            const SizedBox(height: 20),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(18),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: Text(
                            'Recovery codes',
                            style: Theme.of(context).textTheme.titleLarge,
                          ),
                        ),
                        EvidenceBadge(
                          tone: recovery.restartReady
                              ? EvidenceTone.healthy
                              : EvidenceTone.critical,
                          label: recovery.restartReady
                              ? 'Restart ready'
                              : 'Below floor',
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    Text(
                      '${recovery.usable} usable of ${recovery.total}; '
                      'minimum ${recovery.minimumUsable}.',
                    ),
                    const SizedBox(height: 14),
                    Tooltip(
                      message: onCreateRecoveryCode == null
                          ? 'Recovery code creation is unavailable in this session.'
                          : 'Create one-use recovery access',
                      child: FilledButton.icon(
                        key: const Key('create-recovery-code'),
                        onPressed: onCreateRecoveryCode == null
                            ? null
                            : () => _confirmCreateRecoveryCode(context),
                        icon: const Icon(Icons.add),
                        label: const Text('Create recovery code'),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
          const SizedBox(height: 20),
          Text(
            'Authenticated sessions',
            style: Theme.of(context).textTheme.titleLarge,
          ),
          const SizedBox(height: 10),
          if (model.sessions.isEmpty)
            const Card(
              child: Padding(
                padding: EdgeInsets.all(20),
                child: Text('No web or desktop sessions are listed.'),
              ),
            )
          else
            Card(
              child: Column(
                children: [
                  for (
                    var index = 0;
                    index < model.sessions.length;
                    index++
                  ) ...[
                    _SessionRow(
                      session: model.sessions[index],
                      revocationAvailable: onRevokeSession != null,
                      onRevoke: () =>
                          _confirmRevoke(context, model.sessions[index]),
                    ),
                    if (index != model.sessions.length - 1)
                      const Divider(height: 1),
                  ],
                ],
              ),
            ),
        ],
      ),
    );
  }
}

class _SessionRow extends StatelessWidget {
  const _SessionRow({
    required this.session,
    required this.revocationAvailable,
    required this.onRevoke,
  });

  final AccessSessionViewModel session;
  final VoidCallback onRevoke;
  final bool revocationAvailable;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: const Icon(Icons.devices_outlined),
      title: Text(session.principal),
      subtitle: Text(
        '${session.authMethod} · created ${session.createdAt.toLocal()}\n'
        'Expires ${session.expiresAt.toLocal()}',
      ),
      isThreeLine: true,
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (session.current)
            const Padding(
              padding: EdgeInsets.only(right: 8),
              child: EvidenceBadge(
                tone: EvidenceTone.healthy,
                label: 'Current',
                compact: true,
              ),
            ),
          Tooltip(
            message: revocationAvailable
                ? (session.current
                      ? 'Sign out this session'
                      : 'Revoke this session')
                : 'Session revocation is unavailable in this session.',
            child: OutlinedButton.icon(
              key: Key('revoke-session-${session.id}'),
              onPressed: revocationAvailable ? onRevoke : null,
              icon: const Icon(Icons.logout),
              label: Text(session.current ? 'Sign out' : 'Revoke'),
            ),
          ),
        ],
      ),
    );
  }
}
