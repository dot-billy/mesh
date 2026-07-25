import 'package:flutter/material.dart';

import '../models/presentation_models.dart';
import 'async_state_view.dart';
import 'evidence_badge.dart';
import 'freshness_stamp.dart';

class OperationPanel extends StatelessWidget {
  const OperationPanel({
    required this.state,
    required this.emptyTitle,
    required this.emptyMessage,
    this.onRetry,
    super.key,
  });

  final LoadableViewModel<OperationPanelViewModel> state;
  final String emptyTitle;
  final String emptyMessage;
  final VoidCallback? onRetry;

  @override
  Widget build(BuildContext context) {
    return AsyncStateView<OperationPanelViewModel>(
      state: state,
      onRetry: onRetry,
      emptyTitle: emptyTitle,
      emptyMessage: emptyMessage,
      builder: (context, panel) => Card(
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Expanded(
                    child: Text(
                      panel.title,
                      style: Theme.of(context).textTheme.titleLarge,
                    ),
                  ),
                  EvidenceBadge(tone: panel.tone),
                ],
              ),
              const SizedBox(height: 10),
              Text(panel.summary),
              if (panel.generatedAt case final generatedAt?) ...[
                const SizedBox(height: 10),
                FreshnessStamp(generatedAt: generatedAt),
              ],
              if (panel.fields.isNotEmpty) ...[
                const SizedBox(height: 18),
                Wrap(
                  spacing: 12,
                  runSpacing: 12,
                  children: [
                    for (final field in panel.fields)
                      ConstrainedBox(
                        constraints: const BoxConstraints(minWidth: 180),
                        child: DecoratedBox(
                          decoration: BoxDecoration(
                            color: Theme.of(
                              context,
                            ).colorScheme.surfaceContainerLow,
                            borderRadius: BorderRadius.circular(8),
                          ),
                          child: Padding(
                            padding: const EdgeInsets.all(12),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  field.label,
                                  style: Theme.of(
                                    context,
                                  ).textTheme.labelMedium,
                                ),
                                const SizedBox(height: 4),
                                SelectableText(field.value),
                              ],
                            ),
                          ),
                        ),
                      ),
                  ],
                ),
              ],
              for (final alert in panel.alerts) ...[
                const SizedBox(height: 12),
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  leading: Icon(alert.tone.icon),
                  title: Text(alert.title),
                  subtitle: Text(alert.detail),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }
}
