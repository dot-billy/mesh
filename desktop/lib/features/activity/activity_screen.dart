import 'package:flutter/material.dart';

import '../../shared/models/presentation_models.dart';
import '../../shared/widgets/async_state_view.dart';
import '../../shared/widgets/evidence_badge.dart';

class ActivityScreen extends StatefulWidget {
  const ActivityScreen({
    required this.state,
    required this.onRefresh,
    super.key,
  });

  final LoadableViewModel<List<ActivityEventViewModel>> state;
  final VoidCallback onRefresh;

  @override
  State<ActivityScreen> createState() => _ActivityScreenState();
}

class _ActivityScreenState extends State<ActivityScreen> {
  String _query = '';

  @override
  Widget build(BuildContext context) {
    return AsyncStateView<List<ActivityEventViewModel>>(
      state: widget.state,
      onRetry: widget.onRefresh,
      emptyTitle: 'No security activity',
      emptyMessage: 'No append-only audit events were returned.',
      loadingLabel: 'Loading security activity',
      builder: (context, events) {
        final query = _query.trim().toLowerCase();
        final filtered = events.where((event) {
          return query.isEmpty ||
              event.action.toLowerCase().contains(query) ||
              event.resource.toLowerCase().contains(query) ||
              event.actor.toLowerCase().contains(query);
        }).toList();
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(24, 20, 24, 12),
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      'Activity',
                      style: Theme.of(context).textTheme.headlineMedium,
                    ),
                  ),
                  IconButton(
                    tooltip: 'Refresh activity',
                    onPressed: widget.onRefresh,
                    icon: const Icon(Icons.refresh),
                  ),
                ],
              ),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24),
              child: TextField(
                key: const Key('activity-search'),
                decoration: const InputDecoration(
                  labelText: 'Filter by action, resource, or actor',
                  prefixIcon: Icon(Icons.search),
                ),
                onChanged: (value) => setState(() => _query = value),
              ),
            ),
            const SizedBox(height: 12),
            Expanded(
              child: filtered.isEmpty
                  ? const Center(child: Text('No events match this filter.'))
                  : ListView.separated(
                      padding: const EdgeInsets.fromLTRB(24, 0, 24, 24),
                      itemCount: filtered.length,
                      separatorBuilder: (_, _) => const SizedBox(height: 8),
                      itemBuilder: (context, index) {
                        return _ActivityRow(event: filtered[index]);
                      },
                    ),
            ),
          ],
        );
      },
    );
  }
}

class _ActivityRow extends StatelessWidget {
  const _ActivityRow({required this.event});

  final ActivityEventViewModel event;

  @override
  Widget build(BuildContext context) {
    final time = event.occurredAt.toLocal();
    return Semantics(
      label: '${event.action}, ${event.resource}, by ${event.actor}, at $time',
      container: true,
      child: Card(
        child: ListTile(
          leading: Icon(event.tone.icon),
          title: Text(event.action),
          subtitle: Text(
            '${event.resource} · ${event.actor}'
            '${event.detail == null ? '' : '\n${event.detail}'}',
          ),
          isThreeLine: event.detail != null,
          trailing: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              EvidenceBadge(tone: event.tone, compact: true),
              const SizedBox(height: 4),
              Text(
                '${time.hour.toString().padLeft(2, '0')}:'
                '${time.minute.toString().padLeft(2, '0')}',
              ),
            ],
          ),
        ),
      ),
    );
  }
}
