import 'package:flutter/material.dart';

import '../../shared/models/presentation_models.dart';
import '../../shared/widgets/async_state_view.dart';
import '../../shared/widgets/evidence_badge.dart';
import '../../shared/widgets/freshness_stamp.dart';

class FleetScreen extends StatelessWidget {
  const FleetScreen({
    required this.state,
    required this.onRefresh,
    required this.onSelectNetwork,
    super.key,
  });

  final LoadableViewModel<FleetViewModel> state;
  final VoidCallback onRefresh;
  final ValueChanged<String> onSelectNetwork;

  @override
  Widget build(BuildContext context) {
    return AsyncStateView<FleetViewModel>(
      state: state,
      onRetry: onRefresh,
      emptyTitle: 'No networks yet',
      emptyMessage:
          'Create a network to begin managing a private Nebula trust domain.',
      loadingLabel: 'Loading authoritative fleet health',
      builder: (context, fleet) => _FleetContent(
        fleet: fleet,
        onRefresh: onRefresh,
        onSelectNetwork: onSelectNetwork,
      ),
    );
  }
}

class _FleetContent extends StatelessWidget {
  const _FleetContent({
    required this.fleet,
    required this.onRefresh,
    required this.onSelectNetwork,
  });

  final FleetViewModel fleet;
  final VoidCallback onRefresh;
  final ValueChanged<String> onSelectNetwork;

  @override
  Widget build(BuildContext context) {
    return RefreshIndicator(
      onRefresh: () async => onRefresh(),
      child: ListView(
        key: const Key('fleet-scroll-view'),
        padding: const EdgeInsets.all(24),
        children: [
          Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Fleet',
                      style: Theme.of(context).textTheme.headlineMedium,
                    ),
                    const SizedBox(height: 6),
                    FreshnessStamp(generatedAt: fleet.generatedAt),
                  ],
                ),
              ),
              EvidenceBadge(tone: fleet.tone),
              const SizedBox(width: 8),
              IconButton(
                tooltip: 'Refresh fleet',
                onPressed: onRefresh,
                icon: const Icon(Icons.refresh),
              ),
            ],
          ),
          const SizedBox(height: 20),
          Wrap(
            spacing: 12,
            runSpacing: 12,
            children: [
              for (final metric in fleet.metrics) _MetricCard(metric: metric),
            ],
          ),
          const SizedBox(height: 16),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Expanded(
                        child: Text(
                          'Fleet rollout',
                          style: TextStyle(fontWeight: FontWeight.w700),
                        ),
                      ),
                      Text(fleet.rolloutLabel),
                    ],
                  ),
                  const SizedBox(height: 10),
                  Semantics(
                    label: fleet.rolloutFraction == null
                        ? 'Fleet rollout unavailable'
                        : 'Fleet rollout ${(fleet.rolloutFraction! * 100).round()} percent',
                    child: LinearProgressIndicator(
                      value: fleet.rolloutFraction,
                    ),
                  ),
                ],
              ),
            ),
          ),
          if (fleet.alerts.isNotEmpty) ...[
            const SizedBox(height: 16),
            _AlertPanel(alerts: fleet.alerts),
          ],
          const SizedBox(height: 24),
          Text('Networks', style: Theme.of(context).textTheme.titleLarge),
          const SizedBox(height: 10),
          if (fleet.networks.isEmpty)
            const Card(
              child: Padding(
                padding: EdgeInsets.all(24),
                child: Text('No network inventory is available.'),
              ),
            )
          else
            Card(
              child: Column(
                children: [
                  for (
                    var index = 0;
                    index < fleet.networks.length;
                    index++
                  ) ...[
                    _NetworkRow(
                      network: fleet.networks[index],
                      onPressed: () =>
                          onSelectNetwork(fleet.networks[index].id),
                    ),
                    if (index != fleet.networks.length - 1)
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

class _MetricCard extends StatelessWidget {
  const _MetricCard({required this.metric});

  final FleetMetricViewModel metric;

  @override
  Widget build(BuildContext context) {
    return Semantics(
      label: '${metric.label}: ${metric.value}',
      child: SizedBox(
        width: 190,
        child: Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  metric.value,
                  style: Theme.of(context).textTheme.headlineSmall,
                ),
                const SizedBox(height: 4),
                Text(metric.label),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _AlertPanel extends StatelessWidget {
  const _AlertPanel({required this.alerts});

  final List<AlertViewModel> alerts;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: ExpansionTile(
        initiallyExpanded: true,
        leading: const Icon(Icons.warning_amber_rounded),
        title: Text(
          '${alerts.length} ${alerts.length == 1 ? 'alert needs' : 'alerts need'} attention',
        ),
        children: [
          for (final alert in alerts)
            ListTile(
              leading: Icon(alert.tone.icon),
              title: Text(alert.title),
              subtitle: Text(alert.detail),
              trailing: alert.resourceLabel == null
                  ? null
                  : Text(alert.resourceLabel!),
            ),
        ],
      ),
    );
  }
}

class _NetworkRow extends StatelessWidget {
  const _NetworkRow({required this.network, required this.onPressed});

  final NetworkSummaryViewModel network;
  final VoidCallback onPressed;

  @override
  Widget build(BuildContext context) {
    return Semantics(
      button: true,
      excludeSemantics: true,
      label:
          '${network.name}, ${network.cidr}, ${network.statusLabel}, '
          '${network.onlineNodes} of ${network.totalNodes} nodes online, '
          'next action ${network.nextAction}',
      child: InkWell(
        onTap: onPressed,
        child: LayoutBuilder(
          builder: (context, constraints) {
            if (constraints.maxWidth < 800) {
              return ListTile(
                contentPadding: const EdgeInsets.symmetric(
                  horizontal: 16,
                  vertical: 8,
                ),
                title: Text(
                  network.name,
                  style: const TextStyle(fontWeight: FontWeight.w700),
                ),
                subtitle: Text(
                  '${network.cidr}\n'
                  '${network.onlineNodes} online of ${network.totalNodes} · '
                  'Next: ${network.nextAction}',
                ),
                isThreeLine: true,
                trailing: const Icon(Icons.chevron_right),
              );
            }
            return Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
              child: Row(
                children: [
                  Expanded(
                    flex: 2,
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          network.name,
                          style: const TextStyle(fontWeight: FontWeight.w700),
                        ),
                        Text(network.cidr),
                      ],
                    ),
                  ),
                  Expanded(
                    child: EvidenceBadge(
                      tone: network.tone,
                      label: network.statusLabel,
                      compact: true,
                    ),
                  ),
                  Expanded(
                    child: Text(
                      '${network.onlineNodes} online\n'
                      '${network.totalNodes} total',
                    ),
                  ),
                  Expanded(child: Text(network.nextAction)),
                  const Icon(Icons.chevron_right),
                ],
              ),
            );
          },
        ),
      ),
    );
  }
}
