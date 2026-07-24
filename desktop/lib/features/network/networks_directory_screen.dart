import 'package:flutter/material.dart';

import '../../shared/callbacks/presentation_callbacks.dart';
import '../../shared/models/presentation_models.dart';
import '../../shared/widgets/async_state_view.dart';
import '../../shared/widgets/evidence_badge.dart';
import 'create_network_dialog.dart';

class NetworksDirectoryScreen extends StatefulWidget {
  const NetworksDirectoryScreen({
    required this.state,
    required this.role,
    required this.onSelectNetwork,
    required this.onCreateNetwork,
    required this.onRefresh,
    super.key,
  });

  final LoadableViewModel<FleetViewModel> state;
  final MeshRole role;
  final ValueChanged<String> onSelectNetwork;
  final Future<MutationSubmissionResult> Function(CreateNetworkRequest request)?
  onCreateNetwork;
  final VoidCallback onRefresh;

  @override
  State<NetworksDirectoryScreen> createState() =>
      _NetworksDirectoryScreenState();
}

class _NetworksDirectoryScreenState extends State<NetworksDirectoryScreen> {
  String _query = '';

  Future<void> _showCreateNetwork() async {
    final callback = widget.onCreateNetwork;
    if (callback == null) return;
    await showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (context) => CreateNetworkDialog(onSubmit: callback),
    );
  }

  @override
  Widget build(BuildContext context) {
    return AsyncStateView<FleetViewModel>(
      state: widget.state,
      onRetry: widget.onRefresh,
      emptyTitle: 'No networks yet',
      emptyMessage:
          'An Operator or Admin can create the first private network.',
      builder: (context, fleet) {
        final query = _query.trim().toLowerCase();
        final networks = fleet.networks
            .where(
              (network) =>
                  query.isEmpty ||
                  network.name.toLowerCase().contains(query) ||
                  network.cidr.toLowerCase().contains(query),
            )
            .toList();
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(24, 20, 24, 12),
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      'Networks',
                      style: Theme.of(context).textTheme.headlineMedium,
                    ),
                  ),
                  if (widget.role.allows(MeshPermission.networksWrite))
                    Tooltip(
                      message: widget.onCreateNetwork == null
                          ? 'Network creation is unavailable in this session.'
                          : 'Create network',
                      child: FilledButton.icon(
                        key: const Key('new-network-button'),
                        onPressed: widget.onCreateNetwork == null
                            ? null
                            : _showCreateNetwork,
                        icon: const Icon(Icons.add),
                        label: const Text('New network'),
                      ),
                    ),
                  const SizedBox(width: 8),
                  IconButton(
                    tooltip: 'Refresh networks',
                    onPressed: widget.onRefresh,
                    icon: const Icon(Icons.refresh),
                  ),
                ],
              ),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24),
              child: TextField(
                key: const Key('network-search'),
                decoration: const InputDecoration(
                  labelText: 'Search network name or CIDR',
                  prefixIcon: Icon(Icons.search),
                ),
                onChanged: (value) => setState(() => _query = value),
              ),
            ),
            const SizedBox(height: 12),
            Expanded(
              child: networks.isEmpty
                  ? const Center(child: Text('No networks match this search.'))
                  : ListView.separated(
                      padding: const EdgeInsets.fromLTRB(24, 0, 24, 24),
                      itemCount: networks.length,
                      separatorBuilder: (_, _) => const SizedBox(height: 8),
                      itemBuilder: (context, index) {
                        final network = networks[index];
                        return Card(
                          child: ListTile(
                            contentPadding: const EdgeInsets.symmetric(
                              horizontal: 18,
                              vertical: 8,
                            ),
                            title: Text(
                              network.name,
                              style: const TextStyle(
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                            subtitle: Text(
                              '${network.cidr}\n'
                              '${network.onlineNodes} online of '
                              '${network.totalNodes} nodes · '
                              'Next: ${network.nextAction}',
                            ),
                            isThreeLine: true,
                            trailing: Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                EvidenceBadge(
                                  tone: network.tone,
                                  label: network.statusLabel,
                                  compact: true,
                                ),
                                const SizedBox(width: 10),
                                const Icon(Icons.chevron_right),
                              ],
                            ),
                            onTap: () => widget.onSelectNetwork(network.id),
                          ),
                        );
                      },
                    ),
            ),
          ],
        );
      },
    );
  }
}
