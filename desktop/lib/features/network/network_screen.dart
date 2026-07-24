import 'package:flutter/material.dart';

import '../../shared/callbacks/presentation_callbacks.dart';
import '../../shared/models/presentation_models.dart';
import '../../shared/widgets/async_state_view.dart';
import '../../shared/widgets/evidence_badge.dart';
import '../../shared/widgets/freshness_stamp.dart';
import '../../shared/widgets/operation_panel.dart';
import '../../shared/widgets/permission_gate.dart';
import '../nodes/nodes_screen.dart';

enum NetworkDestination {
  overview,
  nodes,
  firewall,
  readiness,
  dns,
  relays,
  routing,
  security,
}

extension on NetworkDestination {
  String get label => switch (this) {
    NetworkDestination.overview => 'Overview',
    NetworkDestination.nodes => 'Nodes',
    NetworkDestination.firewall => 'Firewall',
    NetworkDestination.readiness => 'Readiness',
    NetworkDestination.dns => 'DNS',
    NetworkDestination.relays => 'Relays',
    NetworkDestination.routing => 'Routing',
    NetworkDestination.security => 'Security',
  };

  IconData get icon => switch (this) {
    NetworkDestination.overview => Icons.dashboard_outlined,
    NetworkDestination.nodes => Icons.dns_outlined,
    NetworkDestination.firewall => Icons.shield_outlined,
    NetworkDestination.readiness => Icons.fact_check_outlined,
    NetworkDestination.dns => Icons.language_outlined,
    NetworkDestination.relays => Icons.compare_arrows,
    NetworkDestination.routing => Icons.route_outlined,
    NetworkDestination.security => Icons.admin_panel_settings_outlined,
  };
}

class NetworkScreen extends StatefulWidget {
  const NetworkScreen({
    required this.state,
    required this.role,
    required this.callbacks,
    super.key,
  });

  final LoadableViewModel<NetworkOverviewViewModel> state;
  final MeshRole role;
  final MeshPresentationCallbacks callbacks;

  @override
  State<NetworkScreen> createState() => _NetworkScreenState();
}

class _NetworkScreenState extends State<NetworkScreen> {
  NetworkDestination _destination = NetworkDestination.overview;

  MeshMutationCallbacks? get _mutations =>
      widget.callbacks is MeshMutationCallbacks
      ? widget.callbacks as MeshMutationCallbacks
      : null;

  @override
  Widget build(BuildContext context) {
    return AsyncStateView<NetworkOverviewViewModel>(
      state: widget.state,
      emptyTitle: 'No network selected',
      emptyMessage: 'Select a network from the fleet directory.',
      onRetry: widget.callbacks.refreshFleet,
      builder: (context, model) {
        return LayoutBuilder(
          builder: (context, constraints) {
            final vertical = constraints.maxWidth >= 880;
            final navigation = _NetworkNavigation(
              selected: _destination,
              vertical: vertical,
              onSelected: (value) => setState(() => _destination = value),
            );
            final content = _content(model);
            return Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Padding(
                  padding: const EdgeInsets.fromLTRB(24, 20, 24, 12),
                  child: Row(
                    children: [
                      IconButton(
                        tooltip: 'Back to fleet',
                        onPressed: widget.callbacks.clearSelectedNetwork,
                        icon: const Icon(Icons.arrow_back),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Row(
                              children: [
                                Flexible(
                                  child: Text(
                                    model.network.name,
                                    style: Theme.of(
                                      context,
                                    ).textTheme.headlineMedium,
                                  ),
                                ),
                                const SizedBox(width: 12),
                                EvidenceBadge(
                                  tone: model.network.tone,
                                  label: model.network.statusLabel,
                                  compact: true,
                                ),
                              ],
                            ),
                            Text(model.network.cidr),
                          ],
                        ),
                      ),
                      FreshnessStamp(
                        generatedAt: model.updatedAt,
                        prefix: 'Updated',
                      ),
                    ],
                  ),
                ),
                const Divider(height: 1),
                Expanded(
                  child: vertical
                      ? Row(
                          crossAxisAlignment: CrossAxisAlignment.stretch,
                          children: [
                            SizedBox(width: 200, child: navigation),
                            const VerticalDivider(width: 1),
                            Expanded(
                              child: Padding(
                                padding: const EdgeInsets.all(24),
                                child: content,
                              ),
                            ),
                          ],
                        )
                      : Column(
                          children: [
                            navigation,
                            const Divider(height: 1),
                            Expanded(
                              child: Padding(
                                padding: const EdgeInsets.all(16),
                                child: content,
                              ),
                            ),
                          ],
                        ),
                ),
              ],
            );
          },
        );
      },
    );
  }

  Widget _content(NetworkOverviewViewModel model) {
    return switch (_destination) {
      NetworkDestination.overview => _Overview(
        model: model,
        role: widget.role,
        onNextAction: () =>
            setState(() => _destination = NetworkDestination.nodes),
        onOpenNodes: () =>
            setState(() => _destination = NetworkDestination.nodes),
      ),
      NetworkDestination.nodes => NodesScreen(
        networkId: model.network.id,
        nodes: model.nodes,
        role: widget.role,
        mutationCallbacks: _mutations,
        onSelectNode: (nodeId) =>
            widget.callbacks.selectNode(model.network.id, nodeId),
      ),
      NetworkDestination.firewall => OperationPanel(
        state: model.firewall,
        emptyTitle: 'No firewall document',
        emptyMessage: 'No authoritative firewall policy document was returned.',
        onRetry: widget.callbacks.refreshFleet,
      ),
      NetworkDestination.readiness => OperationPanel(
        state: model.readiness,
        emptyTitle: 'Readiness unavailable',
        emptyMessage: 'No deployment-readiness evidence was returned.',
        onRetry: widget.callbacks.refreshFleet,
      ),
      NetworkDestination.dns => OperationPanel(
        state: model.dns,
        emptyTitle: 'DNS is not configured',
        emptyMessage: 'Managed DNS has no desired configuration.',
        onRetry: widget.callbacks.refreshFleet,
      ),
      NetworkDestination.relays => OperationPanel(
        state: model.relays,
        emptyTitle: 'Relays are not configured',
        emptyMessage: 'No managed relay candidates are selected.',
        onRetry: widget.callbacks.refreshFleet,
      ),
      NetworkDestination.routing => OperationPanel(
        state: model.routing,
        emptyTitle: 'No managed routes',
        emptyMessage:
            'No route policy, transfer, or routed-subnet ownership is active.',
        onRetry: widget.callbacks.refreshFleet,
      ),
      NetworkDestination.security => PermissionGate(
        role: widget.role,
        permission: MeshPermission.networksSecurity,
        readOnlyChild: OperationPanel(
          state: model.caRotation,
          emptyTitle: 'No CA rotation',
          emptyMessage:
              'The network is using its current certificate authority.',
          onRetry: widget.callbacks.refreshFleet,
        ),
        child: OperationPanel(
          state: model.caRotation,
          emptyTitle: 'No CA rotation',
          emptyMessage:
              'The network is using its current certificate authority.',
          onRetry: widget.callbacks.refreshFleet,
        ),
      ),
    };
  }
}

class _NetworkNavigation extends StatelessWidget {
  const _NetworkNavigation({
    required this.selected,
    required this.vertical,
    required this.onSelected,
  });

  final NetworkDestination selected;
  final bool vertical;
  final ValueChanged<NetworkDestination> onSelected;

  @override
  Widget build(BuildContext context) {
    if (!vertical) {
      return SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        child: SegmentedButton<NetworkDestination>(
          segments: [
            for (final destination in NetworkDestination.values)
              ButtonSegment(
                value: destination,
                icon: Icon(destination.icon),
                label: Text(destination.label),
              ),
          ],
          selected: {selected},
          onSelectionChanged: (values) => onSelected(values.first),
        ),
      );
    }
    return ListView(
      padding: const EdgeInsets.all(12),
      children: [
        for (final destination in NetworkDestination.values)
          ListTile(
            selected: destination == selected,
            leading: Icon(destination.icon),
            title: Text(destination.label),
            onTap: () => onSelected(destination),
          ),
      ],
    );
  }
}

class _Overview extends StatelessWidget {
  const _Overview({
    required this.model,
    required this.role,
    required this.onNextAction,
    required this.onOpenNodes,
  });

  final NetworkOverviewViewModel model;
  final MeshRole role;
  final VoidCallback onNextAction;
  final VoidCallback onOpenNodes;

  @override
  Widget build(BuildContext context) {
    return ListView(
      children: [
        LayoutBuilder(
          builder: (context, constraints) {
            final wide = constraints.maxWidth >= 900;
            final topology = _Topology(model: model, onOpenNodes: onOpenNodes);
            final setup = _Setup(
              model: model,
              role: role,
              onNextAction: onNextAction,
            );
            if (wide) {
              return Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Expanded(flex: 3, child: topology),
                  const SizedBox(width: 16),
                  Expanded(flex: 2, child: setup),
                ],
              );
            }
            return Column(
              children: [topology, const SizedBox(height: 16), setup],
            );
          },
        ),
        if (model.alerts.isNotEmpty) ...[
          const SizedBox(height: 16),
          Card(
            child: ExpansionTile(
              initiallyExpanded: true,
              title: Text(
                '${model.alerts.length} authoritative health '
                '${model.alerts.length == 1 ? 'alert' : 'alerts'}',
              ),
              children: [
                for (final alert in model.alerts)
                  ListTile(
                    leading: Icon(alert.tone.icon),
                    title: Text(alert.title),
                    subtitle: Text(alert.detail),
                  ),
              ],
            ),
          ),
        ],
      ],
    );
  }
}

class _Topology extends StatelessWidget {
  const _Topology({required this.model, required this.onOpenNodes});

  final NetworkOverviewViewModel model;
  final VoidCallback onOpenNodes;

  @override
  Widget build(BuildContext context) {
    final lighthouses = model.nodes
        .where((node) => node.role == MeshNodeRole.lighthouse)
        .length;
    final members = model.nodes
        .where((node) => node.role == MeshNodeRole.member)
        .length;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    'Topology',
                    style: Theme.of(context).textTheme.titleLarge,
                  ),
                ),
                TextButton(
                  onPressed: onOpenNodes,
                  child: const Text('Manage nodes'),
                ),
              ],
            ),
            Text('$lighthouses lighthouses · $members members'),
            const SizedBox(height: 16),
            Semantics(
              label:
                  'Network topology for ${model.network.name}. '
                  '$lighthouses lighthouses and $members members.',
              container: true,
              child: Column(
                children: [
                  CircleAvatar(
                    radius: 28,
                    child: Icon(
                      Icons.hub_outlined,
                      color: Theme.of(context).colorScheme.primary,
                    ),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    model.network.name,
                    style: const TextStyle(fontWeight: FontWeight.w700),
                  ),
                  Text(model.network.cidr),
                  const Padding(
                    padding: EdgeInsets.symmetric(vertical: 10),
                    child: Icon(Icons.arrow_downward),
                  ),
                  Wrap(
                    alignment: WrapAlignment.center,
                    spacing: 12,
                    runSpacing: 12,
                    children: [
                      for (final node in model.nodes)
                        SizedBox(
                          width: 180,
                          child: ListTile(
                            contentPadding: EdgeInsets.zero,
                            leading: Icon(node.role.icon),
                            title: Text(node.name),
                            subtitle: Text(node.status.label),
                          ),
                        ),
                    ],
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _Setup extends StatelessWidget {
  const _Setup({
    required this.model,
    required this.role,
    required this.onNextAction,
  });

  final NetworkOverviewViewModel model;
  final MeshRole role;
  final VoidCallback onNextAction;

  @override
  Widget build(BuildContext context) {
    final permission = model.nextActionPermission;
    final action = FilledButton(
      onPressed: onNextAction,
      child: const Text('Continue'),
    );
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Next action', style: Theme.of(context).textTheme.labelLarge),
            const SizedBox(height: 6),
            Text(
              model.nextActionTitle,
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 8),
            Text(model.nextActionDetail),
            const SizedBox(height: 16),
            if (permission == null)
              action
            else
              PermissionGate(role: role, permission: permission, child: action),
            const Divider(height: 28),
            Text(
              'Setup progress',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            for (var index = 0; index < model.setupStages.length; index++)
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: CircleAvatar(
                  radius: 14,
                  child: model.setupStages[index].state == EvidenceTone.healthy
                      ? const Icon(Icons.check, size: 16)
                      : Text('${index + 1}'),
                ),
                title: Text(model.setupStages[index].label),
                trailing: EvidenceBadge(
                  tone: model.setupStages[index].state,
                  compact: true,
                ),
              ),
            const SizedBox(height: 8),
            const Text(
              'Authenticated lifecycle state only; peer reachability is not inferred.',
            ),
          ],
        ),
      ),
    );
  }
}
