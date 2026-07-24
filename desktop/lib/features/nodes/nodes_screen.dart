import 'package:flutter/material.dart';

import '../../shared/callbacks/presentation_callbacks.dart';
import '../../shared/models/presentation_models.dart';
import '../../shared/widgets/evidence_badge.dart';
import '../../shared/widgets/mutation_dialogs.dart';
import '../../shared/widgets/permission_gate.dart';
import 'create_enrollment_dialog.dart';

class NodesScreen extends StatefulWidget {
  const NodesScreen({
    required this.networkId,
    required this.nodes,
    required this.role,
    required this.onSelectNode,
    this.mutationCallbacks,
    super.key,
  });

  final String networkId;
  final List<NodeViewModel> nodes;
  final MeshRole role;
  final ValueChanged<String> onSelectNode;
  final MeshMutationCallbacks? mutationCallbacks;

  @override
  State<NodesScreen> createState() => _NodesScreenState();
}

class _NodesScreenState extends State<NodesScreen> {
  String _query = '';
  String? _selectedNodeId;

  Future<void> _createEnrollment() async {
    final mutations = widget.mutationCallbacks;
    if (mutations == null) return;
    await showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (context) => CreateEnrollmentDialog(
        networkId: widget.networkId,
        onSubmit: mutations.createNodeEnrollment,
      ),
    );
  }

  Future<void> _reissueEnrollment(NodeViewModel node) async {
    final mutations = widget.mutationCallbacks;
    if (mutations == null) return;
    await showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (context) => MutationConfirmationDialog(
        title: 'Reissue enrollment for ${node.name}?',
        detail:
            'The current unclaimed enrollment material will stop working. '
            'New one-time enrollment material will be displayed after the '
            'control plane confirms the change.',
        confirmLabel: 'Reissue enrollment',
        onConfirm: () => mutations.reissueEnrollment(
          ReissueEnrollmentRequest(
            networkId: widget.networkId,
            nodeId: node.id,
            nodeName: node.name,
          ),
        ),
      ),
    );
  }

  Future<void> _rotateCertificate(NodeViewModel node) async {
    final mutations = widget.mutationCallbacks;
    if (mutations == null) return;
    await showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (context) => MutationConfirmationDialog(
        title: 'Rotate certificate for ${node.name}?',
        detail:
            'The control plane will issue a replacement certificate. The '
            'node must check in and apply it before the rotation is complete.',
        confirmLabel: 'Rotate certificate',
        onConfirm: () => mutations.rotateNodeCertificate(
          RotateNodeCertificateRequest(
            networkId: widget.networkId,
            nodeId: node.id,
            nodeName: node.name,
          ),
        ),
      ),
    );
  }

  Future<void> _revokeNode(NodeViewModel node) async {
    final mutations = widget.mutationCallbacks;
    if (mutations == null) return;
    await showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (context) => ExactNameConfirmationDialog(
        title: 'Permanently revoke ${node.name}?',
        detail:
            'This immediately revokes the node certificate and prevents this '
            'node identity from rejoining. This action cannot be undone.',
        requiredName: node.name,
        confirmLabel: 'Permanently revoke node',
        onConfirm: (confirmedName) => mutations.revokeNode(
          RevokeNodeRequest(
            networkId: widget.networkId,
            nodeId: node.id,
            nodeName: node.name,
            confirmedName: confirmedName,
          ),
        ),
      ),
    );
  }

  @override
  void didUpdateWidget(covariant NodesScreen oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (_selectedNodeId != null &&
        !widget.nodes.any((node) => node.id == _selectedNodeId)) {
      _selectedNodeId = null;
    }
  }

  @override
  Widget build(BuildContext context) {
    final normalized = _query.trim().toLowerCase();
    final filtered = widget.nodes.where((node) {
      return normalized.isEmpty ||
          node.name.toLowerCase().contains(normalized) ||
          node.overlayAddress.toLowerCase().contains(normalized) ||
          node.site.toLowerCase().contains(normalized) ||
          node.groups.any((group) => group.toLowerCase().contains(normalized));
    }).toList();
    final selected = _selectedNodeId == null
        ? null
        : widget.nodes.where((node) => node.id == _selectedNodeId).firstOrNull;

    return LayoutBuilder(
      builder: (context, constraints) {
        final split = constraints.maxWidth >= 1050;
        final list = _NodeList(
          nodes: filtered,
          query: _query,
          canCreate: widget.role.allows(MeshPermission.networksWrite),
          creationAvailable: widget.mutationCallbacks != null,
          onCreate: _createEnrollment,
          onQueryChanged: (value) => setState(() => _query = value),
          onSelect: (node) {
            setState(() => _selectedNodeId = node.id);
            widget.onSelectNode(node.id);
          },
        );
        final detail = selected == null
            ? const _NoNodeSelected()
            : NodeDetail(
                node: selected,
                role: widget.role,
                mutationAvailable: widget.mutationCallbacks != null,
                onReissueEnrollment: () => _reissueEnrollment(selected),
                onRotateCertificate: () => _rotateCertificate(selected),
                onRevoke: () => _revokeNode(selected),
              );
        if (split) {
          return Row(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Expanded(flex: 5, child: list),
              const SizedBox(width: 16),
              Expanded(flex: 4, child: detail),
            ],
          );
        }
        return ListView(
          children: [
            SizedBox(height: 460, child: list),
            const SizedBox(height: 16),
            detail,
          ],
        );
      },
    );
  }
}

class _NodeList extends StatelessWidget {
  const _NodeList({
    required this.nodes,
    required this.query,
    required this.canCreate,
    required this.creationAvailable,
    required this.onCreate,
    required this.onQueryChanged,
    required this.onSelect,
  });

  final List<NodeViewModel> nodes;
  final String query;
  final bool canCreate;
  final bool creationAvailable;
  final VoidCallback onCreate;
  final ValueChanged<String> onQueryChanged;
  final ValueChanged<NodeViewModel> onSelect;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    'Nodes',
                    style: Theme.of(context).textTheme.titleLarge,
                  ),
                ),
                if (canCreate)
                  Tooltip(
                    message: creationAvailable
                        ? 'Create node enrollment'
                        : 'Enrollment creation is unavailable in this session.',
                    child: FilledButton.icon(
                      key: const Key('new-node-button'),
                      onPressed: creationAvailable ? onCreate : null,
                      icon: const Icon(Icons.add),
                      label: const Text('New node'),
                    ),
                  ),
              ],
            ),
            const SizedBox(height: 12),
            TextField(
              key: const Key('node-search'),
              decoration: const InputDecoration(
                labelText: 'Search nodes',
                prefixIcon: Icon(Icons.search),
              ),
              onChanged: onQueryChanged,
            ),
            const SizedBox(height: 12),
            Expanded(
              child: nodes.isEmpty
                  ? Center(
                      child: Text(
                        query.isEmpty
                            ? 'No nodes have been created.'
                            : 'No nodes match this search.',
                      ),
                    )
                  : ListView.separated(
                      itemCount: nodes.length,
                      separatorBuilder: (_, _) => const Divider(height: 1),
                      itemBuilder: (context, index) {
                        final node = nodes[index];
                        return ListTile(
                          leading: Icon(node.role.icon),
                          title: Text(node.name),
                          subtitle: Text(
                            '${node.role.label} · ${node.overlayAddress}\n'
                            '${node.site} / ${node.failureDomain}',
                          ),
                          isThreeLine: true,
                          trailing: EvidenceBadge(
                            tone: node.status.tone,
                            label: node.status.label,
                            compact: true,
                          ),
                          onTap: () => onSelect(node),
                        );
                      },
                    ),
            ),
          ],
        ),
      ),
    );
  }
}

class _NoNodeSelected extends StatelessWidget {
  const _NoNodeSelected();

  @override
  Widget build(BuildContext context) {
    return const Card(
      child: Center(
        child: Padding(
          padding: EdgeInsets.all(32),
          child: Text('Select a node to inspect its authoritative state.'),
        ),
      ),
    );
  }
}

class NodeDetail extends StatelessWidget {
  const NodeDetail({
    required this.node,
    required this.role,
    required this.mutationAvailable,
    required this.onReissueEnrollment,
    required this.onRotateCertificate,
    required this.onRevoke,
    super.key,
  });

  final NodeViewModel node;
  final MeshRole role;
  final bool mutationAvailable;
  final VoidCallback onReissueEnrollment;
  final VoidCallback onRotateCertificate;
  final VoidCallback onRevoke;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(node.role.icon),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    node.name,
                    style: Theme.of(context).textTheme.titleLarge,
                  ),
                ),
                EvidenceBadge(
                  tone: node.status.tone,
                  label: node.status.label,
                  compact: true,
                ),
              ],
            ),
            const SizedBox(height: 18),
            _DetailField(label: 'Overlay address', value: node.overlayAddress),
            _DetailField(label: 'Role', value: node.role.label),
            _DetailField(
              label: 'Placement',
              value: '${node.site} / ${node.failureDomain}',
            ),
            _DetailField(
              label: 'Configuration',
              value: node.appliedRevision == null
                  ? 'Desired ${node.desiredRevision}; applied unavailable'
                  : 'Desired ${node.desiredRevision}; applied ${node.appliedRevision}',
            ),
            _DetailField(
              label: 'Groups',
              value: node.groups.isEmpty
                  ? 'None reported'
                  : node.groups.join(', '),
            ),
            if (node.routedSubnets.isNotEmpty)
              _DetailField(
                label: 'Routed subnets',
                value: node.routedSubnets.join(', '),
              ),
            if (node.lastHeartbeatAt != null)
              _DetailField(
                label: 'Last heartbeat',
                value: node.lastHeartbeatAt!.toLocal().toString(),
              ),
            if (node.runtimeObservation != null)
              _DetailField(
                label: 'Runtime observation',
                value:
                    '${node.runtimeObservation}. Not an end-to-end reachability result.',
              ),
            const SizedBox(height: 18),
            Text('Actions', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 10),
            if (node.status == NodeLifecycleStatus.pending) ...[
              PermissionGate(
                role: role,
                permission: MeshPermission.networksWrite,
                child: Tooltip(
                  message: mutationAvailable
                      ? 'Invalidate and reissue enrollment material'
                      : 'Enrollment reissue is unavailable in this session.',
                  child: OutlinedButton.icon(
                    key: const Key('reissue-enrollment-button'),
                    onPressed: mutationAvailable ? onReissueEnrollment : null,
                    icon: const Icon(Icons.refresh),
                    label: const Text('Reissue enrollment'),
                  ),
                ),
              ),
              const SizedBox(height: 12),
            ],
            PermissionGate(
              role: role,
              permission: MeshPermission.networksSecurity,
              child: Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  if (node.status != NodeLifecycleStatus.revoked) ...[
                    Tooltip(
                      message: mutationAvailable
                          ? 'Issue a replacement node certificate'
                          : 'Certificate rotation is unavailable in this session.',
                      child: OutlinedButton.icon(
                        key: const Key('rotate-certificate-button'),
                        onPressed: mutationAvailable
                            ? onRotateCertificate
                            : null,
                        icon: const Icon(Icons.autorenew),
                        label: const Text('Rotate certificate'),
                      ),
                    ),
                    Tooltip(
                      message: mutationAvailable
                          ? 'Permanently revoke this node identity'
                          : 'Node revocation is unavailable in this session.',
                      child: FilledButton.tonalIcon(
                        key: const Key('revoke-node-button'),
                        onPressed: mutationAvailable ? onRevoke : null,
                        icon: const Icon(Icons.block),
                        label: const Text('Revoke node'),
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _DetailField extends StatelessWidget {
  const _DetailField({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Semantics(
        label: '$label: $value',
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(label, style: Theme.of(context).textTheme.labelMedium),
            const SizedBox(height: 3),
            SelectableText(value),
          ],
        ),
      ),
    );
  }
}
