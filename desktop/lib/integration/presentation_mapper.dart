import 'package:mesh_desktop/app/app.dart';

final class MeshPresentationMapper {
  const MeshPresentationMapper();

  FleetViewModel fleet(
    List<Map<String, Object?>> networks,
    Map<String, Object?> health,
  ) {
    final summary = _object(health, 'summary');
    final rollout = _object(health, 'rollout');
    final reports = <String, Map<String, Object?>>{};
    for (final report in _objectList(health, 'networks')) {
      final network = _object(report, 'network');
      reports[_string(network, 'id')] = report;
    }

    final networkModels = <NetworkSummaryViewModel>[];
    final alerts = <AlertViewModel>[];
    for (final network in networks) {
      final id = _string(network, 'id');
      final report = reports[id];
      final networkSummary = report == null ? null : _object(report, 'summary');
      final totalNodes = _integer(network, 'node_count');
      final activeNodes = _integer(network, 'active_nodes');
      final tone = report == null
          ? EvidenceTone.unavailable
          : evidenceTone(_string(networkSummary!, 'overall'));
      networkModels.add(
        NetworkSummaryViewModel(
          id: id,
          name: _string(network, 'name'),
          cidr: _string(network, 'cidr'),
          tone: tone,
          statusLabel: tone.label,
          onlineNodes: activeNodes,
          totalNodes: totalNodes,
          nextAction: _networkNextAction(
            totalNodes: totalNodes,
            activeNodes: activeNodes,
            tone: tone,
          ),
        ),
      );
      if (report != null) {
        for (final alert in _objectList(report, 'alerts')) {
          alerts.add(
            _alert(
              alert,
              networkName: _string(network, 'name'),
              nodes: _objectList(report, 'nodes'),
            ),
          );
        }
      }
    }
    networkModels.sort((left, right) => left.name.compareTo(right.name));

    final generatedAt = _time(health, 'generated_at');
    final percent = _integer(rollout, 'percent');
    return FleetViewModel(
      tone: evidenceTone(_string(summary, 'overall')),
      generatedAt: generatedAt,
      metrics: <FleetMetricViewModel>[
        FleetMetricViewModel(
          label: 'Networks',
          value: '${_integer(summary, 'total_networks')}',
        ),
        FleetMetricViewModel(
          label: 'Active nodes',
          value:
              '${_integer(summary, 'active_nodes')} / ${_integer(summary, 'total_nodes')}',
        ),
        FleetMetricViewModel(
          label: 'Needs attention',
          value:
              '${_integer(summary, 'warning_nodes') + _integer(summary, 'critical_nodes')}',
        ),
        FleetMetricViewModel(
          label: 'Revoked',
          value: '${_integer(summary, 'revoked_nodes')}',
        ),
      ],
      rolloutLabel:
          '${_integer(rollout, 'converged_nodes')} of ${_integer(rollout, 'eligible_nodes')} eligible nodes current',
      rolloutFraction: percent.clamp(0, 100) / 100,
      alerts: List<AlertViewModel>.unmodifiable(alerts),
      networks: List<NetworkSummaryViewModel>.unmodifiable(networkModels),
    );
  }

  NetworkOverviewViewModel networkOverview({
    required Map<String, Object?> network,
    required List<Map<String, Object?>> nodes,
    required Map<String, Object?>? healthReport,
    required LoadableViewModel<OperationPanelViewModel> readiness,
    required LoadableViewModel<OperationPanelViewModel> firewall,
    required LoadableViewModel<OperationPanelViewModel> dns,
    required LoadableViewModel<OperationPanelViewModel> relays,
    required LoadableViewModel<OperationPanelViewModel> routing,
    required LoadableViewModel<OperationPanelViewModel> caRotation,
  }) {
    final desiredRevision = _integer(network, 'config_revision');
    final activeNodes = _integer(network, 'active_nodes');
    final totalNodes = _integer(network, 'node_count');
    final healthSummary = healthReport == null
        ? null
        : _object(healthReport, 'summary');
    final tone = healthSummary == null
        ? EvidenceTone.unavailable
        : evidenceTone(_string(healthSummary, 'overall'));
    final networkSummary = NetworkSummaryViewModel(
      id: _string(network, 'id'),
      name: _string(network, 'name'),
      cidr: _string(network, 'cidr'),
      tone: tone,
      statusLabel: tone.label,
      onlineNodes: activeNodes,
      totalNodes: totalNodes,
      nextAction: _networkNextAction(
        totalNodes: totalNodes,
        activeNodes: activeNodes,
        tone: tone,
      ),
    );

    final nodeHealth = <String, Map<String, Object?>>{};
    if (healthReport != null) {
      for (final health in _objectList(healthReport, 'nodes')) {
        nodeHealth[_string(health, 'id')] = health;
      }
    }
    final nodeModels =
        nodes
            .map(
              (node) => _node(
                node,
                desiredRevision: desiredRevision,
                health: nodeHealth[_string(node, 'id')],
              ),
            )
            .toList()
          ..sort((left, right) {
            final role = left.role.index.compareTo(right.role.index);
            return role != 0 ? role : left.name.compareTo(right.name);
          });

    final lighthouses = nodeModels
        .where((node) => node.role == MeshNodeRole.lighthouse)
        .toList();
    final members = nodeModels
        .where((node) => node.role == MeshNodeRole.member)
        .toList();
    final configCurrent =
        nodeModels.isNotEmpty &&
        nodeModels
            .where((node) => node.status != NodeLifecycleStatus.revoked)
            .every(
              (node) =>
                  node.appliedRevision != null &&
                  node.appliedRevision! >= node.desiredRevision,
            );
    final next = _networkNext(
      lighthouses: lighthouses,
      members: members,
      tone: tone,
    );

    final alerts = healthReport == null
        ? const <AlertViewModel>[]
        : _objectList(healthReport, 'alerts')
              .map(
                (alert) => _alert(
                  alert,
                  networkName: networkSummary.name,
                  nodes: _objectList(healthReport, 'nodes'),
                ),
              )
              .toList();
    return NetworkOverviewViewModel(
      network: networkSummary,
      updatedAt: _time(network, 'config_updated_at'),
      nodes: List<NodeViewModel>.unmodifiable(nodeModels),
      setupStages: <SetupStageViewModel>[
        SetupStageViewModel(
          label: 'Create and enroll a lighthouse',
          state: lighthouses.any(_operational)
              ? EvidenceTone.healthy
              : EvidenceTone.setup,
        ),
        SetupStageViewModel(
          label: 'Create and enroll a member',
          state: members.any(_operational)
              ? EvidenceTone.healthy
              : EvidenceTone.setup,
        ),
        SetupStageViewModel(
          label: 'Apply the current signed configuration',
          state: configCurrent ? EvidenceTone.healthy : EvidenceTone.setup,
        ),
        const SetupStageViewModel(
          label: 'Verify real overlay application traffic',
          state: EvidenceTone.information,
        ),
      ],
      nextActionTitle: next.title,
      nextActionDetail: next.detail,
      nextActionPermission: next.permission,
      alerts: List<AlertViewModel>.unmodifiable(alerts),
      readiness: readiness,
      firewall: firewall,
      dns: dns,
      relays: relays,
      routing: routing,
      caRotation: caRotation,
    );
  }

  OperationPanelViewModel readiness(Map<String, Object?> value) {
    final overall = _string(value, 'overall');
    return OperationPanelViewModel(
      title: 'Deployment readiness',
      summary:
          'Readiness is $overall. This evidence does not replace a real packet or application test.',
      tone: evidenceTone(overall),
      generatedAt: _time(value, 'generated_at'),
      fields: <OperationFieldViewModel>[
        OperationFieldViewModel(
          label: 'Sites evaluated',
          value: '${_objectList(value, 'sites').length}',
        ),
        OperationFieldViewModel(
          label: 'Lighthouses evaluated',
          value: '${_objectList(value, 'lighthouses').length}',
        ),
        OperationFieldViewModel(
          label: 'Schema',
          value: _string(value, 'schema'),
        ),
      ],
    );
  }

  OperationPanelViewModel firewall(Map<String, Object?> value) {
    return OperationPanelViewModel(
      title: 'Firewall',
      summary:
          '${_objectList(value, 'inbound').length} inbound and ${_objectList(value, 'outbound').length} outbound rules are in the signed policy.',
      tone: EvidenceTone.information,
      generatedAt: _time(value, 'config_updated_at'),
      fields: <OperationFieldViewModel>[
        OperationFieldViewModel(label: 'Mode', value: _string(value, 'mode')),
        OperationFieldViewModel(
          label: 'Configuration revision',
          value: '${_integer(value, 'config_revision')}',
        ),
        OperationFieldViewModel(
          label: 'Effective node projections',
          value: '${_objectList(value, 'effective_nodes').length}',
        ),
        OperationFieldViewModel(
          label: 'Policy fingerprint',
          value: _shortFingerprint(_string(value, 'policy_sha256')),
        ),
      ],
    );
  }

  OperationPanelViewModel dns(Map<String, Object?> value) {
    final enabled = _boolean(value, 'enabled');
    final firewallReady = _boolean(value, 'firewall_ready');
    return OperationPanelViewModel(
      title: 'DNS',
      summary: enabled
          ? 'Split DNS is enabled for ${_string(value, 'search_domain')}.'
          : 'Mesh DNS is disabled.',
      tone: !enabled
          ? EvidenceTone.information
          : firewallReady
          ? EvidenceTone.healthy
          : EvidenceTone.warning,
      generatedAt: _time(value, 'config_updated_at'),
      fields: <OperationFieldViewModel>[
        OperationFieldViewModel(
          label: 'Resolvers',
          value: '${_objectList(value, 'resolvers').length}',
        ),
        OperationFieldViewModel(
          label: 'Native resolver',
          value: _boolean(value, 'native_resolver') ? 'Enabled' : 'Disabled',
        ),
        OperationFieldViewModel(
          label: 'Firewall prerequisite',
          value: firewallReady ? 'Ready' : 'Not ready',
        ),
      ],
    );
  }

  OperationPanelViewModel relays(Map<String, Object?> value) {
    final enabled = _boolean(value, 'enabled');
    return OperationPanelViewModel(
      title: 'Relays',
      summary: enabled
          ? '${_objectList(value, 'active_relays').length} relays are active. Clients still prefer direct UDP paths.'
          : 'Nebula relay selection is disabled.',
      tone: enabled ? EvidenceTone.information : EvidenceTone.unavailable,
      generatedAt: _time(value, 'config_updated_at'),
      fields: <OperationFieldViewModel>[
        OperationFieldViewModel(
          label: 'Selected nodes',
          value: '${_stringList(value, 'relay_node_ids').length}',
        ),
        OperationFieldViewModel(
          label: 'Maximum relays',
          value: '${_integer(value, 'max_relay_nodes')}',
        ),
        OperationFieldViewModel(
          label: 'Configuration revision',
          value: '${_integer(value, 'config_revision')}',
        ),
      ],
    );
  }

  OperationPanelViewModel routing(Map<String, Object?> value) {
    final policies = _objectList(value, 'policies');
    final prefixes = policies
        .map((policy) => _string(policy, 'prefix'))
        .toList();
    return OperationPanelViewModel(
      title: 'Routing',
      summary: policies.isEmpty
          ? 'No routed-subnet policies are configured.'
          : '${policies.length} routed-subnet policies are configured.',
      tone: policies.isEmpty ? EvidenceTone.information : EvidenceTone.healthy,
      fields: <OperationFieldViewModel>[
        OperationFieldViewModel(
          label: 'Prefixes',
          value: prefixes.isEmpty ? 'None' : prefixes.join(', '),
        ),
        OperationFieldViewModel(
          label: 'Configuration revision',
          value: '${_integer(value, 'config_revision')}',
        ),
        OperationFieldViewModel(
          label: 'Available actions',
          value: _stringList(value, 'available_actions').join(', '),
        ),
      ],
    );
  }

  OperationPanelViewModel caRotation(Map<String, Object?> value) {
    final phase = _string(value, 'phase');
    final active = _integer(value, 'active_nodes');
    final converged = _integer(value, 'converged_nodes');
    return OperationPanelViewModel(
      title: 'Certificate authority rotation',
      summary:
          'Rotation phase is $phase. $converged of $active active nodes are converged.',
      tone: converged == active ? EvidenceTone.healthy : EvidenceTone.warning,
      generatedAt: _time(value, 'config_updated_at'),
      fields: <OperationFieldViewModel>[
        OperationFieldViewModel(label: 'Phase', value: phase),
        OperationFieldViewModel(
          label: 'Configuration revision',
          value: '${_integer(value, 'config_revision')}',
        ),
        OperationFieldViewModel(
          label: 'Available actions',
          value: _stringList(value, 'available_actions').join(', '),
        ),
      ],
    );
  }

  List<ActivityEventViewModel> activity(List<Map<String, Object?>> events) {
    return events
        .map((event) {
          final actor = _optionalObject(event, 'actor');
          final actorLabel = actor == null
              ? 'System'
              : '${_string(actor, 'kind')} · ${_string(actor, 'id')}';
          return ActivityEventViewModel(
            id: _string(event, 'id'),
            action: _readableCode(_string(event, 'action')),
            resource:
                '${_string(event, 'resource')} · ${_string(event, 'resource_id')}',
            actor: actorLabel,
            occurredAt: _time(event, 'at'),
            detail: _auditDetail(event['details']),
          );
        })
        .toList(growable: false);
  }

  AccessManagementViewModel access({
    required List<Map<String, Object?>> sessions,
    required Map<String, Object?>? recovery,
    required String? currentSessionId,
  }) {
    final sessionModels =
        sessions.map((session) {
            final principal = _object(session, 'principal');
            final absolute = _time(session, 'absolute_expires_at');
            final idle = _time(session, 'idle_expires_at');
            return BrowserSessionViewModel(
              id: _string(session, 'id'),
              principal: _principalLabel(principal),
              authMethod: _string(session, 'auth_method'),
              createdAt: _time(session, 'created_at'),
              expiresAt: absolute.isBefore(idle) ? absolute : idle,
              current: _string(session, 'id') == currentSessionId,
            );
          }).toList()
          ..sort((left, right) => right.createdAt.compareTo(left.createdAt));
    final recoveryModel = recovery == null
        ? null
        : RecoveryInventoryViewModel(
            usable: _integer(recovery, 'usable_codes'),
            minimumUsable: _integer(recovery, 'minimum_usable_codes'),
            total: _objectList(recovery, 'codes').length,
          );
    return AccessManagementViewModel(
      sessions: List<BrowserSessionViewModel>.unmodifiable(sessionModels),
      recoveryInventory: recoveryModel,
    );
  }
}

EvidenceTone evidenceTone(String value) => switch (value.toLowerCase()) {
  'healthy' || 'ready' || 'operational' || 'passed' => EvidenceTone.healthy,
  'warning' || 'degraded' => EvidenceTone.warning,
  'critical' || 'failed' || 'offline' || 'revoked' => EvidenceTone.critical,
  'setup' || 'pending' || 'in_progress' => EvidenceTone.setup,
  'unavailable' || 'unknown' => EvidenceTone.unavailable,
  _ => EvidenceTone.information,
};

bool _operational(NodeViewModel node) =>
    node.status == NodeLifecycleStatus.operational;

NodeViewModel _node(
  Map<String, Object?> node, {
  required int desiredRevision,
  Map<String, Object?>? health,
}) {
  final status = _nodeStatus(node, health);
  final agentStatus = _optionalString(node, 'agent_status');
  final nebulaRunning = _boolean(node, 'nebula_running');
  return NodeViewModel(
    id: _string(node, 'id'),
    name: _string(node, 'name'),
    role: _string(node, 'role') == 'lighthouse'
        ? MeshNodeRole.lighthouse
        : MeshNodeRole.member,
    status: status,
    overlayAddress: _string(node, 'ip'),
    site: _optionalString(node, 'site') ?? 'Unassigned site',
    failureDomain:
        _optionalString(node, 'failure_domain') ?? 'Unassigned failure domain',
    groups: _stringList(node, 'groups'),
    desiredRevision: health == null
        ? desiredRevision
        : _integer(health, 'desired_config_revision'),
    appliedRevision: _optionalInteger(node, 'applied_config_revision'),
    lastHeartbeatAt: _optionalTime(node, 'last_seen_at'),
    certificateExpiresAt: _optionalTime(node, 'certificate_expires_at'),
    runtimeObservation: agentStatus == null
        ? null
        : '$agentStatus; Nebula ${nebulaRunning ? 'reported running' : 'not reported running'}',
    routedSubnets: _stringList(node, 'routed_subnets'),
  );
}

NodeLifecycleStatus _nodeStatus(
  Map<String, Object?> node,
  Map<String, Object?>? health,
) {
  if (_optionalTime(node, 'revoked_at') != null ||
      _string(node, 'status') == 'revoked') {
    return NodeLifecycleStatus.revoked;
  }
  final source = health == null
      ? _string(node, 'status')
      : _string(health, 'severity');
  return switch (source.toLowerCase()) {
    'pending' || 'setup' || 'created' => NodeLifecycleStatus.pending,
    'healthy' || 'operational' || 'enrolled' => NodeLifecycleStatus.operational,
    'warning' || 'degraded' => NodeLifecycleStatus.warning,
    'critical' || 'offline' || 'failed' => NodeLifecycleStatus.offline,
    'revoked' => NodeLifecycleStatus.revoked,
    _ => NodeLifecycleStatus.warning,
  };
}

AlertViewModel _alert(
  Map<String, Object?> alert, {
  required String networkName,
  required List<Map<String, Object?>> nodes,
}) {
  final code = _string(alert, 'code');
  final nodeId = _optionalString(alert, 'node_id');
  String? nodeName;
  if (nodeId != null) {
    for (final node in nodes) {
      if (_string(node, 'id') == nodeId) {
        nodeName = _string(node, 'name');
        break;
      }
    }
  }
  return AlertViewModel(
    id: '$networkName:$code:${nodeId ?? 'network'}',
    title: _readableCode(code),
    detail: _evidenceDetail(_optionalObject(alert, 'evidence')),
    tone: evidenceTone(_string(alert, 'severity')),
    resourceLabel: nodeName == null ? networkName : '$networkName · $nodeName',
  );
}

String _evidenceDetail(Map<String, Object?>? evidence) {
  if (evidence == null || evidence.isEmpty) {
    return 'Mesh returned no additional evidence for this alert.';
  }
  final parts = <String>[];
  final status = _optionalString(evidence, 'reported_status');
  if (status != null) parts.add('reported status $status');
  final age = _optionalInteger(evidence, 'age_seconds');
  final threshold = _optionalInteger(evidence, 'threshold_seconds');
  if (age != null) {
    parts.add(
      threshold == null
          ? 'age ${_duration(age)}'
          : 'age ${_duration(age)}, threshold ${_duration(threshold)}',
    );
  }
  final activeLighthouses = _optionalInteger(evidence, 'active_lighthouses');
  final requiredLighthouses = _optionalInteger(
    evidence,
    'required_lighthouses',
  );
  if (activeLighthouses != null && requiredLighthouses != null) {
    parts.add(
      '$activeLighthouses active of $requiredLighthouses required lighthouses',
    );
  }
  final applied = _optionalInteger(evidence, 'applied_config_revision');
  final desired = _optionalInteger(evidence, 'desired_config_revision');
  if (applied != null || desired != null) {
    parts.add(
      'applied revision ${applied ?? 'unknown'}, desired ${desired ?? 'unknown'}',
    );
  }
  final expires = _optionalTime(evidence, 'expires_at');
  if (expires != null) parts.add('expires ${expires.toLocal()}');
  return parts.isEmpty
      ? 'Review the current network and node evidence.'
      : '${parts.join('; ')}.';
}

String _duration(int seconds) {
  if (seconds < 60) return '${seconds}s';
  if (seconds < 3600) return '${seconds ~/ 60}m';
  if (seconds < 86400) return '${seconds ~/ 3600}h';
  return '${seconds ~/ 86400}d';
}

String _networkNextAction({
  required int totalNodes,
  required int activeNodes,
  required EvidenceTone tone,
}) {
  if (totalNodes == 0) return 'Create the first lighthouse';
  if (activeNodes == 0) return 'Finish the first enrollment';
  if (activeNodes < totalNodes) return 'Review nodes that are not operational';
  if (tone == EvidenceTone.healthy) return 'Verify real overlay traffic';
  return 'Review current health evidence';
}

_NetworkNext _networkNext({
  required List<NodeViewModel> lighthouses,
  required List<NodeViewModel> members,
  required EvidenceTone tone,
}) {
  if (lighthouses.isEmpty) {
    return const _NetworkNext(
      title: 'Create the first lighthouse',
      detail:
          'A lighthouse provides discovery. Create one, then run its one-time enrollment on the intended host.',
      permission: MeshPermission.networksWrite,
    );
  }
  if (!lighthouses.any(_operational)) {
    return const _NetworkNext(
      title: 'Enroll the first lighthouse',
      detail:
          'Run the one-time enrollment on the lighthouse host and wait for its managed heartbeat.',
      permission: MeshPermission.networksWrite,
    );
  }
  if (members.isEmpty) {
    return const _NetworkNext(
      title: 'Add a member node',
      detail:
          'Create a member, enroll it on its intended host, and wait for the signed configuration to apply.',
      permission: MeshPermission.networksWrite,
    );
  }
  if (tone != EvidenceTone.healthy) {
    return const _NetworkNext(
      title: 'Review health evidence',
      detail:
          'Resolve current heartbeat, runtime, revision, or certificate evidence before changing policy.',
    );
  }
  return const _NetworkNext(
    title: 'Verify real overlay traffic',
    detail:
        'Lifecycle health is current. Test the required packet and application paths before treating the network as ready.',
  );
}

final class _NetworkNext {
  const _NetworkNext({
    required this.title,
    required this.detail,
    this.permission,
  });

  final String title;
  final String detail;
  final MeshPermission? permission;
}

String _principalLabel(Map<String, Object?> principal) =>
    _optionalString(principal, 'display_name') ??
    _optionalString(principal, 'email') ??
    _string(principal, 'id');

String? _auditDetail(Object? value) {
  if (value is! Map<String, Object?> || value.isEmpty) return null;
  final safe = <String>[];
  for (final entry in value.entries) {
    if (entry.value is String || entry.value is num || entry.value is bool) {
      final rendered = '${entry.value}';
      if (rendered.length <= 160) {
        safe.add('${_readableCode(entry.key)}: $rendered');
      }
    }
    if (safe.length == 4) break;
  }
  return safe.isEmpty ? null : safe.join(' · ');
}

String _readableCode(String value) {
  final words = value
      .replaceAll(RegExp(r'[^A-Za-z0-9]+'), ' ')
      .trim()
      .toLowerCase();
  if (words.isEmpty) return value;
  return '${words[0].toUpperCase()}${words.substring(1)}';
}

String _shortFingerprint(String value) =>
    value.length <= 16 ? value : '${value.substring(0, 16)}…';

Map<String, Object?> _object(Map<String, Object?> object, String field) {
  final value = object[field];
  if (value is! Map<String, Object?>) {
    throw FormatException('"$field" must be an object.');
  }
  return value;
}

Map<String, Object?>? _optionalObject(
  Map<String, Object?> object,
  String field,
) {
  final value = object[field];
  if (value == null) return null;
  if (value is! Map<String, Object?>) {
    throw FormatException('"$field" must be an object when present.');
  }
  return value;
}

List<Map<String, Object?>> _objectList(
  Map<String, Object?> object,
  String field,
) {
  final value = object[field];
  if (value is! List<Object?>) {
    throw FormatException('"$field" must be an array.');
  }
  return value
      .map((item) {
        if (item is! Map<String, Object?>) {
          throw FormatException('"$field" must contain objects.');
        }
        return item;
      })
      .toList(growable: false);
}

List<String> _stringList(Map<String, Object?> object, String field) {
  final value = object[field];
  if (value == null) return const <String>[];
  if (value is! List<Object?> || value.any((item) => item is! String)) {
    throw FormatException('"$field" must be a string array.');
  }
  return List<String>.unmodifiable(value.cast<String>());
}

String _string(Map<String, Object?> object, String field) {
  final value = object[field];
  if (value is! String || value.isEmpty) {
    throw FormatException('"$field" must be a nonempty string.');
  }
  return value;
}

String? _optionalString(Map<String, Object?> object, String field) {
  final value = object[field];
  if (value == null || value == '') return null;
  if (value is! String) {
    throw FormatException('"$field" must be a string when present.');
  }
  return value;
}

bool _boolean(Map<String, Object?> object, String field) {
  final value = object[field];
  if (value is! bool) throw FormatException('"$field" must be a boolean.');
  return value;
}

int _integer(Map<String, Object?> object, String field) {
  final value = object[field];
  if (value is! int) throw FormatException('"$field" must be an integer.');
  return value;
}

int? _optionalInteger(Map<String, Object?> object, String field) {
  final value = object[field];
  if (value == null) return null;
  if (value is! int) throw FormatException('"$field" must be an integer.');
  return value;
}

DateTime _time(Map<String, Object?> object, String field) {
  final value = _string(object, field);
  final parsed = DateTime.tryParse(value);
  if (parsed == null) throw FormatException('"$field" must be a timestamp.');
  return parsed.toUtc();
}

DateTime? _optionalTime(Map<String, Object?> object, String field) {
  final value = _optionalString(object, field);
  if (value == null) return null;
  final parsed = DateTime.tryParse(value);
  if (parsed == null) throw FormatException('"$field" must be a timestamp.');
  return parsed.toUtc();
}
