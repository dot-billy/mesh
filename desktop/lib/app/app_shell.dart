import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../features/access/access_screen.dart';
import '../features/activity/activity_screen.dart';
import '../features/fleet/fleet_screen.dart';
import '../features/help/help_screen.dart';
import '../features/network/network_screen.dart';
import '../features/network/networks_directory_screen.dart';
import '../features/preferences/preferences_screen.dart';
import '../shared/callbacks/presentation_callbacks.dart';
import '../shared/models/presentation_models.dart';
import '../shared/theme/mesh_theme.dart';
import '../shared/widgets/one_time_secret_panel.dart';
import '../shared/widgets/operation_receipt.dart';

enum MeshDestination { fleet, networks, activity, access, preferences, help }

extension MeshDestinationPresentation on MeshDestination {
  String get label => switch (this) {
    MeshDestination.fleet => 'Fleet',
    MeshDestination.networks => 'Networks',
    MeshDestination.activity => 'Activity',
    MeshDestination.access => 'Access',
    MeshDestination.preferences => 'Preferences',
    MeshDestination.help => 'Help',
  };

  IconData get icon => switch (this) {
    MeshDestination.fleet => Icons.monitor_heart_outlined,
    MeshDestination.networks => Icons.hub_outlined,
    MeshDestination.activity => Icons.history,
    MeshDestination.access => Icons.manage_accounts_outlined,
    MeshDestination.preferences => Icons.settings_outlined,
    MeshDestination.help => Icons.help_outline,
  };
}

class MeshAppShell extends StatefulWidget {
  const MeshAppShell({required this.model, required this.callbacks, super.key});

  final MeshDesktopViewModel model;
  final MeshPresentationCallbacks callbacks;

  @override
  State<MeshAppShell> createState() => _MeshAppShellState();
}

class _MeshAppShellState extends State<MeshAppShell> {
  MeshDestination _destination = MeshDestination.fleet;

  AccessContextViewModel get _access => widget.model.accessContext!;
  MeshMutationCallbacks? get _mutations =>
      widget.callbacks is MeshMutationCallbacks
      ? widget.callbacks as MeshMutationCallbacks
      : null;

  List<MeshDestination> get _destinations => [
    MeshDestination.fleet,
    MeshDestination.networks,
    MeshDestination.activity,
    if (_access.role.allows(MeshPermission.identityManage))
      MeshDestination.access,
    MeshDestination.preferences,
    MeshDestination.help,
  ];

  @override
  void didUpdateWidget(covariant MeshAppShell oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (!_destinations.contains(_destination)) {
      _destination = MeshDestination.fleet;
    }
  }

  void _selectDestination(MeshDestination destination) {
    setState(() => _destination = destination);
  }

  void _selectNetwork(String networkId) {
    setState(() => _destination = MeshDestination.networks);
    widget.callbacks.selectNetwork(networkId);
  }

  void _refresh() {
    switch (_destination) {
      case MeshDestination.activity:
        widget.callbacks.refreshActivity();
      case MeshDestination.fleet ||
          MeshDestination.networks ||
          MeshDestination.access ||
          MeshDestination.preferences ||
          MeshDestination.help:
        widget.callbacks.refreshFleet();
    }
  }

  @override
  Widget build(BuildContext context) {
    final modal = widget.model.oneTimeSecret != null;
    return Shortcuts(
      shortcuts: const {
        SingleActivator(LogicalKeyboardKey.keyR, control: true):
            _RefreshIntent(),
        SingleActivator(LogicalKeyboardKey.comma, control: true):
            _PreferencesIntent(),
        SingleActivator(LogicalKeyboardKey.arrowLeft, alt: true): _BackIntent(),
      },
      child: Actions(
        actions: {
          _RefreshIntent: CallbackAction<_RefreshIntent>(
            onInvoke: (_) {
              _refresh();
              return null;
            },
          ),
          _PreferencesIntent: CallbackAction<_PreferencesIntent>(
            onInvoke: (_) {
              _selectDestination(MeshDestination.preferences);
              return null;
            },
          ),
          _BackIntent: CallbackAction<_BackIntent>(
            onInvoke: (_) {
              if (widget.model.selectedNetwork.phase == LoadPhase.ready) {
                widget.callbacks.clearSelectedNetwork();
              } else {
                _selectDestination(MeshDestination.fleet);
              }
              return null;
            },
          ),
        },
        child: FocusTraversalGroup(
          child: Stack(
            children: [
              ExcludeSemantics(
                excluding: modal,
                child: LayoutBuilder(
                  builder: (context, constraints) {
                    final extended =
                        constraints.maxWidth >=
                        MeshWindowMetrics.extendedRailBreakpoint;
                    return Scaffold(
                      body: Row(
                        children: [
                          _AppNavigation(
                            access: _access,
                            extended: extended,
                            destinations: _destinations,
                            selected: _destination,
                            onSelected: _selectDestination,
                            onSignOut: widget.callbacks.signOut,
                          ),
                          const VerticalDivider(width: 1),
                          Expanded(child: _content()),
                        ],
                      ),
                    );
                  },
                ),
              ),
              if (widget.model.receipt case final receipt?)
                Positioned(
                  left: 24,
                  right: 24,
                  bottom: 24,
                  child: Align(
                    alignment: Alignment.bottomCenter,
                    child: ConstrainedBox(
                      constraints: const BoxConstraints(maxWidth: 760),
                      child: OperationReceipt(
                        receipt: receipt,
                        onDismiss: widget.callbacks.dismissReceipt,
                      ),
                    ),
                  ),
                ),
              if (widget.model.oneTimeSecret case final secret?) ...[
                const ModalBarrier(
                  dismissible: false,
                  semanticsLabel: 'One-time credential dialog',
                ),
                Center(
                  child: ConstrainedBox(
                    constraints: const BoxConstraints(
                      maxWidth: 760,
                      maxHeight: 720,
                    ),
                    child: Material(
                      type: MaterialType.transparency,
                      child: SingleChildScrollView(
                        padding: const EdgeInsets.all(24),
                        child: OneTimeSecretPanel(
                          model: secret,
                          onAcknowledged:
                              widget.callbacks.acknowledgeOneTimeSecret,
                          onScrubbed: widget.callbacks.scrubOneTimeSecret,
                        ),
                      ),
                    ),
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  Widget _content() {
    if (_destination == MeshDestination.networks &&
        widget.model.selectedNetwork.phase != LoadPhase.initial &&
        widget.model.selectedNetwork.phase != LoadPhase.empty) {
      return NetworkScreen(
        state: widget.model.selectedNetwork,
        role: _access.role,
        callbacks: widget.callbacks,
      );
    }
    return switch (_destination) {
      MeshDestination.fleet => FleetScreen(
        state: widget.model.fleet,
        onRefresh: widget.callbacks.refreshFleet,
        onSelectNetwork: _selectNetwork,
      ),
      MeshDestination.networks => NetworksDirectoryScreen(
        state: widget.model.fleet,
        role: _access.role,
        onSelectNetwork: _selectNetwork,
        onCreateNetwork: _mutations?.createNetwork,
        onRefresh: widget.callbacks.refreshFleet,
      ),
      MeshDestination.activity => ActivityScreen(
        state: widget.model.activity,
        onRefresh: widget.callbacks.refreshActivity,
      ),
      MeshDestination.access => AccessScreen(
        state: widget.model.accessManagement,
        onRevokeSession: _mutations?.revokeAccessSession,
        onCreateRecoveryCode: _mutations?.createRecoveryAccess,
      ),
      MeshDestination.preferences => PreferencesScreen(
        model: widget.model.preferences,
        onThemeModeChanged: widget.callbacks.updateThemeMode,
        onNotificationsChanged: widget.callbacks.updateNotifications,
        onBackgroundMonitoringChanged:
            widget.callbacks.updateBackgroundMonitoring,
        onOpenSystemSettings: widget.callbacks.openSystemSettings,
      ),
      MeshDestination.help => HelpScreen(
        access: _access,
        onOpenDocumentation: widget.callbacks.openPublicDocumentation,
        onOpenAPIReference: widget.callbacks.openAPIReference,
      ),
    };
  }
}

class _AppNavigation extends StatelessWidget {
  const _AppNavigation({
    required this.access,
    required this.extended,
    required this.destinations,
    required this.selected,
    required this.onSelected,
    required this.onSignOut,
  });

  final AccessContextViewModel access;
  final bool extended;
  final List<MeshDestination> destinations;
  final MeshDestination selected;
  final ValueChanged<MeshDestination> onSelected;
  final VoidCallback onSignOut;

  @override
  Widget build(BuildContext context) {
    return Semantics(
      label: 'Primary navigation',
      container: true,
      child: NavigationRail(
        key: Key(extended ? 'extended-navigation' : 'compact-navigation'),
        extended: extended,
        minExtendedWidth: 220,
        selectedIndex: destinations.indexOf(selected),
        onDestinationSelected: (index) => onSelected(destinations[index]),
        leading: Padding(
          padding: const EdgeInsets.symmetric(vertical: 12),
          child: extended
              ? Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    _Mark(),
                    const SizedBox(width: 10),
                    const Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'Mesh',
                          style: TextStyle(fontWeight: FontWeight.w800),
                        ),
                        Text('Network operations'),
                      ],
                    ),
                  ],
                )
              : _Mark(),
        ),
        trailing: Padding(
          padding: const EdgeInsets.only(top: 8),
          child: SizedBox(
            width: extended ? 196 : 64,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Tooltip(
                  message:
                      '${access.displayName} · ${access.role.label} access',
                  child: extended
                      ? Row(
                          children: [
                            const Icon(Icons.account_circle_outlined),
                            const SizedBox(width: 8),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    access.displayName,
                                    overflow: TextOverflow.ellipsis,
                                  ),
                                  Text(
                                    '${access.role.label} access',
                                    style: Theme.of(
                                      context,
                                    ).textTheme.bodySmall,
                                  ),
                                ],
                              ),
                            ),
                          ],
                        )
                      : const Icon(Icons.account_circle_outlined),
                ),
                if (extended)
                  TextButton.icon(
                    onPressed: onSignOut,
                    icon: const Icon(Icons.logout),
                    label: const Text('Sign out'),
                  )
                else
                  IconButton(
                    tooltip: 'Sign out',
                    onPressed: onSignOut,
                    icon: const Icon(Icons.logout),
                  ),
              ],
            ),
          ),
        ),
        destinations: [
          for (final destination in destinations)
            NavigationRailDestination(
              icon: Icon(destination.icon),
              selectedIcon: Icon(destination.icon),
              label: Text(destination.label),
            ),
        ],
      ),
    );
  }
}

class _Mark extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return DecoratedBox(
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.primary,
        borderRadius: BorderRadius.circular(9),
      ),
      child: Padding(
        padding: const EdgeInsets.all(10),
        child: Text(
          'M',
          style: TextStyle(
            color: Theme.of(context).colorScheme.onPrimary,
            fontWeight: FontWeight.w900,
          ),
        ),
      ),
    );
  }
}

class _RefreshIntent extends Intent {
  const _RefreshIntent();
}

class _PreferencesIntent extends Intent {
  const _PreferencesIntent();
}

class _BackIntent extends Intent {
  const _BackIntent();
}
