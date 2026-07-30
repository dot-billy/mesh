import 'package:flutter/material.dart';

import '../../shared/models/presentation_models.dart';

class PreferencesScreen extends StatelessWidget {
  const PreferencesScreen({
    required this.model,
    required this.onThemeModeChanged,
    required this.onNotificationsChanged,
    required this.onBackgroundMonitoringChanged,
    required this.onOpenSystemSettings,
    required this.onCopyDiagnosticBundle,
    required this.onEraseLocalData,
    this.managedPolicy,
    super.key,
  });

  final PreferencesViewModel model;
  final AppleManagedPolicyViewModel? managedPolicy;
  final ValueChanged<ThemeMode> onThemeModeChanged;
  final ValueChanged<bool> onNotificationsChanged;
  final ValueChanged<bool> onBackgroundMonitoringChanged;
  final VoidCallback onOpenSystemSettings;
  final VoidCallback onCopyDiagnosticBundle;
  final VoidCallback onEraseLocalData;

  Future<void> _confirmEraseLocalData(BuildContext context) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Erase local Mesh Admin data?'),
        content: const Text(
          'This deletes the current session and all saved control-plane '
          'profiles from this device. It does not remove organization-managed '
          'profiles, operating-system permissions, server records, or a '
          'separately installed Mesh Node.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            key: const Key('confirm-erase-local-data-button'),
            onPressed: () => Navigator.of(dialogContext).pop(true),
            style: FilledButton.styleFrom(
              backgroundColor: Theme.of(dialogContext).colorScheme.error,
              foregroundColor: Theme.of(dialogContext).colorScheme.onError,
            ),
            child: const Text('Erase local data'),
          ),
        ],
      ),
    );
    if (confirmed == true) {
      onEraseLocalData();
    }
  }

  @override
  Widget build(BuildContext context) {
    final ios = Theme.of(context).platform == TargetPlatform.iOS;
    final managedNotifications = managedPolicy?.notificationsEnabled;
    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        Text('Preferences', style: Theme.of(context).textTheme.headlineMedium),
        const SizedBox(height: 6),
        const Text(
          'Local application behavior. Control-plane policy is unchanged.',
        ),
        const SizedBox(height: 20),
        if (managedPolicy case final policy?) ...[
          Card(
            child: ListTile(
              leading: Icon(
                policy.valid ? Icons.business_outlined : Icons.error_outline,
              ),
              title: Text(
                policy.valid
                    ? 'Organization-managed settings'
                    : 'Managed settings rejected',
              ),
              subtitle: Text(
                policy.valid
                    ? [
                        if (policy.controlPlaneOrigin != null)
                          policy.originLocked
                              ? 'Control-plane origin locked'
                              : 'Control-plane origin supplied',
                        if (policy.releaseChannel != null)
                          'Release channel: ${policy.releaseChannel}',
                        if (policy.updateRing != null)
                          'Update ring: ${policy.updateRing}',
                        if (policy.showLocalStatus != null)
                          policy.showLocalStatus!
                              ? 'Local status display allowed'
                              : 'Local status display hidden',
                      ].join(' · ')
                    : 'The app failed closed. Correct the MDM application configuration before connecting.',
              ),
            ),
          ),
          const SizedBox(height: 16),
        ],
        Card(
          child: Padding(
            padding: const EdgeInsets.all(18),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Appearance',
                  style: Theme.of(context).textTheme.titleLarge,
                ),
                const SizedBox(height: 12),
                SegmentedButton<ThemeMode>(
                  segments: const [
                    ButtonSegment(
                      value: ThemeMode.system,
                      icon: Icon(Icons.computer),
                      label: Text('System'),
                    ),
                    ButtonSegment(
                      value: ThemeMode.light,
                      icon: Icon(Icons.light_mode_outlined),
                      label: Text('Light'),
                    ),
                    ButtonSegment(
                      value: ThemeMode.dark,
                      icon: Icon(Icons.dark_mode_outlined),
                      label: Text('Dark'),
                    ),
                  ],
                  selected: {model.themeMode},
                  onSelectionChanged: (value) =>
                      onThemeModeChanged(value.first),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 16),
        Card(
          child: Column(
            children: [
              SwitchListTile(
                title: const Text('Notifications'),
                subtitle: const Text(
                  'Allow critical and warning notifications while Mesh is running.',
                ),
                value: model.notificationsEnabled,
                onChanged: managedNotifications == null
                    ? onNotificationsChanged
                    : null,
              ),
              if (ios) ...[
                const Divider(height: 1),
                const ListTile(
                  minTileHeight: 48,
                  leading: Icon(Icons.pause_circle_outline),
                  title: Text('Foreground-only polling'),
                  subtitle: Text(
                    'Polling pauses whenever Mesh Admin is not active. No iOS background mode is requested.',
                  ),
                ),
              ] else ...[
                const Divider(height: 1),
                SwitchListTile(
                  title: const Text('Background monitoring'),
                  subtitle: const Text(
                    'Keep monitoring after the window closes. Off by default.',
                  ),
                  value: model.backgroundMonitoringEnabled,
                  onChanged: onBackgroundMonitoringChanged,
                ),
              ],
            ],
          ),
        ),
        const SizedBox(height: 16),
        Align(
          alignment: Alignment.centerLeft,
          child: Wrap(
            spacing: 12,
            runSpacing: 12,
            children: [
              OutlinedButton.icon(
                onPressed: onOpenSystemSettings,
                icon: const Icon(Icons.settings_outlined),
                label: const Text('Open system notification settings'),
              ),
              if (ios || Theme.of(context).platform == TargetPlatform.macOS)
                OutlinedButton.icon(
                  onPressed: onCopyDiagnosticBundle,
                  icon: const Icon(Icons.content_copy_outlined),
                  label: const Text('Copy bounded diagnostic bundle'),
                ),
            ],
          ),
        ),
        if (ios || Theme.of(context).platform == TargetPlatform.macOS) ...[
          const SizedBox(height: 8),
          const Text(
            'The JSON bundle excludes origins, names, IDs, credentials, raw errors, logs, and configuration. It is never uploaded automatically.',
          ),
          const SizedBox(height: 24),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(18),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Before uninstalling',
                    style: Theme.of(context).textTheme.titleLarge,
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'Erase this app’s Keychain session and saved control-plane '
                    'profiles before removing the application.',
                  ),
                  const SizedBox(height: 12),
                  OutlinedButton.icon(
                    key: const Key('erase-local-data-button'),
                    onPressed: () => _confirmEraseLocalData(context),
                    icon: const Icon(Icons.delete_outline),
                    label: const Text('Erase local data'),
                  ),
                ],
              ),
            ),
          ),
        ],
      ],
    );
  }
}
