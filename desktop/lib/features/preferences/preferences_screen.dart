import 'package:flutter/material.dart';

import '../../shared/models/presentation_models.dart';

class PreferencesScreen extends StatelessWidget {
  const PreferencesScreen({
    required this.model,
    required this.onThemeModeChanged,
    required this.onNotificationsChanged,
    required this.onBackgroundMonitoringChanged,
    required this.onOpenSystemSettings,
    super.key,
  });

  final PreferencesViewModel model;
  final ValueChanged<ThemeMode> onThemeModeChanged;
  final ValueChanged<bool> onNotificationsChanged;
  final ValueChanged<bool> onBackgroundMonitoringChanged;
  final VoidCallback onOpenSystemSettings;

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        Text('Preferences', style: Theme.of(context).textTheme.headlineMedium),
        const SizedBox(height: 6),
        const Text(
          'Local desktop behavior. Control-plane policy is unchanged.',
        ),
        const SizedBox(height: 20),
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
                title: const Text('Desktop notifications'),
                subtitle: const Text(
                  'Allow critical and warning notifications while Mesh is running.',
                ),
                value: model.notificationsEnabled,
                onChanged: onNotificationsChanged,
              ),
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
          ),
        ),
        const SizedBox(height: 16),
        Align(
          alignment: Alignment.centerLeft,
          child: OutlinedButton.icon(
            onPressed: onOpenSystemSettings,
            icon: const Icon(Icons.settings_outlined),
            label: const Text('Open system notification settings'),
          ),
        ),
      ],
    );
  }
}
