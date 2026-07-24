import 'package:flutter/material.dart';

import '../../shared/models/presentation_models.dart';

class HelpScreen extends StatelessWidget {
  const HelpScreen({
    required this.access,
    required this.onOpenDocumentation,
    required this.onOpenAPIReference,
    super.key,
  });

  final AccessContextViewModel access;
  final VoidCallback onOpenDocumentation;
  final VoidCallback onOpenAPIReference;

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        Text('Help', style: Theme.of(context).textTheme.headlineMedium),
        const SizedBox(height: 6),
        const Text(
          'Documentation opens in your system browser. '
          'Credential-bearing and agent operations are not exposed here.',
        ),
        const SizedBox(height: 20),
        Wrap(
          spacing: 12,
          runSpacing: 12,
          children: [
            _HelpCard(
              icon: Icons.menu_book_outlined,
              title: 'Public operator guide',
              detail:
                  'Safe ordering, permissions, failure modes, and verification.',
              buttonLabel: 'Open documentation',
              onPressed: onOpenDocumentation,
            ),
            _HelpCard(
              icon: Icons.code_outlined,
              title: 'API reference',
              detail:
                  'OpenAPI operations, permissions, schemas, and response states.',
              buttonLabel: 'Open API reference',
              onPressed: onOpenAPIReference,
            ),
          ],
        ),
        const SizedBox(height: 24),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(18),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Connection diagnostics',
                  style: Theme.of(context).textTheme.titleLarge,
                ),
                const SizedBox(height: 12),
                SelectableText('Control plane: ${access.controlPlaneName}'),
                SelectableText('Origin: ${access.origin}'),
                SelectableText('Current role: ${access.role.label}'),
                const SizedBox(height: 12),
                const Text(
                  'Do not include administrator tokens, recovery codes, '
                  'enrollment material, private keys, or raw credentials in a '
                  'support bundle.',
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

class _HelpCard extends StatelessWidget {
  const _HelpCard({
    required this.icon,
    required this.title,
    required this.detail,
    required this.buttonLabel,
    required this.onPressed,
  });

  final IconData icon;
  final String title;
  final String detail;
  final String buttonLabel;
  final VoidCallback onPressed;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: 360,
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(18),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(icon, size: 32),
              const SizedBox(height: 12),
              Text(title, style: Theme.of(context).textTheme.titleMedium),
              const SizedBox(height: 6),
              Text(detail),
              const SizedBox(height: 16),
              FilledButton.tonal(
                onPressed: onPressed,
                child: Text(buttonLabel),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
