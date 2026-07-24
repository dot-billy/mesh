import 'package:flutter/material.dart';

import '../../shared/callbacks/presentation_callbacks.dart';

class CreateNetworkDialog extends StatefulWidget {
  const CreateNetworkDialog({required this.onSubmit, super.key});

  final Future<MutationSubmissionResult> Function(CreateNetworkRequest request)
  onSubmit;

  @override
  State<CreateNetworkDialog> createState() => _CreateNetworkDialogState();
}

class _CreateNetworkDialogState extends State<CreateNetworkDialog> {
  final _formKey = GlobalKey<FormState>();
  final _name = TextEditingController();
  final _cidr = TextEditingController();
  bool _submitting = false;
  String? _error;

  @override
  void dispose() {
    _name.dispose();
    _cidr.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (_submitting || !_formKey.currentState!.validate()) return;
    setState(() {
      _submitting = true;
      _error = null;
    });
    try {
      final result = await widget.onSubmit(
        CreateNetworkRequest(name: _name.text.trim(), cidr: _cidr.text.trim()),
      );
      if (!mounted) return;
      if (result.succeeded) {
        Navigator.of(context).pop();
        return;
      }
      setState(() {
        _submitting = false;
        _error = result.message ?? 'The network was not created.';
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _submitting = false;
        _error = 'The network could not be created. Try again.';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Create network'),
      content: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 520),
        child: Form(
          key: _formKey,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'Choose the stable network name and private overlay CIDR. '
                'These values define the enrollment boundary.',
              ),
              const SizedBox(height: 16),
              TextFormField(
                key: const Key('create-network-name'),
                controller: _name,
                enabled: !_submitting,
                autofocus: true,
                decoration: const InputDecoration(labelText: 'Network name'),
                validator: _validateName,
              ),
              const SizedBox(height: 12),
              TextFormField(
                key: const Key('create-network-cidr'),
                controller: _cidr,
                enabled: !_submitting,
                decoration: const InputDecoration(
                  labelText: 'Private overlay CIDR',
                  hintText: '10.42.0.0/24',
                ),
                validator: _validateCIDR,
                onFieldSubmitted: (_) => _submit(),
              ),
              if (_error case final error?) ...[
                const SizedBox(height: 12),
                Semantics(
                  liveRegion: true,
                  label: 'Network creation failed: $error',
                  child: Text(
                    error,
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.error,
                    ),
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: _submitting ? null : () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        FilledButton(
          key: const Key('submit-create-network'),
          onPressed: _submitting ? null : _submit,
          child: _submitting
              ? const SizedBox.square(
                  dimension: 18,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Text('Create network'),
        ),
      ],
    );
  }

  static String? _validateName(String? value) {
    final name = value?.trim() ?? '';
    if (name.isEmpty) return 'Enter a network name.';
    if (name.length > 64) return 'Use 64 characters or fewer.';
    if (!RegExp(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$').hasMatch(name)) {
      return 'Use letters, numbers, periods, underscores, or hyphens.';
    }
    return null;
  }

  static String? _validateCIDR(String? value) {
    final input = value?.trim() ?? '';
    final match = RegExp(
      r'^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$',
    ).firstMatch(input);
    if (match == null) return 'Enter an IPv4 CIDR such as 10.42.0.0/24.';
    final octets = match.group(1)!.split('.').map(int.parse);
    final prefix = int.parse(match.group(2)!);
    if (octets.any((octet) => octet > 255) || prefix > 32) {
      return 'Enter a valid IPv4 CIDR.';
    }
    return null;
  }
}
