import 'package:flutter/material.dart';

import '../../shared/callbacks/presentation_callbacks.dart';
import '../../shared/models/presentation_models.dart';

class CreateEnrollmentDialog extends StatefulWidget {
  const CreateEnrollmentDialog({
    required this.networkId,
    required this.onSubmit,
    super.key,
  });

  final String networkId;
  final Future<MutationSubmissionResult> Function(
    CreateNodeEnrollmentRequest request,
  )
  onSubmit;

  @override
  State<CreateEnrollmentDialog> createState() => _CreateEnrollmentDialogState();
}

class _CreateEnrollmentDialogState extends State<CreateEnrollmentDialog> {
  final _formKey = GlobalKey<FormState>();
  final _name = TextEditingController();
  final _site = TextEditingController();
  final _failureDomain = TextEditingController();
  final _groups = TextEditingController();
  final _publicEndpoint = TextEditingController();
  MeshNodeRole _role = MeshNodeRole.member;
  bool _submitting = false;
  String? _error;

  @override
  void dispose() {
    _name.dispose();
    _site.dispose();
    _failureDomain.dispose();
    _groups.dispose();
    _publicEndpoint.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (_submitting || !_formKey.currentState!.validate()) return;
    setState(() {
      _submitting = true;
      _error = null;
    });
    try {
      final groups = _groups.text
          .split(',')
          .map((group) => group.trim())
          .where((group) => group.isNotEmpty)
          .toSet()
          .toList();
      final result = await widget.onSubmit(
        CreateNodeEnrollmentRequest(
          networkId: widget.networkId,
          name: _name.text.trim(),
          role: _role,
          site: _site.text.trim(),
          failureDomain: _failureDomain.text.trim(),
          groups: groups,
          publicEndpoint: _role == MeshNodeRole.lighthouse
              ? _publicEndpoint.text.trim()
              : null,
        ),
      );
      if (!mounted) return;
      if (result.succeeded) {
        Navigator.of(context).pop();
        return;
      }
      setState(() {
        _submitting = false;
        _error = result.message ?? 'The enrollment was not created.';
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _submitting = false;
        _error = 'The enrollment could not be created. Try again.';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Create node enrollment'),
      content: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 560),
        child: SingleChildScrollView(
          child: Form(
            key: _formKey,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Define the node identity and placement. The resulting '
                  'enrollment material will be shown once.',
                ),
                const SizedBox(height: 16),
                TextFormField(
                  key: const Key('create-node-name'),
                  controller: _name,
                  enabled: !_submitting,
                  autofocus: true,
                  decoration: const InputDecoration(labelText: 'Node name'),
                  validator: _requiredName,
                ),
                const SizedBox(height: 12),
                DropdownButtonFormField<MeshNodeRole>(
                  key: const Key('create-node-role'),
                  initialValue: _role,
                  decoration: const InputDecoration(labelText: 'Node role'),
                  items: [
                    for (final role in MeshNodeRole.values)
                      DropdownMenuItem(value: role, child: Text(role.label)),
                  ],
                  onChanged: _submitting
                      ? null
                      : (value) => setState(() {
                          _role = value ?? MeshNodeRole.member;
                          if (_role == MeshNodeRole.member) {
                            _publicEndpoint.clear();
                          }
                        }),
                ),
                if (_role == MeshNodeRole.lighthouse) ...[
                  const SizedBox(height: 12),
                  TextFormField(
                    key: const Key('create-node-public-endpoint'),
                    controller: _publicEndpoint,
                    enabled: !_submitting,
                    decoration: const InputDecoration(
                      labelText: 'Public UDP endpoint',
                      hintText: 'vpn.example.com:4242',
                      helperText:
                          'Required for lighthouses; use a reachable host and port.',
                    ),
                    validator: _requiredPublicEndpoint,
                  ),
                ],
                const SizedBox(height: 12),
                TextFormField(
                  key: const Key('create-node-site'),
                  controller: _site,
                  enabled: !_submitting,
                  decoration: const InputDecoration(labelText: 'Site'),
                  validator: _requiredPlacement,
                ),
                const SizedBox(height: 12),
                TextFormField(
                  key: const Key('create-node-failure-domain'),
                  controller: _failureDomain,
                  enabled: !_submitting,
                  decoration: const InputDecoration(
                    labelText: 'Failure domain',
                  ),
                  validator: _requiredPlacement,
                ),
                const SizedBox(height: 12),
                TextFormField(
                  key: const Key('create-node-groups'),
                  controller: _groups,
                  enabled: !_submitting,
                  decoration: const InputDecoration(
                    labelText: 'Firewall groups',
                    hintText: 'servers, production',
                    helperText: 'Optional, comma-separated',
                  ),
                  onFieldSubmitted: (_) => _submit(),
                ),
                if (_error case final error?) ...[
                  const SizedBox(height: 12),
                  Semantics(
                    liveRegion: true,
                    label: 'Enrollment creation failed: $error',
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
      ),
      actions: [
        TextButton(
          onPressed: _submitting ? null : () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        FilledButton(
          key: const Key('submit-create-node'),
          onPressed: _submitting ? null : _submit,
          child: _submitting
              ? const SizedBox.square(
                  dimension: 18,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Text('Create enrollment'),
        ),
      ],
    );
  }

  static String? _requiredName(String? value) {
    final name = value?.trim() ?? '';
    if (name.isEmpty) return 'Enter a node name.';
    if (name.length > 64) return 'Use 64 characters or fewer.';
    if (!RegExp(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$').hasMatch(name)) {
      return 'Use letters, numbers, periods, underscores, or hyphens.';
    }
    return null;
  }

  static String? _requiredPlacement(String? value) {
    if ((value?.trim() ?? '').isEmpty) {
      return 'This placement value is required.';
    }
    return null;
  }

  static String? _requiredPublicEndpoint(String? value) {
    final endpoint = value?.trim() ?? '';
    if (endpoint.isEmpty) return 'Enter the lighthouse public endpoint.';
    final separator = endpoint.lastIndexOf(':');
    if (separator < 1 || separator == endpoint.length - 1) {
      return 'Use a host and port, such as vpn.example.com:4242.';
    }
    final port = int.tryParse(endpoint.substring(separator + 1));
    if (port == null || port < 1 || port > 65535) {
      return 'Use a port between 1 and 65535.';
    }
    return null;
  }
}
