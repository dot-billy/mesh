import 'package:flutter/material.dart';

import '../../shared/callbacks/presentation_callbacks.dart';
import '../../shared/models/presentation_models.dart';

class ConnectionScreen extends StatefulWidget {
  const ConnectionScreen({
    required this.model,
    required this.callbacks,
    super.key,
  });

  final ConnectionViewModel model;
  final MeshPresentationCallbacks callbacks;

  @override
  State<ConnectionScreen> createState() => _ConnectionScreenState();
}

class _ConnectionScreenState extends State<ConnectionScreen> {
  final _formKey = GlobalKey<FormState>();
  final _nameController = TextEditingController();
  final _originController = TextEditingController();
  final _credentialController = TextEditingController();
  AuthenticationMethod? _credentialMethod;

  @override
  void dispose() {
    _nameController.dispose();
    _originController.dispose();
    _credentialController.text = '';
    _credentialController.dispose();
    super.dispose();
  }

  void _addConnection() {
    if (!_formKey.currentState!.validate()) return;
    final origin = Uri.parse(_originController.text.trim());
    widget.callbacks.addConnection(
      ConnectionRequest(
        displayName: _nameController.text.trim(),
        origin: origin,
      ),
    );
  }

  String? _validateOrigin(String? value) {
    final uri = Uri.tryParse(value?.trim() ?? '');
    if (uri == null || !uri.hasScheme || uri.host.isEmpty) {
      return 'Enter a complete control-plane URL.';
    }
    final loopback =
        uri.host == 'localhost' || uri.host == '127.0.0.1' || uri.host == '::1';
    if (uri.scheme != 'https' && !(uri.scheme == 'http' && loopback)) {
      return 'Use HTTPS. Cleartext HTTP is allowed only on loopback.';
    }
    if (uri.userInfo.isNotEmpty || uri.path != '' && uri.path != '/') {
      return 'Use only the control-plane origin, without credentials or a path.';
    }
    return null;
  }

  void _authenticate(AuthenticationMethod method) {
    if (method == AuthenticationMethod.oidc) {
      widget.callbacks.authenticate(method);
      return;
    }
    setState(() {
      _credentialMethod = method;
      _credentialController.text = '';
    });
  }

  void _submitCredential() {
    final value = _credentialController.text;
    if (_credentialMethod == null || value.trim().isEmpty) return;
    widget.callbacks.authenticate(_credentialMethod!, credential: value);
    _credentialController.text = '';
  }

  @override
  Widget build(BuildContext context) {
    final selected = widget.model.selectedProfile;
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(32),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 620),
              child: Card(
                child: Padding(
                  padding: const EdgeInsets.all(28),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          DecoratedBox(
                            decoration: BoxDecoration(
                              color: Theme.of(context).colorScheme.primary,
                              borderRadius: BorderRadius.circular(10),
                            ),
                            child: Padding(
                              padding: const EdgeInsets.all(12),
                              child: Text(
                                'M',
                                style: TextStyle(
                                  color: Theme.of(
                                    context,
                                  ).colorScheme.onPrimary,
                                  fontWeight: FontWeight.w900,
                                ),
                              ),
                            ),
                          ),
                          const SizedBox(width: 12),
                          const Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  'Mesh',
                                  style: TextStyle(
                                    fontSize: 20,
                                    fontWeight: FontWeight.w800,
                                  ),
                                ),
                                Text('Network operations'),
                              ],
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 28),
                      Text(
                        'Connect to a control plane',
                        style: Theme.of(context).textTheme.headlineMedium,
                      ),
                      const SizedBox(height: 8),
                      const Text(
                        'Mesh uses the operating system trust store and never '
                        'offers a bypass for invalid TLS.',
                      ),
                      if (widget.model.message case final message?) ...[
                        const SizedBox(height: 16),
                        Semantics(
                          liveRegion: true,
                          label: message,
                          child: Text(
                            message,
                            style: TextStyle(
                              color: widget.model.phase == LoadPhase.error
                                  ? Theme.of(context).colorScheme.error
                                  : null,
                            ),
                          ),
                        ),
                      ],
                      if (widget.model.profiles.isNotEmpty) ...[
                        const SizedBox(height: 20),
                        DropdownButtonFormField<String>(
                          key: const Key('connection-profile-picker'),
                          initialValue: widget.model.selectedProfileId,
                          decoration: const InputDecoration(
                            labelText: 'Saved control plane',
                          ),
                          items: [
                            for (final profile in widget.model.profiles)
                              DropdownMenuItem(
                                value: profile.id,
                                child: Text(
                                  '${profile.displayName} · ${profile.origin}',
                                ),
                              ),
                          ],
                          onChanged: (value) {
                            if (value != null) {
                              widget.callbacks.selectConnection(value);
                            }
                          },
                        ),
                      ],
                      if (selected == null) ...[
                        const SizedBox(height: 20),
                        Form(
                          key: _formKey,
                          child: Column(
                            children: [
                              TextFormField(
                                key: const Key('connection-name'),
                                controller: _nameController,
                                decoration: const InputDecoration(
                                  labelText: 'Connection name',
                                  hintText: 'Production',
                                ),
                                validator: (value) =>
                                    value == null || value.trim().isEmpty
                                    ? 'Enter a connection name.'
                                    : null,
                              ),
                              const SizedBox(height: 12),
                              TextFormField(
                                key: const Key('connection-origin'),
                                controller: _originController,
                                decoration: const InputDecoration(
                                  labelText: 'Control-plane URL',
                                  hintText: 'https://mesh.example.com',
                                ),
                                keyboardType: TextInputType.url,
                                validator: _validateOrigin,
                              ),
                              const SizedBox(height: 16),
                              Align(
                                alignment: Alignment.centerRight,
                                child: FilledButton.icon(
                                  key: const Key('add-control-plane'),
                                  onPressed:
                                      widget.model.phase == LoadPhase.loading
                                      ? null
                                      : _addConnection,
                                  icon: const Icon(Icons.add_link),
                                  label: const Text('Add control plane'),
                                ),
                              ),
                            ],
                          ),
                        ),
                      ] else ...[
                        const SizedBox(height: 20),
                        ListTile(
                          contentPadding: EdgeInsets.zero,
                          leading: Icon(
                            selected.tlsTrusted
                                ? Icons.lock_outline
                                : Icons.warning_amber_rounded,
                          ),
                          title: Text(selected.displayName),
                          subtitle: Text(selected.origin.toString()),
                          trailing: Text(
                            selected.tlsTrusted
                                ? 'System trust verified'
                                : 'Trust not verified',
                          ),
                        ),
                        const Divider(height: 28),
                        Text(
                          'Sign in',
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                        const SizedBox(height: 12),
                        for (final method in widget.model.methods) ...[
                          SizedBox(
                            width: double.infinity,
                            child: method == AuthenticationMethod.oidc
                                ? FilledButton.icon(
                                    onPressed: () => _authenticate(method),
                                    icon: Icon(method.icon),
                                    label: Text(
                                      'Continue with ${method.label}',
                                    ),
                                  )
                                : OutlinedButton.icon(
                                    onPressed: () => _authenticate(method),
                                    icon: Icon(method.icon),
                                    label: Text('Use ${method.label}'),
                                  ),
                          ),
                          const SizedBox(height: 8),
                        ],
                        if (_credentialMethod case final method?) ...[
                          const SizedBox(height: 8),
                          TextField(
                            key: const Key('sign-in-credential'),
                            controller: _credentialController,
                            obscureText: true,
                            autofocus: true,
                            decoration: InputDecoration(
                              labelText: method.label,
                            ),
                            onSubmitted: (_) => _submitCredential(),
                          ),
                          const SizedBox(height: 12),
                          Align(
                            alignment: Alignment.centerRight,
                            child: FilledButton(
                              onPressed: _submitCredential,
                              child: const Text('Sign in'),
                            ),
                          ),
                        ],
                      ],
                      const SizedBox(height: 20),
                      Wrap(
                        spacing: 8,
                        children: [
                          TextButton.icon(
                            onPressed: widget.callbacks.openPublicDocumentation,
                            icon: const Icon(Icons.menu_book_outlined),
                            label: const Text('Public documentation'),
                          ),
                          TextButton.icon(
                            onPressed: widget.callbacks.openAPIReference,
                            icon: const Icon(Icons.code_outlined),
                            label: const Text('API reference'),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
