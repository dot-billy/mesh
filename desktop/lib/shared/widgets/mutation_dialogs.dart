import 'package:flutter/material.dart';

import '../callbacks/presentation_callbacks.dart';

class MutationConfirmationDialog extends StatefulWidget {
  const MutationConfirmationDialog({
    required this.title,
    required this.detail,
    required this.confirmLabel,
    required this.onConfirm,
    this.destructive = false,
    super.key,
  });

  final String title;
  final String detail;
  final String confirmLabel;
  final bool destructive;
  final Future<MutationSubmissionResult> Function() onConfirm;

  @override
  State<MutationConfirmationDialog> createState() =>
      _MutationConfirmationDialogState();
}

class _MutationConfirmationDialogState
    extends State<MutationConfirmationDialog> {
  bool _submitting = false;
  String? _error;

  Future<void> _submit() async {
    if (_submitting) return;
    setState(() {
      _submitting = true;
      _error = null;
    });
    try {
      final result = await widget.onConfirm();
      if (!mounted) return;
      if (result.succeeded) {
        Navigator.of(context).pop();
        return;
      }
      setState(() {
        _submitting = false;
        _error = result.message ?? 'The operation was not completed.';
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _submitting = false;
        _error = 'The operation could not be completed. Try again.';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Text(widget.title),
      content: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 480),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(widget.detail),
            if (_error case final error?) ...[
              const SizedBox(height: 16),
              Semantics(
                liveRegion: true,
                label: 'Operation failed: $error',
                child: Text(
                  error,
                  style: TextStyle(color: Theme.of(context).colorScheme.error),
                ),
              ),
            ],
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: _submitting ? null : () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        FilledButton(
          key: const Key('confirm-mutation'),
          style: widget.destructive
              ? FilledButton.styleFrom(
                  backgroundColor: Theme.of(context).colorScheme.error,
                  foregroundColor: Theme.of(context).colorScheme.onError,
                )
              : null,
          onPressed: _submitting ? null : _submit,
          child: _submitting
              ? const SizedBox.square(
                  dimension: 18,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : Text(widget.confirmLabel),
        ),
      ],
    );
  }
}

class ExactNameConfirmationDialog extends StatefulWidget {
  const ExactNameConfirmationDialog({
    required this.title,
    required this.detail,
    required this.requiredName,
    required this.confirmLabel,
    required this.onConfirm,
    super.key,
  });

  final String title;
  final String detail;
  final String requiredName;
  final String confirmLabel;
  final Future<MutationSubmissionResult> Function(String confirmedName)
  onConfirm;

  @override
  State<ExactNameConfirmationDialog> createState() =>
      _ExactNameConfirmationDialogState();
}

class _ExactNameConfirmationDialogState
    extends State<ExactNameConfirmationDialog> {
  final _controller = TextEditingController();
  bool _submitting = false;
  String? _error;

  bool get _matches => _controller.text == widget.requiredName;

  @override
  void dispose() {
    _controller.clear();
    _controller.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (_submitting || !_matches) return;
    setState(() {
      _submitting = true;
      _error = null;
    });
    try {
      final result = await widget.onConfirm(_controller.text);
      if (!mounted) return;
      if (result.succeeded) {
        _controller.clear();
        Navigator.of(context).pop();
        return;
      }
      setState(() {
        _submitting = false;
        _error = result.message ?? 'The operation was not completed.';
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _submitting = false;
        _error = 'The operation could not be completed. Try again.';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    return AlertDialog(
      icon: Icon(Icons.warning_amber_rounded, color: colorScheme.error),
      title: Text(widget.title),
      content: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 520),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(widget.detail),
            const SizedBox(height: 14),
            Text(
              'Type ${widget.requiredName} to confirm.',
              style: const TextStyle(fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 8),
            TextField(
              key: const Key('exact-name-confirmation'),
              controller: _controller,
              enabled: !_submitting,
              autofocus: true,
              autocorrect: false,
              enableSuggestions: false,
              decoration: InputDecoration(
                labelText: 'Node name',
                errorText: _controller.text.isNotEmpty && !_matches
                    ? 'Name does not match.'
                    : null,
              ),
              onChanged: (_) => setState(() => _error = null),
              onSubmitted: (_) => _submit(),
            ),
            if (_error case final error?) ...[
              const SizedBox(height: 12),
              Semantics(
                liveRegion: true,
                label: 'Operation failed: $error',
                child: Text(error, style: TextStyle(color: colorScheme.error)),
              ),
            ],
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: _submitting ? null : () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        FilledButton(
          key: const Key('confirm-exact-name-mutation'),
          style: FilledButton.styleFrom(
            backgroundColor: colorScheme.error,
            foregroundColor: colorScheme.onError,
          ),
          onPressed: _matches && !_submitting ? _submit : null,
          child: _submitting
              ? const SizedBox.square(
                  dimension: 18,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : Text(widget.confirmLabel),
        ),
      ],
    );
  }
}
