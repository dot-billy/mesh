import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../models/presentation_models.dart';

class OneTimeSecretPanel extends StatefulWidget {
  const OneTimeSecretPanel({
    required this.model,
    required this.onAcknowledged,
    required this.onScrubbed,
    super.key,
  });

  final OneTimeSecretViewModel model;
  final VoidCallback onAcknowledged;
  final VoidCallback onScrubbed;

  @override
  State<OneTimeSecretPanel> createState() => _OneTimeSecretPanelState();
}

class _OneTimeSecretPanelState extends State<OneTimeSecretPanel>
    with WidgetsBindingObserver {
  late List<String> _values;
  late List<bool> _revealed;
  bool _stored = false;
  bool _scrubbed = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _load(widget.model);
  }

  @override
  void didUpdateWidget(covariant OneTimeSecretPanel oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.model.id != widget.model.id) {
      _scrub(notify: false);
      _load(widget.model);
    }
  }

  void _load(OneTimeSecretViewModel model) {
    _values = [for (final item in model.items) item.value];
    _revealed = [for (final item in model.items) !item.hiddenByDefault];
    _stored = false;
    _scrubbed = false;
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.inactive ||
        state == AppLifecycleState.paused ||
        state == AppLifecycleState.hidden ||
        state == AppLifecycleState.detached) {
      _scrub();
    }
  }

  void _scrub({bool notify = true}) {
    if (_scrubbed) return;
    for (var index = 0; index < _values.length; index++) {
      _values[index] = '';
      _revealed[index] = false;
    }
    _stored = false;
    _scrubbed = true;
    if (notify) widget.onScrubbed();
    if (mounted) setState(() {});
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    for (var index = 0; index < _values.length; index++) {
      _values[index] = '';
    }
    super.dispose();
  }

  Future<void> _copy(int index) async {
    if (_scrubbed) return;
    final item = widget.model.items[index];
    await Clipboard.setData(ClipboardData(text: _values[index]));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          '${item.copyConfirmation}. Clear the clipboard after use.',
        ),
      ),
    );
  }

  void _finish() {
    if (!_stored || _scrubbed) return;
    widget.onAcknowledged();
    _scrub();
  }

  @override
  Widget build(BuildContext context) {
    if (_scrubbed) {
      return Semantics(
        label: 'One-time credential scrubbed',
        liveRegion: true,
        child: Card(
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Row(
              children: [
                const Icon(Icons.check_circle_outline),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    'The one-time credential has been removed from this view.',
                    style: Theme.of(context).textTheme.bodyLarge,
                  ),
                ),
              ],
            ),
          ),
        ),
      );
    }

    return Semantics(
      label: '${widget.model.title}. One-time secret material.',
      container: true,
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(
                    Icons.key_outlined,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      widget.model.title,
                      style: Theme.of(context).textTheme.titleLarge,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 10),
              Text(widget.model.detail),
              const SizedBox(height: 18),
              for (
                var index = 0;
                index < widget.model.items.length;
                index++
              ) ...[
                _SecretItem(
                  index: index,
                  item: widget.model.items[index],
                  value: _values[index],
                  revealed: _revealed[index],
                  onRevealChanged: widget.model.items[index].hiddenByDefault
                      ? () =>
                            setState(() => _revealed[index] = !_revealed[index])
                      : null,
                  onCopy: () => _copy(index),
                ),
                if (index != widget.model.items.length - 1)
                  const SizedBox(height: 14),
              ],
              const SizedBox(height: 16),
              CheckboxListTile(
                contentPadding: EdgeInsets.zero,
                controlAffinity: ListTileControlAffinity.leading,
                value: _stored,
                onChanged: (value) => setState(() => _stored = value ?? false),
                title: Text(widget.model.custodyLabel),
              ),
              Align(
                alignment: Alignment.centerRight,
                child: FilledButton(
                  key: const Key('one-time-secret-done'),
                  onPressed: _stored ? _finish : null,
                  child: const Text('Done and scrub'),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _SecretItem extends StatelessWidget {
  const _SecretItem({
    required this.index,
    required this.item,
    required this.value,
    required this.revealed,
    required this.onRevealChanged,
    required this.onCopy,
  });

  final int index;
  final OneTimeSecretItemViewModel item;
  final String value;
  final bool revealed;
  final VoidCallback? onRevealChanged;
  final VoidCallback onCopy;

  @override
  Widget build(BuildContext context) {
    return Semantics(
      label: '${item.label}. One-time material.',
      container: true,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(item.label, style: Theme.of(context).textTheme.labelLarge),
          const SizedBox(height: 6),
          DecoratedBox(
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.surfaceContainerHighest,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Row(
                children: [
                  Expanded(
                    child: SelectableText(
                      revealed ? value : '••••••••••••••••••••••••',
                      key: Key('one-time-secret-value-$index'),
                    ),
                  ),
                  if (onRevealChanged != null)
                    IconButton(
                      tooltip: revealed
                          ? 'Hide ${item.label.toLowerCase()}'
                          : 'Reveal ${item.label.toLowerCase()}',
                      onPressed: onRevealChanged,
                      icon: Icon(
                        revealed ? Icons.visibility_off : Icons.visibility,
                      ),
                    ),
                  IconButton(
                    tooltip: 'Copy ${item.label.toLowerCase()}',
                    onPressed: onCopy,
                    icon: const Icon(Icons.copy_outlined),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}
