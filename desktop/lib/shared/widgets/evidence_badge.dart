import 'package:flutter/material.dart';

import '../models/presentation_models.dart';

class EvidenceBadge extends StatelessWidget {
  const EvidenceBadge({
    required this.tone,
    this.label,
    this.compact = false,
    super.key,
  });

  final EvidenceTone tone;
  final String? label;
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final colors = _toneColors(context, tone);
    final text = label ?? tone.label;
    return Semantics(
      label: 'Status: $text',
      container: true,
      child: DecoratedBox(
        decoration: BoxDecoration(
          color: colors.$1,
          borderRadius: BorderRadius.circular(999),
          border: Border.all(color: colors.$2),
        ),
        child: Padding(
          padding: EdgeInsets.symmetric(
            horizontal: compact ? 8 : 10,
            vertical: compact ? 4 : 6,
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(tone.icon, size: compact ? 14 : 16, color: colors.$3),
              const SizedBox(width: 6),
              Flexible(
                child: Text(
                  text,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: Theme.of(context).textTheme.labelMedium?.copyWith(
                    color: colors.$3,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

(Color, Color, Color) _toneColors(BuildContext context, EvidenceTone tone) {
  final scheme = Theme.of(context).colorScheme;
  return switch (tone) {
    EvidenceTone.healthy => (
      scheme.primaryContainer,
      scheme.primary,
      scheme.onPrimaryContainer,
    ),
    EvidenceTone.warning || EvidenceTone.setup => (
      const Color(0x26ffb300),
      const Color(0xffffb300),
      Theme.of(context).brightness == Brightness.dark
          ? const Color(0xffffcf70)
          : const Color(0xff704d00),
    ),
    EvidenceTone.critical => (
      scheme.errorContainer,
      scheme.error,
      scheme.onErrorContainer,
    ),
    EvidenceTone.unavailable => (
      scheme.surfaceContainerHighest,
      scheme.outline,
      scheme.onSurfaceVariant,
    ),
    EvidenceTone.information => (
      scheme.secondaryContainer,
      scheme.secondary,
      scheme.onSecondaryContainer,
    ),
  };
}
