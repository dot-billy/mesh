import 'package:flutter/material.dart';

class FreshnessStamp extends StatelessWidget {
  const FreshnessStamp({
    required this.generatedAt,
    this.now,
    this.prefix = 'Generated',
    super.key,
  });

  final DateTime generatedAt;
  final DateTime? now;
  final String prefix;

  String _age(DateTime reference) {
    final difference = reference.difference(generatedAt);
    if (difference.inSeconds < 0) return 'clock differs';
    if (difference.inSeconds < 60) return '${difference.inSeconds}s ago';
    if (difference.inMinutes < 60) return '${difference.inMinutes}m ago';
    if (difference.inHours < 24) return '${difference.inHours}h ago';
    return '${difference.inDays}d ago';
  }

  @override
  Widget build(BuildContext context) {
    final reference = now ?? DateTime.now();
    final local = generatedAt.toLocal();
    final exact =
        '${local.year.toString().padLeft(4, '0')}-${local.month.toString().padLeft(2, '0')}-${local.day.toString().padLeft(2, '0')} '
        '${local.hour.toString().padLeft(2, '0')}:${local.minute.toString().padLeft(2, '0')}:${local.second.toString().padLeft(2, '0')}';
    final label = '$prefix $exact (${_age(reference)})';
    return Semantics(
      label: label,
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Icon(Icons.schedule_outlined, size: 16),
          const SizedBox(width: 6),
          Flexible(
            child: Text(label, style: Theme.of(context).textTheme.bodySmall),
          ),
        ],
      ),
    );
  }
}
