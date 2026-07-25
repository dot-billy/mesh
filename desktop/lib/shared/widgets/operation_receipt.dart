import 'package:flutter/material.dart';

import '../models/presentation_models.dart';
import 'evidence_badge.dart';

class OperationReceipt extends StatelessWidget {
  const OperationReceipt({
    required this.receipt,
    required this.onDismiss,
    super.key,
  });

  final OperationReceiptViewModel receipt;
  final VoidCallback onDismiss;

  @override
  Widget build(BuildContext context) {
    return Semantics(
      label: 'Operation receipt: ${receipt.title}. ${receipt.summary}',
      liveRegion: true,
      container: true,
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Expanded(
                    child: Text(
                      receipt.title,
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                  ),
                  EvidenceBadge(tone: receipt.tone, compact: true),
                  IconButton(
                    tooltip: 'Dismiss receipt',
                    onPressed: onDismiss,
                    icon: const Icon(Icons.close),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              Text(receipt.summary),
              if (receipt.revision != null) ...[
                const SizedBox(height: 8),
                Text('Configuration revision ${receipt.revision}'),
              ],
              if (receipt.requestId case final requestId?) ...[
                const SizedBox(height: 4),
                SelectableText('Request ID $requestId'),
              ],
              if (receipt.verification case final verification?) ...[
                const SizedBox(height: 8),
                Text(verification),
              ],
            ],
          ),
        ),
      ),
    );
  }
}
