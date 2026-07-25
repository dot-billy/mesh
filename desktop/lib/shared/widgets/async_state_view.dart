import 'package:flutter/material.dart';

import '../models/presentation_models.dart';

class AsyncStateView<T> extends StatelessWidget {
  const AsyncStateView({
    required this.state,
    required this.builder,
    required this.emptyTitle,
    required this.emptyMessage,
    this.onRetry,
    this.loadingLabel = 'Loading authoritative data',
    super.key,
  });

  final LoadableViewModel<T> state;
  final Widget Function(BuildContext context, T data) builder;
  final String emptyTitle;
  final String emptyMessage;
  final VoidCallback? onRetry;
  final String loadingLabel;

  @override
  Widget build(BuildContext context) {
    return switch (state.phase) {
      LoadPhase.ready when state.data != null => builder(
        context,
        state.data as T,
      ),
      LoadPhase.error => _ErrorState(
        message: state.message ?? 'The requested data could not be loaded.',
        onRetry: onRetry,
      ),
      LoadPhase.empty => _EmptyState(
        title: emptyTitle,
        message: state.message ?? emptyMessage,
      ),
      LoadPhase.initial ||
      LoadPhase.loading => _LoadingState(label: state.message ?? loadingLabel),
      _ => _ErrorState(
        message: 'The data state is incomplete and cannot be shown safely.',
        onRetry: onRetry,
      ),
    };
  }
}

class _LoadingState extends StatelessWidget {
  const _LoadingState({required this.label});

  final String label;

  @override
  Widget build(BuildContext context) {
    return Semantics(
      label: label,
      liveRegion: true,
      child: Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const CircularProgressIndicator(),
              const SizedBox(height: 16),
              Text(label),
            ],
          ),
        ),
      ),
    );
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState({required this.title, required this.message});

  final String title;
  final String message;

  @override
  Widget build(BuildContext context) {
    return Semantics(
      label: '$title. $message',
      container: true,
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 480),
          child: Padding(
            padding: const EdgeInsets.all(32),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  Icons.inbox_outlined,
                  size: 42,
                  color: Theme.of(context).colorScheme.primary,
                ),
                const SizedBox(height: 16),
                Text(title, style: Theme.of(context).textTheme.titleLarge),
                const SizedBox(height: 8),
                Text(message, textAlign: TextAlign.center),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _ErrorState extends StatelessWidget {
  const _ErrorState({required this.message, this.onRetry});

  final String message;
  final VoidCallback? onRetry;

  @override
  Widget build(BuildContext context) {
    return Semantics(
      label: 'Error: $message',
      liveRegion: true,
      container: true,
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 520),
          child: Card(
            color: Theme.of(context).colorScheme.errorContainer,
            child: Padding(
              padding: const EdgeInsets.all(20),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    Icons.error_outline,
                    color: Theme.of(context).colorScheme.onErrorContainer,
                  ),
                  const SizedBox(height: 12),
                  Text(
                    message,
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.onErrorContainer,
                    ),
                  ),
                  if (onRetry != null) ...[
                    const SizedBox(height: 16),
                    FilledButton.tonalIcon(
                      onPressed: onRetry,
                      icon: const Icon(Icons.refresh),
                      label: const Text('Try again'),
                    ),
                  ],
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
