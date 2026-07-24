import 'dart:async';

import 'package:flutter/widgets.dart';

abstract interface class LifecycleSource {
  AppLifecycleState get currentState;

  Stream<AppLifecycleState> get changes;
}

final class WidgetsBindingLifecycleSource
    with WidgetsBindingObserver
    implements LifecycleSource {
  WidgetsBindingLifecycleSource({WidgetsBinding? binding})
    : _binding = binding ?? WidgetsBinding.instance,
      _state =
          (binding ?? WidgetsBinding.instance).lifecycleState ??
          AppLifecycleState.resumed {
    _binding.addObserver(this);
  }

  final WidgetsBinding _binding;
  final StreamController<AppLifecycleState> _changes =
      StreamController<AppLifecycleState>.broadcast(sync: true);
  AppLifecycleState _state;

  @override
  AppLifecycleState get currentState => _state;

  @override
  Stream<AppLifecycleState> get changes => _changes.stream;

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    _state = state;
    _changes.add(state);
  }

  void dispose() {
    _binding.removeObserver(this);
    _changes.close();
  }
}

abstract interface class PollingTimer {
  void cancel();
}

typedef PollingTimerFactory =
    PollingTimer Function(Duration delay, void Function() callback);

final class LifecyclePoller {
  LifecyclePoller({
    required this.lifecycle,
    required this.interval,
    required this.poll,
    this.onError,
    PollingTimerFactory? timerFactory,
  }) : _timerFactory = timerFactory ?? _createTimer {
    if (interval <= Duration.zero) {
      throw ArgumentError.value(interval, 'interval', 'must be positive');
    }
  }

  final LifecycleSource lifecycle;
  final Duration interval;
  final Future<void> Function() poll;
  final void Function(Object error, StackTrace stackTrace)? onError;
  final PollingTimerFactory _timerFactory;

  StreamSubscription<AppLifecycleState>? _subscription;
  PollingTimer? _timer;
  bool _started = false;
  bool _disposed = false;
  bool _polling = false;
  bool _refreshPending = false;

  bool get isRunning => _started && !_disposed;
  bool get isPolling => _polling;

  void start() {
    if (_disposed) {
      throw StateError('LifecyclePoller has been disposed.');
    }
    if (_started) {
      return;
    }
    _started = true;
    _subscription = lifecycle.changes.listen(_lifecycleChanged);
    if (_isActive(lifecycle.currentState)) {
      unawaited(_run());
    }
  }

  void refreshNow() {
    if (!isRunning || !_isActive(lifecycle.currentState)) {
      return;
    }
    _timer?.cancel();
    _timer = null;
    if (_polling) {
      _refreshPending = true;
      return;
    }
    unawaited(_run());
  }

  void _lifecycleChanged(AppLifecycleState state) {
    if (!isRunning) {
      return;
    }
    if (!_isActive(state)) {
      _timer?.cancel();
      _timer = null;
      _refreshPending = false;
      return;
    }
    refreshNow();
  }

  Future<void> _run() async {
    if (_polling || !isRunning || !_isActive(lifecycle.currentState)) {
      return;
    }
    _polling = true;
    try {
      await poll();
    } catch (error, stackTrace) {
      onError?.call(error, stackTrace);
    } finally {
      _polling = false;
    }
    if (!isRunning || !_isActive(lifecycle.currentState)) {
      _refreshPending = false;
      return;
    }
    if (_refreshPending) {
      _refreshPending = false;
      unawaited(_run());
      return;
    }
    _timer?.cancel();
    _timer = _timerFactory(interval, () {
      _timer = null;
      unawaited(_run());
    });
  }

  Future<void> dispose() async {
    if (_disposed) {
      return;
    }
    _disposed = true;
    _timer?.cancel();
    _timer = null;
    await _subscription?.cancel();
    _subscription = null;
  }

  static bool _isActive(AppLifecycleState state) =>
      state == AppLifecycleState.resumed;

  static PollingTimer _createTimer(Duration delay, void Function() callback) =>
      _DartPollingTimer(Timer(delay, callback));
}

final class _DartPollingTimer implements PollingTimer {
  const _DartPollingTimer(this._timer);

  final Timer _timer;

  @override
  void cancel() => _timer.cancel();
}
