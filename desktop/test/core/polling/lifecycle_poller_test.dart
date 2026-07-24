import 'dart:async';

import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/core/polling/lifecycle_poller.dart';

void main() {
  test('polls immediately, suspends, and refreshes on resume', () async {
    final lifecycle = FakeLifecycleSource(AppLifecycleState.resumed);
    final timers = FakeTimerFactory();
    var polls = 0;
    final poller = LifecyclePoller(
      lifecycle: lifecycle,
      interval: const Duration(seconds: 15),
      poll: () async {
        polls += 1;
      },
      timerFactory: timers.create,
    );

    poller.start();
    await pumpEventQueue();
    expect(polls, 1);
    expect(timers.active, hasLength(1));

    lifecycle.setState(AppLifecycleState.paused);
    expect(timers.active, isEmpty);
    timers.fireAll();
    await pumpEventQueue();
    expect(polls, 1);

    lifecycle.setState(AppLifecycleState.resumed);
    await pumpEventQueue();
    expect(polls, 2);

    await poller.dispose();
    expect(timers.active, isEmpty);
    await lifecycle.dispose();
  });

  test('never overlaps requests and coalesces a pending refresh', () async {
    final lifecycle = FakeLifecycleSource(AppLifecycleState.resumed);
    final timers = FakeTimerFactory();
    final first = Completer<void>();
    var polls = 0;
    final poller = LifecyclePoller(
      lifecycle: lifecycle,
      interval: const Duration(seconds: 15),
      poll: () {
        polls += 1;
        return polls == 1 ? first.future : Future<void>.value();
      },
      timerFactory: timers.create,
    );

    poller.start();
    await pumpEventQueue();
    expect(polls, 1);

    poller
      ..refreshNow()
      ..refreshNow();
    await pumpEventQueue();
    expect(polls, 1);

    first.complete();
    await pumpEventQueue();
    expect(polls, 2);
    expect(timers.active, hasLength(1));

    await poller.dispose();
    await lifecycle.dispose();
  });

  test('reports errors and continues scheduling', () async {
    final lifecycle = FakeLifecycleSource(AppLifecycleState.resumed);
    final timers = FakeTimerFactory();
    final errors = <Object>[];
    var polls = 0;
    final poller = LifecyclePoller(
      lifecycle: lifecycle,
      interval: const Duration(seconds: 15),
      poll: () async {
        polls += 1;
        throw StateError('offline');
      },
      onError: (error, stackTrace) => errors.add(error),
      timerFactory: timers.create,
    );

    poller.start();
    await pumpEventQueue();

    expect(polls, 1);
    expect(errors, hasLength(1));
    expect(timers.active, hasLength(1));

    await poller.dispose();
    await lifecycle.dispose();
  });
}

final class FakeLifecycleSource implements LifecycleSource {
  FakeLifecycleSource(this._state);

  final StreamController<AppLifecycleState> _controller =
      StreamController<AppLifecycleState>.broadcast(sync: true);
  AppLifecycleState _state;

  @override
  Stream<AppLifecycleState> get changes => _controller.stream;

  @override
  AppLifecycleState get currentState => _state;

  void setState(AppLifecycleState state) {
    _state = state;
    _controller.add(state);
  }

  Future<void> dispose() => _controller.close();
}

final class FakeTimerFactory {
  final List<FakePollingTimer> timers = <FakePollingTimer>[];

  List<FakePollingTimer> get active =>
      timers.where((timer) => !timer.cancelled && !timer.fired).toList();

  PollingTimer create(Duration delay, void Function() callback) {
    final timer = FakePollingTimer(delay, callback);
    timers.add(timer);
    return timer;
  }

  void fireAll() {
    for (final timer in List<FakePollingTimer>.of(active)) {
      timer.fire();
    }
  }
}

final class FakePollingTimer implements PollingTimer {
  FakePollingTimer(this.delay, this.callback);

  final Duration delay;
  final void Function() callback;
  bool cancelled = false;
  bool fired = false;

  @override
  void cancel() {
    cancelled = true;
  }

  void fire() {
    if (cancelled || fired) {
      return;
    }
    fired = true;
    callback();
  }
}
