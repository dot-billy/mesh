import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

enum AppleAdminNotificationEvent {
  fleetWarning('fleet-warning'),
  fleetCritical('fleet-critical');

  const AppleAdminNotificationEvent(this.code);

  final String code;
}

final class AppleAdminNotificationTransition {
  bool _initialized = false;
  AppleAdminNotificationEvent? _last;

  AppleAdminNotificationEvent? observe({
    required bool hasCritical,
    required bool hasWarning,
  }) {
    final current = hasCritical
        ? AppleAdminNotificationEvent.fleetCritical
        : hasWarning
        ? AppleAdminNotificationEvent.fleetWarning
        : null;
    if (!_initialized) {
      _initialized = true;
      _last = current;
      return null;
    }
    final deliver = current != null && current != _last ? current : null;
    _last = current;
    return deliver;
  }

  void reset() {
    _initialized = false;
    _last = null;
  }
}

abstract interface class AppleAdminNotificationSink {
  Future<bool> requestAuthorization();

  Future<void> deliver(AppleAdminNotificationEvent event);
}

final class MethodChannelAppleAdminNotificationSink
    implements AppleAdminNotificationSink {
  const MethodChannelAppleAdminNotificationSink([
    this._channel = const MethodChannel(channelName),
  ]);

  static const channelName = 'io.rw0.mesh.admin/notifications-v1';
  final MethodChannel _channel;

  bool get _supported =>
      defaultTargetPlatform == TargetPlatform.iOS ||
      defaultTargetPlatform == TargetPlatform.macOS;

  @override
  Future<bool> requestAuthorization() async {
    if (!_supported) return false;
    try {
      return await _channel.invokeMethod<bool>('requestAuthorization') ?? false;
    } on PlatformException {
      return false;
    } on MissingPluginException {
      return false;
    }
  }

  @override
  Future<void> deliver(AppleAdminNotificationEvent event) async {
    if (!_supported) return;
    await _channel.invokeMethod<void>('deliver', <String, Object>{
      'event': event.code,
    });
  }
}
