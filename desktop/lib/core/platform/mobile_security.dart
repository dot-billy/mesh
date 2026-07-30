import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

abstract interface class ProtectedDataEvents {
  void setUnavailableHandler(VoidCallback? handler);

  void dispose();
}

final class MethodChannelProtectedDataEvents implements ProtectedDataEvents {
  MethodChannelProtectedDataEvents({MethodChannel? channel})
    : _channel = channel ?? const MethodChannel(channelName);

  static const String channelName = 'io.rw0.mesh.admin.mobile/security-v1';

  final MethodChannel _channel;
  VoidCallback? _handler;
  bool _registered = false;

  @override
  void setUnavailableHandler(VoidCallback? handler) {
    if (handler == null && !_registered) {
      return;
    }
    _handler = handler;
    _registered = handler != null;
    _channel.setMethodCallHandler(
      handler == null
          ? null
          : (call) async {
              if (call.arguments != null) {
                throw const FormatException(
                  'Mobile security event must not contain data.',
                );
              }
              switch (call.method) {
                case 'protectedDataUnavailable':
                case 'processTerminating':
                  _handler?.call();
                default:
                  throw MissingPluginException(
                    'Unsupported mobile security event.',
                  );
              }
            },
    );
  }

  @override
  void dispose() {
    if (!_registered) {
      return;
    }
    _handler = null;
    _registered = false;
    _channel.setMethodCallHandler(null);
  }
}

abstract interface class SecretClipboard {
  Future<void> copy(String value);
}

final class ExpiringSecretClipboard implements SecretClipboard {
  const ExpiringSecretClipboard();

  static const MethodChannel _channel = MethodChannel(
    MethodChannelProtectedDataEvents.channelName,
  );

  @override
  Future<void> copy(String value) async {
    if (value.isEmpty || value.length > 16_384) {
      throw ArgumentError.value(
        value.length,
        'value',
        'must contain 1 through 16384 characters',
      );
    }
    if (defaultTargetPlatform != TargetPlatform.iOS) {
      await Clipboard.setData(ClipboardData(text: value));
      return;
    }
    try {
      await _channel.invokeMethod<void>('copyExpiringSecret', <String, Object?>{
        'value': value,
      });
    } on MissingPluginException {
      throw StateError(
        'The iOS expiring-pasteboard boundary is unavailable; nothing was copied.',
      );
    }
  }
}
