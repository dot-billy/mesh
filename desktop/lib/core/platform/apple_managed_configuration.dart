import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../connection/connection_profile.dart';

abstract interface class AppleManagedConfigurationSource {
  Future<AppleManagedConfiguration?> load();
}

final class NoAppleManagedConfigurationSource
    implements AppleManagedConfigurationSource {
  const NoAppleManagedConfigurationSource();

  @override
  Future<AppleManagedConfiguration?> load() async => null;
}

final class MethodChannelAppleManagedConfigurationSource
    implements AppleManagedConfigurationSource {
  const MethodChannelAppleManagedConfigurationSource();

  static const channelName = 'io.rw0.mesh.admin/managed-configuration-v1';
  static const _channel = MethodChannel(channelName);

  @override
  Future<AppleManagedConfiguration?> load() async {
    if (defaultTargetPlatform != TargetPlatform.iOS &&
        defaultTargetPlatform != TargetPlatform.macOS) {
      return null;
    }
    final Object? raw;
    try {
      raw = await _channel.invokeMethod<Object?>('readManagedConfiguration');
    } on MissingPluginException {
      throw const AppleManagedConfigurationException(
        'The Apple managed-configuration bridge is unavailable.',
      );
    } on PlatformException {
      throw const AppleManagedConfigurationException(
        'The Apple managed configuration is invalid.',
      );
    }
    if (raw == null) return null;
    return AppleManagedConfiguration.fromPlatformValue(raw);
  }
}

@immutable
final class AppleManagedConfiguration {
  AppleManagedConfiguration({
    required this.controlPlaneOrigin,
    required this.allowOriginChanges,
    required this.releaseChannel,
    required this.updateRing,
    required this.showLocalStatus,
    required this.notificationsEnabled,
  }) {
    if (!allowOriginChanges && controlPlaneOrigin == null) {
      throw const AppleManagedConfigurationException(
        'A locked managed origin is missing.',
      );
    }
  }

  static const schema = 'mesh-apple-managed-configuration-v1';
  static const _keys = <String>{
    'MeshManagedSchema',
    'ControlPlaneOrigin',
    'AllowOriginChanges',
    'ReleaseChannel',
    'UpdateRing',
    'ShowLocalStatus',
    'NotificationsEnabled',
  };
  static final _policyName = RegExp(r'^[a-z][a-z0-9-]{0,31}$');

  final ConnectionProfile? controlPlaneOrigin;
  final bool allowOriginChanges;
  final String? releaseChannel;
  final String? updateRing;
  final bool? showLocalStatus;
  final bool? notificationsEnabled;

  void enforceControlPlaneOrigin(ConnectionProfile profile) {
    if (!allowOriginChanges && profile.origin != controlPlaneOrigin!.origin) {
      throw const FormatException(
        'Your organization locks Mesh Admin to its managed control-plane origin.',
      );
    }
  }

  factory AppleManagedConfiguration.fromPlatformValue(Object value) {
    if (value is! Map<Object?, Object?> ||
        value.length > _keys.length ||
        value.keys.any((key) => key is! String || !_keys.contains(key))) {
      throw const AppleManagedConfigurationException(
        'The Apple managed configuration has unsupported fields.',
      );
    }
    final map = <String, Object?>{
      for (final entry in value.entries) entry.key! as String: entry.value,
    };
    if (map['MeshManagedSchema'] != schema) {
      throw const AppleManagedConfigurationException(
        'The Apple managed configuration schema is invalid.',
      );
    }
    final allowOriginChanges = _optionalBool(
      map,
      'AllowOriginChanges',
      defaultValue: true,
    )!;
    final originValue = _optionalString(map, 'ControlPlaneOrigin');
    ConnectionProfile? origin;
    if (originValue != null) {
      try {
        origin = ConnectionProfile.parse(originValue);
      } on FormatException {
        throw const AppleManagedConfigurationException(
          'The managed control-plane origin is invalid.',
        );
      }
      if (origin.origin.scheme != 'https') {
        throw const AppleManagedConfigurationException(
          'The managed control-plane origin must use HTTPS.',
        );
      }
    }
    return AppleManagedConfiguration(
      controlPlaneOrigin: origin,
      allowOriginChanges: allowOriginChanges,
      releaseChannel: _optionalPolicyName(map, 'ReleaseChannel'),
      updateRing: _optionalPolicyName(map, 'UpdateRing'),
      showLocalStatus: _optionalBool(map, 'ShowLocalStatus'),
      notificationsEnabled: _optionalBool(map, 'NotificationsEnabled'),
    );
  }

  static String? _optionalString(Map<String, Object?> map, String key) {
    final value = map[key];
    if (value == null && !map.containsKey(key)) return null;
    if (value is! String ||
        value.isEmpty ||
        value.length > 2048 ||
        value.trim() != value) {
      throw AppleManagedConfigurationException(
        'The managed $key value is invalid.',
      );
    }
    return value;
  }

  static String? _optionalPolicyName(Map<String, Object?> map, String key) {
    final value = _optionalString(map, key);
    if (value != null && !_policyName.hasMatch(value)) {
      throw AppleManagedConfigurationException(
        'The managed $key value is invalid.',
      );
    }
    return value;
  }

  static bool? _optionalBool(
    Map<String, Object?> map,
    String key, {
    bool? defaultValue,
  }) {
    final value = map[key];
    if (value == null && !map.containsKey(key)) return defaultValue;
    if (value is! bool) {
      throw AppleManagedConfigurationException(
        'The managed $key value is invalid.',
      );
    }
    return value;
  }
}

final class AppleManagedConfigurationException implements Exception {
  const AppleManagedConfigurationException(this.message);

  final String message;

  @override
  String toString() => message;
}
