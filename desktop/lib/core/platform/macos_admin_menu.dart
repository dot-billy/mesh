import 'dart:async';

import 'package:flutter/services.dart';

enum MacAdminMenuCommand { refresh, preferences }

final class MethodChannelMacAdminMenuCommands {
  MethodChannelMacAdminMenuCommands({
    this._channel = const MethodChannel(channelName),
  }) {
    _channel.setMethodCallHandler(_handle);
  }

  static const channelName = 'io.rw0.mesh.admin/macos-menu-v1';

  final MethodChannel _channel;
  final StreamController<MacAdminMenuCommand> _commands =
      StreamController<MacAdminMenuCommand>.broadcast(sync: true);

  Stream<MacAdminMenuCommand> get commands => _commands.stream;

  Future<void> _handle(MethodCall call) async {
    if (call.arguments != null) return;
    final command = switch (call.method) {
      'refresh' => MacAdminMenuCommand.refresh,
      'preferences' => MacAdminMenuCommand.preferences,
      _ => null,
    };
    if (command != null && !_commands.isClosed) {
      _commands.add(command);
    }
  }
}
