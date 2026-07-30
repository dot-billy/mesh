import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:mesh_desktop/app/app.dart';
import 'package:mesh_desktop/core/platform/macos_admin_menu.dart';
import 'package:mesh_desktop/integration/mesh_app_controller.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  final controller = MeshAppController();
  final menuCommands = defaultTargetPlatform == TargetPlatform.macOS
      ? MethodChannelMacAdminMenuCommands().commands
      : const Stream<MacAdminMenuCommand>.empty();
  runApp(
    MeshDesktopApp(
      viewModel: controller,
      callbacks: controller,
      menuCommands: menuCommands,
    ),
  );
  unawaited(controller.initialize());
}
