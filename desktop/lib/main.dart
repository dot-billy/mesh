import 'dart:async';

import 'package:flutter/material.dart';
import 'package:mesh_desktop/app/app.dart';
import 'package:mesh_desktop/integration/mesh_app_controller.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  final controller = MeshAppController();
  runApp(MeshDesktopApp(viewModel: controller, callbacks: controller));
  unawaited(controller.initialize());
}
