import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import '../features/auth/connection_screen.dart';
import '../shared/callbacks/presentation_callbacks.dart';
import '../shared/models/presentation_models.dart';
import '../shared/theme/mesh_theme.dart';
import 'app_shell.dart';

class MeshDesktopApp extends StatelessWidget {
  const MeshDesktopApp({
    required this.viewModel,
    required this.callbacks,
    super.key,
  });

  final ValueListenable<MeshDesktopViewModel> viewModel;
  final MeshPresentationCallbacks callbacks;

  @override
  Widget build(BuildContext context) {
    return ValueListenableBuilder<MeshDesktopViewModel>(
      valueListenable: viewModel,
      builder: (context, model, _) {
        return MaterialApp(
          debugShowCheckedModeBanner: false,
          title: 'Mesh',
          theme: MeshTheme.light(defaultTargetPlatform),
          darkTheme: MeshTheme.dark(defaultTargetPlatform),
          themeMode: model.preferences.themeMode,
          home: model.authenticated
              ? MeshAppShell(model: model, callbacks: callbacks)
              : ConnectionScreen(model: model.connection, callbacks: callbacks),
        );
      },
    );
  }
}
