import 'package:flutter/material.dart';

abstract final class MeshTheme {
  static const Color seed = Color(0xff77df45);

  static ThemeData light(TargetPlatform platform) {
    return _theme(Brightness.light, platform);
  }

  static ThemeData dark(TargetPlatform platform) {
    return _theme(Brightness.dark, platform);
  }

  static ThemeData _theme(Brightness brightness, TargetPlatform platform) {
    final scheme = ColorScheme.fromSeed(
      seedColor: seed,
      brightness: brightness,
      dynamicSchemeVariant: DynamicSchemeVariant.fidelity,
    );
    final windows = platform == TargetPlatform.windows;
    return ThemeData(
      useMaterial3: true,
      brightness: brightness,
      colorScheme: scheme,
      visualDensity: windows ? VisualDensity.standard : VisualDensity.compact,
      fontFamily: windows ? 'Segoe UI' : null,
      fontFamilyFallback: windows
          ? const ['Arial']
          : const ['Cantarell', 'Noto Sans', 'Liberation Sans'],
      scaffoldBackgroundColor: scheme.surface,
      cardTheme: CardThemeData(
        elevation: 0,
        margin: EdgeInsets.zero,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: BorderSide(color: scheme.outlineVariant),
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        border: OutlineInputBorder(borderRadius: BorderRadius.circular(8)),
      ),
      navigationRailTheme: NavigationRailThemeData(
        backgroundColor: scheme.surfaceContainerLow,
        indicatorColor: scheme.secondaryContainer,
        useIndicator: true,
      ),
      dialogTheme: DialogThemeData(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      ),
      snackBarTheme: SnackBarThemeData(
        behavior: SnackBarBehavior.floating,
        showCloseIcon: true,
      ),
      focusColor: scheme.primary.withValues(alpha: 0.18),
    );
  }
}

abstract final class MeshWindowMetrics {
  static const Size defaultSize = Size(1280, 800);
  static const Size minimumSize = Size(900, 600);
  static const double extendedRailBreakpoint = 1100;
  static const double inspectorBreakpoint = 1320;
  static const double contentPadding = 24;
}
