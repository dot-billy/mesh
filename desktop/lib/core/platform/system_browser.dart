import 'dart:io';

import 'package:url_launcher/url_launcher.dart';

abstract interface class SystemBrowserLauncher {
  Future<void> open(Uri uri);
}

typedef BrowserLaunchDelegate = Future<bool> Function(Uri uri);

final class UrlLauncherSystemBrowser implements SystemBrowserLauncher {
  UrlLauncherSystemBrowser({BrowserLaunchDelegate? launch})
    : _launch =
          launch ??
          ((uri) => launchUrl(uri, mode: LaunchMode.externalApplication));

  final BrowserLaunchDelegate _launch;

  @override
  Future<void> open(Uri uri) async {
    final secure = uri.scheme == 'https';
    final loopbackDevelopment =
        uri.scheme == 'http' && _isLoopbackHost(uri.host);
    if ((!secure && !loopbackDevelopment) ||
        uri.host.isEmpty ||
        uri.userInfo.isNotEmpty ||
        uri.hasFragment) {
      throw const BrowserLaunchException(
        'Browser URL must use HTTPS, except for an explicit loopback development origin.',
      );
    }
    if (!await _launch(uri)) {
      throw const BrowserLaunchException(
        'The system browser could not be opened.',
      );
    }
  }
}

bool _isLoopbackHost(String host) {
  if (host.toLowerCase() == 'localhost') return true;
  return InternetAddress.tryParse(host)?.isLoopback ?? false;
}

final class BrowserLaunchException implements Exception {
  const BrowserLaunchException(this.message);

  final String message;

  @override
  String toString() => 'BrowserLaunchException: $message';
}
