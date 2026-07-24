import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/core/platform/system_browser.dart';

void main() {
  test('launches a valid authorization URL in the delegated browser', () async {
    Uri? opened;
    final launcher = UrlLauncherSystemBrowser(
      launch: (uri) async {
        opened = uri;
        return true;
      },
    );
    final target = Uri.parse('https://id.example/authorize?state=value');

    await launcher.open(target);

    expect(opened, target);
  });

  test('allows explicit loopback development URLs', () async {
    final opened = <Uri>[];
    final launcher = UrlLauncherSystemBrowser(
      launch: (uri) async {
        opened.add(uri);
        return true;
      },
    );

    await launcher.open(
      Uri.parse('http://localhost:8443/?mesh_desktop_request=desktop_example'),
    );
    await launcher.open(Uri.parse('http://[::1]:8443/docs.html'));

    expect(opened, hasLength(2));
  });

  test('rejects unsafe URLs before invoking the platform', () async {
    var calls = 0;
    final launcher = UrlLauncherSystemBrowser(
      launch: (uri) async {
        calls += 1;
        return true;
      },
    );

    await expectLater(
      launcher.open(Uri.parse('http://id.example/authorize')),
      throwsA(isA<BrowserLaunchException>()),
    );
    await expectLater(
      launcher.open(Uri.parse('http://192.0.2.10/authorize')),
      throwsA(isA<BrowserLaunchException>()),
    );
    expect(calls, 0);
  });

  test('does not disclose the URL when the platform launch fails', () async {
    final launcher = UrlLauncherSystemBrowser(launch: (uri) async => false);

    final error = await _captureFailure(
      launcher.open(
        Uri.parse('https://id.example/authorize?state=secret-state'),
      ),
    );

    expect(error.toString(), isNot(contains('secret-state')));
  });
}

Future<Object> _captureFailure(Future<void> future) async {
  try {
    await future;
  } catch (error) {
    return error;
  }
  throw StateError('Expected operation to fail.');
}
