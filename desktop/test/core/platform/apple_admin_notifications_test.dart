import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_desktop/core/platform/apple_admin_notifications.dart';

void main() {
  test('notification transition baselines and emits only severity changes', () {
    final transition = AppleAdminNotificationTransition();

    expect(transition.observe(hasCritical: false, hasWarning: true), isNull);
    expect(transition.observe(hasCritical: false, hasWarning: true), isNull);
    expect(
      transition.observe(hasCritical: true, hasWarning: true),
      AppleAdminNotificationEvent.fleetCritical,
    );
    expect(transition.observe(hasCritical: true, hasWarning: false), isNull);
    expect(transition.observe(hasCritical: false, hasWarning: false), isNull);
    expect(
      transition.observe(hasCritical: false, hasWarning: true),
      AppleAdminNotificationEvent.fleetWarning,
    );
  });

  test('reset requires a new non-notifying baseline', () {
    final transition = AppleAdminNotificationTransition()
      ..observe(hasCritical: false, hasWarning: false)
      ..observe(hasCritical: true, hasWarning: false)
      ..reset();

    expect(transition.observe(hasCritical: true, hasWarning: false), isNull);
  });
}
