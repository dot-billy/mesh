import FlutterMacOS
import UserNotifications

enum AppleAdminNotificationEvent: String, CaseIterable {
  case fleetWarning = "fleet-warning"
  case fleetCritical = "fleet-critical"

  var content: UNMutableNotificationContent {
    let content = UNMutableNotificationContent()
    switch self {
    case .fleetWarning:
      content.title = "Mesh fleet needs attention"
      content.body = "Open Mesh Admin to review fresh authoritative evidence."
    case .fleetCritical:
      content.title = "Mesh fleet needs urgent attention"
      content.body = "Open Mesh Admin to review fresh authoritative evidence."
    }
    content.sound = .default
    return content
  }
}

final class AppleAdminNotifications {
  static let channelName = "io.rw0.mesh.admin/notifications-v1"

  static func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    let center = UNUserNotificationCenter.current()
    switch call.method {
    case "requestAuthorization":
      guard call.arguments == nil else {
        result(FlutterMethodNotImplemented)
        return
      }
      center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
        result(granted)
      }
    case "deliver":
      guard
        let arguments = call.arguments as? [String: Any],
        arguments.count == 1,
        let rawEvent = arguments["event"] as? String,
        let event = AppleAdminNotificationEvent(rawValue: rawEvent)
      else {
        result(FlutterError(code: "invalid-notification", message: "The notification event is invalid.", details: nil))
        return
      }
      let request = UNNotificationRequest(
        identifier: "mesh-admin-\(event.rawValue)",
        content: event.content,
        trigger: nil
      )
      center.add(request) { error in
        result(error == nil ? nil : FlutterError(code: "notification-unavailable", message: "The notification could not be delivered.", details: nil))
      }
    default:
      result(FlutterMethodNotImplemented)
    }
  }
}
