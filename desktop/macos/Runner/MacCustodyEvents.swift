import Cocoa
import FlutterMacOS

final class MacCustodyEvents {
  static let channelName = "io.rw0.mesh.admin.mobile/security-v1"
  static let screenLocked = Notification.Name("com.apple.screenIsLocked")

  private let channel: FlutterMethodChannel
  private var distributedObservers: [NSObjectProtocol] = []
  private var workspaceObservers: [NSObjectProtocol] = []
  private var applicationObservers: [NSObjectProtocol] = []

  init(binaryMessenger: FlutterBinaryMessenger, window: NSWindow) {
    channel = FlutterMethodChannel(
      name: Self.channelName,
      binaryMessenger: binaryMessenger
    )
    distributedObservers.append(
      DistributedNotificationCenter.default().addObserver(
        forName: Self.screenLocked,
        object: nil,
        queue: .main
      ) { [weak self] notification in
        self?.handle(notification.name)
      }
    )
    let workspace = NSWorkspace.shared.notificationCenter
    for name in [
      NSWorkspace.screensDidSleepNotification,
      NSWorkspace.willSleepNotification,
    ] {
      workspaceObservers.append(
        workspace.addObserver(
          forName: name,
          object: nil,
          queue: .main
        ) { [weak self] notification in
          self?.handle(notification.name)
        }
      )
    }
    for name in [
      NSApplication.didHideNotification,
      NSApplication.willTerminateNotification,
    ] {
      applicationObservers.append(
        NotificationCenter.default.addObserver(
          forName: name,
          object: nil,
          queue: .main
        ) { [weak self] notification in
          self?.handle(notification.name)
        }
      )
    }
    applicationObservers.append(
      NotificationCenter.default.addObserver(
        forName: NSWindow.willCloseNotification,
        object: window,
        queue: .main
      ) { [weak self] notification in
        self?.handle(notification.name)
      }
    )
  }

  static func method(for name: Notification.Name) -> String? {
    switch name {
    case screenLocked,
      NSWorkspace.screensDidSleepNotification,
      NSWorkspace.willSleepNotification,
      NSApplication.didHideNotification:
      return "protectedDataUnavailable"
    case NSApplication.willTerminateNotification,
      NSWindow.willCloseNotification:
      return "processTerminating"
    default:
      return nil
    }
  }

  private func handle(_ name: Notification.Name) {
    guard let method = Self.method(for: name) else {
      return
    }
    MeshAdminLog.record(
      method == "processTerminating"
        ? .applicationTerminating
        : .protectedDataUnavailable
    )
    channel.invokeMethod(method, arguments: nil)
  }

  deinit {
    for observer in distributedObservers {
      DistributedNotificationCenter.default().removeObserver(observer)
    }
    let workspace = NSWorkspace.shared.notificationCenter
    for observer in workspaceObservers {
      workspace.removeObserver(observer)
    }
    for observer in applicationObservers {
      NotificationCenter.default.removeObserver(observer)
    }
  }
}
