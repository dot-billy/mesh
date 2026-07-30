import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  private var managedConfigurationChannel: FlutterMethodChannel?
  private var notificationChannel: FlutterMethodChannel?
  private var custodyEvents: MacCustodyEvents?
  private var adminMenu: MacAdminMenu?

  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)
    self.title = "Mesh Admin"
    self.minSize = NSSize(width: 900, height: 600)
    self.setFrameAutosaveName("MeshAdminMainWindow")

    RegisterGeneratedPlugins(registry: flutterViewController)
    let managedChannel = FlutterMethodChannel(
      name: "io.rw0.mesh.admin/managed-configuration-v1",
      binaryMessenger: flutterViewController.engine.binaryMessenger
    )
    managedChannel.setMethodCallHandler { call, result in
      guard call.method == "readManagedConfiguration", call.arguments == nil else {
        result(FlutterMethodNotImplemented)
        return
      }
      do {
        result(try AppleManagedConfigurationReader.read())
      } catch {
        result(
          FlutterError(
            code: "invalid-managed-configuration",
            message: "The managed application configuration is invalid.",
            details: nil
          )
        )
      }
    }
    managedConfigurationChannel = managedChannel
    let notifications = FlutterMethodChannel(
      name: AppleAdminNotifications.channelName,
      binaryMessenger: flutterViewController.engine.binaryMessenger
    )
    notifications.setMethodCallHandler(AppleAdminNotifications.handle)
    notificationChannel = notifications
    custodyEvents = MacCustodyEvents(
      binaryMessenger: flutterViewController.engine.binaryMessenger,
      window: self
    )
    let menu = MacAdminMenu(
      binaryMessenger: flutterViewController.engine.binaryMessenger
    )
    menu.install(in: NSApp.mainMenu)
    adminMenu = menu
    MeshAdminLog.record(.windowReady)

    super.awakeFromNib()
  }
}
