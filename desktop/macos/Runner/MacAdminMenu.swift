import Cocoa
import FlutterMacOS

final class MacAdminMenu: NSObject {
  static let channelName = "io.rw0.mesh.admin/macos-menu-v1"

  private let channel: FlutterMethodChannel

  init(binaryMessenger: FlutterBinaryMessenger) {
    channel = FlutterMethodChannel(
      name: Self.channelName,
      binaryMessenger: binaryMessenger
    )
    super.init()
  }

  func install(in mainMenu: NSMenu?) {
    Self.install(in: mainMenu, target: self)
  }

  static func install(in mainMenu: NSMenu?, target: AnyObject) {
    guard let mainMenu else {
      return
    }
    if let applicationMenu = mainMenu.items.first?.submenu,
      let preferences = applicationMenu.items.first(
        where: { $0.title.hasPrefix("Preferences") }
      )
    {
      preferences.target = target
      preferences.action = #selector(showPreferences(_:))
      preferences.keyEquivalent = ","
      preferences.keyEquivalentModifierMask = [.command]
    }
    guard
      let viewMenu = mainMenu.items.first(
        where: { $0.title == "View" }
      )?.submenu
    else {
      return
    }
    let refresh =
      viewMenu.items.first(where: { $0.title == "Refresh" })
      ?? NSMenuItem(
        title: "Refresh",
        action: #selector(refresh(_:)),
        keyEquivalent: "r"
      )
    refresh.target = target
    refresh.action = #selector(refresh(_:))
    refresh.keyEquivalent = "r"
    refresh.keyEquivalentModifierMask = [.command]
    if refresh.menu == nil {
      viewMenu.insertItem(refresh, at: 0)
      viewMenu.insertItem(.separator(), at: 1)
    }
  }

  static func command(for action: Selector) -> String? {
    switch action {
    case #selector(refresh(_:)):
      return "refresh"
    case #selector(showPreferences(_:)):
      return "preferences"
    default:
      return nil
    }
  }

  @objc func refresh(_ sender: Any?) {
    invoke(#selector(refresh(_:)))
  }

  @objc func showPreferences(_ sender: Any?) {
    invoke(#selector(showPreferences(_:)))
  }

  private func invoke(_ action: Selector) {
    guard let command = Self.command(for: action) else {
      return
    }
    channel.invokeMethod(command, arguments: nil)
  }
}
