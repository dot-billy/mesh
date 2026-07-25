import Flutter
import UIKit
import UniformTypeIdentifiers

@main
@objc class AppDelegate: FlutterAppDelegate, FlutterImplicitEngineDelegate {
  static let securityChannelName = "io.rw0.mesh.admin.mobile/security-v1"
  static let managedConfigurationChannelName =
    "io.rw0.mesh.admin/managed-configuration-v1"

  private var securityChannel: FlutterMethodChannel?
  private var managedConfigurationChannel: FlutterMethodChannel?
  private var notificationChannel: FlutterMethodChannel?
  private var protectedDataObserver: NSObjectProtocol?

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    protectedDataObserver = NotificationCenter.default.addObserver(
      forName: UIApplication.protectedDataWillBecomeUnavailableNotification,
      object: application,
      queue: .main
    ) { [weak self] _ in
      MeshAdminLog.record(.protectedDataUnavailable)
      self?.signalDart("protectedDataUnavailable")
    }
    let launched = super.application(
      application,
      didFinishLaunchingWithOptions: launchOptions
    )
    if launched {
      MeshAdminLog.record(.applicationStarted)
    }
    return launched
  }

  func didInitializeImplicitFlutterEngine(_ engineBridge: FlutterImplicitEngineBridge) {
    GeneratedPluginRegistrant.register(with: engineBridge.pluginRegistry)
    let channel = FlutterMethodChannel(
      name: Self.securityChannelName,
      binaryMessenger: engineBridge.applicationRegistrar.messenger()
    )
    channel.setMethodCallHandler { call, result in
      guard call.method == "copyExpiringSecret" else {
        result(FlutterMethodNotImplemented)
        return
      }
      guard
        let arguments = call.arguments as? [String: Any],
        arguments.count == 1,
        let value = arguments["value"] as? String,
        !value.isEmpty,
        value.utf8.count <= 16_384
      else {
        MeshAdminLog.record(.expiringCopyRejected)
        result(
          FlutterError(
            code: "invalid-arguments",
            message: "The bounded copy request was invalid.",
            details: nil
          )
        )
        return
      }
      UIPasteboard.general.setItems(
        [[UTType.utf8PlainText.identifier: value]],
        options: [
          .localOnly: true,
          .expirationDate: Date().addingTimeInterval(120),
        ]
      )
      MeshAdminLog.record(.expiringCopyCompleted)
      result(nil)
    }
    securityChannel = channel
    let managedChannel = FlutterMethodChannel(
      name: Self.managedConfigurationChannelName,
      binaryMessenger: engineBridge.applicationRegistrar.messenger()
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
      binaryMessenger: engineBridge.applicationRegistrar.messenger()
    )
    notifications.setMethodCallHandler(AppleAdminNotifications.handle)
    notificationChannel = notifications
  }

  override func applicationWillTerminate(_ application: UIApplication) {
    MeshAdminLog.record(.applicationTerminating)
    signalDart("processTerminating")
    super.applicationWillTerminate(application)
  }

  deinit {
    if let protectedDataObserver {
      NotificationCenter.default.removeObserver(protectedDataObserver)
    }
  }

  private func signalDart(_ method: String) {
    securityChannel?.invokeMethod(method, arguments: nil)
  }
}
