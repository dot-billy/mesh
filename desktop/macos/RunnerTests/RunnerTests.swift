import Cocoa
import FlutterMacOS
import Security
import XCTest
@testable import Mesh_Admin

class RunnerTests: XCTestCase {
  func testMacCustodyEventsMapOnlyLockSleepHideCloseAndTermination() {
    XCTAssertEqual(
      MacCustodyEvents.method(for: MacCustodyEvents.screenLocked),
      "protectedDataUnavailable"
    )
    XCTAssertEqual(
      MacCustodyEvents.method(for: NSWorkspace.screensDidSleepNotification),
      "protectedDataUnavailable"
    )
    XCTAssertEqual(
      MacCustodyEvents.method(for: NSWorkspace.willSleepNotification),
      "protectedDataUnavailable"
    )
    XCTAssertEqual(
      MacCustodyEvents.method(for: NSApplication.didHideNotification),
      "protectedDataUnavailable"
    )
    XCTAssertEqual(
      MacCustodyEvents.method(for: NSWindow.willCloseNotification),
      "processTerminating"
    )
    XCTAssertEqual(
      MacCustodyEvents.method(for: NSApplication.willTerminateNotification),
      "processTerminating"
    )
    XCTAssertNil(
      MacCustodyEvents.method(for: Notification.Name("server-selected-event"))
    )
  }

  func testMacAdminMenuEmitsOnlyReviewedDataFreeCommands() {
    XCTAssertEqual(
      MacAdminMenu.command(for: #selector(MacAdminMenu.refresh(_:))),
      "refresh"
    )
    XCTAssertEqual(
      MacAdminMenu.command(for: #selector(MacAdminMenu.showPreferences(_:))),
      "preferences"
    )
    XCTAssertNil(
      MacAdminMenu.command(for: Selector(("serverSelectedCommand:")))
    )
    let url = projectRoot.appendingPathComponent("Runner/MacAdminMenu.swift")
    let source = try? String(contentsOf: url, encoding: .utf8)
    XCTAssertTrue(source?.contains("arguments: nil") == true)
  }

  func testMacAdminMenuInstallsNativePreferencesAndRefreshActions() throws {
    let mainMenu = NSMenu(title: "Main Menu")
    let application = NSMenuItem(title: "Mesh Admin", action: nil, keyEquivalent: "")
    let applicationMenu = NSMenu(title: "Mesh Admin")
    let preferences = NSMenuItem(
      title: "Preferences…",
      action: nil,
      keyEquivalent: ""
    )
    applicationMenu.addItem(preferences)
    application.submenu = applicationMenu
    mainMenu.addItem(application)

    let view = NSMenuItem(title: "View", action: nil, keyEquivalent: "")
    let viewMenu = NSMenu(title: "View")
    view.submenu = viewMenu
    mainMenu.addItem(view)

    MacAdminMenu.install(in: mainMenu, target: self)

    XCTAssertEqual(
      preferences.action,
      #selector(MacAdminMenu.showPreferences(_:))
    )
    XCTAssertEqual(preferences.keyEquivalent, ",")
    XCTAssertEqual(preferences.keyEquivalentModifierMask, [.command])
    let refresh = try XCTUnwrap(
      viewMenu.items.first(where: { $0.title == "Refresh" })
    )
    XCTAssertEqual(refresh.action, #selector(MacAdminMenu.refresh(_:)))
    XCTAssertEqual(refresh.keyEquivalent, "r")
    XCTAssertEqual(refresh.keyEquivalentModifierMask, [.command])
    XCTAssertTrue(viewMenu.items.dropFirst().first?.isSeparatorItem == true)
  }

  func testNotificationsContainOnlyReviewedFixedContent() {
    XCTAssertEqual(
      AppleAdminNotificationEvent.allCases.map(\.rawValue),
      ["fleet-warning", "fleet-critical"]
    )
    XCTAssertEqual(
      AppleAdminNotificationEvent.fleetWarning.content.title,
      "Mesh fleet needs attention"
    )
    XCTAssertEqual(
      AppleAdminNotificationEvent.fleetCritical.content.title,
      "Mesh fleet needs urgent attention"
    )
    for event in AppleAdminNotificationEvent.allCases {
      XCTAssertEqual(
        event.content.body,
        "Open Mesh Admin to review fresh authoritative evidence."
      )
      XCTAssertNil(AppleAdminNotificationEvent(rawValue: "server-supplied-text"))
    }
  }

  func testManagedConfigurationAcceptsOnlyReviewedNonSecretPolicy() throws {
    let policy: [String: Any] = [
      "MeshManagedSchema": "mesh-apple-managed-configuration-v1",
      "ControlPlaneOrigin": "https://mesh.example.com",
      "AllowOriginChanges": false,
      "ReleaseChannel": "stable",
      "UpdateRing": "pilot",
      "ShowLocalStatus": false,
      "NotificationsEnabled": true,
    ]

    let validated = try AppleManagedConfigurationReader.validate(policy)

    XCTAssertEqual(validated["ControlPlaneOrigin"] as? String, "https://mesh.example.com")
    XCTAssertEqual(validated["AllowOriginChanges"] as? Bool, false)
    XCTAssertEqual(Set(validated.keys), AppleManagedConfigurationReader.allowedKeys)
  }

  func testManagedConfigurationRejectsSecretsAndMalformedPolicy() {
    let invalid: [[String: Any]] = [
      [
        "MeshManagedSchema": "mesh-apple-managed-configuration-v1",
        "EnrollmentToken": "must-never-cross",
      ],
      [
        "MeshManagedSchema": "mesh-apple-managed-configuration-v1",
        "ControlPlaneOrigin": "http://mesh.example.com",
      ],
      [
        "MeshManagedSchema": "mesh-apple-managed-configuration-v1",
        "AllowOriginChanges": false,
      ],
      [
        "MeshManagedSchema": "mesh-apple-managed-configuration-v1",
        "NotificationsEnabled": "true",
      ],
    ]

    for policy in invalid {
      XCTAssertThrowsError(try AppleManagedConfigurationReader.validate(policy))
    }
  }

  func testOrdinaryLocalDefaultsCannotImpersonateManagedPolicy() throws {
    let representation: [String: Any] = [
      "MeshManagedSchema": "mesh-apple-managed-configuration-v1",
      "ControlPlaneOrigin": "https://local.example.com",
      "OrdinaryLocalPreference": true,
    ]

    XCTAssertTrue(
      AppleManagedConfigurationReader.managedValues(
        representation,
        isForced: { _ in false }
      ).isEmpty
    )

    let forced = AppleManagedConfigurationReader.managedValues(
      representation,
      isForced: { key in
        key == "MeshManagedSchema" || key == "ControlPlaneOrigin"
      }
    )
    XCTAssertEqual(
      try AppleManagedConfigurationReader.validate(forced)[
        "ControlPlaneOrigin"
      ] as? String,
      "https://local.example.com"
    )

    let unknownForced = AppleManagedConfigurationReader.managedValues(
      representation,
      isForced: { _ in true }
    )
    XCTAssertThrowsError(
      try AppleManagedConfigurationReader.validate(unknownForced)
    )
  }

  func testUnifiedLogBoundaryContainsOnlyReviewedFixedCodes() {
    XCTAssertEqual(
      MeshAdminLog.reviewedEventCodes,
      [
        "application-started",
        "application-terminating",
        "window-ready",
        "protected-data-unavailable",
        "privacy-shield-covered",
        "privacy-shield-revealed",
        "expiring-copy-completed",
        "expiring-copy-rejected",
      ]
    )
  }

  private var projectRoot: URL {
    URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
  }

  func testReleaseEntitlementsStayNarrow() throws {
    let url = projectRoot.appendingPathComponent("Runner/Release.entitlements")
    let data = try Data(contentsOf: url)
    let object = try XCTUnwrap(
      PropertyListSerialization.propertyList(from: data, format: nil)
        as? [String: Any]
    )

    XCTAssertEqual(
      Set(object.keys),
      [
        "com.apple.security.app-sandbox",
        "com.apple.security.network.client",
        "keychain-access-groups",
      ]
    )
    XCTAssertEqual(object["com.apple.security.app-sandbox"] as? Bool, true)
    XCTAssertEqual(object["com.apple.security.network.client"] as? Bool, true)
    XCTAssertEqual(
      object["keychain-access-groups"] as? [String],
      ["Y3P5UNNG23.io.rw0.mesh.admin"]
    )
    XCTAssertNil(object["com.apple.security.network.server"])
    XCTAssertNil(object["com.apple.security.cs.allow-jit"])
  }

  func testWindowContractKeepsTheOperatorConsoleBounded() throws {
    let url = projectRoot.appendingPathComponent("Runner/MainFlutterWindow.swift")
    let source = try String(contentsOf: url, encoding: .utf8)

    XCTAssertTrue(source.contains("NSSize(width: 900, height: 600)"))
    XCTAssertTrue(source.contains("self.title = \"Mesh Admin\""))
    XCTAssertTrue(source.contains("setFrameAutosaveName(\"MeshAdminMainWindow\")"))
    XCTAssertFalse(source.contains("/opt/mesh"))
    XCTAssertFalse(source.contains("/private/var/db/mesh"))

    let delegateURL = projectRoot.appendingPathComponent(
      "Runner/AppDelegate.swift"
    )
    let delegate = try String(contentsOf: delegateURL, encoding: .utf8)
    XCTAssertTrue(
      delegate.contains(
        "applicationShouldTerminateAfterLastWindowClosed"
      )
    )
    XCTAssertTrue(delegate.contains("return true"))
    XCTAssertFalse(delegate.contains("oneTimeSecret"))
    XCTAssertFalse(delegate.contains("session_cookie"))
    XCTAssertFalse(delegate.contains("csrf_cookie"))
  }

  func testSessionKeychainRoundTripIsIsolatedAndOriginScoped() throws {
    let originalSearchList = try keychainSearchList()
    defer {
      XCTAssertEqual(SecKeychainSetSearchList(originalSearchList), errSecSuccess)
    }
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
      "mesh-admin-keychain-test-\(UUID().uuidString)",
      isDirectory: true
    )
    try FileManager.default.createDirectory(
      at: directory,
      withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700]
    )
    let keychainPath = directory.appendingPathComponent(
      "session.keychain-db"
    ).path
    var created: SecKeychain?
    let createStatus = keychainPath.withCString { pathPointer in
      "".withCString { passwordPointer in
        SecKeychainCreate(
          pathPointer,
          0,
          passwordPointer,
          false,
          nil,
          &created
        )
      }
    }
    XCTAssertEqual(createStatus, errSecSuccess)
    let keychain = try XCTUnwrap(created)
    defer {
      XCTAssertEqual(SecKeychainDelete(keychain), errSecSuccess)
      try? FileManager.default.removeItem(at: directory)
    }
    XCTAssertTrue(CFEqual(originalSearchList, try keychainSearchList()))
    try FileManager.default.setAttributes(
      [.posixPermissions: 0o600],
      ofItemAtPath: keychainPath
    )

    let attributes = try FileManager.default.attributesOfItem(atPath: keychainPath)
    XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    let values = try URL(fileURLWithPath: keychainPath).resourceValues(
      forKeys: [.isRegularFileKey, .isSymbolicLinkKey]
    )
    XCTAssertEqual(values.isRegularFile, true)
    XCTAssertEqual(values.isSymbolicLink, false)

    let service = "io.rw0.mesh.admin.session.v1.test.\(UUID().uuidString)"
    let productionOrigin = "https://mesh.example"
    let differentOrigin = "https://mesh.example:8443"
    let secret = Data(
      #"{"schema":"mesh-desktop-session-v1","cookies":"test-only"}"#.utf8
    )
    var item: SecKeychainItem?
    let addStatus = service.withCString { servicePointer in
      productionOrigin.withCString { accountPointer in
        secret.withUnsafeBytes { secretBytes in
          SecKeychainAddGenericPassword(
            keychain,
            UInt32(service.utf8.count),
            servicePointer,
            UInt32(productionOrigin.utf8.count),
            accountPointer,
            UInt32(secretBytes.count),
            secretBytes.baseAddress!,
            &item
          )
        }
      }
    }
    XCTAssertEqual(addStatus, errSecSuccess)
    let addedItem = try XCTUnwrap(item)
    defer {
      XCTAssertEqual(SecKeychainItemDelete(addedItem), errSecSuccess)
    }

    XCTAssertEqual(
      try readPassword(
        keychain: keychain,
        service: service,
        account: productionOrigin
      ),
      secret
    )
    XCTAssertNil(
      try readPassword(
        keychain: keychain,
        service: service,
        account: differentOrigin
      )
    )
  }

  private func keychainSearchList() throws -> CFArray {
    var list: CFArray?
    XCTAssertEqual(SecKeychainCopySearchList(&list), errSecSuccess)
    return try XCTUnwrap(list)
  }

  private func readPassword(
    keychain: SecKeychain,
    service: String,
    account: String
  ) throws -> Data? {
    var length: UInt32 = 0
    var bytes: UnsafeMutableRawPointer?
    let status = service.withCString { servicePointer in
      account.withCString { accountPointer in
        SecKeychainFindGenericPassword(
          keychain,
          UInt32(service.utf8.count),
          servicePointer,
          UInt32(account.utf8.count),
          accountPointer,
          &length,
          &bytes,
          nil
        )
      }
    }
    if status == errSecItemNotFound {
      return nil
    }
    XCTAssertEqual(status, errSecSuccess)
    let contents = try XCTUnwrap(bytes)
    defer {
      XCTAssertEqual(SecKeychainItemFreeContent(nil, contents), errSecSuccess)
    }
    return Data(bytes: contents, count: Int(length))
  }
}
