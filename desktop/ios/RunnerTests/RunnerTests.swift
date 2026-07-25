import Flutter
import Security
import UIKit
import XCTest
@testable import Runner

class RunnerTests: XCTestCase {
  func testDeviceOnlyKeychainRoundTripWhenSignedForSimulator() throws {
    let service = "io.rw0.mesh.admin.mobile.tests.device-only-keychain"
    let account = UUID().uuidString
    let value = Data("mesh-keychain-round-trip".utf8)
    let identity: [CFString: Any] = [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: service,
      kSecAttrAccount: account,
      kSecAttrSynchronizable: false,
      kSecUseDataProtectionKeychain: true,
    ]
    defer {
      SecItemDelete(identity as CFDictionary)
    }

    var addition = identity
    addition[kSecAttrAccessible] =
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    addition[kSecValueData] = value
    XCTAssertEqual(
      SecItemAdd(addition as CFDictionary, nil),
      errSecSuccess
    )

    var lookup = identity
    lookup[kSecReturnData] = true
    lookup[kSecMatchLimit] = kSecMatchLimitOne
    var result: CFTypeRef?
    XCTAssertEqual(
      SecItemCopyMatching(lookup as CFDictionary, &result),
      errSecSuccess
    )
    XCTAssertEqual(result as? Data, value)

    XCTAssertEqual(
      SecItemDelete(identity as CFDictionary),
      errSecSuccess
    )
    result = nil
    XCTAssertEqual(
      SecItemCopyMatching(lookup as CFDictionary, &result),
      errSecItemNotFound
    )
    XCTAssertNil(result)
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

  func testPrivacyShieldCoversAndRestoresTheApplicationWindow() {
    let window = UIWindow(frame: CGRect(x: 0, y: 0, width: 390, height: 844))
    let root = UIViewController()
    window.rootViewController = root
    window.makeKeyAndVisible()
    let originalSubviewCount = window.subviews.count
    let shield = PrivacyShieldController()

    shield.cover(window)

    XCTAssertTrue(shield.isCovering)
    XCTAssertEqual(window.subviews.count, originalSubviewCount + 1)
    XCTAssertEqual(window.subviews.last?.accessibilityLabel, "Mesh Admin content hidden")
    XCTAssertEqual(window.subviews.last?.backgroundColor, UIColor.systemBackground)

    shield.reveal()

    XCTAssertFalse(shield.isCovering)
    XCTAssertEqual(window.subviews.count, originalSubviewCount)
  }

  func testPrivacyShieldCoverIsIdempotent() {
    let window = UIWindow(frame: CGRect(x: 0, y: 0, width: 1024, height: 768))
    let shield = PrivacyShieldController()

    shield.cover(window)
    shield.cover(window)

    XCTAssertTrue(shield.isCovering)
    XCTAssertEqual(
      window.subviews.filter { $0.accessibilityLabel == "Mesh Admin content hidden" }.count,
      1
    )
  }
}
