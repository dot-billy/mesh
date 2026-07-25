import Foundation
import OSLog

enum MeshAdminLogEvent: String, CaseIterable {
  case applicationStarted = "application-started"
  case applicationTerminating = "application-terminating"
  case windowReady = "window-ready"
  case protectedDataUnavailable = "protected-data-unavailable"
  case privacyShieldCovered = "privacy-shield-covered"
  case privacyShieldRevealed = "privacy-shield-revealed"
  case expiringCopyCompleted = "expiring-copy-completed"
  case expiringCopyRejected = "expiring-copy-rejected"
}

enum MeshAdminLog {
  private static let logger = Logger(
    subsystem: Bundle.main.bundleIdentifier ?? "io.rw0.mesh.admin",
    category: "lifecycle"
  )

  static var reviewedEventCodes: [String] {
    MeshAdminLogEvent.allCases.map(\.rawValue)
  }

  static func record(_ event: MeshAdminLogEvent) {
    // Every message is a fixed reviewed code. This API has no parameter for
    // origins, identities, errors, credentials, configuration, or user data.
    switch event {
    case .applicationStarted:
      logger.notice("application-started")
    case .applicationTerminating:
      logger.notice("application-terminating")
    case .windowReady:
      logger.notice("window-ready")
    case .protectedDataUnavailable:
      logger.notice("protected-data-unavailable")
    case .privacyShieldCovered:
      logger.notice("privacy-shield-covered")
    case .privacyShieldRevealed:
      logger.notice("privacy-shield-revealed")
    case .expiringCopyCompleted:
      logger.notice("expiring-copy-completed")
    case .expiringCopyRejected:
      logger.error("expiring-copy-rejected")
    }
  }
}
