import CoreFoundation
import Foundation

enum AppleManagedConfigurationError: Error {
  case invalid
}

enum AppleManagedConfigurationReader {
  static let schema = "mesh-apple-managed-configuration-v1"
  static let allowedKeys: Set<String> = [
    "MeshManagedSchema",
    "ControlPlaneOrigin",
    "AllowOriginChanges",
    "ReleaseChannel",
    "UpdateRing",
    "ShowLocalStatus",
    "NotificationsEnabled",
  ]

  static func read(
    defaults: UserDefaults = .standard,
    bundleIdentifier: String? = Bundle.main.bundleIdentifier
  ) throws -> [String: Any]? {
    guard let bundleIdentifier else {
      throw AppleManagedConfigurationError.invalid
    }
    let raw = managedValues(
      defaults.dictionaryRepresentation()
    ) { key in
      defaults.objectIsForced(forKey: key, inDomain: bundleIdentifier)
    }
    if raw.isEmpty {
      return nil
    }
    return try validate(raw)
  }

  static func managedValues(
    _ representation: [String: Any],
    isForced: (String) -> Bool
  ) -> [String: Any] {
    representation.filter { key, _ in isForced(key) }
  }

  static func validate(_ raw: [String: Any]) throws -> [String: Any] {
    guard
      raw.count <= allowedKeys.count,
      Set(raw.keys).isSubset(of: allowedKeys),
      raw["MeshManagedSchema"] as? String == schema
    else {
      throw AppleManagedConfigurationError.invalid
    }
    if let origin = raw["ControlPlaneOrigin"] {
      guard let value = origin as? String, validOrigin(value) else {
        throw AppleManagedConfigurationError.invalid
      }
    }
    for key in ["ReleaseChannel", "UpdateRing"] {
      if let value = raw[key] {
        guard let name = value as? String, validPolicyName(name) else {
          throw AppleManagedConfigurationError.invalid
        }
      }
    }
    for key in [
      "AllowOriginChanges",
      "ShowLocalStatus",
      "NotificationsEnabled",
    ] {
      if let value = raw[key], !isBoolean(value) {
        throw AppleManagedConfigurationError.invalid
      }
    }
    if raw["AllowOriginChanges"] as? Bool == false,
      raw["ControlPlaneOrigin"] == nil
    {
      throw AppleManagedConfigurationError.invalid
    }
    return raw
  }

  private static func validOrigin(_ value: String) -> Bool {
    guard
      !value.isEmpty,
      value.utf8.count <= 2_048,
      value.trimmingCharacters(in: .whitespacesAndNewlines) == value,
      let components = URLComponents(string: value),
      components.scheme == "https",
      components.host?.isEmpty == false,
      components.user == nil,
      components.password == nil,
      components.query == nil,
      components.fragment == nil,
      components.path.isEmpty || components.path == "/"
    else {
      return false
    }
    return true
  }

  private static func validPolicyName(_ value: String) -> Bool {
    value.range(
      of: #"^[a-z][a-z0-9-]{0,31}$"#,
      options: .regularExpression
    ) != nil
  }

  private static func isBoolean(_ value: Any) -> Bool {
    CFGetTypeID(value as CFTypeRef) == CFBooleanGetTypeID()
  }
}
