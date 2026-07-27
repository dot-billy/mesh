import Foundation
import Security

struct TunnelLocalAuthorityState: Equatable {
  let hasPrivateKey: Bool
  let hasCurrentAgentCredential: Bool
  let hasPendingAgentCredential: Bool

  var hasAnyAuthority: Bool {
    hasPrivateKey
      || hasCurrentAgentCredential
      || hasPendingAgentCredential
  }

  var isRecoverableInitialEnrollment: Bool {
    hasPrivateKey
      && hasCurrentAgentCredential
      && !hasPendingAgentCredential
  }
}

final class TunnelHighWaterKeychain: TunnelHighWaterStore {
  static let accessGroupSuffix =
    "io.rw0.mesh.tunnel.mobile.identity"
  static let service = "io.rw0.mesh.tunnel.mobile.identity.v1"
  static let account = "configuration-monotonic-high-water"
  static let runtimeInstanceAccount =
    "runtime-instance-monotonic-high-water"
  private static let identityAccount = "primary"
  private static let privateKeyService =
    "io.rw0.mesh.tunnel.mobile.identity.v1"
  private static let currentAgentService =
    "io.rw0.mesh.tunnel.mobile.agent.v1"
  private static let pendingAgentService =
    "io.rw0.mesh.tunnel.mobile.agent.pending.v1"
  private static let initialEnrollmentIntentService =
    "io.rw0.mesh.tunnel.mobile.initial-enrollment-intent.v1"
  private static let startAuthorizationService =
    "io.rw0.mesh.tunnel.mobile.start-authorization.v1"

  func load() throws -> UInt64 {
    var query = try Self.baseQuery()
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound {
      return 0
    }
    guard status == errSecSuccess,
      let data = result as? Data,
      data.count == MemoryLayout<UInt64>.size
    else {
      if status == errSecSuccess {
        throw TunnelKeychainError.invalidValue
      }
      throw TunnelKeychainError.unexpectedStatus(status)
    }
    return data.withUnsafeBytes {
      UInt64(bigEndian: $0.loadUnaligned(as: UInt64.self))
    }
  }

  func commit(_ value: UInt64) throws {
    let previous = try load()
    guard value > 0, value >= previous else {
      throw TunnelKeychainError.rollbackOrReplay
    }
    var bigEndian = value.bigEndian
    let data = Data(
      bytes: &bigEndian,
      count: MemoryLayout<UInt64>.size
    )
    let attributes: [String: Any] = [
      kSecValueData as String: data,
      kSecAttrAccessible as String:
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ]
    let updateStatus = SecItemUpdate(
      try Self.baseQuery() as CFDictionary,
      attributes as CFDictionary
    )
    if updateStatus == errSecItemNotFound {
      var add = try Self.baseQuery()
      for (key, value) in attributes {
        add[key] = value
      }
      let addStatus = SecItemAdd(add as CFDictionary, nil)
      guard addStatus == errSecSuccess else {
        throw TunnelKeychainError.unexpectedStatus(addStatus)
      }
    } else if updateStatus != errSecSuccess {
      throw TunnelKeychainError.unexpectedStatus(updateStatus)
    }
    guard try load() == value else {
      throw TunnelKeychainError.invalidValue
    }
  }

  private static func baseQuery() throws -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecAttrAccessGroup as String: try resolvedAccessGroup(),
      kSecAttrSynchronizable as String: kCFBooleanFalse!,
      kSecUseDataProtectionKeychain as String: kCFBooleanTrue!,
    ]
  }

  static func resolvedAccessGroup() throws -> String {
    guard
      let value = Bundle.main.object(
        forInfoDictionaryKey: "MeshIdentityKeychainGroup"
      ) as? String,
      value.utf8.count <= 256,
      !value.contains("$"),
      value.hasSuffix(".\(accessGroupSuffix)")
    else {
      throw TunnelKeychainError.invalidValue
    }
    return value
  }

  static func reserveRuntimeInstanceGeneration() throws -> UInt64 {
    let previous = try loadValue(account: runtimeInstanceAccount)
    guard previous < UInt64.max else {
      throw TunnelKeychainError.rollbackOrReplay
    }
    let next = previous + 1
    try commitValue(next, account: runtimeInstanceAccount)
    guard try loadValue(account: runtimeInstanceAccount) == next else {
      throw TunnelKeychainError.invalidValue
    }
    return next
  }

  static func hasLocalAuthority() throws -> Bool {
    try localAuthorityState().hasAnyAuthority
  }

  static func localAuthorityState() throws -> TunnelLocalAuthorityState {
    try TunnelLocalAuthorityState(
      hasPrivateKey: itemExists(service: privateKeyService),
      hasCurrentAgentCredential: itemExists(service: currentAgentService),
      hasPendingAgentCredential: itemExists(service: pendingAgentService)
    )
  }

  static func saveInitialEnrollmentIntent(
    _ intent: TunnelInitialEnrollmentIntent
  ) throws {
    let data = try intent.encoded()
    let attributes: [String: Any] = [
      kSecValueData as String: data,
      kSecAttrAccessible as String:
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ]
    let updateStatus = SecItemUpdate(
      try initialEnrollmentIntentQuery() as CFDictionary,
      attributes as CFDictionary
    )
    if updateStatus == errSecItemNotFound {
      var add = try initialEnrollmentIntentQuery()
      for (key, value) in attributes {
        add[key] = value
      }
      let addStatus = SecItemAdd(add as CFDictionary, nil)
      guard addStatus == errSecSuccess else {
        throw TunnelKeychainError.unexpectedStatus(addStatus)
      }
    } else if updateStatus != errSecSuccess {
      throw TunnelKeychainError.unexpectedStatus(updateStatus)
    }
    guard try loadInitialEnrollmentIntent() == intent else {
      throw TunnelKeychainError.invalidValue
    }
  }

  static func loadInitialEnrollmentIntent()
    throws -> TunnelInitialEnrollmentIntent?
  {
    var query = try initialEnrollmentIntentQuery()
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound {
      return nil
    }
    guard status == errSecSuccess, let data = result as? Data else {
      if status == errSecSuccess {
        throw TunnelKeychainError.invalidValue
      }
      throw TunnelKeychainError.unexpectedStatus(status)
    }
    return try TunnelInitialEnrollmentIntent.decodeExact(data)
  }

  static func clearInitialEnrollmentIntent() throws {
    let status = SecItemDelete(
      try initialEnrollmentIntentQuery() as CFDictionary
    )
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw TunnelKeychainError.unexpectedStatus(status)
    }
  }

  static func retireInitialEnrollmentIntent(
    matching expected: TunnelInitialEnrollmentIntent
  ) throws {
    guard try loadInitialEnrollmentIntent() == expected else {
      throw TunnelKeychainError.invalidValue
    }
    try clearInitialEnrollmentIntent()
    guard try loadInitialEnrollmentIntent() == nil else {
      throw TunnelKeychainError.invalidValue
    }
  }

  static func saveStartAuthorization(
    _ authorization: TunnelStartAuthorization
  ) throws {
    let data = try authorization.encoded()
    let attributes: [String: Any] = [
      kSecValueData as String: data,
      kSecAttrAccessible as String:
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ]
    let updateStatus = SecItemUpdate(
      try startAuthorizationQuery() as CFDictionary,
      attributes as CFDictionary
    )
    if updateStatus == errSecItemNotFound {
      var add = try startAuthorizationQuery()
      for (key, value) in attributes {
        add[key] = value
      }
      let addStatus = SecItemAdd(add as CFDictionary, nil)
      guard addStatus == errSecSuccess else {
        throw TunnelKeychainError.unexpectedStatus(addStatus)
      }
    } else if updateStatus != errSecSuccess {
      throw TunnelKeychainError.unexpectedStatus(updateStatus)
    }
    guard try loadStartAuthorization() == authorization else {
      throw TunnelKeychainError.invalidValue
    }
  }

  static func consumeStartAuthorization(
    matching expected: TunnelStartAuthorization
  ) throws {
    guard try loadStartAuthorization() == expected else {
      throw TunnelKeychainError.invalidValue
    }
    let status = SecItemDelete(
      try startAuthorizationQuery() as CFDictionary
    )
    guard status == errSecSuccess else {
      throw TunnelKeychainError.unexpectedStatus(status)
    }
    guard try loadStartAuthorization() == nil else {
      throw TunnelKeychainError.invalidValue
    }
  }

  private static func loadStartAuthorization()
    throws -> TunnelStartAuthorization?
  {
    var query = try startAuthorizationQuery()
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound {
      return nil
    }
    guard status == errSecSuccess, let data = result as? Data else {
      if status == errSecSuccess {
        throw TunnelKeychainError.invalidValue
      }
      throw TunnelKeychainError.unexpectedStatus(status)
    }
    return try TunnelStartAuthorization.decodeExact(data)
  }

  private static func loadValue(account: String) throws -> UInt64 {
    var query = try baseQuery(account: account)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound {
      return 0
    }
    guard status == errSecSuccess,
      let data = result as? Data,
      data.count == MemoryLayout<UInt64>.size
    else {
      if status == errSecSuccess {
        throw TunnelKeychainError.invalidValue
      }
      throw TunnelKeychainError.unexpectedStatus(status)
    }
    return data.withUnsafeBytes {
      UInt64(bigEndian: $0.loadUnaligned(as: UInt64.self))
    }
  }

  private static func commitValue(
    _ value: UInt64,
    account: String
  ) throws {
    let previous = try loadValue(account: account)
    guard value > 0, value >= previous else {
      throw TunnelKeychainError.rollbackOrReplay
    }
    var bigEndian = value.bigEndian
    let data = Data(
      bytes: &bigEndian,
      count: MemoryLayout<UInt64>.size
    )
    let attributes: [String: Any] = [
      kSecValueData as String: data,
      kSecAttrAccessible as String:
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ]
    let updateStatus = SecItemUpdate(
      try baseQuery(account: account) as CFDictionary,
      attributes as CFDictionary
    )
    if updateStatus == errSecItemNotFound {
      var add = try baseQuery(account: account)
      for (key, value) in attributes {
        add[key] = value
      }
      let addStatus = SecItemAdd(add as CFDictionary, nil)
      guard addStatus == errSecSuccess else {
        throw TunnelKeychainError.unexpectedStatus(addStatus)
      }
    } else if updateStatus != errSecSuccess {
      throw TunnelKeychainError.unexpectedStatus(updateStatus)
    }
  }

  private static func baseQuery(
    account: String
  ) throws -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecAttrAccessGroup as String: try resolvedAccessGroup(),
      kSecAttrSynchronizable as String: kCFBooleanFalse!,
      kSecUseDataProtectionKeychain as String: kCFBooleanTrue!,
    ]
  }

  private static func itemExists(service: String) throws -> Bool {
    var query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: identityAccount,
      kSecAttrAccessGroup as String: try resolvedAccessGroup(),
      kSecAttrSynchronizable as String: kCFBooleanFalse!,
      kSecUseDataProtectionKeychain as String: kCFBooleanTrue!,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    query[kSecReturnData as String] = false
    let status = SecItemCopyMatching(query as CFDictionary, nil)
    if status == errSecSuccess {
      return true
    }
    guard status == errSecItemNotFound else {
      throw TunnelKeychainError.unexpectedStatus(status)
    }
    return false
  }

  private static func initialEnrollmentIntentQuery()
    throws -> [String: Any]
  {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: initialEnrollmentIntentService,
      kSecAttrAccount as String: identityAccount,
      kSecAttrAccessGroup as String: try resolvedAccessGroup(),
      kSecAttrSynchronizable as String: kCFBooleanFalse!,
      kSecUseDataProtectionKeychain as String: kCFBooleanTrue!,
    ]
  }

  private static func startAuthorizationQuery()
    throws -> [String: Any]
  {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: startAuthorizationService,
      kSecAttrAccount as String: identityAccount,
      kSecAttrAccessGroup as String: try resolvedAccessGroup(),
      kSecAttrSynchronizable as String: kCFBooleanFalse!,
      kSecUseDataProtectionKeychain as String: kCFBooleanTrue!,
    ]
  }
}
