import Foundation
import Security

final class TunnelHighWaterKeychain: TunnelHighWaterStore {
  static let accessGroupSuffix =
    "io.rw0.mesh.tunnel.mobile.identity"
  static let service = "io.rw0.mesh.tunnel.mobile.identity.v1"
  static let account = "configuration-monotonic-high-water"
  static let runtimeInstanceAccount =
    "runtime-instance-monotonic-high-water"

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
}
