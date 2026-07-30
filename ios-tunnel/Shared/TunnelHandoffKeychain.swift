import CryptoKit
import Foundation
import Security

public enum TunnelKeychainError: Error, Equatable {
  case unexpectedStatus(OSStatus)
  case invalidValue
  case rollbackOrReplay
}

public enum TunnelHandoffKeychain {
  public static let accessGroupSuffix =
    "io.rw0.mesh.tunnel.mobile.handoff"
  public static let service = "io.rw0.mesh.tunnel.mobile.handoff.v1"
  public static let account = "configuration-authentication-key"

  public static func loadOrCreate() throws -> SymmetricKey {
    if let existing = try read() {
      return SymmetricKey(data: existing)
    }
    var bytes = Data(count: 32)
    let randomStatus = bytes.withUnsafeMutableBytes {
      SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
    }
    guard randomStatus == errSecSuccess else {
      throw TunnelKeychainError.unexpectedStatus(randomStatus)
    }
    var query = try baseQuery()
    query[kSecValueData as String] = bytes
    query[kSecAttrAccessible as String] =
      kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    let addStatus = SecItemAdd(query as CFDictionary, nil)
    if addStatus == errSecDuplicateItem, let existing = try read() {
      bytes.resetBytes(in: 0..<bytes.count)
      return SymmetricKey(data: existing)
    }
    guard addStatus == errSecSuccess else {
      bytes.resetBytes(in: 0..<bytes.count)
      throw TunnelKeychainError.unexpectedStatus(addStatus)
    }
    let key = SymmetricKey(data: bytes)
    bytes.resetBytes(in: 0..<bytes.count)
    return key
  }

  public static func loadExisting() throws -> SymmetricKey? {
    try read().map { SymmetricKey(data: $0) }
  }

  private static func read() throws -> Data? {
    var query = try baseQuery()
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound {
      return nil
    }
    guard status == errSecSuccess,
      let data = result as? Data,
      data.count == 32
    else {
      if status == errSecSuccess {
        throw TunnelKeychainError.invalidValue
      }
      throw TunnelKeychainError.unexpectedStatus(status)
    }
    return data
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

  private static func resolvedAccessGroup() throws -> String {
    guard
      let value = Bundle.main.object(
        forInfoDictionaryKey: "MeshHandoffKeychainGroup"
      ) as? String,
      value.utf8.count <= 256,
      !value.contains("$"),
      value.hasSuffix(".\(accessGroupSuffix)")
    else {
      throw TunnelKeychainError.invalidValue
    }
    return value
  }
}
