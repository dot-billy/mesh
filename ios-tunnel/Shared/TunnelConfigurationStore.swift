import CryptoKit
import Darwin
import Foundation

public protocol TunnelHighWaterStore {
  func load() throws -> UInt64
  func commit(_ value: UInt64) throws
}

public enum TunnelConfigurationStoreError: Error, Equatable {
  case missingCandidate
  case rollbackOrReplay
  case invalidSlot
  case systemCall(String)
}

public final class TunnelConfigurationStore {
  public static let candidateSlot = "candidate.envelope"
  public static let currentSlot = "current.envelope"
  public static let recoverySlot = "recovery.envelope"

  private let directory: SecureSlotDirectory
  private let key: SymmetricKey
  private let highWater: TunnelHighWaterStore

  public init(
    containerURL: URL,
    key: SymmetricKey,
    highWater: TunnelHighWaterStore
  ) throws {
    directory = try SecureSlotDirectory(url: containerURL)
    self.key = key
    self.highWater = highWater
  }

  deinit {
    directory.close()
  }

  public func stage(_ payload: TunnelConfigurationPayload) throws {
    let sealed = try TunnelEnvelopeAuthenticator.seal(payload, using: key)
    if let current = try read(slot: Self.currentSlot),
      payload.monotonicCounter <= current.monotonicCounter
    {
      throw TunnelConfigurationStoreError.rollbackOrReplay
    }
    try directory.write(sealed, to: Self.candidateSlot)
  }

  @discardableResult
  public func activateCandidate() throws -> TunnelConfigurationPayload {
    guard let candidateData = try directory.read(Self.candidateSlot) else {
      throw TunnelConfigurationStoreError.missingCandidate
    }
    let candidate = try TunnelEnvelopeAuthenticator.open(
      candidateData,
      using: key
    )
    let currentData = try directory.read(Self.currentSlot)
    let current = try currentData.map {
      try TunnelEnvelopeAuthenticator.open($0, using: key)
    }
    let effectiveHighWater = max(
      try highWater.load(),
      current?.monotonicCounter ?? 0
    )
    guard candidate.monotonicCounter > effectiveHighWater else {
      throw TunnelConfigurationStoreError.rollbackOrReplay
    }

    if let currentData {
      try directory.write(currentData, to: Self.recoverySlot)
    }
    try directory.write(candidateData, to: Self.currentSlot)

    // The current slot is durable before the high-water write. If this
    // commit reports an ambiguous failure, a later activation derives its
    // effective floor from the authenticated current slot as well.
    try highWater.commit(candidate.monotonicCounter)
    try directory.remove(Self.candidateSlot)
    return candidate
  }

  public func readCurrent() throws -> TunnelConfigurationPayload? {
    guard let current = try read(slot: Self.currentSlot) else {
      return nil
    }
    guard current.monotonicCounter >= (try highWater.load()) else {
      throw TunnelConfigurationStoreError.rollbackOrReplay
    }
    return current
  }

  public func readRecovery() throws -> TunnelConfigurationPayload? {
    try read(slot: Self.recoverySlot)
  }

  public func nextMonotonicCounter() throws -> UInt64 {
    let current = try read(slot: Self.currentSlot)
    let floor = max(
      try highWater.load(),
      current?.monotonicCounter ?? 0
    )
    guard floor < UInt64.max else {
      throw TunnelConfigurationStoreError.rollbackOrReplay
    }
    return floor + 1
  }

  public static func eraseAll(containerURL: URL) throws {
    let directory = try SecureSlotDirectory(url: containerURL)
    defer { directory.close() }
    try directory.remove(Self.candidateSlot)
    try directory.remove(Self.recoverySlot)
    try directory.remove(Self.currentSlot)
  }

  private func read(slot: String) throws -> TunnelConfigurationPayload? {
    guard let data = try directory.read(slot) else {
      return nil
    }
    return try TunnelEnvelopeAuthenticator.open(data, using: key)
  }
}

private final class SecureSlotDirectory {
  private let descriptor: Int32

  init(url: URL) throws {
    descriptor = Darwin.open(
      url.path,
      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
    )
    guard descriptor >= 0 else {
      throw Self.failure("open App Group directory")
    }
    var status = stat()
    guard fstat(descriptor, &status) == 0,
      (status.st_mode & S_IFMT) == S_IFDIR
    else {
      Darwin.close(descriptor)
      throw Self.failure("inspect App Group directory")
    }
  }

  func close() {
    Darwin.close(descriptor)
  }

  func read(_ name: String) throws -> Data? {
    try Self.requireSlotName(name)
    let file = openat(
      descriptor,
      name,
      O_RDONLY | O_NOFOLLOW | O_CLOEXEC
    )
    if file < 0, errno == ENOENT {
      return nil
    }
    guard file >= 0 else {
      throw Self.failure("open configuration slot")
    }
    defer { Darwin.close(file) }

    var before = stat()
    guard fstat(file, &before) == 0,
      (before.st_mode & S_IFMT) == S_IFREG,
      before.st_nlink == 1,
      before.st_size > 0,
      before.st_size <= TunnelEnvelopeAuthenticator.maximumDocumentBytes
    else {
      throw TunnelConfigurationStoreError.invalidSlot
    }
    var bytes = [UInt8](repeating: 0, count: Int(before.st_size))
    var offset = 0
    while offset < bytes.count {
      let remaining = bytes.count - offset
      let count = bytes.withUnsafeMutableBytes { buffer in
        Darwin.read(
          file,
          buffer.baseAddress!.advanced(by: offset),
          remaining
        )
      }
      guard count > 0 else {
        throw Self.failure("read configuration slot")
      }
      offset += count
    }
    var after = stat()
    guard fstat(file, &after) == 0,
      before.st_dev == after.st_dev,
      before.st_ino == after.st_ino,
      before.st_mode == after.st_mode,
      before.st_nlink == after.st_nlink,
      before.st_size == after.st_size,
      before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
      before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec
    else {
      throw TunnelConfigurationStoreError.invalidSlot
    }
    return Data(bytes)
  }

  func write(_ data: Data, to name: String) throws {
    try Self.requireSlotName(name)
    guard !data.isEmpty,
      data.count <= TunnelEnvelopeAuthenticator.maximumDocumentBytes
    else {
      throw TunnelConfigurationStoreError.invalidSlot
    }
    let temporary = ".mesh-\(UUID().uuidString.lowercased())"
    let file = openat(
      descriptor,
      temporary,
      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
      S_IRUSR | S_IWUSR
    )
    guard file >= 0 else {
      throw Self.failure("create configuration slot")
    }
    var renamed = false
    defer {
      Darwin.close(file)
      if !renamed {
        _ = unlinkat(descriptor, temporary, 0)
      }
    }

    var offset = 0
    try data.withUnsafeBytes { buffer in
      while offset < data.count {
        let count = Darwin.write(
          file,
          buffer.baseAddress!.advanced(by: offset),
          data.count - offset
        )
        guard count > 0 else {
          throw Self.failure("write configuration slot")
        }
        offset += count
      }
    }
    guard fsync(file) == 0,
      renameat(descriptor, temporary, descriptor, name) == 0,
      fsync(descriptor) == 0
    else {
      throw Self.failure("publish configuration slot")
    }
    renamed = true
  }

  func remove(_ name: String) throws {
    try Self.requireSlotName(name)
    if unlinkat(descriptor, name, 0) != 0, errno != ENOENT {
      throw Self.failure("remove configuration slot")
    }
    guard fsync(descriptor) == 0 else {
      throw Self.failure("synchronize configuration directory")
    }
  }

  private static func requireSlotName(_ name: String) throws {
    guard
      [
        TunnelConfigurationStore.candidateSlot,
        TunnelConfigurationStore.currentSlot,
        TunnelConfigurationStore.recoverySlot,
      ].contains(name)
    else {
      throw TunnelConfigurationStoreError.invalidSlot
    }
  }

  private static func failure(_ operation: String)
    -> TunnelConfigurationStoreError
  {
    let detail = String(cString: strerror(errno))
    return .systemCall("\(operation): \(detail)")
  }
}
