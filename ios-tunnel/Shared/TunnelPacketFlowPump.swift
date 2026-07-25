import Darwin
import Foundation

public enum TunnelPacketFamily: UInt8, Sendable {
  case ipv4 = 4
  case ipv6 = 6
}

public enum TunnelPacketError: Error, Equatable {
  case invalidPacket
  case familyMismatch
}

public struct TunnelPacket: Equatable, Sendable {
  public static let maximumBytes = 65_575

  public let bytes: Data
  public let family: TunnelPacketFamily

  public init(bytes: Data, family: TunnelPacketFamily) throws {
    guard !bytes.isEmpty, bytes.count <= Self.maximumBytes else {
      throw TunnelPacketError.invalidPacket
    }
    let owned = Data([UInt8](bytes))
    switch family {
    case .ipv4:
      guard owned.count >= 20,
        owned[owned.startIndex] >> 4 == family.rawValue
      else {
        throw TunnelPacketError.familyMismatch
      }
      let headerBytes = Int(owned[owned.startIndex] & 0x0f) * 4
      let totalBytes =
        Int(owned[owned.startIndex + 2]) << 8
        | Int(owned[owned.startIndex + 3])
      guard headerBytes >= 20,
        headerBytes <= owned.count,
        totalBytes == owned.count
      else {
        throw TunnelPacketError.invalidPacket
      }
    case .ipv6:
      guard owned.count >= 40,
        owned[owned.startIndex] >> 4 == family.rawValue
      else {
        throw TunnelPacketError.familyMismatch
      }
      let payloadBytes =
        Int(owned[owned.startIndex + 4]) << 8
        | Int(owned[owned.startIndex + 5])
      guard payloadBytes + 40 == owned.count else {
        throw TunnelPacketError.invalidPacket
      }
    }
    self.bytes = owned
    self.family = family
  }
}

public enum TunnelPacketFlowBatchError: Error, Equatable {
  case invalidBatch
  case protocolCountMismatch
  case unsupportedProtocolFamily
}

public struct TunnelPacketFlowBatch: Equatable, Sendable {
  public let packets: [Data]
  public let protocolFamilies: [Int32]

  public init(packets: [Data], protocolFamilies: [Int32]) {
    self.packets = packets
    self.protocolFamilies = protocolFamilies
  }
}

public enum TunnelPacketFlowBatchCodec {
  public static let ipv4ProtocolFamily = Int32(AF_INET)
  public static let ipv6ProtocolFamily = Int32(AF_INET6)

  public static func decodeAppleRead(
    packets: [Data],
    protocolFamilies: [Int32],
    limits: TunnelPacketFlowPumpLimits
  ) throws -> [TunnelPacket] {
    guard packets.count == protocolFamilies.count else {
      throw TunnelPacketFlowBatchError.protocolCountMismatch
    }
    try validateBatch(packets, limits: limits)
    return try zip(packets, protocolFamilies).map { packet, protocolFamily in
      let family: TunnelPacketFamily
      switch protocolFamily {
      case ipv4ProtocolFamily:
        family = .ipv4
      case ipv6ProtocolFamily:
        family = .ipv6
      default:
        throw TunnelPacketFlowBatchError.unsupportedProtocolFamily
      }
      return try TunnelPacket(bytes: packet, family: family)
    }
  }

  public static func encodeAppleWrite(
    _ packets: [TunnelPacket],
    limits: TunnelPacketFlowPumpLimits
  ) throws -> TunnelPacketFlowBatch {
    let ownedPackets = packets.map {
      Data([UInt8]($0.bytes))
    }
    try validateBatch(ownedPackets, limits: limits)
    return TunnelPacketFlowBatch(
      packets: ownedPackets,
      protocolFamilies: packets.map {
        switch $0.family {
        case .ipv4:
          ipv4ProtocolFamily
        case .ipv6:
          ipv6ProtocolFamily
        }
      }
    )
  }

  private static func validateBatch(
    _ packets: [Data],
    limits: TunnelPacketFlowPumpLimits
  ) throws {
    guard !packets.isEmpty,
      packets.count <= limits.maximumBatchPackets
    else {
      throw TunnelPacketFlowBatchError.invalidBatch
    }
    var bytes = 0
    for packet in packets {
      guard packet.count <= limits.maximumBatchBytes - bytes else {
        throw TunnelPacketFlowBatchError.invalidBatch
      }
      bytes += packet.count
    }
  }
}

public struct TunnelPacketFlowPumpLimits: Equatable, Sendable {
  public let maximumQueuedPackets: Int
  public let maximumQueuedBytes: Int
  public let maximumBatchPackets: Int
  public let maximumBatchBytes: Int

  public init(
    maximumQueuedPackets: Int = 128,
    maximumQueuedBytes: Int = 1_048_576,
    maximumBatchPackets: Int = 64,
    maximumBatchBytes: Int = 262_144
  ) throws {
    guard (1...4096).contains(maximumQueuedPackets),
      (TunnelPacket.maximumBytes...8_388_608).contains(
        maximumQueuedBytes
      ),
      (1...maximumQueuedPackets).contains(maximumBatchPackets),
      (TunnelPacket.maximumBytes...maximumQueuedBytes).contains(
        maximumBatchBytes
      )
    else {
      throw TunnelPacketFlowPumpError.invalidLimits
    }
    self.maximumQueuedPackets = maximumQueuedPackets
    self.maximumQueuedBytes = maximumQueuedBytes
    self.maximumBatchPackets = maximumBatchPackets
    self.maximumBatchBytes = maximumBatchBytes
  }
}

public enum TunnelPacketFlowPumpOffer: Equatable, Sendable {
  case accepted
  case backpressured
}

public enum TunnelPacketFlowPumpState: Equatable, Sendable {
  case idle
  case running
  case stopped
}

public enum TunnelPacketFlowPumpError: Error, Equatable {
  case invalidLimits
  case invalidBatch
  case invalidTransition
  case notRunning
}

public struct TunnelPacketFlowPumpSnapshot: Equatable, Sendable {
  public let state: TunnelPacketFlowPumpState
  public let appleToEngineQueuedPackets: Int
  public let appleToEngineQueuedBytes: Int
  public let engineToAppleQueuedPackets: Int
  public let engineToAppleQueuedBytes: Int
  public let acceptedPackets: UInt64
  public let deliveredPackets: UInt64
  public let applePacketsAccepted: UInt64
  public let enginePacketsAccepted: UInt64
  public let enginePacketsDelivered: UInt64
  public let applePacketsDelivered: UInt64
  public let discardedOnStop: UInt64
}

public actor TunnelPacketFlowPump {
  private let limits: TunnelPacketFlowPumpLimits
  private var state: TunnelPacketFlowPumpState = .idle
  private var appleToEngine: [TunnelPacket] = []
  private var appleToEngineBytes = 0
  private var engineToApple: [TunnelPacket] = []
  private var engineToAppleBytes = 0
  private var acceptedPackets: UInt64 = 0
  private var deliveredPackets: UInt64 = 0
  private var applePacketsAccepted: UInt64 = 0
  private var enginePacketsAccepted: UInt64 = 0
  private var enginePacketsDelivered: UInt64 = 0
  private var applePacketsDelivered: UInt64 = 0
  private var discardedOnStop: UInt64 = 0

  public init(limits: TunnelPacketFlowPumpLimits) {
    self.limits = limits
  }

  public func start() throws {
    guard state == .idle else {
      throw TunnelPacketFlowPumpError.invalidTransition
    }
    state = .running
  }

  public func offerFromApple(
    _ packets: [TunnelPacket]
  ) throws -> TunnelPacketFlowPumpOffer {
    let result = try offer(
      packets,
      queue: &appleToEngine,
      queuedBytes: &appleToEngineBytes
    )
    if result == .accepted {
      applePacketsAccepted &+= UInt64(packets.count)
    }
    return result
  }

  public func offerFromEngine(
    _ packets: [TunnelPacket]
  ) throws -> TunnelPacketFlowPumpOffer {
    let result = try offer(
      packets,
      queue: &engineToApple,
      queuedBytes: &engineToAppleBytes
    )
    if result == .accepted {
      enginePacketsAccepted &+= UInt64(packets.count)
    }
    return result
  }

  public func takeForEngine() throws -> [TunnelPacket] {
    let packets = try take(
      queue: &appleToEngine,
      queuedBytes: &appleToEngineBytes
    )
    enginePacketsDelivered &+= UInt64(packets.count)
    return packets
  }

  public func takeForApple() throws -> [TunnelPacket] {
    let packets = try take(
      queue: &engineToApple,
      queuedBytes: &engineToAppleBytes
    )
    applePacketsDelivered &+= UInt64(packets.count)
    return packets
  }

  public func stop() {
    guard state != .stopped else {
      return
    }
    discardedOnStop &+= UInt64(
      appleToEngine.count + engineToApple.count
    )
    appleToEngine.removeAll(keepingCapacity: false)
    appleToEngineBytes = 0
    engineToApple.removeAll(keepingCapacity: false)
    engineToAppleBytes = 0
    state = .stopped
  }

  public func snapshot() -> TunnelPacketFlowPumpSnapshot {
    TunnelPacketFlowPumpSnapshot(
      state: state,
      appleToEngineQueuedPackets: appleToEngine.count,
      appleToEngineQueuedBytes: appleToEngineBytes,
      engineToAppleQueuedPackets: engineToApple.count,
      engineToAppleQueuedBytes: engineToAppleBytes,
      acceptedPackets: acceptedPackets,
      deliveredPackets: deliveredPackets,
      applePacketsAccepted: applePacketsAccepted,
      enginePacketsAccepted: enginePacketsAccepted,
      enginePacketsDelivered: enginePacketsDelivered,
      applePacketsDelivered: applePacketsDelivered,
      discardedOnStop: discardedOnStop
    )
  }

  private func offer(
    _ packets: [TunnelPacket],
    queue: inout [TunnelPacket],
    queuedBytes: inout Int
  ) throws -> TunnelPacketFlowPumpOffer {
    guard state == .running else {
      throw TunnelPacketFlowPumpError.notRunning
    }
    let batchBytes = packets.reduce(into: 0) {
      $0 += $1.bytes.count
    }
    guard !packets.isEmpty,
      packets.count <= limits.maximumBatchPackets,
      batchBytes <= limits.maximumBatchBytes
    else {
      throw TunnelPacketFlowPumpError.invalidBatch
    }
    guard queue.count <= limits.maximumQueuedPackets - packets.count,
      queuedBytes <= limits.maximumQueuedBytes - batchBytes
    else {
      return .backpressured
    }
    queue.append(contentsOf: packets)
    queuedBytes += batchBytes
    acceptedPackets &+= UInt64(packets.count)
    return .accepted
  }

  private func take(
    queue: inout [TunnelPacket],
    queuedBytes: inout Int
  ) throws -> [TunnelPacket] {
    guard state == .running else {
      throw TunnelPacketFlowPumpError.notRunning
    }
    var count = 0
    var bytes = 0
    while count < queue.count,
      count < limits.maximumBatchPackets,
      bytes <= limits.maximumBatchBytes - queue[count].bytes.count
    {
      bytes += queue[count].bytes.count
      count += 1
    }
    let result = Array(queue.prefix(count))
    queue.removeFirst(count)
    queuedBytes -= bytes
    deliveredPackets &+= UInt64(count)
    return result
  }
}
