import Foundation
import NetworkExtension

enum TunnelEngineAdapterError: Error {
  case unavailable
  case providerUnavailable
  case packetWriteRejected
}

final class UnavailableTunnelEngineSession:
  TunnelEngineSession,
  @unchecked Sendable
{
  func frameworkIdentity() async throws -> String {
    throw TunnelEngineAdapterError.unavailable
  }

  func prepare(
    configuration: TunnelConfigurationPayload
  ) async throws {
    throw TunnelEngineAdapterError.unavailable
  }

  func start() async throws {
    throw TunnelEngineAdapterError.unavailable
  }

  func rebind() async throws {
    throw TunnelEngineAdapterError.unavailable
  }

  func send(_ packets: [TunnelPacket]) async throws {
    throw TunnelEngineAdapterError.unavailable
  }

  func receive() async throws -> [TunnelPacket] {
    throw TunnelEngineAdapterError.unavailable
  }

  func stop() async {}
}

final class ProviderNetworkSettingsSession:
  TunnelNetworkSettingsSession,
  @unchecked Sendable
{
  private weak var provider: NEPacketTunnelProvider?

  init(provider: NEPacketTunnelProvider) {
    self.provider = provider
  }

  func apply(
    plan: TunnelNetworkSettingsPlan,
    tunnelRemoteAddress: TunnelRemoteAddress
  ) async throws {
    guard let provider else {
      throw TunnelEngineAdapterError.providerUnavailable
    }
    let settings = try TunnelAppleNetworkSettingsFactory.make(
      plan: plan,
      tunnelRemoteAddress: tunnelRemoteAddress
    )
    try await provider.setTunnelNetworkSettings(settings)
  }

  func clear() async {
    try? await provider?.setTunnelNetworkSettings(nil)
  }
}

final class ProviderPacketFlowSession: @unchecked Sendable {
  private weak var provider: NEPacketTunnelProvider?
  private let limits: TunnelPacketFlowPumpLimits

  init(
    provider: NEPacketTunnelProvider,
    limits: TunnelPacketFlowPumpLimits
  ) {
    self.provider = provider
    self.limits = limits
  }

  func read() async throws -> [TunnelPacket] {
    guard let flow = provider?.packetFlow else {
      throw TunnelEngineAdapterError.providerUnavailable
    }
    return try await withCheckedThrowingContinuation {
      (continuation: CheckedContinuation<[TunnelPacket], Error>) in
      flow.readPackets { packets, protocols in
        do {
          let protocolFamilies = try protocols.map { value in
            let integer = value.int64Value
            guard value.doubleValue.isFinite,
              value.doubleValue == Double(integer),
              integer >= Int64(Int32.min),
              integer <= Int64(Int32.max)
            else {
              throw TunnelPacketFlowBatchError
                .unsupportedProtocolFamily
            }
            return Int32(integer)
          }
          continuation.resume(
            returning:
              try TunnelPacketFlowBatchCodec
              .decodeAppleRead(
                packets: packets,
                protocolFamilies: protocolFamilies,
                limits: self.limits
              )
          )
        } catch {
          continuation.resume(throwing: error)
        }
      }
    }
  }

  func write(_ packets: [TunnelPacket]) throws {
    guard let flow = provider?.packetFlow else {
      throw TunnelEngineAdapterError.providerUnavailable
    }
    let batch = try TunnelPacketFlowBatchCodec.encodeAppleWrite(
      packets,
      limits: limits
    )
    let protocols = batch.protocolFamilies.map {
      NSNumber(value: $0)
    }
    guard
      flow.writePackets(
        batch.packets,
        withProtocols: protocols
      )
    else {
      throw TunnelEngineAdapterError.packetWriteRejected
    }
  }
}
