import Foundation

public enum TunnelRuntimeCoordinatorState: Equatable, Sendable {
  case idle
  case preparingEngine
  case applyingNetworkSettings
  case startingEngine
  case running
  case stopping
  case stopped
  case failed
}

public enum TunnelRuntimeCoordinatorError: Error, Equatable {
  case invalidTransition
  case engineIdentityMismatch
  case packetBackpressure
}

public protocol TunnelEngineSession: AnyObject, Sendable {
  func frameworkIdentity() async throws -> String
  func prepare(configuration: TunnelConfigurationPayload) async throws
  func start() async throws
  func rebind() async throws
  func send(_ packets: [TunnelPacket]) async throws
  func receive() async throws -> [TunnelPacket]
  func stop() async
}

public protocol TunnelNetworkSettingsSession: AnyObject, Sendable {
  func apply(
    plan: TunnelNetworkSettingsPlan,
    tunnelRemoteAddress: TunnelRemoteAddress
  ) async throws
  func clear() async
}

public struct TunnelRuntimeCoordinatorSnapshot: Equatable, Sendable {
  public let state: TunnelRuntimeCoordinatorState
  public let applePacketsRead: UInt64
  public let applePacketsWritten: UInt64
  public let queuedPackets: Int
  public let discardedOnStop: UInt64
}

public actor TunnelRuntimeCoordinator {
  private let configuration: TunnelConfigurationPayload
  private let engine: any TunnelEngineSession
  private let networkSettings: any TunnelNetworkSettingsSession
  private let pump: TunnelPacketFlowPump

  private var state: TunnelRuntimeCoordinatorState = .idle
  private var enginePrepared = false
  private var settingsAttempted = false
  private var settingsApplied = false
  private var engineStarted = false

  public init(
    configuration: TunnelConfigurationPayload,
    engine: any TunnelEngineSession,
    networkSettings: any TunnelNetworkSettingsSession,
    limits: TunnelPacketFlowPumpLimits
  ) {
    self.configuration = configuration
    self.engine = engine
    self.networkSettings = networkSettings
    pump = TunnelPacketFlowPump(limits: limits)
  }

  public func start() async throws {
    guard state == .idle else {
      throw TunnelRuntimeCoordinatorError.invalidTransition
    }
    do {
      state = .preparingEngine
      let observedIdentity = try await engine.frameworkIdentity()
      guard observedIdentity == configuration.engineIdentity else {
        throw TunnelRuntimeCoordinatorError.engineIdentityMismatch
      }
      try await engine.prepare(configuration: configuration)
      enginePrepared = true

      state = .applyingNetworkSettings
      settingsAttempted = true
      try await networkSettings.apply(
        plan: configuration.networkSettings,
        tunnelRemoteAddress: configuration.tunnelRemoteAddress
      )
      settingsApplied = true

      try await pump.start()
      state = .startingEngine
      try await engine.start()
      engineStarted = true
      state = .running
    } catch {
      await cleanUp(failed: true)
      throw error
    }
  }

  public func sendFromApple(_ packets: [TunnelPacket]) async throws {
    guard state == .running else {
      throw TunnelRuntimeCoordinatorError.invalidTransition
    }
    guard try await pump.offerFromApple(packets) == .accepted else {
      throw TunnelRuntimeCoordinatorError.packetBackpressure
    }
    let accepted = try await pump.takeForEngine()
    do {
      try await engine.send(accepted)
    } catch {
      await cleanUp(failed: true)
      throw error
    }
  }

  public func rebind() async throws {
    guard state == .running else {
      throw TunnelRuntimeCoordinatorError.invalidTransition
    }
    do {
      try await engine.rebind()
    } catch {
      await cleanUp(failed: true)
      throw error
    }
  }

  public func receiveForApple() async throws -> [TunnelPacket] {
    guard state == .running else {
      throw TunnelRuntimeCoordinatorError.invalidTransition
    }
    do {
      let packets = try await engine.receive()
      guard try await pump.offerFromEngine(packets) == .accepted else {
        await cleanUp(failed: true)
        throw TunnelRuntimeCoordinatorError.packetBackpressure
      }
      return try await pump.takeForApple()
    } catch {
      if state != .failed {
        await cleanUp(failed: true)
      }
      throw error
    }
  }

  public func stop() async {
    switch state {
    case .stopped:
      return
    case .idle:
      state = .stopped
    default:
      await cleanUp(failed: false)
    }
  }

  public func snapshot() async -> TunnelRuntimeCoordinatorSnapshot {
    let packetState = await pump.snapshot()
    return TunnelRuntimeCoordinatorSnapshot(
      state: state,
      applePacketsRead: packetState.applePacketsAccepted,
      applePacketsWritten: packetState.applePacketsDelivered,
      queuedPackets: packetState.appleToEngineQueuedPackets
        + packetState.engineToAppleQueuedPackets,
      discardedOnStop: packetState.discardedOnStop
    )
  }

  public func runtimeEvidence(
    sequence: UInt64
  ) async throws -> TunnelRuntimeEvidence {
    let current = await snapshot()
    guard current.state == .running else {
      throw TunnelRuntimeCoordinatorError.invalidTransition
    }
    return TunnelRuntimeEvidence(
      sequence: sequence,
      state: .running,
      configRevision: configuration.configRevision,
      certificateGeneration: configuration.certificateGeneration,
      engineIdentity: configuration.engineIdentity,
      packetsRead: current.applePacketsRead,
      packetsWritten: current.applePacketsWritten
    )
  }

  private func cleanUp(failed: Bool) async {
    state = .stopping
    await pump.stop()
    if engineStarted || enginePrepared {
      await engine.stop()
    }
    engineStarted = false
    enginePrepared = false
    if settingsAttempted || settingsApplied {
      await networkSettings.clear()
    }
    settingsAttempted = false
    settingsApplied = false
    state = failed ? .failed : .stopped
  }
}
