import Foundation

protocol TunnelLifecycleSession: Sendable {
  func refresh(
    current: TunnelConfigurationPayload,
    monotonicCounter: UInt64
  ) async throws -> TunnelLifecycleRefreshOutcome

  func reportRuntime(
    current: TunnelConfigurationPayload,
    instanceGeneration: UInt64,
    sequence: UInt64,
    state: TunnelMobileRuntimeState,
    runtimeUptimeMilliseconds: UInt64,
    packetsRead: UInt64?,
    packetsWritten: UInt64?,
    errorCode: String?
  ) async throws -> TunnelMobileRuntimeReportOutcome
}

protocol TunnelIdentityRemovalSession: Sendable {
  func remove() async throws
}

enum TunnelMobileRuntimeReporterError: Error {
  case counterExhausted
  case evidenceMismatch
  case terminal
}

actor TunnelMobileRuntimeReporter {
  private let configuration: TunnelConfigurationPayload
  private let lifecycle: any TunnelLifecycleSession
  private let instanceGeneration: UInt64
  private let clock = ContinuousClock()
  private let startedAt: ContinuousClock.Instant
  private var sequence: UInt64 = 0
  private var lastAcceptedAt: ContinuousClock.Instant?
  private var terminal = false
  private var stoppedSequence: UInt64?
  private var stoppedReportStarted = false

  init(
    configuration: TunnelConfigurationPayload,
    lifecycle: any TunnelLifecycleSession,
    instanceGeneration: UInt64
  ) {
    self.configuration = configuration
    self.lifecycle = lifecycle
    self.instanceGeneration = instanceGeneration
    startedAt = clock.now
  }

  func report(
    state: TunnelMobileRuntimeState,
    evidence: TunnelRuntimeEvidence? = nil,
    errorCode: String? = nil
  ) async throws -> TunnelMobileRuntimeReportOutcome {
    guard !terminal else {
      throw TunnelMobileRuntimeReporterError.terminal
    }
    guard sequence < UInt64(Int64.max) else {
      throw TunnelMobileRuntimeReporterError.counterExhausted
    }
    let packetsRead: UInt64?
    let packetsWritten: UInt64?
    if state == .tunnelRunning {
      guard let evidence,
        evidence.state == .running,
        evidence.configRevision == configuration.configRevision,
        evidence.certificateGeneration
          == configuration.certificateGeneration,
        evidence.engineIdentity == configuration.engineIdentity,
        let observedRead = evidence.packetsRead,
        let observedWritten = evidence.packetsWritten,
        errorCode == nil
      else {
        throw TunnelMobileRuntimeReporterError.evidenceMismatch
      }
      packetsRead = observedRead
      packetsWritten = observedWritten
    } else {
      guard evidence == nil else {
        throw TunnelMobileRuntimeReporterError.evidenceMismatch
      }
      packetsRead = nil
      packetsWritten = nil
    }
    sequence += 1
    let outcome = try await lifecycle.reportRuntime(
      current: configuration,
      instanceGeneration: instanceGeneration,
      sequence: sequence,
      state: state,
      runtimeUptimeMilliseconds: try uptimeMilliseconds(),
      packetsRead: packetsRead,
      packetsWritten: packetsWritten,
      errorCode: errorCode
    )
    if outcome.status == .accepted, !terminal {
      lastAcceptedAt = clock.now
    }
    return outcome
  }

  func terminalize() {
    guard !terminal else {
      return
    }
    terminal = true
    guard sequence < UInt64(Int64.max) else {
      return
    }
    sequence += 1
    stoppedSequence = sequence
  }

  func reportStopped() async throws -> TunnelMobileRuntimeReportOutcome {
    terminalize()
    guard let stoppedSequence, !stoppedReportStarted else {
      throw TunnelMobileRuntimeReporterError.terminal
    }
    stoppedReportStarted = true
    return try await lifecycle.reportRuntime(
      current: configuration,
      instanceGeneration: instanceGeneration,
      sequence: stoppedSequence,
      state: .stopped,
      runtimeUptimeMilliseconds: try uptimeMilliseconds(),
      packetsRead: nil,
      packetsWritten: nil,
      errorCode: nil
    )
  }

  func deferredEvidenceExceeded(
    _ bound: Duration
  ) -> Bool {
    let anchor = lastAcceptedAt ?? startedAt
    return anchor.duration(to: clock.now) >= bound
  }

  private func uptimeMilliseconds() throws -> UInt64 {
    let components = startedAt.duration(to: clock.now).components
    guard components.seconds >= 0,
      components.attoseconds >= 0,
      UInt64(components.seconds) <= UInt64(Int64.max) / 1_000
    else {
      throw TunnelMobileRuntimeReporterError.counterExhausted
    }
    return UInt64(components.seconds) * 1_000
      + UInt64(components.attoseconds / 1_000_000_000_000_000)
  }
}

#if canImport(MeshMobile)
  @preconcurrency import MeshMobile

  enum GoTunnelEngineSessionError: Error {
    case constructionFailed
    case invalidPacket
  }

  enum GoTunnelLifecycleSessionError: Error {
    case constructionFailed
    case invalidCounter
    case invalidDocument
  }

  final class GoTunnelLifecycleSession:
    TunnelLifecycleSession,
    @unchecked Sendable
  {
    private let session: IosmobileLifecycleSession

    init(accessGroup: String) throws {
      var constructionError: NSError?
      guard
        let session = IosmobileNewLifecycleSession(
          accessGroup,
          TunnelIdentityScope.primaryID,
          &constructionError
        )
      else {
        if let constructionError {
          throw constructionError
        }
        throw GoTunnelLifecycleSessionError.constructionFailed
      }
      self.session = session
    }

    func refresh(
      current: TunnelConfigurationPayload,
      monotonicCounter: UInt64
    ) async throws -> TunnelLifecycleRefreshOutcome {
      guard monotonicCounter <= UInt64(Int64.max) else {
        throw GoTunnelLifecycleSessionError.invalidCounter
      }
      let currentDocument = try current.engineDocument()
      let document = try await Task.detached { [self] in
        var refreshError: NSError?
        let value = session.refresh(
          current.controlPlaneOrigin,
          currentConfigurationJSON: currentDocument,
          monotonicCounter: Int64(monotonicCounter),
          error: &refreshError
        )
        if let refreshError {
          throw refreshError
        }
        return value
      }.value
      guard let data = document.data(using: .utf8) else {
        throw GoTunnelLifecycleSessionError.invalidDocument
      }
      let outcome = try TunnelLifecycleRefreshOutcome.decodeExact(data)
      if let configuration = outcome.configuration,
        configuration.monotonicCounter != monotonicCounter
      {
        throw GoTunnelLifecycleSessionError.invalidCounter
      }
      return outcome
    }

    func reportRuntime(
      current: TunnelConfigurationPayload,
      instanceGeneration: UInt64,
      sequence: UInt64,
      state: TunnelMobileRuntimeState,
      runtimeUptimeMilliseconds: UInt64,
      packetsRead: UInt64?,
      packetsWritten: UInt64?,
      errorCode: String?
    ) async throws -> TunnelMobileRuntimeReportOutcome {
      guard instanceGeneration <= UInt64(Int64.max),
        sequence <= UInt64(Int64.max),
        runtimeUptimeMilliseconds <= UInt64(Int64.max),
        (packetsRead ?? 0) <= UInt64(Int64.max),
        (packetsWritten ?? 0) <= UInt64(Int64.max),
        (packetsRead == nil) == (packetsWritten == nil)
      else {
        throw GoTunnelLifecycleSessionError.invalidCounter
      }
      let currentDocument = try current.engineDocument()
      let document = try await Task.detached { [self] in
        var reportError: NSError?
        let value = session.reportRuntime(
          current.controlPlaneOrigin,
          currentConfigurationJSON: currentDocument,
          instanceGeneration: Int64(instanceGeneration),
          sequence: Int64(sequence),
          state: state.rawValue,
          runtimeUptimeMS: Int64(runtimeUptimeMilliseconds),
          packetsRead: Int64(packetsRead ?? 0),
          packetsWritten: Int64(packetsWritten ?? 0),
          hasPacketCounters: packetsRead != nil,
          errorCode: errorCode ?? "",
          error: &reportError
        )
        if let reportError {
          throw reportError
        }
        return value
      }.value
      guard let data = document.data(using: .utf8) else {
        throw GoTunnelLifecycleSessionError.invalidDocument
      }
      return try TunnelMobileRuntimeReportOutcome.decodeExact(data)
    }
  }

  final class GoTunnelEngineSession:
    TunnelEngineSession,
    @unchecked Sendable
  {
    private let session: IosmobileEngineSession

    init(accessGroup: String, identityID: String) throws {
      var constructionError: NSError?
      guard
        let session = IosmobileNewEngineSession(
          accessGroup,
          identityID,
          &constructionError
        )
      else {
        if let constructionError {
          throw constructionError
        }
        throw GoTunnelEngineSessionError.constructionFailed
      }
      self.session = session
    }

    func frameworkIdentity() async throws -> String {
      session.frameworkIdentity()
    }

    func prepare(
      configuration: TunnelConfigurationPayload
    ) async throws {
      let document = try configuration.engineDocument()
      try await Task.detached { [self] in
        try session.prepare(document)
      }.value
    }

    func start() async throws {
      try await Task.detached { [self] in
        try session.start()
      }.value
    }

    func rebind() async throws {
      try await Task.detached { [self] in
        try session.rebind()
      }.value
    }

    func send(_ packets: [TunnelPacket]) async throws {
      let owned = packets.map(\.bytes)
      try await Task.detached { [self] in
        for packet in owned {
          try session.send(packet)
        }
      }.value
    }

    func receive() async throws -> [TunnelPacket] {
      let bytes = try await Task.detached { [self] in
        try session.receive()
      }.value
      guard let first = bytes.first else {
        throw GoTunnelEngineSessionError.invalidPacket
      }
      let family: TunnelPacketFamily
      switch first >> 4 {
      case TunnelPacketFamily.ipv4.rawValue:
        family = .ipv4
      case TunnelPacketFamily.ipv6.rawValue:
        family = .ipv6
      default:
        throw GoTunnelEngineSessionError.invalidPacket
      }
      return [try TunnelPacket(bytes: bytes, family: family)]
    }

    func stop() async {
      await Task.detached { [self] in
        session.stop()
      }.value
    }
  }

  final class GoTunnelIdentityRemovalSession:
    TunnelIdentityRemovalSession,
    @unchecked Sendable
  {
    private let session: IosmobileIdentityRemovalSession

    init(accessGroup: String) throws {
      var constructionError: NSError?
      guard
        let session = IosmobileNewIdentityRemovalSession(
          accessGroup,
          TunnelIdentityScope.primaryID,
          &constructionError
        )
      else {
        if let constructionError {
          throw constructionError
        }
        throw GoTunnelLifecycleSessionError.constructionFailed
      }
      self.session = session
    }

    func remove() async throws {
      try await Task.detached { [self] in
        try session.remove()
      }.value
    }
  }
#endif

final class UnavailableTunnelLifecycleSession:
  TunnelLifecycleSession,
  @unchecked Sendable
{
  func refresh(
    current: TunnelConfigurationPayload,
    monotonicCounter: UInt64
  ) async throws -> TunnelLifecycleRefreshOutcome {
    throw TunnelEngineAdapterError.unavailable
  }

  func reportRuntime(
    current: TunnelConfigurationPayload,
    instanceGeneration: UInt64,
    sequence: UInt64,
    state: TunnelMobileRuntimeState,
    runtimeUptimeMilliseconds: UInt64,
    packetsRead: UInt64?,
    packetsWritten: UInt64?,
    errorCode: String?
  ) async throws -> TunnelMobileRuntimeReportOutcome {
    throw TunnelEngineAdapterError.unavailable
  }
}

final class UnavailableTunnelIdentityRemovalSession:
  TunnelIdentityRemovalSession,
  @unchecked Sendable
{
  func remove() async throws {
    throw TunnelEngineAdapterError.unavailable
  }
}

enum TunnelEngineSessionFactory {
  static func make(
    configuration: TunnelConfigurationPayload
  ) throws -> any TunnelEngineSession {
    #if canImport(MeshMobile)
      return try GoTunnelEngineSession(
        accessGroup: TunnelHighWaterKeychain.resolvedAccessGroup(),
        identityID: TunnelIdentityScope.primaryID
      )
    #else
      return UnavailableTunnelEngineSession()
    #endif
  }
}

enum TunnelLifecycleSessionFactory {
  static func make() throws -> any TunnelLifecycleSession {
    #if canImport(MeshMobile)
      return try GoTunnelLifecycleSession(
        accessGroup: TunnelHighWaterKeychain.resolvedAccessGroup()
      )
    #else
      return UnavailableTunnelLifecycleSession()
    #endif
  }
}

enum TunnelIdentityRemovalSessionFactory {
  static func make() throws -> any TunnelIdentityRemovalSession {
    #if canImport(MeshMobile)
      return try GoTunnelIdentityRemovalSession(
        accessGroup: TunnelHighWaterKeychain.resolvedAccessGroup()
      )
    #else
      return UnavailableTunnelIdentityRemovalSession()
    #endif
  }
}
