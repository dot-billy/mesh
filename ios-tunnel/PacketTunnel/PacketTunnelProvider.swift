import Foundation
import Network
import NetworkExtension

final class PacketTunnelProvider:
  NEPacketTunnelProvider,
  @unchecked Sendable
{
  private static let applicationGroup =
    "group.io.rw0.mesh.tunnel.mobile"

  private var sequence: UInt64 = 0
  private var state: TunnelLifecycleState = .stopped
  private var errorCode: String?
  private var runtime: TunnelRuntimeCoordinator?
  private var packetTasks: [Task<Void, Never>] = []
  private var lifecycleTask: Task<Void, Never>?
  private var runtimeReporter: TunnelMobileRuntimeReporter?
  private let pathQueue = DispatchQueue(
    label: "io.rw0.mesh.tunnel.mobile.network-path",
    qos: .utility
  )
  private var pathMonitor: NWPathMonitor?
  private var observedInitialPath = false
  private let lifecycleGate = TunnelProviderLifecycleGate()

  override func startTunnel(
    options: [String: NSObject]?,
    completionHandler: @escaping (Error?) -> Void
  ) {
    if let options,
      options.keys.contains(TunnelIdentityRemovalRequest.startOptionKey)
    {
      guard options.count == 1,
        let requestData =
          options[TunnelIdentityRemovalRequest.startOptionKey] as? Data,
        let request = try? TunnelIdentityRemovalRequest.decodeExact(
          requestData
        )
      else {
        TunnelLog.record(.identityRemovalFailed)
        completionHandler(Self.failure("identity-removal-request-invalid"))
        return
      }
      TunnelLog.record(.identityRemovalRequested)
      Task {
        do {
          _ = try await self.removeIdentity(request)
          TunnelLog.record(.identityRemovalCompleted)
          completionHandler(Self.failure("identity-removed"))
        } catch {
          TunnelLog.record(.identityRemovalFailed)
          completionHandler(Self.failure("identity-removal-failed"))
        }
      }
      return
    }
    switch lifecycleGate.beginStart() {
    case .begin:
      break
    case .alreadyRunning:
      completionHandler(nil)
      return
    case .alreadyStarting:
      completionHandler(Self.failure("start-already-in-progress"))
      return
    case .stopped:
      completionHandler(Self.failure("start-cancelled"))
      return
    }
    TunnelLog.record(.startRequested)
    sequence &+= 1
    state = .starting
    Task {
      defer {
        self.lifecycleGate.finishStartFailure()
      }
      let configuration: TunnelConfigurationPayload
      do {
        configuration = try await self.resolveConfiguration(
          options: options
        )
      } catch let failure as TunnelStartupFailure {
        if self.lifecycleGate.isStopped() {
          self.completeCancelledStart(completionHandler)
          return
        }
        self.errorCode = failure.code
        self.state = .extensionError
        TunnelLog.record(failure.event)
        completionHandler(Self.failure(failure.code))
        return
      } catch {
        if self.lifecycleGate.isStopped() {
          self.completeCancelledStart(completionHandler)
          return
        }
        self.errorCode = "configuration-invalid"
        self.state = .extensionError
        TunnelLog.record(.configurationInvalid)
        completionHandler(Self.failure("configuration-invalid"))
        return
      }
      guard self.lifecycleGate.mayContinueStart() else {
        self.completeCancelledStart(completionHandler)
        return
      }
      let reporter: TunnelMobileRuntimeReporter
      do {
        reporter = TunnelMobileRuntimeReporter(
          configuration: configuration,
          lifecycle: try TunnelLifecycleSessionFactory.make(),
          instanceGeneration:
            try TunnelHighWaterKeychain
              .reserveRuntimeInstanceGeneration()
        )
        let outcome = try await reporter.report(
          state: .tunnelStarting
        )
        if let failure = Self.mobileRuntimeFailure(outcome) {
          throw failure
        }
        self.runtimeReporter = reporter
      } catch let failure as TunnelStartupFailure {
        if self.lifecycleGate.isStopped() {
          self.completeCancelledStart(completionHandler)
          return
        }
        self.errorCode = failure.code
        self.state = failure.state
        TunnelLog.record(failure.event)
        completionHandler(Self.failure(failure.code))
        return
      } catch {
        if self.lifecycleGate.isStopped() {
          self.completeCancelledStart(completionHandler)
          return
        }
        self.errorCode = "mobile-runtime-evidence-failed"
        self.state = .quarantined
        TunnelLog.record(.lifecycleRefreshFailed)
        completionHandler(
          Self.failure("mobile-runtime-evidence-failed")
        )
        return
      }
      guard self.lifecycleGate.mayContinueStart() else {
        self.runtimeReporter = nil
        self.completeCancelledStart(completionHandler)
        return
      }
      do {
        let limits = try TunnelPacketFlowPumpLimits()
        let coordinator = TunnelRuntimeCoordinator(
          configuration: configuration,
          engine: try TunnelEngineSessionFactory.make(
            configuration: configuration
          ),
          networkSettings: ProviderNetworkSettingsSession(
            provider: self
          ),
          limits: limits
        )
        let packetFlow = ProviderPacketFlowSession(
          provider: self,
          limits: limits
        )
        self.runtime = coordinator
        do {
          try await coordinator.start()
          let evidence = try await coordinator.runtimeEvidence(
            sequence: max(self.sequence, 1)
          )
          let outcome = try await reporter.report(
            state: .tunnelRunning,
            evidence: evidence
          )
          if let failure = Self.mobileRuntimeFailure(outcome) {
            throw failure
          }
          self.errorCode = nil
          self.state = .running
          guard self.lifecycleGate.markRunning() else {
            await coordinator.stop()
            if self.runtime === coordinator {
              self.runtime = nil
            }
            self.runtimeReporter = nil
            self.completeCancelledStart(completionHandler)
            return
          }
          self.startPathMonitoring(coordinator: coordinator)
          self.startLifecycleReporting(
            coordinator: coordinator,
            reporter: reporter
          )
          completionHandler(nil)
          self.startPacketLoops(
            coordinator: coordinator,
            packetFlow: packetFlow
          )
        } catch let failure as TunnelStartupFailure {
          await coordinator.stop()
          self.runtime = nil
          self.runtimeReporter = nil
          if self.lifecycleGate.isStopped() {
            self.completeCancelledStart(completionHandler)
            return
          }
          self.errorCode = failure.code
          self.state = failure.state
          TunnelLog.record(failure.event)
          completionHandler(Self.failure(failure.code))
        } catch {
          await coordinator.stop()
          self.runtime = nil
          self.runtimeReporter = nil
          if self.lifecycleGate.isStopped() {
            self.completeCancelledStart(completionHandler)
            return
          }
          self.errorCode = "engine-unavailable"
          self.state = .extensionError
          TunnelLog.record(.engineUnavailable)
          completionHandler(Self.failure("engine-unavailable"))
        }
      } catch {
        if self.lifecycleGate.isStopped() {
          self.completeCancelledStart(completionHandler)
          return
        }
        self.errorCode = "configuration-invalid"
        self.state = .extensionError
        TunnelLog.record(.configurationInvalid)
        completionHandler(Self.failure("configuration-invalid"))
      }
    }
  }

  private func resolveConfiguration(
    options: [String: NSObject]?
  ) async throws -> TunnelConfigurationPayload {
    guard
      let container = FileManager.default.containerURL(
        forSecurityApplicationGroupIdentifier: Self.applicationGroup
      )
    else {
      throw TunnelStartupFailure(
        code: "configuration-container-unavailable",
        event: .configurationContainerUnavailable
      )
    }
    let highWater = TunnelHighWaterKeychain()
    let store: TunnelConfigurationStore
    do {
      store = try TunnelConfigurationStore(
        containerURL: container,
        key: try TunnelHandoffKeychain.loadOrCreate(),
        highWater: highWater
      )
    } catch {
      throw TunnelStartupFailure(
        code: "configuration-invalid",
        event: .configurationInvalid
      )
    }
    do {
      if let current = try store.readCurrent() {
        if let options, !options.isEmpty {
          throw TunnelStartupFailure(
            code: "enrollment-request-rejected",
            event: .enrollmentRequestRejected
          )
        }
        return try await refresh(
          current: current,
          store: store
        )
      }
    } catch let failure as TunnelStartupFailure {
      throw failure
    } catch {
      throw TunnelStartupFailure(
        code: "configuration-invalid",
        event: .configurationInvalid
      )
    }
    guard let options,
      options.count == 1,
      let requestData =
        options[TunnelEnrollmentRequest.startOptionKey] as? Data
    else {
      throw TunnelStartupFailure(
        code: "configuration-unavailable",
        event: .configurationUnavailable
      )
    }
    let request: TunnelEnrollmentRequest
    do {
      request = try TunnelEnrollmentRequest.decodeExact(requestData)
    } catch {
      throw TunnelStartupFailure(
        code: "enrollment-request-rejected",
        event: .enrollmentRequestRejected
      )
    }
    do {
      let counter = try store.nextMonotonicCounter()
      let enrollment = try TunnelEnrollmentSessionFactory.make()
      let configuration = try await enrollment.enroll(
        request: request,
        monotonicCounter: counter
      )
      try store.stage(configuration)
      let activated = try store.activateCandidate()
      guard activated == configuration else {
        throw TunnelConfigurationStoreError.invalidSlot
      }
      return activated
    } catch {
      throw TunnelStartupFailure(
        code: "enrollment-failed",
        event: .enrollmentFailed
      )
    }
  }

  private func refresh(
    current: TunnelConfigurationPayload,
    store: TunnelConfigurationStore
  ) async throws -> TunnelConfigurationPayload {
    do {
      let counter = try store.nextMonotonicCounter()
      let lifecycle = try TunnelLifecycleSessionFactory.make()
      let outcome = try await lifecycle.refresh(
        current: current,
        monotonicCounter: counter
      )
      switch outcome.status {
      case .ready:
        guard let configuration = outcome.configuration,
          configuration.networkID == current.networkID,
          configuration.nodeID == current.nodeID,
          configuration.controlPlaneOrigin
            == current.controlPlaneOrigin,
          configuration.agentCredentialGeneration
            >= current.agentCredentialGeneration,
          configuration.certificateGeneration
            >= current.certificateGeneration,
          configuration.configRevision
            >= current.configRevision,
          configuration.monotonicCounter == counter
        else {
          throw TunnelConfigurationStoreError.invalidSlot
        }
        try store.stage(configuration)
        let activated = try store.activateCandidate()
        guard activated == configuration else {
          throw TunnelConfigurationStoreError.invalidSlot
        }
        return activated
      case .deferred:
        guard outcome.configuration == nil else {
          throw TunnelConfigurationStoreError.invalidSlot
        }
        TunnelLog.record(.lifecycleRefreshDeferred)
        return current
      case .unauthorized:
        throw TunnelStartupFailure(
          code: "agent-authorization-rejected",
          event: .agentAuthorizationRejected
        )
      }
    } catch let failure as TunnelStartupFailure {
      throw failure
    } catch {
      throw TunnelStartupFailure(
        code: "lifecycle-refresh-failed",
        event: .lifecycleRefreshFailed
      )
    }
  }

  override func stopTunnel(
    with reason: NEProviderStopReason,
    completionHandler: @escaping () -> Void
  ) {
    TunnelLog.record(.stopRequested)
    _ = lifecycleGate.latchStop()
    sequence &+= 1
    state = .stopping
    stopPathMonitoring()
    cancelPacketTasks()
    cancelLifecycleReporting()
    guard let runtime else {
      runtimeReporter = nil
      state = .stopped
      errorCode = nil
      completionHandler()
      return
    }
    Task {
      await runtime.stop()
      if self.runtime === runtime {
        self.runtime = nil
      }
      self.runtimeReporter = nil
      self.state = .stopped
      self.errorCode = nil
      completionHandler()
    }
  }

  override func sleep(completionHandler: @escaping () -> Void) {
    guard state == .running, let reporter = runtimeReporter else {
      completionHandler()
      return
    }
    state = .suspended
    cancelLifecycleReporting()
    Task {
      _ = try? await reporter.report(state: .suspended)
    }
    completionHandler()
  }

  override func wake() {
    guard
      state == .suspended,
      let coordinator = runtime,
      let reporter = runtimeReporter
    else {
      return
    }
    state = .running
    Task {
      do {
        let evidence = try await coordinator.runtimeEvidence(
          sequence: max(self.sequence, 1)
        )
        let outcome = try await reporter.report(
          state: .tunnelRunning,
          evidence: evidence
        )
        guard
          self.runtime === coordinator,
          self.state == .running
        else {
          return
        }
        if let failure = Self.mobileRuntimeFailure(outcome) {
          await self.mobileRuntimeFailed(
            coordinator: coordinator,
            failure: failure
          )
          return
        }
        if outcome.status == .deferred,
          await reporter.deferredEvidenceExceeded(.seconds(300))
        {
          await self.mobileRuntimeFailed(
            coordinator: coordinator,
            failure: Self.mobileEvidenceStaleFailure()
          )
          return
        }
        if outcome.status != .unsupported {
          self.startLifecycleReporting(
            coordinator: coordinator,
            reporter: reporter
          )
        }
      } catch {
        await self.mobileRuntimeFailed(
          coordinator: coordinator,
          failure: Self.mobileEvidenceInvalidFailure()
        )
      }
    }
  }

  override func handleAppMessage(
    _ messageData: Data,
    completionHandler: ((Data?) -> Void)?
  ) {
    if let request = try? TunnelIdentityRemovalRequest.decodeExact(
      messageData
    ) {
      TunnelLog.record(.identityRemovalRequested)
      Task {
        do {
          let outcome = try await self.removeIdentity(request)
          TunnelLog.record(.identityRemovalCompleted)
          completionHandler?(try? outcome.encoded())
          self.cancelTunnelWithError(Self.failure("identity-removed"))
        } catch {
          TunnelLog.record(.identityRemovalFailed)
          completionHandler?(nil)
        }
      }
      return
    }
    guard
      let request = try? TunnelControlRequest.decodeExact(messageData),
      sequence < UInt64.max
    else {
      TunnelLog.record(.statusRequestRejected)
      completionHandler?(nil)
      return
    }
    sequence += 1
    let responseSequence = sequence
    let responseState = state
    let responseErrorCode = errorCode
    let responseRuntime = runtime
    Task {
      do {
        let evidence: TunnelRuntimeEvidence
        if responseState == .running {
          guard let responseRuntime else {
            throw TunnelRuntimeCoordinatorError.invalidTransition
          }
          evidence = try await responseRuntime.runtimeEvidence(
            sequence: responseSequence
          )
        } else {
          evidence = TunnelRuntimeEvidence(
            sequence: responseSequence,
            state: responseState,
            errorCode:
              responseState == .extensionError
              ? responseErrorCode
              : nil
          )
        }
        let outcome = try TunnelControlOutcome(
          requestID: request.requestID,
          evidence: evidence
        )
        TunnelLog.record(.statusRequestAccepted)
        completionHandler?(try outcome.encoded())
      } catch {
        TunnelLog.record(.statusRequestRejected)
        completionHandler?(nil)
      }
    }
  }

  private func removeIdentity(
    _ request: TunnelIdentityRemovalRequest
  ) async throws -> TunnelIdentityRemovalOutcome {
    guard
      let container = FileManager.default.containerURL(
        forSecurityApplicationGroupIdentifier: Self.applicationGroup
      )
    else {
      throw TunnelStartupFailure(
        code: "configuration-container-unavailable",
        event: .configurationContainerUnavailable
      )
    }
    let store = try TunnelConfigurationStore(
      containerURL: container,
      key: try TunnelHandoffKeychain.loadOrCreate(),
      highWater: TunnelHighWaterKeychain()
    )
    guard let current = try store.readCurrent(),
      current.nodeID == request.confirmationNodeID
    else {
      throw TunnelStartupFailure(
        code: "identity-removal-context-mismatch",
        event: .identityRemovalFailed,
        state: .quarantined
      )
    }

    state = .stopping
    stopPathMonitoring()
    cancelPacketTasks()
    cancelLifecycleReporting()
    if let coordinator = runtime {
      await coordinator.stop()
    }
    runtime = nil
    runtimeReporter = nil

    // Delete extension-only authority first. Configuration slots are erased
    // only after all fixed Keychain deletes succeed, leaving an exact context
    // for a safe retry after any partial Keychain failure.
    try await TunnelIdentityRemovalSessionFactory.make().remove()
    try TunnelConfigurationStore.eraseAll(containerURL: container)
    errorCode = nil
    state = .stopped
    return try TunnelIdentityRemovalOutcome(
      requestID: request.requestID,
      nodeID: current.nodeID
    )
  }

  private func startPacketLoops(
    coordinator: TunnelRuntimeCoordinator,
    packetFlow: ProviderPacketFlowSession
  ) {
    cancelPacketTasks()
    let appleToEngine = Task { [weak self] in
      do {
        while !Task.isCancelled {
          let packets = try await packetFlow.read()
          try Task.checkCancellation()
          try await coordinator.sendFromApple(packets)
        }
      } catch is CancellationError {
        return
      } catch {
        await self?.packetFlowFailed(coordinator: coordinator)
      }
    }
    let engineToApple = Task { [weak self] in
      do {
        while !Task.isCancelled {
          let packets = try await coordinator.receiveForApple()
          try Task.checkCancellation()
          try packetFlow.write(packets)
        }
      } catch is CancellationError {
        return
      } catch {
        await self?.packetFlowFailed(coordinator: coordinator)
      }
    }
    packetTasks = [appleToEngine, engineToApple]
    if runtime !== coordinator || state != .running {
      cancelPacketTasks()
    }
  }

  private func startLifecycleReporting(
    coordinator: TunnelRuntimeCoordinator,
    reporter: TunnelMobileRuntimeReporter
  ) {
    cancelLifecycleReporting()
    lifecycleTask = Task { [weak self] in
      while !Task.isCancelled {
        do {
          try await Task.sleep(for: .seconds(60))
          try Task.checkCancellation()
          let evidence = try await coordinator.runtimeEvidence(
            sequence: 1
          )
          let outcome = try await reporter.report(
            state: .tunnelRunning,
            evidence: evidence
          )
          guard let self,
            self.runtime === coordinator,
            self.state == .running
          else {
            return
          }
          if let failure = Self.mobileRuntimeFailure(outcome) {
            await self.mobileRuntimeFailed(
              coordinator: coordinator,
              failure: failure
            )
            return
          }
          if outcome.status == .unsupported {
            return
          }
          if outcome.status == .deferred,
            await reporter.deferredEvidenceExceeded(.seconds(300))
          {
            await self.mobileRuntimeFailed(
              coordinator: coordinator,
              failure: Self.mobileEvidenceStaleFailure()
            )
            return
          }
        } catch is CancellationError {
          return
        } catch {
          guard let self else {
            return
          }
          await self.mobileRuntimeFailed(
            coordinator: coordinator,
            failure: Self.mobileEvidenceInvalidFailure()
          )
          return
        }
      }
    }
  }

  private func cancelLifecycleReporting() {
    lifecycleTask?.cancel()
    lifecycleTask = nil
  }

  private func completeCancelledStart(
    _ completionHandler: @escaping (Error?) -> Void
  ) {
    runtimeReporter = nil
    errorCode = nil
    state = .stopped
    completionHandler(Self.failure("start-cancelled"))
  }

  private func startPathMonitoring(
    coordinator: TunnelRuntimeCoordinator
  ) {
    stopPathMonitoring()
    observedInitialPath = false
    let monitor = NWPathMonitor()
    monitor.pathUpdateHandler = { [weak self] _ in
      guard let self else {
        return
      }
      guard self.observedInitialPath else {
        self.observedInitialPath = true
        return
      }
      Task {
        do {
          try await coordinator.rebind()
        } catch {
          await self.networkRebindFailed(
            coordinator: coordinator
          )
        }
      }
    }
    pathMonitor = monitor
    monitor.start(queue: pathQueue)
  }

  private func stopPathMonitoring() {
    pathMonitor?.cancel()
    pathMonitor = nil
    observedInitialPath = false
  }

  private func networkRebindFailed(
    coordinator: TunnelRuntimeCoordinator
  ) async {
    guard runtime === coordinator, state == .running else {
      return
    }
    runtime = nil
    stopPathMonitoring()
    cancelPacketTasks()
    cancelLifecycleReporting()
    runtimeReporter = nil
    errorCode = "network-rebind-failed"
    state = .extensionError
    TunnelLog.record(.networkRebindFailed)
    await coordinator.stop()
    guard runtime == nil, state == .extensionError else {
      return
    }
    cancelTunnelWithError(Self.failure("network-rebind-failed"))
  }

  private func packetFlowFailed(
    coordinator: TunnelRuntimeCoordinator
  ) async {
    guard runtime === coordinator, state == .running else {
      return
    }
    runtime = nil
    stopPathMonitoring()
    cancelPacketTasks()
    cancelLifecycleReporting()
    runtimeReporter = nil
    errorCode = "packet-flow-failed"
    state = .extensionError
    TunnelLog.record(.packetFlowFailed)
    await coordinator.stop()
    guard runtime == nil, state == .extensionError else {
      return
    }
    cancelTunnelWithError(Self.failure("packet-flow-failed"))
  }

  private func cancelPacketTasks() {
    for task in packetTasks {
      task.cancel()
    }
    packetTasks.removeAll(keepingCapacity: false)
  }

  private func mobileRuntimeFailed(
    coordinator: TunnelRuntimeCoordinator,
    failure: TunnelStartupFailure
  ) async {
    guard runtime === coordinator,
      state == .running || state == .suspended
    else {
      return
    }
    runtime = nil
    stopPathMonitoring()
    cancelPacketTasks()
    cancelLifecycleReporting()
    runtimeReporter = nil
    errorCode = failure.code
    state = failure.state
    TunnelLog.record(failure.event)
    await coordinator.stop()
    cancelTunnelWithError(Self.failure(failure.code))
  }

  private static func mobileRuntimeFailure(
    _ outcome: TunnelMobileRuntimeReportOutcome
  ) -> TunnelStartupFailure? {
    switch outcome.status {
    case .accepted, .deferred, .unsupported:
      return nil
    case .unauthorized:
      return TunnelStartupFailure(
        code: "agent-authorization-rejected",
        event: .agentAuthorizationRejected,
        state: .quarantined
      )
    case .refreshRequired:
      return TunnelStartupFailure(
        code: "mobile-runtime-refresh-required",
        event: .lifecycleRefreshFailed,
        state: .quarantined
      )
    }
  }

  private static func mobileEvidenceStaleFailure()
    -> TunnelStartupFailure
  {
    TunnelStartupFailure(
      code: "mobile-runtime-evidence-stale",
      event: .lifecycleRefreshFailed,
      state: .quarantined
    )
  }

  private static func mobileEvidenceInvalidFailure()
    -> TunnelStartupFailure
  {
    TunnelStartupFailure(
      code: "mobile-runtime-evidence-invalid",
      event: .lifecycleRefreshFailed,
      state: .quarantined
    )
  }

  private static func failure(_ code: String) -> NSError {
    NSError(
      domain: "io.rw0.mesh.tunnel.mobile",
      code: 1,
      userInfo: [
        NSLocalizedDescriptionKey: code
      ]
    )
  }
}

private struct TunnelStartupFailure: Error {
  let code: String
  let event: TunnelLogEvent
  let state: TunnelLifecycleState

  init(
    code: String,
    event: TunnelLogEvent,
    state: TunnelLifecycleState = .extensionError
  ) {
    self.code = code
    self.event = event
    self.state = state
  }
}
