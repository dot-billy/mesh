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
  private var runtimeGeneration: UInt64?
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
  private var startupTask: Task<Void, Never>?
  private let terminalCleanupLock = NSLock()
  private var terminalCleanupBarrier: TunnelTerminalCleanupBarrier?

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
    guard
      let options,
      options.count == 1,
      let authorizationData =
        options[TunnelStartAuthorization.startOptionKey] as? Data,
      let authorization = try? TunnelStartAuthorization.decodeExact(
        authorizationData
      )
    else {
      completionHandler(Self.failure("start-authorization-required"))
      return
    }
    let complete = completionHandler
    switch lifecycleGate.beginStart() {
    case .begin(let generation):
      startupTask = continueTunnelStart(
        authorization: authorization,
        recordStart: true,
        generation: generation,
        completionHandler: complete
      )
      return
    case .alreadyRunning:
      complete(nil)
      return
    case .alreadyStarting:
      complete(Self.failure("start-already-in-progress"))
      return
    case .stopped:
      complete(Self.failure("start-cancelled"))
      return
    }
  }

  private func continueTunnelStart(
    authorization: TunnelStartAuthorization,
    recordStart: Bool,
    generation: UInt64,
    completionHandler complete: @escaping (Error?) -> Void
  ) -> Task<Void, Never> {
    if recordStart {
      TunnelLog.record(.startRequested)
      sequence &+= 1
      state = .starting
    }
    return Task {
      defer {
        _ = self.lifecycleGate.finishStartFailure(generation)
        if self.lifecycleGate.isLatest(generation) {
          self.startupTask = nil
        }
      }
      guard
        !Task.isCancelled,
        self.lifecycleGate.mayContinueStart(generation)
      else {
        self.completeCancelledStart(complete)
        return
      }
      let configuration: TunnelConfigurationPayload
      do {
        configuration = try await self.resolveConfiguration(
          authorization: authorization
        )
      } catch let failure as TunnelStartupFailure {
        if !self.lifecycleGate.mayContinueStart(generation) {
          self.completeCancelledStart(complete)
          return
        }
        self.completeStartFailure(
          failure,
          generation: generation,
          completionHandler: complete
        )
        return
      } catch {
        if !self.lifecycleGate.mayContinueStart(generation) {
          self.completeCancelledStart(complete)
          return
        }
        self.completeStartFailure(
          TunnelStartupFailure(
            code: "configuration-invalid",
            event: .configurationInvalid
          ),
          generation: generation,
          completionHandler: complete
        )
        return
      }
      guard self.lifecycleGate.mayContinueStart(generation) else {
        self.completeCancelledStart(complete)
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
        do {
          try await coordinator.start()
          guard self.lifecycleGate.mayContinueStart(generation) else {
            await coordinator.stop()
            self.completeCancelledStart(complete)
            return
          }
          try Task.checkCancellation()
          guard self.lifecycleGate.mayContinueStart(generation) else {
            await coordinator.stop()
            self.completeCancelledStart(complete)
            return
          }
          guard self.lifecycleGate.markRunning(
            generation,
            commit: {
              self.runtime = coordinator
              self.runtimeGeneration = generation
              self.runtimeReporter = nil
              self.errorCode = nil
              self.state = .running
              self.startPathMonitoring(coordinator: coordinator)
              self.startPacketLoops(
                coordinator: coordinator,
                packetFlow: packetFlow
              )
            }
          ) else {
            await coordinator.stop()
            self.completeCancelledStart(complete)
            return
          }
          complete(nil)
          self.startPostConnectControlPlaneWork(
            coordinator: coordinator,
            configuration: configuration,
            generation: generation
          )
        } catch let failure as TunnelStartupFailure {
          await coordinator.stop()
          if !self.lifecycleGate.mayContinueStart(generation) {
            self.completeCancelledStart(complete)
            return
          }
          self.completeStartFailure(
            failure,
            generation: generation,
            completionHandler: complete
          )
        } catch {
          await coordinator.stop()
          if !self.lifecycleGate.mayContinueStart(generation) {
            self.completeCancelledStart(complete)
            return
          }
          self.completeStartFailure(
            TunnelStartupFailure(
              code: "engine-unavailable",
              event: .engineUnavailable
            ),
            generation: generation,
            completionHandler: complete
          )
        }
      } catch {
        if !self.lifecycleGate.mayContinueStart(generation) {
          self.completeCancelledStart(complete)
          return
        }
        self.completeStartFailure(
          TunnelStartupFailure(
            code: "configuration-invalid",
            event: .configurationInvalid
          ),
          generation: generation,
          completionHandler: complete
        )
      }
    }
  }

  private func resolveConfiguration(
    authorization: TunnelStartAuthorization
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
        guard authorization.matches(current) else {
          throw TunnelStartupFailure(
            code: "start-authorization-invalid",
            event: .configurationInvalid
          )
        }
        try TunnelHighWaterKeychain.consumeStartAuthorization(
          matching: authorization
        )
        return current
      }
    } catch let failure as TunnelStartupFailure {
      throw failure
    } catch {
      throw TunnelStartupFailure(
        code: "configuration-invalid",
        event: .configurationInvalid
      )
    }
    throw TunnelStartupFailure(
      code: "configuration-unavailable",
      event: .configurationUnavailable
    )
  }

  override func stopTunnel(
    with reason: NEProviderStopReason,
    completionHandler: @escaping () -> Void
  ) {
    TunnelLog.record(.stopRequested)
    let pendingTerminalCleanup = latchStopAndCaptureTerminalCleanup()
    let pendingStartup = startupTask
    pendingStartup?.cancel()
    startupTask = nil
    sequence &+= 1
    state = .stopping
    stopPathMonitoring()
    cancelPacketTasks()
    cancelLifecycleReporting()
    guard let runtime else {
      if let pendingStartup {
        Task {
          await pendingTerminalCleanup?.wait()
          await pendingStartup.value
          if let attachedRuntime = self.runtime {
            await attachedRuntime.stop()
            if self.runtime === attachedRuntime {
              self.runtime = nil
              self.runtimeGeneration = nil
            }
          }
          let reporter = self.runtimeReporter
          self.runtimeReporter = nil
          await reporter?.terminalize()
          self.runtimeGeneration = nil
          self.state = .stopped
          self.errorCode = nil
          self.lifecycleGate.finishStop()
          completionHandler()
          self.reportStoppedBestEffort(reporter)
        }
        return
      }
      let reporter = runtimeReporter
      runtimeReporter = nil
      Task {
        await pendingTerminalCleanup?.wait()
        await reporter?.terminalize()
        self.runtimeGeneration = nil
        self.state = .stopped
        self.errorCode = nil
        self.lifecycleGate.finishStop()
        completionHandler()
        self.reportStoppedBestEffort(reporter)
      }
      return
    }
    Task {
      await pendingTerminalCleanup?.wait()
      if let pendingStartup {
        await pendingStartup.value
      }
      await runtime.stop()
      if self.runtime === runtime {
        self.runtime = nil
        self.runtimeGeneration = nil
      }
      let reporter = self.runtimeReporter
      self.runtimeReporter = nil
      await reporter?.terminalize()
      self.state = .stopped
      self.errorCode = nil
      self.lifecycleGate.finishStop()
      completionHandler()
      self.reportStoppedBestEffort(reporter)
    }
  }

  private func beginTerminalCleanup() -> TunnelTerminalCleanupBarrier? {
    terminalCleanupLock.lock()
    defer { terminalCleanupLock.unlock() }
    guard !lifecycleGate.latchStop() else {
      return nil
    }
    let barrier = TunnelTerminalCleanupBarrier()
    terminalCleanupBarrier = barrier
    return barrier
  }

  private func latchStopAndCaptureTerminalCleanup()
    -> TunnelTerminalCleanupBarrier?
  {
    terminalCleanupLock.lock()
    defer { terminalCleanupLock.unlock() }
    _ = lifecycleGate.latchStop()
    return terminalCleanupBarrier
  }

  private func finishTerminalCleanup(
    _ barrier: TunnelTerminalCleanupBarrier
  ) {
    barrier.finish()
    terminalCleanupLock.lock()
    if terminalCleanupBarrier === barrier {
      terminalCleanupBarrier = nil
    }
    terminalCleanupLock.unlock()
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
      let reporter = runtimeReporter,
      let generation = runtimeGeneration
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
          self.lifecycleGate.isCurrent(generation),
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
            reporter: reporter,
            generation: generation
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

    guard let cleanupBarrier = beginTerminalCleanup() else {
      throw TunnelStartupFailure(
        code: "identity-removal-failed",
        event: .identityRemovalFailed,
        state: .quarantined
      )
    }
    defer {
      finishTerminalCleanup(cleanupBarrier)
    }
    state = .stopping
    stopPathMonitoring()
    cancelPacketTasks()
    cancelLifecycleReporting()
    let reporter = runtimeReporter
    if let coordinator = runtime {
      await coordinator.stop()
    }
    runtime = nil
    runtimeGeneration = nil
    runtimeReporter = nil
    await reporter?.terminalize()
    reportStoppedBestEffort(reporter)

    // Delete shared app-and-extension authority first. Configuration slots are erased
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
    reporter: TunnelMobileRuntimeReporter,
    generation: UInt64
  ) {
    let task = Task { [weak self] in
      while !Task.isCancelled {
        do {
          try await Task.sleep(for: .seconds(60))
          try Task.checkCancellation()
          guard let self,
            self.lifecycleGate.isCurrent(generation),
            self.runtime === coordinator,
            self.state == .running
          else {
            return
          }
          let evidence = try await coordinator.runtimeEvidence(
            sequence: 1
          )
          guard
            self.lifecycleGate.isCurrent(generation),
            self.runtime === coordinator,
            self.state == .running
          else {
            return
          }
          let outcome = try await reporter.report(
            state: .tunnelRunning,
            evidence: evidence
          )
          guard
            self.lifecycleGate.isCurrent(generation),
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
    guard lifecycleGate.commitIfCurrent(
      generation,
      commit: {
        self.lifecycleTask?.cancel()
        self.lifecycleTask = task
      }
    ) else {
      task.cancel()
      reportStoppedBestEffort(reporter)
      return
    }
  }

  private func startPostConnectControlPlaneWork(
    coordinator: TunnelRuntimeCoordinator,
    configuration: TunnelConfigurationPayload,
    generation: UInt64
  ) {
    let task = Task { [weak self] in
      guard let self else {
        return
      }
      do {
        guard
          self.lifecycleGate.isCurrent(generation),
          self.runtime === coordinator,
          self.state == .running
        else {
          return
        }
        let reporter = TunnelMobileRuntimeReporter(
          configuration: configuration,
          lifecycle: try TunnelLifecycleSessionFactory.make(),
          instanceGeneration:
            try TunnelHighWaterKeychain
              .reserveRuntimeInstanceGeneration()
        )
        guard self.lifecycleGate.commitIfCurrent(
          generation,
          commit: {
            self.runtimeReporter = reporter
          }
        ) else {
          await reporter.terminalize()
          self.reportStoppedBestEffort(reporter)
          return
        }
        let evidence = try await coordinator.runtimeEvidence(
          sequence: max(self.sequence, 1)
        )
        guard
          self.lifecycleGate.isCurrent(generation),
          self.runtime === coordinator,
          self.state == .running
        else {
          await reporter.terminalize()
          self.reportStoppedBestEffort(reporter)
          return
        }
        let outcome = try await reporter.report(
          state: .tunnelRunning,
          evidence: evidence
        )
        guard
          self.lifecycleGate.isCurrent(generation),
          self.runtime === coordinator,
          self.state == .running
        else {
          await reporter.terminalize()
          self.reportStoppedBestEffort(reporter)
          return
        }
        if let failure = Self.mobileRuntimeFailure(outcome) {
          await self.mobileRuntimeFailed(
            coordinator: coordinator,
            failure: failure
          )
          return
        }
        if outcome.status != .unsupported {
          self.startLifecycleReporting(
            coordinator: coordinator,
            reporter: reporter,
            generation: generation
          )
        }
      } catch is CancellationError {
        return
      } catch {
        guard
          self.runtime === coordinator,
          self.state == .running
        else {
          return
        }
        TunnelLog.record(.lifecycleRefreshDeferred)
      }
    }
    guard lifecycleGate.commitIfCurrent(
      generation,
      commit: {
        self.lifecycleTask?.cancel()
        self.lifecycleTask = task
      }
    ) else {
      task.cancel()
      return
    }
  }

  private func reportStoppedBestEffort(
    _ reporter: TunnelMobileRuntimeReporter?
  ) {
    guard let reporter else {
      return
    }
    Task {
      _ = try? await reporter.reportStopped()
    }
  }

  private func cancelLifecycleReporting() {
    lifecycleTask?.cancel()
    lifecycleTask = nil
  }

  private func completeCancelledStart(
    _ completionHandler: @escaping (Error?) -> Void
  ) {
    completionHandler(Self.failure("start-cancelled"))
  }

  private func completeStartFailure(
    _ failure: TunnelStartupFailure,
    generation: UInt64,
    completionHandler: @escaping (Error?) -> Void
  ) {
    guard lifecycleGate.finishStartFailure(
      generation,
      commit: {
        self.errorCode = failure.code
        self.state = failure.state
        TunnelLog.record(failure.event)
      }
    ) else {
      completeCancelledStart(completionHandler)
      return
    }
    completionHandler(Self.failure(failure.code))
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
    guard let cleanupBarrier = beginTerminalCleanup() else {
      return
    }
    defer {
      finishTerminalCleanup(cleanupBarrier)
    }
    runtime = nil
    runtimeGeneration = nil
    stopPathMonitoring()
    cancelPacketTasks()
    cancelLifecycleReporting()
    let reporter = runtimeReporter
    runtimeReporter = nil
    await reporter?.terminalize()
    reportStoppedBestEffort(reporter)
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
    guard let cleanupBarrier = beginTerminalCleanup() else {
      return
    }
    defer {
      finishTerminalCleanup(cleanupBarrier)
    }
    runtime = nil
    runtimeGeneration = nil
    stopPathMonitoring()
    cancelPacketTasks()
    cancelLifecycleReporting()
    let reporter = runtimeReporter
    runtimeReporter = nil
    await reporter?.terminalize()
    reportStoppedBestEffort(reporter)
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
    guard let cleanupBarrier = beginTerminalCleanup() else {
      return
    }
    defer {
      finishTerminalCleanup(cleanupBarrier)
    }
    runtime = nil
    runtimeGeneration = nil
    stopPathMonitoring()
    cancelPacketTasks()
    cancelLifecycleReporting()
    let reporter = runtimeReporter
    runtimeReporter = nil
    await reporter?.terminalize()
    reportStoppedBestEffort(reporter)
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

  private static func failure(
    _ code: String,
    requestID: String? = nil
  ) -> NSError {
    var userInfo: [String: Any] = [
      NSLocalizedDescriptionKey: code,
      TunnelProviderFailureContract.schemaKey:
        TunnelProviderFailureContract.schema,
      TunnelProviderFailureContract.codeKey: code,
    ]
    if let requestID {
      userInfo[TunnelProviderFailureContract.requestIDKey] = requestID
    }
    return NSError(
      domain: TunnelProviderFailureContract.domain,
      code: 1,
      userInfo: userInfo
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
