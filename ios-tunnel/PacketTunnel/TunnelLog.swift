import OSLog

enum TunnelLogEvent: String, CaseIterable {
  case startRequested = "start-requested"
  case providerBootstrapReady = "provider-bootstrap-ready"
  case enrollmentHandoffAccepted = "enrollment-handoff-accepted"
  case configurationContainerUnavailable = "configuration-container-unavailable"
  case configurationUnavailable = "configuration-unavailable"
  case configurationInvalid = "configuration-invalid"
  case enrollmentRequestRejected = "enrollment-request-rejected"
  case enrollmentFailed = "enrollment-failed"
  case lifecycleRefreshDeferred = "lifecycle-refresh-deferred"
  case lifecycleRefreshFailed = "lifecycle-refresh-failed"
  case agentAuthorizationRejected = "agent-authorization-rejected"
  case engineUnavailable = "engine-unavailable"
  case networkRebindFailed = "network-rebind-failed"
  case packetFlowFailed = "packet-flow-failed"
  case stopRequested = "stop-requested"
  case statusRequestAccepted = "status-request-accepted"
  case statusRequestRejected = "status-request-rejected"
  case identityRemovalRequested = "identity-removal-requested"
  case identityRemovalCompleted = "identity-removal-completed"
  case identityRemovalFailed = "identity-removal-failed"
}

enum TunnelLog {
  private static let logger = Logger(
    subsystem: "io.rw0.mesh.tunnel.mobile.packet-tunnel",
    category: "lifecycle"
  )

  static func record(_ event: TunnelLogEvent) {
    switch event {
    case .startRequested:
      logger.notice("start-requested")
    case .providerBootstrapReady:
      logger.notice("provider-bootstrap-ready")
    case .enrollmentHandoffAccepted:
      logger.notice("enrollment-handoff-accepted")
    case .configurationContainerUnavailable:
      logger.error("configuration-container-unavailable")
    case .configurationUnavailable:
      logger.error("configuration-unavailable")
    case .configurationInvalid:
      logger.error("configuration-invalid")
    case .enrollmentRequestRejected:
      logger.error("enrollment-request-rejected")
    case .enrollmentFailed:
      logger.error("enrollment-failed")
    case .lifecycleRefreshDeferred:
      logger.notice("lifecycle-refresh-deferred")
    case .lifecycleRefreshFailed:
      logger.error("lifecycle-refresh-failed")
    case .agentAuthorizationRejected:
      logger.error("agent-authorization-rejected")
    case .engineUnavailable:
      logger.error("engine-unavailable")
    case .networkRebindFailed:
      logger.error("network-rebind-failed")
    case .packetFlowFailed:
      logger.error("packet-flow-failed")
    case .stopRequested:
      logger.notice("stop-requested")
    case .statusRequestAccepted:
      logger.notice("status-request-accepted")
    case .statusRequestRejected:
      logger.error("status-request-rejected")
    case .identityRemovalRequested:
      logger.notice("identity-removal-requested")
    case .identityRemovalCompleted:
      logger.notice("identity-removal-completed")
    case .identityRemovalFailed:
      logger.error("identity-removal-failed")
    }
  }
}
