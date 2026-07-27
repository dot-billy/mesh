import CryptoKit
import Darwin
import Foundation

public enum TunnelContractError: Error, Equatable {
  case invalidDocument
  case unsupportedSchema
  case invalidField(String)
  case authenticationFailed
}

public enum TunnelLifecycleState: String, Codable, Sendable {
  case stopped
  case starting
  case running
  case stopping
  case suspended
  case stale
  case quarantined
  case revoked
  case extensionError = "extension-error"
}

public enum TunnelControlOperation: String, Codable, Sendable {
  case status
}

public enum TunnelIdentityScope {
  public static let primaryID = "primary"
}

public enum TunnelProviderFailureContract {
  public static let domain = "io.rw0.mesh.tunnel.mobile"
  public static let schema = "mesh-ios-provider-failure-v1"
  public static let schemaKey = "MeshProviderFailureSchema"
  public static let codeKey = "MeshProviderFailureCode"
  public static let requestIDKey = "MeshEnrollmentRequestID"
}

public enum TunnelProviderObservedStatus: Equatable, Sendable {
  case disconnected
  case connecting
  case connected
  case reasserting
  case disconnecting
  case invalid
}

public enum TunnelProviderStartDecision: Equatable, Sendable {
  case pending
  case connected
  case disconnectedAfterProgress
  case invalid
}

public struct TunnelProviderStartObservation: Sendable {
  private var observedProgress = false

  public init() {}

  public mutating func observe(
    _ status: TunnelProviderObservedStatus
  ) -> TunnelProviderStartDecision {
    switch status {
    case .connected:
      return .connected
    case .connecting, .reasserting:
      observedProgress = true
      return .pending
    case .disconnected:
      return observedProgress ? .disconnectedAfterProgress : .pending
    case .disconnecting, .invalid:
      return .invalid
    }
  }
}

public struct TunnelProviderObservationBudget: Sendable {
  public static let limit = Duration.seconds(90)

  public init() {}

  public func remaining(after elapsed: Duration) -> Duration? {
    guard elapsed >= .zero, elapsed < Self.limit else {
      return nil
    }
    return Self.limit - elapsed
  }
}

public enum TunnelProviderStartProof {
  public static func accepts(
    finalStatus: TunnelProviderObservedStatus,
    connectionDateChanged: Bool,
    sameOriginIdentity: Bool
  ) -> Bool {
    finalStatus == .connected
      && connectionDateChanged
      && sameOriginIdentity
  }
}

public enum TunnelProviderFailureClassifier {
  public static let genericCode = "apple-vpn-disconnected"

  public static func classify(
    domain: String,
    schema: String?,
    code: String?,
    requestID: String?,
    expectedRequestID: String?,
    allowedCodes: Set<String>
  ) -> String {
    guard
      domain == TunnelProviderFailureContract.domain,
      schema == TunnelProviderFailureContract.schema,
      requestID == expectedRequestID,
      let code,
      allowedCodes.contains(code)
    else {
      return genericCode
    }
    return code
  }
}

public final class TunnelOneShotResult<Value>: @unchecked Sendable {
  private let lock = NSLock()
  private var handler: ((Value) -> Void)?

  public init(_ handler: @escaping (Value) -> Void) {
    self.handler = handler
  }

  @discardableResult
  public func resolve(_ value: Value) -> Bool {
    lock.lock()
    let handler = handler
    self.handler = nil
    lock.unlock()
    guard let handler else {
      return false
    }
    handler(value)
    return true
  }
}

public struct TunnelEnrollmentRequest: Codable, Equatable, Sendable {
  public static let schema = "mesh-ios-tunnel-enrollment-v1"
  public static let maximumDocumentBytes = 8 * 1024

  public let schema: String
  public let requestID: String
  public let serverOrigin: String
  public let enrollmentToken: String

  public init(
    requestID: String,
    serverOrigin: String,
    enrollmentToken: String
  ) throws {
    schema = Self.schema
    self.requestID = requestID
    self.serverOrigin = try ContractField.httpsOrigin(
      serverOrigin,
      name: "serverOrigin"
    )
    self.enrollmentToken = enrollmentToken
    try validate()
  }

  public static func normalizedOrigin(_ value: String) throws -> String {
    try ContractField.httpsOrigin(value, name: "serverOrigin")
  }

  public func encoded() throws -> Data {
    try validate()
    return try ExactJSON.canonical(self)
  }

  public static func decodeExact(_ data: Data) throws -> Self {
    try ExactJSON.requireObject(
      data,
      keys: [
        "schema",
        "requestID",
        "serverOrigin",
        "enrollmentToken",
      ],
      maximumBytes: maximumDocumentBytes
    )
    let value = try JSONDecoder().decode(Self.self, from: data)
    try value.validate()
    guard try ExactJSON.canonical(value) == data else {
      throw TunnelContractError.invalidDocument
    }
    return value
  }

  private func validate() throws {
    guard schema == Self.schema else {
      throw TunnelContractError.unsupportedSchema
    }
    try ContractField.identifier(requestID, name: "requestID")
    guard
      try ContractField.httpsOrigin(
        serverOrigin,
        name: "serverOrigin"
      ) == serverOrigin
    else {
      throw TunnelContractError.invalidField("serverOrigin")
    }
    try ContractField.base64URL(
      enrollmentToken,
      bytes: 32,
      name: "enrollmentToken"
    )
  }
}

public struct TunnelInitialEnrollmentIntent:
  Codable,
  Equatable,
  Sendable
{
  public static let schema = "mesh-ios-initial-enrollment-intent-v1"
  public static let maximumDocumentBytes = 4 * 1024

  public let schema: String
  public let controlPlaneOrigin: String
  public let nodeID: String
  public let networkID: String
  public let monotonicCounter: UInt64

  public init(
    controlPlaneOrigin: String,
    nodeID: String,
    networkID: String,
    monotonicCounter: UInt64
  ) throws {
    schema = Self.schema
    self.controlPlaneOrigin = try ContractField.httpsOrigin(
      controlPlaneOrigin,
      name: "controlPlaneOrigin"
    )
    self.nodeID = nodeID
    self.networkID = networkID
    self.monotonicCounter = monotonicCounter
    try validate()
  }

  public init(configuration: TunnelConfigurationPayload) throws {
    try self.init(
      controlPlaneOrigin: configuration.controlPlaneOrigin,
      nodeID: configuration.nodeID,
      networkID: configuration.networkID,
      monotonicCounter: configuration.monotonicCounter
    )
  }

  public func encoded() throws -> Data {
    try validate()
    return try ExactJSON.canonical(self)
  }

  public static func decodeExact(_ data: Data) throws -> Self {
    try ExactJSON.requireObject(
      data,
      keys: [
        "schema",
        "controlPlaneOrigin",
        "nodeID",
        "networkID",
        "monotonicCounter",
      ],
      maximumBytes: maximumDocumentBytes
    )
    let value = try JSONDecoder().decode(Self.self, from: data)
    try value.validate()
    guard try ExactJSON.canonical(value) == data else {
      throw TunnelContractError.invalidDocument
    }
    return value
  }

  private func validate() throws {
    guard schema == Self.schema else {
      throw TunnelContractError.unsupportedSchema
    }
    guard
      try ContractField.httpsOrigin(
        controlPlaneOrigin,
        name: "controlPlaneOrigin"
      ) == controlPlaneOrigin
    else {
      throw TunnelContractError.invalidField("controlPlaneOrigin")
    }
    try ContractField.identifier(nodeID, name: "nodeID")
    try ContractField.identifier(networkID, name: "networkID")
    guard monotonicCounter > 0 else {
      throw TunnelContractError.invalidField("monotonicCounter")
    }
  }
}

public struct TunnelStartAuthorization:
  Codable,
  Equatable,
  Sendable
{
  public static let schema = "mesh-ios-start-authorization-v1"
  public static let startOptionKey = "meshStartAuthorization"
  public static let maximumDocumentBytes = 4 * 1024

  public let schema: String
  public let nonce: String
  public let controlPlaneOrigin: String
  public let nodeID: String
  public let networkID: String
  public let monotonicCounter: UInt64

  public init(
    nonce: String,
    configuration: TunnelConfigurationPayload
  ) throws {
    schema = Self.schema
    self.nonce = nonce
    controlPlaneOrigin = configuration.controlPlaneOrigin
    nodeID = configuration.nodeID
    networkID = configuration.networkID
    monotonicCounter = configuration.monotonicCounter
    try validate()
  }

  public func encoded() throws -> Data {
    try validate()
    return try ExactJSON.canonical(self)
  }

  public static func decodeExact(_ data: Data) throws -> Self {
    try ExactJSON.requireObject(
      data,
      keys: [
        "schema",
        "nonce",
        "controlPlaneOrigin",
        "nodeID",
        "networkID",
        "monotonicCounter",
      ],
      maximumBytes: maximumDocumentBytes
    )
    let value = try JSONDecoder().decode(Self.self, from: data)
    try value.validate()
    guard try ExactJSON.canonical(value) == data else {
      throw TunnelContractError.invalidDocument
    }
    return value
  }

  public func matches(_ configuration: TunnelConfigurationPayload) -> Bool {
    controlPlaneOrigin == configuration.controlPlaneOrigin
      && nodeID == configuration.nodeID
      && networkID == configuration.networkID
      && monotonicCounter == configuration.monotonicCounter
  }

  private func validate() throws {
    guard schema == Self.schema else {
      throw TunnelContractError.unsupportedSchema
    }
    try ContractField.base64URL(nonce, bytes: 32, name: "nonce")
    guard
      try ContractField.httpsOrigin(
        controlPlaneOrigin,
        name: "controlPlaneOrigin"
      ) == controlPlaneOrigin
    else {
      throw TunnelContractError.invalidField("controlPlaneOrigin")
    }
    try ContractField.identifier(nodeID, name: "nodeID")
    try ContractField.identifier(networkID, name: "networkID")
    guard monotonicCounter > 0 else {
      throw TunnelContractError.invalidField("monotonicCounter")
    }
  }
}

public struct TunnelControlRequest: Codable, Equatable, Sendable {
  public static let schema = "mesh-ios-tunnel-control-v1"

  public let schema: String
  public let requestID: String
  public let operation: TunnelControlOperation

  public init(requestID: String, operation: TunnelControlOperation = .status) {
    schema = Self.schema
    self.requestID = requestID
    self.operation = operation
  }

  public func encoded() throws -> Data {
    try validate()
    return try ExactJSON.canonical(self)
  }

  public static func decodeExact(_ data: Data) throws -> Self {
    try ExactJSON.requireObject(
      data,
      keys: ["schema", "requestID", "operation"],
      maximumBytes: 4 * 1024
    )
    let value = try JSONDecoder().decode(Self.self, from: data)
    try value.validate()
    guard try ExactJSON.canonical(value) == data else {
      throw TunnelContractError.invalidDocument
    }
    return value
  }

  private func validate() throws {
    guard schema == Self.schema else {
      throw TunnelContractError.unsupportedSchema
    }
    try ContractField.identifier(requestID, name: "requestID")
    guard operation == .status else {
      throw TunnelContractError.invalidField("operation")
    }
  }
}

public struct TunnelControlOutcome: Codable, Equatable, Sendable {
  public static let schema = "mesh-ios-tunnel-control-outcome-v1"

  public let schema: String
  public let requestID: String
  public let evidence: TunnelRuntimeEvidence

  public init(
    requestID: String,
    evidence: TunnelRuntimeEvidence
  ) throws {
    schema = Self.schema
    self.requestID = requestID
    self.evidence = evidence
    try validate()
  }

  public func encoded() throws -> Data {
    try validate()
    return try ExactJSON.canonical(self)
  }

  public static func decodeExact(_ data: Data) throws -> Self {
    try ExactJSON.requireObject(
      data,
      keys: ["schema", "requestID", "evidence"],
      maximumBytes: 8 * 1024
    )
    let value = try JSONDecoder().decode(Self.self, from: data)
    try value.validate()
    guard try ExactJSON.canonical(value) == data else {
      throw TunnelContractError.invalidDocument
    }
    return value
  }

  private func validate() throws {
    guard schema == Self.schema else {
      throw TunnelContractError.unsupportedSchema
    }
    try ContractField.identifier(requestID, name: "requestID")
    try evidence.validate()
  }
}

public struct TunnelIdentityRemovalRequest:
  Codable,
  Equatable,
  Sendable
{
  public static let schema = "mesh-ios-identity-removal-request-v1"
  public static let startOptionKey = "meshIdentityRemovalRequest"

  public let schema: String
  public let requestID: String
  public let confirmationNodeID: String

  public init(requestID: String, confirmationNodeID: String) throws {
    schema = Self.schema
    self.requestID = requestID
    self.confirmationNodeID = confirmationNodeID
    try validate()
  }

  public func encoded() throws -> Data {
    try validate()
    return try ExactJSON.canonical(self)
  }

  public static func decodeExact(_ data: Data) throws -> Self {
    try ExactJSON.requireObject(
      data,
      keys: ["schema", "requestID", "confirmationNodeID"],
      maximumBytes: 4 * 1024
    )
    let value = try JSONDecoder().decode(Self.self, from: data)
    try value.validate()
    return value
  }

  private func validate() throws {
    guard schema == Self.schema else {
      throw TunnelContractError.unsupportedSchema
    }
    try ContractField.identifier(requestID, name: "requestID")
    try ContractField.identifier(
      confirmationNodeID,
      name: "confirmationNodeID"
    )
  }
}

public enum TunnelIdentityRemovalStatus: String, Codable, Sendable {
  case removed
}

public struct TunnelIdentityRemovalOutcome:
  Codable,
  Equatable,
  Sendable
{
  public static let schema = "mesh-ios-identity-removal-v1"

  public let schema: String
  public let requestID: String
  public let nodeID: String
  public let status: TunnelIdentityRemovalStatus

  public init(requestID: String, nodeID: String) throws {
    schema = Self.schema
    self.requestID = requestID
    self.nodeID = nodeID
    status = .removed
    try validate()
  }

  public func encoded() throws -> Data {
    try validate()
    return try ExactJSON.canonical(self)
  }

  public static func decodeExact(_ data: Data) throws -> Self {
    try ExactJSON.requireObject(
      data,
      keys: ["schema", "requestID", "nodeID", "status"],
      maximumBytes: 4 * 1024
    )
    let value = try JSONDecoder().decode(Self.self, from: data)
    try value.validate()
    return value
  }

  private func validate() throws {
    guard schema == Self.schema, status == .removed else {
      throw TunnelContractError.unsupportedSchema
    }
    try ContractField.identifier(requestID, name: "requestID")
    try ContractField.identifier(nodeID, name: "nodeID")
  }
}

public struct TunnelConfigurationPayload: Codable, Equatable, Sendable {
  public static let schema = "mesh-ios-tunnel-configuration-v4"

  public let schema: String
  public let networkID: String
  public let nodeID: String
  public let controlPlaneOrigin: String
  public let agentCredentialGeneration: UInt64
  public let agentCredentialExpiresAt: String
  public let certificateFingerprint: String
  public let certificateGeneration: UInt64
  public let configRevision: UInt64
  public let configDigest: String
  public let engineIdentity: String
  public let tunnelRemoteAddress: TunnelRemoteAddress
  public let networkSettings: TunnelNetworkSettingsPlan
  public let monotonicCounter: UInt64
  public let issuedAtMilliseconds: UInt64
  public let nebula: TunnelNebulaConfiguration

  public init(
    networkID: String,
    nodeID: String,
    controlPlaneOrigin: String = "https://mesh.example",
    agentCredentialGeneration: UInt64 = 1,
    agentCredentialExpiresAt: String = "2026-08-01T00:00:00Z",
    certificateFingerprint: String,
    certificateGeneration: UInt64,
    configRevision: UInt64,
    configDigest: String,
    engineIdentity: String,
    tunnelRemoteAddress: TunnelRemoteAddress,
    networkSettings: TunnelNetworkSettingsPlan,
    monotonicCounter: UInt64,
    issuedAtMilliseconds: UInt64,
    nebula: TunnelNebulaConfiguration
  ) {
    schema = Self.schema
    self.networkID = networkID
    self.nodeID = nodeID
    self.controlPlaneOrigin = controlPlaneOrigin
    self.agentCredentialGeneration = agentCredentialGeneration
    self.agentCredentialExpiresAt = agentCredentialExpiresAt
    self.certificateFingerprint = certificateFingerprint
    self.certificateGeneration = certificateGeneration
    self.configRevision = configRevision
    self.configDigest = configDigest
    self.engineIdentity = engineIdentity
    self.tunnelRemoteAddress = tunnelRemoteAddress
    self.networkSettings = networkSettings
    self.monotonicCounter = monotonicCounter
    self.issuedAtMilliseconds = issuedAtMilliseconds
    self.nebula = nebula
  }

  func validate() throws {
    guard schema == Self.schema else {
      throw TunnelContractError.unsupportedSchema
    }
    try ContractField.identifier(networkID, name: "networkID")
    try ContractField.identifier(nodeID, name: "nodeID")
    guard
      try ContractField.httpsOrigin(
        controlPlaneOrigin,
        name: "controlPlaneOrigin"
      ) == controlPlaneOrigin
    else {
      throw TunnelContractError.invalidField("controlPlaneOrigin")
    }
    guard agentCredentialGeneration > 0 else {
      throw TunnelContractError.invalidField(
        "agentCredentialGeneration"
      )
    }
    let agentCredentialExpires = try ContractField.timestamp(
      agentCredentialExpiresAt,
      name: "agentCredentialExpiresAt"
    )
    let configurationIssued = try ContractField.timestamp(
      nebula.configIssuedAt,
      name: "nebula.configIssuedAt"
    )
    guard configurationIssued < agentCredentialExpires else {
      throw TunnelContractError.invalidField(
        "agentCredentialExpiresAt"
      )
    }
    try ContractField.digest(
      certificateFingerprint,
      name: "certificateFingerprint"
    )
    try ContractField.digest(configDigest, name: "configDigest")
    try ContractField.digest(engineIdentity, name: "engineIdentity")
    try networkSettings.validate()
    try networkSettings.validateRemoteAddress(tunnelRemoteAddress)
    try nebula.validate(
      networkID: networkID,
      nodeID: nodeID,
      certificateFingerprint: certificateFingerprint,
      certificateGeneration: certificateGeneration,
      configRevision: configRevision,
      configDigest: configDigest
    )
    guard certificateGeneration > 0 else {
      throw TunnelContractError.invalidField("certificateGeneration")
    }
    guard configRevision > 0 else {
      throw TunnelContractError.invalidField("configRevision")
    }
    guard monotonicCounter > 0 else {
      throw TunnelContractError.invalidField("monotonicCounter")
    }
    guard issuedAtMilliseconds > 0 else {
      throw TunnelContractError.invalidField("issuedAtMilliseconds")
    }
  }

  func engineDocument() throws -> String {
    try validate()
    let data = try ExactJSON.canonical(self)
    guard let value = String(data: data, encoding: .utf8) else {
      throw TunnelContractError.invalidDocument
    }
    return value
  }

  public static func decodeExact(_ data: Data) throws -> Self {
    try ExactJSON.requireObject(
      data,
      keys: [
        "schema",
        "networkID",
        "nodeID",
        "controlPlaneOrigin",
        "agentCredentialGeneration",
        "agentCredentialExpiresAt",
        "certificateFingerprint",
        "certificateGeneration",
        "configRevision",
        "configDigest",
        "engineIdentity",
        "tunnelRemoteAddress",
        "networkSettings",
        "monotonicCounter",
        "issuedAtMilliseconds",
        "nebula",
      ],
      maximumBytes: TunnelEnvelopeAuthenticator.maximumDocumentBytes
    )
    try ExactJSON.requireNestedObject(
      data,
      key: "networkSettings",
      keys: [
        "addresses",
        "includedRoutes",
        "excludedRoutes",
        "dnsServers",
        "mtu",
      ]
    )
    try ExactJSON.requireNestedArrayObjects(
      data,
      objectKey: "networkSettings",
      arrayKeys: ["addresses", "includedRoutes", "excludedRoutes"],
      elementKeys: ["address", "prefixLength"]
    )
    try ExactJSON.requireNestedObject(
      data,
      key: "nebula",
      keys: [
        "schema",
        "ca",
        "certificate",
        "config",
        "configIssuedAt",
        "caCertificateSHA256",
        "previousCACertificateSHA256",
        "caRotationRequired",
        "certificateProfileRenewalRequired",
        "certificateExpiresAt",
        "certificateRenewAfter",
        "publicKeyHash",
        "configSigningPublicKey",
        "configSignature",
      ]
    )
    let value = try JSONDecoder().decode(Self.self, from: data)
    try value.validate()
    return value
  }
}

public enum TunnelLifecycleRefreshStatus:
  String,
  Codable,
  Equatable,
  Sendable
{
  case ready
  case deferred
  case unauthorized
}

public struct TunnelLifecycleRefreshOutcome:
  Codable,
  Equatable,
  Sendable
{
  public static let schema = "mesh-ios-lifecycle-refresh-v1"

  public let schema: String
  public let status: TunnelLifecycleRefreshStatus
  public let configuration: TunnelConfigurationPayload?

  private struct Document: Codable {
    let schema: String
    let status: TunnelLifecycleRefreshStatus
    let configuration: String?
  }

  private struct StatusProbe: Codable {
    let status: TunnelLifecycleRefreshStatus
  }

  public static func decodeExact(_ data: Data) throws -> Self {
    guard !data.isEmpty,
      data.count <= TunnelEnvelopeAuthenticator.maximumDocumentBytes
    else {
      throw TunnelContractError.invalidDocument
    }
    let status = try JSONDecoder().decode(
      StatusProbe.self,
      from: data
    ).status
    switch status {
    case .ready:
      try ExactJSON.requireObject(
        data,
        keys: ["schema", "status", "configuration"],
        maximumBytes: TunnelEnvelopeAuthenticator.maximumDocumentBytes
      )
    case .deferred, .unauthorized:
      try ExactJSON.requireObject(
        data,
        keys: ["schema", "status"],
        maximumBytes: TunnelEnvelopeAuthenticator.maximumDocumentBytes
      )
    }
    let document = try JSONDecoder().decode(Document.self, from: data)
    guard document.schema == schema else {
      throw TunnelContractError.unsupportedSchema
    }
    switch document.status {
    case .ready:
      guard let raw = document.configuration,
        let configurationData = raw.data(using: .utf8)
      else {
        throw TunnelContractError.invalidDocument
      }
      return Self(
        schema: document.schema,
        status: document.status,
        configuration: try TunnelConfigurationPayload.decodeExact(
          configurationData
        )
      )
    case .deferred, .unauthorized:
      guard document.configuration == nil else {
        throw TunnelContractError.invalidDocument
      }
      return Self(
        schema: document.schema,
        status: document.status,
        configuration: nil
      )
    }
  }

  private init(
    schema: String,
    status: TunnelLifecycleRefreshStatus,
    configuration: TunnelConfigurationPayload?
  ) {
    self.schema = schema
    self.status = status
    self.configuration = configuration
  }
}

public enum TunnelEnrollmentRecoveryStatus:
  String,
  Codable,
  Equatable,
  Sendable
{
  case ready
  case deferred
  case unauthorized
}

public struct TunnelEnrollmentRecoveryOutcome:
  Codable,
  Equatable,
  Sendable
{
  public static let schema = "mesh-ios-enrollment-recovery-v1"

  public let schema: String
  public let status: TunnelEnrollmentRecoveryStatus
  public let configuration: TunnelConfigurationPayload?

  private struct Document: Codable {
    let schema: String
    let status: TunnelEnrollmentRecoveryStatus
    let configuration: String?
  }

  private struct StatusProbe: Codable {
    let status: TunnelEnrollmentRecoveryStatus
  }

  public static func decodeExact(_ data: Data) throws -> Self {
    guard !data.isEmpty,
      data.count <= TunnelEnvelopeAuthenticator.maximumDocumentBytes
    else {
      throw TunnelContractError.invalidDocument
    }
    let status = try JSONDecoder().decode(
      StatusProbe.self,
      from: data
    ).status
    switch status {
    case .ready:
      try ExactJSON.requireObject(
        data,
        keys: ["schema", "status", "configuration"],
        maximumBytes: TunnelEnvelopeAuthenticator.maximumDocumentBytes
      )
    case .deferred, .unauthorized:
      try ExactJSON.requireObject(
        data,
        keys: ["schema", "status"],
        maximumBytes: TunnelEnvelopeAuthenticator.maximumDocumentBytes
      )
    }
    let document = try JSONDecoder().decode(Document.self, from: data)
    guard document.schema == schema else {
      throw TunnelContractError.unsupportedSchema
    }
    switch document.status {
    case .ready:
      guard let raw = document.configuration,
        let configurationData = raw.data(using: .utf8)
      else {
        throw TunnelContractError.invalidDocument
      }
      return Self(
        schema: document.schema,
        status: document.status,
        configuration: try TunnelConfigurationPayload.decodeExact(
          configurationData
        )
      )
    case .deferred, .unauthorized:
      guard document.configuration == nil else {
        throw TunnelContractError.invalidDocument
      }
      return Self(
        schema: document.schema,
        status: document.status,
        configuration: nil
      )
    }
  }

  private init(
    schema: String,
    status: TunnelEnrollmentRecoveryStatus,
    configuration: TunnelConfigurationPayload?
  ) {
    self.schema = schema
    self.status = status
    self.configuration = configuration
  }
}

public enum TunnelMobileRuntimeState:
  String,
  Codable,
  Equatable,
  Sendable
{
  case tunnelStarting = "tunnel-starting"
  case tunnelRunning = "tunnel-running"
  case tunnelStopping = "tunnel-stopping"
  case stopped
  case suspended
  case quarantined
  case extensionError = "extension-error"
}

public enum TunnelMobileRuntimeReportStatus:
  String,
  Codable,
  Equatable,
  Sendable
{
  case accepted
  case deferred
  case unauthorized
  case refreshRequired = "refresh-required"
  case unsupported
}

public struct TunnelMobileRuntimeReportOutcome:
  Codable,
  Equatable,
  Sendable
{
  public static let schema = "mesh-ios-mobile-runtime-report-v1"

  public let schema: String
  public let status: TunnelMobileRuntimeReportStatus

  public static func decodeExact(_ data: Data) throws -> Self {
    try ExactJSON.requireObject(
      data,
      keys: ["schema", "status"],
      maximumBytes: 4 * 1024
    )
    let value = try JSONDecoder().decode(Self.self, from: data)
    guard value.schema == schema else {
      throw TunnelContractError.unsupportedSchema
    }
    return value
  }
}

public struct TunnelNebulaConfiguration:
  Codable,
  Equatable,
  Sendable
{
  public static let schema =
    "mesh-ios-nebula-engine-configuration-v1"

  public let schema: String
  public let ca: String
  public let certificate: String
  public let config: String
  public let configIssuedAt: String
  public let caCertificateSHA256: String
  public let previousCACertificateSHA256: String
  public let caRotationRequired: Bool
  public let certificateProfileRenewalRequired: Bool
  public let certificateExpiresAt: String
  public let certificateRenewAfter: String
  public let publicKeyHash: String
  public let configSigningPublicKey: String
  public let configSignature: String

  public init(
    ca: String,
    certificate: String,
    config: String,
    configIssuedAt: String,
    caCertificateSHA256: String,
    previousCACertificateSHA256: String = "",
    caRotationRequired: Bool = false,
    certificateProfileRenewalRequired: Bool = false,
    certificateExpiresAt: String,
    certificateRenewAfter: String,
    publicKeyHash: String,
    configSigningPublicKey: String,
    configSignature: String
  ) {
    schema = Self.schema
    self.ca = ca
    self.certificate = certificate
    self.config = config
    self.configIssuedAt = configIssuedAt
    self.caCertificateSHA256 = caCertificateSHA256
    self.previousCACertificateSHA256 =
      previousCACertificateSHA256
    self.caRotationRequired = caRotationRequired
    self.certificateProfileRenewalRequired =
      certificateProfileRenewalRequired
    self.certificateExpiresAt = certificateExpiresAt
    self.certificateRenewAfter = certificateRenewAfter
    self.publicKeyHash = publicKeyHash
    self.configSigningPublicKey = configSigningPublicKey
    self.configSignature = configSignature
  }

  fileprivate func validate(
    networkID: String,
    nodeID: String,
    certificateFingerprint: String,
    certificateGeneration: UInt64,
    configRevision: UInt64,
    configDigest: String
  ) throws {
    guard schema == Self.schema else {
      throw TunnelContractError.unsupportedSchema
    }
    guard !ca.isEmpty, ca.utf8.count <= 256 * 1024,
      !certificate.isEmpty,
      certificate.utf8.count <= 64 * 1024,
      !config.isEmpty,
      config.utf8.count <= 4 * 1024 * 1024,
      !ca.contains("\r"),
      !certificate.contains("\r"),
      !config.contains("\r")
    else {
      throw TunnelContractError.invalidField("nebula.material")
    }
    try ContractField.identifier(networkID, name: "networkID")
    try ContractField.identifier(nodeID, name: "nodeID")
    try ContractField.digest(
      certificateFingerprint,
      name: "certificateFingerprint"
    )
    guard certificateGeneration > 0, configRevision > 0 else {
      throw TunnelContractError.invalidField("nebula.lifecycle")
    }
    try ContractField.digest(
      caCertificateSHA256,
      name: "nebula.caCertificateSHA256"
    )
    if !previousCACertificateSHA256.isEmpty {
      try ContractField.digest(
        previousCACertificateSHA256,
        name: "nebula.previousCACertificateSHA256"
      )
      guard
        previousCACertificateSHA256
          != caCertificateSHA256
      else {
        throw TunnelContractError.invalidField(
          "nebula.previousCACertificateSHA256"
        )
      }
    }
    guard
      !caRotationRequired
        || !previousCACertificateSHA256.isEmpty,
      !(caRotationRequired
        && certificateProfileRenewalRequired)
    else {
      throw TunnelContractError.invalidField(
        "nebula.trustTransition"
      )
    }
    let configIssued = try ContractField.timestamp(
      configIssuedAt,
      name: "nebula.configIssuedAt"
    )
    let certificateExpires = try ContractField.timestamp(
      certificateExpiresAt,
      name: "nebula.certificateExpiresAt"
    )
    let certificateRenews = try ContractField.timestamp(
      certificateRenewAfter,
      name: "nebula.certificateRenewAfter"
    )
    guard configIssued < certificateExpires,
      certificateRenews < certificateExpires
    else {
      throw TunnelContractError.invalidField("nebula.lifecycle")
    }
    try ContractField.base64URL(
      publicKeyHash,
      bytes: 32,
      name: "nebula.publicKeyHash"
    )
    try ContractField.base64URL(
      configSigningPublicKey,
      bytes: 32,
      name: "nebula.configSigningPublicKey"
    )
    try ContractField.base64URL(
      configSignature,
      bytes: 64,
      name: "nebula.configSignature"
    )
    let observedConfigDigest = Data(
      SHA256.hash(data: Data(config.utf8))
    ).lowerHex
    guard observedConfigDigest == configDigest else {
      throw TunnelContractError.invalidField("configDigest")
    }
    let observedCADigest = Data(
      SHA256.hash(data: Data(ca.utf8))
    ).lowerHex
    guard observedCADigest == caCertificateSHA256 else {
      throw TunnelContractError.invalidField(
        "nebula.caCertificateSHA256"
      )
    }
  }
}

public struct TunnelConfigurationEnvelope: Codable, Equatable, Sendable {
  public static let schema = "mesh-ios-tunnel-envelope-v4"

  public let schema: String
  public let payload: TunnelConfigurationPayload
  public let authentication: String

  fileprivate init(
    payload: TunnelConfigurationPayload,
    authentication: String
  ) {
    schema = Self.schema
    self.payload = payload
    self.authentication = authentication
  }
}

public enum TunnelEnvelopeAuthenticator {
  public static let maximumDocumentBytes = 16 * 1024 * 1024

  public static func seal(
    _ payload: TunnelConfigurationPayload,
    using key: SymmetricKey
  ) throws -> Data {
    try payload.validate()
    let authentication = Data(
      HMAC<SHA256>.authenticationCode(
        for: try ExactJSON.canonical(payload),
        using: key
      )
    ).lowerHex
    return try ExactJSON.canonical(
      TunnelConfigurationEnvelope(
        payload: payload,
        authentication: authentication
      )
    )
  }

  public static func open(
    _ data: Data,
    using key: SymmetricKey
  ) throws -> TunnelConfigurationPayload {
    try ExactJSON.requireObject(
      data,
      keys: ["schema", "payload", "authentication"],
      maximumBytes: maximumDocumentBytes
    )
    try ExactJSON.requireNestedObject(
      data,
      key: "payload",
      keys: [
        "schema",
        "networkID",
        "nodeID",
        "controlPlaneOrigin",
        "agentCredentialGeneration",
        "agentCredentialExpiresAt",
        "certificateFingerprint",
        "certificateGeneration",
        "configRevision",
        "configDigest",
        "engineIdentity",
        "tunnelRemoteAddress",
        "networkSettings",
        "monotonicCounter",
        "issuedAtMilliseconds",
        "nebula",
      ]
    )
    try ExactJSON.requireNestedObject(
      data,
      parentKey: "payload",
      key: "networkSettings",
      keys: [
        "addresses",
        "includedRoutes",
        "excludedRoutes",
        "dnsServers",
        "mtu",
      ]
    )
    try ExactJSON.requireNestedArrayObjects(
      data,
      parentKey: "payload",
      objectKey: "networkSettings",
      arrayKeys: ["addresses", "includedRoutes", "excludedRoutes"],
      elementKeys: ["address", "prefixLength"]
    )
    try ExactJSON.requireNestedObject(
      data,
      parentKey: "payload",
      key: "nebula",
      keys: [
        "schema",
        "ca",
        "certificate",
        "config",
        "configIssuedAt",
        "caCertificateSHA256",
        "previousCACertificateSHA256",
        "caRotationRequired",
        "certificateProfileRenewalRequired",
        "certificateExpiresAt",
        "certificateRenewAfter",
        "publicKeyHash",
        "configSigningPublicKey",
        "configSignature",
      ]
    )
    let envelope = try JSONDecoder().decode(
      TunnelConfigurationEnvelope.self,
      from: data
    )
    guard envelope.schema == TunnelConfigurationEnvelope.schema else {
      throw TunnelContractError.unsupportedSchema
    }
    try envelope.payload.validate()
    guard let authentication = Data(lowerHex: envelope.authentication),
      authentication.count == SHA256.byteCount,
      HMAC<SHA256>.isValidAuthenticationCode(
        authentication,
        authenticating: try ExactJSON.canonical(envelope.payload),
        using: key
      )
    else {
      throw TunnelContractError.authenticationFailed
    }
    return envelope.payload
  }
}

public struct TunnelIPPrefix: Codable, Equatable, Sendable {
  public let address: String
  public let prefixLength: UInt8

  public init(address: String, prefixLength: UInt8) {
    self.address = address
    self.prefixLength = prefixLength
  }

  fileprivate func validated(
    field: String,
    requireNetworkAddress: Bool
  ) throws -> ParsedIPAddress {
    let parsed = try ParsedIPAddress.parse(address, field: field)
    guard Int(prefixLength) <= parsed.maximumPrefixLength else {
      throw TunnelContractError.invalidField(field)
    }
    if requireNetworkAddress,
      !parsed.isNetworkAddress(prefixLength: Int(prefixLength))
    {
      throw TunnelContractError.invalidField(field)
    }
    return parsed
  }
}

public struct TunnelNetworkSettingsPlan: Codable, Equatable, Sendable {
  public let addresses: [TunnelIPPrefix]
  public let includedRoutes: [TunnelIPPrefix]
  public let excludedRoutes: [TunnelIPPrefix]
  public let dnsServers: [String]
  public let mtu: UInt16

  public init(
    addresses: [TunnelIPPrefix],
    includedRoutes: [TunnelIPPrefix],
    excludedRoutes: [TunnelIPPrefix] = [],
    dnsServers: [String] = [],
    mtu: UInt16
  ) {
    self.addresses = addresses
    self.includedRoutes = includedRoutes
    self.excludedRoutes = excludedRoutes
    self.dnsServers = dnsServers
    self.mtu = mtu
  }

  func validate() throws {
    guard (1...8).contains(addresses.count) else {
      throw TunnelContractError.invalidField("networkSettings.addresses")
    }
    guard (1...128).contains(includedRoutes.count) else {
      throw TunnelContractError.invalidField(
        "networkSettings.includedRoutes"
      )
    }
    guard excludedRoutes.count <= 128 else {
      throw TunnelContractError.invalidField(
        "networkSettings.excludedRoutes"
      )
    }
    guard dnsServers.count <= 8 else {
      throw TunnelContractError.invalidField("networkSettings.dnsServers")
    }
    guard (1280...1500).contains(mtu) else {
      throw TunnelContractError.invalidField("networkSettings.mtu")
    }

    var addressKeys = Set<String>()
    var addressFamilies = Set<Int32>()
    for value in addresses {
      guard value.prefixLength > 0 else {
        throw TunnelContractError.invalidField(
          "networkSettings.addresses"
        )
      }
      let parsed = try value.validated(
        field: "networkSettings.addresses",
        requireNetworkAddress: false
      )
      guard parsed.isUsableUnicast,
        addressKeys.insert(
          "\(parsed.family):\(parsed.canonical)/\(value.prefixLength)"
        ).inserted
      else {
        throw TunnelContractError.invalidField(
          "networkSettings.addresses"
        )
      }
      addressFamilies.insert(parsed.family)
    }

    let included = try validateRoutes(
      includedRoutes,
      field: "networkSettings.includedRoutes",
      addressFamilies: addressFamilies
    )
    let excluded = try validateRoutes(
      excludedRoutes,
      field: "networkSettings.excludedRoutes",
      addressFamilies: addressFamilies
    )
    guard included.isDisjoint(with: excluded) else {
      throw TunnelContractError.invalidField(
        "networkSettings.routeConflict"
      )
    }

    var dnsKeys = Set<String>()
    for value in dnsServers {
      let parsed = try ParsedIPAddress.parse(
        value,
        field: "networkSettings.dnsServers"
      )
      guard parsed.isUsableUnicast,
        addressFamilies.contains(parsed.family),
        dnsKeys.insert("\(parsed.family):\(parsed.canonical)").inserted
      else {
        throw TunnelContractError.invalidField(
          "networkSettings.dnsServers"
        )
      }
    }
  }

  private func validateRoutes(
    _ routes: [TunnelIPPrefix],
    field: String,
    addressFamilies: Set<Int32>
  ) throws -> Set<String> {
    var keys = Set<String>()
    for route in routes {
      let parsed = try route.validated(
        field: field,
        requireNetworkAddress: true
      )
      guard addressFamilies.contains(parsed.family),
        keys.insert(
          "\(parsed.family):\(parsed.canonical)/\(route.prefixLength)"
        ).inserted
      else {
        throw TunnelContractError.invalidField(field)
      }
    }
    return keys
  }

  fileprivate func validateRemoteAddress(
    _ remoteAddress: TunnelRemoteAddress
  ) throws {
    let remote = try ParsedIPAddress.parse(
      remoteAddress.value,
      field: "tunnelRemoteAddress"
    )
    let addressCollision = try addresses.contains {
      let address = try $0.validated(
        field: "networkSettings.addresses",
        requireNetworkAddress: false
      )
      return address.family == remote.family
        && address.bytes == remote.bytes
    }
    guard !addressCollision else {
      throw TunnelContractError.invalidField("tunnelRemoteAddress")
    }
    let included = try includedRoutes.contains {
      try $0.contains(remote)
    }
    if included {
      let excluded = try excludedRoutes.contains {
        try $0.contains(remote)
      }
      guard excluded else {
        throw TunnelContractError.invalidField(
          "networkSettings.remoteEndpointRoute"
        )
      }
    }
  }
}

public struct TunnelRemoteAddress: Codable, Equatable, Sendable {
  public let value: String

  public init(_ value: String) throws {
    let parsed = try ParsedIPAddress.parse(
      value,
      field: "tunnelRemoteAddress"
    )
    guard parsed.isUsableUnicast else {
      throw TunnelContractError.invalidField("tunnelRemoteAddress")
    }
    self.value = parsed.canonical
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    try self.init(container.decode(String.self))
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    try container.encode(value)
  }
}

struct ParsedIPAddress {
  let family: Int32
  let bytes: [UInt8]
  let canonical: String

  var maximumPrefixLength: Int {
    family == AF_INET ? 32 : 128
  }

  var isUsableUnicast: Bool {
    guard bytes.contains(where: { $0 != 0 }) else {
      return false
    }
    if family == AF_INET {
      return bytes[0] != 0 && bytes[0] != 127 && bytes[0] < 224
    }
    let isLoopback =
      bytes.dropLast().allSatisfy { $0 == 0 }
      && bytes.last == 1
    return !isLoopback && bytes[0] != 0xff
  }

  static func parse(
    _ value: String,
    field: String
  ) throws -> ParsedIPAddress {
    guard !value.isEmpty, value.utf8.count <= 45 else {
      throw TunnelContractError.invalidField(field)
    }
    for family in [AF_INET, AF_INET6] {
      let byteCount = family == AF_INET ? 4 : 16
      var bytes = [UInt8](repeating: 0, count: byteCount)
      let parsed = value.withCString { source in
        bytes.withUnsafeMutableBytes { destination in
          inet_pton(family, source, destination.baseAddress)
        }
      }
      guard parsed == 1 else {
        continue
      }
      var output = [CChar](
        repeating: 0,
        count: family == AF_INET
          ? Int(INET_ADDRSTRLEN)
          : Int(INET6_ADDRSTRLEN)
      )
      let rendered = bytes.withUnsafeBytes { source in
        inet_ntop(
          family,
          source.baseAddress,
          &output,
          socklen_t(output.count)
        )
      }
      guard rendered != nil else {
        throw TunnelContractError.invalidField(field)
      }
      let canonical = String(
        decoding: output.prefix { $0 != 0 }.map {
          UInt8(bitPattern: $0)
        },
        as: UTF8.self
      )
      guard value == canonical else {
        throw TunnelContractError.invalidField(field)
      }
      return ParsedIPAddress(
        family: family,
        bytes: bytes,
        canonical: canonical
      )
    }
    throw TunnelContractError.invalidField(field)
  }

  func isNetworkAddress(prefixLength: Int) -> Bool {
    let completeBytes = prefixLength / 8
    let remainingBits = prefixLength % 8
    if remainingBits > 0 {
      let hostMask = UInt8((1 << (8 - remainingBits)) - 1)
      guard bytes[completeBytes] & hostMask == 0 else {
        return false
      }
    }
    let firstHostByte = completeBytes + (remainingBits == 0 ? 0 : 1)
    return bytes.dropFirst(firstHostByte).allSatisfy { $0 == 0 }
  }

  func matchesPrefix(
    network: ParsedIPAddress,
    prefixLength: Int
  ) -> Bool {
    guard family == network.family else {
      return false
    }
    let completeBytes = prefixLength / 8
    let remainingBits = prefixLength % 8
    guard
      bytes.prefix(completeBytes)
        == network.bytes.prefix(completeBytes)
    else {
      return false
    }
    guard remainingBits > 0 else {
      return true
    }
    let mask = UInt8(0xff << (8 - remainingBits))
    return bytes[completeBytes] & mask
      == network.bytes[completeBytes] & mask
  }
}

extension TunnelIPPrefix {
  fileprivate func contains(_ address: ParsedIPAddress) throws -> Bool {
    let network = try validated(
      field: "networkSettings.route",
      requireNetworkAddress: true
    )
    return address.matchesPrefix(
      network: network,
      prefixLength: Int(prefixLength)
    )
  }
}

public struct TunnelRuntimeEvidence: Codable, Equatable, Sendable {
  public static let schema = "mesh-ios-tunnel-evidence-v1"

  public let schema: String
  public let sequence: UInt64
  public let state: TunnelLifecycleState
  public let configRevision: UInt64?
  public let certificateGeneration: UInt64?
  public let engineIdentity: String?
  public let packetsRead: UInt64?
  public let packetsWritten: UInt64?
  public let errorCode: String?

  public init(
    sequence: UInt64,
    state: TunnelLifecycleState,
    configRevision: UInt64? = nil,
    certificateGeneration: UInt64? = nil,
    engineIdentity: String? = nil,
    packetsRead: UInt64? = nil,
    packetsWritten: UInt64? = nil,
    errorCode: String? = nil
  ) {
    schema = Self.schema
    self.sequence = sequence
    self.state = state
    self.configRevision = configRevision
    self.certificateGeneration = certificateGeneration
    self.engineIdentity = engineIdentity
    self.packetsRead = packetsRead
    self.packetsWritten = packetsWritten
    self.errorCode = errorCode
  }

  public func encoded() throws -> Data {
    try validate()
    return try ExactJSON.canonical(self)
  }

  public static func decodeExact(_ data: Data) throws -> Self {
    guard !data.isEmpty, data.count <= 8 * 1024,
      let object = try JSONSerialization.jsonObject(
        with: data,
        options: []
      ) as? [String: Any]
    else {
      throw TunnelContractError.invalidDocument
    }
    let value = try JSONDecoder().decode(Self.self, from: data)
    try value.validate()
    let baseKeys: Set<String> = ["schema", "sequence", "state"]
    let expectedKeys: Set<String>
    switch value.state {
    case .running:
      expectedKeys = baseKeys.union([
        "configRevision",
        "certificateGeneration",
        "engineIdentity",
        "packetsRead",
        "packetsWritten",
      ])
    case .extensionError:
      expectedKeys = baseKeys.union(["errorCode"])
    default:
      expectedKeys = baseKeys
    }
    guard Set(object.keys) == expectedKeys,
      try ExactJSON.canonical(value) == data
    else {
      throw TunnelContractError.invalidDocument
    }
    return value
  }

  fileprivate func validate() throws {
    guard schema == Self.schema else {
      throw TunnelContractError.unsupportedSchema
    }
    guard sequence > 0 else {
      throw TunnelContractError.invalidField("sequence")
    }
    if let engineIdentity {
      try ContractField.digest(engineIdentity, name: "engineIdentity")
    }
    if let errorCode {
      try ContractField.identifier(errorCode, name: "errorCode")
    }
    if state == .running {
      guard configRevision != nil,
        certificateGeneration != nil,
        engineIdentity != nil,
        packetsRead != nil,
        packetsWritten != nil,
        errorCode == nil
      else {
        throw TunnelContractError.invalidField("runningEvidence")
      }
    } else {
      guard configRevision == nil,
        certificateGeneration == nil,
        engineIdentity == nil,
        packetsRead == nil,
        packetsWritten == nil
      else {
        throw TunnelContractError.invalidField("nonRunningEvidence")
      }
      if state == .extensionError {
        guard errorCode != nil else {
          throw TunnelContractError.invalidField("errorCode")
        }
      } else if errorCode != nil {
        throw TunnelContractError.invalidField("errorCode")
      }
    }
  }
}

private enum ContractField {
  static func identifier(_ value: String, name: String) throws {
    guard !value.isEmpty,
      value.utf8.count <= 128,
      value.unicodeScalars.allSatisfy({
        CharacterSet(
          charactersIn: "abcdefghijklmnopqrstuvwxyz"
            + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            + "0123456789._:-"
        ).contains($0)
      })
    else {
      throw TunnelContractError.invalidField(name)
    }
  }

  static func digest(_ value: String, name: String) throws {
    guard value.count == 64,
      value.unicodeScalars.allSatisfy({
        CharacterSet(charactersIn: "0123456789abcdef").contains($0)
      })
    else {
      throw TunnelContractError.invalidField(name)
    }
  }

  static func base64URL(
    _ value: String,
    bytes: Int,
    name: String
  ) throws {
    guard !value.isEmpty,
      !value.contains("="),
      value.unicodeScalars.allSatisfy({
        CharacterSet(
          charactersIn:
            "abcdefghijklmnopqrstuvwxyz"
            + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            + "0123456789-_"
        ).contains($0)
      })
    else {
      throw TunnelContractError.invalidField(name)
    }
    var standard =
      value
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    let remainder = standard.count % 4
    if remainder > 0 {
      standard += String(repeating: "=", count: 4 - remainder)
    }
    guard let decoded = Data(base64Encoded: standard),
      decoded.count == bytes
    else {
      throw TunnelContractError.invalidField(name)
    }
    let canonical = decoded.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
    guard canonical == value else {
      throw TunnelContractError.invalidField(name)
    }
  }

  static func timestamp(_ value: String, name: String) throws -> Date {
    let pattern =
      #"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$"#
    guard
      value.range(
        of: pattern,
        options: .regularExpression
      ) == value.startIndex..<value.endIndex
    else {
      throw TunnelContractError.invalidField(name)
    }
    if let dot = value.firstIndex(of: ".") {
      let fractional = value[
        value.index(after: dot)..<value.index(before: value.endIndex)
      ]
      guard fractional.last != "0" else {
        throw TunnelContractError.invalidField(name)
      }
    }
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions =
      value.contains(".")
      ? [.withInternetDateTime, .withFractionalSeconds]
      : [.withInternetDateTime]
    guard let parsed = formatter.date(from: value) else {
      throw TunnelContractError.invalidField(name)
    }
    return parsed
  }

  static func httpsOrigin(_ value: String, name: String) throws -> String {
    guard value.utf8.count <= 2 * 1024,
      var components = URLComponents(string: value),
      components.scheme == "https",
      components.user == nil,
      components.password == nil,
      let host = components.host,
      !host.isEmpty,
      host == host.lowercased(),
      !host.unicodeScalars.contains(where: {
        CharacterSet.whitespacesAndNewlines.contains($0)
      }),
      components.query == nil,
      components.fragment == nil,
      components.path.isEmpty || components.path == "/",
      components.port.map({ (1...65_535).contains($0) }) ?? true
    else {
      throw TunnelContractError.invalidField(name)
    }
    components.path = ""
    components.query = nil
    components.fragment = nil
    guard let canonical = components.string,
      !canonical.hasSuffix("/")
    else {
      throw TunnelContractError.invalidField(name)
    }
    return canonical
  }
}

private enum ExactJSON {
  static func canonical<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try encoder.encode(value)
  }

  static func requireObject(
    _ data: Data,
    keys: Set<String>,
    maximumBytes: Int
  ) throws {
    guard !data.isEmpty, data.count <= maximumBytes,
      let object = try JSONSerialization.jsonObject(
        with: data,
        options: []
      ) as? [String: Any],
      Set(object.keys) == keys
    else {
      throw TunnelContractError.invalidDocument
    }
  }

  static func requireNestedObject(
    _ data: Data,
    key: String,
    keys: Set<String>
  ) throws {
    guard
      let object = try JSONSerialization.jsonObject(
        with: data,
        options: []
      ) as? [String: Any],
      let nested = object[key] as? [String: Any],
      Set(nested.keys) == keys
    else {
      throw TunnelContractError.invalidDocument
    }
  }

  static func requireNestedObject(
    _ data: Data,
    parentKey: String,
    key: String,
    keys: Set<String>
  ) throws {
    guard
      let object = try JSONSerialization.jsonObject(
        with: data,
        options: []
      ) as? [String: Any],
      let parent = object[parentKey] as? [String: Any],
      let nested = parent[key] as? [String: Any],
      Set(nested.keys) == keys
    else {
      throw TunnelContractError.invalidDocument
    }
  }

  static func requireNestedArrayObjects(
    _ data: Data,
    objectKey: String,
    arrayKeys: Set<String>,
    elementKeys: Set<String>
  ) throws {
    guard
      let object = try JSONSerialization.jsonObject(
        with: data,
        options: []
      ) as? [String: Any],
      let nested = object[objectKey] as? [String: Any]
    else {
      throw TunnelContractError.invalidDocument
    }
    for key in arrayKeys {
      guard let values = nested[key] as? [[String: Any]],
        values.allSatisfy({ Set($0.keys) == elementKeys })
      else {
        throw TunnelContractError.invalidDocument
      }
    }
  }

  static func requireNestedArrayObjects(
    _ data: Data,
    parentKey: String,
    objectKey: String,
    arrayKeys: Set<String>,
    elementKeys: Set<String>
  ) throws {
    guard
      let object = try JSONSerialization.jsonObject(
        with: data,
        options: []
      ) as? [String: Any],
      let parent = object[parentKey] as? [String: Any],
      let nested = parent[objectKey] as? [String: Any]
    else {
      throw TunnelContractError.invalidDocument
    }
    for key in arrayKeys {
      guard let values = nested[key] as? [[String: Any]],
        values.allSatisfy({ Set($0.keys) == elementKeys })
      else {
        throw TunnelContractError.invalidDocument
      }
    }
  }
}

extension Data {
  fileprivate init?(lowerHex: String) {
    guard lowerHex.count.isMultiple(of: 2),
      lowerHex.unicodeScalars.allSatisfy({
        CharacterSet(charactersIn: "0123456789abcdef").contains($0)
      })
    else {
      return nil
    }
    var result = Data()
    result.reserveCapacity(lowerHex.count / 2)
    var index = lowerHex.startIndex
    while index < lowerHex.endIndex {
      let next = lowerHex.index(index, offsetBy: 2)
      guard let byte = UInt8(lowerHex[index..<next], radix: 16) else {
        return nil
      }
      result.append(byte)
      index = next
    }
    self = result
  }

  fileprivate var lowerHex: String {
    map { String(format: "%02x", $0) }.joined()
  }
}
