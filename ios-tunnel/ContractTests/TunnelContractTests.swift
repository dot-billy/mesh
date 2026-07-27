import CryptoKit
import Foundation
import Testing

@testable import MeshTunnelContract

private let digest = String(repeating: "a", count: 64)
private let key = SymmetricKey(data: Data(repeating: 0x42, count: 32))
private let signedConfig =
  "pki:\n  ca: /etc/nebula/ca.crt\n"
  + "  cert: /etc/nebula/host.crt\n"
  + "  key: /etc/nebula/host.key\n"
private let caCertificate = "test-ca\n"

private func lowerHexSHA256(_ value: String) -> String {
  Data(SHA256.hash(data: Data(value.utf8)))
    .map { String(format: "%02x", $0) }
    .joined()
}

private func base64URL(_ bytes: Int, value: UInt8) -> String {
  Data(repeating: value, count: bytes)
    .base64EncodedString()
    .replacingOccurrences(of: "+", with: "-")
    .replacingOccurrences(of: "/", with: "_")
    .replacingOccurrences(of: "=", with: "")
}

private func nebulaConfiguration(
  ca: String = caCertificate,
  config: String = signedConfig,
  configIssuedAt: String = "2026-07-24T12:00:00Z",
  caCertificateSHA256: String? = nil,
  certificateExpiresAt: String = "2026-07-25T12:00:00Z",
  certificateRenewAfter: String = "2026-07-25T02:00:00Z"
) -> TunnelNebulaConfiguration {
  TunnelNebulaConfiguration(
    ca: ca,
    certificate: "test-certificate\n",
    config: config,
    configIssuedAt: configIssuedAt,
    caCertificateSHA256: (caCertificateSHA256 ?? lowerHexSHA256(ca)),
    certificateExpiresAt: certificateExpiresAt,
    certificateRenewAfter: certificateRenewAfter,
    publicKeyHash: base64URL(32, value: 0x31),
    configSigningPublicKey: base64URL(32, value: 0x32),
    configSignature: base64URL(64, value: 0x33)
  )
}

private func networkSettings() -> TunnelNetworkSettingsPlan {
  TunnelNetworkSettingsPlan(
    addresses: [
      TunnelIPPrefix(address: "10.42.0.7", prefixLength: 24),
      TunnelIPPrefix(address: "fd00:42::7", prefixLength: 64),
    ],
    includedRoutes: [
      TunnelIPPrefix(address: "0.0.0.0", prefixLength: 0),
      TunnelIPPrefix(address: "::", prefixLength: 0),
    ],
    excludedRoutes: [
      TunnelIPPrefix(address: "192.0.2.0", prefixLength: 24)
    ],
    dnsServers: ["10.42.0.1", "fd00:42::1"],
    mtu: 1300
  )
}

private final class MemoryHighWater: TunnelHighWaterStore {
  var value: UInt64 = 0

  func load() throws -> UInt64 {
    value
  }

  func commit(_ value: UInt64) throws {
    self.value = value
  }
}

private enum RuntimeTestFailure: Error {
  case settings
  case start
  case rebind
  case send
  case receive
}

private actor RuntimeEventRecorder {
  private var values: [String] = []

  func append(_ value: String) {
    values.append(value)
  }

  func snapshot() -> [String] {
    values
  }
}

private actor RecordingEngineSession: TunnelEngineSession {
  let identity: String
  let recorder: RuntimeEventRecorder
  let startFailure: Bool
  let rebindFailure: Bool
  let sendFailure: Bool
  let receiveFailure: Bool
  var receivedPackets: [TunnelPacket]

  init(
    identity: String = digest,
    recorder: RuntimeEventRecorder,
    startFailure: Bool = false,
    rebindFailure: Bool = false,
    sendFailure: Bool = false,
    receiveFailure: Bool = false,
    receivedPackets: [TunnelPacket] = []
  ) {
    self.identity = identity
    self.recorder = recorder
    self.startFailure = startFailure
    self.rebindFailure = rebindFailure
    self.sendFailure = sendFailure
    self.receiveFailure = receiveFailure
    self.receivedPackets = receivedPackets
  }

  func frameworkIdentity() async throws -> String {
    await recorder.append("engine-identity")
    return identity
  }

  func prepare(configuration: TunnelConfigurationPayload) async throws {
    await recorder.append("engine-prepare-\(configuration.configRevision)")
  }

  func start() async throws {
    await recorder.append("engine-start")
    if startFailure {
      throw RuntimeTestFailure.start
    }
  }

  func rebind() async throws {
    await recorder.append("engine-rebind")
    if rebindFailure {
      throw RuntimeTestFailure.rebind
    }
  }

  func send(_ packets: [TunnelPacket]) async throws {
    await recorder.append("engine-send-\(packets.count)")
    if sendFailure {
      throw RuntimeTestFailure.send
    }
  }

  func receive() async throws -> [TunnelPacket] {
    await recorder.append("engine-receive")
    if receiveFailure {
      throw RuntimeTestFailure.receive
    }
    let packets = receivedPackets
    receivedPackets = []
    return packets
  }

  func stop() async {
    await recorder.append("engine-stop")
  }
}

private actor RecordingNetworkSettingsSession:
  TunnelNetworkSettingsSession
{
  let recorder: RuntimeEventRecorder
  let applyFailure: Bool

  init(
    recorder: RuntimeEventRecorder,
    applyFailure: Bool = false
  ) {
    self.recorder = recorder
    self.applyFailure = applyFailure
  }

  func apply(
    plan: TunnelNetworkSettingsPlan,
    tunnelRemoteAddress: TunnelRemoteAddress
  ) async throws {
    await recorder.append(
      "settings-apply-\(tunnelRemoteAddress.value)-\(plan.mtu)"
    )
    if applyFailure {
      throw RuntimeTestFailure.settings
    }
  }

  func clear() async {
    await recorder.append("settings-clear")
  }
}

private func payload(
  nebula: TunnelNebulaConfiguration = nebulaConfiguration(),
  configDigest: String = lowerHexSHA256(signedConfig)
) -> TunnelConfigurationPayload {
  TunnelConfigurationPayload(
    networkID: "network_1",
    nodeID: "node_1",
    certificateFingerprint: digest,
    certificateGeneration: 2,
    configRevision: 7,
    configDigest: configDigest,
    engineIdentity: digest,
    tunnelRemoteAddress: try! TunnelRemoteAddress("192.0.2.9"),
    networkSettings: networkSettings(),
    monotonicCounter: 9,
    issuedAtMilliseconds: 1_785_000_000_000,
    nebula: nebula
  )
}

private func ipv4Packet(_ marker: UInt8 = 0) throws -> TunnelPacket {
  var bytes = Data(repeating: 0, count: 20)
  bytes[0] = 0x45
  bytes[2] = 0
  bytes[3] = 20
  bytes[19] = marker
  return try TunnelPacket(bytes: bytes, family: .ipv4)
}

private func ipv6Packet(_ marker: UInt8 = 0) throws -> TunnelPacket {
  var bytes = Data(repeating: 0, count: 40)
  bytes[0] = 0x60
  bytes[39] = marker
  return try TunnelPacket(bytes: bytes, family: .ipv6)
}

@Test
func userAuthorizationBindsBrowserURLToTheServerAndRequest() throws {
  let pollSecret = base64URL(32, value: 0x44)
  let requestID = "desktop_\(base64URL(32, value: 0x45))"
  let data = try JSONSerialization.data(
    withJSONObject: [
      "request_id": requestID,
      "poll_secret": pollSecret,
      "verification_url":
        "https://mesh.example/?mesh_desktop_request=\(requestID)",
      "expires_at": "2026-07-25T21:05:00Z",
      "interval_seconds": 5,
    ],
    options: [.sortedKeys]
  )
  let response = try TunnelUserAuthorizationStartResponse.decode(
    data,
    serverOrigin: "https://mesh.example"
  )
  #expect(response.pollSecret == pollSecret)
  #expect(
    try response.validatedVerificationURL(
      serverOrigin: "https://mesh.example"
    ).host == "mesh.example"
  )

  let redirected = try JSONSerialization.data(
    withJSONObject: [
      "request_id": requestID,
      "poll_secret": pollSecret,
      "verification_url":
        "https://attacker.example/?mesh_desktop_request=\(requestID)",
      "expires_at": "2026-07-25T21:05:00Z",
      "interval_seconds": 5,
    ],
    options: [.sortedKeys]
  )
  #expect(throws: TunnelUserEnrollmentError.self) {
    try TunnelUserAuthorizationStartResponse.decode(
      redirected,
      serverOrigin: "https://mesh.example"
    )
  }
}

@Test
func authorizedUserSessionMustCarrySelfEnrollmentPermission() throws {
  func completion(permissions: [String]) throws -> Data {
    try JSONSerialization.data(
      withJSONObject: [
        "state": "authorized",
        "expires_at": "2026-07-25T21:05:00Z",
        "interval_seconds": 5,
        "session": [
          "authenticated": true,
          "auth_method": "oidc",
          "role": "member",
          "permissions": permissions,
        ],
      ],
      options: [.sortedKeys]
    )
  }

  let authorized = try TunnelUserAuthorizationCompletionResponse.decode(
    completion(permissions: ["networks.read", "nodes.enroll.self"])
  )
  #expect(authorized.state == .authorized)
  #expect(throws: TunnelUserEnrollmentError.self) {
    try TunnelUserAuthorizationCompletionResponse.decode(
      completion(permissions: ["networks.read"])
    )
  }
}

@Test
func enrollmentSessionRetainsOnlyItsPrivateEphemeralCookiePair() throws {
  let configuration =
    try TunnelUserEnrollmentSessionFactory.ephemeralConfiguration()
  let storage = try #require(configuration.httpCookieStorage)
  #expect(storage !== HTTPCookieStorage.shared)
  #expect(configuration.httpShouldSetCookies)
  #expect(configuration.urlCache == nil)

  let completionURL = try #require(
    URL(
      string:
        "https://mesh.example/api/v1/auth/desktop/complete"
    )
  )
  let enrollmentURL = try #require(
    URL(
      string:
        "https://mesh.example/api/v1/networks/network_1/self-enrollment"
    )
  )
  let session = HTTPCookie.cookies(
    withResponseHeaderFields: [
      "Set-Cookie":
        "__Host-mesh_session=session-value; Path=/; Secure; "
        + "HttpOnly; SameSite=Strict",
    ],
    for: completionURL
  )
  let csrf = HTTPCookie.cookies(
    withResponseHeaderFields: [
      "Set-Cookie":
        "__Host-mesh_csrf=csrf-value; Path=/; Secure; "
        + "SameSite=Strict",
    ],
    for: completionURL
  )
  #expect(session.count == 1)
  #expect(csrf.count == 1)
  storage.setCookies(
    session + csrf,
    for: completionURL,
    mainDocumentURL: nil
  )
  let available = try #require(storage.cookies(for: enrollmentURL))
  #expect(
    Set(available.map(\.name))
      == Set(["__Host-mesh_session", "__Host-mesh_csrf"])
  )
  for cookie in available {
    storage.deleteCookie(cookie)
  }
  #expect(storage.cookies(for: enrollmentURL)?.isEmpty != false)
}

@Test
func selfEnrollmentResponseIsFixedPolicyAndTokenNeverEntersRequest() throws {
  let request = try TunnelUserSelfEnrollmentRequest(name: "ios-7f3a9c2d")
  let encodedRequest = try request.encoded()
  let requestText = try #require(
    String(data: encodedRequest, encoding: .utf8)
  )
  #expect(requestText == #"{"name":"ios-7f3a9c2d"}"#)
  #expect(!requestText.contains("token"))

  func response(role: String) throws -> Data {
    try JSONSerialization.data(
      withJSONObject: [
        "node": [
          "id": "node_1",
          "network_id": "network_1",
          "name": "ios-7f3a9c2d",
          "site": "mobile",
          "groups": ["all", "members"],
          "role": role,
          "status": "pending",
          "ip": "10.42.0.7",
        ],
        "enrollment_token": base64URL(32, value: 0x66),
        "expires_at": "2026-07-25T21:05:00Z",
      ],
      options: [.sortedKeys]
    )
  }
  let enrollment = try TunnelUserSelfEnrollmentResponse.decode(
    response(role: "member"),
    networkID: "network_1",
    nodeName: "ios-7f3a9c2d"
  )
  #expect(enrollment.node.site == "mobile")
  #expect(throws: TunnelUserEnrollmentError.self) {
    try TunnelUserSelfEnrollmentResponse.decode(
      response(role: "lighthouse"),
      networkID: "network_1",
      nodeName: "ios-7f3a9c2d"
    )
  }
}

@Test
func lifecycleRefreshOutcomesAreExactAndDoNotCarryCredentials() throws {
  let configuration = try payload().engineDocument()
  let ready = try JSONSerialization.data(
    withJSONObject: [
      "schema": TunnelLifecycleRefreshOutcome.schema,
      "status": "ready",
      "configuration": configuration,
    ],
    options: [.sortedKeys, .withoutEscapingSlashes]
  )
  let decodedReady = try TunnelLifecycleRefreshOutcome.decodeExact(ready)
  #expect(decodedReady.status == .ready)
  #expect(decodedReady.configuration == payload())
  let readyText = try #require(String(data: ready, encoding: .utf8))
  #expect(!readyText.contains("Bearer "))
  #expect(!readyText.contains("enrollmentToken"))

  for status in ["deferred", "unauthorized"] {
    let data = try JSONSerialization.data(
      withJSONObject: [
        "schema": TunnelLifecycleRefreshOutcome.schema,
        "status": status,
      ],
      options: [.sortedKeys]
    )
    let decoded = try TunnelLifecycleRefreshOutcome.decodeExact(data)
    #expect(decoded.configuration == nil)
    #expect(decoded.status.rawValue == status)
  }

  let unexpected = try JSONSerialization.data(
    withJSONObject: [
      "schema": TunnelLifecycleRefreshOutcome.schema,
      "status": "deferred",
      "unexpected": true,
    ],
    options: [.sortedKeys]
  )
  #expect(throws: TunnelContractError.invalidDocument) {
    try TunnelLifecycleRefreshOutcome.decodeExact(unexpected)
  }
}

@Test
func mobileRuntimeReportOutcomesAreExactAndVersioned() throws {
  for status in [
    "accepted",
    "deferred",
    "unauthorized",
    "refresh-required",
    "unsupported",
  ] {
    let data = try JSONSerialization.data(
      withJSONObject: [
        "schema": TunnelMobileRuntimeReportOutcome.schema,
        "status": status,
      ],
      options: [.sortedKeys]
    )
    let decoded = try TunnelMobileRuntimeReportOutcome.decodeExact(data)
    #expect(decoded.status.rawValue == status)
  }
  let unexpected = try JSONSerialization.data(
    withJSONObject: [
      "schema": TunnelMobileRuntimeReportOutcome.schema,
      "status": "accepted",
      "credential": "forbidden",
    ],
    options: [.sortedKeys]
  )
  #expect(throws: TunnelContractError.invalidDocument) {
    try TunnelMobileRuntimeReportOutcome.decodeExact(unexpected)
  }
}

@Test
func enrollmentRequestIsCanonicalBoundedAndSecretOnlyInItsEnvelope() throws {
  let token = base64URL(32, value: 0x55)
  let request = try TunnelEnrollmentRequest(
    requestID: "request_1",
    serverOrigin: "https://mesh.example/",
    enrollmentToken: token
  )
  #expect(request.serverOrigin == "https://mesh.example")
  let encoded = try request.encoded()
  #expect(try TunnelEnrollmentRequest.decodeExact(encoded) == request)
  #expect(String(decoding: encoded, as: UTF8.self).contains(token))

  let duplicate = Data(
    """
    {"enrollmentToken":"\(token)","requestID":"request_1",\
    "schema":"\(TunnelEnrollmentRequest.schema)",\
    "serverOrigin":"https://mesh.example",\
    "serverOrigin":"https://other.example"}
    """.utf8
  )
  #expect(throws: TunnelContractError.invalidDocument) {
    try TunnelEnrollmentRequest.decodeExact(duplicate)
  }
  for origin in [
    "http://mesh.example",
    "https://user@mesh.example",
    "https://mesh.example/path",
    "https://MESH.example",
  ] {
    #expect(throws: TunnelContractError.self) {
      try TunnelEnrollmentRequest(
        requestID: "request_1",
        serverOrigin: origin,
        enrollmentToken: token
      )
    }
  }
}

@Test
func verifiedEngineDocumentDecodesWithoutAnAppGroupEnvelope() throws {
  let value = payload()
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  let raw = try encoder.encode(value)
  #expect(try TunnelConfigurationPayload.decodeExact(raw) == value)
}

@Test
func packetValidationBindsFamilyAndExactLength() throws {
  _ = try ipv4Packet()
  _ = try ipv6Packet()
  var malformed = Data(repeating: 0, count: 20)
  malformed[0] = 0x45
  malformed[3] = 19
  #expect(throws: TunnelPacketError.invalidPacket) {
    try TunnelPacket(bytes: malformed, family: .ipv4)
  }
  #expect(throws: TunnelPacketError.familyMismatch) {
    try TunnelPacket(bytes: Data(repeating: 0x60, count: 40), family: .ipv4)
  }
}

@Test
func packetFlowBatchCodecMapsAppleFamiliesAndOwnsBytes() throws {
  let limits = try TunnelPacketFlowPumpLimits()
  let first = try ipv4Packet(1)
  let second = try ipv6Packet(2)
  var appleIPv4 = first.bytes
  let decoded = try TunnelPacketFlowBatchCodec.decodeAppleRead(
    packets: [appleIPv4, second.bytes],
    protocolFamilies: [
      TunnelPacketFlowBatchCodec.ipv4ProtocolFamily,
      TunnelPacketFlowBatchCodec.ipv6ProtocolFamily,
    ],
    limits: limits
  )
  appleIPv4[19] = 9
  #expect(decoded == [first, second])

  let encoded = try TunnelPacketFlowBatchCodec.encodeAppleWrite(
    decoded,
    limits: limits
  )
  #expect(encoded.packets == [first.bytes, second.bytes])
  #expect(
    encoded.protocolFamilies == [
      TunnelPacketFlowBatchCodec.ipv4ProtocolFamily,
      TunnelPacketFlowBatchCodec.ipv6ProtocolFamily,
    ])
}

@Test
func packetFlowBatchCodecRejectsMalformedAppleBatches() throws {
  let limits = try TunnelPacketFlowPumpLimits(
    maximumQueuedPackets: 1,
    maximumQueuedBytes: TunnelPacket.maximumBytes,
    maximumBatchPackets: 1,
    maximumBatchBytes: TunnelPacket.maximumBytes
  )
  let packet = try ipv4Packet()
  #expect(throws: TunnelPacketFlowBatchError.protocolCountMismatch) {
    try TunnelPacketFlowBatchCodec.decodeAppleRead(
      packets: [packet.bytes],
      protocolFamilies: [],
      limits: limits
    )
  }
  #expect(throws: TunnelPacketFlowBatchError.unsupportedProtocolFamily) {
    try TunnelPacketFlowBatchCodec.decodeAppleRead(
      packets: [packet.bytes],
      protocolFamilies: [-1],
      limits: limits
    )
  }
  #expect(throws: TunnelPacketFlowBatchError.invalidBatch) {
    try TunnelPacketFlowBatchCodec.decodeAppleRead(
      packets: [],
      protocolFamilies: [],
      limits: limits
    )
  }
  #expect(throws: TunnelPacketFlowBatchError.invalidBatch) {
    try TunnelPacketFlowBatchCodec.decodeAppleRead(
      packets: [packet.bytes, packet.bytes],
      protocolFamilies: [
        TunnelPacketFlowBatchCodec.ipv4ProtocolFamily,
        TunnelPacketFlowBatchCodec.ipv4ProtocolFamily,
      ],
      limits: limits
    )
  }
  #expect(throws: TunnelPacketError.familyMismatch) {
    try TunnelPacketFlowBatchCodec.decodeAppleRead(
      packets: [packet.bytes],
      protocolFamilies: [
        TunnelPacketFlowBatchCodec.ipv6ProtocolFamily
      ],
      limits: limits
    )
  }
}

@Test
func packetPumpAppliesAtomicBackpressureAndPreservesOrder() async throws {
  let limits = try TunnelPacketFlowPumpLimits(
    maximumQueuedPackets: 2,
    maximumQueuedBytes: TunnelPacket.maximumBytes * 2,
    maximumBatchPackets: 2,
    maximumBatchBytes: TunnelPacket.maximumBytes * 2
  )
  let pump = TunnelPacketFlowPump(limits: limits)
  try await pump.start()
  let first = try ipv4Packet(1)
  let second = try ipv4Packet(2)
  #expect(try await pump.offerFromApple([first, second]) == .accepted)
  #expect(try await pump.offerFromApple([try ipv4Packet(3)]) == .backpressured)
  let pressured = await pump.snapshot()
  #expect(pressured.appleToEngineQueuedPackets == 2)
  #expect(pressured.acceptedPackets == 2)
  #expect(try await pump.takeForEngine() == [first, second])
  #expect(try await pump.offerFromApple([try ipv4Packet(3)]) == .accepted)
  await #expect(throws: TunnelPacketFlowPumpError.invalidTransition) {
    try await pump.start()
  }
  await #expect(throws: TunnelPacketFlowPumpError.invalidBatch) {
    try await pump.offerFromEngine([])
  }
}

@Test
func packetPumpKeepsDirectionsIndependentAndStopsCleanly() async throws {
  let pump = TunnelPacketFlowPump(
    limits: try TunnelPacketFlowPumpLimits()
  )
  try await pump.start()
  let fromApple = try ipv4Packet(1)
  let fromEngine = try ipv6Packet(2)
  #expect(try await pump.offerFromApple([fromApple]) == .accepted)
  #expect(try await pump.offerFromEngine([fromEngine]) == .accepted)
  #expect(try await pump.takeForApple() == [fromEngine])
  await pump.stop()
  await pump.stop()
  let snapshot = await pump.snapshot()
  #expect(snapshot.state == .stopped)
  #expect(snapshot.appleToEngineQueuedPackets == 0)
  #expect(snapshot.engineToAppleQueuedPackets == 0)
  #expect(snapshot.acceptedPackets == 2)
  #expect(snapshot.deliveredPackets == 1)
  #expect(snapshot.discardedOnStop == 1)
  await #expect(throws: TunnelPacketFlowPumpError.notRunning) {
    try await pump.takeForEngine()
  }
  await #expect(throws: TunnelPacketFlowPumpError.invalidTransition) {
    try await pump.start()
  }
}

@Test
func runtimeCoordinatorOrdersStartupPacketsEvidenceAndCleanup() async throws {
  let recorder = RuntimeEventRecorder()
  let fromEngine = try ipv6Packet(2)
  let engine = RecordingEngineSession(
    recorder: recorder,
    receivedPackets: [fromEngine]
  )
  let settings = RecordingNetworkSettingsSession(recorder: recorder)
  let coordinator = TunnelRuntimeCoordinator(
    configuration: payload(),
    engine: engine,
    networkSettings: settings,
    limits: try TunnelPacketFlowPumpLimits()
  )

  try await coordinator.start()
  #expect(
    await recorder.snapshot() == [
      "engine-identity",
      "engine-prepare-7",
      "settings-apply-192.0.2.9-1300",
      "engine-start",
    ])

  try await coordinator.sendFromApple([try ipv4Packet(1)])
  try await coordinator.rebind()
  #expect(try await coordinator.receiveForApple() == [fromEngine])
  let evidence = try await coordinator.runtimeEvidence(sequence: 11)
  #expect(evidence.state == .running)
  #expect(evidence.configRevision == 7)
  #expect(evidence.certificateGeneration == 2)
  #expect(evidence.engineIdentity == digest)
  #expect(evidence.packetsRead == 1)
  #expect(evidence.packetsWritten == 1)

  await coordinator.stop()
  await coordinator.stop()
  let stopped = await coordinator.snapshot()
  #expect(stopped.state == .stopped)
  #expect(stopped.queuedPackets == 0)
  #expect(
    await recorder.snapshot() == [
      "engine-identity",
      "engine-prepare-7",
      "settings-apply-192.0.2.9-1300",
      "engine-start",
      "engine-send-1",
      "engine-rebind",
      "engine-receive",
      "engine-stop",
      "settings-clear",
    ])
}

@Test
func runtimeCoordinatorFailsClosedBeforeSettingsOnIdentityMismatch() async throws {
  let recorder = RuntimeEventRecorder()
  let engine = RecordingEngineSession(
    identity: String(repeating: "b", count: 64),
    recorder: recorder
  )
  let settings = RecordingNetworkSettingsSession(recorder: recorder)
  let coordinator = TunnelRuntimeCoordinator(
    configuration: payload(),
    engine: engine,
    networkSettings: settings,
    limits: try TunnelPacketFlowPumpLimits()
  )

  await #expect(
    throws: TunnelRuntimeCoordinatorError.engineIdentityMismatch
  ) {
    try await coordinator.start()
  }
  #expect((await coordinator.snapshot()).state == .failed)
  #expect(await recorder.snapshot() == ["engine-identity"])
}

@Test
func runtimeCoordinatorClearsPartiallyAppliedSettingsAndPreparedEngine() async throws {
  let recorder = RuntimeEventRecorder()
  let engine = RecordingEngineSession(recorder: recorder)
  let settings = RecordingNetworkSettingsSession(
    recorder: recorder,
    applyFailure: true
  )
  let coordinator = TunnelRuntimeCoordinator(
    configuration: payload(),
    engine: engine,
    networkSettings: settings,
    limits: try TunnelPacketFlowPumpLimits()
  )

  await #expect(throws: RuntimeTestFailure.settings) {
    try await coordinator.start()
  }
  #expect((await coordinator.snapshot()).state == .failed)
  #expect(
    await recorder.snapshot() == [
      "engine-identity",
      "engine-prepare-7",
      "settings-apply-192.0.2.9-1300",
      "engine-stop",
      "settings-clear",
    ])
}

@Test
func runtimeCoordinatorStopsAfterEnginePacketFailure() async throws {
  let recorder = RuntimeEventRecorder()
  let engine = RecordingEngineSession(
    recorder: recorder,
    sendFailure: true
  )
  let settings = RecordingNetworkSettingsSession(recorder: recorder)
  let coordinator = TunnelRuntimeCoordinator(
    configuration: payload(),
    engine: engine,
    networkSettings: settings,
    limits: try TunnelPacketFlowPumpLimits()
  )
  try await coordinator.start()

  await #expect(throws: RuntimeTestFailure.send) {
    try await coordinator.sendFromApple([try ipv4Packet(1)])
  }
  #expect((await coordinator.snapshot()).state == .failed)
  #expect(
    await recorder.snapshot().suffix(3) == [
      "engine-send-1",
      "engine-stop",
      "settings-clear",
    ])
}

@Test
func runtimeCoordinatorFailsClosedAfterEngineRebindFailure() async throws {
  let recorder = RuntimeEventRecorder()
  let engine = RecordingEngineSession(
    recorder: recorder,
    rebindFailure: true
  )
  let settings = RecordingNetworkSettingsSession(recorder: recorder)
  let coordinator = TunnelRuntimeCoordinator(
    configuration: payload(),
    engine: engine,
    networkSettings: settings,
    limits: try TunnelPacketFlowPumpLimits()
  )
  try await coordinator.start()

  await #expect(throws: RuntimeTestFailure.rebind) {
    try await coordinator.rebind()
  }
  #expect((await coordinator.snapshot()).state == .failed)
  #expect(
    await recorder.snapshot().suffix(3) == [
      "engine-rebind",
      "engine-stop",
      "settings-clear",
    ])
}

@Test
func networkSettingsRejectAmbiguityAndUnsafeValues() throws {
  let hostBits = TunnelNetworkSettingsPlan(
    addresses: [TunnelIPPrefix(address: "10.42.0.7", prefixLength: 24)],
    includedRoutes: [
      TunnelIPPrefix(address: "10.42.0.7", prefixLength: 24)
    ],
    mtu: 1300
  )
  let hostBitsPayload = TunnelConfigurationPayload(
    networkID: "network_1",
    nodeID: "node_1",
    certificateFingerprint: digest,
    certificateGeneration: 2,
    configRevision: 7,
    configDigest: lowerHexSHA256(signedConfig),
    engineIdentity: digest,
    tunnelRemoteAddress: try TunnelRemoteAddress("192.0.2.9"),
    networkSettings: hostBits,
    monotonicCounter: 9,
    issuedAtMilliseconds: 1_785_000_000_000,
    nebula: nebulaConfiguration()
  )
  #expect(
    throws: TunnelContractError.invalidField(
      "networkSettings.includedRoutes"
    )
  ) {
    try TunnelEnvelopeAuthenticator.seal(hostBitsPayload, using: key)
  }

  let noncanonical = TunnelNetworkSettingsPlan(
    addresses: [TunnelIPPrefix(address: "fd00:0042::7", prefixLength: 64)],
    includedRoutes: [TunnelIPPrefix(address: "::", prefixLength: 0)],
    mtu: 1300
  )
  let noncanonicalPayload = TunnelConfigurationPayload(
    networkID: "network_1",
    nodeID: "node_1",
    certificateFingerprint: digest,
    certificateGeneration: 2,
    configRevision: 7,
    configDigest: lowerHexSHA256(signedConfig),
    engineIdentity: digest,
    tunnelRemoteAddress: try TunnelRemoteAddress("192.0.2.9"),
    networkSettings: noncanonical,
    monotonicCounter: 9,
    issuedAtMilliseconds: 1_785_000_000_000,
    nebula: nebulaConfiguration()
  )
  #expect(
    throws: TunnelContractError.invalidField(
      "networkSettings.addresses"
    )
  ) {
    try TunnelEnvelopeAuthenticator.seal(noncanonicalPayload, using: key)
  }

  let wrongFamilyDNS = TunnelNetworkSettingsPlan(
    addresses: [TunnelIPPrefix(address: "10.42.0.7", prefixLength: 24)],
    includedRoutes: [
      TunnelIPPrefix(address: "0.0.0.0", prefixLength: 0)
    ],
    dnsServers: ["fd00:42::1"],
    mtu: 1300
  )
  let wrongFamilyPayload = TunnelConfigurationPayload(
    networkID: "network_1",
    nodeID: "node_1",
    certificateFingerprint: digest,
    certificateGeneration: 2,
    configRevision: 7,
    configDigest: lowerHexSHA256(signedConfig),
    engineIdentity: digest,
    tunnelRemoteAddress: try TunnelRemoteAddress("192.0.2.9"),
    networkSettings: wrongFamilyDNS,
    monotonicCounter: 9,
    issuedAtMilliseconds: 1_785_000_000_000,
    nebula: nebulaConfiguration()
  )
  #expect(
    throws: TunnelContractError.invalidField(
      "networkSettings.dnsServers"
    )
  ) {
    try TunnelEnvelopeAuthenticator.seal(wrongFamilyPayload, using: key)
  }
}

@Test
func appleNetworkSettingsMapEveryValidatedField() throws {
  let mapped = try TunnelAppleNetworkSettingsFactory.make(
    plan: networkSettings(),
    tunnelRemoteAddress: TunnelRemoteAddress("192.0.2.9")
  )
  #expect(mapped.tunnelRemoteAddress == "192.0.2.9")
  #expect(mapped.mtu == 1300)
  #expect(mapped.ipv4Settings?.addresses == ["10.42.0.7"])
  #expect(mapped.ipv4Settings?.subnetMasks == ["255.255.255.0"])
  #expect(
    mapped.ipv4Settings?.includedRoutes?.map(\.destinationAddress) == [
      "0.0.0.0"
    ])
  #expect(
    mapped.ipv4Settings?.excludedRoutes?.map(\.destinationAddress) == [
      "192.0.2.0"
    ])
  #expect(mapped.ipv6Settings?.addresses == ["fd00:42::7"])
  #expect(mapped.ipv6Settings?.networkPrefixLengths == [64])
  #expect(
    mapped.ipv6Settings?.includedRoutes?.map(\.destinationAddress) == [
      "::"
    ])
  #expect(mapped.dnsSettings?.servers == ["10.42.0.1", "fd00:42::1"])
}

@Test
func appleNetworkSettingsRejectInvalidOrMissingRemoteEndpoint() throws {
  #expect(throws: TunnelContractError.invalidField("tunnelRemoteAddress")) {
    try TunnelRemoteAddress("mesh-overlay")
  }
  #expect(throws: TunnelContractError.invalidField("tunnelRemoteAddress")) {
    try TunnelRemoteAddress("127.0.0.1")
  }
}

@Test
func authenticatedRemoteEndpointMustRemainOutsideSelectedTunnelRoutes() throws {
  let unsafe = TunnelConfigurationPayload(
    networkID: "network_1",
    nodeID: "node_1",
    certificateFingerprint: digest,
    certificateGeneration: 2,
    configRevision: 7,
    configDigest: lowerHexSHA256(signedConfig),
    engineIdentity: digest,
    tunnelRemoteAddress: try TunnelRemoteAddress("203.0.113.9"),
    networkSettings: networkSettings(),
    monotonicCounter: 9,
    issuedAtMilliseconds: 1_785_000_000_000,
    nebula: nebulaConfiguration()
  )
  #expect(
    throws: TunnelContractError.invalidField(
      "networkSettings.remoteEndpointRoute"
    )
  ) {
    try TunnelEnvelopeAuthenticator.seal(unsafe, using: key)
  }

  let sealed = try TunnelEnvelopeAuthenticator.seal(payload(), using: key)
  let opened = try TunnelEnvelopeAuthenticator.open(sealed, using: key)
  #expect(opened.tunnelRemoteAddress.value == "192.0.2.9")
}

@Test
func envelopeDecoderRevalidatesAndRequiresRemoteEndpoint() throws {
  let sealed = try TunnelEnvelopeAuthenticator.seal(payload(), using: key)
  var object = try #require(
    JSONSerialization.jsonObject(with: sealed) as? [String: Any]
  )
  var payloadObject = try #require(object["payload"] as? [String: Any])
  payloadObject["tunnelRemoteAddress"] = "127.0.0.1"
  object["payload"] = payloadObject
  let loopback = try JSONSerialization.data(withJSONObject: object)
  #expect(
    throws: TunnelContractError.invalidField(
      "tunnelRemoteAddress"
    )
  ) {
    try TunnelEnvelopeAuthenticator.open(loopback, using: key)
  }

  object = try #require(
    JSONSerialization.jsonObject(with: sealed) as? [String: Any]
  )
  payloadObject = try #require(object["payload"] as? [String: Any])
  payloadObject.removeValue(forKey: "tunnelRemoteAddress")
  object["payload"] = payloadObject
  let missing = try JSONSerialization.data(withJSONObject: object)
  #expect(throws: TunnelContractError.invalidDocument) {
    try TunnelEnvelopeAuthenticator.open(missing, using: key)
  }
}

@Test
func envelopeRejectsUnknownNetworkSettingsFields() throws {
  let sealed = try TunnelEnvelopeAuthenticator.seal(payload(), using: key)
  var object = try #require(
    JSONSerialization.jsonObject(with: sealed) as? [String: Any]
  )
  var payloadObject = try #require(object["payload"] as? [String: Any])
  var settings = try #require(
    payloadObject["networkSettings"] as? [String: Any]
  )
  settings["matchDomains"] = [""]
  payloadObject["networkSettings"] = settings
  object["payload"] = payloadObject
  let expanded = try JSONSerialization.data(withJSONObject: object)
  #expect(throws: TunnelContractError.invalidDocument) {
    try TunnelEnvelopeAuthenticator.open(expanded, using: key)
  }

  object = try #require(
    JSONSerialization.jsonObject(with: sealed) as? [String: Any]
  )
  payloadObject = try #require(object["payload"] as? [String: Any])
  settings = try #require(
    payloadObject["networkSettings"] as? [String: Any]
  )
  var addresses = try #require(settings["addresses"] as? [[String: Any]])
  addresses[0]["scopeID"] = 4
  settings["addresses"] = addresses
  payloadObject["networkSettings"] = settings
  object["payload"] = payloadObject
  let expandedElement = try JSONSerialization.data(withJSONObject: object)
  #expect(throws: TunnelContractError.invalidDocument) {
    try TunnelEnvelopeAuthenticator.open(expandedElement, using: key)
  }
}

@Test
func envelopeRejectsUnknownNebulaFields() throws {
  let sealed = try TunnelEnvelopeAuthenticator.seal(payload(), using: key)
  var object = try #require(
    JSONSerialization.jsonObject(with: sealed) as? [String: Any]
  )
  var payloadObject = try #require(object["payload"] as? [String: Any])
  var nebula = try #require(payloadObject["nebula"] as? [String: Any])
  nebula["privateKey"] = "must-not-be-accepted"
  payloadObject["nebula"] = nebula
  object["payload"] = payloadObject
  let expanded = try JSONSerialization.data(withJSONObject: object)
  #expect(throws: TunnelContractError.invalidDocument) {
    try TunnelEnvelopeAuthenticator.open(expanded, using: key)
  }
}

@Test
func payloadBindsNebulaConfigAndCADigests() throws {
  let modifiedConfig = nebulaConfiguration(
    config: signedConfig + "# tampered\n"
  )
  #expect(throws: TunnelContractError.invalidField("configDigest")) {
    try TunnelEnvelopeAuthenticator.seal(
      payload(nebula: modifiedConfig),
      using: key
    )
  }

  let modifiedCA = nebulaConfiguration(
    ca: caCertificate + "tampered\n",
    caCertificateSHA256: lowerHexSHA256(caCertificate)
  )
  #expect(
    throws: TunnelContractError.invalidField(
      "nebula.caCertificateSHA256"
    )
  ) {
    try TunnelEnvelopeAuthenticator.seal(
      payload(nebula: modifiedCA),
      using: key
    )
  }
}

@Test
func payloadRejectsInvalidNebulaLifecycleTimestamps() throws {
  let nonCanonical = nebulaConfiguration(
    configIssuedAt: "2026-07-24T12:00:00.0Z"
  )
  #expect(
    throws: TunnelContractError.invalidField(
      "nebula.configIssuedAt"
    )
  ) {
    try TunnelEnvelopeAuthenticator.seal(
      payload(nebula: nonCanonical),
      using: key
    )
  }

  let renewalAtExpiry = nebulaConfiguration(
    certificateExpiresAt: "2026-07-25T12:00:00Z",
    certificateRenewAfter: "2026-07-25T12:00:00Z"
  )
  #expect(throws: TunnelContractError.invalidField("nebula.lifecycle")) {
    try TunnelEnvelopeAuthenticator.seal(
      payload(nebula: renewalAtExpiry),
      using: key
    )
  }

  let issuedAfterExpiry = nebulaConfiguration(
    configIssuedAt: "2026-07-26T12:00:00Z",
    certificateExpiresAt: "2026-07-25T12:00:00Z"
  )
  #expect(throws: TunnelContractError.invalidField("nebula.lifecycle")) {
    try TunnelEnvelopeAuthenticator.seal(
      payload(nebula: issuedAfterExpiry),
      using: key
    )
  }
}

@Test
func authenticatedEnvelopeRoundTripsExactly() throws {
  let sealed = try TunnelEnvelopeAuthenticator.seal(payload(), using: key)
  let opened = try TunnelEnvelopeAuthenticator.open(sealed, using: key)
  #expect(opened == payload())
}

@Test
func envelopeRejectsWrongKeyAndUnknownFields() throws {
  let sealed = try TunnelEnvelopeAuthenticator.seal(payload(), using: key)
  let otherKey = SymmetricKey(data: Data(repeating: 0x24, count: 32))
  #expect(throws: TunnelContractError.authenticationFailed) {
    try TunnelEnvelopeAuthenticator.open(sealed, using: otherKey)
  }

  var object = try #require(
    JSONSerialization.jsonObject(with: sealed) as? [String: Any]
  )
  object["privateKey"] = "must-not-be-accepted"
  let expanded = try JSONSerialization.data(withJSONObject: object)
  #expect(throws: TunnelContractError.invalidDocument) {
    try TunnelEnvelopeAuthenticator.open(expanded, using: key)
  }
}

@Test
func controlRequestRejectsUnknownOperationsAndFields() throws {
  let request = TunnelControlRequest(requestID: "request_1")
  let encoded = try request.encoded()
  #expect(try TunnelControlRequest.decodeExact(encoded) == request)

  let expanded = Data(
    """
    {"schema":"mesh-ios-tunnel-control-v1","requestID":"request_1",\
    "operation":"status","path":"/private/key"}
    """.utf8
  )
  #expect(throws: TunnelContractError.invalidDocument) {
    try TunnelControlRequest.decodeExact(expanded)
  }

  let evidence = TunnelRuntimeEvidence(
    sequence: 1,
    state: .stopped
  )
  let outcome = try TunnelControlOutcome(
    requestID: request.requestID,
    evidence: evidence
  )
  #expect(
    try TunnelControlOutcome.decodeExact(outcome.encoded())
      == outcome
  )
  let mismatched = Data(
    """
    {"evidence":{"schema":"mesh-ios-tunnel-evidence-v1",\
    "sequence":1,"state":"stopped"},\
    "requestID":"request_2",\
    "schema":"mesh-ios-tunnel-control-outcome-v1",\
    "unexpected":true}
    """.utf8
  )
  #expect(throws: TunnelContractError.invalidDocument) {
    try TunnelControlOutcome.decodeExact(mismatched)
  }
}

@Test
func identityRemovalRequestAndOutcomeRequireExactNodeContext() throws {
  let request = try TunnelIdentityRemovalRequest(
    requestID: "removal_1",
    confirmationNodeID: "node_1"
  )
  #expect(
    try TunnelIdentityRemovalRequest.decodeExact(request.encoded())
      == request
  )
  let outcome = try TunnelIdentityRemovalOutcome(
    requestID: request.requestID,
    nodeID: request.confirmationNodeID
  )
  #expect(
    try TunnelIdentityRemovalOutcome.decodeExact(outcome.encoded())
      == outcome
  )
  let expanded = Data(
    """
    {"schema":"mesh-ios-identity-removal-request-v1",\
    "requestID":"removal_1","confirmationNodeID":"node_1",\
    "path":"/private/key"}
    """.utf8
  )
  #expect(throws: Error.self) {
    try TunnelIdentityRemovalRequest.decodeExact(expanded)
  }
}

@Test
func runningEvidenceRequiresRealEngineAndPacketFields() throws {
  let incomplete = TunnelRuntimeEvidence(
    sequence: 1,
    state: .running
  )
  #expect(throws: TunnelContractError.invalidField("runningEvidence")) {
    try incomplete.encoded()
  }

  let unavailable = TunnelRuntimeEvidence(
    sequence: 2,
    state: .extensionError,
    errorCode: "engine-unavailable"
  )
  let encoded = try unavailable.encoded()
  let text = try #require(String(data: encoded, encoding: .utf8))
  #expect(text.contains("\"state\":\"extension-error\""))
  #expect(!text.contains("healthy"))

  let running = TunnelRuntimeEvidence(
    sequence: 3,
    state: .running,
    configRevision: 7,
    certificateGeneration: 2,
    engineIdentity: String(repeating: "a", count: 64),
    packetsRead: 11,
    packetsWritten: 9
  )
  #expect(
    try TunnelRuntimeEvidence.decodeExact(running.encoded())
      == running
  )

  let pollutedStopped = TunnelRuntimeEvidence(
    sequence: 4,
    state: .stopped,
    packetsRead: 1
  )
  #expect(throws: TunnelContractError.invalidField("nonRunningEvidence")) {
    try pollutedStopped.encoded()
  }

  let missingError = TunnelRuntimeEvidence(
    sequence: 5,
    state: .extensionError
  )
  #expect(throws: TunnelContractError.invalidField("errorCode")) {
    try missingError.encoded()
  }

  var expanded = try #require(
    JSONSerialization.jsonObject(
      with: running.encoded()
    ) as? [String: Any]
  )
  expanded["nodeID"] = "must-not-be-accepted"
  let expandedData = try JSONSerialization.data(
    withJSONObject: expanded,
    options: [.sortedKeys, .withoutEscapingSlashes]
  )
  #expect(throws: TunnelContractError.invalidDocument) {
    try TunnelRuntimeEvidence.decodeExact(expandedData)
  }
}

@Test
func providerLifecycleGateSerializesStartAndLatchesStop() {
  let gate = TunnelProviderLifecycleGate()
  #expect(gate.beginStart() == .begin)
  #expect(gate.beginStart() == .alreadyStarting)
  #expect(gate.mayContinueStart())
  #expect(gate.markRunning())
  #expect(gate.beginStart() == .alreadyRunning)
  #expect(!gate.latchStop())
  #expect(gate.isStopped())
  #expect(gate.beginStart() == .stopped)
  #expect(!gate.markRunning())
  #expect(gate.latchStop())
}

@Test
func providerLifecycleGateRejectsStopRacingStart() {
  let gate = TunnelProviderLifecycleGate()
  #expect(gate.beginStart() == .begin)
  #expect(!gate.latchStop())
  #expect(!gate.mayContinueStart())
  #expect(!gate.markRunning())
  gate.finishStartFailure()
  #expect(gate.beginStart() == .stopped)
}

@Test
func providerLifecycleGateAllowsRetryAfterStartFailure() {
  let gate = TunnelProviderLifecycleGate()
  #expect(gate.beginStart() == .begin)
  gate.finishStartFailure()
  #expect(gate.beginStart() == .begin)
  #expect(gate.markRunning())
}

@Test
func providerStartObservationRequiresConnected() {
  var observation = TunnelProviderStartObservation()
  #expect(observation.observe(.disconnected) == .pending)
  #expect(observation.observe(.connecting) == .pending)
  #expect(observation.observe(.reasserting) == .pending)
  #expect(observation.observe(.connected) == .connected)
}

@Test
func providerStartObservationAttributesOnlyPostProgressDisconnect() {
  var neverStarted = TunnelProviderStartObservation()
  #expect(neverStarted.observe(.disconnected) == .pending)

  var stopped = TunnelProviderStartObservation()
  #expect(stopped.observe(.connecting) == .pending)
  #expect(
    stopped.observe(.disconnected) == .disconnectedAfterProgress
  )

  var invalid = TunnelProviderStartObservation()
  #expect(invalid.observe(.reasserting) == .pending)
  #expect(invalid.observe(.disconnecting) == .invalid)
  #expect(invalid.observe(.invalid) == .invalid)
}

@Test
func providerObservationBudgetExpiresAcrossSuspension() {
  let budget = TunnelProviderObservationBudget()
  #expect(budget.remaining(after: .seconds(89)) != nil)
  #expect(budget.remaining(after: .seconds(90)) == nil)
  #expect(budget.remaining(after: .seconds(600)) == nil)
}

@Test
func providerStartProofRejectsConnectedThenDisconnectedRace() {
  #expect(
    TunnelProviderStartProof.accepts(
      finalStatus: .connected,
      connectionDateChanged: true,
      sameOriginIdentity: true
    )
  )
  #expect(
    !TunnelProviderStartProof.accepts(
      finalStatus: .disconnected,
      connectionDateChanged: true,
      sameOriginIdentity: true
    )
  )
  #expect(
    !TunnelProviderStartProof.accepts(
      finalStatus: .connected,
      connectionDateChanged: false,
      sameOriginIdentity: true
    )
  )
  #expect(
    !TunnelProviderStartProof.accepts(
      finalStatus: .connected,
      connectionDateChanged: true,
      sameOriginIdentity: false
    )
  )
}

@Test
func providerFailureClassificationRequiresExactRequestAndAllowlist() {
  let requestID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  let allowed = Set(["enrollment-failed"])
  let exact = TunnelProviderFailureClassifier.classify(
    domain: TunnelProviderFailureContract.domain,
    schema: TunnelProviderFailureContract.schema,
    code: "enrollment-failed",
    requestID: requestID,
    expectedRequestID: requestID,
    allowedCodes: allowed
  )
  #expect(exact == "enrollment-failed")
  #expect(exact != requestID)

  for result in [
    TunnelProviderFailureClassifier.classify(
      domain: "arbitrary",
      schema: TunnelProviderFailureContract.schema,
      code: "enrollment-failed",
      requestID: requestID,
      expectedRequestID: requestID,
      allowedCodes: allowed
    ),
    TunnelProviderFailureClassifier.classify(
      domain: TunnelProviderFailureContract.domain,
      schema: "wrong",
      code: "enrollment-failed",
      requestID: requestID,
      expectedRequestID: requestID,
      allowedCodes: allowed
    ),
    TunnelProviderFailureClassifier.classify(
      domain: TunnelProviderFailureContract.domain,
      schema: TunnelProviderFailureContract.schema,
      code: "raw-provider-text",
      requestID: requestID,
      expectedRequestID: requestID,
      allowedCodes: allowed
    ),
    TunnelProviderFailureClassifier.classify(
      domain: TunnelProviderFailureContract.domain,
      schema: TunnelProviderFailureContract.schema,
      code: "enrollment-failed",
      requestID: "ffffffff-1111-2222-3333-444444444444",
      expectedRequestID: requestID,
      allowedCodes: allowed
    ),
  ] {
    #expect(result == TunnelProviderFailureClassifier.genericCode)
    #expect(result != requestID)
  }
}

@Test
func disconnectCallbackAndTimeoutResolveExactlyOnce() {
  var callbackFirst: [String] = []
  let callbackGate = TunnelOneShotResult<String> {
    callbackFirst.append($0)
  }
  #expect(callbackGate.resolve("callback"))
  #expect(!callbackGate.resolve("timeout"))
  #expect(callbackFirst == ["callback"])

  var timeoutFirst: [String] = []
  let timeoutGate = TunnelOneShotResult<String> {
    timeoutFirst.append($0)
  }
  #expect(timeoutGate.resolve("timeout"))
  #expect(!timeoutGate.resolve("callback"))
  #expect(timeoutFirst == ["timeout"])
}

@Test
func configurationSlotsActivateMonotonicallyAndPreserveRecovery() throws {
  let root = FileManager.default.temporaryDirectory.appending(
    path: "mesh-tunnel-store-\(UUID().uuidString)",
    directoryHint: .isDirectory
  )
  try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: root) }
  let highWater = MemoryHighWater()
  let store = try TunnelConfigurationStore(
    containerURL: root,
    key: key,
    highWater: highWater
  )

  let first = payload()
  try store.stage(first)
  #expect(try store.activateCandidate() == first)
  #expect(highWater.value == first.monotonicCounter)
  #expect(try store.nextMonotonicCounter() == first.monotonicCounter + 1)

  let second = TunnelConfigurationPayload(
    networkID: first.networkID,
    nodeID: first.nodeID,
    controlPlaneOrigin: first.controlPlaneOrigin,
    agentCredentialGeneration: first.agentCredentialGeneration,
    agentCredentialExpiresAt: first.agentCredentialExpiresAt,
    certificateFingerprint: first.certificateFingerprint,
    certificateGeneration: first.certificateGeneration,
    configRevision: first.configRevision + 1,
    configDigest: first.configDigest,
    engineIdentity: first.engineIdentity,
    tunnelRemoteAddress: first.tunnelRemoteAddress,
    networkSettings: first.networkSettings,
    monotonicCounter: first.monotonicCounter + 1,
    issuedAtMilliseconds: first.issuedAtMilliseconds + 1,
    nebula: first.nebula
  )
  try store.stage(second)
  #expect(try store.activateCandidate() == second)
  #expect(try store.readCurrent() == second)
  #expect(try store.readRecovery() == first)
  highWater.value = second.monotonicCounter + 4
  #expect(
    try store.nextMonotonicCounter()
      == second.monotonicCounter + 5
  )
  try TunnelConfigurationStore.eraseAll(containerURL: root)
  #expect(try store.readCurrent() == nil)
  #expect(try store.readRecovery() == nil)
}

@Test
func configurationSlotsRejectReplayAndSymlinkInput() throws {
  let root = FileManager.default.temporaryDirectory.appending(
    path: "mesh-tunnel-store-\(UUID().uuidString)",
    directoryHint: .isDirectory
  )
  try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: root) }
  let store = try TunnelConfigurationStore(
    containerURL: root,
    key: key,
    highWater: MemoryHighWater()
  )
  try store.stage(payload())
  _ = try store.activateCandidate()
  #expect(throws: TunnelConfigurationStoreError.rollbackOrReplay) {
    try store.stage(payload())
  }

  let candidate = root.appending(path: TunnelConfigurationStore.candidateSlot)
  try FileManager.default.createSymbolicLink(
    at: candidate,
    withDestinationURL: root.appending(path: TunnelConfigurationStore.currentSlot)
  )
  #expect(throws: TunnelConfigurationStoreError.self) {
    _ = try store.activateCandidate()
  }
}
