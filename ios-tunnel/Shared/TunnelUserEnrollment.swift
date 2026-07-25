import Foundation

public enum TunnelUserEnrollmentError: Error, Equatable {
  case invalidDocument
  case invalidField(String)
  case authorizationDenied
  case authorizationExpired
  case authorizationCancelled
  case authorizationUnavailable
  case networkSelectionRequired
}

public struct TunnelUserAuthorizationStartResponse:
  Codable,
  Equatable,
  Sendable
{
  public let requestID: String
  public let pollSecret: String
  public let verificationURL: String
  public let expiresAt: String
  public let intervalSeconds: Int

  private enum CodingKeys: String, CodingKey {
    case requestID = "request_id"
    case pollSecret = "poll_secret"
    case verificationURL = "verification_url"
    case expiresAt = "expires_at"
    case intervalSeconds = "interval_seconds"
  }

  public static func decode(
    _ data: Data,
    serverOrigin: String
  ) throws -> Self {
    try TunnelUserEnrollmentJSON.requireObject(
      data,
      keys: [
        "request_id",
        "poll_secret",
        "verification_url",
        "expires_at",
        "interval_seconds",
      ],
      maximumBytes: 8 * 1024
    )
    let value = try JSONDecoder().decode(Self.self, from: data)
    try value.validate(serverOrigin: serverOrigin)
    return value
  }

  public func validatedVerificationURL(
    serverOrigin: String
  ) throws -> URL {
    try validate(serverOrigin: serverOrigin)
    guard let url = URL(string: verificationURL) else {
      throw TunnelUserEnrollmentError.invalidField("verification_url")
    }
    return url
  }

  public func expirationDate() throws -> Date {
    try TunnelUserEnrollmentField.timestamp(
      expiresAt,
      name: "expires_at"
    )
  }

  private func validate(serverOrigin: String) throws {
    let normalizedOrigin = try TunnelEnrollmentRequest.normalizedOrigin(
      serverOrigin
    )
    try TunnelUserEnrollmentField.identifier(
      requestID,
      name: "request_id"
    )
    guard requestID.hasPrefix("desktop_") else {
      throw TunnelUserEnrollmentError.invalidField("request_id")
    }
    try TunnelUserEnrollmentField.base64URL(
      pollSecret,
      bytes: 32,
      name: "poll_secret"
    )
    guard (1...60).contains(intervalSeconds),
      let origin = URLComponents(string: normalizedOrigin),
      let verification = URLComponents(string: verificationURL),
      verification.scheme == origin.scheme,
      verification.host == origin.host,
      verification.port == origin.port,
      verification.user == nil,
      verification.password == nil,
      verification.path == "/",
      verification.fragment == nil,
      verification.queryItems == [
        URLQueryItem(
          name: "mesh_desktop_request",
          value: requestID
        )
      ]
    else {
      throw TunnelUserEnrollmentError.invalidField("verification_url")
    }
    _ = try expirationDate()
  }
}

public struct TunnelUserAuthorizationCompletionResponse:
  Codable,
  Equatable,
  Sendable
{
  public enum State: String, Codable, Sendable {
    case pending
    case authorized
    case denied
    case expired
  }

  public struct Session: Codable, Equatable, Sendable {
    public let authenticated: Bool
    public let authMethod: String
    public let role: String
    public let permissions: [String]

    private enum CodingKeys: String, CodingKey {
      case authenticated
      case authMethod = "auth_method"
      case role
      case permissions
    }
  }

  public let state: State
  public let expiresAt: String
  public let intervalSeconds: Int
  public let session: Session?

  private enum CodingKeys: String, CodingKey {
    case state
    case expiresAt = "expires_at"
    case intervalSeconds = "interval_seconds"
    case session
  }

  public static func decode(_ data: Data) throws -> Self {
    guard !data.isEmpty, data.count <= 64 * 1024,
      let object = try JSONSerialization.jsonObject(
        with: data,
        options: [.fragmentsAllowed]
      ) as? [String: Any]
    else {
      throw TunnelUserEnrollmentError.invalidDocument
    }
    let baseKeys: Set<String> = [
      "state",
      "expires_at",
      "interval_seconds",
    ]
    guard Set(object.keys) == baseKeys
      || Set(object.keys) == baseKeys.union(["session"])
    else {
      throw TunnelUserEnrollmentError.invalidDocument
    }
    let value = try JSONDecoder().decode(Self.self, from: data)
    try value.validate()
    return value
  }

  public func expirationDate() throws -> Date {
    try TunnelUserEnrollmentField.timestamp(
      expiresAt,
      name: "expires_at"
    )
  }

  private func validate() throws {
    guard (1...60).contains(intervalSeconds) else {
      throw TunnelUserEnrollmentError.invalidField("interval_seconds")
    }
    _ = try expirationDate()
    switch state {
    case .authorized:
      guard let session,
        session.authenticated,
        session.authMethod == "oidc",
        ["member", "operator", "admin"].contains(session.role),
        session.permissions.contains("nodes.enroll.self")
      else {
        throw TunnelUserEnrollmentError.authorizationUnavailable
      }
    case .pending, .denied, .expired:
      guard session == nil else {
        throw TunnelUserEnrollmentError.invalidDocument
      }
    }
  }
}

public struct TunnelUserNetwork: Codable, Equatable, Sendable {
  public let id: String
  public let name: String

  public static func decodeList(_ data: Data) throws -> [Self] {
    guard !data.isEmpty, data.count <= 4 * 1024 * 1024 else {
      throw TunnelUserEnrollmentError.invalidDocument
    }
    let values = try JSONDecoder().decode([Self].self, from: data)
    for value in values {
      try TunnelUserEnrollmentField.identifier(
        value.id,
        name: "network.id"
      )
      guard !value.name.isEmpty, value.name.utf8.count <= 128 else {
        throw TunnelUserEnrollmentError.invalidField("network.name")
      }
    }
    return values
  }
}

public struct TunnelUserSelfEnrollmentRequest:
  Codable,
  Equatable,
  Sendable
{
  public let name: String

  public init(name: String) throws {
    try TunnelUserEnrollmentField.nodeName(name)
    self.name = name
  }

  public func encoded() throws -> Data {
    try TunnelUserEnrollmentField.nodeName(name)
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try encoder.encode(self)
  }
}

public struct TunnelUserSelfEnrollmentResponse:
  Codable,
  Equatable,
  Sendable
{
  public struct Node: Codable, Equatable, Sendable {
    public let id: String
    public let networkID: String
    public let name: String
    public let site: String
    public let groups: [String]
    public let role: String
    public let status: String

    private enum CodingKeys: String, CodingKey {
      case id
      case networkID = "network_id"
      case name
      case site
      case groups
      case role
      case status
    }
  }

  public let node: Node
  public let enrollmentToken: String
  public let expiresAt: String

  private enum CodingKeys: String, CodingKey {
    case node
    case enrollmentToken = "enrollment_token"
    case expiresAt = "expires_at"
  }

  public static func decode(
    _ data: Data,
    networkID: String,
    nodeName: String
  ) throws -> Self {
    try TunnelUserEnrollmentJSON.requireObject(
      data,
      keys: ["node", "enrollment_token", "expires_at"],
      maximumBytes: 256 * 1024
    )
    let value = try JSONDecoder().decode(Self.self, from: data)
    try value.validate(networkID: networkID, nodeName: nodeName)
    return value
  }

  private func validate(networkID: String, nodeName: String) throws {
    try TunnelUserEnrollmentField.identifier(node.id, name: "node.id")
    guard node.networkID == networkID,
      node.name == nodeName,
      node.site == "mobile",
      node.groups == ["all", "members"],
      node.role == "member",
      node.status == "pending"
    else {
      throw TunnelUserEnrollmentError.invalidDocument
    }
    try TunnelUserEnrollmentField.base64URL(
      enrollmentToken,
      bytes: 32,
      name: "enrollment_token"
    )
    _ = try TunnelUserEnrollmentField.timestamp(
      expiresAt,
      name: "expires_at"
    )
  }
}

private enum TunnelUserEnrollmentJSON {
  static func requireObject(
    _ data: Data,
    keys: Set<String>,
    maximumBytes: Int
  ) throws {
    guard !data.isEmpty, data.count <= maximumBytes,
      let object = try JSONSerialization.jsonObject(
        with: data,
        options: [.fragmentsAllowed]
      ) as? [String: Any],
      Set(object.keys) == keys
    else {
      throw TunnelUserEnrollmentError.invalidDocument
    }
  }
}

private enum TunnelUserEnrollmentField {
  static func identifier(_ value: String, name: String) throws {
    guard !value.isEmpty, value.utf8.count <= 128,
      value.unicodeScalars.allSatisfy({
        CharacterSet(
          charactersIn: "abcdefghijklmnopqrstuvwxyz"
            + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            + "0123456789._:-"
        ).contains($0)
      })
    else {
      throw TunnelUserEnrollmentError.invalidField(name)
    }
  }

  static func nodeName(_ value: String) throws {
    guard !value.isEmpty, value.utf8.count <= 63,
      let first = value.unicodeScalars.first,
      CharacterSet.alphanumerics.contains(first),
      value.unicodeScalars.allSatisfy({
        CharacterSet(
          charactersIn: "abcdefghijklmnopqrstuvwxyz"
            + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            + "0123456789._-"
        ).contains($0)
      })
    else {
      throw TunnelUserEnrollmentError.invalidField("name")
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
      throw TunnelUserEnrollmentError.invalidField(name)
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
      throw TunnelUserEnrollmentError.invalidField(name)
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
      throw TunnelUserEnrollmentError.invalidField(name)
    }
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions =
      value.contains(".")
      ? [.withInternetDateTime, .withFractionalSeconds]
      : [.withInternetDateTime]
    guard let parsed = formatter.date(from: value) else {
      throw TunnelUserEnrollmentError.invalidField(name)
    }
    return parsed
  }
}
