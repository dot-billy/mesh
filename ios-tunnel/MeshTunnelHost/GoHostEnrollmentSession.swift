import Foundation

protocol TunnelHostEnrollmentSession: Sendable {
  func enroll(
    request: TunnelEnrollmentRequest,
    monotonicCounter: UInt64
  ) async throws -> TunnelConfigurationPayload
  func recover(
    origin: String,
    monotonicCounter: UInt64
  ) async throws -> TunnelEnrollmentRecoveryOutcome
}

protocol TunnelHostIdentityRemovalSession: Sendable {
  func remove() async throws
}

protocol TunnelHostLifecycleSession: Sendable {
  func refresh(
    current: TunnelConfigurationPayload,
    monotonicCounter: UInt64
  ) async throws -> TunnelLifecycleRefreshOutcome
}

enum TunnelHostEnrollmentSessionError: Error {
  case constructionFailed
  case invalidCounter
  case invalidDocument
  case unavailable
}

#if canImport(MeshMobile)
  @preconcurrency import MeshMobile

  final class GoHostEnrollmentSession:
    TunnelHostEnrollmentSession,
    @unchecked Sendable
  {
    private let session: IosmobileEnrollmentSession

    init(accessGroup: String) throws {
      var constructionError: NSError?
      guard
        let session = IosmobileNewEnrollmentSession(
          accessGroup,
          TunnelIdentityScope.primaryID,
          &constructionError
        )
      else {
        if let constructionError {
          throw constructionError
        }
        throw TunnelHostEnrollmentSessionError.constructionFailed
      }
      self.session = session
    }

    func enroll(
      request: TunnelEnrollmentRequest,
      monotonicCounter: UInt64
    ) async throws -> TunnelConfigurationPayload {
      guard monotonicCounter <= UInt64(Int64.max) else {
        throw TunnelHostEnrollmentSessionError.invalidCounter
      }
      let document = try await Task.detached { [self] in
        var enrollmentError: NSError?
        let value = session.enroll(
          request.serverOrigin,
          enrollmentToken: request.enrollmentToken,
          monotonicCounter: Int64(monotonicCounter),
          error: &enrollmentError
        )
        if let enrollmentError {
          throw enrollmentError
        }
        return value
      }.value
      guard let data = document.data(using: .utf8) else {
        throw TunnelHostEnrollmentSessionError.invalidDocument
      }
      let configuration = try TunnelConfigurationPayload.decodeExact(data)
      guard configuration.monotonicCounter == monotonicCounter else {
        throw TunnelHostEnrollmentSessionError.invalidCounter
      }
      return configuration
    }

    func recover(
      origin: String,
      monotonicCounter: UInt64
    ) async throws -> TunnelEnrollmentRecoveryOutcome {
      guard monotonicCounter <= UInt64(Int64.max) else {
        throw TunnelHostEnrollmentSessionError.invalidCounter
      }
      let document = try await Task.detached { [self] in
        var recoveryError: NSError?
        let value = session.recover(
          origin,
          monotonicCounter: Int64(monotonicCounter),
          error: &recoveryError
        )
        if let recoveryError {
          throw recoveryError
        }
        return value
      }.value
      guard let data = document.data(using: .utf8) else {
        throw TunnelHostEnrollmentSessionError.invalidDocument
      }
      let outcome = try TunnelEnrollmentRecoveryOutcome.decodeExact(data)
      guard outcome.configuration?.monotonicCounter == monotonicCounter
        || outcome.configuration == nil
      else {
        throw TunnelHostEnrollmentSessionError.invalidCounter
      }
      return outcome
    }
  }

  final class GoHostIdentityRemovalSession:
    TunnelHostIdentityRemovalSession,
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
        throw TunnelHostEnrollmentSessionError.constructionFailed
      }
      self.session = session
    }

    func remove() async throws {
      try await Task.detached { [self] in
        try session.remove()
      }.value
    }
  }

  final class GoHostLifecycleSession:
    TunnelHostLifecycleSession,
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
        throw TunnelHostEnrollmentSessionError.constructionFailed
      }
      self.session = session
    }

    func refresh(
      current: TunnelConfigurationPayload,
      monotonicCounter: UInt64
    ) async throws -> TunnelLifecycleRefreshOutcome {
      guard monotonicCounter <= UInt64(Int64.max) else {
        throw TunnelHostEnrollmentSessionError.invalidCounter
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
        throw TunnelHostEnrollmentSessionError.invalidDocument
      }
      let outcome = try TunnelLifecycleRefreshOutcome.decodeExact(data)
      guard outcome.configuration?.monotonicCounter == monotonicCounter
        || outcome.configuration == nil
      else {
        throw TunnelHostEnrollmentSessionError.invalidCounter
      }
      return outcome
    }
  }
#endif

final class UnavailableHostEnrollmentSession:
  TunnelHostEnrollmentSession,
  @unchecked Sendable
{
  func enroll(
    request: TunnelEnrollmentRequest,
    monotonicCounter: UInt64
  ) async throws -> TunnelConfigurationPayload {
    throw TunnelHostEnrollmentSessionError.unavailable
  }

  func recover(
    origin: String,
    monotonicCounter: UInt64
  ) async throws -> TunnelEnrollmentRecoveryOutcome {
    throw TunnelHostEnrollmentSessionError.unavailable
  }
}

final class UnavailableHostIdentityRemovalSession:
  TunnelHostIdentityRemovalSession,
  @unchecked Sendable
{
  func remove() async throws {
    throw TunnelHostEnrollmentSessionError.unavailable
  }
}

final class UnavailableHostLifecycleSession:
  TunnelHostLifecycleSession,
  @unchecked Sendable
{
  func refresh(
    current _: TunnelConfigurationPayload,
    monotonicCounter _: UInt64
  ) async throws -> TunnelLifecycleRefreshOutcome {
    throw TunnelHostEnrollmentSessionError.unavailable
  }
}

enum TunnelHostEnrollmentSessionFactory {
  static func make() throws -> any TunnelHostEnrollmentSession {
    #if canImport(MeshMobile)
      return try GoHostEnrollmentSession(
        accessGroup: TunnelHighWaterKeychain.resolvedAccessGroup()
      )
    #else
      return UnavailableHostEnrollmentSession()
    #endif
  }
}

enum TunnelHostIdentityRemovalSessionFactory {
  static func make() throws -> any TunnelHostIdentityRemovalSession {
    #if canImport(MeshMobile)
      return try GoHostIdentityRemovalSession(
        accessGroup: TunnelHighWaterKeychain.resolvedAccessGroup()
      )
    #else
      return UnavailableHostIdentityRemovalSession()
    #endif
  }
}

enum TunnelHostLifecycleSessionFactory {
  static func make() throws -> any TunnelHostLifecycleSession {
    #if canImport(MeshMobile)
      return try GoHostLifecycleSession(
        accessGroup: TunnelHighWaterKeychain.resolvedAccessGroup()
      )
    #else
      return UnavailableHostLifecycleSession()
    #endif
  }
}
