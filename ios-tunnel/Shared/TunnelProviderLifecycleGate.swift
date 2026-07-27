import Foundation

public enum TunnelProviderStartDisposition: Equatable, Sendable {
  case begin
  case alreadyStarting
  case alreadyRunning
  case stopped
}

public final class TunnelProviderLifecycleGate: @unchecked Sendable {
  private let lock = NSLock()
  private var starting = false
  private var running = false
  private var stopped = false

  public init() {}

  public func beginStart() -> TunnelProviderStartDisposition {
    lock.lock()
    defer { lock.unlock() }
    if stopped {
      return .stopped
    }
    if running {
      return .alreadyRunning
    }
    if starting {
      return .alreadyStarting
    }
    starting = true
    return .begin
  }

  public func mayContinueStart() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return starting && !running && !stopped
  }

  @discardableResult
  public func markRunning() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard starting, !running, !stopped else {
      return false
    }
    starting = false
    running = true
    return true
  }

  public func finishStartFailure() {
    lock.lock()
    starting = false
    lock.unlock()
  }

  @discardableResult
  public func latchStop() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    let wasStopped = stopped
    stopped = true
    running = false
    return wasStopped
  }

  public func isStopped() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return stopped
  }
}

public enum TunnelProviderBootstrapClaim:
  Equatable,
  Sendable
{
  case accepted
  case mismatchWhileAwaiting
  case alreadyClaimed
  case unavailable
  case stopped
}

public final class TunnelProviderBootstrapGate: @unchecked Sendable {
  private let lock = NSLock()
  private var pending: TunnelProviderBootstrapRequest?
  private var claimedRequestID: String?
  private var stopped = false

  public init() {}

  public func arm(_ request: TunnelProviderBootstrapRequest) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard pending == nil, claimedRequestID == nil, !stopped else {
      return false
    }
    pending = request
    return true
  }

  public func claim(
    _ request: TunnelProviderEnrollmentRequest
  ) -> TunnelProviderBootstrapClaim {
    lock.lock()
    defer { lock.unlock() }
    guard !stopped else {
      return .stopped
    }
    if claimedRequestID != nil {
      return .alreadyClaimed
    }
    guard let pending else {
      return .unavailable
    }
    guard
      pending.requestID == request.requestID,
      pending.serverOrigin == request.serverOrigin
    else {
      return .mismatchWhileAwaiting
    }
    claimedRequestID = request.requestID
    self.pending = nil
    return .accepted
  }

  public func expire(requestID: String) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard
      let pending,
      pending.requestID == requestID,
      claimedRequestID == nil,
      !stopped
    else {
      return false
    }
    self.pending = nil
    return true
  }

  public func isAwaiting(requestID: String) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return
      pending?.requestID == requestID
      && claimedRequestID == nil
      && !stopped
  }

  public func clear() {
    lock.lock()
    pending = nil
    claimedRequestID = nil
    lock.unlock()
  }

  public func stop() {
    lock.lock()
    pending = nil
    stopped = true
    lock.unlock()
  }
}
