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
