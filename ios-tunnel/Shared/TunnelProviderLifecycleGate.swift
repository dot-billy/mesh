import Foundation

public final class TunnelTerminalCleanupBarrier: @unchecked Sendable {
  private let lock = NSLock()
  private var finished = false
  private var waiters: [CheckedContinuation<Void, Never>] = []

  public init() {}

  public func wait() async {
    await withCheckedContinuation { continuation in
      lock.lock()
      if finished {
        lock.unlock()
        continuation.resume()
        return
      }
      waiters.append(continuation)
      lock.unlock()
    }
  }

  public func finish() {
    lock.lock()
    guard !finished else {
      lock.unlock()
      return
    }
    finished = true
    let pending = waiters
    waiters.removeAll(keepingCapacity: false)
    lock.unlock()
    for continuation in pending {
      continuation.resume()
    }
  }
}

public enum TunnelProviderStartDisposition: Equatable, Sendable {
  case begin(UInt64)
  case alreadyStarting
  case alreadyRunning
  case stopped
}

public final class TunnelProviderLifecycleGate: @unchecked Sendable {
  private let lock = NSLock()
  private var generation: UInt64 = 0
  private var activeGeneration: UInt64?
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
    guard generation < UInt64.max else {
      stopped = true
      return .stopped
    }
    generation += 1
    activeGeneration = generation
    starting = true
    return .begin(generation)
  }

  public func mayContinueStart(_ generation: UInt64) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return activeGeneration == generation
      && starting
      && !running
      && !stopped
  }

  @discardableResult
  public func markRunning(
    _ generation: UInt64,
    commit: () -> Void
  ) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard activeGeneration == generation,
      starting,
      !running,
      !stopped
    else {
      return false
    }
    starting = false
    running = true
    commit()
    return true
  }

  @discardableResult
  public func finishStartFailure(
    _ generation: UInt64,
    commit: () -> Void = {}
  ) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard activeGeneration == generation, starting, !running else {
      return false
    }
    starting = false
    activeGeneration = nil
    commit()
    return true
  }

  @discardableResult
  public func latchStop() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    let wasStopped = stopped
    stopped = true
    activeGeneration = nil
    starting = false
    running = false
    return wasStopped
  }

  public func isCurrent(_ generation: UInt64) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return activeGeneration == generation && !stopped
  }

  @discardableResult
  public func commitIfCurrent(
    _ generation: UInt64,
    commit: () -> Void
  ) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard activeGeneration == generation, running, !stopped else {
      return false
    }
    commit()
    return true
  }

  public func isLatest(_ generation: UInt64) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return self.generation == generation
  }

  public func isStopped() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return stopped
  }

  public func finishStop() {
    lock.lock()
    stopped = false
    lock.unlock()
  }
}
