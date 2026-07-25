# ADR 0005: Apple deployment targets

- Status: accepted for engineering; support claim pending device evidence
- Date: 2026-07-23

## Decision

Use macOS 14, iOS 17, and iPadOS 17 as the initial minimum deployment targets.
Build on the exact Xcode, SDK, Swift, and Flutter versions in the Apple build
receipt. The supported maximum is the newest major version that passes the
release matrix, not whatever happens to be installed on a developer host.

## Consequences

The release matrix requires current patched releases of macOS 14 and every
later supported major version, current iOS/iPadOS 17 and every later supported
major version, Apple Silicon, native Intel execution for any Intel claim,
representative iPhone sizes, and a physical iPad for iPad tunnel support.
Compilation or simulator evidence does not add a platform to the support
matrix. End-of-support occurs no earlier than 90 days after a documented
notice, except when an actively exploited platform defect requires an
immediate security floor.

