# ADR 0009: Initial iOS distribution

- Status: accepted for engineering; channel approval pending
- Date: 2026-07-23

## Decision

Use TestFlight for controlled qualification and Apple Business Manager Custom
App distribution through MDM for the initial managed release. Do not claim
public App Store availability or enterprise in-house distribution.

## Consequences

TestFlight and Custom App archives have separate provisioning and distribution
receipts but one reviewed source and entitlement contract. MDM may configure
non-secret origin, release channel, notification, and approved VPN/on-demand
policy. It never carries Mesh sessions, enrollment or recovery tokens, private
keys, or unrestricted enrollment authority. Supervised and unsupervised
behavior must be documented from real-device evidence before release.

