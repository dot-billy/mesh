# ADR 0002: macOS menu-bar experience

- Status: accepted for engineering
- Date: 2026-07-23

## Decision

Defer the menu-bar projection until the full-window Flutter macOS operator
console passes its source, accessibility, authentication, secret-custody, and
clean-host unsigned-build gates.

## Consequences

Phase one has one application process and one control-plane client. A future
menu-bar item must project the existing controller state; it may not introduce
a second API client, privileged file access, a second credential store, or a
local node support claim. A Swift companion requires a new ADR and signed IPC
review.

