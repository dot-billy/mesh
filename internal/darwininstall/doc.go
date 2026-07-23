// Package darwininstall owns the privileged native macOS installation
// transaction boundary. Implemented primitives cover the installer-owned
// persistent runtime gate, create-only immutable release publication,
// expected-prior-bound current-release selection, exact launchd-plist
// publication, and a durable cross-process journal that wires publication to
// fail-closed launchd activation. A canonical state store retains exact
// release high-water authority and active/previous rollback identity under the
// same lock. Compiled-root metadata intake, append-only trusted-root history,
// and journaled active/previous rollback are implemented. Accepted online or
// root-private offline metadata is durably reverified across restart; its
// selected artifact is captured within exact bounds, and deterministic
// intake-owned staging resets interrupted extraction before the activation
// journal consumes authority. The offline format has fixed basenames and no
// unsigned policy, platform, floor, clock, size, digest, or key field.
// A fixed system-domain launchctl controller proves absence/loading only
// through successful bootout/bootstrap mutations and never parses non-API
// status text. Native execution of that controller remains separate work.
package darwininstall
