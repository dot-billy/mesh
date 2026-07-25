# Apple platform architecture decisions

These records freeze the product choices needed to begin Apple platform work.
They authorize source and test implementation only. They do not authorize
production signing, distribution, enrollment, or a support claim; each product
retains the independent release gates in
[`../apple-platform-security.md`](../apple-platform-security.md).

| ADR | Decision |
| --- | --- |
| [0001](0001-apple-product-artifacts.md) | Independent macOS operator and node artifacts |
| [0002](0002-macos-menu-bar.md) | Defer the menu-bar projection |
| [0003](0003-macos-distribution.md) | Direct distribution for the first macOS release |
| [0004](0004-darwin-architectures.md) | Separate Darwin architecture artifacts |
| [0005](0005-apple-deployment-targets.md) | Initial deployment targets and test matrix |
| [0006](0006-ios-sequencing.md) | Ship the iOS operator before tunnel support |
| [0007](0007-ios-nebula-runtime.md) | Bounded Mesh/Nebula mobile framework |
| [0008](0008-ios-suspension-state.md) | Explicit mobile suspension evidence |
| [0009](0009-ios-distribution.md) | TestFlight plus managed Custom App distribution |
| [0010](0010-macos-node-package-bootstrap.md) | Compiled, authenticated macOS node package bootstrap |
| [0011](0011-macos-node-release-identifiers.md) | Proposed macOS node signing, package, and path identifiers |
| [0012](0012-ios-tunnel-enrollment.md) | Extension-owned iOS Tunnel enrollment |
| [0013](0013-ios-tunnel-lifecycle-refresh.md) | Extension-owned pre-start lifecycle refresh |
| [0014](0014-ios-tunnel-runtime-lifecycle-and-removal.md) | Extension-owned runtime lifecycle and local identity removal |
