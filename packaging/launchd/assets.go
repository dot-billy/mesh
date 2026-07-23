// Package launchd embeds the reviewed service-manager assets reserved for a
// future native macOS package. Embedding does not make the package supported;
// callers receive fresh copies so tests and release tooling cannot mutate the
// reviewed bytes.
package launchd

import _ "embed"

var (
	//go:embed io.mesh.node-agent.plist
	nodeAgentPlist string

	//go:embed README.md
	readme string
)

// NodeAgentPlist returns a fresh copy of the sole reviewed LaunchDaemon.
func NodeAgentPlist() []byte { return []byte(nodeAgentPlist) }

// README returns a fresh copy of the macOS ownership and proof boundary.
func README() []byte { return []byte(readme) }
