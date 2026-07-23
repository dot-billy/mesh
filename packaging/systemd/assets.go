// Package systemd embeds the reviewed service-manager assets used by Linux
// bundles. Accessors return fresh copies so callers cannot mutate future reads.
package systemd

import _ "embed"

var (
	//go:embed 10-timeout-abort.conf
	timeoutAbortCompatibilityMask string

	//go:embed mesh-agent.service
	meshAgentService string

	//go:embed mesh-nebula.service
	meshNebulaService string

	//go:embed README.md
	readme string
)

// TimeoutAbortCompatibilityMask returns a fresh copy of the comment-only
// unit-specific drop-in that masks a distribution-wide file of the same name.
func TimeoutAbortCompatibilityMask() []byte { return []byte(timeoutAbortCompatibilityMask) }

// MeshAgentService returns a fresh copy of mesh-agent.service.
func MeshAgentService() []byte { return []byte(meshAgentService) }

// MeshNebulaService returns a fresh copy of mesh-nebula.service.
func MeshNebulaService() []byte { return []byte(meshNebulaService) }

// README returns a fresh copy of the systemd installation and ownership guide.
func README() []byte { return []byte(readme) }
