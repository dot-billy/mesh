// Package nebula embeds the reviewed Slack Nebula dependency lock used by
// mesh-deps. The lock is part of Mesh source and release provenance; no
// network response can replace or amend it at runtime.
package nebula

import _ "embed"

var (
	// lockV1103 is kept private so an importer cannot mutate trust bytes before
	// a verifier reads them.
	//
	//go:embed v1.10.3.lock.json
	lockV1103 string

	// licenseV1103 is the exact LICENSE from the reviewed upstream v1.10.3 tag.
	//
	//go:embed LICENSE
	licenseV1103 string
)

// V1103Lock returns a fresh copy of the exact source-controlled lock.
func V1103Lock() []byte { return []byte(lockV1103) }

// V1103License returns a fresh copy of Slack Nebula v1.10.3's exact upstream
// LICENSE bytes.
func V1103License() []byte { return []byte(licenseV1103) }
