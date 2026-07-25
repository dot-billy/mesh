// Package nebulawindowsruntime embeds the reviewed Windows cross-build output
// lock layered on Mesh's immutable Slack Nebula source/patch policy.
package nebulawindowsruntime

import _ "embed"

//go:embed v1.10.3-build.lock.json
var buildLock string

// BuildLock returns a fresh copy of the exact source-controlled Windows lock.
func BuildLock() []byte { return []byte(buildLock) }
