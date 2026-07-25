// Package nebulaobserver embeds the reviewed source-build policy and patch
// series for Mesh's Linux-only Slack Nebula runtime observer.
package nebulaobserver

import (
	"embed"
)

var (
	//go:embed v1.10.3-build.lock.json
	buildLock string

	//go:embed series *.patch
	patchFiles embed.FS
)

// BuildLock returns a fresh copy of the exact source-controlled build lock.
func BuildLock() []byte { return []byte(buildLock) }

// Series returns a fresh copy of the exact source-controlled patch ordering.
func Series() []byte {
	raw, err := patchFiles.ReadFile("series")
	if err != nil {
		panic("embedded Nebula observer series is missing: " + err.Error())
	}
	return raw
}

// Patch returns a fresh copy of a named source-controlled patch. Callers must
// still require the exact ordered names selected by the embedded build lock.
func Patch(name string) ([]byte, error) { return patchFiles.ReadFile(name) }
