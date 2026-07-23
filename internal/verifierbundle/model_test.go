package verifierbundle

import (
	"strings"
	"testing"

	"mesh/internal/buildinfo"
)

func TestPackageSchemaIsExactAndBounded(t *testing.T) {
	metadata := Package{
		Schema: Schema,
		Build: buildinfo.IdentityInfo{
			Schema: buildinfo.Schema, Version: "1.2.3", Commit: strings.Repeat("a", 40),
			BuildTime: "2026-07-21T12:00:00Z", SecurityFloor: 1,
			AgentStateReadMin: 2, AgentStateReadMax: 2, AgentStateWriteVersion: 2,
		},
		GoVersion: "go1.26.0", Target: Target{OS: "linux", Arch: "amd64"},
		Entries: []Entry{{Path: verifierPath("linux"), Mode: verifierMode, Size: 1024, SHA256: strings.Repeat("b", 64)}},
	}
	if _, err := validatePackage(metadata); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Package){
		"schema": func(value *Package) { value.Schema = "other" },
		"target": func(value *Package) { value.Target.OS = "darwin" },
		"path":   func(value *Package) { value.Entries[0].Path = "bin/other" },
		"mode":   func(value *Package) { value.Entries[0].Mode = 0o777 },
		"digest": func(value *Package) { value.Entries[0].SHA256 = strings.Repeat("B", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := clonePackage(metadata)
			mutate(&candidate)
			if _, err := validatePackage(candidate); err == nil {
				t.Fatal("invalid package accepted")
			}
		})
	}
	windows := clonePackage(metadata)
	windows.Target.OS = "windows"
	windows.Entries[0].Path = verifierPath("windows")
	if _, err := validatePackage(windows); err != nil {
		t.Fatalf("canonical Windows verifier package rejected: %v", err)
	}
	windows.Entries[0].Path = verifierPath("linux")
	if _, err := validatePackage(windows); err == nil {
		t.Fatal("Windows verifier package with Linux entry path accepted")
	}
	if size, err := exactArchiveSize(1024, 4096); err != nil || size != 7168 {
		t.Fatalf("archive size=%d err=%v", size, err)
	}
}
