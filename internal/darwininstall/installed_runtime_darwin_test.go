//go:build darwin

package darwininstall

import (
	"path/filepath"
	"testing"
)

func TestProductionDarwinRuntimeDirectoryRequiresExactActiveRelease(t *testing.T) {
	authority := validAuthenticatedDarwinRelease(1, 2, 1, "a", "b")
	exact := filepath.Join(ProductionReleasesRoot, authority.InstalledID, "bin")
	if err := validateProductionDarwinRuntimeDirectory(exact, authority.InstalledID); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"current selector": filepath.Join(ProductionMeshRoot, "current", "bin"),
		"other release": filepath.Join(
			ProductionReleasesRoot,
			validAuthenticatedDarwinRelease(1, 3, 1, "c", "d").InstalledID,
			"bin",
		),
		"nested":   filepath.Join(exact, "nested"),
		"relative": filepath.Join("opt", "mesh", "releases", authority.InstalledID, "bin"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateProductionDarwinRuntimeDirectory(path, authority.InstalledID); err == nil {
				t.Fatal("non-active Darwin runtime directory was accepted")
			}
		})
	}
}
