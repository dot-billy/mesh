package darwinnodepackage

import (
	"strings"
	"testing"
)

func TestPayloadPlanContainsOnlyMeshOwnedPackageRoot(t *testing.T) {
	_, policy, err := EncodePolicy(PolicySpec{
		PackageIdentifier:      "io.mesh.node",
		PackageRootPath:        "/Library/Application Support/Mesh/NodePackage",
		InstalledBootstrapPath: "/Library/Application Support/Mesh/NodePackage/mesh-install",
		PackageSnapshotPath:    "/Library/Application Support/Mesh/NodePackage/snapshot",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, architecture := range []string{"arm64", "amd64"} {
		plan, err := Plan(policy, architecture)
		if err != nil {
			t.Fatal(err)
		}
		if plan.InstallLocation != PackageInstallLocation || len(plan.Entries) != 6 {
			t.Fatalf("plan=%+v", plan)
		}
		for _, entry := range plan.Entries {
			if !strings.HasPrefix(entry.Path, "NodePackage") ||
				strings.HasPrefix(entry.Path, "Library/") ||
				strings.HasPrefix(entry.Path, "private/") ||
				strings.HasPrefix(entry.Path, "usr/") {
				t.Fatalf("entry can author a system ancestor: %+v", entry)
			}
		}
	}
}

func TestPayloadPlanRejectsArchitectureAndExactInventoryDrift(t *testing.T) {
	_, policy, err := EncodePolicy(PolicySpec{
		PackageIdentifier:      "io.mesh.node",
		PackageRootPath:        "/Library/Application Support/Mesh/NodePackage",
		InstalledBootstrapPath: "/Library/Application Support/Mesh/NodePackage/mesh-install",
		PackageSnapshotPath:    "/Library/Application Support/Mesh/NodePackage/snapshot",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Plan(policy, "universal"); err == nil {
		t.Fatal("universal package plan accepted")
	}
	plan, err := Plan(policy, "arm64")
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*PayloadPlan){
		"extra": func(value *PayloadPlan) {
			value.Entries = append(value.Entries, rootWheelEntry("NodePackage/extra", FileKind, SnapshotFileMode))
		},
		"writable bootstrap": func(value *PayloadPlan) {
			value.Entries[1].Mode = 0o755
		},
		"system ancestor": func(value *PayloadPlan) {
			value.Entries[0].Path = "Library"
		},
		"shell script": func(value *PayloadPlan) {
			value.Postinstall.Mode = 0o755
		},
	} {
		t.Run(name, func(t *testing.T) {
			drifted := plan
			drifted.Entries = append([]PayloadEntry(nil), plan.Entries...)
			mutate(&drifted)
			if err := drifted.Validate(policy); err == nil {
				t.Fatal("drifted payload plan accepted")
			}
		})
	}
}
