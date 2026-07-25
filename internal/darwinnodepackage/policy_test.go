package darwinnodepackage

import (
	"reflect"
	"strings"
	"testing"
)

func TestPolicyCanonicalRoundTrip(t *testing.T) {
	frame, policy, err := EncodePolicy(PolicySpec{
		PackageIdentifier:      "io.mesh.node",
		PackageRootPath:        "/Library/Application Support/Mesh/NodePackage",
		InstalledBootstrapPath: "/Library/Application Support/Mesh/NodePackage/mesh-install",
		PackageSnapshotPath:    "/Library/Application Support/Mesh/NodePackage/snapshot",
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePolicyIdentity(frame)
	if err != nil || !reflect.DeepEqual(parsed, policy) {
		t.Fatalf("parsed=%+v policy=%+v error=%v", parsed, policy, err)
	}
	if policy.SHA256 == "" {
		t.Fatal("policy digest is empty")
	}
}

func TestPolicyRejectsCallerSelectedOrAmbiguousAuthority(t *testing.T) {
	valid := PolicySpec{
		PackageIdentifier:      "io.mesh.node",
		PackageRootPath:        "/Library/Application Support/Mesh/NodePackage",
		InstalledBootstrapPath: "/Library/Application Support/Mesh/NodePackage/mesh-install",
		PackageSnapshotPath:    "/Library/Application Support/Mesh/NodePackage/snapshot",
	}
	cases := map[string]PolicySpec{
		"empty":                {},
		"ambiguous identifier": {PackageIdentifier: "io..mesh", InstalledBootstrapPath: valid.InstalledBootstrapPath, PackageSnapshotPath: valid.PackageSnapshotPath},
		"root outside":         {PackageIdentifier: valid.PackageIdentifier, PackageRootPath: "/tmp/NodePackage", InstalledBootstrapPath: valid.InstalledBootstrapPath, PackageSnapshotPath: valid.PackageSnapshotPath},
		"nested root":          {PackageIdentifier: valid.PackageIdentifier, PackageRootPath: "/Library/Application Support/Mesh/Nested/NodePackage", InstalledBootstrapPath: valid.InstalledBootstrapPath, PackageSnapshotPath: valid.PackageSnapshotPath},
		"bootstrap outside":    {PackageIdentifier: valid.PackageIdentifier, PackageRootPath: valid.PackageRootPath, InstalledBootstrapPath: "/tmp/mesh-install", PackageSnapshotPath: valid.PackageSnapshotPath},
		"wrong bootstrap name": {PackageIdentifier: valid.PackageIdentifier, PackageRootPath: valid.PackageRootPath, InstalledBootstrapPath: valid.PackageRootPath + "/bootstrap", PackageSnapshotPath: valid.PackageSnapshotPath},
		"snapshot outside":     {PackageIdentifier: valid.PackageIdentifier, PackageRootPath: valid.PackageRootPath, InstalledBootstrapPath: valid.InstalledBootstrapPath, PackageSnapshotPath: "/Library/Application Support/Mesh/snapshot"},
		"nested snapshot":      {PackageIdentifier: valid.PackageIdentifier, PackageRootPath: valid.PackageRootPath, InstalledBootstrapPath: valid.InstalledBootstrapPath, PackageSnapshotPath: valid.PackageRootPath + "/nested/snapshot"},
		"unclean bootstrap":    {PackageIdentifier: valid.PackageIdentifier, PackageRootPath: valid.PackageRootPath, InstalledBootstrapPath: valid.PackageRootPath + "/../mesh-install", PackageSnapshotPath: valid.PackageSnapshotPath},
		"root as snapshot":     {PackageIdentifier: valid.PackageIdentifier, PackageRootPath: valid.PackageRootPath, InstalledBootstrapPath: valid.InstalledBootstrapPath, PackageSnapshotPath: valid.PackageRootPath},
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := EncodePolicy(spec); err == nil {
				t.Fatal("invalid Darwin node package policy accepted")
			}
		})
	}
}

func TestPolicyRejectsMalformedFramesAndDevelopmentIdentity(t *testing.T) {
	original := Identity
	t.Cleanup(func() { Identity = original })
	Identity = DevelopmentPolicy
	if _, err := LoadPolicy(); err == nil {
		t.Fatal("development Darwin node package identity loaded")
	}
	frame, _, err := EncodePolicy(PolicySpec{
		PackageIdentifier:      "io.mesh.node",
		PackageRootPath:        "/Library/Application Support/Mesh/NodePackage",
		InstalledBootstrapPath: "/Library/Application Support/Mesh/NodePackage/mesh-install",
		PackageSnapshotPath:    "/Library/Application Support/Mesh/NodePackage/snapshot",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{
		strings.Replace(frame, FramePrefix, "OTHER.", 1),
		frame + "x",
		strings.Replace(frame, "A", "!", 1),
	} {
		if _, err := ParsePolicyIdentity(mutation); err == nil {
			t.Fatal("malformed Darwin node package policy frame accepted")
		}
	}
}
