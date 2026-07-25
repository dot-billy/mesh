package darwincodesign

import (
	"reflect"
	"testing"
)

func TestVerificationArgumentsAreExact(t *testing.T) {
	_, policy, err := EncodePolicy(PolicySpec{
		TeamID: "AB12CD34EF", MeshInstallIdentifier: "io.mesh.node.mesh-install",
		MeshctlIdentifier: "io.mesh.node.meshctl",
		NebulaIdentifier:  "io.mesh.node.nebula", NebulaCertIdentifier: "io.mesh.node.nebula-cert",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerificationArguments(policy, NebulaRole, "/opt/mesh/releases/exact/bin/nebula")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"--verify", "--strict=all", "--test-requirement",
		`=anchor apple generic and identifier "io.mesh.node.nebula" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "AB12CD34EF"`,
		"/opt/mesh/releases/exact/bin/nebula",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("arguments=%q want=%q", got, want)
	}
	for _, path := range []string{"relative", "/", "/opt/mesh/../other", "/opt/mesh/\x00bad"} {
		if _, err := VerificationArguments(policy, NebulaRole, path); err == nil {
			t.Fatalf("invalid target %q accepted", path)
		}
	}
}

func TestApplePlatformToolArgumentsAreFixed(t *testing.T) {
	want := []string{
		"--verify", "--strict=all", "--test-requirement",
		`=anchor apple and identifier "com.apple.xpc.launchctl"`,
		"/bin/launchctl",
	}
	if got := launchctlVerificationArguments(); !reflect.DeepEqual(got, want) {
		t.Fatalf("launchctl arguments=%q want=%q", got, want)
	}
}
