package darwincodesign

import (
	"reflect"
	"strings"
	"testing"
)

func TestPolicyCanonicalRoundTripAndRequirements(t *testing.T) {
	frame, policy, err := EncodePolicy(PolicySpec{
		TeamID: "AB12CD34EF", MeshInstallIdentifier: "io.mesh.node.mesh-install",
		MeshctlIdentifier: "io.mesh.node.meshctl",
		NebulaIdentifier:  "io.mesh.node.nebula", NebulaCertIdentifier: "io.mesh.node.nebula-cert",
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePolicyIdentity(frame)
	if err != nil || !reflect.DeepEqual(parsed, policy) {
		t.Fatalf("parsed=%+v policy=%+v error=%v", parsed, policy, err)
	}
	want := `anchor apple generic and identifier "io.mesh.node.meshctl"` +
		` and certificate 1[field.1.2.840.113635.100.6.2.6] exists` +
		` and certificate leaf[field.1.2.840.113635.100.6.1.13] exists` +
		` and certificate leaf[subject.OU] = "AB12CD34EF"`
	if got, err := policy.Requirement(MeshctlRole); err != nil || got != want {
		t.Fatalf("requirement=%q error=%v", got, err)
	}
	if got, err := policy.Requirement(MeshInstallRole); err != nil ||
		!strings.Contains(got, `identifier "io.mesh.node.mesh-install"`) {
		t.Fatalf("installer requirement=%q error=%v", got, err)
	}
	if _, err := policy.Requirement("unknown"); err == nil {
		t.Fatal("unknown Darwin executable role was admitted")
	}
}

func TestPolicyRejectsMissingOrAmbiguousAuthority(t *testing.T) {
	valid := PolicySpec{
		TeamID: "AB12CD34EF", MeshInstallIdentifier: "io.mesh.node.mesh-install",
		MeshctlIdentifier: "io.mesh.node.meshctl",
		NebulaIdentifier:  "io.mesh.node.nebula", NebulaCertIdentifier: "io.mesh.node.nebula-cert",
	}
	cases := map[string]PolicySpec{
		"missing team":       {MeshInstallIdentifier: valid.MeshInstallIdentifier, MeshctlIdentifier: valid.MeshctlIdentifier, NebulaIdentifier: valid.NebulaIdentifier, NebulaCertIdentifier: valid.NebulaCertIdentifier},
		"missing installer":  {TeamID: valid.TeamID, MeshctlIdentifier: valid.MeshctlIdentifier, NebulaIdentifier: valid.NebulaIdentifier, NebulaCertIdentifier: valid.NebulaCertIdentifier},
		"lowercase team":     {TeamID: "ab12CD34EF", MeshInstallIdentifier: valid.MeshInstallIdentifier, MeshctlIdentifier: valid.MeshctlIdentifier, NebulaIdentifier: valid.NebulaIdentifier, NebulaCertIdentifier: valid.NebulaCertIdentifier},
		"quoted identifier":  {TeamID: valid.TeamID, MeshInstallIdentifier: valid.MeshInstallIdentifier, MeshctlIdentifier: `io.mesh."node`, NebulaIdentifier: valid.NebulaIdentifier, NebulaCertIdentifier: valid.NebulaCertIdentifier},
		"empty segment":      {TeamID: valid.TeamID, MeshInstallIdentifier: valid.MeshInstallIdentifier, MeshctlIdentifier: "io..meshctl", NebulaIdentifier: valid.NebulaIdentifier, NebulaCertIdentifier: valid.NebulaCertIdentifier},
		"duplicate identity": {TeamID: valid.TeamID, MeshInstallIdentifier: valid.MeshctlIdentifier, MeshctlIdentifier: valid.MeshctlIdentifier, NebulaIdentifier: valid.NebulaIdentifier, NebulaCertIdentifier: valid.NebulaCertIdentifier},
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := EncodePolicy(spec); err == nil {
				t.Fatal("invalid Darwin code-signing policy accepted")
			}
		})
	}
}

func TestPolicyRejectsMalformedFramesAndDevelopmentIdentity(t *testing.T) {
	original := Identity
	t.Cleanup(func() { Identity = original })
	Identity = DevelopmentPolicy
	if _, err := LoadPolicy(); err == nil {
		t.Fatal("development Darwin code-signing identity loaded")
	}
	frame, _, err := EncodePolicy(PolicySpec{
		TeamID: "AB12CD34EF", MeshInstallIdentifier: "io.mesh.node.mesh-install",
		MeshctlIdentifier: "io.mesh.node.meshctl",
		NebulaIdentifier:  "io.mesh.node.nebula", NebulaCertIdentifier: "io.mesh.node.nebula-cert",
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
			t.Fatal("malformed Darwin code-signing policy frame accepted")
		}
	}
}
