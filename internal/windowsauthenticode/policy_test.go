package windowsauthenticode

import (
	"reflect"
	"strings"
	"testing"
)

func TestPolicyCanonicalRoundTripAndRoles(t *testing.T) {
	meshA := strings.Repeat("a", 64)
	meshB := strings.Repeat("b", 64)
	wintun := strings.Repeat("c", 64)
	frame, policy, err := EncodePolicy(PolicySpec{
		MeshSignerSPKISHA256: []string{meshB, meshA}, WintunSignerSPKISHA256: []string{wintun},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePolicyIdentity(frame)
	if err != nil || !reflect.DeepEqual(parsed, policy) {
		t.Fatalf("parsed=%+v policy=%+v error=%v", parsed, policy, err)
	}
	if !policy.Allows(MeshSignerRole, meshA) || !policy.Allows(MeshSignerRole, meshB) ||
		policy.Allows(MeshSignerRole, wintun) || !policy.Allows(WintunSignerRole, wintun) ||
		policy.Allows("unknown", meshA) {
		t.Fatal("Windows Authenticode role pin selection is not exact")
	}
}

func TestPolicyRejectsMalformedOrWeakenedAuthority(t *testing.T) {
	digest := strings.Repeat("d", 64)
	for name, spec := range map[string]PolicySpec{
		"missing mesh":   {WintunSignerSPKISHA256: []string{digest}},
		"missing wintun": {MeshSignerSPKISHA256: []string{digest}},
		"duplicate":      {MeshSignerSPKISHA256: []string{digest, digest}, WintunSignerSPKISHA256: []string{digest}},
		"uppercase":      {MeshSignerSPKISHA256: []string{strings.Repeat("A", 64)}, WintunSignerSPKISHA256: []string{digest}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := EncodePolicy(spec); err == nil {
				t.Fatal("invalid Windows Authenticode policy accepted")
			}
		})
	}
	frame, _, err := EncodePolicy(PolicySpec{
		MeshSignerSPKISHA256:   []string{strings.Repeat("e", 64)},
		WintunSignerSPKISHA256: []string{strings.Repeat("f", 64)},
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
			t.Fatal("malformed Windows Authenticode frame accepted")
		}
	}
}
