package iosmobile

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFrameworkIdentityIsExactAndNonSecret(t *testing.T) {
	var identity map[string]string
	if err := json.Unmarshal([]byte(FrameworkIdentity()), &identity); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"schema":         frameworkSchema,
		"nebula_version": nebulaVersion,
		"capability": "extension-enrollment-lifecycle-renewal-credential-rotation-" +
			"mobile-evidence-identity-removal-signed-config-packet-session",
	}
	if len(identity) != len(want) {
		t.Fatalf("unexpected identity: %#v", identity)
	}
	for key, value := range want {
		if identity[key] != value {
			t.Fatalf("%s = %q, want %q", key, identity[key], value)
		}
	}
	for _, forbidden := range []string{
		"private",
		"bearer",
		"token",
	} {
		if strings.Contains(FrameworkIdentity(), forbidden) {
			t.Fatalf("framework identity contains %q", forbidden)
		}
	}
	if FrameworkIdentitySHA256() == "" ||
		len(FrameworkIdentitySHA256()) != 64 {
		t.Fatal("framework identity digest is invalid")
	}
}

func TestEnsureIdentityRejectsUnscopedInputBeforeKeychain(t *testing.T) {
	for _, test := range []struct {
		group string
		id    string
	}{
		{"", "node_1"},
		{"TEAM.other.group", "node_1"},
		{"TEAM." + identityGroupSuffix, ""},
		{"TEAM." + identityGroupSuffix, "../node"},
	} {
		if _, err := EnsureIdentity(test.group, test.id); err == nil {
			t.Fatalf("accepted group %q identity %q", test.group, test.id)
		}
	}
}
