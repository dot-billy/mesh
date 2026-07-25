//go:build darwin

package darwincodesign

import (
	"os"
	"strings"
	"testing"
)

func TestDarwinNativeApplePlatformToolRequirements(t *testing.T) {
	if os.Getenv("MESH_DARWIN_NATIVE_FAULT_TEST") != "1" {
		t.Skip("run through the approved root-only native Darwin harness")
	}
	if err := VerifyLaunchctl(); err != nil {
		t.Fatal(err)
	}
}

func TestDarwinNativeDevelopmentPolicyFailsBeforeTargetAdmission(t *testing.T) {
	original := Identity
	t.Cleanup(func() { Identity = original })
	Identity = DevelopmentPolicy
	_, err := VerifyRelease("/opt/mesh/releases/not-present")
	if err == nil || !strings.Contains(err.Error(), "no Darwin code-signing admission policy") {
		t.Fatalf("development policy returned %v", err)
	}
}
