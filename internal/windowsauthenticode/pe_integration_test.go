package windowsauthenticode

import (
	"os"
	"testing"
)

func TestLockedWintunAuthenticodeEnvelope(t *testing.T) {
	path := os.Getenv("MESH_WINTUN_DLL")
	if path == "" {
		t.Skip("set MESH_WINTUN_DLL to a lock-verified upstream Wintun DLL")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InspectPEEnvelope(content); err != nil {
		t.Fatalf("locked upstream Wintun Authenticode envelope: %v", err)
	}
}
