package nebula

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestV1103LicenseExactAndFresh(t *testing.T) {
	first := V1103License()
	if len(first) != 1088 {
		t.Fatalf("LICENSE length = %d, want 1088", len(first))
	}
	digest := sha256.Sum256(first)
	if got := hex.EncodeToString(digest[:]); got != "aefd0cce553f24945ce1c692c3c4f9fda581f078ba82977845715cd18565b3bd" {
		t.Fatalf("LICENSE SHA-256 = %s", got)
	}
	first[0] ^= 0xff
	if got := string(V1103License()[:12]); got != "MIT License\n" {
		t.Fatalf("later LICENSE copy starts %q", got)
	}
}

func TestV1103LockIsFresh(t *testing.T) {
	first := V1103Lock()
	if len(first) == 0 {
		t.Fatal("embedded lock is empty")
	}
	want := first[0]
	first[0] ^= 0xff
	if got := V1103Lock()[0]; got != want {
		t.Fatal("mutating one lock copy changed a later copy")
	}
}
