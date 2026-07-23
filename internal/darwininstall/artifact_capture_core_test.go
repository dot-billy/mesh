package darwininstall

import (
	"strings"
	"testing"
)

func TestDarwinArtifactCaptureNamesBindExactDigest(t *testing.T) {
	digest := strings.Repeat("a", 64)
	live, err := darwinArtifactCaptureName(digest)
	if err != nil || live != "artifact-"+digest+".tar" {
		t.Fatalf("live artifact capture name = %q, %v", live, err)
	}
	pending, err := darwinArtifactCapturePendingName(digest)
	if err != nil || pending != ".artifact-"+digest+".tar.new" {
		t.Fatalf("pending artifact capture name = %q, %v", pending, err)
	}
	for _, invalid := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		if _, err := darwinArtifactCaptureName(invalid); err == nil {
			t.Fatalf("invalid capture digest %q was accepted", invalid)
		}
	}
}
