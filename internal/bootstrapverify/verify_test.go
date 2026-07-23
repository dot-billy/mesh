package bootstrapverify

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyRejectsUnauthenticatedDigestAndUnboundedInputsFirst(t *testing.T) {
	if _, err := Verify(Input{ExpectedRootSHA256: "not-a-digest"}); err == nil || !strings.Contains(err.Error(), "64 lowercase") {
		t.Fatalf("invalid independent digest returned %v", err)
	}
	if _, err := Verify(Input{ExpectedRootSHA256: strings.Repeat("0", 64)}); err == nil || !strings.Contains(err.Error(), "root size") {
		t.Fatalf("empty root returned %v", err)
	}
}

func TestVerifyFilesRejectsMissingAndEmptySignaturePaths(t *testing.T) {
	base := FileInput{
		RootPath: "root", ExpectedRootSHA256: strings.Repeat("0", 64),
		ManifestPath: "manifest", InstallerPath: "installer",
	}
	if _, err := VerifyFiles(base); err == nil || !strings.Contains(err.Error(), "signature count") {
		t.Fatalf("missing signatures returned %v", err)
	}
	base.SignaturePaths = []string{""}
	if _, err := VerifyFiles(base); err == nil {
		t.Fatal("empty signature path accepted")
	}
}

func TestVerifyHandoffFilesRejectsMissingAndUnauthenticatedAnchorFirst(t *testing.T) {
	if _, err := VerifyHandoffFiles(HandoffFileInput{}); err == nil || !strings.Contains(err.Error(), "paths are required") {
		t.Fatalf("empty handoff input returned %v", err)
	}
	input := HandoffFileInput{
		HandoffPath: "handoff", RootPath: "root", ManifestPath: "manifest", InstallerPath: "installer",
		ExpectedHandoffSHA256: "not-a-digest", SignaturePaths: []string{"signature"},
	}
	if _, err := VerifyHandoffFiles(input); err == nil || !strings.Contains(err.Error(), "64 lowercase") {
		t.Fatalf("invalid independent handoff digest returned %v", err)
	}
	input.ExpectedHandoffSHA256 = strings.Repeat("1", 64)
	input.AnchorPath = "anchor"
	if _, err := VerifyHandoffFiles(input); err == nil || !strings.Contains(err.Error(), "exactly one independent") {
		t.Fatalf("mixed independent handoff authorities returned %v", err)
	}
	input.ExpectedHandoffSHA256 = ""
	input.AnchorPath = ""
	if _, err := VerifyHandoffFiles(input); err == nil || !strings.Contains(err.Error(), "exactly one independent") {
		t.Fatalf("missing independent handoff authority returned %v", err)
	}
}

func TestVerifyHandoffFilesReadsIndependentAnchorBeforeCourierHandoff(t *testing.T) {
	root := t.TempDir()
	_, err := VerifyHandoffFiles(HandoffFileInput{
		AnchorPath:     filepath.Join(root, "missing-anchor.json"),
		HandoffPath:    filepath.Join(root, "missing-handoff.json"),
		RootPath:       filepath.Join(root, "missing-root.json"),
		ManifestPath:   filepath.Join(root, "missing-manifest.json"),
		SignaturePaths: []string{filepath.Join(root, "missing-signature.json")},
		InstallerPath:  filepath.Join(root, "missing-installer"),
	})
	if err == nil || !strings.Contains(err.Error(), "read bootstrap anchor") || strings.Contains(err.Error(), "read bootstrap handoff") {
		t.Fatalf("anchor-first read returned %v", err)
	}
}
