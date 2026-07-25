package darwininstall

import (
	"testing"
	"time"
)

func TestDarwinAcceptedStageNameIsDeterministicAndAuthorityBound(t *testing.T) {
	inspection := validDarwinCandidateInspection(t)
	root, keys := darwinCandidateTestRoot(t)
	metadata := darwinCandidateTestMetadata(t, root, keys, inspection, 4)
	candidate, err := VerifyDarwinCandidateWithRoots(metadata, root.SHA256, root, root, nil,
		mustParseDarwinStageTestTime(t), inspection.Package.SecurityFloor, inspection.Package.Target.Arch)
	if err != nil {
		t.Fatal(err)
	}
	name, err := darwinAcceptedStageName(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if got := DarwinCandidateInstalledID(candidate); got == "" || name != ".stage-"+got+"-"+candidate.ChannelManifestSHA256[:32] {
		t.Fatalf("derived Darwin accepted stage = %q, installed ID = %q", name, got)
	}
	changed := candidate
	changed.Sequence++
	changedName, err := darwinAcceptedStageName(changed)
	if err != nil || changedName == name {
		t.Fatalf("changed Darwin candidate stage = %q, %v", changedName, err)
	}
}

func mustParseDarwinStageTestTime(t *testing.T) time.Time {
	t.Helper()
	value, err := time.Parse(time.RFC3339, "2026-07-21T20:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	return value
}
