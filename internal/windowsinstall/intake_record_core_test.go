package windowsinstall

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"mesh/internal/onlinerelease"
)

func TestWindowsIntakeRecordCanonicalRoundTrip(t *testing.T) {
	inspection := validWindowsCandidateInspection(t)
	root, keys := windowsCandidateTestRoot(t)
	metadata := windowsCandidateTestMetadata(t, root, keys, inspection, 7)
	now := time.Date(2026, 7, 21, 20, 0, 0, 0, time.UTC)
	candidate, err := VerifyWindowsCandidateWithRoots(metadata, root.SHA256, root, root, nil, now, 2, inspection.Package.Target.Arch)
	if err != nil {
		t.Fatal(err)
	}
	intake := VerifiedWindowsIntake{
		Candidate: candidate, InstallerBootstrapRootSHA256: root.SHA256,
	}
	bundle := onlinerelease.Bundle{
		RootUpdates:       [][]byte{},
		ChannelManifest:   metadata.ChannelManifest,
		ChannelSignatures: metadata.ChannelSignatures,
		ReleaseManifest:   metadata.ReleaseManifest,
		ReleaseSignatures: metadata.ReleaseSignatures,
	}
	record, err := NewWindowsIntakeRecord(bundle, intake)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalWindowsIntakeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseWindowsIntakeRecord(raw)
	if err != nil || !reflect.DeepEqual(parsed, record) {
		t.Fatalf("parsed=%+v err=%v", parsed, err)
	}
	if recovered, err := parsed.Intake(); err != nil || !reflect.DeepEqual(recovered, intake) {
		t.Fatalf("recovered=%+v err=%v", recovered, err)
	}
	if _, err := ParseWindowsIntakeRecord(append([]byte(" "), raw...)); err == nil {
		t.Fatal("noncanonical Windows accepted intake was accepted")
	}
	changed := record
	changed.Candidate.ReleaseManifestSHA256 = strings.Repeat("f", 64)
	if err := changed.Validate(); err == nil {
		t.Fatal("Windows accepted intake allowed cached candidate drift from signed bytes")
	}
}
