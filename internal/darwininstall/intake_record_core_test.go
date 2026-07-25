package darwininstall

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"mesh/internal/onlinerelease"
	releasetrust "mesh/internal/release"
)

func TestDarwinIntakeRecordCanonicalRoundTrip(t *testing.T) {
	inspection := validDarwinCandidateInspection(t)
	root, keys := darwinCandidateTestRoot(t)
	metadata := darwinCandidateTestMetadata(t, root, keys, inspection, 4)
	bundle := onlinerelease.Bundle{
		RootUpdates: [][]byte{}, ChannelManifest: metadata.ChannelManifest, ChannelSignatures: metadata.ChannelSignatures,
		ReleaseManifest: metadata.ReleaseManifest, ReleaseSignatures: metadata.ReleaseSignatures,
	}
	candidate, err := VerifyDarwinCandidateWithRoots(metadata, strings.Repeat("e", 64), root, root, nil,
		time.Date(2026, 7, 21, 20, 0, 0, 0, time.UTC), 4, inspection.Package.Target.Arch)
	if err != nil {
		t.Fatal(err)
	}
	record, err := NewDarwinIntakeRecord(bundle, VerifiedDarwinIntake{
		Candidate: candidate, InstallerBootstrapRootSHA256: strings.Repeat("e", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := encodeDarwinIntakeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeDarwinIntakeRecord(raw)
	if err != nil || !sameDarwinIntakeRecord(record, decoded) {
		t.Fatalf("decoded accepted intake = %+v, %v", decoded, err)
	}
	for name, changed := range map[string][]byte{
		"trailing": append(append([]byte(nil), raw...), '\n'),
		"unknown":  bytes.Replace(raw, []byte(`"schema":`), []byte(`"unknown":1,"schema":`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeDarwinIntakeRecord(changed); err == nil {
				t.Fatal("noncanonical accepted intake was decoded")
			}
		})
	}
	changed := record
	changed.Candidate.Artifact = releasetrust.Artifact{
		OS: "darwin", Arch: candidate.Artifact.Arch, URL: candidate.Artifact.URL,
		Size: candidate.Artifact.Size, SHA256: strings.Repeat("f", 64),
	}
	if _, err := encodeDarwinIntakeRecord(changed); err == nil {
		t.Fatal("accepted intake with candidate drift was encoded")
	}
}
