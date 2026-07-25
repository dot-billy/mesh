package darwininstall

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"mesh/internal/darwinbundle"
)

func TestInstallerJournalCanonicalRoundTripAndIndependentClone(t *testing.T) {
	journal := validInstallerJournal(t)
	raw, err := encodeInstallerJournal(journal)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeInstallerJournal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, journal) {
		t.Fatalf("decoded journal differs: %#v", decoded)
	}
	decoded.Inspection.Package.Entries[0].SHA256 = strings.Repeat("f", 64)
	if journal.Inspection.Package.Entries[0].SHA256 == decoded.Inspection.Package.Entries[0].SHA256 {
		t.Fatal("decoded journal aliases caller inspection entries")
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' || bytes.Contains(raw, []byte(" \n")) {
		t.Fatalf("journal bytes are not one canonical line: %q", raw)
	}
}

func TestInstallerJournalRejectsIdentityAndInspectionAmbiguity(t *testing.T) {
	for name, mutate := range map[string]func(*InstallerJournal){
		"schema":    func(value *InstallerJournal) { value.Schema = "mesh-darwin-install-journal-v5" },
		"operation": func(value *InstallerJournal) { value.Operation = "replace" },
		"installed id": func(value *InstallerJournal) {
			value.InstalledID = "e00000000000000000001-s00000000000000000001-rbbbbbbbbbbbbbbbb-affffffffffffffff"
		},
		"stage name":         func(value *InstallerJournal) { value.StageName = ".stage-unbound-" + strings.Repeat("c", 32) },
		"same prior":         func(value *InstallerJournal) { value.ExpectedPrior = value.InstalledID },
		"temporary name":     func(value *InstallerJournal) { value.CurrentTemporaryName = "current" },
		"inspection schema":  func(value *InstallerJournal) { value.Inspection.Schema = "wrong" },
		"authority artifact": func(value *InstallerJournal) { value.Authority.ArtifactSHA256 = strings.Repeat("f", 64) },
		"artifact suffix": func(value *InstallerJournal) {
			value.Inspection.ArtifactSHA256 = strings.Repeat("e", 64)
		},
		"phase": func(value *InstallerJournal) { value.Phase = "launchd_loaded" },
	} {
		t.Run(name, func(t *testing.T) {
			journal := validInstallerJournal(t)
			mutate(&journal)
			if err := journal.Validate(); err == nil {
				t.Fatal("invalid Darwin installer journal was accepted")
			}
		})
	}
}

func TestInstallerJournalTransitionsAreMonotonicAndImmutable(t *testing.T) {
	staged := validInstallerJournal(t)
	if err := validateInstallerJournalTransition(false, InstallerJournal{}, staged); err != nil {
		t.Fatal(err)
	}
	published, err := staged.WithPhase(JournalPhasePublished)
	if err != nil {
		t.Fatal(err)
	}
	activated, err := published.WithPhase(JournalPhaseActivated)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateInstallerJournalTransition(true, activated, activated); err != nil {
		t.Fatalf("idempotent terminal transition: %v", err)
	}
	if err := validateInstallerJournalTransition(false, InstallerJournal{}, published); err == nil {
		t.Fatal("new journal skipped staged")
	}
	if err := validateInstallerJournalTransition(true, staged, activated); err == nil {
		t.Fatal("journal skipped published")
	}
	if err := validateInstallerJournalTransition(true, published, staged); err == nil {
		t.Fatal("journal phase regressed")
	}
	changed := published
	changed.ExpectedPrior = "e00000000000000000001-s00000000000000000002-rdddddddddddddddd-aeeeeeeeeeeeeeeee"
	if err := validateInstallerJournalTransition(true, staged, changed); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("changed journal identity error = %v", err)
	}
	changed = published
	changed.RestoreRuntimeGate = !published.RestoreRuntimeGate
	if err := validateInstallerJournalTransition(true, staged, changed); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("changed runtime-gate intent error = %v", err)
	}
}

func TestRollbackJournalBindsExactSourceTargetAndOneStepTransition(t *testing.T) {
	targetJournal := validInstallerJournal(t)
	target := targetJournal.Authority
	source := validAuthenticatedDarwinRelease(1, 2, target.MinimumSecurityFloor, "d", "e")
	source.PackageJSONSHA256 = target.PackageJSONSHA256
	journal, err := NewRollbackJournal(
		target.InstalledID, source.InstalledID, ".current-"+strings.Repeat("e", 32),
		targetJournal.Inspection, source, target, source, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateInstallerJournalTransition(false, InstallerJournal{}, journal); err != nil {
		t.Fatal(err)
	}
	activated, err := journal.WithPhase(JournalPhaseActivated)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateInstallerJournalTransition(true, activated, activated); err != nil {
		t.Fatal(err)
	}
	state := validDarwinInstallState(source)
	state.Active = cloneAuthenticatedDarwinRelease(&source)
	state.Previous = cloneAuthenticatedDarwinRelease(&target)
	rolledBack, err := completeRollbackJournalState(activated, state)
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.Active == nil || rolledBack.Previous == nil || *rolledBack.Active != target || *rolledBack.Previous != source || rolledBack.HighWater != source {
		t.Fatalf("completed rollback state = %+v", rolledBack)
	}
	resumed, err := completeRollbackJournalState(activated, rolledBack)
	if err != nil || !sameDarwinInstallState(resumed, rolledBack) {
		t.Fatalf("terminal rollback resume changed state: %+v, %v", resumed, err)
	}
	tampered := rolledBack
	tampered.HighWater = target
	if _, err := completeRollbackJournalState(activated, tampered); err == nil {
		t.Fatal("rollback journal accepted lowered high-water state")
	}
	for name, mutate := range map[string]func(*InstallerJournal){
		"stage":      func(value *InstallerJournal) { value.StageName = ".stage-x" },
		"source":     func(value *InstallerJournal) { value.SourceAuthority = nil },
		"high water": func(value *InstallerJournal) { value.HighWaterAuthority = nil },
		"prior":      func(value *InstallerJournal) { value.ExpectedPrior = value.InstalledID },
		"phase":      func(value *InstallerJournal) { value.Phase = JournalPhasePublished },
	} {
		t.Run(name, func(t *testing.T) {
			changed := journal
			mutate(&changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("invalid rollback journal was accepted")
			}
		})
	}
}

func TestDecodeInstallerJournalRejectsUnknownDuplicateAndNoncanonicalJSON(t *testing.T) {
	raw, err := encodeInstallerJournal(validInstallerJournal(t))
	if err != nil {
		t.Fatal(err)
	}
	unknown := append([]byte(nil), raw[:len(raw)-2]...)
	unknown = append(unknown, []byte(`,"unknown":true}`+"\n")...)
	duplicate := bytes.Replace(raw, []byte(`{"schema":`), []byte(`{"schema":"mesh-darwin-install-journal-v4","schema":`), 1)
	noncanonical := append([]byte(" "), raw...)
	trailing := append(append([]byte(nil), raw...), []byte(`{}`)...)
	for name, candidate := range map[string][]byte{
		"unknown": unknown, "duplicate": duplicate, "noncanonical": noncanonical, "trailing": trailing,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeInstallerJournal(candidate); err == nil {
				t.Fatal("ambiguous journal JSON was accepted")
			}
		})
	}
}

func validInstallerJournal(t *testing.T) InstallerJournal {
	t.Helper()
	inspection := validDarwinCandidateInspection(t)
	installedID := "e00000000000000000001-s00000000000000000001-rbbbbbbbbbbbbbbbb-a" + inspection.ArtifactSHA256[:16]
	authority := validAuthenticatedDarwinRelease(1, 1, inspection.Package.SecurityFloor, "b", "a")
	authority.PackageJSONSHA256 = inspection.PackageJSONSHA256
	authority.InstalledID = installedID
	journal, err := NewInstallerJournal(
		installedID,
		".stage-"+installedID+"-"+strings.Repeat("c", 32),
		"",
		".current-"+strings.Repeat("d", 32),
		inspection,
		authority,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

func validDarwinCandidateInspection(t *testing.T) darwinbundle.CandidateInspection {
	t.Helper()
	entries := []darwinbundle.Entry{
		{Path: "Library/LaunchDaemons/io.mesh.node-agent.plist", ArchiveMode: 0o444, Size: 1, SHA256: strings.Repeat("1", 64)},
		{Path: "bin/meshctl", ArchiveMode: 0o555, Size: 1, SHA256: strings.Repeat("2", 64)},
		{Path: "bin/nebula", ArchiveMode: 0o555, Size: 1, SHA256: strings.Repeat("3", 64)},
		{Path: "bin/nebula-cert", ArchiveMode: 0o555, Size: 1, SHA256: strings.Repeat("4", 64)},
		{Path: "share/doc/mesh/launchd/README.md", ArchiveMode: 0o444, Size: 1, SHA256: strings.Repeat("5", 64)},
		{Path: "share/licenses/nebula/LICENSE", ArchiveMode: 0o444, Size: 1, SHA256: strings.Repeat("6", 64)},
	}
	pack := darwinbundle.Package{
		Schema: darwinbundle.Schema, Version: "1.2.3", Commit: strings.Repeat("a", 40),
		BuildTime: "2026-07-19T16:00:00Z", SecurityFloor: 1,
		AgentStateReadMin: 2, AgentStateReadMax: 2, AgentStateWriteVersion: 2,
		GoVersion: "go1.26.5", Target: darwinbundle.Target{OS: "darwin", Arch: "amd64"},
		Runtime: darwinbundle.RuntimeIdentity{
			Version: "v1.10.3", Commit: strings.Repeat("b", 40),
			UpstreamLockSHA256: strings.Repeat("7", 64), SourceBuildLockSHA256: strings.Repeat("8", 64),
			DarwinBuildLockSHA256: strings.Repeat("9", 64), SourceTreeSHA256: strings.Repeat("a", 64),
			PatchedTreeSHA256: strings.Repeat("b", 64), PatchSetSHA256: strings.Repeat("c", 64), GoVersion: "go1.26.5",
		},
		Entries: entries,
	}
	packageJSON, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	packageJSON = append(packageJSON, '\n')
	packageDigest := sha256.Sum256(packageJSON)
	padded := func(size int64) int64 { return (size + 511) / 512 * 512 }
	archiveSize := int64(512) + padded(int64(len(packageJSON))) + 2*512
	for _, entry := range entries {
		archiveSize += 512 + padded(entry.Size)
	}
	inspection := darwinbundle.CandidateInspection{
		Schema: darwinbundle.CandidateInspectionSchema, ArtifactSHA256: strings.Repeat("a", 64),
		ArtifactSize: archiveSize, PackageJSONSHA256: hex.EncodeToString(packageDigest[:]),
		FileCount: len(entries) + 1, DirectoryCount: 9, TotalBytes: int64(len(packageJSON) + len(entries)),
		Package: pack,
	}
	if err := darwinbundle.ValidateCandidateInspection(inspection); err != nil {
		t.Fatalf("test candidate inspection: %v", err)
	}
	return inspection
}
