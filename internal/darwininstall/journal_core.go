package darwininstall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"

	"mesh/internal/darwinbundle"
)

const (
	InstallerJournalSchema  = "mesh-darwin-install-journal-v4"
	maxInstallerJournalSize = 128 << 10
)

type InstallerJournalPhase string

type InstallerJournalOperation string

const (
	JournalOperationActivate InstallerJournalOperation = "activate"
	JournalOperationRollback InstallerJournalOperation = "rollback"

	JournalPhasePrepared  InstallerJournalPhase = "prepared"
	JournalPhaseStaged    InstallerJournalPhase = "staged"
	JournalPhasePublished InstallerJournalPhase = "published"
	JournalPhaseActivated InstallerJournalPhase = "activated"
)

var (
	darwinInstalledIDPattern      = regexp.MustCompile(`^(?:s[0-9]{20}|e[0-9]{20}-s[0-9]{20})-r[0-9a-f]{16}-a[0-9a-f]{16}$`)
	darwinStageNamePattern        = regexp.MustCompile(`^\.stage-(?:s[0-9]{20}|e[0-9]{20}-s[0-9]{20})-r[0-9a-f]{16}-a[0-9a-f]{16}-[0-9a-f]{32}$`)
	darwinCurrentTemporaryPattern = regexp.MustCompile(`^\.current-[0-9a-f]{32}$`)
)

// InstallerJournal is the immutable identity and monotonic phase of one
// authenticated Darwin release publication/launchd-activation transaction.
type InstallerJournal struct {
	Schema               string                           `json:"schema"`
	Operation            InstallerJournalOperation        `json:"operation"`
	InstalledID          string                           `json:"installed_id"`
	StageName            string                           `json:"stage_name"`
	ExpectedPrior        string                           `json:"expected_prior"`
	CurrentTemporaryName string                           `json:"current_temporary_name"`
	Inspection           darwinbundle.CandidateInspection `json:"inspection"`
	Authority            AuthenticatedDarwinRelease       `json:"authority"`
	SourceAuthority      *AuthenticatedDarwinRelease      `json:"source_authority,omitempty"`
	HighWaterAuthority   *AuthenticatedDarwinRelease      `json:"high_water_authority,omitempty"`
	RestoreRuntimeGate   bool                             `json:"restore_runtime_gate"`
	Phase                InstallerJournalPhase            `json:"phase"`
}

func NewInstallerJournal(installedID string, stageName string, expectedPrior string, currentTemporaryName string, inspection darwinbundle.CandidateInspection, authority AuthenticatedDarwinRelease, restoreRuntimeGate bool) (InstallerJournal, error) {
	journal := InstallerJournal{
		Schema: InstallerJournalSchema, Operation: JournalOperationActivate, InstalledID: installedID, StageName: stageName,
		ExpectedPrior: expectedPrior, CurrentTemporaryName: currentTemporaryName,
		Inspection: inspection, Authority: authority, RestoreRuntimeGate: restoreRuntimeGate, Phase: JournalPhaseStaged,
	}
	if err := journal.Validate(); err != nil {
		return InstallerJournal{}, err
	}
	return journal, nil
}

// NewRollbackJournal records both sides of the sole legal active/previous
// swap. Unlike activation, the target is already an authenticated published
// release and therefore has no private stage or publication phase.
func NewRollbackJournal(installedID string, expectedPrior string, currentTemporaryName string, inspection darwinbundle.CandidateInspection, source, target, highWater AuthenticatedDarwinRelease, restoreRuntimeGate bool) (InstallerJournal, error) {
	journal := InstallerJournal{
		Schema: InstallerJournalSchema, Operation: JournalOperationRollback,
		InstalledID: installedID, ExpectedPrior: expectedPrior, CurrentTemporaryName: currentTemporaryName,
		Inspection: inspection, Authority: target, SourceAuthority: &source, HighWaterAuthority: &highWater,
		RestoreRuntimeGate: restoreRuntimeGate, Phase: JournalPhasePrepared,
	}
	if err := journal.Validate(); err != nil {
		return InstallerJournal{}, err
	}
	return journal, nil
}

func (journal InstallerJournal) Validate() error {
	if journal.Schema != InstallerJournalSchema {
		return errors.New("Darwin installer journal schema is invalid")
	}
	if !darwinInstalledIDPattern.MatchString(journal.InstalledID) {
		return errors.New("Darwin installer journal installed ID is not canonical")
	}
	if journal.ExpectedPrior == journal.InstalledID || journal.ExpectedPrior != "" && !darwinInstalledIDPattern.MatchString(journal.ExpectedPrior) {
		return errors.New("Darwin installer journal expected prior is invalid")
	}
	if !darwinCurrentTemporaryPattern.MatchString(journal.CurrentTemporaryName) {
		return errors.New("Darwin installer journal current temporary name is invalid")
	}
	if err := darwinbundle.ValidateCandidateInspection(journal.Inspection); err != nil {
		return fmt.Errorf("Darwin installer journal inspection: %w", err)
	}
	if !strings.HasSuffix(journal.InstalledID, "-a"+journal.Inspection.ArtifactSHA256[:16]) {
		return errors.New("Darwin installer journal installed ID differs from the inspected artifact")
	}
	if err := journal.Authority.Validate(); err != nil {
		return fmt.Errorf("Darwin installer journal authority: %w", err)
	}
	if journal.Authority.InstalledID != journal.InstalledID ||
		journal.Authority.ArtifactSHA256 != journal.Inspection.ArtifactSHA256 ||
		journal.Authority.PackageJSONSHA256 != journal.Inspection.PackageJSONSHA256 ||
		journal.Authority.Arch != journal.Inspection.Package.Target.Arch ||
		journal.Authority.BundleSecurityFloor != journal.Inspection.Package.SecurityFloor ||
		journal.Authority.AgentStateReadMin != journal.Inspection.Package.AgentStateReadMin ||
		journal.Authority.AgentStateReadMax != journal.Inspection.Package.AgentStateReadMax ||
		journal.Authority.AgentStateWriteVersion != journal.Inspection.Package.AgentStateWriteVersion {
		return errors.New("Darwin installer journal authority differs from the authenticated bundle inspection")
	}
	switch journal.Operation {
	case JournalOperationActivate:
		if !darwinStageNamePattern.MatchString(journal.StageName) || !strings.HasPrefix(journal.StageName, ".stage-"+journal.InstalledID+"-") {
			return errors.New("Darwin activation journal stage name is not bound to its installed ID")
		}
		if journal.SourceAuthority != nil || journal.HighWaterAuthority != nil {
			return errors.New("Darwin activation journal cannot carry rollback source authority")
		}
		if journal.Phase != JournalPhaseStaged && journal.Phase != JournalPhasePublished && journal.Phase != JournalPhaseActivated {
			return fmt.Errorf("unsupported Darwin activation journal phase %q", journal.Phase)
		}
	case JournalOperationRollback:
		if journal.StageName != "" || journal.ExpectedPrior == "" {
			return errors.New("Darwin rollback journal requires an existing prior and no private stage")
		}
		if journal.SourceAuthority == nil {
			return errors.New("Darwin rollback journal requires exact source authority")
		}
		if journal.HighWaterAuthority == nil {
			return errors.New("Darwin rollback journal requires exact high-water authority")
		}
		if err := journal.SourceAuthority.Validate(); err != nil {
			return fmt.Errorf("Darwin rollback source authority: %w", err)
		}
		if err := journal.HighWaterAuthority.Validate(); err != nil {
			return fmt.Errorf("Darwin rollback high-water authority: %w", err)
		}
		if journal.SourceAuthority.InstalledID != journal.ExpectedPrior ||
			journal.SourceAuthority.InstalledID == journal.Authority.InstalledID ||
			journal.SourceAuthority.InstallerBootstrapRootSHA256 != journal.Authority.InstallerBootstrapRootSHA256 ||
			journal.SourceAuthority.Channel != journal.Authority.Channel || journal.SourceAuthority.Arch != journal.Authority.Arch ||
			journal.HighWaterAuthority.InstallerBootstrapRootSHA256 != journal.Authority.InstallerBootstrapRootSHA256 ||
			journal.HighWaterAuthority.Channel != journal.Authority.Channel || journal.HighWaterAuthority.Arch != journal.Authority.Arch ||
			compareDarwinReleasePosition(*journal.SourceAuthority, *journal.HighWaterAuthority) > 0 ||
			compareDarwinReleasePosition(journal.Authority, *journal.HighWaterAuthority) > 0 {
			return errors.New("Darwin rollback source and target authority are inconsistent")
		}
		if journal.Phase != JournalPhasePrepared && journal.Phase != JournalPhaseActivated {
			return fmt.Errorf("unsupported Darwin rollback journal phase %q", journal.Phase)
		}
	default:
		return fmt.Errorf("unsupported Darwin installer journal operation %q", journal.Operation)
	}
	return nil
}

func (journal InstallerJournal) WithPhase(phase InstallerJournalPhase) (InstallerJournal, error) {
	next := cloneInstallerJournal(journal)
	next.Phase = phase
	if err := next.Validate(); err != nil {
		return InstallerJournal{}, err
	}
	if err := validateInstallerJournalTransition(true, journal, next); err != nil {
		return InstallerJournal{}, err
	}
	return next, nil
}

func validateInstallerJournalTransition(found bool, current InstallerJournal, next InstallerJournal) error {
	if err := next.Validate(); err != nil {
		return err
	}
	if !found {
		if next.Operation == JournalOperationActivate && next.Phase != JournalPhaseStaged ||
			next.Operation == JournalOperationRollback && next.Phase != JournalPhasePrepared {
			return errors.New("a new Darwin installer journal has the wrong initial phase")
		}
		return nil
	}
	if err := current.Validate(); err != nil {
		return fmt.Errorf("current Darwin installer journal: %w", err)
	}
	currentIdentity := cloneInstallerJournal(current)
	nextIdentity := cloneInstallerJournal(next)
	currentIdentity.Phase = ""
	nextIdentity.Phase = ""
	if !reflect.DeepEqual(currentIdentity, nextIdentity) {
		return errors.New("Darwin installer journal fields other than phase are immutable")
	}
	if current.Phase == next.Phase {
		return nil
	}
	if current.Operation == JournalOperationActivate && current.Phase == JournalPhaseStaged && next.Phase == JournalPhasePublished ||
		current.Operation == JournalOperationActivate && current.Phase == JournalPhasePublished && next.Phase == JournalPhaseActivated ||
		current.Operation == JournalOperationRollback && current.Phase == JournalPhasePrepared && next.Phase == JournalPhaseActivated {
		return nil
	}
	return fmt.Errorf("Darwin installer journal phase cannot advance from %q to %q", current.Phase, next.Phase)
}

func nextInstallerJournalPhase(phase InstallerJournalPhase) (InstallerJournalPhase, bool) {
	switch phase {
	case JournalPhasePrepared:
		return JournalPhaseActivated, true
	case JournalPhaseStaged:
		return JournalPhasePublished, true
	case JournalPhasePublished:
		return JournalPhaseActivated, true
	default:
		return "", false
	}
}

// rollbackJournalStateStatus recognizes only the exact state immediately
// before or immediately after the journaled swap. The boolean is true only
// after the state commit, allowing recovery to clear the terminal journal
// without accidentally swapping back.
func rollbackJournalStateStatus(journal InstallerJournal, state DarwinInstallState) (bool, error) {
	if err := journal.Validate(); err != nil || journal.Operation != JournalOperationRollback {
		return false, errors.Join(err, errors.New("valid Darwin rollback journal is required"))
	}
	if err := state.Validate(); err != nil {
		return false, err
	}
	if state.Active == nil || state.Previous == nil || journal.SourceAuthority == nil || journal.HighWaterAuthority == nil ||
		state.HighWater != *journal.HighWaterAuthority {
		return false, errors.New("Darwin install state differs from rollback journal authority")
	}
	if *state.Active == *journal.SourceAuthority && *state.Previous == journal.Authority {
		return false, nil
	}
	if *state.Active == journal.Authority && *state.Previous == *journal.SourceAuthority {
		return true, nil
	}
	return false, errors.New("Darwin install-state active/previous pair differs from rollback journal")
}

func completeRollbackJournalState(journal InstallerJournal, state DarwinInstallState) (DarwinInstallState, error) {
	alreadyCommitted, err := rollbackJournalStateStatus(journal, state)
	if err != nil {
		return DarwinInstallState{}, err
	}
	if alreadyCommitted {
		return cloneDarwinInstallState(state), nil
	}
	next, err := state.RollbackPrevious()
	if err != nil {
		return DarwinInstallState{}, err
	}
	committed, err := rollbackJournalStateStatus(journal, next)
	if err != nil || !committed {
		return DarwinInstallState{}, errors.Join(err, errors.New("Darwin rollback state did not reach its journaled target"))
	}
	return next, nil
}

func encodeInstallerJournal(journal InstallerJournal) ([]byte, error) {
	journal = cloneInstallerJournal(journal)
	if err := journal.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(journal)
	if err != nil {
		return nil, fmt.Errorf("encode Darwin installer journal: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) == 0 || len(raw) > maxInstallerJournalSize {
		return nil, errors.New("Darwin installer journal exceeds its size bound")
	}
	return raw, nil
}

func decodeInstallerJournal(raw []byte) (InstallerJournal, error) {
	if len(raw) == 0 || len(raw) > maxInstallerJournalSize || !utf8.Valid(raw) {
		return InstallerJournal{}, errors.New("Darwin installer journal bytes are invalid or outside their bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var journal InstallerJournal
	if err := decoder.Decode(&journal); err != nil {
		return InstallerJournal{}, fmt.Errorf("decode Darwin installer journal: %w", err)
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return InstallerJournal{}, fmt.Errorf("decode Darwin installer journal trailing data: %w", err)
		}
		return InstallerJournal{}, fmt.Errorf("decode Darwin installer journal trailing token %v", token)
	}
	canonical, err := encodeInstallerJournal(journal)
	if err != nil {
		return InstallerJournal{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return InstallerJournal{}, errors.New("Darwin installer journal is not canonical")
	}
	return cloneInstallerJournal(journal), nil
}

func cloneInstallerJournal(journal InstallerJournal) InstallerJournal {
	journal.Inspection.Package.Entries = append([]darwinbundle.Entry(nil), journal.Inspection.Package.Entries...)
	journal.SourceAuthority = cloneAuthenticatedDarwinRelease(journal.SourceAuthority)
	journal.HighWaterAuthority = cloneAuthenticatedDarwinRelease(journal.HighWaterAuthority)
	return journal
}
