package windowsinstall

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
)

const (
	WindowsActivationJournalSchema = "mesh-windows-activation-journal-v3"
	maximumWindowsJournalBytes     = 32 << 10
)

type WindowsActivationPhase string
type WindowsActivationOperation string

const (
	WindowsOperationActivate WindowsActivationOperation = "activate"
	WindowsOperationRollback WindowsActivationOperation = "rollback"
)

const (
	WindowsActivationPrepared  WindowsActivationPhase = "prepared"
	WindowsActivationQuiesced  WindowsActivationPhase = "quiesced"
	WindowsActivationSelected  WindowsActivationPhase = "selected"
	WindowsActivationActivated WindowsActivationPhase = "activated"
)

var windowsTransactionIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// WindowsActivationJournal is the durable, immutable identity and monotonic
// phase of one selector-and-service activation. Source observations are
// captured before mutation; desired state is explicit so first installation
// need not pretend there was a running source service.
type WindowsActivationJournal struct {
	Schema                 string                       `json:"schema"`
	TransactionID          string                       `json:"transaction_id"`
	Operation              WindowsActivationOperation   `json:"operation"`
	ExpectedPrior          *CurrentDescriptor           `json:"expected_prior,omitempty"`
	Target                 CurrentDescriptor            `json:"target"`
	SourceAuthority        *AuthenticatedWindowsRelease `json:"source_authority,omitempty"`
	Authority              AuthenticatedWindowsRelease  `json:"authority"`
	HighWaterAuthority     AuthenticatedWindowsRelease  `json:"high_water_authority"`
	CurrentTemporaryName   string                       `json:"current_temporary_name"`
	SourceServiceInstalled bool                         `json:"source_service_installed"`
	SourceServiceRunning   bool                         `json:"source_service_running"`
	SourceRuntimeGateOpen  bool                         `json:"source_runtime_gate_open"`
	DesiredServiceRunning  bool                         `json:"desired_service_running"`
	DesiredRuntimeGateOpen bool                         `json:"desired_runtime_gate_open"`
	Phase                  WindowsActivationPhase       `json:"phase"`
}

func NewWindowsActivationJournal(
	source *AuthenticatedWindowsRelease,
	target AuthenticatedWindowsRelease,
	currentTemporaryName string,
	sourceServiceInstalled, sourceServiceRunning, sourceRuntimeGateOpen bool,
	desiredServiceRunning, desiredRuntimeGateOpen bool,
) (WindowsActivationJournal, error) {
	return newWindowsActivationJournal(
		WindowsOperationActivate, source, target, target, currentTemporaryName,
		sourceServiceInstalled, sourceServiceRunning, sourceRuntimeGateOpen,
		desiredServiceRunning, desiredRuntimeGateOpen,
	)
}

func NewWindowsRollbackJournal(
	state WindowsInstallState,
	currentTemporaryName string,
	sourceServiceInstalled, sourceServiceRunning, sourceRuntimeGateOpen bool,
	desiredServiceRunning, desiredRuntimeGateOpen bool,
) (WindowsActivationJournal, error) {
	if err := state.Validate(); err != nil {
		return WindowsActivationJournal{}, err
	}
	if state.Active == nil || state.Previous == nil {
		return WindowsActivationJournal{}, errors.New("Windows rollback journal requires active and previous authorities")
	}
	if _, err := state.RollbackPrevious(); err != nil {
		return WindowsActivationJournal{}, err
	}
	return newWindowsActivationJournal(
		WindowsOperationRollback, state.Active, *state.Previous, state.HighWater, currentTemporaryName,
		sourceServiceInstalled, sourceServiceRunning, sourceRuntimeGateOpen,
		desiredServiceRunning, desiredRuntimeGateOpen,
	)
}

func newWindowsActivationJournal(
	operation WindowsActivationOperation,
	source *AuthenticatedWindowsRelease,
	target, highWater AuthenticatedWindowsRelease,
	currentTemporaryName string,
	sourceServiceInstalled, sourceServiceRunning, sourceRuntimeGateOpen bool,
	desiredServiceRunning, desiredRuntimeGateOpen bool,
) (WindowsActivationJournal, error) {
	targetDescriptor, err := target.CurrentDescriptor()
	if err != nil {
		return WindowsActivationJournal{}, err
	}
	var expectedPrior *CurrentDescriptor
	if source != nil {
		descriptor, err := source.CurrentDescriptor()
		if err != nil {
			return WindowsActivationJournal{}, err
		}
		expectedPrior = &descriptor
	}
	identity := make([]byte, 16)
	if _, err := rand.Read(identity); err != nil {
		return WindowsActivationJournal{}, fmt.Errorf("create Windows activation identity: %w", err)
	}
	journal := WindowsActivationJournal{
		Schema: WindowsActivationJournalSchema, TransactionID: hex.EncodeToString(identity),
		Operation: operation, ExpectedPrior: cloneCurrentDescriptor(expectedPrior), Target: targetDescriptor,
		SourceAuthority: cloneAuthenticatedWindowsRelease(source), Authority: target, HighWaterAuthority: highWater,
		CurrentTemporaryName:   currentTemporaryName,
		SourceServiceInstalled: sourceServiceInstalled, SourceServiceRunning: sourceServiceRunning,
		SourceRuntimeGateOpen: sourceRuntimeGateOpen, DesiredServiceRunning: desiredServiceRunning,
		DesiredRuntimeGateOpen: desiredRuntimeGateOpen, Phase: WindowsActivationPrepared,
	}
	if err := journal.Validate(); err != nil {
		return WindowsActivationJournal{}, err
	}
	return journal, nil
}

func (journal WindowsActivationJournal) Validate() error {
	if journal.Schema != WindowsActivationJournalSchema || !windowsTransactionIDPattern.MatchString(journal.TransactionID) {
		return errors.New("Windows activation journal schema or transaction identity is invalid")
	}
	if err := journal.Target.Validate(); err != nil {
		return fmt.Errorf("Windows activation target: %w", err)
	}
	if err := journal.Authority.Validate(); err != nil {
		return fmt.Errorf("Windows activation authority: %w", err)
	}
	authorityTarget, err := journal.Authority.CurrentDescriptor()
	if err != nil || authorityTarget != journal.Target {
		return errors.Join(err, errors.New("Windows activation target differs from authenticated authority"))
	}
	if err := journal.HighWaterAuthority.Validate(); err != nil {
		return fmt.Errorf("Windows activation high-water authority: %w", err)
	}
	if journal.HighWaterAuthority.InstallerBootstrapRootSHA256 != journal.Authority.InstallerBootstrapRootSHA256 ||
		journal.HighWaterAuthority.Channel != journal.Authority.Channel || journal.HighWaterAuthority.Arch != journal.Authority.Arch {
		return errors.New("Windows activation target and high water differ in fixed installer authority")
	}
	position := compareWindowsReleasePosition(journal.Authority, journal.HighWaterAuthority)
	if position > 0 || position == 0 && journal.Authority != journal.HighWaterAuthority {
		return errors.New("Windows activation target exceeds or equivocates with journaled high water")
	}
	if journal.Authority.BundleSecurityFloor < journal.HighWaterAuthority.MinimumSecurityFloor {
		return errors.New("Windows activation target cannot process journaled security-floor high water")
	}
	if journal.ExpectedPrior != nil {
		if err := journal.ExpectedPrior.Validate(); err != nil {
			return fmt.Errorf("Windows activation expected prior: %w", err)
		}
		if descriptorEqual(journal.ExpectedPrior, &journal.Target) {
			return errors.New("Windows activation target must differ from its expected prior")
		}
		if journal.SourceAuthority == nil {
			return errors.New("Windows activation expected prior has no authenticated source authority")
		}
		if err := journal.SourceAuthority.Validate(); err != nil {
			return fmt.Errorf("Windows activation source authority: %w", err)
		}
		sourceDescriptor, err := journal.SourceAuthority.CurrentDescriptor()
		if err != nil || sourceDescriptor != *journal.ExpectedPrior {
			return errors.Join(err, errors.New("Windows activation expected prior differs from source authority"))
		}
		if journal.SourceAuthority.InstallerBootstrapRootSHA256 != journal.Authority.InstallerBootstrapRootSHA256 ||
			journal.SourceAuthority.Channel != journal.Authority.Channel || journal.SourceAuthority.Arch != journal.Authority.Arch {
			return errors.New("Windows activation source and target differ in fixed installer authority")
		}
		if position := compareWindowsReleasePosition(*journal.SourceAuthority, journal.HighWaterAuthority); position > 0 || position == 0 && *journal.SourceAuthority != journal.HighWaterAuthority {
			return errors.New("Windows activation source exceeds or equivocates with journaled high water")
		}
		if err := validateWindowsAgentStateRollbackPair(*journal.SourceAuthority, journal.Authority); err != nil {
			return err
		}
	} else if journal.SourceAuthority != nil {
		return errors.New("first Windows activation cannot carry source authority")
	}
	switch journal.Operation {
	case WindowsOperationActivate:
		if journal.HighWaterAuthority != journal.Authority {
			return errors.New("Windows activation target must equal accepted high water")
		}
	case WindowsOperationRollback:
		if journal.SourceAuthority == nil {
			return errors.New("Windows rollback journal requires a source authority")
		}
	default:
		return fmt.Errorf("unsupported Windows activation operation %q", journal.Operation)
	}
	if !currentTemporaryPattern.MatchString(journal.CurrentTemporaryName) {
		return errors.New("Windows activation current temporary name is invalid")
	}
	if journal.SourceServiceRunning && (!journal.SourceServiceInstalled || !journal.SourceRuntimeGateOpen) {
		return errors.New("Windows activation source cannot run without an installed service and open gate")
	}
	if journal.DesiredServiceRunning && !journal.DesiredRuntimeGateOpen {
		return errors.New("Windows activation cannot request a running target with a closed gate")
	}
	switch journal.Phase {
	case WindowsActivationPrepared, WindowsActivationQuiesced, WindowsActivationSelected, WindowsActivationActivated:
		return nil
	default:
		return fmt.Errorf("unsupported Windows activation phase %q", journal.Phase)
	}
}

func (journal WindowsActivationJournal) WithPhase(phase WindowsActivationPhase) (WindowsActivationJournal, error) {
	next := cloneWindowsActivationJournal(journal)
	next.Phase = phase
	if err := validateWindowsActivationTransition(&journal, next); err != nil {
		return WindowsActivationJournal{}, err
	}
	return next, nil
}

func validateWindowsActivationTransition(current *WindowsActivationJournal, next WindowsActivationJournal) error {
	if err := next.Validate(); err != nil {
		return err
	}
	if current == nil {
		if next.Phase != WindowsActivationPrepared {
			return errors.New("new Windows activation journal must begin prepared")
		}
		return nil
	}
	if err := current.Validate(); err != nil {
		return fmt.Errorf("current Windows activation journal: %w", err)
	}
	currentIdentity := cloneWindowsActivationJournal(*current)
	nextIdentity := cloneWindowsActivationJournal(next)
	currentIdentity.Phase = ""
	nextIdentity.Phase = ""
	if !reflect.DeepEqual(currentIdentity, nextIdentity) {
		return errors.New("Windows activation journal fields other than phase are immutable")
	}
	if current.Phase == next.Phase {
		return nil
	}
	if current.Phase == WindowsActivationPrepared && next.Phase == WindowsActivationQuiesced ||
		current.Phase == WindowsActivationQuiesced && next.Phase == WindowsActivationSelected ||
		current.Phase == WindowsActivationSelected && next.Phase == WindowsActivationActivated {
		return nil
	}
	return fmt.Errorf("Windows activation phase cannot advance from %q to %q", current.Phase, next.Phase)
}

func windowsStateReflectsFinalizedActivation(state WindowsInstallState, journal WindowsActivationJournal) bool {
	if state.Validate() != nil || state.HighWater != journal.HighWaterAuthority || state.Active == nil || *state.Active != journal.Authority {
		return false
	}
	return sameAuthenticatedWindowsReleasePointer(state.Previous, journal.SourceAuthority)
}

// authorizeWindowsTransactionState is the portable authority decision used
// before any Windows selector, service, or runtime-gate mutation.
func authorizeWindowsTransactionState(state WindowsInstallState, journal WindowsActivationJournal) (alreadyFinalized bool, err error) {
	if err := state.Validate(); err != nil {
		return false, err
	}
	if err := journal.Validate(); err != nil {
		return false, err
	}
	if state.HighWater != journal.HighWaterAuthority {
		return false, errors.New("Windows transaction high water differs from durable install state")
	}
	if state.Active != nil && *state.Active == journal.Authority {
		if journal.Phase != WindowsActivationActivated || !sameAuthenticatedWindowsReleasePointer(state.Previous, journal.SourceAuthority) {
			return false, errors.New("Windows target state differs from an exact finalized transaction")
		}
		return true, nil
	}
	if !sameAuthenticatedWindowsReleasePointer(state.Active, journal.SourceAuthority) {
		return false, errors.New("Windows transaction source differs from the persisted active release")
	}
	var next WindowsInstallState
	switch journal.Operation {
	case WindowsOperationActivate:
		next, err = state.ActivateAccepted()
	case WindowsOperationRollback:
		if !sameAuthenticatedWindowsReleasePointer(state.Previous, &journal.Authority) {
			return false, errors.New("Windows rollback target differs from persisted previous release")
		}
		next, err = state.RollbackPrevious()
	default:
		return false, errors.New("Windows transaction operation is unsupported")
	}
	if err != nil || next.Active == nil || *next.Active != journal.Authority {
		return false, errors.Join(err, errors.New("Windows transaction cannot produce its journaled target state"))
	}
	return false, nil
}

func sameAuthenticatedWindowsReleasePointer(left, right *AuthenticatedWindowsRelease) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func MarshalWindowsActivationJournal(journal WindowsActivationJournal) ([]byte, error) {
	journal = cloneWindowsActivationJournal(journal)
	if err := journal.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(journal)
	if err != nil {
		return nil, fmt.Errorf("encode Windows activation journal: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) > maximumWindowsJournalBytes {
		return nil, errors.New("Windows activation journal exceeds its size bound")
	}
	return raw, nil
}

func ParseWindowsActivationJournal(raw []byte) (WindowsActivationJournal, error) {
	if len(raw) < 2 || len(raw) > maximumWindowsJournalBytes {
		return WindowsActivationJournal{}, errors.New("Windows activation journal is empty or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var journal WindowsActivationJournal
	if err := decoder.Decode(&journal); err != nil {
		return WindowsActivationJournal{}, fmt.Errorf("decode Windows activation journal: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return WindowsActivationJournal{}, errors.New("Windows activation journal contains multiple JSON values")
		}
		return WindowsActivationJournal{}, fmt.Errorf("decode trailing Windows activation data: %w", err)
	}
	canonical, err := MarshalWindowsActivationJournal(journal)
	if err != nil {
		return WindowsActivationJournal{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return WindowsActivationJournal{}, errors.New("Windows activation journal is not canonical")
	}
	return cloneWindowsActivationJournal(journal), nil
}

func cloneWindowsActivationJournal(journal WindowsActivationJournal) WindowsActivationJournal {
	journal.ExpectedPrior = cloneCurrentDescriptor(journal.ExpectedPrior)
	journal.SourceAuthority = cloneAuthenticatedWindowsRelease(journal.SourceAuthority)
	return journal
}
