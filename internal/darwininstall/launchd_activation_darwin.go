//go:build darwin

package darwininstall

import (
	"errors"
	"reflect"
	"sync"
)

// LaunchdServiceController is the narrow native mutation boundary. Bootout is
// an idempotent proof of absence and Bootstrap is a proof of loading; neither
// may infer state from launchctl's diagnostic output.
type LaunchdServiceController interface {
	Bootout() error
	Bootstrap() error
}

func (activation *LaunchdActivation) ValidateInstallerJournal(journal InstallerJournal) error {
	if activation == nil {
		return errors.New("Darwin launchd activation is required")
	}
	activation.mu.Lock()
	defer activation.mu.Unlock()
	if err := activation.validateLocked(); err != nil {
		return err
	}
	activation.current.mu.Lock()
	defer activation.current.mu.Unlock()
	if journal.InstalledID != activation.current.target || journal.ExpectedPrior != activation.current.expectedPrior ||
		journal.CurrentTemporaryName != activation.current.temporaryName || !reflect.DeepEqual(journal.Inspection, activation.current.inspection) {
		return errors.New("Darwin launchd activation differs from the installer journal")
	}
	return nil
}

// LaunchdActivation binds one journal target to its runtime gate, current-link
// transaction, exact plist publication, and native launchd service controller.
type LaunchdActivation struct {
	mu sync.Mutex

	gate           *RuntimeGate
	current        *CurrentSwitch
	service        LaunchdServiceController
	plistDirectory string
	publisher      *LaunchdPlistPublisher
	closed         bool
}

func NewProductionLaunchdActivation(gate *RuntimeGate, current *CurrentSwitch, service LaunchdServiceController) (*LaunchdActivation, error) {
	return NewLaunchdActivation(gate, current, service, ProductionLaunchdDirectory)
}

// NewLaunchdActivation accepts a destination override only for the root-only
// native harness. It deliberately creates the plist publisher lazily because
// the journal's staged release is not published when Begin captures gate
// intent.
func NewLaunchdActivation(gate *RuntimeGate, current *CurrentSwitch, service LaunchdServiceController, plistDirectory string) (*LaunchdActivation, error) {
	if gate == nil || current == nil || current.layout == nil || service == nil {
		return nil, errors.New("Darwin launchd activation requires a gate, current switch, and service controller")
	}
	if !cleanDarwinInstallPath(plistDirectory) {
		return nil, errors.New("Darwin launchd activation plist directory is invalid")
	}
	return &LaunchdActivation{
		gate: gate, current: current, service: service, plistDirectory: plistDirectory,
	}, nil
}

func (activation *LaunchdActivation) InspectRuntimeGate() (bool, error) {
	activation.mu.Lock()
	defer activation.mu.Unlock()
	if err := activation.validateLocked(); err != nil {
		return false, err
	}
	return activation.gate.Inspect()
}

func (activation *LaunchdActivation) CloseRuntimeGate() error {
	activation.mu.Lock()
	defer activation.mu.Unlock()
	if err := activation.validateLocked(); err != nil {
		return err
	}
	return activation.gate.Close()
}

func (activation *LaunchdActivation) BootoutService() error {
	activation.mu.Lock()
	defer activation.mu.Unlock()
	if err := activation.validateLocked(); err != nil {
		return err
	}
	return activation.service.Bootout()
}

func (activation *LaunchdActivation) SwitchCurrent() error {
	activation.mu.Lock()
	defer activation.mu.Unlock()
	if err := activation.validateLocked(); err != nil {
		return err
	}
	return activation.current.Execute()
}

func (activation *LaunchdActivation) PublishPlist() error {
	activation.mu.Lock()
	defer activation.mu.Unlock()
	if err := activation.validateLocked(); err != nil {
		return err
	}
	if err := activation.ensurePublisherLocked(); err != nil {
		return err
	}
	return activation.publisher.Publish()
}

func (activation *LaunchdActivation) BootstrapService() error {
	activation.mu.Lock()
	defer activation.mu.Unlock()
	if err := activation.validateLocked(); err != nil {
		return err
	}
	return activation.service.Bootstrap()
}

func (activation *LaunchdActivation) OpenRuntimeGate() error {
	activation.mu.Lock()
	defer activation.mu.Unlock()
	if err := activation.validateLocked(); err != nil {
		return err
	}
	return activation.gate.Open()
}

func (activation *LaunchdActivation) InspectTarget() error {
	activation.mu.Lock()
	defer activation.mu.Unlock()
	if err := activation.validateLocked(); err != nil {
		return err
	}
	if err := activation.current.ProveSelected(); err != nil {
		return err
	}
	if err := activation.ensurePublisherLocked(); err != nil {
		return err
	}
	return activation.publisher.Inspect()
}

func (activation *LaunchdActivation) ensurePublisherLocked() error {
	if activation.publisher != nil {
		return nil
	}
	publisher, err := NewLaunchdPlistPublisher(
		activation.current.layout,
		activation.current.target,
		activation.current.inspection,
		activation.plistDirectory,
	)
	if err != nil {
		return err
	}
	activation.publisher = publisher
	return nil
}

func (activation *LaunchdActivation) validateLocked() error {
	if activation == nil || activation.closed || activation.gate == nil || activation.current == nil || activation.service == nil {
		return errors.New("Darwin launchd activation is closed or incomplete")
	}
	return nil
}

func (activation *LaunchdActivation) Close() error {
	if activation == nil {
		return nil
	}
	activation.mu.Lock()
	defer activation.mu.Unlock()
	if activation.closed {
		return nil
	}
	activation.closed = true
	if activation.publisher == nil {
		return nil
	}
	err := activation.publisher.Close()
	activation.publisher = nil
	return err
}
