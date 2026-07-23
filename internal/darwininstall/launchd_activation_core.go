package darwininstall

import "errors"

type launchdActivationOperations interface {
	InspectRuntimeGate() (bool, error)
	CloseRuntimeGate() error
	BootoutService() error
	SwitchCurrent() error
	PublishPlist() error
	BootstrapService() error
	OpenRuntimeGate() error
	InspectTarget() error
}

type installerJournalBoundOperations interface {
	ValidateInstallerJournal(InstallerJournal) error
}

// activateLaunchdRelease applies the fail-closed native activation order for
// one journal-bound target. restoreRuntimeGate is captured before the first
// mutation and must be durable transaction identity, never a restart-time
// observation. Every operation must be exact and idempotent for recovery.
func activateLaunchdRelease(operations launchdActivationOperations, restoreRuntimeGate bool) error {
	if operations == nil {
		return errors.New("Darwin launchd activation operations are required")
	}
	gateOpen, err := operations.InspectRuntimeGate()
	if err != nil {
		return err
	}
	if gateOpen {
		if err := operations.CloseRuntimeGate(); err != nil {
			return err
		}
	}
	gateOpen, err = operations.InspectRuntimeGate()
	if err != nil {
		return err
	}
	if gateOpen {
		return errors.New("Darwin runtime gate remains open before launchd bootout")
	}
	// BootoutService is an idempotent proof operation, not a best-effort stop:
	// it may return only after one successful launchd removal. An absent service
	// is first bootstrapped from the exact gate-closed release plist so that the
	// subsequent successful bootout is authoritative without parsing launchctl
	// diagnostic output.
	if err := operations.BootoutService(); err != nil {
		return err
	}
	if err := operations.SwitchCurrent(); err != nil {
		return err
	}
	if err := operations.PublishPlist(); err != nil {
		return err
	}
	// The preceding bootout proved absence, so a successful bootstrap proves
	// that this exact published plist is loaded. Recovery always repeats this
	// sequence instead of consulting launchctl's explicitly unstable print
	// format.
	if err := operations.BootstrapService(); err != nil {
		return err
	}
	gateOpen, err = operations.InspectRuntimeGate()
	if err != nil {
		return err
	}
	if restoreRuntimeGate && !gateOpen {
		if err := operations.OpenRuntimeGate(); err != nil {
			return err
		}
	}
	return proveLaunchdActivation(operations, restoreRuntimeGate)
}

func proveLaunchdActivation(operations launchdActivationOperations, wantGateOpen bool) error {
	if err := operations.InspectTarget(); err != nil {
		return err
	}
	gateOpen, err := operations.InspectRuntimeGate()
	if err != nil {
		return err
	}
	if gateOpen != wantGateOpen {
		return errors.New("Darwin runtime gate differs from its journaled pre-activation intent")
	}
	return nil
}
