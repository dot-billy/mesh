package darwininstall

import "errors"

type launchdPlistFileState uint8

const (
	launchdPlistAbsent launchdPlistFileState = iota
	launchdPlistReplaceable
	launchdPlistComplete
)

type launchdPlistOperations interface {
	InspectLive() (launchdPlistFileState, error)
	InspectPending() (launchdPlistFileState, error)
	CreatePending() error
	SyncPending() error
	FinalizePending() error
	RemovePending() error
	PublishPending() error
	SyncDirectory() error
}

// publishLaunchdPlist durably replaces only a structurally trusted live plist
// with the exact authenticated release bytes. A pending object is recoverable
// only when the platform adapter proves it is either the complete target or a
// safe prefix created with the private recovery mode.
func publishLaunchdPlist(operations launchdPlistOperations) error {
	if operations == nil {
		return errors.New("Darwin launchd plist operations are required")
	}
	live, err := operations.InspectLive()
	if err != nil {
		return err
	}
	pending, err := operations.InspectPending()
	if err != nil {
		return err
	}
	if live == launchdPlistComplete {
		if pending != launchdPlistAbsent {
			if err := operations.RemovePending(); err != nil {
				return err
			}
		}
		if err := operations.SyncDirectory(); err != nil {
			return err
		}
		return proveLaunchdPlist(operations)
	}
	if pending == launchdPlistReplaceable {
		if err := operations.RemovePending(); err != nil {
			return err
		}
		if err := operations.SyncDirectory(); err != nil {
			return err
		}
		pending = launchdPlistAbsent
	}
	if pending == launchdPlistAbsent {
		if err := operations.CreatePending(); err != nil {
			return err
		}
	}
	if err := operations.SyncPending(); err != nil {
		return err
	}
	if err := operations.FinalizePending(); err != nil {
		return err
	}
	if err := operations.SyncPending(); err != nil {
		return err
	}
	pending, err = operations.InspectPending()
	if err != nil {
		return err
	}
	if pending != launchdPlistComplete {
		return errors.New("Darwin launchd pending plist is not complete before publication")
	}
	if err := operations.PublishPending(); err != nil {
		return err
	}
	if err := operations.SyncDirectory(); err != nil {
		return err
	}
	return proveLaunchdPlist(operations)
}

func proveLaunchdPlist(operations launchdPlistOperations) error {
	live, err := operations.InspectLive()
	if err != nil {
		return err
	}
	pending, err := operations.InspectPending()
	if err != nil {
		return err
	}
	if live != launchdPlistComplete || pending != launchdPlistAbsent {
		return errors.New("Darwin launchd plist publication is not exact and durable")
	}
	return nil
}
