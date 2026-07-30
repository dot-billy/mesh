package darwininstall

import "errors"

type launchdPlistRemovalOperations interface {
	InspectLive() (launchdPlistFileState, error)
	InspectPending() (launchdPlistFileState, error)
	RemoveLive() error
	SyncDirectory() error
}

// removeLaunchdPlist removes only the complete authenticated live plist.
// Absence is an idempotent response-loss result. Recovery or replaceable
// objects are left untouched for explicit operator investigation.
func removeLaunchdPlist(operations launchdPlistRemovalOperations) error {
	if operations == nil {
		return errors.New("Darwin launchd plist removal operations are required")
	}
	live, err := operations.InspectLive()
	if err != nil {
		return err
	}
	pending, err := operations.InspectPending()
	if err != nil {
		return err
	}
	if pending != launchdPlistAbsent {
		return errors.New("Darwin launchd plist removal refuses a pending object")
	}
	switch live {
	case launchdPlistAbsent:
	case launchdPlistComplete:
		if err := operations.RemoveLive(); err != nil {
			return err
		}
	default:
		return errors.New("Darwin launchd plist removal refuses non-authenticated live content")
	}
	if err := operations.SyncDirectory(); err != nil {
		return err
	}
	live, err = operations.InspectLive()
	if err != nil {
		return err
	}
	pending, err = operations.InspectPending()
	if err != nil {
		return err
	}
	if live != launchdPlistAbsent || pending != launchdPlistAbsent {
		return errors.New("Darwin launchd plist remains after removal")
	}
	return nil
}
