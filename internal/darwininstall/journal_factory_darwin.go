//go:build darwin

package darwininstall

import (
	"errors"
	"reflect"
)

// NewInstallerJournalFor binds the already-finalized stage and the planned
// expected-prior current switch into the sole canonical initial journal.
func NewInstallerJournalFor(stage *ReleaseStage, current *CurrentSwitch, authority AuthenticatedDarwinRelease, restoreRuntimeGate bool) (InstallerJournal, error) {
	if stage == nil || current == nil || stage.layout == nil || current.layout == nil || stage.layout != current.layout {
		return InstallerJournal{}, errors.New("Darwin installer journal stage and current switch must share one release layout")
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	current.mu.Lock()
	defer current.mu.Unlock()
	if stage.closed || stage.directory == nil || !stage.staged || stage.installedID != current.target ||
		!reflect.DeepEqual(stage.inspection, current.inspection) {
		return InstallerJournal{}, errors.New("Darwin installer journal stage and current switch identity differ")
	}
	return NewInstallerJournal(
		stage.installedID, stage.name, current.expectedPrior, current.temporaryName, stage.inspection, authority, restoreRuntimeGate,
	)
}
