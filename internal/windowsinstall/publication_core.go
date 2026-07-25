package windowsinstall

import "errors"

type windowsReleaseDirectoryState uint8

const (
	windowsReleaseDirectoryAbsent windowsReleaseDirectoryState = iota
	windowsReleaseDirectoryPrivate
	windowsReleaseDirectoryFinalized
)

type windowsReleasePublicationOperations interface {
	InspectStage() (windowsReleaseDirectoryState, error)
	InspectPublished() (windowsReleaseDirectoryState, error)
	SyncStage() error
	PublishNoReplace() error
	SyncReleases() error
}

// publishWindowsFinalizedRelease provides one crash-resumable publication
// ordering for an authenticated immutable release tree. PublishNoReplace must
// use a write-through Windows rename without replacement semantics.
func publishWindowsFinalizedRelease(operations windowsReleasePublicationOperations) error {
	if operations == nil {
		return errors.New("Windows release-publication operations are required")
	}
	stage, err := operations.InspectStage()
	if err != nil {
		return err
	}
	published, err := operations.InspectPublished()
	if err != nil {
		return err
	}
	if stage == windowsReleaseDirectoryAbsent && published == windowsReleaseDirectoryFinalized {
		if err := operations.SyncReleases(); err != nil {
			return err
		}
		return proveWindowsPublishedRelease(operations)
	}
	if stage != windowsReleaseDirectoryFinalized || published != windowsReleaseDirectoryAbsent {
		return errors.New("Windows release publication is not in one exact resumable state")
	}
	if err := operations.SyncStage(); err != nil {
		return err
	}
	if err := operations.PublishNoReplace(); err != nil {
		return err
	}
	if err := operations.SyncReleases(); err != nil {
		return err
	}
	return proveWindowsPublishedRelease(operations)
}

func proveWindowsPublishedRelease(operations windowsReleasePublicationOperations) error {
	stage, err := operations.InspectStage()
	if err != nil {
		return err
	}
	published, err := operations.InspectPublished()
	if err != nil {
		return err
	}
	if stage != windowsReleaseDirectoryAbsent || published != windowsReleaseDirectoryFinalized {
		return errors.New("Windows release publication did not produce one exact immutable directory")
	}
	return nil
}
