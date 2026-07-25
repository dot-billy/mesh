package darwininstall

import "errors"

type releaseDirectoryState uint8

const (
	releaseDirectoryAbsent releaseDirectoryState = iota
	releaseDirectoryPrivate
	releaseDirectoryFinalized
)

type releasePublicationOperations interface {
	InspectStage() (releaseDirectoryState, error)
	InspectPublished() (releaseDirectoryState, error)
	SyncStage() error
	PublishNoReplace() error
	SyncReleases() error
}

// publishFinalizedRelease implements the crash-resumable durability ordering
// for one authenticated immutable release. The platform adapter must bind both
// names to the same already-anchored directory and make publication no-replace.
func publishFinalizedRelease(operations releasePublicationOperations) error {
	if operations == nil {
		return errors.New("Darwin release-publication operations are required")
	}
	stage, err := operations.InspectStage()
	if err != nil {
		return err
	}
	published, err := operations.InspectPublished()
	if err != nil {
		return err
	}
	if stage == releaseDirectoryAbsent && published == releaseDirectoryFinalized {
		if err := operations.SyncReleases(); err != nil {
			return err
		}
		return provePublishedRelease(operations)
	}
	if stage != releaseDirectoryFinalized || published != releaseDirectoryAbsent {
		return errors.New("Darwin release publication is not in one exact resumable state")
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
	return provePublishedRelease(operations)
}

func provePublishedRelease(operations releasePublicationOperations) error {
	stage, err := operations.InspectStage()
	if err != nil {
		return err
	}
	published, err := operations.InspectPublished()
	if err != nil {
		return err
	}
	if stage != releaseDirectoryAbsent || published != releaseDirectoryFinalized {
		return errors.New("Darwin release publication did not produce one exact immutable directory")
	}
	return nil
}
