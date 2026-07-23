//go:build windows

package windowsinstall

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"

	"mesh/internal/windowsbundle"
	"mesh/internal/windowssecurity"
)

const maximumWindowsAcceptedStageEntries = 128

// PublishAcceptedWindowsIntake completes inner bundle authority, commits exact
// high water, and recovers or publishes one deterministic intake-owned stage
// while holding the cross-process installer lock throughout the handoff.
func (store *ActivationJournalStore) PublishAcceptedWindowsIntake(layout *ReleaseLayout, intake VerifiedWindowsIntake) (stage *ReleaseStage, authority AuthenticatedWindowsRelease, state WindowsInstallState, returnErr error) {
	if store == nil || layout == nil {
		return nil, authority, state, errors.New("Windows accepted-intake publication requires a store and release layout")
	}
	if err := intake.Validate(); err != nil {
		return nil, authority, state, err
	}
	if layout.actorSID != windowssecurity.LocalSystemSID {
		return nil, authority, state, errors.New("production Windows accepted-intake publication requires the LocalSystem layout actor")
	}
	stageName, err := WindowsAcceptedStageName(intake)
	if err != nil {
		return nil, authority, state, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := store.acquireInstallerLock()
	if err != nil {
		return nil, authority, state, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	root, err := store.openRoot()
	if err != nil {
		return nil, authority, state, err
	}
	defer root.Close()
	if err := rejectWindowsCandidateAcceptanceDuringActivation(root); err != nil {
		return nil, authority, state, err
	}
	record, err := store.recoverWindowsAcceptedIntakeLocked(root)
	if err != nil || record == nil {
		return nil, authority, state, errors.Join(err, errors.New("Windows accepted-intake publication has no durable intake"))
	}
	persisted, err := record.Intake()
	if err != nil || !reflect.DeepEqual(persisted, intake) {
		return nil, authority, state, errors.Join(err, errors.New("Windows accepted-intake publication differs from the durable decision"))
	}
	liveName, pendingName := windowsArtifactCaptureNames(intake.Candidate.Artifact.SHA256)
	pending, err := readWindowsArtifactCapture(root, pendingName, intake.Candidate.Artifact)
	if err != nil || pending.found {
		return nil, authority, state, errors.Join(err, errors.New("Windows accepted-intake publication has pending artifact bytes"))
	}
	capture, err := readWindowsArtifactCapture(root, liveName, intake.Candidate.Artifact)
	if err != nil || !capture.found || !capture.complete {
		return nil, authority, state, errors.Join(err, errors.New("Windows accepted-intake publication has no exact artifact capture"))
	}
	capturePath := filepath.Join(store.directory, liveName)
	raw, err := readAuthenticatedWindowsCandidate(capturePath, windowssecurity.LocalSystemSID)
	if err != nil {
		return nil, authority, state, err
	}
	expanded, err := windowsbundle.InspectCandidateArchive(raw)
	if err != nil {
		return nil, authority, state, err
	}
	authority, state, err = store.commitAcceptedWindowsAuthorityLocked(root, intake, expanded.Inspection)
	if err != nil {
		return nil, AuthenticatedWindowsRelease{}, WindowsInstallState{}, err
	}
	installedID, err := WindowsCandidateInstalledID(intake.Candidate)
	if err != nil || installedID != authority.InstalledID {
		return nil, AuthenticatedWindowsRelease{}, WindowsInstallState{}, errors.Join(err, errors.New("Windows accepted-intake stage identity differs from completed authority"))
	}
	if recovered, resumeErr := layout.ResumeAuthenticatedStage(authority, stageName); resumeErr == nil {
		stage = recovered
		if filepath.Base(stage.Path()) != authority.InstalledID {
			if err := stage.Publish(); err != nil {
				stage.Close()
				return nil, AuthenticatedWindowsRelease{}, WindowsInstallState{}, err
			}
		}
		return stage, authority, state, nil
	}
	stage, err = layout.resetAndCreateAcceptedStage(authority, stageName)
	if err != nil {
		return nil, AuthenticatedWindowsRelease{}, WindowsInstallState{}, err
	}
	owned := true
	defer func() {
		if returnErr != nil && owned {
			returnErr = errors.Join(returnErr, stage.Close())
		}
	}()
	stagedInspection, err := stage.StageAuthenticatedArtifact(capturePath)
	if err != nil || !reflect.DeepEqual(stagedInspection, expanded.Inspection) {
		return nil, AuthenticatedWindowsRelease{}, WindowsInstallState{}, errors.Join(err, errors.New("Windows accepted-intake stage differs from its captured inspection"))
	}
	if err := stage.Publish(); err != nil {
		return nil, AuthenticatedWindowsRelease{}, WindowsInstallState{}, err
	}
	owned = false
	return stage, authority, state, nil
}

func (layout *ReleaseLayout) resetAndCreateAcceptedStage(authority AuthenticatedWindowsRelease, stageName string) (*ReleaseStage, error) {
	target, err := authority.CurrentDescriptor()
	if err != nil {
		return nil, err
	}
	if !releaseStageNamePattern.MatchString(stageName) || !strings.HasPrefix(stageName, ".stage-"+target.InstalledID+"-") {
		return nil, errors.New("Windows accepted stage name differs from its authority")
	}
	layout.mu.Lock()
	defer layout.mu.Unlock()
	if err := layout.validateOpenLocked(); err != nil {
		return nil, err
	}
	if published, err := layout.releaseDirectoryExistsLocked(target.InstalledID); err != nil {
		return nil, err
	} else if published {
		return nil, errors.New("Windows published release exists but could not be authenticated for recovery")
	}
	if exists, err := layout.releaseDirectoryExistsLocked(stageName); err != nil {
		return nil, err
	} else if exists {
		if err := layout.removeAcceptedStageLocked(stageName); err != nil {
			return nil, err
		}
	}
	stage, err := layout.createNamedAcceptedStageLocked(target, stageName)
	if err != nil {
		return nil, err
	}
	copy := authority
	stage.authority = &copy
	return stage, nil
}

func (layout *ReleaseLayout) createNamedAcceptedStageLocked(target CurrentDescriptor, name string) (*ReleaseStage, error) {
	relative := filepath.Join("releases", name)
	if err := layout.root.Mkdir(relative, 0o700); err != nil {
		return nil, fmt.Errorf("create deterministic Windows release stage: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = layout.root.Remove(relative)
		}
	}()
	visible, err := layout.root.Lstat(relative)
	if err != nil || visible.Mode()&os.ModeSymlink != 0 || !visible.IsDir() {
		return nil, errors.New("created deterministic Windows release stage is not a real directory")
	}
	directory, err := layout.root.Open(relative)
	if err != nil {
		return nil, err
	}
	opened, statErr := directory.Stat()
	if statErr != nil || !sameStableWindowsFile(visible, opened) {
		directory.Close()
		return nil, errors.New("deterministic Windows release stage changed while opening")
	}
	protectErr := windowssecurity.ProtectPrivateFileForActor(directory, windowssecurity.Directory, layout.actorSID)
	closeErr := directory.Close()
	if protectErr != nil || closeErr != nil {
		return nil, errors.Join(protectErr, closeErr)
	}
	stagePath := filepath.Join(layout.releasesPath, name)
	root, identity, err := openNoReparseRoot(stagePath)
	if err != nil || !os.SameFile(visible, identity) {
		if root != nil {
			root.Close()
		}
		return nil, errors.Join(err, errors.New("deterministic Windows release-stage path changed after protection"))
	}
	if err := inspectRootDirectory(root, identity, layout.actorSID); err != nil {
		root.Close()
		return nil, err
	}
	cleanup = false
	return &ReleaseStage{
		layout: layout, target: target, name: name, path: stagePath,
		root: root, identity: identity,
	}, nil
}

func (layout *ReleaseLayout) removeAcceptedStageLocked(stageName string) error {
	root, identity, err := layout.openReleaseDirectoryLocked(stageName)
	if err != nil {
		return err
	}
	type entrySnapshot struct {
		name string
		info os.FileInfo
		dir  bool
	}
	var files, directories []entrySnapshot
	entryCount := 0
	walkErr := fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." {
			return nil
		}
		entryCount++
		if entryCount > maximumWindowsAcceptedStageEntries || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "../") || strings.ContainsAny(name, `\:`) {
			return errors.New("interrupted Windows accepted stage exceeds its safe topology")
		}
		before, err := root.Lstat(name)
		if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() && !before.Mode().IsRegular() {
			return errors.Join(err, fmt.Errorf("interrupted Windows accepted-stage entry %q is unsupported", name))
		}
		file, err := root.Open(name)
		if err != nil {
			return err
		}
		opened, statErr := file.Stat()
		if statErr != nil || !sameStableWindowsFile(before, opened) {
			file.Close()
			return errors.New("interrupted Windows accepted-stage entry changed while opening")
		}
		kind := windowssecurity.RegularFile
		if before.IsDir() {
			kind = windowssecurity.Directory
		}
		inspectErr := windowssecurity.InspectPrivateFileForActor(file, kind, layout.actorSID)
		if !before.IsDir() && inspectErr == nil {
			inspectErr = windowssecurity.InspectPrivateFileSingleLinkForActor(file, kind, layout.actorSID)
		}
		closeErr := file.Close()
		if inspectErr != nil || closeErr != nil {
			return errors.Join(inspectErr, closeErr)
		}
		snapshot := entrySnapshot{name: name, info: opened, dir: before.IsDir()}
		if snapshot.dir {
			directories = append(directories, snapshot)
		} else {
			files = append(files, snapshot)
		}
		return nil
	})
	if walkErr != nil {
		root.Close()
		return walkErr
	}
	for _, snapshot := range files {
		visible, err := root.Lstat(snapshot.name)
		if err != nil || !sameStableWindowsFile(snapshot.info, visible) || visible.Mode()&os.ModeSymlink != 0 || !visible.Mode().IsRegular() {
			root.Close()
			return errors.Join(err, errors.New("interrupted Windows accepted-stage file changed before removal"))
		}
		if err := root.Chmod(snapshot.name, 0o600); err != nil {
			root.Close()
			return err
		}
		if err := root.Remove(snapshot.name); err != nil {
			root.Close()
			return err
		}
	}
	for index := len(directories) - 1; index >= 0; index-- {
		snapshot := directories[index]
		visible, err := root.Lstat(snapshot.name)
		if err != nil || !os.SameFile(snapshot.info, visible) || visible.Mode()&os.ModeSymlink != 0 || !visible.IsDir() {
			root.Close()
			return errors.Join(err, errors.New("interrupted Windows accepted-stage directory changed before removal"))
		}
		if err := root.Chmod(snapshot.name, 0o700); err != nil {
			root.Close()
			return err
		}
		if err := root.Remove(snapshot.name); err != nil {
			root.Close()
			return err
		}
	}
	if err := root.Close(); err != nil {
		return err
	}
	relative := filepath.Join("releases", stageName)
	visible, err := layout.root.Lstat(relative)
	if err != nil || !os.SameFile(identity, visible) || visible.Mode()&os.ModeSymlink != 0 || !visible.IsDir() {
		return errors.Join(err, errors.New("interrupted Windows accepted-stage root changed before removal"))
	}
	if err := layout.root.Chmod(relative, 0o700); err != nil {
		return err
	}
	if err := layout.root.Remove(relative); err != nil {
		return err
	}
	if _, err := layout.root.Lstat(relative); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(err, errors.New("interrupted Windows accepted stage remains visible"))
	}
	return nil
}
