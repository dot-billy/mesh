//go:build darwin

package darwininstall

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"mesh/internal/nodeagent"

	"golang.org/x/sys/unix"
)

// StageAcceptedIntake resets the deterministic intake-owned stage, expands
// the exact immutable capture into it, and completes inner authority. A crash
// at any extraction boundary can repeat this method without guessing which
// random private directory belonged to the accepted metadata.
func (store *InstallerJournalStore) StageAcceptedIntake(layout *ReleaseLayout, intake VerifiedDarwinIntake) (stage *ReleaseStage, authority AuthenticatedDarwinRelease, returnErr error) {
	if store == nil || layout == nil {
		return nil, authority, errors.New("Darwin accepted-intake staging requires a store and release layout")
	}
	if err := validateVerifiedDarwinCandidate(intake.Candidate); err != nil || !darwinDigestPattern.MatchString(intake.InstallerBootstrapRootSHA256) {
		return nil, authority, errors.Join(err, errors.New("verified Darwin intake is invalid"))
	}
	installedID := DarwinCandidateInstalledID(intake.Candidate)
	stageName, err := darwinAcceptedStageName(intake.Candidate)
	if err != nil {
		return nil, authority, err
	}
	lock, err := store.AcquireLock()
	if err != nil {
		return nil, authority, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	if _, found, err := lock.Load(); err != nil {
		return nil, authority, err
	} else if found {
		return nil, authority, errors.New("Darwin accepted intake cannot stage during an active installer journal")
	}
	record, found, err := lock.LoadIntakeRecord()
	if err != nil {
		return nil, authority, err
	}
	persisted, intakeErr := record.Intake()
	if !found || intakeErr != nil || persisted != intake {
		return nil, authority, errors.Join(intakeErr, errors.New("Darwin staging requires the exact active accepted intake"))
	}
	liveName, _ := darwinArtifactCaptureName(intake.Candidate.Artifact.SHA256)
	pendingName, _ := darwinArtifactCapturePendingName(intake.Candidate.Artifact.SHA256)
	capture := &DarwinArtifactCapture{
		lock: lock, expected: intake.Candidate.Artifact, liveName: liveName, pendingName: pendingName,
	}
	live, err := capture.read(liveName, darwinArtifactCaptureLiveMode, true)
	if err != nil || !live.found || live.rawSHA != intake.Candidate.Artifact.SHA256 {
		return nil, authority, errors.Join(err, errors.New("Darwin accepted intake has no exact finalized artifact capture"))
	}
	if _, pending, err := capture.inspectPending(); err != nil || pending.found {
		return nil, authority, errors.Join(err, errors.New("Darwin accepted intake has an ambiguous pending artifact capture"))
	}
	stage, err = layout.resetAndCreateAcceptedStage(installedID, stageName)
	if err != nil {
		return nil, authority, err
	}
	createdStage := stage
	owned := true
	defer func() {
		if returnErr != nil && owned {
			returnErr = errors.Join(returnErr, createdStage.Close())
		}
	}()
	inspection, err := stage.StageAuthenticatedArtifact(filepath.Join(store.directory, liveName))
	if err != nil {
		return nil, authority, err
	}
	authority, err = intake.Complete(inspection)
	if err != nil || authority.InstalledID != installedID {
		return nil, AuthenticatedDarwinRelease{}, errors.Join(err, errors.New("staged Darwin intake differs from its derived authority"))
	}
	confirmed, err := capture.read(liveName, darwinArtifactCaptureLiveMode, true)
	if err != nil || !sameDarwinArtifactCaptureSnapshot(live, confirmed) {
		return nil, AuthenticatedDarwinRelease{}, errors.Join(err, errors.New("Darwin artifact capture changed during accepted-intake staging"))
	}
	owned = false
	return stage, authority, nil
}

func (layout *ReleaseLayout) resetAndCreateAcceptedStage(installedID, stageName string) (*ReleaseStage, error) {
	if layout == nil || !darwinInstalledIDPattern.MatchString(installedID) || !darwinStageNamePattern.MatchString(stageName) ||
		!strings.HasPrefix(stageName, ".stage-"+installedID+"-") {
		return nil, errors.New("Darwin accepted-intake stage identity is invalid")
	}
	layout.mu.Lock()
	defer layout.mu.Unlock()
	if err := layout.validateAnchorsLocked(); err != nil {
		return nil, err
	}
	if err := layout.removeAcceptedStageLocked(stageName); err != nil {
		return nil, err
	}
	if err := unix.Mkdirat(layout.releasesFD, stageName, uint32(darwinPrivateReleaseStageMode)); err != nil {
		return nil, err
	}
	path := filepath.Join(layout.releasesPath, stageName)
	cleanup := func(cause error, directory *os.File) error {
		var closeErr error
		if directory != nil {
			closeErr = directory.Close()
		}
		return errors.Join(cause, closeErr, unix.Unlinkat(layout.releasesFD, stageName, unix.AT_REMOVEDIR), layout.releases.Sync())
	}
	fd, err := unix.Openat(layout.releasesFD, stageName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, 0)
	if err != nil {
		return nil, cleanup(err, nil)
	}
	directory := os.NewFile(uintptr(fd), path)
	if directory == nil {
		_ = unix.Close(fd)
		return nil, cleanup(errors.New("adopt Darwin accepted-intake stage descriptor"), nil)
	}
	if err := unix.Fchown(fd, 0, 0); err != nil {
		return nil, cleanup(err, directory)
	}
	if err := unix.Fchmod(fd, uint32(darwinPrivateReleaseStageMode)); err != nil {
		return nil, cleanup(err, directory)
	}
	if err := authenticateDarwinReleaseDirectory(path, layout.releasesFD, stageName, fd, darwinPrivateReleaseStageMode); err != nil {
		return nil, cleanup(err, directory)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, cleanup(err, directory)
	}
	if err := directory.Sync(); err != nil {
		return nil, cleanup(err, directory)
	}
	if err := layout.releases.Sync(); err != nil {
		return nil, cleanup(err, directory)
	}
	return &ReleaseStage{
		layout: layout, installedID: installedID, name: stageName, path: path,
		directory: directory, fd: fd, identity: darwinObjectIdentity(stat),
	}, nil
}

func (layout *ReleaseLayout) removeAcceptedStageLocked(stageName string) (returnErr error) {
	var visible unix.Stat_t
	if err := unix.Fstatat(layout.releasesFD, stageName, &visible, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return err
	}
	mode := uint16(visible.Mode & 0o7777)
	if mode != darwinPrivateReleaseStageMode && mode != darwinPublishedReleaseMode {
		return errors.New("existing Darwin accepted-intake stage has an unsupported mode")
	}
	if err := validateDarwinReleaseDirectoryStat(visible, mode); err != nil {
		return err
	}
	path := filepath.Join(layout.releasesPath, stageName)
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		return err
	}
	fd, err := unix.Openat(layout.releasesFD, stageName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), path)
	if directory == nil {
		_ = unix.Close(fd)
		return errors.New("adopt interrupted Darwin accepted-intake stage descriptor")
	}
	directoryOpen := true
	defer func() {
		if directoryOpen {
			returnErr = errors.Join(returnErr, directory.Close())
		}
	}()
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return err
	}
	if darwinObjectIdentity(visible) != darwinObjectIdentity(opened) {
		return errors.New("Darwin accepted-intake stage changed while opening for reset")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	rootOpen := true
	defer func() {
		if rootOpen {
			returnErr = errors.Join(returnErr, root.Close())
		}
	}()
	rootInfo, err := root.Stat(".")
	directoryInfo, directoryErr := directory.Stat()
	if err != nil || directoryErr != nil || !os.SameFile(rootInfo, directoryInfo) {
		return errors.Join(err, directoryErr, errors.New("Darwin accepted-intake reset root differs from its anchored descriptor"))
	}
	if err := root.Chmod(".", 0o700); err != nil {
		return err
	}
	var files, directories []string
	entryCount := 0
	if err := fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." {
			return nil
		}
		entryCount++
		if entryCount > maximumDarwinReleaseTreeEntries || filepath.Clean(name) != name || strings.HasPrefix(name, "../") || strings.Contains(name, `\`) {
			return errors.New("interrupted Darwin accepted-intake stage exceeds its safe topology")
		}
		if entry.IsDir() {
			directories = append(directories, name)
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errors.Join(err, fmt.Errorf("interrupted Darwin accepted-intake entry %q is not a regular file", name))
		}
		files = append(files, name)
		return nil
	}); err != nil {
		return err
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := root.Chmod(directories[index], 0o700); err != nil {
			return err
		}
	}
	for _, name := range files {
		if err := root.Remove(name); err != nil {
			return err
		}
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := root.Remove(directories[index]); err != nil {
			return err
		}
	}
	rootDirectory, err := root.Open(".")
	if err != nil {
		return err
	}
	syncErr := rootDirectory.Sync()
	closeErr := rootDirectory.Close()
	if syncErr != nil || closeErr != nil {
		return errors.Join(syncErr, closeErr)
	}
	if err := directory.Close(); err != nil {
		return err
	}
	directoryOpen = false
	if err := root.Close(); err != nil {
		return err
	}
	rootOpen = false
	if err := unix.Unlinkat(layout.releasesFD, stageName, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	if err := layout.releases.Sync(); err != nil {
		return err
	}
	if err := unix.Fstatat(layout.releasesFD, stageName, &visible, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		if err != nil {
			return err
		}
		return errors.New("reset Darwin accepted-intake stage remains visible")
	}
	return nil
}
