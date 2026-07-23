//go:build windows

package windowsinstall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"mesh/internal/onlinerelease"
	releasetrust "mesh/internal/release"
	"mesh/internal/windowssecurity"

	"golang.org/x/sys/windows"
)

type windowsArtifactFetcher interface {
	FetchArtifact(context.Context, releasetrust.Artifact, *os.File) error
}

type windowsArtifactCaptureSnapshot struct {
	found    bool
	complete bool
	info     os.FileInfo
}

// FetchProductionWindowsArtifact re-verifies the durable signed intake using
// compiled trust, then streams only its selected artifact through the bounded
// no-redirect client into one protected restart-recoverable capture.
func (store *ActivationJournalStore) FetchProductionWindowsArtifact(ctx context.Context, intake VerifiedWindowsIntake) (string, error) {
	if ctx == nil {
		return "", errors.New("Windows artifact fetch requires a context")
	}
	persisted, found, err := store.LoadProductionWindowsIntake()
	if err != nil || !found || !reflect.DeepEqual(persisted, intake) {
		return "", errors.Join(err, errors.New("Windows artifact fetch requires the exact reverified accepted intake"))
	}
	return store.fetchWindowsArtifactUsing(ctx, intake, onlinerelease.NewClient())
}

func (store *ActivationJournalStore) fetchWindowsArtifactUsing(ctx context.Context, intake VerifiedWindowsIntake, fetcher windowsArtifactFetcher) (result string, returnErr error) {
	if store == nil || ctx == nil || fetcher == nil {
		return "", errors.New("Windows artifact capture requires a store, context, and bounded fetcher")
	}
	if err := intake.Validate(); err != nil {
		return "", err
	}
	liveName, pendingName := windowsArtifactCaptureNames(intake.Candidate.Artifact.SHA256)
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := store.acquireInstallerLock()
	if err != nil {
		return "", err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	root, err := store.openRoot()
	if err != nil {
		return "", err
	}
	defer root.Close()
	if err := rejectWindowsCandidateAcceptanceDuringActivation(root); err != nil {
		return "", err
	}
	record, err := store.recoverWindowsAcceptedIntakeLocked(root)
	if err != nil || record == nil {
		return "", errors.Join(err, errors.New("Windows artifact capture has no durable accepted intake"))
	}
	persisted, err := record.Intake()
	if err != nil || !reflect.DeepEqual(persisted, intake) {
		return "", errors.Join(err, errors.New("Windows artifact capture intake differs from the durable decision"))
	}
	live, err := readWindowsArtifactCapture(root, liveName, intake.Candidate.Artifact)
	if err != nil {
		return "", err
	}
	pending, err := readWindowsArtifactCapture(root, pendingName, intake.Candidate.Artifact)
	if err != nil {
		return "", err
	}
	if live.found {
		if pending.found || !live.complete {
			return "", errors.New("Windows artifact capture has ambiguous live and pending objects")
		}
		return filepath.Join(store.directory, liveName), nil
	}
	if pending.found {
		if pending.complete {
			if err := publishWindowsArtifactCapture(store.directory, pendingName, liveName); err != nil {
				return "", err
			}
			confirmed, err := readWindowsArtifactCapture(root, liveName, intake.Candidate.Artifact)
			if err != nil || !confirmed.found || !confirmed.complete {
				return "", errors.Join(err, errors.New("recovered Windows artifact capture differs after publication"))
			}
			return filepath.Join(store.directory, liveName), nil
		}
		stable, err := readWindowsArtifactCapture(root, pendingName, intake.Candidate.Artifact)
		if err != nil || !sameWindowsArtifactCaptureSnapshot(pending, stable) {
			return "", errors.Join(err, errors.New("partial Windows artifact capture changed during recovery"))
		}
		if err := root.Remove(pendingName); err != nil {
			return "", err
		}
	}
	file, err := root.OpenFile(pendingName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	if err := windowssecurity.ProtectPrivateFileForActor(file, windowssecurity.RegularFile, windowssecurity.LocalSystemSID); err != nil {
		closeErr := file.Close()
		removeErr := root.Remove(pendingName)
		return "", errors.Join(err, closeErr, removeErr)
	}
	fetchErr := fetcher.FetchArtifact(ctx, intake.Candidate.Artifact, file)
	syncErr := file.Sync()
	closeErr := file.Close()
	if fetchErr != nil || syncErr != nil || closeErr != nil {
		return "", errors.Join(fetchErr, syncErr, closeErr)
	}
	pending, err = readWindowsArtifactCapture(root, pendingName, intake.Candidate.Artifact)
	if err != nil || !pending.found || !pending.complete {
		return "", errors.Join(err, errors.New("Windows artifact capture differs after bounded download"))
	}
	if err := publishWindowsArtifactCapture(store.directory, pendingName, liveName); err != nil {
		return "", err
	}
	live, err = readWindowsArtifactCapture(root, liveName, intake.Candidate.Artifact)
	if err != nil || !live.found || !live.complete {
		return "", errors.Join(err, errors.New("published Windows artifact capture differs from signed authority"))
	}
	return filepath.Join(store.directory, liveName), nil
}

func windowsArtifactCaptureNames(digest string) (string, string) {
	live := "artifact-" + digest + ".tar"
	return live, "." + live + ".new"
}

func readWindowsArtifactCapture(root *os.Root, name string, expected releasetrust.Artifact) (windowsArtifactCaptureSnapshot, error) {
	var result windowsArtifactCaptureSnapshot
	before, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > expected.Size {
		return result, errors.Join(err, errors.New("Windows artifact capture is not one bounded real regular file"))
	}
	file, err := root.Open(name)
	if err != nil {
		return result, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !sameStableWindowsFile(before, opened) {
		return result, errors.New("Windows artifact capture changed while opening")
	}
	if err := windowssecurity.InspectPrivateFileSingleLinkForActor(file, windowssecurity.RegularFile, windowssecurity.LocalSystemSID); err != nil {
		return result, err
	}
	complete := opened.Size() == expected.Size
	if complete {
		if err := releasetrust.VerifyArtifact(file, expected); err != nil {
			return result, fmt.Errorf("authenticate Windows artifact capture: %w", err)
		}
	}
	after, statErr := file.Stat()
	visible, pathErr := root.Lstat(name)
	if statErr != nil || pathErr != nil || !sameStableWindowsFile(opened, after) || !sameStableWindowsFile(opened, visible) {
		return result, errors.New("Windows artifact capture changed during readback")
	}
	return windowsArtifactCaptureSnapshot{found: true, complete: complete, info: visible}, nil
}

func publishWindowsArtifactCapture(directory, pendingName, liveName string) error {
	from, err := windows.UTF16PtrFromString(filepath.Join(directory, pendingName))
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(filepath.Join(directory, liveName))
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return fmt.Errorf("publish Windows artifact capture without replacement: %w", err)
	}
	return nil
}

func discardWindowsArtifactCaptureLocked(root *os.Root, expected releasetrust.Artifact) error {
	liveName, pendingName := windowsArtifactCaptureNames(expected.SHA256)
	pending, err := readWindowsArtifactCapture(root, pendingName, expected)
	if err != nil || pending.found {
		return errors.Join(err, errors.New("Windows artifact capture cannot finalize with pending bytes"))
	}
	live, err := readWindowsArtifactCapture(root, liveName, expected)
	if err != nil || !live.found {
		return err
	}
	stable, err := readWindowsArtifactCapture(root, liveName, expected)
	if err != nil || !sameWindowsArtifactCaptureSnapshot(live, stable) {
		return errors.Join(err, errors.New("Windows artifact capture changed before discard"))
	}
	if err := root.Remove(liveName); err != nil {
		return err
	}
	remaining, err := readWindowsArtifactCapture(root, liveName, expected)
	if err != nil || remaining.found {
		return errors.Join(err, errors.New("discarded Windows artifact capture remains visible"))
	}
	return nil
}

func sameWindowsArtifactCaptureSnapshot(left, right windowsArtifactCaptureSnapshot) bool {
	if left.found != right.found || left.complete != right.complete {
		return false
	}
	if !left.found {
		return true
	}
	return sameStableWindowsFile(left.info, right.info)
}
