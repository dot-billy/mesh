//go:build darwin

package darwininstall

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"mesh/internal/buildinfo"
	"mesh/internal/installtrust"
	"mesh/internal/onlinerelease"
	releasetrust "mesh/internal/release"
)

type nativeDarwinArtifactFetcherFunc func(context.Context, releasetrust.Artifact, *os.File) error

func (fetch nativeDarwinArtifactFetcherFunc) FetchArtifact(ctx context.Context, artifact releasetrust.Artifact, destination *os.File) error {
	return fetch(ctx, artifact, destination)
}

type nativeLaunchdService struct {
	loaded    bool
	plistPath string
}

func (service *nativeLaunchdService) Bootout() error {
	service.loaded = false
	return nil
}

func (service *nativeLaunchdService) Bootstrap() error {
	if _, err := os.Lstat(service.plistPath); err != nil {
		return err
	}
	service.loaded = true
	return nil
}

func requireDarwinNativeInstallerTest(t *testing.T) {
	t.Helper()
	if os.Getenv("MESH_DARWIN_NATIVE_FAULT_TEST") != "1" {
		t.Skip("set MESH_DARWIN_NATIVE_FAULT_TEST=1 through the native harness")
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Fatal("native Darwin installer fault injection requires root:wheel")
	}
}

func writeNativeDarwinOfflineSnapshot(t *testing.T, parent string, bundle onlinerelease.Bundle, artifactPath string) string {
	t.Helper()
	directory := filepath.Join(parent, "offline-snapshot")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(directory, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	bundleRaw, err := onlinerelease.Encode(bundle)
	if err != nil {
		t.Fatal(err)
	}
	descriptorRaw, err := EncodeDarwinInstallSnapshotDescriptor(DarwinInstallSnapshotDescriptor{
		Schema: DarwinInstallSnapshotSchema, OnlineBundle: DarwinInstallSnapshotBundleFile, Artifact: DarwinInstallSnapshotArtifact,
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		DarwinInstallSnapshotFile: descriptorRaw, DarwinInstallSnapshotBundleFile: bundleRaw,
	} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, raw, 0o400); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	source, err := os.Open(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	destinationPath := filepath.Join(directory, DarwinInstallSnapshotArtifact)
	destination, err := os.OpenFile(destinationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		_ = source.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(destination, source)
	closeErr := errors.Join(destination.Close(), source.Close())
	if err := errors.Join(copyErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(destinationPath, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(destinationPath, 0o400); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestDarwinNativeInstallerRuntimeGateLifecycle(t *testing.T) {
	requireDarwinNativeInstallerTest(t)
	parent, err := os.MkdirTemp("/private/var/db", ".mesh-native-installer-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(parent, 0, 0); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Chmod(filepath.Join(parent, "state"), 0o700)
		if err := os.RemoveAll(parent); err != nil {
			t.Errorf("remove exact Darwin installer fault directory: %v", err)
		}
	}()

	stateDirectory := filepath.Join(parent, "state")
	if err := EnsureStateDirectory(stateDirectory); err != nil {
		t.Fatal(err)
	}
	gate, err := NewRuntimeGate(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	assertDarwinRuntimeGateState(t, gate, false)
	if err := gate.Open(); err != nil {
		t.Fatal(err)
	}
	assertDarwinRuntimeGateState(t, gate, true)
	if err := gate.Open(); err != nil {
		t.Fatalf("idempotent open: %v", err)
	}
	if err := gate.Close(); err != nil {
		t.Fatal(err)
	}
	assertDarwinRuntimeGateState(t, gate, false)

	pendingPath := filepath.Join(stateDirectory, runtimeGateRecoveryName)
	writeDarwinRuntimeGateFaultFile(t, pendingPath, runtimeGateContent[:7])
	if err := gate.Open(); err != nil {
		t.Fatalf("resume incomplete recovery: %v", err)
	}
	assertDarwinRuntimeGateState(t, gate, true)
	if _, err := os.Lstat(pendingPath); !os.IsNotExist(err) {
		t.Fatalf("recovery file remains after resumed publication: %v", err)
	}
	if err := gate.Close(); err != nil {
		t.Fatal(err)
	}

	writeDarwinRuntimeGateFaultFile(t, pendingPath, []byte("untrusted\n"))
	if err := gate.Open(); err == nil || !strings.Contains(err.Error(), "unexpected content") {
		t.Fatalf("unexpected recovery content error = %v", err)
	}
	if _, err := os.Lstat(pendingPath); err != nil {
		t.Fatalf("unexpected recovery content was removed: %v", err)
	}
	if err := os.Remove(pendingPath); err != nil {
		t.Fatal(err)
	}

	if err := gate.Open(); err != nil {
		t.Fatal(err)
	}
	writeDarwinRuntimeGateFaultFile(t, pendingPath, runtimeGateContent)
	if err := gate.Open(); err == nil || !strings.Contains(err.Error(), "unexpected recovery") {
		t.Fatalf("live-plus-recovery error = %v", err)
	}
	if err := gate.Close(); err != nil {
		t.Fatalf("close live-plus-recovery state: %v", err)
	}
	assertDarwinRuntimeGateState(t, gate, false)

	if err := os.Chmod(stateDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Inspect(); err == nil || !strings.Contains(err.Error(), "mode-0700") {
		t.Fatalf("writable installer state directory error = %v", err)
	}
	if err := os.Chmod(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestDarwinNativeInstallStateStoreLifecycle(t *testing.T) {
	requireDarwinNativeInstallerTest(t)
	parent, err := os.MkdirTemp("/private/var/db", ".mesh-native-install-state-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(parent, 0, 0); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = filepath.WalkDir(parent, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr == nil && entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
		if err := os.RemoveAll(parent); err != nil {
			t.Errorf("remove exact Darwin install-state fault directory: %v", err)
		}
	}()

	stateDirectory := filepath.Join(parent, "state")
	if err := EnsureStateDirectory(stateDirectory); err != nil {
		t.Fatal(err)
	}
	store, err := NewInstallerJournalStore(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	first := validAuthenticatedDarwinRelease(1, 1, 1, "1", "2")
	state := validDarwinInstallState(first)
	if err := store.CommitInstallState(state); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := store.LoadInstallState()
	if err != nil || !found || !sameDarwinInstallState(loaded, state) {
		t.Fatalf("initial Darwin install state = %+v, found=%t err=%v", loaded, found, err)
	}
	state, err = state.ActivateAccepted()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitInstallState(state); err != nil {
		t.Fatal(err)
	}
	second := validAuthenticatedDarwinRelease(1, 2, 1, "3", "4")
	state, err = state.AdvanceHighWater(second)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitInstallState(state); err != nil {
		t.Fatal(err)
	}
	state, err = state.ActivateAccepted()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitInstallState(state); err != nil {
		t.Fatal(err)
	}
	state, err = state.RollbackPrevious()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitInstallState(state); err != nil {
		t.Fatal(err)
	}
	if state.HighWater != second || state.Active == nil || *state.Active != first {
		t.Fatalf("native Darwin rollback lowered authority or selected wrong release: %+v", state)
	}

	statePath := filepath.Join(stateDirectory, darwinInstallStateName)
	if info, err := os.Lstat(statePath); err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("native Darwin install-state file = %v, %v", info, err)
	}
	pendingPath := filepath.Join(stateDirectory, darwinInstallStatePendingName)
	if err := os.WriteFile(pendingPath, []byte("untrusted\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(pendingPath, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(pendingPath, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.LoadInstallState(); err == nil {
		t.Fatal("malformed Darwin install-state recovery bytes were accepted")
	}
	if _, err := os.Lstat(pendingPath); err != nil {
		t.Fatalf("malformed Darwin install-state recovery bytes were removed: %v", err)
	}
}

func TestDarwinNativeArtifactCaptureLifecycle(t *testing.T) {
	requireDarwinNativeInstallerTest(t)
	parent, err := os.MkdirTemp("/private/var/db", ".mesh-native-artifact-capture-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(parent, 0, 0); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = filepath.WalkDir(parent, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr == nil && entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
		if err := os.RemoveAll(parent); err != nil {
			t.Errorf("remove exact Darwin artifact-capture fault directory: %v", err)
		}
	}()
	stateDirectory := filepath.Join(parent, "state")
	if err := EnsureStateDirectory(stateDirectory); err != nil {
		t.Fatal(err)
	}
	store, err := NewInstallerJournalStore(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("authenticated Darwin artifact capture\n")
	digest := sha256.Sum256(payload)
	expected := releasetrust.Artifact{
		OS: "darwin", Arch: "amd64", URL: "https://releases.invalid/mesh-darwin-amd64.tar",
		Size: int64(len(payload)), SHA256: hex.EncodeToString(digest[:]),
	}
	capture, err := store.BeginArtifactCapture(expected)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := capture.Destination()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := destination.Write(payload[:len(payload)/2]); err != nil {
		t.Fatal(err)
	}
	if err := capture.Close(); err != nil {
		t.Fatal(err)
	}

	capture, err = store.BeginArtifactCapture(expected)
	if err != nil {
		t.Fatal(err)
	}
	destination, err = capture.Destination()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(destination, strings.NewReader(string(payload))); err != nil {
		t.Fatal(err)
	}
	if err := capture.Publish(); err != nil {
		t.Fatal(err)
	}
	livePath := capture.Path()
	if info, err := os.Lstat(livePath); err != nil || info.Mode().Perm() != 0o400 || info.Size() != int64(len(payload)) {
		t.Fatalf("native Darwin captured artifact = %v, %v", info, err)
	}
	if err := capture.Close(); err != nil {
		t.Fatal(err)
	}

	capture, err = store.BeginArtifactCapture(expected)
	if err != nil || capture.Path() != livePath {
		t.Fatalf("recovered native Darwin captured artifact = %q, %v", capture.Path(), err)
	}
	if err := capture.Discard(); err != nil {
		t.Fatal(err)
	}
	if err := capture.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(livePath); !os.IsNotExist(err) {
		t.Fatalf("discarded native Darwin artifact remains: %v", err)
	}

	pendingName, _ := darwinArtifactCapturePendingName(expected.SHA256)
	pendingPath := filepath.Join(stateDirectory, pendingName)
	wrong := append([]byte(nil), payload...)
	wrong[0] ^= 1
	if err := os.WriteFile(pendingPath, wrong, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(pendingPath, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(pendingPath, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginArtifactCapture(expected); err == nil {
		t.Fatal("wrong finalized Darwin artifact capture was accepted")
	}
	if _, err := os.Lstat(pendingPath); err != nil {
		t.Fatalf("wrong finalized Darwin artifact capture was removed: %v", err)
	}
}

func TestDarwinNativeTrustedRootHistoryLifecycle(t *testing.T) {
	requireDarwinNativeInstallerTest(t)
	parent, err := os.MkdirTemp("/private/var/db", ".mesh-native-root-history-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(parent, 0, 0); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = filepath.WalkDir(parent, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr == nil && entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
		if err := os.RemoveAll(parent); err != nil {
			t.Errorf("remove exact Darwin root-history fault directory: %v", err)
		}
	}()

	stateDirectory := filepath.Join(parent, "state")
	if err := EnsureStateDirectory(stateDirectory); err != nil {
		t.Fatal(err)
	}
	store, err := NewInstallerJournalStore(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	initial, rootKeys, releaseKeys := darwinCandidateTestAuthority(t)
	update, successor := darwinRootHistoryTestUpdate(t, initial, rootKeys)
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	result, err := store.ApplyTrustedRootUpdates(initial, [][]byte{update}, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !sameDarwinTrustedRoot(result.Root, successor) || len(result.Applied) != 1 {
		t.Fatalf("native Darwin trusted-root result = %+v", result)
	}
	loaded, err := store.LoadTrustedRoot(initial)
	if err != nil || !sameDarwinTrustedRoot(loaded, successor) {
		t.Fatalf("replayed native Darwin trusted root = %+v, %v", loaded, err)
	}

	lock, err := store.AcquireLock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lock.LoadTrustedRoot(initial); err != nil {
		_ = lock.Close()
		t.Fatal(err)
	}
	historical, err := lock.TrustedRootVersion(initial.Document.Version)
	closeErr := lock.Close()
	if err != nil || closeErr != nil || !sameDarwinTrustedRoot(historical, initial) {
		t.Fatalf("historical native Darwin trusted root = %+v, err=%v close=%v", historical, err, closeErr)
	}
	livePath := filepath.Join(stateDirectory, darwinRootHistoryName(successor.Document.Version))
	if info, err := os.Lstat(livePath); err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("native Darwin root-history file = %v, %v", info, err)
	}
	inspection := validDarwinCandidateInspection(t)
	metadata := darwinCandidateTestMetadata(t, successor, releaseKeys, inspection, 4)
	intake, err := store.authenticateDarwinCandidateUsing(onlinerelease.Bundle{
		RootUpdates:       [][]byte{},
		ChannelManifest:   metadata.ChannelManifest,
		ChannelSignatures: metadata.ChannelSignatures,
		ReleaseManifest:   metadata.ReleaseManifest,
		ReleaseSignatures: metadata.ReleaseSignatures,
	}, now, installtrust.Bootstrap{
		InitialRoot: initial, InitialRootSHA256: initial.SHA256,
	}, buildinfo.Info{OS: "darwin", Arch: inspection.Package.Target.Arch, SecurityFloor: inspection.Package.SecurityFloor})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := intake.Complete(inspection)
	if err != nil || authority.TrustedRootVersion != successor.Document.Version || authority.TrustedRootSHA256 != successor.SHA256 {
		t.Fatalf("native Darwin authenticated intake = %+v, %v", authority, err)
	}
	intakePath := filepath.Join(stateDirectory, darwinIntakeRecordName)
	if info, err := os.Lstat(intakePath); err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("native Darwin accepted-intake file = %v, %v", info, err)
	}
	intakePendingPath := filepath.Join(stateDirectory, darwinIntakeRecordPendingName)
	if err := os.Rename(intakePath, intakePendingPath); err != nil {
		t.Fatal(err)
	}
	recovered, found, err := store.loadDarwinIntakeUsing(installtrust.Bootstrap{
		InitialRoot: initial, InitialRootSHA256: initial.SHA256,
	}, buildinfo.Info{OS: "darwin", Arch: inspection.Package.Target.Arch, SecurityFloor: inspection.Package.SecurityFloor})
	if err != nil || !found || recovered != intake {
		t.Fatalf("recovered native Darwin accepted intake = %+v, found=%v err=%v", recovered, found, err)
	}
	if _, err := os.Lstat(intakePath); err != nil {
		t.Fatalf("recovered native Darwin accepted intake was not published: %v", err)
	}
	if _, err := os.Lstat(intakePendingPath); !os.IsNotExist(err) {
		t.Fatalf("recovered native Darwin accepted-intake pending file remains: %v", err)
	}
	retry, err := store.authenticateDarwinCandidateUsing(onlinerelease.Bundle{
		RootUpdates:       [][]byte{},
		ChannelManifest:   metadata.ChannelManifest,
		ChannelSignatures: metadata.ChannelSignatures,
		ReleaseManifest:   metadata.ReleaseManifest,
		ReleaseSignatures: metadata.ReleaseSignatures,
	}, now.Add(2*time.Hour), installtrust.Bootstrap{
		InitialRoot: initial, InitialRootSHA256: initial.SHA256,
	}, buildinfo.Info{OS: "darwin", Arch: inspection.Package.Target.Arch, SecurityFloor: inspection.Package.SecurityFloor})
	if err != nil || retry != intake {
		t.Fatalf("exact native Darwin intake retry = %+v, %v", retry, err)
	}
	unrelatedMetadata := darwinCandidateTestMetadata(t, successor, releaseKeys, inspection, 5)
	if _, err := store.authenticateDarwinCandidateUsing(onlinerelease.Bundle{
		RootUpdates:       [][]byte{},
		ChannelManifest:   unrelatedMetadata.ChannelManifest,
		ChannelSignatures: unrelatedMetadata.ChannelSignatures,
		ReleaseManifest:   unrelatedMetadata.ReleaseManifest,
		ReleaseSignatures: unrelatedMetadata.ReleaseSignatures,
	}, now, installtrust.Bootstrap{
		InitialRoot: initial, InitialRootSHA256: initial.SHA256,
	}, buildinfo.Info{OS: "darwin", Arch: inspection.Package.Target.Arch, SecurityFloor: inspection.Package.SecurityFloor}); err == nil {
		t.Fatal("unrelated native Darwin candidate overlapped an accepted intake")
	}
	if _, err := store.ApplyTrustedRootUpdates(initial, nil, now, 0); err == nil {
		t.Fatal("native Darwin root history advanced while an accepted intake was active")
	}
	fetchAttempts := 0
	if _, err := store.fetchDarwinArtifactUsing(context.Background(), intake, nativeDarwinArtifactFetcherFunc(
		func(_ context.Context, _ releasetrust.Artifact, destination *os.File) error {
			fetchAttempts++
			if destination == nil {
				t.Fatal("native Darwin fetch adapter received no bounded destination")
			}
			return errors.New("injected native artifact transport failure")
		},
	)); err == nil || fetchAttempts != 1 {
		t.Fatalf("native Darwin failed fetch = attempts %d, err %v", fetchAttempts, err)
	}
	pendingArtifactName, _ := darwinArtifactCapturePendingName(intake.Candidate.Artifact.SHA256)
	if info, err := os.Lstat(filepath.Join(stateDirectory, pendingArtifactName)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("native Darwin failed fetch partial = %v, %v", info, err)
	}
	capture, err := store.BeginAcceptedArtifactCapture(intake)
	if err != nil {
		t.Fatal(err)
	}
	if capture.Path() != "" {
		t.Fatalf("native Darwin partial fetch recovery unexpectedly finalized %q", capture.Path())
	}
	if err := capture.Close(); err != nil {
		t.Fatal(err)
	}

	pendingPath := filepath.Join(stateDirectory, darwinRootPendingName(successor.Document.Version+1))
	if err := os.WriteFile(pendingPath, []byte("untrusted\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(pendingPath, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(pendingPath, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadTrustedRoot(initial); err == nil {
		t.Fatal("malformed Darwin pending root-history bytes were accepted")
	}
	if _, err := os.Lstat(pendingPath); err != nil {
		t.Fatalf("malformed Darwin pending root-history bytes were removed: %v", err)
	}
}

func darwinRootHistoryTestUpdate(t *testing.T, current releasetrust.ParsedRoot, rootKeys []ed25519.PrivateKey) ([]byte, releasetrust.ParsedRoot) {
	t.Helper()
	document := current.Document
	document.Version++
	document.IssuedAt = "2026-07-21T00:00:00Z"
	document.ExpiresAt = "2026-08-21T00:00:00Z"
	raw, err := releasetrust.EncodeRoot(document)
	if err != nil {
		t.Fatal(err)
	}
	signatures := make([][]byte, 0, len(rootKeys))
	for _, key := range rootKeys {
		signature, err := releasetrust.SignManifest(releasetrust.RootManifestKind, raw, key)
		if err != nil {
			t.Fatal(err)
		}
		signatures = append(signatures, signature)
	}
	update, err := releasetrust.EncodeRootUpdate(releasetrust.RootUpdate{RootManifest: raw, Signatures: signatures})
	if err != nil {
		t.Fatal(err)
	}
	transition, err := releasetrust.VerifyRootTransition(current, raw, signatures)
	if err != nil {
		t.Fatal(err)
	}
	return update, transition.Root
}

func TestDarwinNativeReleaseLayoutAndOptionalPublication(t *testing.T) {
	requireDarwinNativeInstallerTest(t)
	parent, err := os.MkdirTemp("/private/var/db", ".mesh-native-release-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(parent, 0, 0); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = filepath.WalkDir(parent, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr == nil && entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
		if err := os.RemoveAll(parent); err != nil {
			t.Errorf("remove exact Darwin release-layout fault directory: %v", err)
		}
	}()

	rootPath := filepath.Join(parent, "mesh")
	layout, err := EnsureReleaseLayout(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer layout.Close()
	const installedID = "e00000000000000000001-s00000000000000000001-r0123456789abcdef-a0123456789abcdef"
	stage, err := layout.CreateStage(installedID)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	if info, err := os.Lstat(stage.Path()); err != nil || info.Mode() != os.ModeDir|0o700 {
		t.Fatalf("private Darwin release stage = %v, %v", info, err)
	}

	bundle := os.Getenv("MESH_DARWIN_NATIVE_BUNDLE")
	if bundle != "" {
		inspection, err := stage.StageAuthenticatedArtifact(bundle)
		if err != nil {
			t.Fatal(err)
		}
		if inspection.Package.Target.OS != "darwin" {
			t.Fatalf("staged target = %s", inspection.Package.Target.OS)
		}
		stageName := stage.name
		if err := stage.Close(); err != nil {
			t.Fatal(err)
		}
		stage, err = layout.ResumeStage(installedID, stageName, inspection)
		if err != nil {
			t.Fatal(err)
		}
		defer stage.Close()
		if err := stage.Publish(); err != nil {
			t.Fatal(err)
		}
		published := filepath.Join(rootPath, "releases", installedID)
		if stage.Path() != published {
			t.Fatalf("published path = %q, want %q", stage.Path(), published)
		}
		if _, err := os.Lstat(published); err != nil {
			t.Fatal(err)
		}
		if err := stage.Close(); err != nil {
			t.Fatal(err)
		}
		stage, err = layout.ResumeStage(installedID, stageName, inspection)
		if err != nil {
			t.Fatal(err)
		}
		defer stage.Close()
		if err := stage.Publish(); err != nil {
			t.Fatalf("resume already-published release: %v", err)
		}

		selection, err := layout.NewCurrentSwitch("", installedID, inspection)
		if err != nil {
			t.Fatal(err)
		}
		if err := selection.InspectTarget(); err != nil {
			t.Fatal(err)
		}
		if err := selection.CreateTemporary(); err != nil {
			t.Fatal(err)
		}
		if err := selection.SyncRoot(); err != nil {
			t.Fatal(err)
		}
		selection, err = layout.ResumeCurrentSwitch("", installedID, selection.TemporaryName(), inspection)
		if err != nil {
			t.Fatal(err)
		}
		if err := selection.Execute(); err != nil {
			t.Fatalf("resume prepared Darwin current switch: %v", err)
		}
		if target, err := os.Readlink(filepath.Join(rootPath, "current")); err != nil || target != "releases/"+installedID {
			t.Fatalf("first Darwin current target = %q, %v", target, err)
		}
		selection, err = layout.ResumeCurrentSwitch("", installedID, selection.TemporaryName(), inspection)
		if err != nil {
			t.Fatal(err)
		}
		if err := selection.Execute(); err != nil {
			t.Fatalf("resume already-selected Darwin current release: %v", err)
		}

		const secondInstalledID = "e00000000000000000001-s00000000000000000002-r0123456789abcdef-a0123456789abcdef"
		secondStage, err := layout.CreateStage(secondInstalledID)
		if err != nil {
			t.Fatal(err)
		}
		defer secondStage.Close()
		secondInspection, err := secondStage.StageAuthenticatedArtifact(bundle)
		if err != nil {
			t.Fatal(err)
		}
		if err := secondStage.Publish(); err != nil {
			t.Fatal(err)
		}
		stale, err := layout.NewCurrentSwitch("", secondInstalledID, secondInspection)
		if err != nil {
			t.Fatal(err)
		}
		if err := stale.Execute(); err == nil || !strings.Contains(err.Error(), "expected prior") {
			t.Fatalf("stale Darwin current switch error = %v", err)
		}
		if target, err := os.Readlink(filepath.Join(rootPath, "current")); err != nil || target != "releases/"+installedID {
			t.Fatalf("stale transaction changed Darwin current target = %q, %v", target, err)
		}
		upgrade, err := layout.NewCurrentSwitch(installedID, secondInstalledID, secondInspection)
		if err != nil {
			t.Fatal(err)
		}
		if err := upgrade.Execute(); err != nil {
			t.Fatal(err)
		}
		if target, err := os.Readlink(filepath.Join(rootPath, "current")); err != nil || target != "releases/"+secondInstalledID {
			t.Fatalf("upgraded Darwin current target = %q, %v", target, err)
		}

		journalRoot, journalReleaseKeys := darwinCandidateTestRoot(t)
		journalMetadata := darwinCandidateTestMetadata(t, journalRoot, journalReleaseKeys, secondInspection, 3)
		journalNow := time.Date(2026, 7, 21, 20, 0, 0, 0, time.UTC)
		journalCandidate, err := VerifyDarwinCandidateWithRoots(
			journalMetadata, journalRoot.SHA256, journalRoot, journalRoot, nil, journalNow,
			secondInspection.Package.SecurityFloor, secondInspection.Package.Target.Arch,
		)
		if err != nil {
			t.Fatal(err)
		}
		journalIntake := VerifiedDarwinIntake{Candidate: journalCandidate, InstallerBootstrapRootSHA256: journalRoot.SHA256}
		journalAuthority, err := journalIntake.Complete(secondInspection)
		if err != nil {
			t.Fatal(err)
		}
		thirdInstalledID := journalAuthority.InstalledID
		journalSwitch, err := layout.NewCurrentSwitch(secondInstalledID, thirdInstalledID, secondInspection)
		if err != nil {
			t.Fatal(err)
		}
		journalDirectory := filepath.Join(parent, "journal-state")
		if err := EnsureStateDirectory(journalDirectory); err != nil {
			t.Fatal(err)
		}
		store, err := NewInstallerJournalStore(journalDirectory)
		if err != nil {
			t.Fatal(err)
		}
		journalGate, err := NewRuntimeGate(journalDirectory)
		if err != nil {
			t.Fatal(err)
		}
		launchdDirectory := filepath.Join(parent, "LaunchDaemons")
		if err := os.Mkdir(launchdDirectory, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(launchdDirectory, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(launchdDirectory, 0o755); err != nil {
			t.Fatal(err)
		}
		livePlist := filepath.Join(launchdDirectory, LaunchdPlistName)
		if err := os.WriteFile(livePlist, []byte("old plist\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(livePlist, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(livePlist, 0o644); err != nil {
			t.Fatal(err)
		}
		service := &nativeLaunchdService{plistPath: livePlist}
		activation, err := NewLaunchdActivation(journalGate, journalSwitch, service, launchdDirectory)
		if err != nil {
			t.Fatal(err)
		}
		secondAuthority := validAuthenticatedDarwinRelease(1, 2, secondInspection.Package.SecurityFloor, "0", "0")
		secondAuthority.ReleaseManifestSHA256 = strings.Repeat("0123456789abcdef", 4)
		secondAuthority.ArtifactSHA256 = strings.Repeat("0123456789abcdef", 4)
		secondAuthority.PackageJSONSHA256 = secondInspection.PackageJSONSHA256
		secondAuthority.Arch = secondInspection.Package.Target.Arch
		secondAuthority.AgentStateReadMin = secondInspection.Package.AgentStateReadMin
		secondAuthority.AgentStateReadMax = secondInspection.Package.AgentStateReadMax
		secondAuthority.AgentStateWriteVersion = secondInspection.Package.AgentStateWriteVersion
		secondAuthority.InstallerBootstrapRootSHA256 = journalRoot.SHA256
		secondAuthority.TrustedRootVersion = journalRoot.Document.Version
		secondAuthority.TrustedRootSHA256 = journalRoot.SHA256
		secondAuthority.Channel = journalRoot.Document.Channel
		secondAuthority.InstalledID = DarwinInstalledID(secondAuthority)
		seedState := validDarwinInstallState(secondAuthority)
		if err := store.CommitInstallState(seedState); err != nil {
			t.Fatal(err)
		}
		seedState, err = seedState.ActivateAccepted()
		if err != nil {
			t.Fatal(err)
		}
		if err := store.CommitInstallState(seedState); err != nil {
			t.Fatal(err)
		}
		offlineBundle := onlinerelease.Bundle{
			RootUpdates:       [][]byte{},
			ChannelManifest:   journalMetadata.ChannelManifest,
			ChannelSignatures: journalMetadata.ChannelSignatures,
			ReleaseManifest:   journalMetadata.ReleaseManifest,
			ReleaseSignatures: journalMetadata.ReleaseSignatures,
		}
		offlineSnapshot := writeNativeDarwinOfflineSnapshot(t, parent, offlineBundle, bundle)
		persistedIntake, capture, err := store.importDarwinSnapshotUsing(context.Background(), offlineSnapshot, journalNow, installtrust.Bootstrap{
			InitialRoot: journalRoot, InitialRootSHA256: journalRoot.SHA256,
		}, buildinfo.Info{OS: "darwin", Arch: secondInspection.Package.Target.Arch, SecurityFloor: secondInspection.Package.SecurityFloor})
		if err != nil || persistedIntake != journalIntake {
			t.Fatalf("persist native Darwin journal intake = %+v, %v", persistedIntake, err)
		}
		if capture.Path() == "" {
			t.Fatal("native Darwin offline snapshot did not finalize its exact artifact capture")
		}
		if err := capture.Close(); err != nil {
			t.Fatal(err)
		}
		acceptedStageName, err := darwinAcceptedStageName(persistedIntake.Candidate)
		if err != nil {
			t.Fatal(err)
		}
		partialStage, err := layout.resetAndCreateAcceptedStage(thirdInstalledID, acceptedStageName)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(partialStage.Path(), "interrupted"), []byte("partial\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := partialStage.Close(); err != nil {
			t.Fatal(err)
		}
		thirdStage, stagedAuthority, err := store.StageAcceptedIntake(layout, persistedIntake)
		if err != nil {
			t.Fatal(err)
		}
		thirdInspection := thirdStage.inspection
		if !reflect.DeepEqual(thirdInspection, secondInspection) || stagedAuthority != journalAuthority || thirdStage.name != acceptedStageName {
			t.Fatalf("native Darwin accepted staging = inspection match %t authority match %t name %q", reflect.DeepEqual(thirdInspection, secondInspection), stagedAuthority == journalAuthority, thirdStage.name)
		}
		journal, err := NewInstallerJournalFor(thirdStage, journalSwitch, journalAuthority, false)
		if err != nil {
			t.Fatal(err)
		}
		acceptedIntakeRaw, err := os.ReadFile(filepath.Join(journalDirectory, darwinIntakeRecordName))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.BeginAcceptedIntake(layout, journal, activation, persistedIntake); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(filepath.Join(journalDirectory, darwinIntakeRecordName)); !os.IsNotExist(err) {
			t.Fatalf("journal-consumed Darwin accepted intake remains: %v", err)
		}
		acceptedArtifactName, _ := darwinArtifactCaptureName(persistedIntake.Candidate.Artifact.SHA256)
		if _, err := os.Lstat(filepath.Join(journalDirectory, acceptedArtifactName)); !os.IsNotExist(err) {
			t.Fatalf("journal-consumed Darwin artifact capture remains: %v", err)
		}
		// Recreate the exact record to model a crash after the journal rename but
		// before accepted-intake unlink. Resume must consume only this exact match.
		staleIntakePath := filepath.Join(journalDirectory, darwinIntakeRecordName)
		if err := os.WriteFile(staleIntakePath, acceptedIntakeRaw, 0o400); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(staleIntakePath, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(staleIntakePath, 0o400); err != nil {
			t.Fatal(err)
		}
		if err := thirdStage.Close(); err != nil {
			t.Fatal(err)
		}
		if err := store.Resume(layout, activation); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(staleIntakePath); !os.IsNotExist(err) {
			t.Fatalf("journal recovery left its exact stale Darwin intake: %v", err)
		}
		if err := activation.publisher.Inspect(); err != nil {
			t.Fatal(err)
		}
		plistContents, err := os.ReadFile(livePlist)
		if err != nil {
			t.Fatal(err)
		}
		pendingPlist := filepath.Join(launchdDirectory, launchdPlistPendingName)
		if err := os.WriteFile(pendingPlist, plistContents[:len(plistContents)/2], 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(pendingPlist, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(pendingPlist, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := activation.publisher.Publish(); err != nil {
			t.Fatalf("recover partial launchd plist publication: %v", err)
		}
		if _, err := os.Lstat(pendingPlist); !os.IsNotExist(err) {
			t.Fatalf("recognized launchd pending plist remains: %v", err)
		}
		if err := os.WriteFile(pendingPlist, []byte("untrusted\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(pendingPlist, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(pendingPlist, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := activation.publisher.Publish(); err == nil || !strings.Contains(err.Error(), "recognized recovery") {
			t.Fatalf("unrecognized launchd pending plist error = %v", err)
		}
		if _, err := os.Lstat(pendingPlist); err != nil {
			t.Fatalf("unrecognized launchd pending plist was removed: %v", err)
		}
		if err := os.Remove(pendingPlist); err != nil {
			t.Fatal(err)
		}
		if err := activation.Close(); err != nil {
			t.Fatal(err)
		}
		if target, err := os.Readlink(filepath.Join(rootPath, "current")); err != nil || target != "releases/"+thirdInstalledID {
			t.Fatalf("journal-recovered Darwin current target = %q, %v", target, err)
		}
		if _, err := os.Lstat(filepath.Join(journalDirectory, installerJournalName)); !os.IsNotExist(err) {
			t.Fatalf("completed Darwin installer journal remains: %v", err)
		}
		if err := store.BeginRollback(layout); err != nil {
			t.Fatal(err)
		}
		prepared, found, err := func() (InstallerJournal, bool, error) {
			lock, err := store.AcquireLock()
			if err != nil {
				return InstallerJournal{}, false, err
			}
			journal, found, loadErr := lock.Load()
			return journal, found, errors.Join(loadErr, lock.Close())
		}()
		if err != nil || !found || prepared.Operation != JournalOperationRollback || prepared.Phase != JournalPhasePrepared ||
			prepared.SourceAuthority == nil || prepared.SourceAuthority.InstalledID != thirdInstalledID || prepared.InstalledID != secondInstalledID {
			t.Fatalf("prepared Darwin rollback journal = %+v, found=%t err=%v", prepared, found, err)
		}
		if err := store.ResumeJournalWithService(layout, service, launchdDirectory); err != nil {
			t.Fatal(err)
		}
		if target, err := os.Readlink(filepath.Join(rootPath, "current")); err != nil || target != "releases/"+secondInstalledID {
			t.Fatalf("rolled-back Darwin current target = %q, %v", target, err)
		}
		rolledBack, found, err := store.LoadInstallState()
		if err != nil || !found || rolledBack.Active == nil || rolledBack.Previous == nil ||
			rolledBack.Active.InstalledID != secondInstalledID || rolledBack.Previous.InstalledID != thirdInstalledID ||
			rolledBack.HighWater.InstalledID != thirdInstalledID {
			t.Fatalf("completed Darwin rollback state = %+v, found=%t err=%v", rolledBack, found, err)
		}
		if _, err := os.Lstat(filepath.Join(journalDirectory, installerJournalName)); !os.IsNotExist(err) {
			t.Fatalf("completed Darwin rollback journal remains: %v", err)
		}
		lock, err := store.AcquireLock()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.AcquireLock(); err == nil || !strings.Contains(err.Error(), "in-process") {
			t.Fatalf("concurrent Darwin journal lock error = %v", err)
		}
		if err := lock.Close(); err != nil {
			t.Fatal(err)
		}
	}

	releasesPath := filepath.Join(rootPath, "releases")
	if err := os.Chmod(releasesPath, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := layout.CreateStage(installedID); err == nil || !strings.Contains(err.Error(), "mode-0755") {
		t.Fatalf("insecure Darwin releases directory error = %v", err)
	}
	if err := os.Chmod(releasesPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if bundle == "" {
		if err := stage.DiscardPrivate(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(stage.Path()); !os.IsNotExist(err) {
			t.Fatalf("discarded Darwin stage remains: %v", err)
		}
	}
}

func assertDarwinRuntimeGateState(t *testing.T, gate *RuntimeGate, want bool) {
	t.Helper()
	got, err := gate.Inspect()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("runtime gate open = %v, want %v", got, want)
	}
}

func writeDarwinRuntimeGateFaultFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, 0); err != nil {
		t.Fatal(err)
	}
}
