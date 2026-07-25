//go:build windows

package windowsinstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"mesh/internal/buildinfo"
	"mesh/internal/installtrust"
	"mesh/internal/onlinerelease"
	"mesh/internal/windowsbundle"
	"mesh/internal/windowssecurity"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestWindowsInstallerLifecycleNative(t *testing.T) {
	if os.Getenv("MESH_WINDOWS_NATIVE_FAULT_TEST") != "1" {
		t.Skip("set MESH_WINDOWS_NATIVE_FAULT_TEST=1 on an isolated elevated Windows host")
	}
	bundlePath := os.Getenv("MESH_WINDOWS_NATIVE_BUNDLE")
	if bundlePath == "" {
		t.Fatal("MESH_WINDOWS_NATIVE_BUNDLE must name one canonical bundle for the native lifecycle proof")
	}
	upgradeBundlePath := os.Getenv("MESH_WINDOWS_NATIVE_UPGRADE_BUNDLE")
	if upgradeBundlePath == "" {
		t.Fatal("MESH_WINDOWS_NATIVE_UPGRADE_BUNDLE must name a distinct canonical upgrade bundle")
	}
	assertNativeServiceAbsent(t)

	actorSID := windowssecurity.LocalSystemSID
	testRoot := filepath.Join(t.TempDir(), "MeshNativeLifecycle")
	if err := ensureProtectedDirectory(testRoot, actorSID); err != nil {
		t.Fatal(err)
	}
	layout, err := EnsureReleaseLayout(filepath.Join(testRoot, "releases-root"), actorSID)
	if err != nil {
		t.Fatal(err)
	}
	defer layout.Close()

	inspection, privateBundlePath := prepareNativeWindowsCandidate(t, testRoot, "initial", bundlePath, actorSID)
	if inspection.Package.Target.Arch != runtime.GOARCH {
		t.Fatalf("native Windows bundle architecture %q does not match host %q", inspection.Package.Target.Arch, runtime.GOARCH)
	}
	if inspection.Package.Schema != windowsbundle.SignedSchema {
		t.Fatalf("native Windows lifecycle requires final signed bundle-v3, got %q", inspection.Package.Schema)
	}
	installerDirectory := filepath.Join(testRoot, "installer")
	if err := ensureProtectedDirectory(installerDirectory, actorSID); err != nil {
		t.Fatal(err)
	}
	testNativeDACLAndReparseRejection(t, testRoot, installerDirectory)
	gate, err := NewRuntimeGate(installerDirectory)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewActivationJournalStore(installerDirectory)
	if err != nil {
		t.Fatal(err)
	}
	compiledRoot, releaseKeys := windowsCandidateTestRoot(t)
	if loadedRoot, err := store.LoadTrustedRoot(compiledRoot); err != nil || loadedRoot.SHA256 != compiledRoot.SHA256 {
		t.Fatalf("native Windows trusted-root replay = %s, error = %v", loadedRoot.SHA256, err)
	}
	verificationTime := time.Date(2026, 7, 21, 20, 0, 0, 0, time.UTC)
	metadata := windowsCandidateTestMetadata(t, compiledRoot, releaseKeys, inspection, 1)
	bundle := onlinerelease.Bundle{
		RootUpdates:       [][]byte{},
		ChannelManifest:   metadata.ChannelManifest,
		ChannelSignatures: metadata.ChannelSignatures,
		ReleaseManifest:   metadata.ReleaseManifest,
		ReleaseSignatures: metadata.ReleaseSignatures,
	}
	offlineSnapshot := writeNativeWindowsOfflineSnapshot(t, testRoot, "initial", bundle, privateBundlePath, actorSID)
	intake, capturedBundlePath, err := store.importWindowsSnapshotUsing(
		context.Background(), offlineSnapshot, verificationTime,
		installtrust.Bootstrap{InitialRoot: compiledRoot, InitialRootSHA256: compiledRoot.SHA256},
		buildinfo.Info{
			OS: "windows", Arch: inspection.Package.Target.Arch,
			SecurityFloor: inspection.Package.SecurityFloor,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	preflightAuthority, acceptedState, err := store.commitAcceptedWindowsAuthority(intake, inspection)
	if err != nil {
		t.Fatal(err)
	}
	stageName, err := WindowsAcceptedStageName(intake)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := layout.resetAndCreateAcceptedStage(preflightAuthority, stageName)
	if err != nil {
		t.Fatal(err)
	}
	stagedInspection, err := stage.StageAuthenticatedArtifact(capturedBundlePath)
	if err != nil {
		stage.Close()
		t.Fatal(err)
	}
	if stagedInspection.ArtifactSHA256 != inspection.ArtifactSHA256 || stagedInspection.PackageJSONSHA256 != inspection.PackageJSONSHA256 {
		stage.Close()
		t.Fatalf("native staged inspection = %+v, want artifact %s", stagedInspection, inspection.ArtifactSHA256)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	stage, authority, recoveredState, err := store.PublishAcceptedWindowsIntake(layout, intake)
	if err != nil {
		t.Fatal(err)
	}
	if authority != preflightAuthority || !reflect.DeepEqual(recoveredState, acceptedState) {
		stage.Close()
		t.Fatalf("native Windows accepted-stage recovery authority=%+v state=%+v", authority, recoveredState)
	}
	defer stage.Close()
	target, err := authority.CurrentDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	releasePath := stage.Path()

	current, err := layout.NewCurrentSwitch(nil, target)
	if err != nil {
		t.Fatal(err)
	}
	publishedAlias := filepath.Join(testRoot, "published-package-hardlink.json")
	if err := os.Link(filepath.Join(releasePath, "package.json"), publishedAlias); err != nil {
		t.Fatalf("create native Windows published hard-link proof: %v", err)
	}
	if err := current.InspectTarget(target); err == nil {
		t.Fatal("native Windows selector accepted a published file with an external hard link")
	}
	if err := os.Remove(publishedAlias); err != nil {
		t.Fatal(err)
	}
	if err := current.InspectTarget(target); err != nil {
		t.Fatal(err)
	}

	statePath := filepath.Join(testRoot, "agent", "state.json")
	if err := ensureProtectedDirectory(filepath.Dir(statePath), actorSID); err != nil {
		t.Fatal(err)
	}
	agentState := []byte("native-enrollment-state-must-survive-runtime-uninstall\n")
	writeNativeWindowsPrivateFile(t, statePath, agentState, actorSID)
	contract, err := NewNodeAgentServiceContract(releasePath, statePath)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := NewNodeAgentServiceController(contract)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if installed, inspectErr := controller.InspectInstalled(); inspectErr == nil && installed {
			_ = controller.StopAndProve(context.Background())
			_ = controller.DeleteStopped()
		}
	}()
	journal, err := NewWindowsActivationJournal(
		nil, authority, current.TemporaryName(), false, false, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	operations, err := NewActivationOperations(journal, current, gate, nil, controller)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	completed, err := RunWindowsActivation(ctx, store, operations)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Phase != WindowsActivationActivated {
		t.Fatalf("native Windows activation phase = %q", completed.Phase)
	}
	loaded, err := store.Load()
	if err != nil || loaded == nil || !reflectWindowsJournal(*loaded, completed) {
		t.Fatalf("native Windows journal load = %#v, error = %v", loaded, err)
	}
	if installed, err := controller.InspectInstalled(); err != nil || !installed {
		t.Fatalf("native Windows service proof installed=%t error=%v", installed, err)
	}
	if running, err := controller.InspectRunningAndProve(); err != nil || running {
		t.Fatalf("native Windows service stopped proof running=%t error=%v", running, err)
	}
	finalizedState, err := store.FinalizeAcceptedWindowsActivation(completed)
	if err != nil {
		t.Fatal(err)
	}
	if finalizedState.Active == nil || *finalizedState.Active != authority || finalizedState.HighWater != acceptedState.HighWater {
		t.Fatalf("native Windows finalized state = %+v, want active authority %+v", finalizedState, authority)
	}
	replayedFinalization, err := store.FinalizeAcceptedWindowsActivation(completed)
	if err != nil || !reflect.DeepEqual(replayedFinalization, finalizedState) {
		t.Fatalf("native Windows finalization replay = %+v, error = %v", replayedFinalization, err)
	}
	if _, err := os.Lstat(capturedBundlePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("native Windows finalized artifact capture remains visible: %v", err)
	}

	upgradeInspection, privateUpgradePath := prepareNativeWindowsCandidate(t, testRoot, "upgrade", upgradeBundlePath, actorSID)
	if upgradeInspection.Package.Target.Arch != inspection.Package.Target.Arch ||
		upgradeInspection.Package.Schema != windowsbundle.SignedSchema ||
		upgradeInspection.ArtifactSHA256 == inspection.ArtifactSHA256 ||
		upgradeInspection.Package.Version == inspection.Package.Version {
		t.Fatalf("native Windows upgrade bundle must be a distinct signed-v3 version for the same architecture: initial=%+v upgrade=%+v", inspection.Package, upgradeInspection.Package)
	}
	upgradeMetadata := windowsCandidateTestMetadata(t, compiledRoot, releaseKeys, upgradeInspection, 2)
	upgradeBundle := onlinerelease.Bundle{
		RootUpdates:       [][]byte{},
		ChannelManifest:   upgradeMetadata.ChannelManifest,
		ChannelSignatures: upgradeMetadata.ChannelSignatures,
		ReleaseManifest:   upgradeMetadata.ReleaseManifest,
		ReleaseSignatures: upgradeMetadata.ReleaseSignatures,
	}
	upgradeSnapshot := writeNativeWindowsOfflineSnapshot(t, testRoot, "upgrade", upgradeBundle, privateUpgradePath, actorSID)
	upgradeIntake, capturedUpgradePath, err := store.importWindowsSnapshotUsing(
		context.Background(), upgradeSnapshot, verificationTime,
		installtrust.Bootstrap{InitialRoot: compiledRoot, InitialRootSHA256: compiledRoot.SHA256},
		buildinfo.Info{
			OS: "windows", Arch: upgradeInspection.Package.Target.Arch,
			SecurityFloor: upgradeInspection.Package.SecurityFloor,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	upgradeAuthority, upgradeAcceptedState, err := store.commitAcceptedWindowsAuthority(upgradeIntake, upgradeInspection)
	if err != nil {
		t.Fatal(err)
	}
	upgradeStageName, err := WindowsAcceptedStageName(upgradeIntake)
	if err != nil {
		t.Fatal(err)
	}
	upgradeStage, err := layout.resetAndCreateAcceptedStage(upgradeAuthority, upgradeStageName)
	if err != nil {
		t.Fatal(err)
	}
	if stagedUpgrade, err := upgradeStage.StageAuthenticatedArtifact(capturedUpgradePath); err != nil ||
		stagedUpgrade.ArtifactSHA256 != upgradeInspection.ArtifactSHA256 {
		upgradeStage.Close()
		t.Fatalf("stage native Windows upgrade: inspection=%+v error=%v", stagedUpgrade, err)
	}
	if err := upgradeStage.Close(); err != nil {
		t.Fatal(err)
	}
	upgradeStage, recoveredUpgradeAuthority, recoveredUpgradeState, err := store.PublishAcceptedWindowsIntake(layout, upgradeIntake)
	if err != nil {
		t.Fatal(err)
	}
	defer upgradeStage.Close()
	if recoveredUpgradeAuthority != upgradeAuthority || !reflect.DeepEqual(recoveredUpgradeState, upgradeAcceptedState) {
		t.Fatalf("native Windows upgrade recovery authority=%+v state=%+v", recoveredUpgradeAuthority, recoveredUpgradeState)
	}
	installation := &productionWindowsInstallation{
		meshRoot: filepath.Join(testRoot, "releases-root"), statePath: statePath,
		layout: layout, store: store, gate: gate,
	}
	_, upgradeOperations, err := installation.newActivationOperations(finalizedState, upgradeAuthority)
	if err != nil {
		t.Fatal(err)
	}
	upgradeContext, cancelUpgrade := context.WithTimeout(context.Background(), 30*time.Second)
	upgradedJournal, err := RunWindowsActivation(upgradeContext, store, upgradeOperations)
	cancelUpgrade()
	if err != nil {
		t.Fatal(err)
	}
	upgradedState, err := store.FinalizeAcceptedWindowsActivation(upgradedJournal)
	if err != nil {
		t.Fatal(err)
	}
	if upgradedState.Active == nil || *upgradedState.Active != upgradeAuthority ||
		upgradedState.Previous == nil || *upgradedState.Previous != authority ||
		upgradedState.HighWater != upgradeAuthority {
		t.Fatalf("native Windows upgraded state = %+v", upgradedState)
	}
	if _, err := os.Lstat(capturedUpgradePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("native Windows finalized upgrade capture remains visible: %v", err)
	}

	_, rollbackOperations, err := installation.newRollbackOperations(upgradedState)
	if err != nil {
		t.Fatal(err)
	}
	rollbackContext, cancelRollback := context.WithTimeout(context.Background(), 30*time.Second)
	rolledBackJournal, err := RunWindowsRollback(rollbackContext, store, rollbackOperations)
	cancelRollback()
	if err != nil {
		t.Fatal(err)
	}
	rolledBackState, err := store.FinalizeWindowsRollback(rolledBackJournal)
	if err != nil {
		t.Fatal(err)
	}
	if rolledBackState.Active == nil || *rolledBackState.Active != authority ||
		rolledBackState.Previous == nil || *rolledBackState.Previous != upgradeAuthority ||
		rolledBackState.HighWater != upgradeAuthority {
		t.Fatalf("native Windows rolled-back state = %+v", rolledBackState)
	}
	if selected, err := layout.InspectCurrentSelection(); err != nil || selected == nil || selected.InstalledID != authority.InstalledID {
		t.Fatalf("native Windows rollback selector=%+v error=%v", selected, err)
	}
	if installed, err := controller.InspectInstalled(); err != nil || !installed {
		t.Fatalf("native Windows rollback service proof installed=%t error=%v", installed, err)
	}
	upgradeTarget, err := upgradeAuthority.CurrentDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	if err := layout.InspectPublishedRelease(upgradeTarget); err != nil {
		t.Fatalf("native Windows rollback changed retained upgrade release: %v", err)
	}
	finalizedState = rolledBackState

	runNativeWindowsRuntimeUninstall(t, store, layout, gate, controller, finalizedState, target)
	deactivated, err := store.LoadInstallState()
	if err != nil || deactivated == nil || deactivated.Active != nil || deactivated.Previous != nil || deactivated.HighWater != finalizedState.HighWater {
		t.Fatalf("native Windows runtime-uninstall state = %+v, error = %v", deactivated, err)
	}
	if installed, err := controller.InspectInstalled(); err != nil || installed {
		t.Fatalf("native Windows uninstalled service proof installed=%t error=%v", installed, err)
	}
	if open, err := gate.Inspect(); err != nil || open {
		t.Fatalf("native Windows uninstalled runtime gate open=%t error=%v", open, err)
	}
	if selected, err := layout.InspectCurrentSelection(); err != nil || selected != nil {
		t.Fatalf("native Windows uninstalled selector=%+v error=%v", selected, err)
	}
	if err := layout.InspectPublishedRelease(target); err != nil {
		t.Fatalf("native Windows runtime uninstall removed or changed retained release: %v", err)
	}
	if err := layout.InspectPublishedRelease(upgradeTarget); err != nil {
		t.Fatalf("native Windows runtime uninstall removed or changed retained upgrade release: %v", err)
	}
	if uninstall, err := store.LoadRuntimeUninstall(); err != nil || uninstall != nil {
		t.Fatalf("native Windows terminal uninstall journal=%+v error=%v", uninstall, err)
	}
	retainedAgentState, err := os.ReadFile(statePath)
	if err != nil || !bytes.Equal(retainedAgentState, agentState) {
		t.Fatalf("native Windows runtime uninstall changed retained agent state: bytes=%q error=%v", retainedAgentState, err)
	}
	if retainedRoot, err := store.LoadTrustedRoot(compiledRoot); err != nil || retainedRoot.SHA256 != compiledRoot.SHA256 {
		t.Fatalf("native Windows runtime uninstall changed retained trusted-root history: root=%+v error=%v", retainedRoot, err)
	}
}

func runNativeWindowsRuntimeUninstall(
	t *testing.T,
	store *ActivationJournalStore,
	layout *ReleaseLayout,
	gate *RuntimeGate,
	controller *NodeAgentServiceController,
	state WindowsInstallState,
	target CurrentDescriptor,
) {
	t.Helper()
	journal, err := NewWindowsRuntimeUninstallJournal(state)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := store.acquireInstallerLock()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lock.Close(); err != nil {
			t.Error(err)
		}
	}()
	root, err := store.openRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := advanceWindowsRuntimeUninstallJournalLocked(root, store.directory, nil, journal); err != nil {
		t.Fatal(err)
	}
	operations := &productionWindowsRuntimeUninstallOperations{
		journal: journal, root: root, directory: store.directory,
		layout: layout, gate: gate, service: controller,
	}
	writer := &lockedWindowsRuntimeUninstallJournalWriter{root: root, directory: store.directory}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	completed, err := advanceWindowsRuntimeUninstall(ctx, writer, operations, journal)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Phase != WindowsUninstallStateDeactivated {
		t.Fatalf("native Windows runtime-uninstall phase = %q", completed.Phase)
	}
	if err := finalizeWindowsRuntimeUninstallLocked(root, store.directory, completed); err != nil {
		t.Fatal(err)
	}
	if err := layout.InspectPublishedRelease(target); err != nil {
		t.Fatalf("native Windows retained release proof after journal finalization: %v", err)
	}
}

func writeNativeWindowsOfflineSnapshot(t *testing.T, testRoot, label string, bundle onlinerelease.Bundle, artifactPath, actorSID string) string {
	t.Helper()
	bundleRaw, err := onlinerelease.Encode(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(testRoot, "offline-bundle-"+label+"-input.json")
	writeNativeWindowsPrivateFile(t, bundlePath, bundleRaw, actorSID)
	directory := filepath.Join(testRoot, "offline-snapshot-"+label)
	prepared, err := PrepareProductionWindowsSnapshot(context.Background(), bundlePath, artifactPath, directory)
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := readAuthenticatedWindowsCandidate(artifactPath, actorSID)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(inspection)
	if prepared.Directory != directory || prepared.Architecture != runtime.GOARCH || prepared.ArtifactSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("native prepared Windows snapshot = %+v", prepared)
	}
	return directory
}

func writeNativeWindowsPrivateFile(t *testing.T, path string, raw []byte, actorSID string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	protectErr := windowssecurity.ProtectPrivateFileForActor(file, windowssecurity.RegularFile, actorSID)
	written, writeErr := file.Write(raw)
	syncErr := file.Sync()
	inspectErr := windowssecurity.InspectPrivateFileSingleLinkForActor(file, windowssecurity.RegularFile, actorSID)
	closeErr := file.Close()
	if protectErr != nil || writeErr != nil || written != len(raw) || syncErr != nil || inspectErr != nil || closeErr != nil {
		t.Fatalf(
			"write native Windows private file: protect=%v write=%v bytes=%d/%d sync=%v inspect=%v close=%v",
			protectErr, writeErr, written, len(raw), syncErr, inspectErr, closeErr,
		)
	}
}

func prepareNativeWindowsCandidate(t *testing.T, testRoot, label, bundlePath, actorSID string) (windowsbundle.CandidateInspection, string) {
	t.Helper()
	file, err := os.Open(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > windowsbundle.MaxArchiveSize {
		t.Fatalf("native Windows bundle size=%d error=%v", info.Size(), err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, windowsbundle.MaxArchiveSize+1))
	if err != nil || int64(len(raw)) != info.Size() {
		t.Fatalf("read native Windows bundle: %v", err)
	}
	expanded, err := windowsbundle.InspectCandidateArchive(raw)
	if err != nil {
		t.Fatal(err)
	}
	intakeDirectory := filepath.Join(testRoot, "intake-"+label)
	if err := ensureProtectedDirectory(intakeDirectory, actorSID); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(intakeDirectory, "candidate.tar")
	private, err := os.OpenFile(privatePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	protectErr := windowssecurity.ProtectPrivateFileForActor(private, windowssecurity.RegularFile, actorSID)
	written, writeErr := private.Write(raw)
	syncErr := private.Sync()
	closeErr := private.Close()
	if protectErr != nil || writeErr != nil || written != len(raw) || syncErr != nil || closeErr != nil {
		t.Fatalf("prepare protected native Windows bundle: protect=%v write=%v bytes=%d/%d sync=%v close=%v", protectErr, writeErr, written, len(raw), syncErr, closeErr)
	}
	return expanded.Inspection, privatePath
}

func testNativeDACLAndReparseRejection(t *testing.T, rootPath, protectedParent string) {
	t.Helper()
	probe := filepath.Join(protectedParent, "dacl-probe")
	if err := os.WriteFile(probe, []byte("probe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(probe)
	if err != nil {
		t.Fatal(err)
	}
	if err := windowssecurity.ProtectPrivatePath(probe, info, windowssecurity.RegularFile, windowssecurity.LocalSystemSID); err != nil {
		t.Fatal(err)
	}
	setNativeBroadDACL(t, probe)
	if err := windowssecurity.InspectPrivatePathForActor(probe, info, windowssecurity.RegularFile, windowssecurity.LocalSystemSID); err == nil {
		t.Fatal("native Windows DACL drift was accepted")
	}
	if err := windowssecurity.ProtectPrivatePath(probe, info, windowssecurity.RegularFile, windowssecurity.LocalSystemSID); err != nil {
		t.Fatal(err)
	}
	link := rootPath + "-reparse"
	if err := os.Symlink(rootPath, link); err != nil {
		t.Fatalf("create native Windows reparse proof: %v", err)
	}
	defer os.Remove(link)
	if file, err := openNoReparseDirectory(link); err == nil {
		file.Close()
		t.Fatal("native Windows no-reparse walk accepted a directory link")
	}
}

func setNativeBroadDACL(t *testing.T, target string) {
	t.Helper()
	everyone, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		t.Fatal(err)
	}
	entries := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	}}
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(target, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(entries)
}

func assertNativeServiceAbsent(t *testing.T) {
	t.Helper()
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(NodeAgentServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	service.Close()
	t.Fatalf("refusing native lifecycle proof because service %q already exists", NodeAgentServiceName)
}

func reflectWindowsJournal(left, right WindowsActivationJournal) bool {
	leftRaw, leftErr := MarshalWindowsActivationJournal(left)
	rightRaw, rightErr := MarshalWindowsActivationJournal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}
