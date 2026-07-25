//go:build windows

package windowsinstall

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"time"

	"mesh/internal/onlinerelease"
	releasetrust "mesh/internal/release"
	"mesh/internal/windowsbundle"
)

// AcceptWindowsCandidate advances authenticated root history, verifies the
// signed channel/release decision, and durably records that exact decision
// under one cross-process installer lock. No artifact bytes are trusted here.
func (store *ActivationJournalStore) AcceptWindowsCandidate(
	compiledRoot releasetrust.ParsedRoot,
	bundle onlinerelease.Bundle,
	bootstrapTrustSHA256 string,
	now time.Time,
	rootClockSkew time.Duration,
	supportedSecurityFloor uint64,
	arch string,
) (result VerifiedWindowsIntake, returnErr error) {
	if store == nil {
		return result, errors.New("Windows installer store is required")
	}
	initial, err := canonicalWindowsRoot(compiledRoot)
	if err != nil {
		return result, err
	}
	if bootstrapTrustSHA256 != initial.SHA256 {
		return result, errors.New("Windows installer bootstrap digest differs from the compiled root")
	}
	encoded, err := onlinerelease.Encode(bundle)
	if err != nil {
		return result, fmt.Errorf("validate Windows online release bundle: %w", err)
	}
	exact, err := onlinerelease.Parse(encoded)
	if err != nil {
		return result, fmt.Errorf("canonicalize Windows online release bundle: %w", err)
	}
	metadata := windowsMetadataFromOnlineBundle(exact)
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := store.acquireInstallerLock()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	root, err := store.openRoot()
	if err != nil {
		return result, err
	}
	defer root.Close()
	if err := rejectWindowsCandidateAcceptanceDuringActivation(root); err != nil {
		return result, err
	}
	existing, err := store.recoverWindowsAcceptedIntakeLocked(root)
	if err != nil {
		return result, err
	}
	if existing != nil {
		if !bytes.Equal([]byte(existing.OnlineBundle), encoded) {
			return result, errors.New("an unrelated Windows accepted intake must finish before authenticating another candidate")
		}
		return verifyExistingWindowsIntakeLocked(root, store.directory, initial, *existing, supportedSecurityFloor, arch)
	}
	rootResult, err := store.applyWindowsRootUpdatesLocked(root, initial, exact.RootUpdates, now, rootClockSkew)
	if err != nil {
		return result, err
	}
	completeChain, err := releasetrust.EvaluateRootChain(initial, exact.RootUpdates, now, rootClockSkew)
	if err != nil || !sameWindowsTrustedRoot(completeChain.Root, rootResult.Root) {
		return result, errors.Join(err, errors.New("Windows online bundle does not reproduce the complete trusted-root history"))
	}
	current, versions, err := replayWindowsRootHistory(root, initial)
	if err != nil || !sameWindowsTrustedRoot(current, rootResult.Root) {
		return result, errors.Join(err, errors.New("Windows trusted root changed before candidate verification"))
	}
	state, err := recoverWindowsInstallStateLocked(root, store.directory)
	if err != nil {
		return result, err
	}
	authority, err := selectWindowsMetadataAuthority(metadata, current, versions, state)
	if err != nil {
		return result, err
	}
	candidate, err := VerifyWindowsCandidateWithRoots(
		metadata, bootstrapTrustSHA256, current, authority, state, now,
		supportedSecurityFloor, arch,
	)
	if err != nil {
		return result, err
	}
	result = VerifiedWindowsIntake{Candidate: candidate, InstallerBootstrapRootSHA256: bootstrapTrustSHA256}
	if err := store.persistWindowsAcceptedIntakeLocked(root, exact, result); err != nil {
		return VerifiedWindowsIntake{}, err
	}
	return result, nil
}

func verifyExistingWindowsIntakeLocked(
	root *os.Root,
	directory string,
	initial releasetrust.ParsedRoot,
	record WindowsIntakeRecord,
	supportedSecurityFloor uint64,
	arch string,
) (VerifiedWindowsIntake, error) {
	want, err := record.Intake()
	if err != nil {
		return VerifiedWindowsIntake{}, err
	}
	if want.InstallerBootstrapRootSHA256 != initial.SHA256 || want.Candidate.Artifact.Arch != arch {
		return VerifiedWindowsIntake{}, errors.New("Windows accepted-intake retry differs from compiled trust or architecture")
	}
	bundle, err := record.Bundle()
	if err != nil {
		return VerifiedWindowsIntake{}, err
	}
	metadata := windowsMetadataFromOnlineBundle(bundle)
	current, versions, err := replayWindowsRootHistory(root, initial)
	if err != nil {
		return VerifiedWindowsIntake{}, err
	}
	authority, ok := versions[want.Candidate.TrustedRootVersion]
	if !ok || authority.SHA256 != want.Candidate.TrustedRootSHA256 {
		return VerifiedWindowsIntake{}, errors.New("Windows accepted-intake root authority is absent from authenticated history")
	}
	state, err := recoverWindowsInstallStateLocked(root, directory)
	if err != nil {
		return VerifiedWindowsIntake{}, err
	}
	verificationTime, err := parseWindowsCanonicalTime(want.Candidate.VerifiedAt)
	if err != nil {
		return VerifiedWindowsIntake{}, err
	}
	completeChain, err := releasetrust.EvaluateRootChain(initial, bundle.RootUpdates, verificationTime, 0)
	if err != nil || !sameWindowsTrustedRoot(completeChain.Root, current) {
		return VerifiedWindowsIntake{}, errors.Join(err, errors.New("persisted Windows online bundle does not reproduce trusted-root history"))
	}
	candidate, err := VerifyWindowsCandidateWithRoots(
		metadata, initial.SHA256, current, authority, state, verificationTime,
		supportedSecurityFloor, arch,
	)
	if err != nil {
		return VerifiedWindowsIntake{}, err
	}
	got := VerifiedWindowsIntake{Candidate: candidate, InstallerBootstrapRootSHA256: initial.SHA256}
	if !reflect.DeepEqual(got, want) {
		return VerifiedWindowsIntake{}, errors.New("Windows accepted-intake retry differs from its durable trust decision")
	}
	return got, nil
}

func selectWindowsMetadataAuthority(metadata WindowsSignedMetadata, current releasetrust.ParsedRoot, versions map[uint64]releasetrust.ParsedRoot, state *WindowsInstallState) (releasetrust.ParsedRoot, error) {
	if state == nil {
		return current, nil
	}
	channelDigest, releaseDigest, err := windowsSignedMetadataDigests(metadata)
	if err != nil {
		return releasetrust.ParsedRoot{}, err
	}
	if channelDigest != state.HighWater.ChannelManifestSHA256 || releaseDigest != state.HighWater.ReleaseManifestSHA256 {
		return current, nil
	}
	authority, ok := versions[state.HighWater.TrustedRootVersion]
	if !ok || authority.SHA256 != state.HighWater.TrustedRootSHA256 {
		return releasetrust.ParsedRoot{}, errors.New("accepted Windows release root is absent from authenticated history")
	}
	return authority, nil
}

func rejectWindowsCandidateAcceptanceDuringActivation(root *os.Root) error {
	if err := rejectWindowsMutationDuringRuntimeUninstallLocked(root); err != nil {
		return err
	}
	live, err := readWindowsActivationJournal(root, windowsActivationJournalName)
	if err != nil {
		return err
	}
	pending, err := readWindowsActivationJournal(root, windowsActivationJournalPendingName)
	if err != nil {
		return err
	}
	if live != nil || pending != nil {
		return errors.New("Windows candidate cannot be accepted during an active installer transaction")
	}
	return nil
}

// commitAcceptedWindowsAuthority is retained for the native recovery harness;
// production callers use PublishAcceptedWindowsIntake so high-water commit and
// deterministic stage recovery cannot be separated.
func (store *ActivationJournalStore) commitAcceptedWindowsAuthority(intake VerifiedWindowsIntake, inspection windowsbundle.CandidateInspection) (authority AuthenticatedWindowsRelease, next WindowsInstallState, returnErr error) {
	if store == nil {
		return authority, next, errors.New("Windows installer store is required")
	}
	if _, err := intake.Complete(inspection); err != nil {
		return authority, next, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := store.acquireInstallerLock()
	if err != nil {
		return authority, next, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	root, err := store.openRoot()
	if err != nil {
		return authority, next, err
	}
	defer root.Close()
	return store.commitAcceptedWindowsAuthorityLocked(root, intake, inspection)
}

func (store *ActivationJournalStore) commitAcceptedWindowsAuthorityLocked(root *os.Root, intake VerifiedWindowsIntake, inspection windowsbundle.CandidateInspection) (authority AuthenticatedWindowsRelease, next WindowsInstallState, returnErr error) {
	if store == nil || root == nil {
		return authority, next, errors.New("Windows installer store and root are required")
	}
	completed, err := intake.Complete(inspection)
	if err != nil {
		return authority, next, err
	}
	record, err := store.recoverWindowsAcceptedIntakeLocked(root)
	if err != nil || record == nil {
		return authority, next, errors.Join(err, errors.New("Windows accepted intake is absent before authority commit"))
	}
	want, err := record.Intake()
	if err != nil || !reflect.DeepEqual(want, intake) {
		return authority, next, errors.Join(err, errors.New("Windows accepted intake differs before authority commit"))
	}
	current, err := recoverWindowsInstallStateLocked(root, store.directory)
	if err != nil {
		return authority, next, err
	}
	if current == nil {
		next = WindowsInstallState{
			Schema: WindowsInstallStateSchema, BootstrapTrustSHA256: completed.InstallerBootstrapRootSHA256,
			Channel: completed.Channel, Arch: completed.Arch, HighWater: completed,
		}
	} else {
		next, err = current.AdvanceHighWater(completed)
		if err != nil {
			return authority, WindowsInstallState{}, err
		}
	}
	if err := commitWindowsInstallStateLocked(root, store.directory, current, next); err != nil {
		return authority, WindowsInstallState{}, err
	}
	return completed, next, nil
}
