//go:build darwin

package darwininstall

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"mesh/internal/buildinfo"
	"mesh/internal/installtrust"
	"mesh/internal/onlinerelease"
	releasetrust "mesh/internal/release"
)

// AuthenticateProductionDarwinCandidate binds untrusted online transport to
// the release root and build identity compiled into this installer. Root
// updates, persisted authority, and journal quiescence are all proved under
// the one installer transaction lock.
func (store *InstallerJournalStore) AuthenticateProductionDarwinCandidate(bundle onlinerelease.Bundle, now time.Time) (VerifiedDarwinIntake, error) {
	bootstrap, err := installtrust.LoadBootstrap()
	if err != nil {
		return VerifiedDarwinIntake{}, fmt.Errorf("load compiled Darwin installer trust: %w", err)
	}
	build, err := buildinfo.CurrentProduction()
	if err != nil {
		return VerifiedDarwinIntake{}, fmt.Errorf("load compiled Darwin installer identity: %w", err)
	}
	return store.authenticateDarwinCandidateUsing(bundle, now, bootstrap, build)
}

// LoadProductionDarwinIntake recovers the one previously accepted metadata
// decision. The cached candidate is reproduced from its exact signed bytes at
// the original verification time before it is returned.
func (store *InstallerJournalStore) LoadProductionDarwinIntake() (VerifiedDarwinIntake, bool, error) {
	bootstrap, err := installtrust.LoadBootstrap()
	if err != nil {
		return VerifiedDarwinIntake{}, false, fmt.Errorf("load compiled Darwin installer trust: %w", err)
	}
	build, err := buildinfo.CurrentProduction()
	if err != nil {
		return VerifiedDarwinIntake{}, false, fmt.Errorf("load compiled Darwin installer identity: %w", err)
	}
	return store.loadDarwinIntakeUsing(bootstrap, build)
}

func (store *InstallerJournalStore) authenticateDarwinCandidateUsing(bundle onlinerelease.Bundle, now time.Time, bootstrap installtrust.Bootstrap, build buildinfo.Info) (result VerifiedDarwinIntake, returnErr error) {
	if store == nil {
		return result, errors.New("Darwin installer journal store is required")
	}
	if build.OS != "darwin" || build.Arch != "amd64" && build.Arch != "arm64" {
		return result, errors.New("Mesh Darwin installation is supported only on darwin/amd64 and darwin/arm64")
	}
	if build.SecurityFloor == 0 || now.IsZero() {
		return result, errors.New("Darwin installer build floor and verification time are required")
	}
	if bootstrap.InitialRootSHA256 == "" || bootstrap.InitialRoot.SHA256 != bootstrap.InitialRootSHA256 {
		return result, errors.New("compiled Darwin installer root identity is inconsistent")
	}
	encoded, err := onlinerelease.Encode(bundle)
	if err != nil {
		return result, fmt.Errorf("validate Darwin online release bundle: %w", err)
	}
	exact, err := onlinerelease.Parse(encoded)
	if err != nil {
		return result, fmt.Errorf("canonicalize Darwin online release bundle: %w", err)
	}
	lock, err := store.AcquireLock()
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	if _, found, err := lock.Load(); err != nil {
		return result, err
	} else if found {
		return result, errors.New("an unfinished Darwin installer transaction must be resumed before authenticating another candidate")
	}
	record, recordFound, err := lock.LoadIntakeRecord()
	if err != nil {
		return result, err
	}
	state, stateFound, err := lock.LoadInstallState()
	if err != nil {
		return result, err
	}
	if stateFound && (state.BootstrapTrustSHA256 != bootstrap.InitialRootSHA256 || state.Channel != bootstrap.InitialRoot.Document.Channel || state.Arch != build.Arch) {
		return result, errors.New("persisted Darwin installer state differs from compiled trust, channel, or architecture")
	}
	currentRoot, err := lock.LoadTrustedRoot(bootstrap.InitialRoot)
	if err != nil {
		return result, err
	}
	if recordFound {
		if !bytes.Equal([]byte(record.OnlineBundle), encoded) {
			return result, errors.New("an unrelated Darwin accepted intake must finish before authenticating another candidate")
		}
		return verifyPersistedDarwinIntake(lock, record, bootstrap, build, currentRoot, state, stateFound)
	}
	rootResult, err := lock.ApplyTrustedRootUpdates(exact.RootUpdates, now, 0)
	if err != nil {
		return result, fmt.Errorf("authenticate and persist Darwin release-root updates: %w", err)
	}
	metadata := DarwinSignedMetadata{
		ChannelManifest: exact.ChannelManifest, ChannelSignatures: exact.ChannelSignatures,
		ReleaseManifest: exact.ReleaseManifest, ReleaseSignatures: exact.ReleaseSignatures,
	}
	authority := rootResult.Root
	if stateFound {
		channelDigest, releaseDigest, digestErr := darwinSignedMetadataDigests(metadata)
		if digestErr != nil {
			return result, digestErr
		}
		if channelDigest == state.HighWater.ChannelManifestSHA256 && releaseDigest == state.HighWater.ReleaseManifestSHA256 &&
			(state.HighWater.TrustedRootVersion != authority.Document.Version || state.HighWater.TrustedRootSHA256 != authority.SHA256) {
			authority, err = lock.TrustedRootVersion(state.HighWater.TrustedRootVersion)
			if err != nil {
				return result, fmt.Errorf("load recorded historical Darwin release root: %w", err)
			}
			if authority.SHA256 != state.HighWater.TrustedRootSHA256 {
				return result, errors.New("recorded historical Darwin release-root digest differs from persisted history")
			}
		}
	}
	var prior *DarwinInstallState
	if stateFound {
		prior = &state
	}
	candidate, err := VerifyDarwinCandidateWithRoots(
		metadata, bootstrap.InitialRootSHA256, rootResult.Root, authority, prior, now, build.SecurityFloor, build.Arch,
	)
	if err != nil {
		return result, fmt.Errorf("authenticate Darwin release candidate: %w", err)
	}
	result = VerifiedDarwinIntake{
		Candidate: candidate, InstallerBootstrapRootSHA256: bootstrap.InitialRootSHA256,
	}
	record, err = NewDarwinIntakeRecord(exact, result)
	if err != nil {
		return VerifiedDarwinIntake{}, err
	}
	if err := lock.CommitIntakeRecord(record); err != nil {
		return VerifiedDarwinIntake{}, fmt.Errorf("persist accepted Darwin intake: %w", err)
	}
	return result, nil
}

func (store *InstallerJournalStore) loadDarwinIntakeUsing(bootstrap installtrust.Bootstrap, build buildinfo.Info) (result VerifiedDarwinIntake, found bool, returnErr error) {
	if store == nil {
		return result, false, errors.New("Darwin installer journal store is required")
	}
	if build.OS != "darwin" || build.Arch != "amd64" && build.Arch != "arm64" || build.SecurityFloor == 0 {
		return result, false, errors.New("compiled Darwin installer identity is invalid")
	}
	if bootstrap.InitialRootSHA256 == "" || bootstrap.InitialRoot.SHA256 != bootstrap.InitialRootSHA256 {
		return result, false, errors.New("compiled Darwin installer root identity is inconsistent")
	}
	lock, err := store.AcquireLock()
	if err != nil {
		return result, false, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	if _, active, err := lock.Load(); err != nil {
		return result, false, err
	} else if active {
		return result, false, errors.New("an unfinished Darwin installer transaction must be resumed before loading accepted intake")
	}
	record, found, err := lock.LoadIntakeRecord()
	if err != nil || !found {
		return result, found, err
	}
	state, stateFound, err := lock.LoadInstallState()
	if err != nil {
		return result, false, err
	}
	currentRoot, err := lock.LoadTrustedRoot(bootstrap.InitialRoot)
	if err != nil {
		return result, false, err
	}
	result, err = verifyPersistedDarwinIntake(lock, record, bootstrap, build, currentRoot, state, stateFound)
	return result, true, err
}

func verifyPersistedDarwinIntake(lock *InstallerJournalLock, record DarwinIntakeRecord, bootstrap installtrust.Bootstrap, build buildinfo.Info, currentRoot releasetrust.ParsedRoot, state DarwinInstallState, stateFound bool) (VerifiedDarwinIntake, error) {
	if record.InstallerBootstrapRootSHA256 != bootstrap.InitialRootSHA256 || record.Candidate.Artifact.Arch != build.Arch {
		return VerifiedDarwinIntake{}, errors.New("accepted Darwin intake differs from compiled trust or architecture")
	}
	if stateFound && (state.BootstrapTrustSHA256 != bootstrap.InitialRootSHA256 || state.Channel != bootstrap.InitialRoot.Document.Channel || state.Arch != build.Arch) {
		return VerifiedDarwinIntake{}, errors.New("persisted Darwin installer state differs from compiled trust, channel, or architecture")
	}
	bundle, err := record.Bundle()
	if err != nil {
		return VerifiedDarwinIntake{}, err
	}
	authorityRoot, err := lock.TrustedRootVersion(record.Candidate.TrustedRootVersion)
	if err != nil {
		return VerifiedDarwinIntake{}, fmt.Errorf("load accepted Darwin intake authority root: %w", err)
	}
	if authorityRoot.SHA256 != record.Candidate.TrustedRootSHA256 {
		return VerifiedDarwinIntake{}, errors.New("accepted Darwin intake authority digest differs from persisted root history")
	}
	verifiedAt, err := parseDarwinCanonicalTime(record.Candidate.VerifiedAt)
	if err != nil {
		return VerifiedDarwinIntake{}, err
	}
	var prior *DarwinInstallState
	if stateFound {
		prior = &state
	}
	candidate, err := VerifyDarwinCandidateWithRoots(
		darwinMetadataFromOnlineBundle(bundle), bootstrap.InitialRootSHA256, currentRoot, authorityRoot,
		prior, verifiedAt, build.SecurityFloor, build.Arch,
	)
	if err != nil {
		return VerifiedDarwinIntake{}, fmt.Errorf("reverify accepted Darwin intake: %w", err)
	}
	if candidate != record.Candidate {
		return VerifiedDarwinIntake{}, errors.New("reverified Darwin intake differs from its persisted candidate")
	}
	return VerifiedDarwinIntake{Candidate: candidate, InstallerBootstrapRootSHA256: bootstrap.InitialRootSHA256}, nil
}
