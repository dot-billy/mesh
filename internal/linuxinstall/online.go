//go:build linux

package linuxinstall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"mesh/internal/installtrust"
	"mesh/internal/linuxbundle"
	"mesh/internal/onlinerelease"
	releasetrust "mesh/internal/release"
)

type onlineReleaseFetcher interface {
	FetchBundle(context.Context, string) (onlinerelease.Bundle, error)
	FetchArtifact(context.Context, releasetrust.Artifact, *os.File) error
}

type onlineStateLock interface {
	Load() (State, bool, error)
	Close() error
}

type onlineInstallBoundary struct {
	stateDirectory  string
	statePath       string
	intakeDirectory string

	verifyProduction     func() error
	now                  func() time.Time
	ensureStateDirectory func(string) error
	acquireIntake        func(string, uint32) (*onlineIntakeLock, error)
	closeIntake          func(*onlineIntakeLock) error
	applyRootUpdates     func([][]byte, time.Time) error
	acquireStateLock     func(string) (onlineStateLock, error)
	verifyCandidate      func(SignedMetadata, *State, time.Time) (CandidateMetadata, error)
	materializeSnapshot  func(*onlineWorkspace, onlinerelease.Bundle, *os.File) (string, error)
	applySnapshot        func(context.Context, string, time.Time) (InstallResult, error)
	cleanupWorkspace     func(*onlineWorkspace) error
}

func ApplyOnline(ctx context.Context, bundleURL string) (InstallResult, error) {
	return applyOnlineUsing(ctx, bundleURL, onlinerelease.NewClient(), productionOnlineInstallBoundary())
}

func productionOnlineInstallBoundary() onlineInstallBoundary {
	return onlineInstallBoundary{
		stateDirectory:  ProductionStateDirectory,
		statePath:       ProductionStatePath,
		intakeDirectory: productionOnlineIntakeDirectory,
		verifyProduction: func() error {
			_, err := verifyProductionBoundary()
			return err
		},
		now:                  time.Now,
		ensureStateDirectory: EnsureStateDirectory,
		acquireIntake:        acquireOnlineIntake,
		closeIntake: func(lock *onlineIntakeLock) error {
			return lock.Close()
		},
		applyRootUpdates: applyProductionOnlineRootUpdates,
		acquireStateLock: func(path string) (onlineStateLock, error) {
			store, err := NewStateStore(path)
			if err != nil {
				return nil, err
			}
			return store.AcquireLock()
		},
		verifyCandidate: verifySignedCandidateAt,
		materializeSnapshot: func(workspace *onlineWorkspace, bundle onlinerelease.Bundle, artifact *os.File) (string, error) {
			return workspace.materializeSnapshot(bundle, artifact)
		},
		applySnapshot: applySnapshotAt,
		cleanupWorkspace: func(workspace *onlineWorkspace) error {
			return workspace.remove()
		},
	}
}

func applyOnlineUsing(ctx context.Context, bundleURL string, fetcher onlineReleaseFetcher, boundary onlineInstallBoundary) (result InstallResult, returnErr error) {
	defer func() {
		if returnErr != nil {
			result = InstallResult{}
		}
	}()
	canonicalURL, err := onlinerelease.CanonicalBundleURL(bundleURL)
	if err != nil {
		return result, onlineStageError("validate bundle URL", err)
	}
	if ctx == nil {
		return result, onlineStageError("validate bundle URL", errors.New("context is nil"))
	}
	if fetcher == nil {
		return result, onlineStageError("fetch metadata", errors.New("online release fetcher is nil"))
	}
	if err := validateOnlineInstallBoundary(boundary); err != nil {
		return result, err
	}
	updateStart := boundary.now().UTC()
	if updateStart.IsZero() {
		return result, onlineStageError("record update start", errors.New("update start time is zero"))
	}
	if err := boundary.verifyProduction(); err != nil {
		return result, onlineStageError("verify production installer boundary", err)
	}
	if err := boundary.ensureStateDirectory(boundary.stateDirectory); err != nil {
		return result, onlineStageError("prepare fixed installer state", err)
	}
	intake, err := boundary.acquireIntake(boundary.intakeDirectory, uint32(os.Geteuid()))
	if err != nil {
		return result, onlineStageError("clean online intake", err)
	}
	defer func() {
		if err := boundary.closeIntake(intake); err != nil {
			returnErr = errors.Join(returnErr, onlineStageError("clean online intake", err))
		}
	}()
	if err := intake.reconcile(); err != nil {
		return result, onlineStageError("clean online intake", err)
	}

	bundle, err := fetcher.FetchBundle(ctx, canonicalURL)
	if err != nil {
		return result, onlineStageError("fetch metadata", err)
	}
	encoded, err := onlinerelease.Encode(bundle)
	if err != nil {
		return result, onlineStageError("decode online bundle", err)
	}
	bundle, err = onlinerelease.Parse(encoded)
	if err != nil {
		return result, onlineStageError("decode online bundle", err)
	}
	if err := boundary.applyRootUpdates(bundle.RootUpdates, updateStart); err != nil {
		return result, onlineStageError("advance trusted release roots", err)
	}

	candidate, err := authenticateOnlineCandidate(boundary, SignedMetadata{
		ChannelManifest: bundle.ChannelManifest, ChannelSignatures: bundle.ChannelSignatures,
		ReleaseManifest: bundle.ReleaseManifest, ReleaseSignatures: bundle.ReleaseSignatures,
	}, updateStart)
	if err != nil {
		return result, onlineStageError("authenticate candidate before artifact", err)
	}
	artifact := candidate.Artifact

	workspace, err := intake.newWorkspace()
	if err != nil {
		return result, onlineStageError("clean online intake", err)
	}
	defer func() {
		if err := boundary.cleanupWorkspace(workspace); err != nil {
			returnErr = errors.Join(returnErr, onlineStageError("clean online intake", err))
		}
	}()
	artifactFile, err := workspace.openArtifact()
	if err != nil {
		return result, onlineStageError("fetch artifact", err)
	}
	defer func() {
		if err := artifactFile.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			returnErr = errors.Join(returnErr, onlineStageError("clean online intake", fmt.Errorf("close artifact descriptor: %w", err)))
		}
	}()
	if err := fetcher.FetchArtifact(ctx, artifact, artifactFile); err != nil {
		return result, onlineStageError("fetch artifact", err)
	}
	snapshotPath, err := boundary.materializeSnapshot(workspace, bundle, artifactFile)
	if err != nil {
		return result, onlineStageError("materialize offline snapshot", err)
	}
	result, err = boundary.applySnapshot(ctx, snapshotPath, updateStart)
	if err != nil {
		return result, onlineStageError("apply authenticated snapshot", err)
	}
	return result, nil
}

// applyProductionOnlineRootUpdates advances the append-only trust history
// before any artifact request. It takes locks in the same root-then-state order
// as ApplySnapshot so a one-time v2 state migration cannot race past root v1.
func applyProductionOnlineRootUpdates(rawUpdates [][]byte, updateStart time.Time) (returnErr error) {
	bootstrap, err := installtrust.LoadBootstrap()
	if err != nil {
		return fmt.Errorf("load compiled installer trust: %w", err)
	}
	return applyOnlineRootUpdatesUsing(rawUpdates, updateStart, onlineRootAdvanceConfig{
		rootDirectory: productionRootStoreDirectory,
		statePath:     ProductionStatePath,
		uid:           uint32(os.Geteuid()),
		bootstrap:     bootstrap,
	})
}

type onlineRootAdvanceConfig struct {
	rootDirectory string
	statePath     string
	uid           uint32
	bootstrap     installtrust.Bootstrap
}

func applyOnlineRootUpdatesUsing(rawUpdates [][]byte, updateStart time.Time, config onlineRootAdvanceConfig) (returnErr error) {
	if updateStart.IsZero() {
		return errors.New("root update start time is zero")
	}
	if config.rootDirectory == "" || config.statePath == "" || config.bootstrap.SHA256 == "" {
		return errors.New("online root advancement is not configured")
	}
	rootStore, err := NewRootStore(config.rootDirectory, config.uid, config.bootstrap.InitialRoot)
	if err != nil {
		return fmt.Errorf("configure installer root history: %w", err)
	}
	rootLock, err := rootStore.Acquire()
	if err != nil {
		return fmt.Errorf("lock installer root history: %w", err)
	}
	defer func() { returnErr = errors.Join(returnErr, rootLock.Close()) }()

	if err := validateOnlineStateBeforeRootAdvance(rootLock, config.statePath, config.bootstrap); err != nil {
		return err
	}
	if _, err := rootLock.ApplyChain(rawUpdates, updateStart, 0); err != nil {
		return fmt.Errorf("authenticate and persist release-root updates: %w", err)
	}
	return nil
}

func validateOnlineStateBeforeRootAdvance(rootLock *RootStoreLock, statePath string, bootstrap installtrust.Bootstrap) (returnErr error) {
	store, err := NewStateStore(statePath)
	if err != nil {
		return err
	}
	lock, err := store.AcquireLock()
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	state, found, err := lock.Load()
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if state.Schema == LegacyStateSchema {
		empty, err := rootLock.HistoryEmpty()
		if err != nil {
			return err
		}
		state, err = lock.MigrateV2(bootstrap, empty)
		if err != nil {
			return fmt.Errorf("migrate installer state to root-aware schema: %w", err)
		}
	}
	if err := validatePersistedBootstrap(state, bootstrap); err != nil {
		return err
	}
	if state.Pending != nil {
		return errors.New("an unfinished installation exists; run mesh-install recover before advancing release roots")
	}
	return nil
}

func authenticateOnlineCandidate(boundary onlineInstallBoundary, metadata SignedMetadata, updateStart time.Time) (candidate CandidateMetadata, returnErr error) {
	lock, err := boundary.acquireStateLock(boundary.statePath)
	if err != nil {
		return candidate, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	state, found, err := lock.Load()
	if err != nil {
		return candidate, err
	}
	var prior *State
	if found {
		if err := state.Validate(); err != nil {
			return candidate, fmt.Errorf("validate persisted installer state: %w", err)
		}
		if state.Pending != nil {
			return candidate, errors.New("an unfinished installation exists; run mesh-install recover before downloading another artifact")
		}
		prior = &state
	}
	candidate, err = boundary.verifyCandidate(metadata, prior, updateStart)
	if err != nil {
		return CandidateMetadata{}, err
	}
	if err := releasetrust.ValidateArtifactReference(candidate.Artifact); err != nil {
		return CandidateMetadata{}, fmt.Errorf("authenticated artifact reference: %w", err)
	}
	if candidate.Artifact.Size > linuxbundle.MaxArchiveSize {
		return CandidateMetadata{}, fmt.Errorf("authenticated Linux bundle size %d exceeds installer limit %d", candidate.Artifact.Size, linuxbundle.MaxArchiveSize)
	}
	return candidate, nil
}

func validateOnlineInstallBoundary(boundary onlineInstallBoundary) error {
	if boundary.stateDirectory == "" || boundary.statePath == "" || boundary.intakeDirectory == "" ||
		boundary.verifyProduction == nil || boundary.now == nil || boundary.ensureStateDirectory == nil || boundary.acquireIntake == nil || boundary.closeIntake == nil ||
		boundary.applyRootUpdates == nil || boundary.acquireStateLock == nil || boundary.verifyCandidate == nil || boundary.materializeSnapshot == nil || boundary.applySnapshot == nil || boundary.cleanupWorkspace == nil {
		return errors.New("online installer boundary is incomplete")
	}
	return nil
}

type stagedOnlineError struct {
	stage string
	err   error
}

func (err *stagedOnlineError) Error() string {
	return err.stage + ": " + cleanOnlineErrorText(err.err.Error())
}

func (err *stagedOnlineError) Unwrap() error { return err.err }

func onlineStageError(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &stagedOnlineError{stage: stage, err: err}
}
