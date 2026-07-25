//go:build linux

package linuxinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"mesh/internal/agentstate"
	"mesh/internal/installtrust"
	"mesh/internal/onlinerelease"
	releasetrust "mesh/internal/release"
)

const onlineTestBundleURL = "https://releases.example/channels/stable/bundle.json"

func TestApplyOnlineUsesTwoPassOrderAndReturnsFinalResult(t *testing.T) {
	trace := make([]string, 0, 8)
	artifactRaw := []byte("authenticated artifact")
	fetcher := newFakeOnlineFetcher(&trace, artifactRaw)
	candidate := onlineTestCandidate(artifactRaw)
	want := InstallResult{Operation: OperationActivate, AlreadyActive: true, AgentEnabled: true}
	boundary := onlineTestBoundary(t, &trace, candidate, want)

	got, err := applyOnlineUsing(context.Background(), onlineTestBundleURL, fetcher, boundary)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("result = %+v, want %+v", got, want)
	}
	wantTrace := []string{
		"record-time", "fetch-bundle", "apply-roots", "lock-state", "verify-first", "unlock-state",
		"fetch-artifact", "materialize-snapshot", "apply-snapshot", "cleanup",
	}
	if !reflect.DeepEqual(trace, wantTrace) {
		t.Fatalf("trace = %v, want %v", trace, wantTrace)
	}
}

func TestApplyOnlinePersistsAcceptedRootsAcrossEveryLaterFailure(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*onlineInstallBoundary, *fakeOnlineFetcher)
	}{
		{name: "invalid release metadata", change: func(boundary *onlineInstallBoundary, _ *fakeOnlineFetcher) {
			boundary.verifyCandidate = func(SignedMetadata, *State, time.Time) (CandidateMetadata, error) {
				return CandidateMetadata{}, errors.New("revoked release signer")
			}
		}},
		{name: "artifact failure", change: func(_ *onlineInstallBoundary, fetcher *fakeOnlineFetcher) {
			fetcher.artifactErr = errors.New("artifact transport failed")
		}},
		{name: "cancellation", change: func(_ *onlineInstallBoundary, fetcher *fakeOnlineFetcher) {
			fetcher.artifactErr = context.Canceled
		}},
		{name: "materialization failure", change: func(boundary *onlineInstallBoundary, _ *fakeOnlineFetcher) {
			boundary.materializeSnapshot = func(*onlineWorkspace, onlinerelease.Bundle, *os.File) (string, error) {
				return "", errors.New("snapshot fsync failed")
			}
		}},
		{name: "activation failure", change: func(boundary *onlineInstallBoundary, _ *fakeOnlineFetcher) {
			boundary.applySnapshot = func(context.Context, string, time.Time) (InstallResult, error) {
				return InstallResult{}, errors.New("activation rolled back")
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			trace := make([]string, 0)
			artifactRaw := []byte("artifact")
			fetcher := newFakeOnlineFetcher(&trace, artifactRaw)
			config, updates, store := onlineRootAdvanceFixture(t, 2)
			fetcher.bundle.RootUpdates = updates
			boundary := onlineTestBoundary(t, &trace, onlineTestCandidate(artifactRaw), InstallResult{})
			boundary.applyRootUpdates = func(got [][]byte, updateStart time.Time) error {
				trace = append(trace, "apply-roots")
				return applyOnlineRootUpdatesUsing(got, updateStart, config)
			}
			test.change(&boundary, fetcher)

			result, err := applyOnlineUsing(context.Background(), onlineTestBundleURL, fetcher, boundary)
			if err == nil || !reflect.DeepEqual(result, InstallResult{}) {
				t.Fatalf("later failure returned result=%+v err=%v", result, err)
			}
			lock, lockErr := store.Acquire()
			if lockErr != nil {
				t.Fatal(lockErr)
			}
			if got := lock.Current().Document.Version; got != 3 {
				_ = lock.Close()
				t.Fatalf("persisted root version = %d, want 3", got)
			}
			if closeErr := lock.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
		})
	}
}

func TestApplyOnlineRejectsRootAndReleaseTrustFailuresBeforeArtifact(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*testing.T, onlineRootAdvanceConfig, [][]byte) (onlineRootAdvanceConfig, [][]byte, time.Time)
		verifyErr error
	}{
		{name: "insufficient root threshold", configure: func(t *testing.T, config onlineRootAdvanceConfig, updates [][]byte) (onlineRootAdvanceConfig, [][]byte, time.Time) {
			parsed, err := releasetrust.ParseRootUpdate(updates[0])
			if err != nil {
				t.Fatal(err)
			}
			parsed.Signatures = parsed.Signatures[:1]
			raw, err := releasetrust.EncodeRootUpdate(parsed)
			if err != nil {
				t.Fatal(err)
			}
			return config, [][]byte{raw}, time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
		}},
		{name: "root gap", configure: func(_ *testing.T, config onlineRootAdvanceConfig, updates [][]byte) (onlineRootAdvanceConfig, [][]byte, time.Time) {
			return config, updates[1:], time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
		}},
		{name: "root equivocation", configure: func(t *testing.T, config onlineRootAdvanceConfig, updates [][]byte) (onlineRootAdvanceConfig, [][]byte, time.Time) {
			now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
			if err := applyOnlineRootUpdatesUsing(updates[:1], now, config); err != nil {
				t.Fatal(err)
			}
			_, different, _ := onlineRootAdvanceFixture(t, 1)
			return config, different, now
		}},
		{name: "expired final root", configure: func(_ *testing.T, config onlineRootAdvanceConfig, updates [][]byte) (onlineRootAdvanceConfig, [][]byte, time.Time) {
			return config, updates[:1], time.Date(2028, 7, 23, 10, 0, 0, 0, time.UTC)
		}},
		{name: "revoked release signer", verifyErr: errors.New("release signature threshold not met")},
		{name: "wrong release epoch", verifyErr: errors.New("release epoch differs from trusted root")},
	} {
		t.Run(test.name, func(t *testing.T) {
			trace := make([]string, 0)
			fetcher := newFakeOnlineFetcher(&trace, []byte("artifact"))
			config, updates, _ := onlineRootAdvanceFixture(t, 2)
			updateStart := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
			if test.configure != nil {
				config, updates, updateStart = test.configure(t, config, updates)
			}
			fetcher.bundle.RootUpdates = updates
			boundary := onlineTestBoundary(t, &trace, onlineTestCandidate([]byte("artifact")), InstallResult{})
			boundary.now = func() time.Time { return updateStart }
			boundary.applyRootUpdates = func(got [][]byte, fixed time.Time) error {
				return applyOnlineRootUpdatesUsing(got, fixed, config)
			}
			if test.verifyErr != nil {
				boundary.verifyCandidate = func(SignedMetadata, *State, time.Time) (CandidateMetadata, error) {
					return CandidateMetadata{}, test.verifyErr
				}
			}
			result, err := applyOnlineUsing(context.Background(), onlineTestBundleURL, fetcher, boundary)
			if err == nil || fetcher.artifactCalls != 0 || !reflect.DeepEqual(result, InstallResult{}) {
				t.Fatalf("trust failure result=%+v err=%v artifact calls=%d", result, err, fetcher.artifactCalls)
			}
			if _, statErr := os.Lstat(config.statePath); !os.IsNotExist(statErr) {
				t.Fatalf("trust failure mutated installer state: %v", statErr)
			}
		})
	}
}

func TestApplyOnlineAcceptsMaterializerOwnershipOfSealedArtifact(t *testing.T) {
	trace := make([]string, 0, 8)
	artifactRaw := []byte("authenticated artifact")
	fetcher := newFakeOnlineFetcher(&trace, artifactRaw)
	want := InstallResult{Operation: OperationActivate, AlreadyActive: true}
	boundary := onlineTestBoundary(t, &trace, onlineTestCandidate(artifactRaw), want)
	boundary.materializeSnapshot = func(workspace *onlineWorkspace, bundle onlinerelease.Bundle, artifact *os.File) (string, error) {
		trace = append(trace, "materialize-snapshot")
		return workspace.materializeSnapshot(bundle, artifact)
	}

	got, err := applyOnlineUsing(context.Background(), onlineTestBundleURL, fetcher, boundary)
	if err != nil {
		t.Fatalf("real snapshot materialization turned successful descriptor sealing into an error: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("result = %+v, want %+v", got, want)
	}
}

func TestApplyOnlineStopsBeforeArtifactOnAuthenticationAndStateFailures(t *testing.T) {
	artifactRaw := []byte("artifact")
	tests := []struct {
		name   string
		change func(*onlineInstallBoundary, *fakeOnlineFetcher, *[]string)
		match  string
	}{
		{name: "root persistence failure", match: "advance trusted release roots", change: func(boundary *onlineInstallBoundary, _ *fakeOnlineFetcher, trace *[]string) {
			boundary.applyRootUpdates = func([][]byte, time.Time) error {
				*trace = append(*trace, "apply-roots")
				return errors.New("trust store fsync failed")
			}
		}},
		{name: "invalid first verification", match: "authenticate candidate before artifact", change: func(boundary *onlineInstallBoundary, _ *fakeOnlineFetcher, trace *[]string) {
			boundary.verifyCandidate = func(SignedMetadata, *State, time.Time) (CandidateMetadata, error) {
				*trace = append(*trace, "verify-first")
				return CandidateMetadata{}, errors.New("bad\nforged-verifier-line")
			}
		}},
		{name: "pending state", match: "unfinished installation", change: func(boundary *onlineInstallBoundary, _ *fakeOnlineFetcher, _ *[]string) {
			boundary.acquireStateLock = func(string) (onlineStateLock, error) {
				return &fakeOnlineStateLock{state: preparedInitialState(), found: true}, nil
			}
		}},
		{name: "state lock contention", match: "state lock busy", change: func(boundary *onlineInstallBoundary, _ *fakeOnlineFetcher, trace *[]string) {
			boundary.acquireStateLock = func(string) (onlineStateLock, error) {
				*trace = append(*trace, "lock-state")
				return nil, errors.New("state lock busy")
			}
		}},
		{name: "state unlock failure", match: "unlock failed", change: func(boundary *onlineInstallBoundary, _ *fakeOnlineFetcher, trace *[]string) {
			boundary.acquireStateLock = func(string) (onlineStateLock, error) {
				*trace = append(*trace, "lock-state")
				return &fakeOnlineStateLock{trace: trace, closeErr: errors.New("unlock failed")}, nil
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			trace := make([]string, 0)
			fetcher := newFakeOnlineFetcher(&trace, artifactRaw)
			boundary := onlineTestBoundary(t, &trace, onlineTestCandidate(artifactRaw), InstallResult{AlreadyActive: true})
			test.change(&boundary, fetcher, &trace)
			result, err := applyOnlineUsing(context.Background(), onlineTestBundleURL, fetcher, boundary)
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("error = %v, want %q", err, test.match)
			}
			if strings.ContainsAny(err.Error(), "\r\n") {
				t.Fatalf("error contains attacker-controlled line break: %q", err)
			}
			if !reflect.DeepEqual(result, InstallResult{}) {
				t.Fatalf("failure returned success-shaped result %+v", result)
			}
			if fetcher.artifactCalls != 0 || containsOnlineTrace(trace, "materialize-snapshot") || containsOnlineTrace(trace, "apply-snapshot") {
				t.Fatalf("early failure crossed artifact boundary: calls=%d trace=%v", fetcher.artifactCalls, trace)
			}
		})
	}
}

func TestApplyOnlineCleansWorkspaceAfterArtifactOrFinalApplyFailure(t *testing.T) {
	artifactRaw := []byte("artifact")
	t.Run("artifact failure", func(t *testing.T) {
		trace := make([]string, 0)
		fetcher := newFakeOnlineFetcher(&trace, artifactRaw)
		fetcher.artifactErr = errors.New("artifact transport failed")
		boundary := onlineTestBoundary(t, &trace, onlineTestCandidate(artifactRaw), InstallResult{})
		result, err := applyOnlineUsing(context.Background(), onlineTestBundleURL, fetcher, boundary)
		if err == nil || !strings.Contains(err.Error(), "fetch artifact") || !containsOnlineTrace(trace, "cleanup") {
			t.Fatalf("artifact failure result=%+v err=%v trace=%v", result, err, trace)
		}
		if containsOnlineTrace(trace, "materialize-snapshot") || containsOnlineTrace(trace, "apply-snapshot") || !reflect.DeepEqual(result, InstallResult{}) {
			t.Fatalf("artifact failure crossed later phase: result=%+v trace=%v", result, trace)
		}
	})

	t.Run("final apply rejects advanced state", func(t *testing.T) {
		trace := make([]string, 0)
		fetcher := newFakeOnlineFetcher(&trace, artifactRaw)
		advanced := false
		fetcher.afterArtifact = func() { advanced = true }
		boundary := onlineTestBoundary(t, &trace, onlineTestCandidate(artifactRaw), InstallResult{})
		boundary.applySnapshot = func(context.Context, string, time.Time) (InstallResult, error) {
			trace = append(trace, "apply-snapshot")
			if !advanced {
				t.Fatal("final apply did not observe simulated state advance")
			}
			return InstallResult{AlreadyActive: true}, errors.New("candidate stale after state advance")
		}
		result, err := applyOnlineUsing(context.Background(), onlineTestBundleURL, fetcher, boundary)
		if err == nil || !strings.Contains(err.Error(), "apply authenticated snapshot") || !containsOnlineTrace(trace, "cleanup") {
			t.Fatalf("final rejection result=%+v err=%v trace=%v", result, err, trace)
		}
		if !reflect.DeepEqual(result, InstallResult{}) {
			t.Fatalf("final rejection returned success-shaped result %+v", result)
		}
	})
}

func TestApplyOnlineCancellationAndCleanupErrorComposition(t *testing.T) {
	artifactRaw := []byte("artifact")
	t.Run("cancellation reaches artifact fetch", func(t *testing.T) {
		trace := make([]string, 0)
		fetcher := newFakeOnlineFetcher(&trace, artifactRaw)
		fetcher.waitForCancellation = true
		boundary := onlineTestBoundary(t, &trace, onlineTestCandidate(artifactRaw), InstallResult{})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result, err := applyOnlineUsing(ctx, onlineTestBundleURL, fetcher, boundary)
		if !errors.Is(err, context.Canceled) || !containsOnlineTrace(trace, "cleanup") || !reflect.DeepEqual(result, InstallResult{}) {
			t.Fatalf("cancellation result=%+v err=%v trace=%v", result, err, trace)
		}
	})

	t.Run("cleanup error joins primary failure", func(t *testing.T) {
		trace := make([]string, 0)
		primary := errors.New("primary artifact failure")
		cleanup := errors.New("cleanup fsync failure")
		fetcher := newFakeOnlineFetcher(&trace, artifactRaw)
		fetcher.artifactErr = primary
		boundary := onlineTestBoundary(t, &trace, onlineTestCandidate(artifactRaw), InstallResult{})
		boundary.cleanupWorkspace = func(workspace *onlineWorkspace) error {
			trace = append(trace, "cleanup")
			removeErr := workspace.remove()
			return errors.Join(removeErr, cleanup)
		}
		result, err := applyOnlineUsing(context.Background(), onlineTestBundleURL, fetcher, boundary)
		if !errors.Is(err, primary) || !errors.Is(err, cleanup) || !reflect.DeepEqual(result, InstallResult{}) {
			t.Fatalf("joined failure result=%+v err=%v", result, err)
		}
	})
}

func TestApplyOnlineIntakeContentionDoesNotTouchState(t *testing.T) {
	rootPath := filepath.Join(t.TempDir(), "online-intake")
	held, err := acquireOnlineIntake(rootPath, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	trace := make([]string, 0)
	fetcher := newFakeOnlineFetcher(&trace, []byte("artifact"))
	boundary := onlineTestBoundary(t, &trace, onlineTestCandidate([]byte("artifact")), InstallResult{})
	boundary.intakeDirectory = rootPath
	stateTouches := 0
	boundary.acquireStateLock = func(string) (onlineStateLock, error) {
		stateTouches++
		return nil, errors.New("must not be called")
	}
	result, err := applyOnlineUsing(context.Background(), onlineTestBundleURL, fetcher, boundary)
	if err == nil || !strings.Contains(err.Error(), "intake lock") || stateTouches != 0 || fetcher.bundleCalls != 0 || !reflect.DeepEqual(result, InstallResult{}) {
		t.Fatalf("contention result=%+v err=%v stateTouches=%d bundleCalls=%d", result, err, stateTouches, fetcher.bundleCalls)
	}
}

func TestApplyOnlineExactFsyncedCandidateUsesExistingResumeSemantics(t *testing.T) {
	policy, privateKeys := candidateTrust(t)
	issued := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	metadata := candidateMetadata(t, policy, privateKeys, 5, issued, issued.Add(time.Hour), "a")
	accepted, err := verifySignedCandidateWithPolicy(metadata, policy, nil, issued.Add(10*time.Minute), 3)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := accepted.releaseIdentity(
		strings.Repeat("b", 64), "", 3,
		agentstate.CurrentSchemaVersion, agentstate.CurrentSchemaVersion, agentstate.CurrentWriteVersion,
	)
	if err != nil {
		t.Fatal(err)
	}
	prior := State{Schema: LegacyStateSchema, TrustPolicySHA256: policy.SHA256, Channel: policy.Channel, HighWater: identity, Active: &identity}
	trace := make([]string, 0)
	fetcher := newFakeOnlineFetcher(&trace, bytesOfSize(1024))
	fetcher.bundle = onlinerelease.Bundle{
		ChannelManifest: metadata.ChannelManifest, ChannelSignatures: metadata.ChannelSignatures,
		ReleaseManifest: metadata.ReleaseManifest, ReleaseSignatures: metadata.ReleaseSignatures,
	}
	boundary := onlineTestBoundary(t, &trace, CandidateMetadata{}, InstallResult{AlreadyActive: true})
	boundary.acquireStateLock = func(string) (onlineStateLock, error) {
		trace = append(trace, "lock-state")
		return &fakeOnlineStateLock{trace: &trace, state: prior, found: true}, nil
	}
	boundary.verifyCandidate = func(got SignedMetadata, gotPrior *State, updateStart time.Time) (CandidateMetadata, error) {
		trace = append(trace, "verify-first")
		return verifySignedCandidateWithPolicy(got, policy, gotPrior, updateStart, 3)
	}
	if _, err := applyOnlineUsing(context.Background(), onlineTestBundleURL, fetcher, boundary); err != nil {
		t.Fatalf("exact fsynced candidate did not resume through verifier semantics: %v", err)
	}
}

type fakeOnlineFetcher struct {
	trace               *[]string
	bundle              onlinerelease.Bundle
	artifactRaw         []byte
	bundleErr           error
	artifactErr         error
	bundleCalls         int
	artifactCalls       int
	waitForCancellation bool
	afterArtifact       func()
}

func newFakeOnlineFetcher(trace *[]string, artifactRaw []byte) *fakeOnlineFetcher {
	return &fakeOnlineFetcher{trace: trace, bundle: onlineSnapshotTestBundle(), artifactRaw: append([]byte(nil), artifactRaw...)}
}

func (fetcher *fakeOnlineFetcher) FetchBundle(context.Context, string) (onlinerelease.Bundle, error) {
	fetcher.bundleCalls++
	*fetcher.trace = append(*fetcher.trace, "fetch-bundle")
	return fetcher.bundle, fetcher.bundleErr
}

func (fetcher *fakeOnlineFetcher) FetchArtifact(ctx context.Context, _ releasetrust.Artifact, destination *os.File) error {
	fetcher.artifactCalls++
	*fetcher.trace = append(*fetcher.trace, "fetch-artifact")
	if fetcher.waitForCancellation {
		<-ctx.Done()
		return ctx.Err()
	}
	if fetcher.artifactErr != nil {
		return fetcher.artifactErr
	}
	if _, err := destination.Write(fetcher.artifactRaw); err != nil {
		return err
	}
	if err := destination.Sync(); err != nil {
		return err
	}
	if fetcher.afterArtifact != nil {
		fetcher.afterArtifact()
	}
	return nil
}

type fakeOnlineStateLock struct {
	trace    *[]string
	state    State
	found    bool
	loadErr  error
	closeErr error
	closed   bool
}

func (lock *fakeOnlineStateLock) Load() (State, bool, error) {
	return lock.state, lock.found, lock.loadErr
}

func (lock *fakeOnlineStateLock) Close() error {
	if !lock.closed && lock.trace != nil {
		*lock.trace = append(*lock.trace, "unlock-state")
	}
	lock.closed = true
	return lock.closeErr
}

func onlineTestBoundary(t *testing.T, trace *[]string, candidate CandidateMetadata, result InstallResult) onlineInstallBoundary {
	t.Helper()
	root := t.TempDir()
	fixedUpdateStart := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	return onlineInstallBoundary{
		stateDirectory:  filepath.Join(root, "state"),
		statePath:       filepath.Join(root, "state", "state.json"),
		intakeDirectory: filepath.Join(root, "online-intake"),
		verifyProduction: func() error {
			return nil
		},
		now: func() time.Time {
			*trace = append(*trace, "record-time")
			return fixedUpdateStart
		},
		ensureStateDirectory: func(string) error { return nil },
		acquireIntake:        acquireOnlineIntake,
		closeIntake: func(lock *onlineIntakeLock) error {
			return lock.Close()
		},
		applyRootUpdates: func(_ [][]byte, updateStart time.Time) error {
			*trace = append(*trace, "apply-roots")
			if !updateStart.Equal(fixedUpdateStart) {
				t.Fatalf("root update time = %s, want %s", updateStart, fixedUpdateStart)
			}
			return nil
		},
		acquireStateLock: func(string) (onlineStateLock, error) {
			*trace = append(*trace, "lock-state")
			return &fakeOnlineStateLock{trace: trace}, nil
		},
		verifyCandidate: func(_ SignedMetadata, _ *State, updateStart time.Time) (CandidateMetadata, error) {
			*trace = append(*trace, "verify-first")
			if !updateStart.Equal(fixedUpdateStart) {
				t.Fatalf("release verification time = %s, want %s", updateStart, fixedUpdateStart)
			}
			return candidate, nil
		},
		materializeSnapshot: func(workspace *onlineWorkspace, _ onlinerelease.Bundle, _ *os.File) (string, error) {
			*trace = append(*trace, "materialize-snapshot")
			return workspace.path, nil
		},
		applySnapshot: func(_ context.Context, _ string, updateStart time.Time) (InstallResult, error) {
			*trace = append(*trace, "apply-snapshot")
			if !updateStart.Equal(fixedUpdateStart) {
				t.Fatalf("privileged apply time = %s, want %s", updateStart, fixedUpdateStart)
			}
			return result, nil
		},
		cleanupWorkspace: func(workspace *onlineWorkspace) error {
			*trace = append(*trace, "cleanup")
			return workspace.remove()
		},
	}
}

func onlineRootAdvanceFixture(t *testing.T, count int) (onlineRootAdvanceConfig, [][]byte, *RootStore) {
	t.Helper()
	initial, updates := rootStoreFixture(t, count)
	initialRaw, err := releasetrust.EncodeRoot(initial.Document)
	if err != nil {
		t.Fatal(err)
	}
	_, bootstrap, err := installtrust.EncodeBootstrap(installtrust.BootstrapSpec{InitialRoot: initialRaw})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	stateDirectory := filepath.Join(root, "state")
	if err := EnsureStateDirectory(stateDirectory); err != nil {
		t.Fatal(err)
	}
	config := onlineRootAdvanceConfig{
		rootDirectory: filepath.Join(root, "trust"),
		statePath:     filepath.Join(stateDirectory, "state.json"),
		uid:           uint32(os.Geteuid()),
		bootstrap:     bootstrap,
	}
	store, err := NewRootStore(config.rootDirectory, config.uid, bootstrap.InitialRoot)
	if err != nil {
		t.Fatal(err)
	}
	return config, updates, store
}

func onlineTestCandidate(artifactRaw []byte) CandidateMetadata {
	digest := sha256.Sum256(artifactRaw)
	return CandidateMetadata{Artifact: releasetrust.Artifact{
		OS: "linux", Arch: "amd64", URL: "https://releases.example/artifact.tar",
		Size: int64(len(artifactRaw)), SHA256: hex.EncodeToString(digest[:]),
	}}
}

func containsOnlineTrace(trace []string, want string) bool {
	for _, value := range trace {
		if value == want {
			return true
		}
	}
	return false
}

func bytesOfSize(size int) []byte {
	return []byte(strings.Repeat("a", size))
}
