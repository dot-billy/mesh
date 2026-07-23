//go:build linux

package linuxinstall

import (
	"context"
	"testing"
	"time"
)

func TestRollbackTargetIsExplicitAndRetrySafe(t *testing.T) {
	active := testRelease(10, "a", "b", 2)
	previous := testRelease(9, "c", "d", 1)
	state := State{Active: &active, Previous: &previous}
	already, err := classifyRollbackTarget(state, previous.InstalledID)
	if err != nil || already {
		t.Fatalf("select previous: already=%t err=%v", already, err)
	}
	completed := State{Active: &previous, Previous: &active}
	already, err = classifyRollbackTarget(completed, previous.InstalledID)
	if err != nil || !already {
		t.Fatalf("retry completed rollback: already=%t err=%v", already, err)
	}
	if _, err := classifyRollbackTarget(state, testRelease(8, "e", "f", 1).InstalledID); err == nil {
		t.Fatal("unrecorded rollback target accepted")
	}
	if _, err := classifyRollbackTarget(state, "previous"); err == nil {
		t.Fatal("noncanonical rollback target accepted")
	}
}

func TestInstallerCompletionProofContextDetachesCancellationAndStaysBounded(t *testing.T) {
	request, cancelRequest := context.WithCancel(context.Background())
	cancelRequest()
	proof, cancelProof := newInstallerCompletionProofContext(request)
	defer cancelProof()
	if err := proof.Err(); err != nil {
		t.Fatalf("completion proof inherited request cancellation: %v", err)
	}
	deadline, ok := proof.Deadline()
	if !ok {
		t.Fatal("completion proof has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > installerCompletionProofTimeout {
		t.Fatalf("completion proof deadline remaining=%s", remaining)
	}
}

func TestInstallResultReportsRuntimeGateState(t *testing.T) {
	var result InstallResult
	setInstallResultServices(&result, ServiceSnapshot{
		AgentWasEnabled: true, AgentWasActive: true,
		NebulaWasActive: true, RuntimeGateWasOpen: true,
	})
	if !result.AgentEnabled || !result.AgentActive || !result.NebulaActive || !result.RuntimeGateOpen {
		t.Fatalf("service result is incomplete: %+v", result)
	}
}
