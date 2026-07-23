package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mesh/internal/nodeagent"
)

func TestLoadAgentRecoveryTokenSources(t *testing.T) {
	token := strings.Repeat("t", 42) + "A"
	fromEnvironment, err := loadAgentRecoveryToken("", bytes.NewBufferString("ignored"), token)
	if err != nil || fromEnvironment != token {
		t.Fatalf("environment token = %q, err=%v", fromEnvironment, err)
	}
	fromStdin, err := loadAgentRecoveryToken("-", bytes.NewBufferString(token+"\n"), "")
	if err != nil || fromStdin != token {
		t.Fatalf("stdin token = %q, err=%v", fromStdin, err)
	}
	automaticStdin, err := loadAgentRecoveryToken("", bytes.NewBufferString(token+"\n"), "")
	if err != nil || automaticStdin != token {
		t.Fatalf("automatic stdin token = %q, err=%v", automaticStdin, err)
	}
	if _, err := loadAgentRecoveryToken("-", bytes.NewBufferString(token), token); err == nil || !strings.Contains(err.Error(), "only one") {
		t.Fatalf("multiple token sources returned %v", err)
	}
	if _, err := loadAgentRecoveryToken("-", bytes.NewBufferString("not-a-token"), ""); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("invalid token returned %v", err)
	}
}

func TestLoadAgentRecoveryInputResumeRejectsEveryTokenSource(t *testing.T) {
	token := strings.Repeat("r", 42) + "A"
	if loaded, err := loadAgentRecoveryInput(true, "", nil, ""); err != nil || loaded != "" {
		t.Fatalf("resume input = %q, err=%v", loaded, err)
	}
	for name, test := range map[string]struct {
		tokenFile   string
		input       *bytes.Buffer
		environment string
	}{
		"environment": {environment: token},
		"token file":  {tokenFile: "/private/token"},
		"stdin":       {input: bytes.NewBufferString(token)},
	} {
		t.Run(name, func(t *testing.T) {
			var reader io.Reader
			if test.input != nil {
				reader = test.input
			}
			if _, err := loadAgentRecoveryInput(true, test.tokenFile, reader, test.environment); err == nil || !strings.Contains(err.Error(), "--resume cannot be combined") {
				t.Fatalf("resume conflict returned %v", err)
			}
		})
	}
}

func TestDescribeRecoveryFailureDistinguishesPendingAndCommittedReset(t *testing.T) {
	cause := context.DeadlineExceeded
	pending := nodeagent.State{AgentCredentialGeneration: 4, PendingRecoveryToken: strings.Repeat("p", 42) + "A", PendingBearer: strings.Repeat("b", 42) + "A"}
	err := describeRecoveryFailure(cause, nil, 4, pending, true)
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "--resume") || !strings.Contains(err.Error(), "Nebula remains quarantined") {
		t.Fatalf("pending recovery error=%v", err)
	}

	committed := nodeagent.State{AgentCredentialGeneration: 5}
	err = describeRecoveryFailure(cause, nil, 4, committed, true)
	if !errors.Is(err, cause) || strings.Contains(err.Error(), "--resume") || !strings.Contains(err.Error(), "durably committed") || !strings.Contains(err.Error(), "start mesh-agent.service") {
		t.Fatalf("committed recovery error=%v", err)
	}

	unchanged := nodeagent.State{AgentCredentialGeneration: 4}
	err = describeRecoveryFailure(cause, nil, 4, unchanged, true)
	if !errors.Is(err, cause) || strings.Contains(err.Error(), "--resume") || strings.Contains(err.Error(), "durably committed") {
		t.Fatalf("unchanged recovery error=%v", err)
	}
}

func TestDescribeRecoveryFailureReplacesOnlyRejectedPendingToken(t *testing.T) {
	pending := nodeagent.State{
		AgentCredentialGeneration: 4,
		PendingRecoveryToken:      strings.Repeat("p", 42) + "A",
		PendingBearer:             strings.Repeat("b", 42) + "A",
	}
	unauthorized := errors.Join(
		&nodeagent.APIError{StatusCode: http.StatusConflict, Message: "unrelated conflict"},
		fmt.Errorf("retry recovery exchange: %w", &nodeagent.APIError{StatusCode: http.StatusUnauthorized, Message: "expired recovery token"}),
	)
	err := describeRecoveryFailure(unauthorized, nil, 4, pending, true)
	if !errors.Is(err, unauthorized) || !strings.Contains(err.Error(), "replacement recovery token") || !strings.Contains(err.Error(), "new token") || !strings.Contains(err.Error(), "safely probe the old pending bearer") {
		t.Fatalf("rejected pending-token error=%v", err)
	}
	if strings.Contains(err.Error(), "--resume") {
		t.Fatalf("rejected pending-token error suggests an endless resume: %v", err)
	}

	conflict := &nodeagent.APIError{StatusCode: http.StatusConflict, Message: "pending bearer is already authenticated"}
	err = describeRecoveryFailure(conflict, nil, 4, pending, true)
	if !strings.Contains(err.Error(), "--resume") || strings.Contains(err.Error(), "replacement recovery token") {
		t.Fatalf("authenticated pending-bearer conflict error=%v", err)
	}

	transient := fmt.Errorf("ambiguous transport failure: %w", context.DeadlineExceeded)
	err = describeRecoveryFailure(transient, nil, 4, pending, true)
	if !strings.Contains(err.Error(), "--resume") || strings.Contains(err.Error(), "replacement recovery token") {
		t.Fatalf("transient pending recovery error=%v", err)
	}
}

func TestLoadAgentRecoveryTokenPrivateFile(t *testing.T) {
	token := strings.Repeat("u", 42) + "A"
	path := filepath.Join(t.TempDir(), "recovery-token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadAgentRecoveryToken(path, nil, "")
	if err != nil || loaded != token {
		t.Fatalf("private token file = %q, err=%v", loaded, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAgentRecoveryToken(path, nil, ""); err == nil || !strings.Contains(err.Error(), "group or other") {
		t.Fatalf("insecure token file returned %v", err)
	}
}

func TestSelectRecoveryRuntimeRequiresAuthoritativeOrExplicitFailOpen(t *testing.T) {
	if _, err := selectRecoveryRuntime(recoveryRuntimeOptions{noReload: true}); err == nil || !strings.Contains(err.Error(), "explicit --fail-open") {
		t.Fatalf("unsafe no-reload returned %v", err)
	}
	plan, err := selectRecoveryRuntime(recoveryRuntimeOptions{noReload: true, failOpen: true})
	if err != nil || plan.stageOnly || !plan.failOpen {
		t.Fatalf("explicit fail-open plan=%#v err=%v", plan, err)
	}
	if _, err := selectRecoveryRuntime(recoveryRuntimeOptions{quarantineService: "mesh-nebula.service", noReload: true}); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("conflicting quarantine plan returned %v", err)
	}
	if _, err := selectRecoveryRuntime(recoveryRuntimeOptions{quarantineService: "mesh-nebula.service", failOpen: true}); err == nil || !strings.Contains(err.Error(), "authoritative") {
		t.Fatalf("fail-open quarantine plan returned %v", err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	authoritative, err := selectRecoveryRuntime(recoveryRuntimeOptions{
		quarantineService: "mesh-nebula.service",
		runner:            &recordingCommandRunner{},
		configPath:        filepath.Join(t.TempDir(), "current", "config.yml"),
		nebulaBinary:      executable,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !authoritative.stageOnly || authoritative.failOpen || authoritative.quarantineService != "mesh-nebula.service" {
		t.Fatalf("authoritative recovery plan=%#v", authoritative)
	}
	if _, ok := authoritative.reloader.(stageOnlyReloader); !ok {
		t.Fatalf("authoritative recovery reloader=%T", authoritative.reloader)
	}
	if _, ok := authoritative.quarantine.(*serviceRuntime); !ok {
		t.Fatalf("authoritative quarantine controller=%T", authoritative.quarantine)
	}
}

func TestEnforceRecoveryQuarantineFailsClosed(t *testing.T) {
	runtime := &recordingRecoveryRuntime{err: context.DeadlineExceeded}
	plan := recoveryRuntimePlan{quarantine: runtime, reloader: stageOnlyReloader{}, stageOnly: true}
	if err := enforceRecoveryQuarantine(context.Background(), plan, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "quarantine Nebula") {
		t.Fatalf("failed quarantine returned %v", err)
	}
	if runtime.calls != 1 {
		t.Fatalf("quarantine calls=%d", runtime.calls)
	}

	plan.stageOnly = false
	plan.failOpen = true
	var warnings bytes.Buffer
	if err := enforceRecoveryQuarantine(context.Background(), plan, &warnings); err != nil || !strings.Contains(warnings.String(), "explicitly fail-open") {
		t.Fatalf("fail-open quarantine err=%v warning=%q", err, warnings.String())
	}
}

func TestEnforceRecoveryQuarantineProvesManagedSystemdServiceStopped(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "current", "config.yml")
	runner := &recordingCommandRunner{outputs: [][]byte{
		[]byte(fmt.Sprintf("{ path=%s ; argv[]=%s -config %s ; ignore_errors=no ; }\n", executable, executable, configPath)),
		[]byte("ActiveState=inactive\nSubState=dead\nMainPID=0\n"),
	}}
	controller := &serviceRuntime{
		service: "mesh-nebula.service", runner: runner,
		expectedConfig: configPath, expectedBinary: executable,
	}
	plan := recoveryRuntimePlan{
		quarantine: controller, reloader: stageOnlyReloader{}, stageOnly: true,
		quarantineService: "mesh-nebula.service",
	}
	if err := enforceRecoveryQuarantine(context.Background(), plan, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 3 {
		t.Fatalf("systemd quarantine commands=%v", runner.commands)
	}
	if got := strings.Join(runner.commands[1], " "); got != "systemctl stop -- mesh-nebula.service" {
		t.Fatalf("stop command=%q", got)
	}
	if got := strings.Join(runner.commands[2], " "); !strings.Contains(got, "--property=ActiveState,SubState,MainPID") {
		t.Fatalf("runtime proof command=%q", got)
	}
}

type recordingRecoveryRuntime struct {
	calls int
	err   error
}

func (r *recordingRecoveryRuntime) Reload(context.Context) error { return nil }

func (r *recordingRecoveryRuntime) Observe(context.Context) (runtimeObservation, error) {
	return runtimeObservation{}, nil
}

func (r *recordingRecoveryRuntime) Quarantine(context.Context) error {
	r.calls++
	return r.err
}

var _ nodeagent.Reloader = stageOnlyReloader{}
