//go:build !windows

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestReadPIDFileRejectsSymlink(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	target := filepath.Join(directory, "target.pid")
	if err := os.WriteFile(target, []byte("123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "nebula.pid")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readPIDFile(link); err == nil {
		t.Fatal("expected symlink PID file to fail")
	}
}

func TestPIDRuntimeQuarantineTerminatesVerifiedProcess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux /proc identity check required")
	}
	binary, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep binary unavailable")
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "30")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	defer command.Process.Kill()

	pidFile := filepath.Join(t.TempDir(), "nebula.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(command.Process.Pid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	controller := &pidRuntime{path: pidFile, nebulaBinary: filepath.Clean(binary)}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := controller.Quarantine(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("verified process was not reaped after quarantine")
	}
	if err := controller.Quarantine(ctx); err != nil {
		t.Fatalf("reconfirm stopped process quarantine: %v", err)
	}
}
