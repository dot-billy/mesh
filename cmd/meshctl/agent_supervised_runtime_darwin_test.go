//go:build darwin

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func requireDarwinNativeChildTest(t *testing.T) {
	t.Helper()
	if os.Getenv("MESH_DARWIN_NATIVE_FAULT_TEST") != "1" {
		t.Skip("set MESH_DARWIN_NATIVE_FAULT_TEST=1 through the native harness")
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Fatal("native Darwin child fault injection requires root:wheel")
	}
}

func TestDarwinNativeChildIdentityAndDetachedCycleContext(t *testing.T) {
	requireDarwinNativeChildTest(t)
	binary := "/bin/sleep"
	resolved, err := filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	processValue, err := (darwinChildStarter{resolvedBinary: resolved}).Start(ctx, binary, []string{"60"})
	if err != nil {
		t.Fatal(err)
	}
	process := processValue.(*darwinChildProcess)
	defer func() {
		_ = process.Terminate()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Second)
		defer cleanupCancel()
		_ = process.Wait(cleanupCtx)
	}()
	cancel()
	if err := process.Prove(context.Background(), binary, []string{"60"}); err != nil {
		t.Fatalf("prove exact child after cycle-context cancellation: %v", err)
	}
	if err := process.Prove(context.Background(), binary, []string{"61"}); err == nil {
		t.Fatal("mismatched child proof request was accepted")
	}
	if err := process.Terminate(); err != nil {
		t.Fatal(err)
	}
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer waitCancel()
	if err := process.Wait(waitCtx); err != nil {
		t.Fatal(err)
	}
	if err := process.Prove(context.Background(), binary, []string{"60"}); err == nil {
		t.Fatal("reaped child remained provable")
	}
	requireDarwinProcessGroupAbsent(t, process.pid)
}

func TestDarwinNativeChildForcedGroupKillAndReap(t *testing.T) {
	requireDarwinNativeChildTest(t)
	binary := "/bin/sh"
	resolved, err := filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	arguments := []string{"-c", "trap '' TERM; while :; do /bin/sleep 1; done"}
	processValue, err := (darwinChildStarter{resolvedBinary: resolved}).Start(context.Background(), binary, arguments)
	if err != nil {
		t.Fatal(err)
	}
	process := processValue.(*darwinChildProcess)
	defer func() {
		_ = unix.Kill(-process.pid, unix.SIGKILL)
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Second)
		defer cleanupCancel()
		_ = process.Wait(cleanupCtx)
	}()
	if err := process.Prove(context.Background(), binary, arguments); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := process.Terminate(); err != nil {
		t.Fatal(err)
	}
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	started := time.Now()
	err = process.Wait(waitCtx)
	waitCancel()
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(started) < 150*time.Millisecond {
		t.Fatal("SIGTERM-ignoring process group exited before the forced-kill deadline")
	}
	requireDarwinProcessGroupAbsent(t, process.pid)
}

func requireDarwinProcessGroupAbsent(t *testing.T, processGroup int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := unix.Kill(-processGroup, 0)
		if errors.Is(err, unix.ESRCH) {
			return
		}
		if err != nil {
			t.Fatalf("inspect Darwin child process group: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("Darwin child process group %d remained after reap", processGroup)
		}
		time.Sleep(25 * time.Millisecond)
	}
}
