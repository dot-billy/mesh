//go:build windows

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mesh/internal/windowssecurity"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == "-config" {
		// Native Job Object tests launch this exact test image through the same
		// fixed Nebula argv contract. Remaining alive gives the parent time to
		// prove the process handle, image identity, and job policy.
		time.Sleep(10 * time.Minute)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestWindowsContainedChildNative(t *testing.T) {
	if os.Getenv("MESH_WINDOWS_NATIVE_FAULT_TEST") != "1" {
		t.Skip("set MESH_WINDOWS_NATIVE_FAULT_TEST=1 on an isolated Windows host")
	}
	actorSID, err := windowssecurity.CurrentActorSID()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "nebula-proof.exe")
	copyExactFile(t, source, binary)
	config := filepath.Join(root, "config.yml")
	if err := os.WriteFile(config, []byte("native-proof\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{binary, config} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := windowssecurity.ProtectPrivatePath(path, info, windowssecurity.RegularFile, actorSID); err != nil {
			t.Fatalf("protect %s: %v", filepath.Base(path), err)
		}
	}
	binaryInfo, err := inspectWindowsManagedFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	starter := windowsChildStarter{binaryInfo: binaryInfo}
	process, err := starter.Start(context.Background(), binary, []string{"-config", config})
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Prove(context.Background(), binary, []string{"-config", config}); err != nil {
		t.Fatal(err)
	}
	if err := process.Prove(context.Background(), binary, []string{"-config", config + ".drift"}); err == nil {
		t.Fatal("drifted Windows child proof request was accepted")
	}
	if err := process.Terminate(); err != nil {
		t.Fatal(err)
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := process.Wait(waitCtx); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(context.Background()); err != nil {
		t.Fatalf("idempotent wait: %v", err)
	}
	if err := process.Prove(context.Background(), binary, []string{"-config", config}); err == nil {
		t.Fatal("exited Windows child remained provable")
	}
}

func copyExactFile(t *testing.T, source, target string) {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := output.ReadFrom(input); err != nil {
		output.Close()
		t.Fatal(err)
	}
	if err := output.Sync(); err != nil {
		output.Close()
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
}
