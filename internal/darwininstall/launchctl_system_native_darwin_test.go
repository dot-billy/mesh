//go:build darwin

package darwininstall

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"mesh/internal/nodeagent"

	"golang.org/x/sys/unix"
)

const (
	nativeLaunchctlProofLabel = "io.mesh.node-agent.native-proof"
	nativeLaunchctlProofName  = nativeLaunchctlProofLabel + ".plist"
)

var nativeLaunchctlProofPlist = []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>io.mesh.node-agent.native-proof</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/true</string>
  </array>
  <key>RunAtLoad</key>
  <false/>
</dict>
</plist>
`)

func TestDarwinNativeSystemLaunchctlMutationProof(t *testing.T) {
	requireDarwinNativeInstallerTest(t)
	if os.Getenv("MESH_DARWIN_SYSTEM_LAUNCHCTL_TEST") != "1" {
		t.Skip("set MESH_DARWIN_SYSTEM_LAUNCHCTL_TEST=1 only on an approved native Mac")
	}
	plistPath := filepath.Join(ProductionLaunchdDirectory, nativeLaunchctlProofName)
	if _, err := os.Lstat(plistPath); err == nil {
		t.Fatalf("refusing to replace pre-existing native launchctl proof plist %s", plistPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	identity := launchctlServiceIdentity{
		domain: launchctlSystemDomain,
		target: launchctlSystemDomain + "/" + nativeLaunchctlProofLabel,
	}
	contract, err := newLaunchctlCommandContract(identity, plistPath)
	if err != nil {
		t.Fatal(err)
	}
	operations := launchctlServiceOperations{
		runner:   productionLaunchctlCommandRunner{contract: contract},
		identity: identity,
	}
	if err := writeNativeLaunchctlProofPlist(plistPath); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cleanupNativeLaunchctlProof(plistPath, operations); err != nil {
			t.Errorf("clean native system-domain launchctl proof: %v", err)
		}
	}()

	// First prove the absent path: failed direct bootout must be followed by a
	// successful bootstrap of the exact fixture and a successful bootout.
	if err := operations.Bootout(plistPath); err != nil {
		t.Fatalf("prove initially absent native launchctl service: %v", err)
	}
	// Then prove loading and direct removal of that exact system-domain label.
	if err := operations.Bootstrap(plistPath); err != nil {
		t.Fatalf("bootstrap native system-domain launchctl proof: %v", err)
	}
	if err := operations.Bootout(plistPath); err != nil {
		t.Fatalf("bootout loaded native system-domain launchctl proof: %v", err)
	}
	// Repeat the absent recovery route to prove the transaction is idempotent.
	if err := operations.Bootout(plistPath); err != nil {
		t.Fatalf("repeat native launchctl absence proof: %v", err)
	}
}

func writeNativeLaunchctlProofPlist(path string) (returnErr error) {
	if err := nodeagent.InspectDarwinSensitivePath(ProductionLaunchdDirectory); err != nil {
		return err
	}
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, 0o644)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("adopt native launchctl proof plist descriptor")
	}
	open := true
	defer func() {
		if open {
			returnErr = errors.Join(returnErr, file.Close())
		}
	}()
	if err := unix.Fchown(fd, 0, 0); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, 0o644); err != nil {
		return err
	}
	written, writeErr := file.Write(nativeLaunchctlProofPlist)
	if writeErr != nil || written != len(nativeLaunchctlProofPlist) {
		return errors.Join(writeErr, errors.New("native launchctl proof plist short write"))
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		open = false
		return err
	}
	open = false
	if err := authenticateNativeLaunchctlProofPlist(path); err != nil {
		return err
	}
	return nodeagent.SyncDarwinSensitiveDirectory(ProductionLaunchdDirectory)
}

func authenticateNativeLaunchctlProofPlist(path string) error {
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o644 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || stat.Flags != 0 || stat.Size != int64(len(nativeLaunchctlProofPlist)) {
		return errors.New("native launchctl proof plist metadata differs from its exact root:wheel mode-0644 contract")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, nativeLaunchctlProofPlist) {
		return errors.New("native launchctl proof plist bytes differ from the exact fixture")
	}
	return nil
}

func cleanupNativeLaunchctlProof(path string, operations launchctlServiceOperations) error {
	if err := authenticateNativeLaunchctlProofPlist(path); err != nil {
		return errors.Join(err, errors.New("refusing to remove an unauthenticated native launchctl proof plist"))
	}
	if err := operations.Bootout(path); err != nil {
		return fmt.Errorf("prove native launchctl proof service absent before plist removal: %w", err)
	}
	if err := unix.Unlink(path); err != nil {
		return err
	}
	if err := nodeagent.SyncDarwinSensitiveDirectory(ProductionLaunchdDirectory); err != nil {
		return err
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(errors.New("native launchctl proof plist remains after cleanup"), err)
	}
	return nil
}
