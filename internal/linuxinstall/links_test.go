//go:build linux

package linuxinstall

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestProductionManagedLinkTopologyIsExact(t *testing.T) {
	if err := validateProductionTopologyConstants(); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"bin/meshctl":      "/opt/mesh/current/bin/meshctl",
		"bin/mesh-install": "/opt/mesh/current/bin/mesh-install",
		"bin/nebula":       "/opt/mesh/current/bin/nebula",
		"bin/nebula-cert":  "/opt/mesh/current/bin/nebula-cert",
		"share/doc/mesh":   "/opt/mesh/current/share/doc/mesh",
	}
	specs := topologySpecs(ProductionMeshRoot)
	if len(specs) != len(want) {
		t.Fatalf("production topology has %d links, want %d", len(specs), len(want))
	}
	for _, spec := range specs {
		endpoint := filepath.ToSlash(spec.endpointRelative())
		if target, ok := want[endpoint]; !ok || filepath.ToSlash(spec.target) != target {
			t.Fatalf("unexpected production link %q -> %q", endpoint, spec.target)
		}
		delete(want, endpoint)
	}
	if len(want) != 0 {
		t.Fatalf("missing production links: %#v", want)
	}
	files := topologyFileSpecs()
	wantFiles := []string{
		"lib/systemd/system/mesh-agent.service",
		"lib/systemd/system/mesh-agent.service.d/10-timeout-abort.conf",
		"lib/systemd/system/mesh-nebula.service",
		"lib/systemd/system/mesh-nebula.service.d/10-timeout-abort.conf",
	}
	if len(files) != len(wantFiles) {
		t.Fatalf("unexpected stable unit-file topology: %#v", files)
	}
	for index, spec := range files {
		if filepath.ToSlash(spec.endpointRelative()) != wantFiles[index] || len(spec.content) == 0 {
			t.Fatalf("unexpected stable unit-file topology entry %d: %#v", index, spec)
		}
	}
}

func TestManagedLinkTopologyFirstInstallEnsureAuditAndRemove(t *testing.T) {
	topology, localPath, meshPath := newTestManagedLinkTopology(t)
	if err := topology.RequireAbsent(); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"bin", "lib", "share"} {
		if _, err := os.Lstat(filepath.Join(localPath, directory)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("absence preflight created %q: %v", directory, err)
		}
	}
	if err := topology.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := topology.Audit(); err != nil {
		t.Fatal(err)
	}
	if err := topology.Ensure(); err != nil {
		t.Fatalf("exact recovery topology was not idempotent: %v", err)
	}
	if err := topology.RequireAbsent(); err == nil {
		t.Fatal("installed topology passed first-install absence preflight")
	}
	assertTestTopologyLinks(t, localPath, meshPath)
	for _, relative := range topologyDirectoryOrder() {
		info, err := os.Lstat(filepath.Join(localPath, relative))
		if err != nil || info.Mode() != os.ModeDir|0o755 {
			t.Fatalf("directory %q mode=%v err=%v", relative, infoMode(info), err)
		}
	}
	if err := topology.Remove(); err != nil {
		t.Fatal(err)
	}
	if err := topology.Remove(); err != nil {
		t.Fatalf("idempotent managed-link rollback failed: %v", err)
	}
	if err := topology.RequireAbsent(); err != nil {
		t.Fatal(err)
	}
	if err := topology.Audit(); err == nil {
		t.Fatal("absent topology passed complete audit")
	}
	for _, spec := range topology.specs {
		if _, err := os.Lstat(filepath.Join(localPath, spec.endpointRelative())); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("endpoint %q survived removal: %v", spec.endpointRelative(), err)
		}
	}
	for _, spec := range topology.files {
		if _, err := os.Lstat(filepath.Join(localPath, spec.endpointRelative())); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("endpoint %q survived removal: %v", spec.endpointRelative(), err)
		}
	}
	for _, relative := range topologyDirectoryOrder() {
		if info, err := os.Lstat(filepath.Join(localPath, relative)); err != nil || !info.IsDir() {
			t.Fatalf("rollback removed shared parent %q: %v", relative, err)
		}
	}
}

func TestManagedLinkEnsureCompletesExactPartialRecovery(t *testing.T) {
	topology, localPath, meshPath := newTestManagedLinkTopology(t)
	createTestTopologyDirectories(t, localPath)
	first := topology.specs[0]
	if err := os.Symlink(first.target, filepath.Join(localPath, first.endpointRelative())); err != nil {
		t.Fatal(err)
	}
	if err := topology.RequireAbsent(); err == nil {
		t.Fatal("partial exact topology accepted as a fresh first install")
	}
	if err := topology.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := topology.Audit(); err != nil {
		t.Fatal(err)
	}
	assertTestTopologyLinks(t, localPath, meshPath)
}

func TestManagedLinkTopologyRecoversAfterSIGKILLAtCreationTransitions(t *testing.T) {
	checkpoints := []string{
		topologyCheckpointDirectoryCreated,
		topologyCheckpointDirectoryFinalMode,
		topologyCheckpointDirectoryPublished,
		topologyCheckpointFileCreated,
		topologyCheckpointFileContentWritten,
		topologyCheckpointFileContentSynced,
		topologyCheckpointFileFinalMode,
		topologyCheckpointFileFinalSynced,
		topologyCheckpointFilePublished,
	}
	for _, checkpoint := range checkpoints {
		t.Run(checkpoint, func(t *testing.T) {
			outer := t.TempDir()
			usrPath := filepath.Join(outer, "usr")
			localPath := filepath.Join(usrPath, "local")
			if err := os.Mkdir(usrPath, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(localPath, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(usrPath, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(localPath, 0o755); err != nil {
				t.Fatal(err)
			}
			meshPath := filepath.Join(outer, "opt", "mesh")
			markerPath := filepath.Join(outer, "checkpoint")
			command := exec.Command(os.Args[0], "-test.run=^TestManagedLinkTopologySIGKILLHelper$")
			command.Env = append(os.Environ(),
				"MESH_TEST_TOPOLOGY_CRASH_POINT="+checkpoint,
				"MESH_TEST_TOPOLOGY_LOCAL_PATH="+localPath,
				"MESH_TEST_TOPOLOGY_MESH_PATH="+meshPath,
				"MESH_TEST_TOPOLOGY_MARKER_PATH="+markerPath,
			)
			var output bytes.Buffer
			command.Stdout = &output
			command.Stderr = &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(10 * time.Second)
			for {
				if _, err := os.Stat(markerPath); err == nil {
					break
				} else if !errors.Is(err, os.ErrNotExist) {
					_ = command.Process.Kill()
					_ = command.Wait()
					t.Fatalf("inspect crash checkpoint: %v", err)
				}
				if time.Now().After(deadline) {
					_ = command.Process.Kill()
					_ = command.Wait()
					t.Fatalf("child did not reach %q: %s", checkpoint, output.String())
				}
				time.Sleep(5 * time.Millisecond)
			}
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			waitErr := command.Wait()
			var exitErr *exec.ExitError
			if !errors.As(waitErr, &exitErr) {
				t.Fatalf("SIGKILL helper wait error = %v, output=%s", waitErr, output.String())
			}
			status, ok := exitErr.Sys().(syscall.WaitStatus)
			if !ok || status.Signal() != syscall.SIGKILL {
				t.Fatalf("helper exit status = %v, output=%s", exitErr, output.String())
			}

			assertCrashDidNotExposePartialFinalName(t, checkpoint, localPath)
			topology, err := newManagedLinkTopology(localPath, meshPath)
			if err != nil {
				t.Fatalf("reopen topology after SIGKILL at %q: %v", checkpoint, err)
			}
			defer topology.Close()
			if err := topology.Ensure(); err != nil {
				t.Fatalf("recover topology after SIGKILL at %q: %v", checkpoint, err)
			}
			if err := topology.Audit(); err != nil {
				t.Fatalf("audit recovered topology after SIGKILL at %q: %v", checkpoint, err)
			}
			assertTestTopologyLinks(t, localPath, meshPath)
			assertNoTopologyTemporaries(t, localPath)
		})
	}
}

func TestManagedLinkTopologyScavengesOnlyExactPrivateTemporaries(t *testing.T) {
	topology, localPath, _ := newTestManagedLinkTopology(t)
	canonicalDirectory := topologyDirectoryTemporaryPrefix + strings.Repeat("a", 32)
	if err := os.Mkdir(filepath.Join(localPath, canonicalDirectory), stagingMode); err != nil {
		t.Fatal(err)
	}
	noncanonicalDirectory := topologyDirectoryTemporaryPrefix + "operator-owned"
	if err := os.Mkdir(filepath.Join(localPath, noncanonicalDirectory), stagingMode); err != nil {
		t.Fatal(err)
	}
	if err := topology.Ensure(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(localPath, canonicalDirectory)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("exact abandoned directory temporary survived recovery: %v", err)
	}
	if info, err := os.Lstat(filepath.Join(localPath, noncanonicalDirectory)); err != nil || !info.IsDir() {
		t.Fatalf("noncanonical operator object was changed: mode=%v err=%v", infoMode(info), err)
	}

	unitParent := filepath.Join(localPath, "lib", "systemd", "system")
	canonicalFile := topologyFileTemporaryPrefix + strings.Repeat("b", 32)
	if err := os.WriteFile(filepath.Join(unitParent, canonicalFile), []byte("partial"), stagingMode); err != nil {
		t.Fatal(err)
	}
	if err := topology.Ensure(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(unitParent, canonicalFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("exact abandoned file temporary survived recovery: %v", err)
	}
}

func TestManagedLinkTopologyRejectsSuspiciousCanonicalTemporary(t *testing.T) {
	topology, localPath, _ := newTestManagedLinkTopology(t)
	name := topologyDirectoryTemporaryPrefix + strings.Repeat("c", 32)
	path := filepath.Join(localPath, name)
	if err := os.WriteFile(path, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := topology.Ensure(); err == nil {
		t.Fatal("canonical temporary name with a foreign inode shape was removed")
	}
	if content, err := os.ReadFile(path); err != nil || string(content) != "foreign" {
		t.Fatalf("suspicious canonical temporary was changed: content=%q err=%v", content, err)
	}
	for _, relative := range topologyDirectoryOrder() {
		if _, err := os.Lstat(filepath.Join(localPath, relative)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed preflight partially created %q: %v", relative, err)
		}
	}
}

func TestManagedLinkTopologySIGKILLHelper(t *testing.T) {
	checkpoint := os.Getenv("MESH_TEST_TOPOLOGY_CRASH_POINT")
	if checkpoint == "" {
		return
	}
	topology, err := newManagedLinkTopology(
		os.Getenv("MESH_TEST_TOPOLOGY_LOCAL_PATH"),
		os.Getenv("MESH_TEST_TOPOLOGY_MESH_PATH"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer topology.Close()
	reached := false
	topology.testCheckpoint = func(current string) {
		if reached || current != checkpoint {
			return
		}
		reached = true
		marker, err := os.OpenFile(os.Getenv("MESH_TEST_TOPOLOGY_MARKER_PATH"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := marker.Write([]byte(checkpoint)); err != nil {
			t.Fatal(err)
		}
		if err := marker.Sync(); err != nil {
			t.Fatal(err)
		}
		if err := marker.Close(); err != nil {
			t.Fatal(err)
		}
		for {
			_ = syscall.Pause()
		}
	}
	if err := topology.Ensure(); err != nil {
		t.Fatal(err)
	}
	t.Fatalf("topology ensure completed without reaching checkpoint %q", checkpoint)
}

func assertCrashDidNotExposePartialFinalName(t *testing.T, checkpoint, localPath string) {
	t.Helper()
	switch checkpoint {
	case topologyCheckpointDirectoryCreated, topologyCheckpointDirectoryFinalMode:
		if _, err := os.Lstat(filepath.Join(localPath, "bin")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("SIGKILL at %q exposed partial final directory: %v", checkpoint, err)
		}
	case topologyCheckpointDirectoryPublished:
		info, err := os.Lstat(filepath.Join(localPath, "bin"))
		if err != nil || !trustedTopologyDirectory(info) {
			t.Fatalf("SIGKILL after directory publication left mode=%v err=%v", infoMode(info), err)
		}
	case topologyCheckpointFileCreated, topologyCheckpointFileContentWritten, topologyCheckpointFileContentSynced,
		topologyCheckpointFileFinalMode, topologyCheckpointFileFinalSynced:
		spec := topologyFileSpecs()[0]
		if _, err := os.Lstat(filepath.Join(localPath, spec.endpointRelative())); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("SIGKILL at %q exposed partial final file: %v", checkpoint, err)
		}
	case topologyCheckpointFilePublished:
		spec := topologyFileSpecs()[0]
		info, err := os.Lstat(filepath.Join(localPath, spec.endpointRelative()))
		if err != nil || !trustedExactManagedFile(info, int64(len(spec.content))) {
			t.Fatalf("SIGKILL after file publication left mode=%v err=%v", infoMode(info), err)
		}
		content, err := os.ReadFile(filepath.Join(localPath, spec.endpointRelative()))
		if err != nil || !bytes.Equal(content, spec.content) {
			t.Fatalf("SIGKILL after file publication left wrong content: err=%v", err)
		}
	default:
		t.Fatalf("unrecognized crash checkpoint %q", checkpoint)
	}
}

func assertNoTopologyTemporaries(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if _, recognized := topologyTemporaryName(entry.Name()); recognized {
			t.Errorf("abandoned topology temporary remains at %q", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestManagedLinkPreflightRefusesCollisionWithoutPartialMutation(t *testing.T) {
	t.Run("ensure", func(t *testing.T) {
		topology, localPath, _ := newTestManagedLinkTopology(t)
		if err := os.Mkdir(filepath.Join(localPath, "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(localPath, "bin", "meshctl"), []byte("foreign"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := topology.Ensure(); err == nil {
			t.Fatal("foreign endpoint was adopted or replaced")
		}
		for _, relative := range []string{"lib", "share"} {
			if _, err := os.Lstat(filepath.Join(localPath, relative)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("collision preflight partially created %q: %v", relative, err)
			}
		}
		if content, err := os.ReadFile(filepath.Join(localPath, "bin", "meshctl")); err != nil || string(content) != "foreign" {
			t.Fatalf("foreign endpoint changed: content=%q err=%v", content, err)
		}
	})

	t.Run("remove", func(t *testing.T) {
		topology, localPath, _ := newTestManagedLinkTopology(t)
		createTestTopologyDirectories(t, localPath)
		exact := topology.specs[0]
		conflict := topology.specs[1]
		if err := os.Symlink(exact.target, filepath.Join(localPath, exact.endpointRelative())); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(localPath, conflict.endpointRelative()), []byte("foreign"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := topology.Remove(); err == nil {
			t.Fatal("rollback crossed a foreign endpoint collision")
		}
		if target, err := os.Readlink(filepath.Join(localPath, exact.endpointRelative())); err != nil || target != exact.target {
			t.Fatalf("rollback removed an exact link before completing preflight: target=%q err=%v", target, err)
		}
		if content, err := os.ReadFile(filepath.Join(localPath, conflict.endpointRelative())); err != nil || string(content) != "foreign" {
			t.Fatalf("rollback mutated foreign collision: content=%q err=%v", content, err)
		}
	})
}

func TestManagedLinkTopologyRejectsWrongOrMultiplyLinkedEndpoints(t *testing.T) {
	tests := []struct {
		name   string
		create func(t *testing.T, endpoint, exactTarget string)
	}{
		{
			name: "relative target",
			create: func(t *testing.T, endpoint, _ string) {
				if err := os.Symlink("../../opt/mesh/current/bin/meshctl", endpoint); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong absolute target",
			create: func(t *testing.T, endpoint, exactTarget string) {
				if err := os.Symlink(exactTarget+"-other", endpoint); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "regular file",
			create: func(t *testing.T, endpoint, _ string) {
				if err := os.WriteFile(endpoint, []byte("foreign"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "directory",
			create: func(t *testing.T, endpoint, _ string) {
				if err := os.Mkdir(endpoint, 0o755); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			topology, localPath, _ := newTestManagedLinkTopology(t)
			createTestTopologyDirectories(t, localPath)
			spec := topology.specs[0]
			endpoint := filepath.Join(localPath, spec.endpointRelative())
			test.create(t, endpoint, spec.target)
			for name, operation := range map[string]func() error{
				"require-absent": topology.RequireAbsent,
				"ensure":         topology.Ensure,
				"audit":          topology.Audit,
				"remove":         topology.Remove,
			} {
				if err := operation(); err == nil {
					t.Fatalf("%s accepted conflicting endpoint", name)
				}
			}
			if _, err := os.Lstat(endpoint); err != nil {
				t.Fatalf("conflicting endpoint was removed: %v", err)
			}
		})
	}

	t.Run("multiply linked symlink", func(t *testing.T) {
		topology, localPath, _ := newTestManagedLinkTopology(t)
		createTestTopologyDirectories(t, localPath)
		spec := topology.specs[0]
		endpoint := filepath.Join(localPath, spec.endpointRelative())
		if err := os.Symlink(spec.target, endpoint); err != nil {
			t.Fatal(err)
		}
		second := endpoint + ".second"
		if err := os.Link(endpoint, second); err != nil {
			t.Skipf("filesystem cannot hard-link a symlink: %v", err)
		}
		if err := topology.Audit(); err == nil {
			t.Fatal("multiply-linked managed symlink accepted")
		}
		if err := topology.Remove(); err == nil {
			t.Fatal("multiply-linked managed symlink removed")
		}
	})
}

func TestManagedLinkTopologyRejectsInsecureParentsBeforeMutation(t *testing.T) {
	t.Run("symlink component", func(t *testing.T) {
		topology, localPath, _ := newTestManagedLinkTopology(t)
		external := filepath.Join(t.TempDir(), "external")
		if err := os.Mkdir(external, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(external, filepath.Join(localPath, "lib")); err != nil {
			t.Fatal(err)
		}
		if err := topology.Ensure(); err == nil {
			t.Fatal("symlinked parent component accepted")
		}
		if _, err := os.Lstat(filepath.Join(localPath, "bin")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("preflight created bin before rejecting symlink: %v", err)
		}
	})

	t.Run("writable component", func(t *testing.T) {
		topology, localPath, _ := newTestManagedLinkTopology(t)
		if err := os.Mkdir(filepath.Join(localPath, "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(localPath, "bin"), 0o775); err != nil {
			t.Fatal(err)
		}
		if err := topology.RequireAbsent(); err == nil {
			t.Fatal("group-writable endpoint parent accepted")
		}
		if err := topology.Ensure(); err == nil {
			t.Fatal("group-writable endpoint parent used")
		}
	})

	t.Run("root path replacement", func(t *testing.T) {
		topology, localPath, _ := newTestManagedLinkTopology(t)
		moved := localPath + ".moved"
		if err := os.Rename(localPath, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(localPath, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := topology.RequireAbsent(); err == nil {
			t.Fatal("replacement local root accepted by anchored topology")
		}
	})

	t.Run("symlinked ancestor retaining root inode", func(t *testing.T) {
		outer := t.TempDir()
		parent := filepath.Join(outer, "usr")
		localPath := filepath.Join(parent, "local")
		if err := os.Mkdir(parent, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(localPath, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(localPath, 0o755); err != nil {
			t.Fatal(err)
		}
		topology, err := newManagedLinkTopology(localPath, filepath.Join(outer, "opt/mesh"))
		if err != nil {
			t.Fatal(err)
		}
		defer topology.Close()
		moved := parent + ".moved"
		if err := os.Rename(parent, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(moved, parent); err != nil {
			t.Fatal(err)
		}
		if err := topology.RequireAbsent(); err == nil {
			t.Fatal("symlinked local-root ancestor accepted")
		}
		if err := os.Remove(parent); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(moved, parent); err != nil {
			t.Fatal(err)
		}
	})
}

func TestManagedLinkRollbackAcceptsAbsentExactMixtureButNotWrongLink(t *testing.T) {
	topology, localPath, _ := newTestManagedLinkTopology(t)
	if err := topology.Ensure(); err != nil {
		t.Fatal(err)
	}
	missing := topology.specs[0]
	if err := os.Remove(filepath.Join(localPath, missing.endpointRelative())); err != nil {
		t.Fatal(err)
	}
	if err := topology.Remove(); err != nil {
		t.Fatalf("rollback rejected absent/exact recovery mixture: %v", err)
	}
	if err := topology.Ensure(); err != nil {
		t.Fatal(err)
	}
	wrong := topology.specs[len(topology.specs)-1]
	wrongPath := filepath.Join(localPath, wrong.endpointRelative())
	if err := os.Remove(wrongPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(wrong.target+"-foreign", wrongPath); err != nil {
		t.Fatal(err)
	}
	if err := topology.Remove(); err == nil {
		t.Fatal("rollback removed links in the presence of a wrong target")
	}
	first := topology.specs[0]
	if target, err := os.Readlink(filepath.Join(localPath, first.endpointRelative())); err != nil || target != first.target {
		t.Fatalf("preflight failure partially removed exact link: target=%q err=%v", target, err)
	}
}

func TestManagedLinkTopologyConcurrentEnsureIsIdempotent(t *testing.T) {
	topology, _, _ := newTestManagedLinkTopology(t)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			errs <- topology.Ensure()
		}()
	}
	close(start)
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := topology.Audit(); err != nil {
		t.Fatal(err)
	}
}

func TestManagedLinkTopologyRejectsForeignOwnerWhenPrivileged(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create a foreign-owned topology root")
	}
	outer := t.TempDir()
	localPath := filepath.Join(outer, "local")
	if err := os.Mkdir(localPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(localPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(localPath, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := newManagedLinkTopology(localPath, filepath.Join(outer, "mesh")); err == nil {
		t.Fatal("foreign-owned topology root accepted")
	}
}

func TestManagedLinkTopologyClosed(t *testing.T) {
	topology, _, _ := newTestManagedLinkTopology(t)
	if err := topology.Close(); err != nil {
		t.Fatal(err)
	}
	for name, operation := range map[string]func() error{
		"require-absent": topology.RequireAbsent,
		"ensure":         topology.Ensure,
		"audit":          topology.Audit,
		"remove":         topology.Remove,
	} {
		if err := operation(); err == nil || !strings.Contains(err.Error(), "closed") {
			t.Fatalf("%s on closed topology returned %v", name, err)
		}
	}
}

func newTestManagedLinkTopology(t *testing.T) (*ManagedLinkTopology, string, string) {
	t.Helper()
	outer := t.TempDir()
	usrPath := filepath.Join(outer, "usr")
	localPath := filepath.Join(usrPath, "local")
	if err := os.Mkdir(usrPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(localPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(usrPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(localPath, 0o755); err != nil {
		t.Fatal(err)
	}
	meshPath := filepath.Join(outer, "opt", "mesh")
	topology, err := newManagedLinkTopology(localPath, meshPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := topology.Close(); err != nil {
			t.Errorf("close managed-link topology: %v", err)
		}
	})
	return topology, localPath, meshPath
}

func createTestTopologyDirectories(t *testing.T, localPath string) {
	t.Helper()
	for _, relative := range topologyDirectoryOrder() {
		path := filepath.Join(localPath, relative)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func assertTestTopologyLinks(t *testing.T, localPath, meshPath string) {
	t.Helper()
	for _, spec := range topologySpecs(meshPath) {
		path := filepath.Join(localPath, spec.endpointRelative())
		info, err := os.Lstat(path)
		if err != nil || !trustedExactSymlink(info) {
			t.Fatalf("endpoint %q is not an exact symlink: mode=%v err=%v", spec.endpointRelative(), infoMode(info), err)
		}
		target, err := os.Readlink(path)
		if err != nil || target != spec.target {
			t.Fatalf("endpoint %q target=%q want=%q err=%v", spec.endpointRelative(), target, spec.target, err)
		}
	}
	for _, spec := range topologyFileSpecs() {
		path := filepath.Join(localPath, spec.endpointRelative())
		info, err := os.Lstat(path)
		if err != nil || !trustedExactManagedFile(info, int64(len(spec.content))) {
			t.Fatalf("endpoint %q is not an exact managed file: mode=%v err=%v", spec.endpointRelative(), infoMode(info), err)
		}
		content, err := os.ReadFile(path)
		if err != nil || string(content) != string(spec.content) {
			t.Fatalf("endpoint %q content differs: err=%v", spec.endpointRelative(), err)
		}
	}
}
