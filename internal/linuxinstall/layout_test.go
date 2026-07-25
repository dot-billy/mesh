//go:build linux

package linuxinstall

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestProductionReleaseLayoutConstants(t *testing.T) {
	if ProductionMeshRoot != "/opt/mesh" || ProductionReleasesRoot != "/opt/mesh/releases" || ProductionCurrentLink != "/opt/mesh/current" {
		t.Fatalf("unexpected production layout: root=%q releases=%q current=%q", ProductionMeshRoot, ProductionReleasesRoot, ProductionCurrentLink)
	}
}

func TestEnsureAndOpenReleaseLayout(t *testing.T) {
	rootPath := filepath.Join(t.TempDir(), "mesh")
	layout, err := EnsureReleaseLayout(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(rootPath); err != nil || info.Mode() != os.ModeDir|0o755 {
		t.Fatalf("root mode=%v err=%v", infoMode(info), err)
	}
	if info, err := os.Lstat(filepath.Join(rootPath, "releases")); err != nil || info.Mode() != os.ModeDir|0o755 {
		t.Fatalf("releases mode=%v err=%v", infoMode(info), err)
	}
	if err := layout.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenReleaseLayout(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists, err := reopened.ReadCurrent(); err != nil || exists {
		t.Fatalf("current exists=%v err=%v", exists, err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureReleaseLayout(rootPath + "/../other"); err == nil {
		t.Fatal("unclean absolute layout path accepted")
	}
	if _, err := EnsureReleaseLayout("relative/mesh"); err == nil {
		t.Fatal("relative layout path accepted")
	}
}

func TestEnsureReleaseLayoutScavengesOnlyExactPrivateTemporaries(t *testing.T) {
	parent := t.TempDir()
	stale := filepath.Join(parent, ".mesh-layout-directory-"+strings.Repeat("a", 32))
	if err := os.Mkdir(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	layout, err := EnsureReleaseLayout(filepath.Join(parent, "mesh"))
	if err != nil {
		t.Fatal(err)
	}
	defer layout.Close()
	if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("abandoned layout temporary survived: %v", err)
	}
	foreign := filepath.Join(parent, ".mesh-layout-directory-not-canonical")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	other, err := EnsureReleaseLayout(filepath.Join(parent, "other"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := os.Lstat(foreign); err != nil {
		t.Fatalf("noncanonical foreign object was removed: %v", err)
	}
}

func TestEnsureReleaseLayoutRejectsSymlinkOrWritableManagedPath(t *testing.T) {
	t.Run("symlink ancestry", func(t *testing.T) {
		parent := t.TempDir()
		realParent := filepath.Join(parent, "real")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatal(err)
		}
		linkedParent := filepath.Join(parent, "linked")
		if err := os.Symlink(realParent, linkedParent); err != nil {
			t.Fatal(err)
		}
		if _, err := EnsureReleaseLayout(filepath.Join(linkedParent, "mesh")); err == nil {
			t.Fatal("symlinked layout ancestry accepted")
		}
	})
	t.Run("writable managed root", func(t *testing.T) {
		rootPath := filepath.Join(t.TempDir(), "mesh")
		if err := os.Mkdir(rootPath, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(rootPath, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := EnsureReleaseLayout(rootPath); err == nil {
			t.Fatal("world-writable managed root accepted")
		}
	})
	t.Run("existing conflict", func(t *testing.T) {
		rootPath := filepath.Join(t.TempDir(), "mesh")
		if err := os.WriteFile(rootPath, []byte("conflict"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := EnsureReleaseLayout(rootPath); err == nil {
			t.Fatal("regular-file layout conflict accepted")
		}
	})
	t.Run("open does not create", func(t *testing.T) {
		rootPath := filepath.Join(t.TempDir(), "missing")
		if _, err := OpenReleaseLayout(rootPath); err == nil {
			t.Fatal("missing release layout opened")
		}
		if _, err := os.Lstat(rootPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("OpenReleaseLayout mutated missing root: %v", err)
		}
	})
}

func TestReleaseStagePublishIsImmutableCreateOnly(t *testing.T) {
	layout, rootPath := newTestReleaseLayout(t)
	identity := testRelease(42, "1", "2", 3)
	stage := createFinalTestStage(t, layout, identity)
	defer stage.Close()
	if !strings.HasPrefix(filepath.Base(stage.Path()), ".stage-"+identity.InstalledID+"-") {
		t.Fatalf("stage name %q does not bind installed ID", filepath.Base(stage.Path()))
	}
	if err := stage.Publish(); err != nil {
		t.Fatal(err)
	}
	if err := stage.Publish(); err != nil {
		t.Fatalf("same anchored stage publish retry failed: %v", err)
	}
	if _, err := os.Lstat(stage.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging name survived publication: %v", err)
	}
	finalPath := filepath.Join(rootPath, "releases", identity.InstalledID)
	if info, err := os.Lstat(finalPath); err != nil || info.Mode() != os.ModeDir|0o555 {
		t.Fatalf("published mode=%v err=%v", infoMode(info), err)
	}
	if published, err := layout.InspectRelease(identity); err != nil || !published {
		t.Fatalf("published=%v err=%v", published, err)
	}
	audit, err := layout.Audit(identity)
	if err != nil || !audit.Published || audit.Current {
		t.Fatalf("audit=%#v err=%v", audit, err)
	}

	collision := createFinalTestStage(t, layout, identity)
	defer collision.Close()
	if err := collision.Publish(); err == nil {
		t.Fatal("existing installed ID was replaced")
	}
	if info, err := os.Lstat(collision.Path()); err != nil || info.Mode() != os.ModeDir|0o555 {
		t.Fatalf("colliding stage was not retained: mode=%v err=%v", infoMode(info), err)
	}
}

func TestReleaseStagePublishesRootBoundEpochIdentity(t *testing.T) {
	layout, rootPath := newTestReleaseLayout(t)
	identity := testRelease(1, "8", "9", 3)
	identity.ReleaseEpoch = 2
	identity.TrustedRootVersion = 4
	identity.TrustedRootSHA256 = strings.Repeat("a", 64)
	identity.InstallerBootstrapRootSHA256 = strings.Repeat("b", 64)
	identity.InstalledID = InstalledID(identity)

	stage := createFinalTestStage(t, layout, identity)
	defer stage.Close()
	if !strings.HasPrefix(filepath.Base(stage.Path()), ".stage-e00000000000000000002-s00000000000000000001-") {
		t.Fatalf("root-bound stage name is not epoch-qualified: %q", filepath.Base(stage.Path()))
	}
	if err := stage.Publish(); err != nil {
		t.Fatal(err)
	}
	if published, err := layout.InspectRelease(identity); err != nil || !published {
		t.Fatalf("root-bound release published=%v err=%v", published, err)
	}
	if info, err := os.Lstat(filepath.Join(rootPath, "releases", identity.InstalledID)); err != nil || info.Mode() != os.ModeDir|0o555 {
		t.Fatalf("root-bound published mode=%v err=%v", infoMode(info), err)
	}
}

func TestReleaseStageFinalIdentityAndBoundedDiscard(t *testing.T) {
	layout, rootPath := newTestReleaseLayout(t)
	provisional := testRelease(15, "a", "b", 2)
	stage, err := layout.CreateStage(provisional)
	if err != nil {
		t.Fatal(err)
	}
	stagePath := stage.Path()
	if err := os.WriteFile(filepath.Join(stagePath, "partial"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	final := provisional
	final.BundleManifestSHA256 = strings.Repeat("e", 64)
	final.BundleSecurityFloor = 3
	if err := stage.FinalizeIdentity(final); err != nil {
		t.Fatal(err)
	}
	wrong := final
	wrong.ArtifactSHA256 = strings.Repeat("f", 64)
	wrong.InstalledID = InstalledID(wrong)
	if err := stage.FinalizeIdentity(wrong); err == nil {
		t.Fatal("stage accepted a different threshold-authenticated locator")
	}
	if err := stage.Discard(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stagePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("discarded stage still exists: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(rootPath, "releases"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("unexpected release entries after discard: %v err=%v", entries, err)
	}
}

func TestReleaseLayoutReconcilesCrashAbandonedIntake(t *testing.T) {
	layout, rootPath := newTestReleaseLayout(t)
	abandonedStageIdentity := testRelease(20, "1", "2", 2)
	abandonedStage, err := layout.CreateStage(abandonedStageIdentity)
	if err != nil {
		t.Fatal(err)
	}
	abandonedStagePath := abandonedStage.Path()
	if err := os.WriteFile(filepath.Join(abandonedStagePath, "partial"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := abandonedStage.Close(); err != nil {
		t.Fatal(err)
	}

	orphanIdentity := testRelease(21, "3", "4", 2)
	orphan := createFinalTestStage(t, layout, orphanIdentity)
	if err := orphan.Publish(); err != nil {
		t.Fatal(err)
	}
	if err := orphan.Close(); err != nil {
		t.Fatal(err)
	}
	if err := layout.ReconcileIntake(nil); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{abandonedStagePath, filepath.Join(rootPath, "releases", orphanIdentity.InstalledID)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("abandoned intake %q survived: %v", path, err)
		}
	}

	keptIdentity := testRelease(22, "5", "6", 2)
	kept := createFinalTestStage(t, layout, keptIdentity)
	if err := kept.Publish(); err != nil {
		t.Fatal(err)
	}
	if err := kept.Close(); err != nil {
		t.Fatal(err)
	}
	state := State{
		Schema: LegacyStateSchema, TrustPolicySHA256: strings.Repeat("f", 64), Channel: "stable",
		HighWater: keptIdentity, Active: &keptIdentity,
	}
	if err := layout.ReconcileIntake(&state); err != nil {
		t.Fatal(err)
	}
	if published, err := layout.InspectRelease(keptIdentity); err != nil || !published {
		t.Fatalf("durably referenced release was removed: published=%t err=%v", published, err)
	}
}

func TestConcurrentReleasePublicationHasOneWinner(t *testing.T) {
	layout, _ := newTestReleaseLayout(t)
	identity := testRelease(43, "3", "4", 3)
	left := createFinalTestStage(t, layout, identity)
	right := createFinalTestStage(t, layout, identity)
	defer left.Close()
	defer right.Close()

	start := make(chan struct{})
	results := make(chan error, 2)
	var group sync.WaitGroup
	for _, stage := range []*ReleaseStage{left, right} {
		group.Add(1)
		go func(stage *ReleaseStage) {
			defer group.Done()
			<-start
			results <- stage.Publish()
		}(stage)
	}
	close(start)
	group.Wait()
	close(results)
	succeeded := 0
	failed := 0
	for err := range results {
		if err == nil {
			succeeded++
		} else {
			failed++
		}
	}
	if succeeded != 1 || failed != 1 {
		t.Fatalf("concurrent publications succeeded=%d failed=%d", succeeded, failed)
	}
}

func TestReleaseLayoutCurrentSwitchAndRecoveryAudit(t *testing.T) {
	layout, rootPath := newTestReleaseLayout(t)
	first := testRelease(5, "5", "6", 1)
	second := testRelease(6, "7", "8", 2)
	publishTestRelease(t, layout, first)
	publishTestRelease(t, layout, second)

	if err := layout.SwitchCurrent(first); err != nil {
		t.Fatal(err)
	}
	current, exists, err := layout.ReadCurrent()
	if err != nil || !exists || current.InstalledID != first.InstalledID || current.Target != "releases/"+first.InstalledID {
		t.Fatalf("current=%#v exists=%v err=%v", current, exists, err)
	}
	if target, err := os.Readlink(filepath.Join(rootPath, "current")); err != nil || target != "releases/"+first.InstalledID {
		t.Fatalf("raw current target=%q err=%v", target, err)
	}
	if err := layout.SwitchCurrent(second); err != nil {
		t.Fatal(err)
	}
	firstAudit, err := layout.Audit(first)
	if err != nil || !firstAudit.Published || firstAudit.Current {
		t.Fatalf("first audit=%#v err=%v", firstAudit, err)
	}
	secondAudit, err := layout.Audit(second)
	if err != nil || !secondAudit.Published || !secondAudit.Current {
		t.Fatalf("second audit=%#v err=%v", secondAudit, err)
	}
	if err := layout.ClearCurrent(first); err == nil {
		t.Fatal("stale transaction cleared a different current release")
	}
	if err := layout.ClearCurrent(second); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := layout.ReadCurrent(); err != nil || exists {
		t.Fatalf("current survived clear: exists=%v err=%v", exists, err)
	}
	if err := layout.ClearCurrent(second); err != nil {
		t.Fatalf("idempotent current clear failed: %v", err)
	}
	entries, err := os.ReadDir(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".current-") {
			t.Fatalf("temporary current link survived successful switch: %q", entry.Name())
		}
	}
}

func TestSwitchCurrentRejectsConflictsAndUnpublishedRelease(t *testing.T) {
	tests := []struct {
		name   string
		inject func(t *testing.T, rootPath string, desired, other ReleaseIdentity)
	}{
		{
			name: "regular current",
			inject: func(t *testing.T, rootPath string, _, _ ReleaseIdentity) {
				if err := os.WriteFile(filepath.Join(rootPath, "current"), []byte("conflict"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "absolute current",
			inject: func(t *testing.T, rootPath string, desired, _ ReleaseIdentity) {
				if err := os.Symlink(filepath.Join(rootPath, "releases", desired.InstalledID), filepath.Join(rootPath, "current")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "traversing current",
			inject: func(t *testing.T, rootPath string, desired, _ ReleaseIdentity) {
				if err := os.Symlink("releases/../releases/"+desired.InstalledID, filepath.Join(rootPath, "current")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing canonical target",
			inject: func(t *testing.T, rootPath string, _, other ReleaseIdentity) {
				if err := os.Symlink("releases/"+other.InstalledID, filepath.Join(rootPath, "current")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlinked release target",
			inject: func(t *testing.T, rootPath string, desired, other ReleaseIdentity) {
				if err := os.Symlink(desired.InstalledID, filepath.Join(rootPath, "releases", other.InstalledID)); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("releases/"+other.InstalledID, filepath.Join(rootPath, "current")); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			layout, rootPath := newTestReleaseLayout(t)
			desired := testRelease(10, "9", "a", 2)
			other := testRelease(9, "b", "c", 1)
			publishTestRelease(t, layout, desired)
			test.inject(t, rootPath, desired, other)
			if _, _, err := layout.ReadCurrent(); err == nil {
				t.Fatal("malformed current link accepted")
			}
			if err := layout.SwitchCurrent(desired); err == nil {
				t.Fatal("malformed current conflict overwritten")
			}
		})
	}

	t.Run("unpublished desired", func(t *testing.T) {
		layout, _ := newTestReleaseLayout(t)
		if err := layout.SwitchCurrent(testRelease(11, "d", "e", 2)); err == nil {
			t.Fatal("unpublished release selected as current")
		}
	})
}

func TestReleaseLayoutRejectsPathAndStageSubstitution(t *testing.T) {
	t.Run("symlinked ancestor retaining same inode", func(t *testing.T) {
		outer := t.TempDir()
		parent := filepath.Join(outer, "parent")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		rootPath := filepath.Join(parent, "mesh")
		layout, err := EnsureReleaseLayout(rootPath)
		if err != nil {
			t.Fatal(err)
		}
		defer layout.Close()
		moved := parent + ".moved"
		if err := os.Rename(parent, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(moved, parent); err != nil {
			t.Fatal(err)
		}
		if _, err := layout.CreateStage(testRelease(11, "0", "f", 1)); err == nil {
			t.Fatal("symlinked ancestor accepted even though it resolved to the anchored inode")
		}
		if err := os.Remove(parent); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(moved, parent); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("layout path replacement", func(t *testing.T) {
		layout, rootPath := newTestReleaseLayout(t)
		moved := rootPath + ".moved"
		if err := os.Rename(rootPath, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(rootPath, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(rootPath, "releases"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := layout.CreateStage(testRelease(12, "1", "f", 1)); err == nil {
			t.Fatal("replacement layout path accepted by anchored handle")
		}
	})

	t.Run("stage path replacement", func(t *testing.T) {
		layout, _ := newTestReleaseLayout(t)
		identity := testRelease(13, "2", "e", 1)
		stage, err := layout.CreateStage(identity)
		if err != nil {
			t.Fatal(err)
		}
		defer stage.Close()
		moved := stage.Path() + ".moved"
		if err := os.Rename(stage.Path(), moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(stage.Path(), 0o555); err != nil {
			t.Fatal(err)
		}
		if err := stage.Root().Chmod(".", 0o555); err != nil {
			t.Fatal(err)
		}
		if err := stage.Publish(); err == nil {
			t.Fatal("substituted staging path published")
		}
	})

	t.Run("special stage mode", func(t *testing.T) {
		layout, _ := newTestReleaseLayout(t)
		identity := testRelease(14, "3", "d", 1)
		stage, err := layout.CreateStage(identity)
		if err != nil {
			t.Fatal(err)
		}
		defer stage.Close()
		if err := stage.Root().Chmod(".", 0o555|os.ModeSetgid); err != nil {
			t.Fatal(err)
		}
		if err := stage.Publish(); err == nil {
			t.Fatal("stage with special mode published")
		}
	})
}

func TestInspectReleaseRejectsPostPublicationMutation(t *testing.T) {
	layout, rootPath := newTestReleaseLayout(t)
	identity := testRelease(15, "4", "c", 1)
	publishTestRelease(t, layout, identity)
	path := filepath.Join(rootPath, "releases", identity.InstalledID)
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := layout.InspectRelease(identity); err == nil {
		t.Fatal("writable published release accepted")
	}
}

func TestReleaseLayoutRejectsForeignManagedOwnerWhenPrivileged(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to construct a foreign-owned managed directory")
	}
	rootPath := filepath.Join(t.TempDir(), "mesh")
	if err := os.Mkdir(rootPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(rootPath, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureReleaseLayout(rootPath); err == nil {
		t.Fatal("foreign-owned managed root accepted")
	}
}

func newTestReleaseLayout(t *testing.T) (*ReleaseLayout, string) {
	t.Helper()
	rootPath := filepath.Join(t.TempDir(), "mesh")
	layout, err := EnsureReleaseLayout(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := layout.Close(); err != nil {
			t.Errorf("close layout: %v", err)
		}
	})
	return layout, rootPath
}

func createFinalTestStage(t *testing.T, layout *ReleaseLayout, identity ReleaseIdentity) *ReleaseStage {
	t.Helper()
	stage, err := layout.CreateStage(identity)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := stage.Root().Stat("."); err != nil || info.Mode() != os.ModeDir|0o700 {
		_ = stage.Close()
		t.Fatalf("initial stage mode=%v err=%v", infoMode(info), err)
	}
	if err := stage.Root().Chmod(".", 0o555); err != nil {
		_ = stage.Close()
		t.Fatal(err)
	}
	return stage
}

func publishTestRelease(t *testing.T, layout *ReleaseLayout, identity ReleaseIdentity) {
	t.Helper()
	stage := createFinalTestStage(t, layout, identity)
	if err := stage.Publish(); err != nil {
		_ = stage.Close()
		t.Fatal(err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
}

func infoMode(info os.FileInfo) os.FileMode {
	if info == nil {
		return 0
	}
	return info.Mode()
}

func TestOwnedExactSymlinkRejectsExtraLink(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "link")
	if err := os.Symlink("target", link); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(link, filepath.Join(root, "second-link")); err != nil {
		t.Skipf("filesystem cannot hard-link a symlink: %v", err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if ownedExactSymlink(info) {
		t.Fatal("multiply-linked current symlink accepted")
	}
}
