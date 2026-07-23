//go:build linux

package linuxinstall

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
)

const (
	ProductionMeshRoot     = "/opt/mesh"
	ProductionReleasesRoot = "/opt/mesh/releases"
	ProductionCurrentLink  = "/opt/mesh/current"

	managedLayoutMode = 0o755
	stagingMode       = 0o700
	publishedMode     = 0o555
)

var (
	installedDirectoryPattern = regexp.MustCompile(`^` + installedIDPatternBody + `$`)
	stageDirectoryPattern     = regexp.MustCompile(`^\.stage-` + installedIDPatternBody + `-[0-9a-f]{32}$`)
	layoutTemporaryPattern    = regexp.MustCompile(`^\.mesh-layout-directory-[0-9a-f]{32}$`)
)

// ReleaseLayout is an inode-anchored view of the fixed Linux release layout.
// Callers must hold the installer StateStore lock around publication and
// current-link mutations; the filesystem primitives here provide collision
// resistance and crash durability, not a second transaction lock.
type ReleaseLayout struct {
	mu sync.Mutex

	rootPath     string
	releasesPath string
	rootInfo     os.FileInfo
	releasesInfo os.FileInfo
	root         *os.Root
	releases     *os.Root
	rootDir      *os.File
	releasesDir  *os.File
	closed       bool
}

// CurrentRelease is the exact canonical relative target of /opt/mesh/current.
type CurrentRelease struct {
	InstalledID string
	Target      string
}

// ReleaseAudit describes only filesystem publication state. It does not
// replace bundle verification or the durable installer journal.
type ReleaseAudit struct {
	InstalledID string
	Published   bool
	Current     bool
}

// ReleaseStage is a create-only private staging directory bound to one
// authenticated release identity. The caller writes the deterministic bundle
// through Root and must finalize and verify it before calling Publish.
type ReleaseStage struct {
	mu sync.Mutex

	layout    *ReleaseLayout
	identity  ReleaseIdentity
	name      string
	path      string
	info      os.FileInfo
	root      *os.Root
	closed    bool
	published bool
}

// FinalizeIdentity replaces the provisional release identity used to allocate
// a private stage with the complete identity obtained from the authenticated
// inner package. The outer sequence and manifest/artifact digests—and thus the
// InstalledID—must remain exact.
func (stage *ReleaseStage) FinalizeIdentity(identity ReleaseIdentity) error {
	if stage == nil || stage.layout == nil {
		return errors.New("release stage is required")
	}
	if err := identity.Validate(); err != nil {
		return fmt.Errorf("finalize release stage identity: %w", err)
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.closed || stage.root == nil || stage.published {
		return errors.New("release stage cannot change identity after close or publication")
	}
	if identity.InstalledID != stage.identity.InstalledID ||
		identity.Sequence != stage.identity.Sequence ||
		identity.ChannelManifestSHA256 != stage.identity.ChannelManifestSHA256 ||
		identity.ReleaseManifestSHA256 != stage.identity.ReleaseManifestSHA256 ||
		identity.ArtifactSHA256 != stage.identity.ArtifactSHA256 {
		return errors.New("final release identity differs from the threshold-authenticated stage locator")
	}
	stage.identity = identity
	return nil
}

// EnsureReleaseLayout creates only the two fixed managed directories beneath
// rootPath. Existing paths must already have the exact secure type, owner, mode,
// and ancestry expected by the installer.
func EnsureReleaseLayout(rootPath string) (*ReleaseLayout, error) {
	abs, err := canonicalAbsoluteLayoutPath(rootPath)
	if err != nil {
		return nil, err
	}
	parentPath, name := filepath.Split(abs)
	parentPath = filepath.Clean(parentPath)
	if name == "" || name == "." || name == ".." {
		return nil, errors.New("release layout root must name a directory beneath an existing parent")
	}
	if err := validateSecureAncestorChain(parentPath, false); err != nil {
		return nil, fmt.Errorf("validate release layout ancestry: %w", err)
	}
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, fmt.Errorf("anchor release layout parent: %w", err)
	}
	parentDir, err := os.Open(parentPath)
	if err != nil {
		_ = parent.Close()
		return nil, fmt.Errorf("open release layout parent: %w", err)
	}
	if err := ensureManagedChild(parent, parentDir, parentPath, name); err != nil {
		_ = parentDir.Close()
		_ = parent.Close()
		return nil, err
	}
	if err := parentDir.Close(); err != nil {
		_ = parent.Close()
		return nil, err
	}
	if err := parent.Close(); err != nil {
		return nil, err
	}

	root, rootDir, rootInfo, err := openAnchoredManagedDirectory(abs, managedLayoutMode)
	if err != nil {
		return nil, err
	}
	closeRoot := func() {
		_ = rootDir.Close()
		_ = root.Close()
	}
	if err := ensureManagedChild(root, rootDir, abs, "releases"); err != nil {
		closeRoot()
		return nil, err
	}
	releasesPath := filepath.Join(abs, "releases")
	releases, releasesDir, releasesInfo, err := openAnchoredManagedDirectory(releasesPath, managedLayoutMode)
	if err != nil {
		closeRoot()
		return nil, err
	}
	layout := &ReleaseLayout{
		rootPath: abs, releasesPath: releasesPath,
		rootInfo: rootInfo, releasesInfo: releasesInfo,
		root: root, releases: releases, rootDir: rootDir, releasesDir: releasesDir,
	}
	if err := layout.validateAnchorsLocked(); err != nil {
		_ = layout.closeLocked()
		return nil, err
	}
	return layout, nil
}

// OpenReleaseLayout opens an existing layout without creating or repairing it.
func OpenReleaseLayout(rootPath string) (*ReleaseLayout, error) {
	abs, err := canonicalAbsoluteLayoutPath(rootPath)
	if err != nil {
		return nil, err
	}
	if err := validateSecureAncestorChain(abs, false); err != nil {
		return nil, fmt.Errorf("validate release layout ancestry: %w", err)
	}
	root, rootDir, rootInfo, err := openAnchoredManagedDirectory(abs, managedLayoutMode)
	if err != nil {
		return nil, err
	}
	releasesPath := filepath.Join(abs, "releases")
	releases, releasesDir, releasesInfo, err := openAnchoredManagedDirectory(releasesPath, managedLayoutMode)
	if err != nil {
		_ = rootDir.Close()
		_ = root.Close()
		return nil, err
	}
	layout := &ReleaseLayout{
		rootPath: abs, releasesPath: releasesPath,
		rootInfo: rootInfo, releasesInfo: releasesInfo,
		root: root, releases: releases, rootDir: rootDir, releasesDir: releasesDir,
	}
	if err := layout.validateAnchorsLocked(); err != nil {
		_ = layout.closeLocked()
		return nil, err
	}
	return layout, nil
}

func canonicalAbsoluteLayoutPath(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return "", errors.New("release layout root must be a clean absolute non-root path")
	}
	return path, nil
}

func ensureManagedChild(parent *os.Root, parentDir *os.File, parentPath, name string) error {
	if err := cleanupLayoutDirectoryTemporaries(parent, parentDir, parentPath); err != nil {
		return err
	}
	info, err := parent.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		temporary, err := createLayoutTemporaryDirectory(parent)
		if err != nil {
			return fmt.Errorf("create managed release directory temporary for %q: %w", filepath.Join(parentPath, name), err)
		}
		var child *os.File
		var created os.FileInfo
		temporaryNamed := true
		cleanup := func() error {
			var cleanupErr error
			if child != nil {
				cleanupErr = errors.Join(cleanupErr, child.Close())
				child = nil
			}
			if temporaryNamed {
				visible, err := parent.Lstat(temporary)
				if errors.Is(err, os.ErrNotExist) {
					return cleanupErr
				}
				if err != nil || created == nil || !os.SameFile(created, visible) ||
					!ownedTopologyTemporary(visible, true) {
					return errors.Join(cleanupErr, errors.New("managed release directory temporary changed before cleanup"))
				}
				cleanupErr = errors.Join(cleanupErr, parent.Remove(temporary), parentDir.Sync())
			}
			return cleanupErr
		}
		child, err = parent.Open(temporary)
		if err != nil {
			return errors.Join(fmt.Errorf("anchor managed release directory temporary: %w", err), cleanup())
		}
		created, err = child.Stat()
		visible, visibleErr := parent.Lstat(temporary)
		if err != nil || visibleErr != nil || !sameDirectoryObject(created, visible) || !ownedExactDirectory(created, stagingMode) {
			return errors.Join(errors.New("new managed release directory temporary changed while anchoring"), cleanup())
		}
		if err := child.Chmod(managedLayoutMode); err != nil {
			return errors.Join(fmt.Errorf("set managed release directory mode: %w", err), cleanup())
		}
		if err := child.Sync(); err != nil {
			return errors.Join(fmt.Errorf("sync managed release directory: %w", err), cleanup())
		}
		final, statErr := child.Stat()
		visible, visibleErr = parent.Lstat(temporary)
		if statErr != nil || visibleErr != nil || !sameDirectoryObject(final, visible) || !ownedExactDirectory(final, managedLayoutMode) {
			return errors.Join(errors.New("managed release directory temporary changed while finalizing"), cleanup())
		}
		if err := rejectPOSIXACL(filepath.Join(parentPath, temporary)); err != nil {
			return errors.Join(err, cleanup())
		}
		if err := child.Close(); err != nil {
			child = nil
			return errors.Join(err, cleanup())
		}
		child = nil
		if err := renameNoReplace(parentDir, temporary, name); err != nil {
			return errors.Join(fmt.Errorf("publish managed release directory without replacement: %w", err), cleanup())
		}
		temporaryNamed = false
		if err := parentDir.Sync(); err != nil {
			return fmt.Errorf("sync managed release parent: %w", err)
		}
		published, err := parent.Lstat(name)
		if err != nil || !sameDirectoryObject(created, published) || !ownedExactDirectory(published, managedLayoutMode) {
			return errors.New("published managed release directory changed")
		}
		return rejectPOSIXACL(filepath.Join(parentPath, name))
	}
	if err != nil {
		return fmt.Errorf("inspect managed release directory %q: %w", filepath.Join(parentPath, name), err)
	}
	if !ownedExactDirectory(info, managedLayoutMode) {
		return fmt.Errorf("managed release directory %q must be effective-user-owned mode-0755 without special bits", filepath.Join(parentPath, name))
	}
	return rejectPOSIXACL(filepath.Join(parentPath, name))
}

func createLayoutTemporaryDirectory(parent *os.Root) (string, error) {
	for attempt := 0; attempt < 4; attempt++ {
		suffix, err := randomLayoutSuffix()
		if err != nil {
			return "", err
		}
		name := ".mesh-layout-directory-" + suffix
		if err := parent.Mkdir(name, stagingMode); errors.Is(err, os.ErrExist) {
			continue
		} else if err != nil {
			return "", err
		}
		return name, nil
	}
	return "", errors.New("could not allocate a unique release-layout directory temporary")
}

func cleanupLayoutDirectoryTemporaries(parent *os.Root, parentDir *os.File, parentPath string) error {
	directory, err := parent.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	if len(entries) > 1<<20 {
		return errors.New("release-layout parent exceeds the cleanup entry bound")
	}
	removed := false
	for _, entry := range entries {
		if !layoutTemporaryPattern.MatchString(entry.Name()) {
			continue
		}
		info, err := parent.Lstat(entry.Name())
		if err != nil || !ownedTopologyTemporary(info, true) {
			return fmt.Errorf("release-layout temporary %q is unsafe", filepath.Join(parentPath, entry.Name()))
		}
		if err := rejectPOSIXACL(filepath.Join(parentPath, entry.Name())); err != nil {
			return err
		}
		if err := parent.Remove(entry.Name()); err != nil {
			return fmt.Errorf("remove abandoned release-layout temporary %q: %w", entry.Name(), err)
		}
		removed = true
	}
	if removed {
		return parentDir.Sync()
	}
	return nil
}

func openAnchoredManagedDirectory(path string, mode os.FileMode) (*os.Root, *os.File, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil || !ownedExactDirectory(before, mode) {
		return nil, nil, nil, fmt.Errorf("managed release path %q is not an effective-user-owned mode-%04o directory", path, mode)
	}
	if err := rejectPOSIXACL(path); err != nil {
		return nil, nil, nil, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("anchor managed release path %q: %w", path, err)
	}
	directory, err := os.Open(path)
	if err != nil {
		_ = root.Close()
		return nil, nil, nil, fmt.Errorf("open managed release path %q: %w", path, err)
	}
	rootInfo, rootErr := root.Stat(".")
	directoryInfo, directoryErr := directory.Stat()
	visible, visibleErr := os.Lstat(path)
	if rootErr != nil || directoryErr != nil || visibleErr != nil || !sameDirectoryObject(before, rootInfo) ||
		!sameDirectoryObject(before, directoryInfo) || !sameDirectoryObject(before, visible) {
		_ = directory.Close()
		_ = root.Close()
		return nil, nil, nil, fmt.Errorf("managed release path %q changed while anchoring", path)
	}
	return root, directory, before, nil
}

func ownedExactDirectory(info os.FileInfo, mode os.FileMode) bool {
	if info == nil || info.Mode() != os.ModeDir|mode {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func sameDirectoryObject(left, right os.FileInfo) bool {
	return left != nil && right != nil && left.IsDir() && right.IsDir() && os.SameFile(left, right)
}

func (layout *ReleaseLayout) validateAnchorsLocked() error {
	if layout == nil || layout.closed || layout.root == nil || layout.releases == nil || layout.rootDir == nil || layout.releasesDir == nil {
		return errors.New("release layout is closed")
	}
	if err := validateSecureAncestorChain(layout.releasesPath, false); err != nil {
		return fmt.Errorf("release layout ancestry changed: %w", err)
	}
	rootFromRoot, rootErr := layout.root.Stat(".")
	rootFromFile, rootFileErr := layout.rootDir.Stat()
	rootVisible, rootPathErr := os.Lstat(layout.rootPath)
	releasesFromRoot, releasesErr := layout.releases.Stat(".")
	releasesFromFile, releasesFileErr := layout.releasesDir.Stat()
	releasesVisible, releasesPathErr := os.Lstat(layout.releasesPath)
	releasesFromParent, parentErr := layout.root.Lstat("releases")
	if rootErr != nil || rootFileErr != nil || rootPathErr != nil || releasesErr != nil || releasesFileErr != nil ||
		releasesPathErr != nil || parentErr != nil || !sameDirectoryObject(layout.rootInfo, rootFromRoot) ||
		!sameDirectoryObject(layout.rootInfo, rootFromFile) || !sameDirectoryObject(layout.rootInfo, rootVisible) ||
		!sameDirectoryObject(layout.releasesInfo, releasesFromRoot) || !sameDirectoryObject(layout.releasesInfo, releasesFromFile) ||
		!sameDirectoryObject(layout.releasesInfo, releasesVisible) || !sameDirectoryObject(layout.releasesInfo, releasesFromParent) ||
		!ownedExactDirectory(rootFromRoot, managedLayoutMode) || !ownedExactDirectory(releasesFromRoot, managedLayoutMode) {
		return errors.New("release layout path or anchored directory changed")
	}
	if err := rejectPOSIXACL(layout.rootPath); err != nil {
		return err
	}
	return rejectPOSIXACL(layout.releasesPath)
}

// CreateStage creates and anchors a private empty directory whose name is not
// selected by the caller. Publication later derives its final name again from
// identity instead of trusting a pathname.
func (layout *ReleaseLayout) CreateStage(identity ReleaseIdentity) (*ReleaseStage, error) {
	if err := identity.Validate(); err != nil {
		return nil, fmt.Errorf("stage release identity: %w", err)
	}
	layout.mu.Lock()
	defer layout.mu.Unlock()
	if err := layout.validateAnchorsLocked(); err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 4; attempt++ {
		suffix, err := randomLayoutSuffix()
		if err != nil {
			return nil, fmt.Errorf("generate release staging name: %w", err)
		}
		name := ".stage-" + identity.InstalledID + "-" + suffix
		if err := layout.releases.Mkdir(name, stagingMode); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return nil, fmt.Errorf("create release stage: %w", err)
		}
		path := filepath.Join(layout.releasesPath, name)
		visible, visibleErr := layout.releases.Lstat(name)
		root, openErr := layout.releases.OpenRoot(name)
		if visibleErr != nil || openErr != nil {
			if root != nil {
				_ = root.Close()
			}
			return nil, errors.New("release stage changed while anchoring")
		}
		anchored, statErr := root.Stat(".")
		if statErr != nil || !sameDirectoryObject(visible, anchored) || !ownedExactDirectory(anchored, stagingMode) {
			_ = root.Close()
			return nil, errors.New("release stage is not an anchored effective-user-owned mode-0700 directory")
		}
		if err := rejectPOSIXACL(path); err != nil {
			_ = root.Close()
			return nil, err
		}
		if err := layout.releasesDir.Sync(); err != nil {
			_ = root.Close()
			return nil, fmt.Errorf("sync release stage creation: %w", err)
		}
		return &ReleaseStage{layout: layout, identity: identity, name: name, path: path, info: anchored, root: root}, nil
	}
	return nil, errors.New("could not allocate a unique release staging directory")
}

func randomLayoutSuffix() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

// Root returns the already-anchored empty staging root consumed by
// linuxbundle.StageAuthenticated. The ReleaseStage must remain open through
// publication.
func (stage *ReleaseStage) Root() *os.Root {
	if stage == nil {
		return nil
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.closed {
		return nil
	}
	return stage.root
}

// Path returns the controlled staging pathname for read-only bundle auditing.
func (stage *ReleaseStage) Path() string {
	if stage == nil {
		return ""
	}
	return stage.path
}

// Publish atomically renames a finalized 0555 stage to its authenticated
// InstalledID. Linux renameat2(RENAME_NOREPLACE) makes collisions fail rather
// than adopting or replacing an existing release.
func (stage *ReleaseStage) Publish() error {
	if stage == nil || stage.layout == nil {
		return errors.New("release stage is required")
	}
	layout := stage.layout
	layout.mu.Lock()
	defer layout.mu.Unlock()
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.closed || stage.root == nil {
		return errors.New("release stage is closed")
	}
	if err := layout.validateAnchorsLocked(); err != nil {
		return err
	}
	if err := stage.identity.Validate(); err != nil || !installedDirectoryPattern.MatchString(stage.identity.InstalledID) {
		return errors.New("release stage identity is invalid")
	}
	if stage.published {
		return stage.validatePublishedLocked()
	}
	anchored, rootErr := stage.root.Stat(".")
	visible, visibleErr := layout.releases.Lstat(stage.name)
	pathVisible, pathErr := os.Lstat(stage.path)
	if rootErr != nil || visibleErr != nil || pathErr != nil || !sameDirectoryObject(stage.info, anchored) ||
		!sameDirectoryObject(stage.info, visible) || !sameDirectoryObject(stage.info, pathVisible) ||
		!ownedExactDirectory(anchored, publishedMode) {
		return errors.New("finalized release stage path, identity, owner, or mode changed")
	}
	if err := rejectPOSIXACL(stage.path); err != nil {
		return err
	}
	if err := renameNoReplace(layout.releasesDir, stage.name, stage.identity.InstalledID); err != nil {
		return fmt.Errorf("publish release without replacement: %w", err)
	}
	stage.published = true
	if err := layout.releasesDir.Sync(); err != nil {
		return fmt.Errorf("release was renamed but releases directory sync failed: %w", err)
	}
	return stage.validatePublishedLocked()
}

func (stage *ReleaseStage) validatePublishedLocked() error {
	final, err := stage.layout.releases.Lstat(stage.identity.InstalledID)
	if err != nil || !sameDirectoryObject(stage.info, final) || !ownedExactDirectory(final, publishedMode) {
		return errors.New("published release no longer matches its anchored stage")
	}
	if _, err := stage.layout.releases.Lstat(stage.name); !errors.Is(err, os.ErrNotExist) {
		return errors.New("published release staging name still exists")
	}
	return rejectPOSIXACL(filepath.Join(stage.layout.releasesPath, stage.identity.InstalledID))
}

func (stage *ReleaseStage) Close() error {
	if stage == nil {
		return nil
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.closed {
		return nil
	}
	stage.closed = true
	if stage.root == nil {
		return nil
	}
	err := stage.root.Close()
	stage.root = nil
	return err
}

// Discard removes only this anchored unpublished private stage. It is the
// bounded cleanup path for failed intake and exact-release retries; published
// immutable releases are never removed here.
func (stage *ReleaseStage) Discard() error {
	if stage == nil || stage.layout == nil {
		return nil
	}
	layout := stage.layout
	layout.mu.Lock()
	defer layout.mu.Unlock()
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.published {
		return nil
	}
	if stage.closed || stage.root == nil {
		return errors.New("release stage is already closed")
	}
	if err := layout.validateAnchorsLocked(); err != nil {
		return err
	}
	anchored, rootErr := stage.root.Stat(".")
	visible, visibleErr := layout.releases.Lstat(stage.name)
	if rootErr != nil || visibleErr != nil || !sameDirectoryObject(stage.info, anchored) ||
		!sameDirectoryObject(stage.info, visible) || !strings.HasPrefix(stage.name, ".stage-") {
		return errors.New("release stage changed before bounded cleanup")
	}
	if err := stage.root.Close(); err != nil {
		return err
	}
	stage.root = nil
	stage.closed = true
	if err := layout.releases.RemoveAll(stage.name); err != nil {
		return fmt.Errorf("remove unpublished release stage: %w", err)
	}
	if _, err := layout.releases.Lstat(stage.name); !errors.Is(err, os.ErrNotExist) {
		return errors.New("unpublished release stage survived cleanup")
	}
	if err := layout.releasesDir.Sync(); err != nil {
		return fmt.Errorf("sync unpublished release cleanup: %w", err)
	}
	return nil
}

// ReconcileIntake removes only installer-owned unpublished stages and
// immutable releases that are not referenced by durable state or current.
// Callers hold the StateStore lock, so a crash before the prepared journal can
// be retried without accumulating hundreds of megabytes per attempt.
func (layout *ReleaseLayout) ReconcileIntake(state *State) error {
	layout.mu.Lock()
	defer layout.mu.Unlock()
	if err := layout.validateAnchorsLocked(); err != nil {
		return err
	}
	keep := make(map[string]bool)
	if state != nil {
		if err := state.Validate(); err != nil {
			return err
		}
		keepRelease := func(identity *ReleaseIdentity) {
			if identity != nil {
				keep[identity.InstalledID] = true
			}
		}
		keepRelease(&state.HighWater)
		keepRelease(state.Active)
		keepRelease(state.Previous)
		if state.Pending != nil {
			keepRelease(&state.Pending.Candidate)
			keepRelease(state.Pending.SourceActive)
			keepRelease(state.Pending.SourcePrevious)
			keepRelease(&state.Pending.TargetActive)
		}
	}
	current, exists, err := layout.readCurrentLocked()
	if err != nil {
		return err
	}
	if exists {
		keep[current.InstalledID] = true
	}
	directory, err := layout.releases.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	if len(entries) > 4096 {
		return errors.New("release directory exceeds the reconciliation entry bound")
	}
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		info, err := layout.releases.Lstat(name)
		if err != nil {
			return err
		}
		switch {
		case stageDirectoryPattern.MatchString(name):
			if !ownedExactDirectory(info, stagingMode) && !ownedExactDirectory(info, publishedMode) {
				return fmt.Errorf("unpublished stage %q has an unsafe owner, type, or mode", name)
			}
		case installedDirectoryPattern.MatchString(name):
			if keep[name] {
				continue
			}
			if !ownedExactDirectory(info, publishedMode) {
				return fmt.Errorf("orphan release %q has an unsafe owner, type, or mode", name)
			}
		default:
			return fmt.Errorf("unexpected object %q in the managed release directory", name)
		}
		path := filepath.Join(layout.releasesPath, name)
		if err := rejectPOSIXACL(path); err != nil {
			return err
		}
		if err := layout.releases.RemoveAll(name); err != nil {
			return fmt.Errorf("remove abandoned release intake %q: %w", name, err)
		}
		if _, err := layout.releases.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("abandoned release intake %q survived cleanup", name)
		}
		removed = true
	}
	if removed {
		if err := layout.releasesDir.Sync(); err != nil {
			return fmt.Errorf("sync abandoned release intake cleanup: %w", err)
		}
	}
	return nil
}

// InspectRelease validates a final release directory by authenticated identity.
func (layout *ReleaseLayout) InspectRelease(identity ReleaseIdentity) (bool, error) {
	if err := identity.Validate(); err != nil {
		return false, fmt.Errorf("inspect release identity: %w", err)
	}
	layout.mu.Lock()
	defer layout.mu.Unlock()
	if err := layout.validateAnchorsLocked(); err != nil {
		return false, err
	}
	return layout.inspectReleaseLocked(identity.InstalledID)
}

func (layout *ReleaseLayout) inspectReleaseLocked(installedID string) (bool, error) {
	if !installedDirectoryPattern.MatchString(installedID) {
		return false, errors.New("installed release directory name is not canonical")
	}
	visible, err := layout.releases.Lstat(installedID)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !ownedExactDirectory(visible, publishedMode) {
		return false, errors.New("published release must be a real effective-user-owned mode-0555 directory")
	}
	root, err := layout.releases.OpenRoot(installedID)
	if err != nil {
		return false, fmt.Errorf("anchor published release: %w", err)
	}
	defer root.Close()
	anchored, rootErr := root.Stat(".")
	pathVisible, pathErr := os.Lstat(filepath.Join(layout.releasesPath, installedID))
	if rootErr != nil || pathErr != nil || !sameDirectoryObject(visible, anchored) || !sameDirectoryObject(visible, pathVisible) {
		return false, errors.New("published release changed while anchoring")
	}
	if err := rejectPOSIXACL(filepath.Join(layout.releasesPath, installedID)); err != nil {
		return false, err
	}
	return true, nil
}

// ReadCurrent validates that current is either absent or exactly one relative
// releases/<installed-id> symlink whose target is a published immutable tree.
func (layout *ReleaseLayout) ReadCurrent() (CurrentRelease, bool, error) {
	layout.mu.Lock()
	defer layout.mu.Unlock()
	if err := layout.validateAnchorsLocked(); err != nil {
		return CurrentRelease{}, false, err
	}
	return layout.readCurrentLocked()
}

func (layout *ReleaseLayout) readCurrentLocked() (CurrentRelease, bool, error) {
	info, err := layout.root.Lstat("current")
	if errors.Is(err, os.ErrNotExist) {
		return CurrentRelease{}, false, nil
	}
	if err != nil || !ownedExactSymlink(info) {
		return CurrentRelease{}, false, errors.New("current must be an effective-user-owned canonical symlink")
	}
	target, err := layout.root.Readlink("current")
	if err != nil || strings.Contains(target, `\`) || filepath.ToSlash(target) != target {
		return CurrentRelease{}, false, errors.New("read canonical current symlink")
	}
	prefix := "releases/"
	installedID := strings.TrimPrefix(target, prefix)
	if installedID == target || target != prefix+installedID || !installedDirectoryPattern.MatchString(installedID) {
		return CurrentRelease{}, false, errors.New("current symlink target is not canonical releases/<installed-id>")
	}
	published, err := layout.inspectReleaseLocked(installedID)
	if err != nil || !published {
		if err != nil {
			return CurrentRelease{}, false, err
		}
		return CurrentRelease{}, false, errors.New("current symlink target is not a published release")
	}
	return CurrentRelease{InstalledID: installedID, Target: target}, true, nil
}

func ownedExactSymlink(info os.FileInfo) bool {
	if info == nil || info.Mode() != os.ModeSymlink|0o777 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}

// SwitchCurrent durably replaces current with a canonical relative symlink to
// an already-published authenticated identity. Invalid pre-existing current
// paths are conflicts and are never overwritten.
func (layout *ReleaseLayout) SwitchCurrent(identity ReleaseIdentity) error {
	if err := identity.Validate(); err != nil {
		return fmt.Errorf("switch current release identity: %w", err)
	}
	layout.mu.Lock()
	defer layout.mu.Unlock()
	if err := layout.validateAnchorsLocked(); err != nil {
		return err
	}
	published, err := layout.inspectReleaseLocked(identity.InstalledID)
	if err != nil || !published {
		if err != nil {
			return err
		}
		return errors.New("cannot switch current to an unpublished release")
	}
	before, existed, err := layout.readCurrentLocked()
	if err != nil {
		return err
	}
	target := "releases/" + identity.InstalledID
	if existed && before.Target == target {
		return nil
	}
	temporary, err := randomCurrentName()
	if err != nil {
		return fmt.Errorf("generate current-link staging name: %w", err)
	}
	if err := layout.root.Symlink(target, temporary); err != nil {
		return fmt.Errorf("create temporary current symlink: %w", err)
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = layout.root.Remove(temporary)
			_ = layout.rootDir.Sync()
		}
	}()
	temporaryInfo, infoErr := layout.root.Lstat(temporary)
	temporaryTarget, targetErr := layout.root.Readlink(temporary)
	if infoErr != nil || targetErr != nil || !ownedExactSymlink(temporaryInfo) || temporaryTarget != target {
		return errors.New("temporary current symlink changed before switch")
	}
	if err := layout.rootDir.Sync(); err != nil {
		return fmt.Errorf("sync temporary current symlink: %w", err)
	}
	currentAgain, existsAgain, err := layout.readCurrentLocked()
	if err != nil || existsAgain != existed || currentAgain != before {
		if err != nil {
			return err
		}
		return errors.New("current symlink changed during switch")
	}
	if err := layout.root.Rename(temporary, "current"); err != nil {
		return fmt.Errorf("atomically switch current symlink: %w", err)
	}
	removeTemporary = false
	if err := layout.rootDir.Sync(); err != nil {
		return fmt.Errorf("current was switched but layout sync failed: %w", err)
	}
	current, ok, err := layout.readCurrentLocked()
	if err != nil || !ok || current.Target != target {
		if err != nil {
			return err
		}
		return errors.New("current symlink does not match the switched release")
	}
	return nil
}

func randomCurrentName() (string, error) {
	suffix, err := randomLayoutSuffix()
	if err != nil {
		return "", err
	}
	return ".current-" + suffix, nil
}

// ClearCurrent removes current only when it is absent or points to expected.
// This supports rollback of a failed first installation without permitting a
// stale transaction to unlink a newer release selected by another transaction.
func (layout *ReleaseLayout) ClearCurrent(expected ReleaseIdentity) error {
	if err := expected.Validate(); err != nil {
		return fmt.Errorf("clear current release identity: %w", err)
	}
	layout.mu.Lock()
	defer layout.mu.Unlock()
	if err := layout.validateAnchorsLocked(); err != nil {
		return err
	}
	current, exists, err := layout.readCurrentLocked()
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if current.InstalledID != expected.InstalledID {
		return errors.New("refusing to clear a current release different from the transaction target")
	}
	if err := layout.root.Remove("current"); err != nil {
		return fmt.Errorf("remove current symlink: %w", err)
	}
	if err := layout.rootDir.Sync(); err != nil {
		return fmt.Errorf("current was removed but layout sync failed: %w", err)
	}
	return nil
}

// Audit provides the two filesystem facts used during journal recovery.
func (layout *ReleaseLayout) Audit(identity ReleaseIdentity) (ReleaseAudit, error) {
	if err := identity.Validate(); err != nil {
		return ReleaseAudit{}, fmt.Errorf("audit release identity: %w", err)
	}
	layout.mu.Lock()
	defer layout.mu.Unlock()
	if err := layout.validateAnchorsLocked(); err != nil {
		return ReleaseAudit{}, err
	}
	published, err := layout.inspectReleaseLocked(identity.InstalledID)
	if err != nil {
		return ReleaseAudit{}, err
	}
	current, exists, err := layout.readCurrentLocked()
	if err != nil {
		return ReleaseAudit{}, err
	}
	return ReleaseAudit{InstalledID: identity.InstalledID, Published: published, Current: exists && current.InstalledID == identity.InstalledID}, nil
}

func (layout *ReleaseLayout) Close() error {
	if layout == nil {
		return nil
	}
	layout.mu.Lock()
	defer layout.mu.Unlock()
	return layout.closeLocked()
}

func (layout *ReleaseLayout) closeLocked() error {
	if layout.closed {
		return nil
	}
	layout.closed = true
	var errs []error
	for _, closer := range []io.Closer{layout.releasesDir, layout.releases, layout.rootDir, layout.root} {
		if closer != nil {
			if err := closer.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
