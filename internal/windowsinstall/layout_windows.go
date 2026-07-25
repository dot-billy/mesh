//go:build windows

package windowsinstall

import (
	"archive/tar"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"mesh/internal/windowsauthenticode"
	"mesh/internal/windowsbundle"
	"mesh/internal/windowssecurity"
)

const (
	currentDescriptorName = "current.json"
	maximumCurrentBytes   = 4096
)

type ReleaseLayout struct {
	mu sync.Mutex

	rootPath     string
	releasesPath string
	actorSID     string
	root         *os.Root
	closed       bool
}

type CurrentSwitch struct {
	mu sync.Mutex

	layout        *ReleaseLayout
	expectedPrior *CurrentDescriptor
	target        CurrentDescriptor
	temporaryName string
}

// EnsureReleaseLayout creates only rootPath and its releases child. Existing
// ancestors are opened component by component without accepting a reparse
// point. Both managed directories receive the exact protected target-service
// DACL before the layout is returned.
func EnsureReleaseLayout(rootPath, actorSID string) (*ReleaseLayout, error) {
	if err := validateLayoutIdentity(rootPath, actorSID); err != nil {
		return nil, err
	}
	if err := ensureProtectedDirectory(rootPath, actorSID); err != nil {
		return nil, err
	}
	releasesPath := filepath.Join(rootPath, "releases")
	if err := ensureProtectedDirectory(releasesPath, actorSID); err != nil {
		return nil, err
	}
	return OpenReleaseLayout(rootPath, actorSID)
}

func OpenReleaseLayout(rootPath, actorSID string) (*ReleaseLayout, error) {
	if err := validateLayoutIdentity(rootPath, actorSID); err != nil {
		return nil, err
	}
	root, rootInfo, err := openNoReparseRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("anchor Windows release root: %w", err)
	}
	if err := inspectRootDirectory(root, rootInfo, actorSID); err != nil {
		root.Close()
		return nil, fmt.Errorf("authenticate Windows release root: %w", err)
	}
	releasesPath := filepath.Join(rootPath, "releases")
	releasesInfo, err := root.Lstat("releases")
	if err != nil || releasesInfo.Mode()&os.ModeSymlink != 0 || !releasesInfo.IsDir() {
		root.Close()
		return nil, errors.New("Windows releases root must be a real directory")
	}
	releasesRoot, err := root.OpenRoot("releases")
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("anchor Windows releases root: %w", err)
	}
	defer releasesRoot.Close()
	anchoredReleases, err := releasesRoot.Stat(".")
	if err != nil || !os.SameFile(releasesInfo, anchoredReleases) {
		root.Close()
		return nil, errors.New("Windows releases root changed while anchoring")
	}
	if err := inspectRootDirectory(releasesRoot, anchoredReleases, actorSID); err != nil {
		root.Close()
		return nil, fmt.Errorf("authenticate Windows releases root: %w", err)
	}
	return &ReleaseLayout{rootPath: rootPath, releasesPath: releasesPath, actorSID: actorSID, root: root}, nil
}

func (layout *ReleaseLayout) Close() error {
	if layout == nil {
		return nil
	}
	layout.mu.Lock()
	defer layout.mu.Unlock()
	if layout.closed {
		return nil
	}
	layout.closed = true
	if layout.root == nil {
		return nil
	}
	err := layout.root.Close()
	layout.root = nil
	return err
}

func (layout *ReleaseLayout) NewCurrentSwitch(expectedPrior *CurrentDescriptor, target CurrentDescriptor) (*CurrentSwitch, error) {
	if layout == nil || layout.closed || layout.root == nil {
		return nil, errors.New("Windows release layout is closed")
	}
	if err := target.Validate(); err != nil {
		return nil, err
	}
	if expectedPrior != nil {
		if err := expectedPrior.Validate(); err != nil {
			return nil, err
		}
		if reflect.DeepEqual(*expectedPrior, target) {
			return nil, errors.New("Windows current-switch prior and target must differ")
		}
	}
	suffix := make([]byte, 16)
	if _, err := rand.Read(suffix); err != nil {
		return nil, fmt.Errorf("create Windows current-switch identity: %w", err)
	}
	return &CurrentSwitch{
		layout: layout, expectedPrior: cloneCurrentDescriptor(expectedPrior), target: target,
		temporaryName: ".current-" + hex.EncodeToString(suffix) + ".json",
	}, nil
}

func (layout *ReleaseLayout) ResumeCurrentSwitch(expectedPrior *CurrentDescriptor, target CurrentDescriptor, temporaryName string) (*CurrentSwitch, error) {
	if !currentTemporaryPattern.MatchString(temporaryName) {
		return nil, errors.New("Windows current-switch temporary name is not canonical")
	}
	current, err := layout.NewCurrentSwitch(expectedPrior, target)
	if err != nil {
		return nil, err
	}
	current.temporaryName = temporaryName
	return current, nil
}

func (current *CurrentSwitch) TemporaryName() string {
	if current == nil {
		return ""
	}
	current.mu.Lock()
	defer current.mu.Unlock()
	return current.temporaryName
}

func (current *CurrentSwitch) Execute() error {
	if current == nil || current.layout == nil {
		return errors.New("Windows current switch is required")
	}
	current.layout.mu.Lock()
	defer current.layout.mu.Unlock()
	current.mu.Lock()
	defer current.mu.Unlock()
	if err := current.layout.validateOpenLocked(); err != nil {
		return err
	}
	return switchCurrentRelease(current, current.expectedPrior, current.target)
}

func (current *CurrentSwitch) ProveSelected() error {
	if current == nil || current.layout == nil {
		return errors.New("Windows current switch is required")
	}
	current.layout.mu.Lock()
	defer current.layout.mu.Unlock()
	current.mu.Lock()
	defer current.mu.Unlock()
	if err := current.layout.validateOpenLocked(); err != nil {
		return err
	}
	return proveCurrentRelease(current, current.target)
}

func (current *CurrentSwitch) InspectTarget(target CurrentDescriptor) error {
	if current == nil || current.layout == nil {
		return errors.New("Windows current switch is required")
	}
	if err := current.layout.inspectPublishedReleaseLocked(target); err != nil {
		return err
	}
	if err := current.layout.inspectPublishedAuthenticodeLocked(target); err != nil {
		return err
	}
	// Reconstruct the entire canonical release after native signature checks.
	// This binds each checked pathname back to the exact selected artifact and
	// detects any mutation around the path-oriented Windows trust APIs.
	return current.layout.inspectPublishedReleaseLocked(target)
}

func (layout *ReleaseLayout) InspectPublishedRelease(target CurrentDescriptor) error {
	if layout == nil {
		return errors.New("Windows release layout is required")
	}
	layout.mu.Lock()
	defer layout.mu.Unlock()
	if err := layout.validateOpenLocked(); err != nil {
		return err
	}
	return layout.inspectPublishedReleaseLocked(target)
}

func (layout *ReleaseLayout) inspectPublishedReleaseLocked(target CurrentDescriptor) error {
	relative := filepath.Join("releases", target.InstalledID)
	info, err := layout.root.Lstat(relative)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("Windows selected release is not a real published directory")
	}
	root, err := layout.root.OpenRoot(relative)
	if err != nil {
		return fmt.Errorf("anchor Windows selected release: %w", err)
	}
	defer root.Close()
	anchored, err := root.Stat(".")
	if err != nil || !os.SameFile(info, anchored) {
		return errors.New("Windows selected release changed while anchoring")
	}
	if err := inspectRootDirectory(root, anchored, layout.actorSID); err != nil {
		return fmt.Errorf("authenticate Windows selected release: %w", err)
	}
	return inspectPublishedReleaseTree(root, layout.actorSID, target)
}

func (layout *ReleaseLayout) inspectPublishedAuthenticodeLocked(target CurrentDescriptor) error {
	if err := target.Validate(); err != nil {
		return err
	}
	checks := []struct {
		name string
		role string
	}{
		{name: filepath.Join("bin", "meshctl.exe"), role: windowsauthenticode.MeshSignerRole},
		{name: filepath.Join("bin", "nebula.exe"), role: windowsauthenticode.MeshSignerRole},
		{name: filepath.Join("bin", "nebula-cert.exe"), role: windowsauthenticode.MeshSignerRole},
		{
			name: filepath.Join("bin", "dist", "windows", "wintun", "bin", target.Architecture, "wintun.dll"),
			role: windowsauthenticode.WintunSignerRole,
		},
	}
	for _, check := range checks {
		absolute := filepath.Join(layout.releasesPath, target.InstalledID, check.name)
		if _, err := windowsauthenticode.VerifyFile(absolute, check.role); err != nil {
			return fmt.Errorf("authenticate Windows published file %q with Authenticode: %w", filepath.ToSlash(check.name), err)
		}
	}
	return nil
}

func (current *CurrentSwitch) InspectCurrent() (*CurrentDescriptor, error) {
	return current.layout.readDescriptorLocked(currentDescriptorName)
}

func (current *CurrentSwitch) InspectTemporary(target CurrentDescriptor) (bool, error) {
	descriptor, err := current.layout.readDescriptorLocked(current.temporaryName)
	if err != nil {
		return false, err
	}
	if descriptor == nil {
		return false, nil
	}
	if !reflect.DeepEqual(*descriptor, target) {
		return false, errors.New("Windows current-switch temporary contains unexpected release authority")
	}
	return true, nil
}

func (current *CurrentSwitch) CreateTemporary(target CurrentDescriptor) (returnErr error) {
	raw, err := MarshalCurrentDescriptor(target)
	if err != nil {
		return err
	}
	file, err := current.layout.root.OpenFile(current.temporaryName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create Windows current-switch temporary: %w", err)
	}
	keep := false
	defer func() {
		returnErr = errors.Join(returnErr, file.Close())
		if !keep {
			_ = current.layout.root.Remove(current.temporaryName)
		}
	}()
	if err := windowssecurity.ProtectPrivateFileForActor(file, windowssecurity.RegularFile, current.layout.actorSID); err != nil {
		return fmt.Errorf("protect Windows current-switch temporary: %w", err)
	}
	if err := windowssecurity.InspectPrivateFileForActor(file, windowssecurity.RegularFile, current.layout.actorSID); err != nil {
		return fmt.Errorf("authenticate Windows current-switch temporary: %w", err)
	}
	if _, err := file.Write(raw); err != nil {
		return fmt.Errorf("write Windows current-switch temporary: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync Windows current-switch temporary: %w", err)
	}
	keep = true
	return nil
}

func (current *CurrentSwitch) RemoveTemporary() error {
	present, err := current.InspectTemporary(current.target)
	if err != nil || !present {
		return err
	}
	return current.layout.root.Remove(current.temporaryName)
}

// Windows exposes durable file flushing but no standard directory-fsync
// equivalent. Every descriptor is flushed before atomic replacement; this
// method is still an explicit state-machine boundary for a future native
// metadata flush or journal proof.
func (current *CurrentSwitch) SyncRoot() error { return nil }

func (current *CurrentSwitch) ReplaceCurrent(target CurrentDescriptor) error {
	if err := current.InspectTarget(target); err != nil {
		return err
	}
	selection, err := current.InspectCurrent()
	if err != nil {
		return err
	}
	if !descriptorEqual(selection, current.expectedPrior) {
		return errors.New("Windows current release changed immediately before replacement")
	}
	present, err := current.InspectTemporary(target)
	if err != nil {
		return err
	}
	if !present {
		return errors.New("Windows current-switch temporary disappeared before replacement")
	}
	if err := current.layout.root.Rename(current.temporaryName, currentDescriptorName); err != nil {
		return fmt.Errorf("replace Windows current descriptor: %w", err)
	}
	return nil
}

// InspectCurrentSelection reads the durable selector while holding the layout
// lock and re-authenticating the anchored release root.
func (layout *ReleaseLayout) InspectCurrentSelection() (*CurrentDescriptor, error) {
	if layout == nil {
		return nil, errors.New("Windows release layout is required")
	}
	layout.mu.Lock()
	defer layout.mu.Unlock()
	if err := layout.validateOpenLocked(); err != nil {
		return nil, err
	}
	return layout.readDescriptorLocked(currentDescriptorName)
}

func (layout *ReleaseLayout) RejectCurrentTransactionTemporaries() error {
	if layout == nil {
		return errors.New("Windows release layout is required")
	}
	layout.mu.Lock()
	defer layout.mu.Unlock()
	if err := layout.validateOpenLocked(); err != nil {
		return err
	}
	return layout.rejectCurrentTemporariesLocked()
}

// RemoveCurrentSelection removes only the exact authenticated current
// descriptor. Published releases remain intact. An orphaned current-switch
// temporary is treated as an unresolved transaction and blocks removal.
func (layout *ReleaseLayout) RemoveCurrentSelection(expected CurrentDescriptor) error {
	if layout == nil {
		return errors.New("Windows release layout is required")
	}
	if err := expected.Validate(); err != nil {
		return err
	}
	layout.mu.Lock()
	defer layout.mu.Unlock()
	if err := layout.validateOpenLocked(); err != nil {
		return err
	}
	if err := layout.rejectCurrentTemporariesLocked(); err != nil {
		return err
	}
	selected, err := layout.readDescriptorLocked(currentDescriptorName)
	if err != nil {
		return err
	}
	if selected == nil {
		return nil
	}
	if *selected != expected {
		return errors.New("Windows current selection differs from runtime-uninstall authority")
	}
	if err := layout.root.Remove(currentDescriptorName); err != nil {
		return fmt.Errorf("remove Windows current selection: %w", err)
	}
	if err := layout.rejectCurrentTemporariesLocked(); err != nil {
		return err
	}
	selected, err = layout.readDescriptorLocked(currentDescriptorName)
	if err != nil || selected != nil {
		return errors.Join(err, errors.New("Windows current selection remained after exact removal"))
	}
	return nil
}

func (layout *ReleaseLayout) rejectCurrentTemporariesLocked() error {
	entries, err := fs.ReadDir(layout.root.FS(), ".")
	if err != nil {
		return fmt.Errorf("list Windows release root for current-switch temporaries: %w", err)
	}
	for _, entry := range entries {
		if currentTemporaryPattern.MatchString(entry.Name()) {
			return fmt.Errorf("Windows current-switch temporary %q blocks runtime uninstall", entry.Name())
		}
	}
	return nil
}

func (layout *ReleaseLayout) readDescriptorLocked(name string) (*CurrentDescriptor, error) {
	if name != currentDescriptorName && !currentTemporaryPattern.MatchString(name) {
		return nil, errors.New("Windows current-descriptor name is not managed")
	}
	before, err := layout.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 2 || before.Size() > maximumCurrentBytes {
		return nil, errors.New("Windows current descriptor is not a bounded real regular file")
	}
	file, err := layout.root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open Windows current descriptor: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("Windows current descriptor changed while opening")
	}
	if err := windowssecurity.InspectPrivateFileForActor(file, windowssecurity.RegularFile, layout.actorSID); err != nil {
		return nil, fmt.Errorf("authenticate Windows current descriptor: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumCurrentBytes+1))
	if err != nil || int64(len(raw)) != opened.Size() {
		return nil, errors.New("Windows current descriptor changed while reading")
	}
	after, err := layout.root.Lstat(name)
	if err != nil || !os.SameFile(opened, after) {
		return nil, errors.New("Windows current descriptor changed during readback")
	}
	descriptor, err := ParseCurrentDescriptor(raw)
	if err != nil {
		return nil, err
	}
	return &descriptor, nil
}

func (layout *ReleaseLayout) validateOpenLocked() error {
	if layout.closed || layout.root == nil {
		return errors.New("Windows release layout is closed")
	}
	storedInfo, err := layout.root.Stat(".")
	if err != nil {
		return err
	}
	freshRoot, freshInfo, err := openNoReparseRoot(layout.rootPath)
	if err != nil {
		return fmt.Errorf("re-authenticate Windows release root path: %w", err)
	}
	defer freshRoot.Close()
	if !os.SameFile(storedInfo, freshInfo) {
		return errors.New("Windows release root path no longer names the anchored layout")
	}
	if err := inspectRootDirectory(layout.root, storedInfo, layout.actorSID); err != nil {
		return err
	}
	releasesInfo, err := layout.root.Lstat("releases")
	if err != nil || releasesInfo.Mode()&os.ModeSymlink != 0 || !releasesInfo.IsDir() {
		return errors.New("Windows releases root is no longer a real directory")
	}
	releasesRoot, err := layout.root.OpenRoot("releases")
	if err != nil {
		return fmt.Errorf("re-anchor Windows releases root: %w", err)
	}
	defer releasesRoot.Close()
	anchoredReleases, err := releasesRoot.Stat(".")
	if err != nil || !os.SameFile(releasesInfo, anchoredReleases) {
		return errors.New("Windows releases root changed while re-anchoring")
	}
	freshReleases, freshReleasesInfo, err := openNoReparseRoot(layout.releasesPath)
	if err != nil {
		return fmt.Errorf("re-authenticate Windows releases root path: %w", err)
	}
	defer freshReleases.Close()
	if !os.SameFile(anchoredReleases, freshReleasesInfo) {
		return errors.New("Windows releases root path no longer names the anchored directory")
	}
	return inspectRootDirectory(releasesRoot, anchoredReleases, layout.actorSID)
}

func validateLayoutIdentity(rootPath, actorSID string) error {
	if !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath || filepath.Dir(rootPath) == rootPath || strings.HasPrefix(rootPath, `\\`) {
		return errors.New("Windows release root must be a clean absolute local non-root path")
	}
	volume := filepath.VolumeName(rootPath)
	if len(volume) != 2 || volume[1] != ':' {
		return errors.New("Windows release root must be on a drive-letter volume")
	}
	if err := windowssecurity.ValidateActorSID(actorSID); err != nil {
		return err
	}
	return nil
}

func ensureProtectedDirectory(path, actorSID string) error {
	parent := filepath.Dir(path)
	parentRoot, _, err := openNoReparseRoot(parent)
	if err != nil {
		return fmt.Errorf("anchor Windows managed-directory parent: %w", err)
	}
	defer parentRoot.Close()
	name := filepath.Base(path)
	info, err := parentRoot.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		if err := parentRoot.Mkdir(name, 0o700); err != nil {
			return fmt.Errorf("create Windows managed directory: %w", err)
		}
		info, err = parentRoot.Lstat(name)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("created Windows managed directory is not real")
		}
	} else if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("Windows managed path is not a real directory")
	}
	file, err := parentRoot.Open(name)
	if err != nil {
		return fmt.Errorf("open Windows managed directory relative to its parent: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return errors.New("Windows managed directory changed while opening")
	}
	if err := windowssecurity.ProtectPrivateFileForActor(file, windowssecurity.Directory, actorSID); err != nil {
		return fmt.Errorf("protect Windows managed directory: %w", err)
	}
	confirmedRoot, confirmedInfo, err := openNoReparseRoot(path)
	if err != nil {
		return fmt.Errorf("confirm Windows managed-directory path: %w", err)
	}
	defer confirmedRoot.Close()
	if !os.SameFile(opened, confirmedInfo) {
		return errors.New("Windows managed-directory path changed after protection")
	}
	if err := inspectRootDirectory(confirmedRoot, confirmedInfo, actorSID); err != nil {
		return fmt.Errorf("authenticate protected Windows managed directory: %w", err)
	}
	return nil
}

func inspectRootDirectory(root *os.Root, expected os.FileInfo, actorSID string) error {
	if root == nil || expected == nil {
		return errors.New("Windows directory root and expected identity are required")
	}
	file, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open Windows directory root handle: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(expected, opened) {
		return errors.New("Windows directory root changed while opening its handle")
	}
	return windowssecurity.InspectPrivateFileForActor(file, windowssecurity.Directory, actorSID)
}

func inspectPublishedReleaseTree(root *os.Root, actorSID string, target CurrentDescriptor) error {
	packageJSON, err := readManagedReleaseFile(root, "package.json", 64<<10, actorSID)
	if err != nil {
		return err
	}
	inspection, err := windowsbundle.ReconstructCandidateInspection(target.ArtifactSHA256, packageJSON)
	if err != nil {
		return fmt.Errorf("reconstruct Windows published package authority: %w", err)
	}
	if inspection.PackageJSONSHA256 != target.PackageJSONSHA256 ||
		inspection.Package.Target.Arch != target.Architecture ||
		inspection.Package.SecurityFloor != target.SecurityFloor {
		return errors.New("Windows published package metadata differs from current-descriptor authority")
	}

	expected := map[string]bool{"package.json": false}
	for _, entry := range inspection.Package.Entries {
		expected[entry.Path] = false
		for parent := path.Dir(entry.Path); parent != "."; parent = path.Dir(parent) {
			expected[parent] = true
		}
	}
	seen := make(map[string]bool, len(expected))
	if err := fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." {
			return nil
		}
		wantDirectory, ok := expected[name]
		if !ok {
			return fmt.Errorf("Windows published release contains unexpected path %q", name)
		}
		if seen[name] || entry.Type()&os.ModeSymlink != 0 || entry.IsDir() != wantDirectory {
			return fmt.Errorf("Windows published release path %q has an unexpected type or identity", name)
		}
		seen[name] = true
		if !wantDirectory {
			return nil
		}
		before, err := root.Lstat(name)
		if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
			return fmt.Errorf("inspect Windows published directory %q", name)
		}
		directory, err := root.Open(name)
		if err != nil {
			return fmt.Errorf("open Windows published directory %q: %w", name, err)
		}
		defer directory.Close()
		opened, err := directory.Stat()
		if err != nil || !os.SameFile(before, opened) {
			return fmt.Errorf("Windows published directory %q changed while opening", name)
		}
		if err := windowssecurity.InspectPrivateManagedDirectoryForActor(directory, actorSID); err != nil {
			return fmt.Errorf("authenticate Windows published directory %q: %w", name, err)
		}
		return nil
	}); err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return errors.New("Windows published release tree is incomplete")
	}

	buildTime, err := time.Parse(time.RFC3339, inspection.Package.BuildTime)
	if err != nil {
		return errors.New("Windows published package build time is invalid")
	}
	artifactHash := sha256.New()
	counted := &countWriter{writer: artifactHash}
	archive := tar.NewWriter(counted)
	if err := writeCanonicalHeader(archive, "package.json", 0o444, int64(len(packageJSON)), buildTime); err != nil {
		return err
	}
	if _, err := archive.Write(packageJSON); err != nil {
		return fmt.Errorf("hash Windows published package metadata: %w", err)
	}
	for _, entry := range inspection.Package.Entries {
		if err := writeCanonicalHeader(archive, entry.Path, entry.ArchiveMode, entry.Size, buildTime); err != nil {
			return err
		}
		if err := streamManagedReleaseFile(root, entry, actorSID, archive); err != nil {
			return err
		}
	}
	if err := archive.Close(); err != nil {
		return fmt.Errorf("finish canonical Windows release reconstruction: %w", err)
	}
	if counted.count != inspection.ArtifactSize || hex.EncodeToString(artifactHash.Sum(nil)) != target.ArtifactSHA256 {
		return errors.New("Windows published release bytes differ from the selected canonical artifact")
	}
	return nil
}

func readManagedReleaseFile(root *os.Root, name string, maximum int64, actorSID string) ([]byte, error) {
	file, before, err := openManagedReleaseFile(root, name, maximum, actorSID)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) != before.Size() {
		return nil, fmt.Errorf("Windows published file %q changed while reading", name)
	}
	if err := proveManagedReleaseFileStable(root, name, file, before, actorSID); err != nil {
		return nil, err
	}
	return raw, nil
}

func streamManagedReleaseFile(root *os.Root, entry windowsbundle.Entry, actorSID string, destination io.Writer) error {
	file, before, err := openManagedReleaseFile(root, entry.Path, entry.Size, actorSID)
	if err != nil {
		return err
	}
	defer file.Close()
	contentHash := sha256.New()
	written, err := io.Copy(destination, io.TeeReader(io.LimitReader(file, entry.Size+1), contentHash))
	if err != nil || written != entry.Size || hex.EncodeToString(contentHash.Sum(nil)) != entry.SHA256 {
		return fmt.Errorf("Windows published file %q content differs from package.json", entry.Path)
	}
	return proveManagedReleaseFileStable(root, entry.Path, file, before, actorSID)
}

func openManagedReleaseFile(root *os.Root, name string, maximum int64, actorSID string) (*os.File, os.FileInfo, error) {
	before, err := root.Lstat(name)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maximum {
		return nil, nil, fmt.Errorf("Windows published file %q is not a bounded real regular file", name)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, nil, fmt.Errorf("open Windows published file %q: %w", name, err)
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		file.Close()
		return nil, nil, fmt.Errorf("Windows published file %q changed while opening", name)
	}
	if err := windowssecurity.InspectPrivateManagedFileSingleLinkForActor(file, actorSID); err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("authenticate Windows published file %q: %w", name, err)
	}
	return file, opened, nil
}

func proveManagedReleaseFileStable(root *os.Root, name string, file *os.File, before os.FileInfo, actorSID string) error {
	after, err := root.Lstat(name)
	openedAfter, openErr := file.Stat()
	if err != nil || openErr != nil || !os.SameFile(before, after) || !os.SameFile(before, openedAfter) || before.Size() != openedAfter.Size() {
		return fmt.Errorf("Windows published file %q changed during authentication", name)
	}
	if err := windowssecurity.InspectPrivateManagedFileSingleLinkForActor(file, actorSID); err != nil {
		return fmt.Errorf("reauthenticate Windows published file %q: %w", name, err)
	}
	return nil
}

func writeCanonicalHeader(writer *tar.Writer, name string, mode uint32, size int64, buildTime time.Time) error {
	header := &tar.Header{
		Name: name, Mode: int64(mode), Uid: 0, Gid: 0, Size: size,
		ModTime: buildTime.UTC(), AccessTime: time.Time{}, ChangeTime: time.Time{},
		Typeflag: tar.TypeReg, Format: tar.FormatUSTAR,
	}
	if err := writer.WriteHeader(header); err != nil {
		return fmt.Errorf("reconstruct Windows USTAR header for %q: %w", name, err)
	}
	return nil
}

type countWriter struct {
	writer io.Writer
	count  int64
}

func (writer *countWriter) Write(content []byte) (int, error) {
	written, err := writer.writer.Write(content)
	writer.count += int64(written)
	return written, err
}
