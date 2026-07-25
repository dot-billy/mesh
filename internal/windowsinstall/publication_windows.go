//go:build windows

package windowsinstall

import (
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
	"sort"
	"strings"
	"sync"

	"mesh/internal/windowsbundle"
	"mesh/internal/windowssecurity"

	"golang.org/x/sys/windows"
)

// ReleaseStage owns one randomly named private directory for a release target
// selected by independently authenticated outer metadata. Candidate archive
// contents may prove conformance to compiled policy, but never select target.
type ReleaseStage struct {
	mu sync.Mutex

	layout    *ReleaseLayout
	target    CurrentDescriptor
	name      string
	path      string
	root      *os.Root
	identity  os.FileInfo
	authority *AuthenticatedWindowsRelease
	staged    bool
	published bool
	closed    bool
}

// CreateAuthenticatedStage is the lower-level publication mechanism. The
// production path uses PublishAcceptedWindowsIntake so high-water commit and
// deterministic restart recovery cannot be separated.
func (layout *ReleaseLayout) CreateAuthenticatedStage(authority AuthenticatedWindowsRelease) (*ReleaseStage, error) {
	target, err := authority.CurrentDescriptor()
	if err != nil {
		return nil, err
	}
	stage, err := layout.createStage(target)
	if err != nil {
		return nil, err
	}
	copy := authority
	stage.authority = &copy
	return stage, nil
}

func (layout *ReleaseLayout) createStage(target CurrentDescriptor) (*ReleaseStage, error) {
	if layout == nil {
		return nil, errors.New("Windows release layout is required")
	}
	if err := target.Validate(); err != nil {
		return nil, err
	}
	layout.mu.Lock()
	defer layout.mu.Unlock()
	if err := layout.validateOpenLocked(); err != nil {
		return nil, err
	}
	publishedRelative := filepath.Join("releases", target.InstalledID)
	if _, err := layout.root.Lstat(publishedRelative); err == nil {
		return nil, errors.New("Windows target release is already present")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect Windows target release: %w", err)
	}
	for attempt := 0; attempt < 4; attempt++ {
		suffix := make([]byte, 16)
		if _, err := rand.Read(suffix); err != nil {
			return nil, fmt.Errorf("create Windows release-stage identity: %w", err)
		}
		name := ".stage-" + target.InstalledID + "-" + hex.EncodeToString(suffix)
		relative := filepath.Join("releases", name)
		if err := layout.root.Mkdir(relative, 0o700); errors.Is(err, os.ErrExist) {
			continue
		} else if err != nil {
			return nil, fmt.Errorf("create Windows release stage: %w", err)
		}
		cleanup := true
		defer func() {
			if cleanup {
				_ = layout.root.Remove(relative)
			}
		}()
		visible, err := layout.root.Lstat(relative)
		if err != nil || visible.Mode()&os.ModeSymlink != 0 || !visible.IsDir() {
			return nil, errors.New("created Windows release stage is not a real directory")
		}
		directory, err := layout.root.Open(relative)
		if err != nil {
			return nil, fmt.Errorf("open Windows release-stage directory: %w", err)
		}
		opened, statErr := directory.Stat()
		if statErr != nil || !os.SameFile(visible, opened) {
			directory.Close()
			return nil, errors.New("Windows release stage changed while opening")
		}
		if err := windowssecurity.ProtectPrivateFileForActor(directory, windowssecurity.Directory, layout.actorSID); err != nil {
			directory.Close()
			return nil, fmt.Errorf("protect Windows release stage: %w", err)
		}
		if err := directory.Close(); err != nil {
			return nil, fmt.Errorf("close protected Windows release stage: %w", err)
		}
		stagePath := filepath.Join(layout.releasesPath, name)
		root, identity, err := openNoReparseRoot(stagePath)
		if err != nil {
			return nil, fmt.Errorf("anchor Windows release stage: %w", err)
		}
		if !os.SameFile(visible, identity) {
			root.Close()
			return nil, errors.New("Windows release-stage path changed after protection")
		}
		if err := inspectRootDirectory(root, identity, layout.actorSID); err != nil {
			root.Close()
			return nil, fmt.Errorf("authenticate Windows release stage: %w", err)
		}
		cleanup = false
		return &ReleaseStage{
			layout: layout, target: target, name: name, path: stagePath,
			root: root, identity: identity,
		}, nil
	}
	return nil, errors.New("could not allocate a unique Windows release stage")
}

// ResumeStage reanchors one finalized directory named by durable installer
// state. Exactly one of stageName and target.InstalledID must exist, and its
// full canonical artifact must match target before recovery can continue.
// ResumeAuthenticatedStage reanchors only the exact stage/published directory
// named by durable state and the same completed outer authority.
func (layout *ReleaseLayout) ResumeAuthenticatedStage(authority AuthenticatedWindowsRelease, stageName string) (*ReleaseStage, error) {
	target, err := authority.CurrentDescriptor()
	if err != nil {
		return nil, err
	}
	stage, err := layout.resumeStage(target, stageName)
	if err != nil {
		return nil, err
	}
	copy := authority
	stage.authority = &copy
	return stage, nil
}

func (layout *ReleaseLayout) resumeStage(target CurrentDescriptor, stageName string) (*ReleaseStage, error) {
	if layout == nil {
		return nil, errors.New("Windows release layout is required")
	}
	if err := target.Validate(); err != nil {
		return nil, err
	}
	if !releaseStageNamePattern.MatchString(stageName) || !strings.HasPrefix(stageName, ".stage-"+target.InstalledID+"-") {
		return nil, errors.New("Windows release recovery identity is not canonical")
	}
	layout.mu.Lock()
	defer layout.mu.Unlock()
	if err := layout.validateOpenLocked(); err != nil {
		return nil, err
	}
	stageExists, err := layout.releaseDirectoryExistsLocked(stageName)
	if err != nil {
		return nil, err
	}
	publishedExists, err := layout.releaseDirectoryExistsLocked(target.InstalledID)
	if err != nil {
		return nil, err
	}
	if stageExists == publishedExists {
		return nil, errors.New("Windows release recovery requires exactly one stage or published directory")
	}
	visibleName := stageName
	published := false
	if publishedExists {
		visibleName = target.InstalledID
		published = true
	}
	root, identity, err := layout.openReleaseDirectoryLocked(visibleName)
	if err != nil {
		return nil, err
	}
	if err := inspectPublishedReleaseTree(root, layout.actorSID, target); err != nil {
		root.Close()
		return nil, err
	}
	return &ReleaseStage{
		layout: layout, target: target, name: stageName,
		path: filepath.Join(layout.releasesPath, visibleName), root: root, identity: identity,
		staged: true, published: published,
	}, nil
}

func (stage *ReleaseStage) StageAuthenticatedArtifact(artifactPath string) (windowsbundle.CandidateInspection, error) {
	if stage == nil || stage.layout == nil {
		return windowsbundle.CandidateInspection{}, errors.New("Windows release stage is required")
	}
	stage.layout.mu.Lock()
	defer stage.layout.mu.Unlock()
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.closed || stage.root == nil || stage.staged || stage.published {
		return windowsbundle.CandidateInspection{}, errors.New("Windows release stage is not empty and writable")
	}
	if err := stage.layout.validateOpenLocked(); err != nil {
		return windowsbundle.CandidateInspection{}, err
	}
	state, err := stage.inspectNamedTreeLocked(stage.name)
	if err != nil || state != windowsReleaseDirectoryPrivate {
		if err != nil {
			return windowsbundle.CandidateInspection{}, err
		}
		return windowsbundle.CandidateInspection{}, errors.New("Windows private release stage changed before bundle intake")
	}
	raw, err := readAuthenticatedWindowsCandidate(artifactPath, stage.layout.actorSID)
	if err != nil {
		return windowsbundle.CandidateInspection{}, err
	}
	expanded, err := windowsbundle.InspectCandidateArchive(raw)
	if err != nil {
		return windowsbundle.CandidateInspection{}, err
	}
	if err := candidateMatchesWindowsTarget(expanded.Inspection, stage.target); err != nil {
		return windowsbundle.CandidateInspection{}, err
	}
	if err := stage.writeExpandedCandidateLocked(expanded); err != nil {
		return windowsbundle.CandidateInspection{}, err
	}
	stage.staged = true
	if state, err := stage.inspectNamedTreeLocked(stage.name); err != nil || state != windowsReleaseDirectoryFinalized {
		stage.staged = false
		if err != nil {
			return windowsbundle.CandidateInspection{}, err
		}
		return windowsbundle.CandidateInspection{}, errors.New("Windows release stage did not finalize exactly")
	}
	return expanded.Inspection, nil
}

func (stage *ReleaseStage) Publish() error {
	if stage == nil || stage.layout == nil {
		return errors.New("Windows release stage is required")
	}
	stage.layout.mu.Lock()
	defer stage.layout.mu.Unlock()
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.closed || !stage.staged {
		return errors.New("Windows release stage is not finalized")
	}
	if err := stage.layout.validateOpenLocked(); err != nil {
		return err
	}
	if err := publishWindowsFinalizedRelease(stage); err != nil {
		return err
	}
	if err := stage.reanchorLocked(stage.target.InstalledID); err != nil {
		return err
	}
	stage.published = true
	stage.path = filepath.Join(stage.layout.releasesPath, stage.target.InstalledID)
	return nil
}

func (stage *ReleaseStage) InspectStage() (windowsReleaseDirectoryState, error) {
	return stage.inspectNamedTreeLocked(stage.name)
}

func (stage *ReleaseStage) InspectPublished() (windowsReleaseDirectoryState, error) {
	return stage.inspectNamedTreeLocked(stage.target.InstalledID)
}

// Windows has no directory-fsync equivalent in Go. Every staged file is
// flushed before this boundary and the complete tree is reauthenticated here.
func (stage *ReleaseStage) SyncStage() error {
	state, err := stage.inspectNamedTreeLocked(stage.name)
	if err != nil {
		return err
	}
	if state != windowsReleaseDirectoryFinalized {
		return errors.New("Windows release stage is not finalized before publication")
	}
	return nil
}

func (stage *ReleaseStage) PublishNoReplace() error {
	if stage.root != nil {
		if err := stage.root.Close(); err != nil {
			return fmt.Errorf("close Windows release-stage anchor before rename: %w", err)
		}
		stage.root = nil
	}
	from, err := windows.UTF16PtrFromString(filepath.Join(stage.layout.releasesPath, stage.name))
	if err != nil {
		return fmt.Errorf("encode Windows release-stage path: %w", err)
	}
	to, err := windows.UTF16PtrFromString(filepath.Join(stage.layout.releasesPath, stage.target.InstalledID))
	if err != nil {
		return fmt.Errorf("encode Windows published-release path: %w", err)
	}
	// Omitting MOVEFILE_REPLACE_EXISTING makes target creation exclusive.
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return fmt.Errorf("publish Windows release without replacement: %w", err)
	}
	return nil
}

// MOVEFILE_WRITE_THROUGH is the native publication durability primitive. This
// explicit boundary reauthenticates the still-anchored managed layout.
func (stage *ReleaseStage) SyncReleases() error {
	return stage.layout.validateOpenLocked()
}

func (stage *ReleaseStage) Name() string {
	if stage == nil {
		return ""
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	return stage.name
}

func (stage *ReleaseStage) Path() string {
	if stage == nil {
		return ""
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	return stage.path
}

func (stage *ReleaseStage) Target() CurrentDescriptor {
	if stage == nil {
		return CurrentDescriptor{}
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	return stage.target
}

func (stage *ReleaseStage) Authority() (*AuthenticatedWindowsRelease, error) {
	if stage == nil {
		return nil, errors.New("Windows release stage is required")
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.authority == nil {
		return nil, errors.New("Windows release stage has no completed outer authority")
	}
	copy := *stage.authority
	if err := copy.Validate(); err != nil {
		return nil, err
	}
	return &copy, nil
}

// Close releases handles but deliberately leaves a recognized stage in place
// so a durable activation journal can resume publication after a crash.
func (stage *ReleaseStage) Close() error {
	if stage == nil {
		return nil
	}
	if stage.layout != nil {
		stage.layout.mu.Lock()
		defer stage.layout.mu.Unlock()
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

func (stage *ReleaseStage) inspectNamedTreeLocked(name string) (windowsReleaseDirectoryState, error) {
	root, identity, err := stage.layout.openReleaseDirectoryLocked(name)
	if errors.Is(err, os.ErrNotExist) {
		return windowsReleaseDirectoryAbsent, nil
	}
	if err != nil {
		return windowsReleaseDirectoryAbsent, err
	}
	defer root.Close()
	if stage.identity == nil || !os.SameFile(stage.identity, identity) {
		return windowsReleaseDirectoryAbsent, fmt.Errorf("Windows release path %q does not identify its anchored stage", name)
	}
	if name == stage.name && !stage.staged {
		children, err := fs.ReadDir(root.FS(), ".")
		if err != nil {
			return windowsReleaseDirectoryAbsent, err
		}
		if len(children) != 0 {
			return windowsReleaseDirectoryAbsent, errors.New("Windows private release stage contains an incomplete tree")
		}
		return windowsReleaseDirectoryPrivate, nil
	}
	if !stage.staged {
		return windowsReleaseDirectoryAbsent, errors.New("Windows published release has no authenticated target")
	}
	if err := inspectPublishedReleaseTree(root, stage.layout.actorSID, stage.target); err != nil {
		return windowsReleaseDirectoryAbsent, err
	}
	return windowsReleaseDirectoryFinalized, nil
}

func (stage *ReleaseStage) reanchorLocked(name string) error {
	root, identity, err := stage.layout.openReleaseDirectoryLocked(name)
	if err != nil {
		return err
	}
	if stage.identity == nil || !os.SameFile(stage.identity, identity) {
		root.Close()
		return errors.New("Windows published release changed identity while reanchoring")
	}
	if err := inspectPublishedReleaseTree(root, stage.layout.actorSID, stage.target); err != nil {
		root.Close()
		return err
	}
	if stage.root != nil {
		_ = stage.root.Close()
	}
	stage.root = root
	return nil
}

func (layout *ReleaseLayout) releaseDirectoryExistsLocked(name string) (bool, error) {
	relative := filepath.Join("releases", name)
	info, err := layout.root.Lstat(relative)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, fmt.Errorf("Windows release path %q is not a real directory", name)
	}
	return true, nil
}

func (layout *ReleaseLayout) openReleaseDirectoryLocked(name string) (*os.Root, os.FileInfo, error) {
	relative := filepath.Join("releases", name)
	visible, err := layout.root.Lstat(relative)
	if err != nil {
		return nil, nil, err
	}
	if visible.Mode()&os.ModeSymlink != 0 || !visible.IsDir() {
		return nil, nil, fmt.Errorf("Windows release path %q is not a real directory", name)
	}
	root, identity, err := openNoReparseRoot(filepath.Join(layout.releasesPath, name))
	if err != nil {
		return nil, nil, err
	}
	if !os.SameFile(visible, identity) {
		root.Close()
		return nil, nil, fmt.Errorf("Windows release path %q changed while anchoring", name)
	}
	if err := inspectRootDirectory(root, identity, layout.actorSID); err != nil {
		root.Close()
		return nil, nil, err
	}
	return root, identity, nil
}

func readAuthenticatedWindowsCandidate(artifactPath, actorSID string) ([]byte, error) {
	if !filepath.IsAbs(artifactPath) || filepath.Clean(artifactPath) != artifactPath || filepath.Dir(artifactPath) == artifactPath || strings.HasPrefix(artifactPath, `\\`) {
		return nil, errors.New("Windows candidate artifact must be a clean absolute local non-root path")
	}
	volume := filepath.VolumeName(artifactPath)
	if len(volume) != 2 || volume[1] != ':' {
		return nil, errors.New("Windows candidate artifact must be on a drive-letter volume")
	}
	parentRoot, _, err := openNoReparseRoot(filepath.Dir(artifactPath))
	if err != nil {
		return nil, fmt.Errorf("anchor Windows candidate parent: %w", err)
	}
	defer parentRoot.Close()
	name := filepath.Base(artifactPath)
	before, err := parentRoot.Lstat(name)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > windowsbundle.MaxArchiveSize {
		return nil, errors.New("Windows candidate artifact must be one bounded real regular file")
	}
	file, err := parentRoot.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open Windows candidate artifact: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !sameStableWindowsFile(before, opened) {
		return nil, errors.New("Windows candidate artifact changed while opening")
	}
	if err := windowssecurity.InspectPrivateFileSingleLinkForActor(file, windowssecurity.RegularFile, actorSID); err != nil {
		return nil, fmt.Errorf("authenticate Windows candidate artifact: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, windowsbundle.MaxArchiveSize+1))
	if err != nil || int64(len(raw)) != opened.Size() {
		return nil, errors.New("Windows candidate artifact changed or exceeded its bound while reading")
	}
	after, statErr := file.Stat()
	visibleAfter, pathErr := parentRoot.Lstat(name)
	if statErr != nil || pathErr != nil || !sameStableWindowsFile(opened, after) || !sameStableWindowsFile(opened, visibleAfter) {
		return nil, errors.New("Windows candidate artifact changed during snapshot")
	}
	if err := windowssecurity.InspectPrivateFileSingleLinkForActor(file, windowssecurity.RegularFile, actorSID); err != nil {
		return nil, fmt.Errorf("reauthenticate Windows candidate artifact: %w", err)
	}
	return raw, nil
}

func sameStableWindowsFile(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) && left.Mode() == right.Mode() &&
		left.Size() == right.Size() && left.ModTime().Equal(right.ModTime())
}

func candidateMatchesWindowsTarget(inspection windowsbundle.CandidateInspection, target CurrentDescriptor) error {
	if err := windowsbundle.ValidateCandidateInspection(inspection); err != nil {
		return err
	}
	want, err := CurrentDescriptorFromInspection(target.InstalledID, inspection)
	if err != nil {
		return err
	}
	if want != target {
		return errors.New("Windows candidate artifact differs from authenticated release authority")
	}
	return nil
}

func (stage *ReleaseStage) writeExpandedCandidateLocked(expanded windowsbundle.ExpandedCandidate) error {
	if err := validateExpandedWindowsCandidate(expanded); err != nil {
		return err
	}
	children, err := fs.ReadDir(stage.root.FS(), ".")
	if err != nil || len(children) != 0 {
		return errors.New("Windows release stage must be empty before expansion")
	}
	directories := expandedWindowsDirectories(expanded.Files)
	for _, directoryName := range directories {
		relative := filepath.FromSlash(directoryName)
		if err := stage.root.Mkdir(relative, 0o700); err != nil {
			return fmt.Errorf("create Windows release directory %q: %w", directoryName, err)
		}
		visible, err := stage.root.Lstat(relative)
		if err != nil || visible.Mode()&os.ModeSymlink != 0 || !visible.IsDir() {
			return fmt.Errorf("created Windows release directory %q is not real", directoryName)
		}
		directory, err := stage.root.Open(relative)
		if err != nil {
			return fmt.Errorf("open Windows release directory %q: %w", directoryName, err)
		}
		opened, statErr := directory.Stat()
		if statErr != nil || !os.SameFile(visible, opened) {
			directory.Close()
			return fmt.Errorf("Windows release directory %q changed while opening", directoryName)
		}
		protectErr := windowssecurity.ProtectPrivateFileForActor(directory, windowssecurity.Directory, stage.layout.actorSID)
		closeErr := directory.Close()
		if protectErr != nil || closeErr != nil {
			return fmt.Errorf("protect Windows release directory %q: protect=%v close=%v", directoryName, protectErr, closeErr)
		}
	}
	for _, expandedFile := range expanded.Files {
		relative := filepath.FromSlash(expandedFile.Path)
		file, err := stage.root.OpenFile(relative, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("create Windows release file %q: %w", expandedFile.Path, err)
		}
		protectErr := windowssecurity.ProtectPrivateFileForActor(file, windowssecurity.RegularFile, stage.layout.actorSID)
		written, writeErr := file.Write(expandedFile.Content)
		syncErr := file.Sync()
		inspectErr := windowssecurity.InspectPrivateFileSingleLinkForActor(file, windowssecurity.RegularFile, stage.layout.actorSID)
		closeErr := file.Close()
		if protectErr != nil || writeErr != nil || written != len(expandedFile.Content) || syncErr != nil || inspectErr != nil || closeErr != nil {
			return fmt.Errorf(
				"finish Windows release file %q: protect=%v write=%v bytes=%d/%d sync=%v inspect=%v close=%v",
				expandedFile.Path, protectErr, writeErr, written, len(expandedFile.Content), syncErr, inspectErr, closeErr,
			)
		}
	}
	return inspectPublishedReleaseTree(stage.root, stage.layout.actorSID, stage.target)
}

func validateExpandedWindowsCandidate(expanded windowsbundle.ExpandedCandidate) error {
	if err := windowsbundle.ValidateCandidateInspection(expanded.Inspection); err != nil {
		return err
	}
	entries := expanded.Inspection.Package.Entries
	if len(expanded.Files) != len(entries)+1 {
		return errors.New("expanded Windows candidate has an unexpected file count")
	}
	for index, file := range expanded.Files {
		if !safeExpandedWindowsPath(file.Path) || len(file.Content) == 0 {
			return fmt.Errorf("expanded Windows candidate path %q is invalid", file.Path)
		}
		if index == 0 {
			if file.Path != "package.json" || file.ArchiveMode != 0o444 || int64(len(file.Content)) > 64<<10 {
				return errors.New("expanded Windows candidate package.json is invalid")
			}
			digest := sha256.Sum256(file.Content)
			if hex.EncodeToString(digest[:]) != expanded.Inspection.PackageJSONSHA256 {
				return errors.New("expanded Windows candidate package.json digest differs")
			}
			continue
		}
		entry := entries[index-1]
		digest := sha256.Sum256(file.Content)
		if file.Path != entry.Path || file.ArchiveMode != entry.ArchiveMode || int64(len(file.Content)) != entry.Size ||
			hex.EncodeToString(digest[:]) != entry.SHA256 {
			return fmt.Errorf("expanded Windows candidate file %q differs from package.json", file.Path)
		}
	}
	return nil
}

func safeExpandedWindowsPath(name string) bool {
	return name != "" && name != "." && path.Clean(name) == name && !strings.HasPrefix(name, "/") &&
		!strings.HasPrefix(name, "../") && !strings.ContainsAny(name, `\:`)
}

func expandedWindowsDirectories(files []windowsbundle.ExpandedFile) []string {
	set := make(map[string]struct{})
	for _, file := range files {
		for parent := path.Dir(file.Path); parent != "."; parent = path.Dir(parent) {
			set[parent] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for directory := range set {
		result = append(result, directory)
	}
	sort.Slice(result, func(left, right int) bool {
		leftDepth, rightDepth := strings.Count(result[left], "/"), strings.Count(result[right], "/")
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		return result[left] < result[right]
	})
	return result
}
