//go:build darwin

package darwininstall

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"mesh/internal/darwinbundle"
	"mesh/internal/nodeagent"

	"golang.org/x/sys/unix"
)

const (
	ProductionMeshRoot     = "/opt/mesh"
	ProductionReleasesRoot = ProductionMeshRoot + "/releases"
	ProductionCurrentLink  = ProductionMeshRoot + "/current"

	darwinManagedReleaseDirectoryMode = uint16(0o755)
	darwinPrivateReleaseStageMode     = uint16(0o700)
	darwinPublishedReleaseMode        = uint16(0o555)
	maximumDarwinReleaseTreeEntries   = 32
)

// ReleaseLayout is a descriptor-anchored view of one root:wheel immutable
// release namespace. InstallerJournalStore serializes transaction callers
// across processes; the mutex here prevents only in-process overlap.
type ReleaseLayout struct {
	mu sync.Mutex

	rootPath     string
	releasesPath string
	root         *os.File
	releases     *os.File
	rootFD       int
	releasesFD   int
	rootIdentity darwinInstallObjectIdentity
	releasesID   darwinInstallObjectIdentity
	closed       bool
}

// ReleaseStage owns one randomly named private stage and the exact inspection
// of the authenticated Darwin bundle written into it.
type ReleaseStage struct {
	mu sync.Mutex

	layout      *ReleaseLayout
	installedID string
	name        string
	path        string
	directory   *os.File
	fd          int
	identity    darwinInstallObjectIdentity
	inspection  darwinbundle.CandidateInspection
	staged      bool
	published   bool
	closed      bool
}

type darwinReleaseFileExpectation struct {
	mode   uint16
	size   int64
	digest string
}

type darwinInstallObjectIdentity struct {
	device     int32
	inode      uint64
	generation uint32
	typeBits   uint16
}

func EnsureProductionReleaseLayout() (*ReleaseLayout, error) {
	return EnsureReleaseLayout(ProductionMeshRoot)
}

// EnsureReleaseLayout creates only rootPath and its releases child. Every
// existing ancestor and resulting directory must already satisfy the native
// root:wheel, no-ACL/xattr/flags path policy.
func EnsureReleaseLayout(rootPath string) (*ReleaseLayout, error) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return nil, errors.New("Darwin release-layout creation requires root:wheel execution")
	}
	if !cleanDarwinInstallPath(rootPath) {
		return nil, errors.New("Darwin release-layout root must be an exact absolute non-root path")
	}
	if err := ensureDarwinReleaseDirectory(rootPath); err != nil {
		return nil, err
	}
	releasesPath := filepath.Join(rootPath, "releases")
	if err := ensureDarwinReleaseDirectory(releasesPath); err != nil {
		return nil, err
	}
	return openDarwinReleaseLayout(rootPath)
}

func OpenReleaseLayout(rootPath string) (*ReleaseLayout, error) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return nil, errors.New("Darwin release-layout access requires root:wheel execution")
	}
	if !cleanDarwinInstallPath(rootPath) {
		return nil, errors.New("Darwin release-layout root must be an exact absolute non-root path")
	}
	return openDarwinReleaseLayout(rootPath)
}

func openDarwinReleaseLayout(rootPath string) (*ReleaseLayout, error) {
	root, rootFD, rootStat, err := openDarwinManagedReleaseDirectory(rootPath)
	if err != nil {
		return nil, err
	}
	releasesPath := filepath.Join(rootPath, "releases")
	releases, releasesFD, releasesStat, err := openDarwinManagedReleaseDirectory(releasesPath)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	layout := &ReleaseLayout{
		rootPath: rootPath, releasesPath: releasesPath,
		root: root, releases: releases, rootFD: rootFD, releasesFD: releasesFD,
		rootIdentity: darwinObjectIdentity(rootStat), releasesID: darwinObjectIdentity(releasesStat),
	}
	if err := layout.validateAnchorsLocked(); err != nil {
		_ = layout.closeLocked()
		return nil, err
	}
	return layout, nil
}

func ensureDarwinReleaseDirectory(path string) (returnErr error) {
	parentPath := filepath.Dir(path)
	name := filepath.Base(path)
	if !cleanDarwinInstallPath(path) || name == "." || name == string(filepath.Separator) {
		return errors.New("Darwin managed release directory path is invalid")
	}
	if err := nodeagent.InspectDarwinSensitivePath(parentPath); err != nil {
		return fmt.Errorf("authenticate Darwin managed release parent: %w", err)
	}
	var visibleBefore unix.Stat_t
	if err := unix.Lstat(parentPath, &visibleBefore); err != nil {
		return err
	}
	parentFD, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, 0)
	if err != nil {
		return err
	}
	parent := os.NewFile(uintptr(parentFD), parentPath)
	if parent == nil {
		_ = unix.Close(parentFD)
		return errors.New("adopt Darwin managed release parent descriptor")
	}
	defer func() { returnErr = errors.Join(returnErr, parent.Close()) }()
	var openedParent, visibleAfter unix.Stat_t
	if err := unix.Fstat(parentFD, &openedParent); err != nil {
		return err
	}
	if err := unix.Lstat(parentPath, &visibleAfter); err != nil {
		return err
	}
	if darwinObjectIdentity(visibleBefore) != darwinObjectIdentity(openedParent) ||
		darwinObjectIdentity(openedParent) != darwinObjectIdentity(visibleAfter) {
		return errors.New("Darwin managed release parent changed while anchoring")
	}
	if err := nodeagent.InspectDarwinSensitivePath(parentPath); err != nil {
		return fmt.Errorf("reauthenticate Darwin managed release parent: %w", err)
	}
	created := false
	if err := unix.Mkdirat(parentFD, name, uint32(darwinManagedReleaseDirectoryMode)); err == nil {
		created = true
	} else if !errors.Is(err, unix.EEXIST) {
		return err
	}
	cleanup := func(cause error) error {
		if !created {
			return cause
		}
		return errors.Join(cause, unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR), parent.Sync())
	}
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, 0)
	if err != nil {
		return cleanup(err)
	}
	directory := os.NewFile(uintptr(fd), path)
	if directory == nil {
		_ = unix.Close(fd)
		return cleanup(errors.New("adopt Darwin managed release directory descriptor"))
	}
	open := true
	closeDirectory := func() error {
		if !open {
			return nil
		}
		open = false
		return directory.Close()
	}
	defer func() {
		if open {
			returnErr = errors.Join(returnErr, directory.Close())
		}
	}()
	if created {
		if err := unix.Fchown(fd, 0, 0); err != nil {
			return cleanup(errors.Join(err, closeDirectory()))
		}
		if err := unix.Fchmod(fd, uint32(darwinManagedReleaseDirectoryMode)); err != nil {
			return cleanup(errors.Join(err, closeDirectory()))
		}
	}
	if err := authenticateDarwinReleaseDirectory(path, parentFD, name, fd, darwinManagedReleaseDirectoryMode); err != nil {
		return cleanup(errors.Join(err, closeDirectory()))
	}
	if err := directory.Sync(); err != nil {
		return err
	}
	if err := parent.Sync(); err != nil {
		return err
	}
	return authenticateDarwinReleaseDirectory(path, parentFD, name, fd, darwinManagedReleaseDirectoryMode)
}

func openDarwinManagedReleaseDirectory(path string) (*os.File, int, unix.Stat_t, error) {
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		return nil, -1, unix.Stat_t{}, err
	}
	var visibleBefore unix.Stat_t
	if err := unix.Lstat(path, &visibleBefore); err != nil {
		return nil, -1, unix.Stat_t{}, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, 0)
	if err != nil {
		return nil, -1, unix.Stat_t{}, err
	}
	directory := os.NewFile(uintptr(fd), path)
	if directory == nil {
		_ = unix.Close(fd)
		return nil, -1, unix.Stat_t{}, errors.New("adopt Darwin managed release descriptor")
	}
	var opened, visibleAfter unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		_ = directory.Close()
		return nil, -1, unix.Stat_t{}, err
	}
	if err := unix.Lstat(path, &visibleAfter); err != nil {
		_ = directory.Close()
		return nil, -1, unix.Stat_t{}, err
	}
	if darwinObjectIdentity(visibleBefore) != darwinObjectIdentity(opened) ||
		darwinObjectIdentity(opened) != darwinObjectIdentity(visibleAfter) {
		_ = directory.Close()
		return nil, -1, unix.Stat_t{}, errors.New("Darwin managed release directory changed while anchoring")
	}
	if err := validateDarwinReleaseDirectoryStat(opened, darwinManagedReleaseDirectoryMode); err != nil {
		_ = directory.Close()
		return nil, -1, unix.Stat_t{}, err
	}
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		_ = directory.Close()
		return nil, -1, unix.Stat_t{}, err
	}
	return directory, fd, opened, nil
}

func (layout *ReleaseLayout) validateAnchorsLocked() error {
	if layout == nil || layout.closed || layout.root == nil || layout.releases == nil || layout.rootFD < 0 || layout.releasesFD < 0 {
		return errors.New("Darwin release layout is closed")
	}
	if err := nodeagent.InspectDarwinSensitivePath(layout.releasesPath); err != nil {
		return err
	}
	var rootOpened, rootVisible, releasesOpened, releasesVisible, releasesFromRoot unix.Stat_t
	if err := unix.Fstat(layout.rootFD, &rootOpened); err != nil {
		return err
	}
	if err := unix.Lstat(layout.rootPath, &rootVisible); err != nil {
		return err
	}
	if err := unix.Fstat(layout.releasesFD, &releasesOpened); err != nil {
		return err
	}
	if err := unix.Lstat(layout.releasesPath, &releasesVisible); err != nil {
		return err
	}
	if err := unix.Fstatat(layout.rootFD, "releases", &releasesFromRoot, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if layout.rootIdentity != darwinObjectIdentity(rootOpened) || layout.rootIdentity != darwinObjectIdentity(rootVisible) ||
		layout.releasesID != darwinObjectIdentity(releasesOpened) || layout.releasesID != darwinObjectIdentity(releasesVisible) ||
		layout.releasesID != darwinObjectIdentity(releasesFromRoot) {
		return errors.New("Darwin release-layout path or anchored directory changed")
	}
	if err := validateDarwinReleaseDirectoryStat(rootOpened, darwinManagedReleaseDirectoryMode); err != nil {
		return err
	}
	return validateDarwinReleaseDirectoryStat(releasesOpened, darwinManagedReleaseDirectoryMode)
}

func (layout *ReleaseLayout) CreateStage(installedID string) (*ReleaseStage, error) {
	if !darwinInstalledIDPattern.MatchString(installedID) {
		return nil, errors.New("Darwin installed release ID is not canonical")
	}
	layout.mu.Lock()
	defer layout.mu.Unlock()
	if err := layout.validateAnchorsLocked(); err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 4; attempt++ {
		suffix, err := randomDarwinReleaseSuffix()
		if err != nil {
			return nil, err
		}
		name := ".stage-" + installedID + "-" + suffix
		if err := unix.Mkdirat(layout.releasesFD, name, uint32(darwinPrivateReleaseStageMode)); errors.Is(err, unix.EEXIST) {
			continue
		} else if err != nil {
			return nil, err
		}
		path := filepath.Join(layout.releasesPath, name)
		cleanup := func(cause error, directory *os.File) error {
			var closeErr error
			if directory != nil {
				closeErr = directory.Close()
			}
			removeErr := unix.Unlinkat(layout.releasesFD, name, unix.AT_REMOVEDIR)
			syncErr := layout.releases.Sync()
			return errors.Join(cause, closeErr, removeErr, syncErr)
		}
		fd, err := unix.Openat(layout.releasesFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, 0)
		if err != nil {
			return nil, cleanup(err, nil)
		}
		directory := os.NewFile(uintptr(fd), path)
		if directory == nil {
			_ = unix.Close(fd)
			return nil, cleanup(errors.New("adopt Darwin private release-stage descriptor"), nil)
		}
		if err := unix.Fchown(fd, 0, 0); err != nil {
			return nil, cleanup(err, directory)
		}
		if err := unix.Fchmod(fd, uint32(darwinPrivateReleaseStageMode)); err != nil {
			return nil, cleanup(err, directory)
		}
		if err := authenticateDarwinReleaseDirectory(path, layout.releasesFD, name, fd, darwinPrivateReleaseStageMode); err != nil {
			return nil, cleanup(err, directory)
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return nil, cleanup(err, directory)
		}
		if err := directory.Sync(); err != nil {
			return nil, cleanup(err, directory)
		}
		if err := layout.releases.Sync(); err != nil {
			return nil, cleanup(err, directory)
		}
		return &ReleaseStage{
			layout: layout, installedID: installedID, name: name, path: path,
			directory: directory, fd: fd, identity: darwinObjectIdentity(stat),
		}, nil
	}
	return nil, errors.New("could not allocate a unique Darwin release stage")
}

// ResumeStage reanchors the one finalized directory named by the durable
// installer journal. Exactly one of the random stage name and installed ID may
// exist. The supplied inspection must come from the authenticated transaction;
// filesystem package metadata is never allowed to select it.
func (layout *ReleaseLayout) ResumeStage(installedID string, stageName string, inspection darwinbundle.CandidateInspection) (*ReleaseStage, error) {
	if !darwinInstalledIDPattern.MatchString(installedID) || !darwinStageNamePattern.MatchString(stageName) ||
		!strings.HasPrefix(stageName, ".stage-"+installedID+"-") || inspection.Schema != darwinbundle.CandidateInspectionSchema {
		return nil, errors.New("Darwin release recovery identity is not canonical")
	}
	layout.mu.Lock()
	defer layout.mu.Unlock()
	if err := layout.validateAnchorsLocked(); err != nil {
		return nil, err
	}
	stageExists, err := darwinReleaseDirectoryExists(layout.releasesFD, stageName)
	if err != nil {
		return nil, err
	}
	publishedExists, err := darwinReleaseDirectoryExists(layout.releasesFD, installedID)
	if err != nil {
		return nil, err
	}
	if stageExists == publishedExists {
		return nil, errors.New("Darwin release recovery requires exactly one stage or published directory")
	}
	visibleName := stageName
	published := false
	if publishedExists {
		visibleName = installedID
		published = true
	}
	path := filepath.Join(layout.releasesPath, visibleName)
	fd, err := unix.Openat(layout.releasesFD, visibleName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), path)
	if directory == nil {
		_ = unix.Close(fd)
		return nil, errors.New("adopt resumed Darwin release descriptor")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = directory.Close()
		return nil, err
	}
	stage := &ReleaseStage{
		layout: layout, installedID: installedID, name: stageName, path: path,
		directory: directory, fd: fd, identity: darwinObjectIdentity(stat),
		inspection: inspection, staged: true, published: published,
	}
	if err := stage.validateFinalizedTreeLocked(visibleName); err != nil {
		_ = directory.Close()
		return nil, err
	}
	return stage, nil
}

func darwinReleaseDirectoryExists(parentFD int, name string) (bool, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if err := validateDarwinReleaseDirectoryStat(stat, darwinPublishedReleaseMode); err != nil {
		return false, err
	}
	return true, nil
}

func (stage *ReleaseStage) StageAuthenticatedArtifact(artifactPath string) (darwinbundle.CandidateInspection, error) {
	if stage == nil || stage.layout == nil {
		return darwinbundle.CandidateInspection{}, errors.New("Darwin release stage is required")
	}
	layout := stage.layout
	layout.mu.Lock()
	defer layout.mu.Unlock()
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.closed || stage.directory == nil || stage.published || stage.staged {
		return darwinbundle.CandidateInspection{}, errors.New("Darwin release stage is not empty and writable")
	}
	if err := layout.validateAnchorsLocked(); err != nil {
		return darwinbundle.CandidateInspection{}, err
	}
	state, err := stage.inspectNamedTreeLocked(stage.name)
	if err != nil || state != releaseDirectoryPrivate {
		return darwinbundle.CandidateInspection{}, errors.New("Darwin private release stage changed before bundle intake")
	}
	inspection, err := darwinbundle.InspectCandidateFile(artifactPath, stage.path)
	if err != nil {
		return darwinbundle.CandidateInspection{}, err
	}
	stage.inspection = inspection
	stage.staged = true
	if err := stage.validateFinalizedTreeLocked(stage.name); err != nil {
		stage.staged = false
		return darwinbundle.CandidateInspection{}, err
	}
	return inspection, nil
}

func (stage *ReleaseStage) Publish() error {
	if stage == nil || stage.layout == nil {
		return errors.New("Darwin release stage is required")
	}
	layout := stage.layout
	layout.mu.Lock()
	defer layout.mu.Unlock()
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.closed || stage.directory == nil || !stage.staged {
		return errors.New("Darwin release stage is not finalized")
	}
	if err := layout.validateAnchorsLocked(); err != nil {
		return err
	}
	if err := publishFinalizedRelease(stage); err != nil {
		return err
	}
	stage.published = true
	stage.path = filepath.Join(layout.releasesPath, stage.installedID)
	return nil
}

func (stage *ReleaseStage) InspectStage() (releaseDirectoryState, error) {
	return stage.inspectNamedTreeLocked(stage.name)
}

func (stage *ReleaseStage) InspectPublished() (releaseDirectoryState, error) {
	return stage.inspectNamedTreeLocked(stage.installedID)
}

func (stage *ReleaseStage) SyncStage() error {
	if err := stage.validateFinalizedTreeLocked(stage.name); err != nil {
		return err
	}
	return stage.directory.Sync()
}

func (stage *ReleaseStage) PublishNoReplace() error {
	return unix.RenameatxNp(stage.layout.releasesFD, stage.name, stage.layout.releasesFD, stage.installedID, unix.RENAME_EXCL)
}

func (stage *ReleaseStage) SyncReleases() error {
	return stage.layout.releases.Sync()
}

func (stage *ReleaseStage) inspectNamedTreeLocked(name string) (releaseDirectoryState, error) {
	var visible unix.Stat_t
	if err := unix.Fstatat(stage.layout.releasesFD, name, &visible, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return releaseDirectoryAbsent, nil
	} else if err != nil {
		return releaseDirectoryAbsent, err
	}
	if stage.identity != darwinObjectIdentity(visible) {
		return releaseDirectoryAbsent, fmt.Errorf("Darwin release path %q does not identify its anchored stage", name)
	}
	mode := visible.Mode & 0o7777
	if mode == darwinPrivateReleaseStageMode {
		if err := validateDarwinReleaseDirectoryStat(visible, darwinPrivateReleaseStageMode); err != nil {
			return releaseDirectoryAbsent, err
		}
		if err := nodeagent.InspectDarwinSensitivePath(filepath.Join(stage.layout.releasesPath, name)); err != nil {
			return releaseDirectoryAbsent, err
		}
		return releaseDirectoryPrivate, nil
	}
	if mode != darwinPublishedReleaseMode {
		return releaseDirectoryAbsent, fmt.Errorf("Darwin release path %q has an unsupported mode", name)
	}
	if err := stage.validateFinalizedTreeLocked(name); err != nil {
		return releaseDirectoryAbsent, err
	}
	return releaseDirectoryFinalized, nil
}

func (stage *ReleaseStage) validateFinalizedTreeLocked(visibleName string) error {
	if !stage.staged || stage.inspection.Schema != darwinbundle.CandidateInspectionSchema {
		return errors.New("Darwin release stage has no authenticated bundle inspection")
	}
	basePath := filepath.Join(stage.layout.releasesPath, visibleName)
	var opened, visible unix.Stat_t
	if err := unix.Fstat(stage.fd, &opened); err != nil {
		return err
	}
	if err := unix.Fstatat(stage.layout.releasesFD, visibleName, &visible, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if stage.identity != darwinObjectIdentity(opened) || stage.identity != darwinObjectIdentity(visible) {
		return errors.New("Darwin finalized release root changed identity")
	}
	if err := validateDarwinReleaseDirectoryStat(opened, darwinPublishedReleaseMode); err != nil {
		return err
	}
	if err := nodeagent.InspectDarwinSensitivePath(basePath); err != nil {
		return err
	}
	files, directories, err := darwinReleaseExpectations(stage.inspection)
	if err != nil {
		return err
	}
	seenFiles := make(map[string]bool, len(files))
	seenDirectories := make(map[string]bool, len(directories))
	entryCount := 0
	err = filepath.WalkDir(basePath, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entryCount++
		if entryCount > maximumDarwinReleaseTreeEntries {
			return errors.New("Darwin release tree exceeds its entry bound")
		}
		relative, err := filepath.Rel(basePath, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("Darwin release tree escaped its anchored root")
		}
		if relative == "." {
			return nil
		}
		if filepath.Clean(relative) != relative || strings.Contains(relative, `\`) {
			return errors.New("Darwin release tree contains a noncanonical path")
		}
		if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
			return err
		}
		if entry.IsDir() {
			if !directories[relative] {
				return fmt.Errorf("unexpected Darwin release directory %q", relative)
			}
			var stat unix.Stat_t
			if err := unix.Fstatat(stage.fd, relative, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
			if err := validateDarwinReleaseDirectoryStat(stat, darwinPublishedReleaseMode); err != nil {
				return err
			}
			seenDirectories[relative] = true
			return nil
		}
		expectation, ok := files[relative]
		if !ok {
			return fmt.Errorf("unexpected Darwin release file %q", relative)
		}
		if err := validateDarwinReleaseFile(stage.fd, basePath, relative, expectation); err != nil {
			return err
		}
		seenFiles[relative] = true
		return nil
	})
	if err != nil {
		return err
	}
	if len(seenFiles) != len(files) || len(seenDirectories) != len(directories) {
		return errors.New("Darwin release tree is incomplete")
	}
	return nil
}

func darwinReleaseExpectations(inspection darwinbundle.CandidateInspection) (map[string]darwinReleaseFileExpectation, map[string]bool, error) {
	if inspection.FileCount != len(inspection.Package.Entries)+1 || inspection.DirectoryCount <= 0 ||
		inspection.Package.Target.OS != "darwin" || (inspection.Package.Target.Arch != "amd64" && inspection.Package.Target.Arch != "arm64") {
		return nil, nil, errors.New("Darwin candidate inspection is incomplete")
	}
	files := map[string]darwinReleaseFileExpectation{
		"package.json": {mode: 0o444, digest: inspection.PackageJSONSHA256},
	}
	directories := make(map[string]bool)
	for _, entry := range inspection.Package.Entries {
		files[entry.Path] = darwinReleaseFileExpectation{mode: uint16(entry.ArchiveMode), size: entry.Size, digest: entry.SHA256}
		for parent := filepath.Dir(entry.Path); parent != "."; parent = filepath.Dir(parent) {
			directories[parent] = true
		}
	}
	if len(files) != inspection.FileCount || len(directories) != inspection.DirectoryCount {
		return nil, nil, errors.New("Darwin candidate inspection file topology is inconsistent")
	}
	return files, directories, nil
}

func validateDarwinReleaseFile(rootFD int, basePath string, name string, expectation darwinReleaseFileExpectation) error {
	_, err := inspectDarwinReleaseFile(rootFD, basePath, name, expectation, false)
	return err
}

func readDarwinReleaseFile(rootFD int, basePath string, name string, expectation darwinReleaseFileExpectation) (contents []byte, returnErr error) {
	return inspectDarwinReleaseFile(rootFD, basePath, name, expectation, true)
}

func inspectDarwinReleaseFile(rootFD int, basePath string, name string, expectation darwinReleaseFileExpectation, capture bool) (contents []byte, returnErr error) {
	absolute := filepath.Join(basePath, name)
	if err := nodeagent.InspectDarwinSensitivePath(absolute); err != nil {
		return nil, err
	}
	var visibleBefore unix.Stat_t
	if err := unix.Fstatat(rootFD, name, &visibleBefore, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	if expectation.size == 0 {
		if visibleBefore.Size < 1 || visibleBefore.Size > 64<<10 {
			return nil, errors.New("Darwin release package metadata size is outside its bound")
		}
		expectation.size = visibleBefore.Size
	}
	if err := validateDarwinReleaseFileStat(visibleBefore, expectation); err != nil {
		return nil, fmt.Errorf("Darwin release file %q: %w", name, err)
	}
	fd, err := unix.Openat(rootFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), absolute)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("adopt Darwin release file descriptor")
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	var openedBefore, openedAfter, visibleAfter unix.Stat_t
	if err := unix.Fstat(fd, &openedBefore); err != nil {
		return nil, err
	}
	digest := sha256.New()
	var captured bytes.Buffer
	output := io.Writer(digest)
	if capture {
		captured.Grow(int(expectation.size))
		output = io.MultiWriter(digest, &captured)
	}
	read, err := io.Copy(output, io.LimitReader(file, expectation.size+1))
	if err != nil || read != expectation.size {
		return nil, errors.Join(err, errors.New("Darwin release file size changed while hashing"))
	}
	if hex.EncodeToString(digest.Sum(nil)) != expectation.digest {
		return nil, errors.New("Darwin release file digest differs from authenticated bundle")
	}
	if err := unix.Fstat(fd, &openedAfter); err != nil {
		return nil, err
	}
	if err := unix.Fstatat(rootFD, name, &visibleAfter, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	for _, stat := range []unix.Stat_t{openedBefore, openedAfter, visibleAfter} {
		if err := validateDarwinReleaseFileStat(stat, expectation); err != nil {
			return nil, err
		}
	}
	before := snapshotDarwinInstallStat(visibleBefore)
	if before != snapshotDarwinInstallStat(openedBefore) || before != snapshotDarwinInstallStat(openedAfter) || before != snapshotDarwinInstallStat(visibleAfter) {
		return nil, errors.New("Darwin release file changed while hashing")
	}
	if err := nodeagent.InspectDarwinSensitivePath(absolute); err != nil {
		return nil, err
	}
	if capture {
		contents = append([]byte(nil), captured.Bytes()...)
	}
	return contents, nil
}

func validateDarwinReleaseFileStat(stat unix.Stat_t, expectation darwinReleaseFileExpectation) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != expectation.mode || stat.Uid != 0 || stat.Gid != 0 ||
		stat.Nlink != 1 || stat.Flags != 0 || stat.Size != expectation.size {
		return errors.New("must be an exact root:wheel single-link immutable regular file without flags")
	}
	return nil
}

func authenticateDarwinReleaseDirectory(path string, parentFD int, name string, fd int, mode uint16) error {
	var visibleBefore, openedBefore, openedAfter, visibleAfter unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &visibleBefore, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if err := unix.Fstat(fd, &openedBefore); err != nil {
		return err
	}
	if darwinObjectIdentity(visibleBefore) != darwinObjectIdentity(openedBefore) {
		return errors.New("Darwin release directory path does not identify its opened descriptor")
	}
	if err := validateDarwinReleaseDirectoryStat(visibleBefore, mode); err != nil {
		return err
	}
	if err := validateDarwinReleaseDirectoryStat(openedBefore, mode); err != nil {
		return err
	}
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		return err
	}
	if err := unix.Fstat(fd, &openedAfter); err != nil {
		return err
	}
	if err := unix.Fstatat(parentFD, name, &visibleAfter, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if darwinObjectIdentity(openedBefore) != darwinObjectIdentity(openedAfter) ||
		darwinObjectIdentity(openedBefore) != darwinObjectIdentity(visibleAfter) {
		return errors.New("Darwin release directory changed while authenticating")
	}
	if err := validateDarwinReleaseDirectoryStat(openedAfter, mode); err != nil {
		return err
	}
	return validateDarwinReleaseDirectoryStat(visibleAfter, mode)
}

func validateDarwinReleaseDirectoryStat(stat unix.Stat_t, mode uint16) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o7777 != mode || stat.Uid != 0 || stat.Gid != 0 || stat.Flags != 0 {
		return fmt.Errorf("Darwin release directory must be exact root:wheel mode-%04o without file flags", mode)
	}
	return nil
}

func darwinObjectIdentity(stat unix.Stat_t) darwinInstallObjectIdentity {
	return darwinInstallObjectIdentity{device: stat.Dev, inode: stat.Ino, generation: stat.Gen, typeBits: stat.Mode & unix.S_IFMT}
}

func randomDarwinReleaseSuffix() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func (stage *ReleaseStage) Path() string {
	if stage == nil {
		return ""
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	return stage.path
}

// DiscardPrivate removes only this exact empty unpublished 0700 stage. A
// finalized stage is intentionally retained for journal-driven recovery.
func (stage *ReleaseStage) DiscardPrivate() error {
	if stage == nil || stage.layout == nil {
		return nil
	}
	layout := stage.layout
	layout.mu.Lock()
	defer layout.mu.Unlock()
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.closed || stage.directory == nil || stage.staged || stage.published {
		return errors.New("only an open empty Darwin release stage can be discarded")
	}
	if err := layout.validateAnchorsLocked(); err != nil {
		return err
	}
	state, err := stage.inspectNamedTreeLocked(stage.name)
	if err != nil || state != releaseDirectoryPrivate {
		return errors.New("Darwin private release stage changed before discard")
	}
	duplicateFD, err := unix.Dup(stage.fd)
	if err != nil {
		return err
	}
	duplicate := os.NewFile(uintptr(duplicateFD), stage.path)
	if duplicate == nil {
		_ = unix.Close(duplicateFD)
		return errors.New("adopt duplicate Darwin release-stage descriptor")
	}
	entries, readErr := duplicate.ReadDir(1)
	closeErr := duplicate.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return errors.Join(readErr, closeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	if len(entries) != 0 {
		return errors.New("refusing to discard a nonempty Darwin private release stage")
	}
	if err := stage.directory.Close(); err != nil {
		return err
	}
	stage.directory = nil
	stage.fd = -1
	stage.closed = true
	if err := unix.Unlinkat(layout.releasesFD, stage.name, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	if err := layout.releases.Sync(); err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(layout.releasesFD, stage.name, &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		if err != nil {
			return err
		}
		return errors.New("discarded Darwin private release stage remains visible")
	}
	return nil
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
	if stage.directory == nil {
		return nil
	}
	err := stage.directory.Close()
	stage.directory = nil
	stage.fd = -1
	return err
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
	var err error
	if layout.releases != nil {
		err = errors.Join(err, layout.releases.Close())
		layout.releases = nil
		layout.releasesFD = -1
	}
	if layout.root != nil {
		err = errors.Join(err, layout.root.Close())
		layout.root = nil
		layout.rootFD = -1
	}
	return err
}
