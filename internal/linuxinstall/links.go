//go:build linux

package linuxinstall

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	systemdassets "mesh/packaging/systemd"
)

const productionLocalRoot = "/usr/local"

const (
	topologyDirectoryTemporaryPrefix = ".mesh-directory-"
	topologyFileTemporaryPrefix      = ".mesh-file-"
	maximumTopologyTemporaryFileSize = 64 << 10
	managedTimeoutAbortDropInName    = "10-timeout-abort.conf"
)

type managedLinkSpec struct {
	parentRelative string
	name           string
	target         string
}

type managedFileSpec struct {
	parentRelative string
	name           string
	content        []byte
}

func (spec managedFileSpec) endpointRelative() string {
	return filepath.Join(spec.parentRelative, spec.name)
}

func (spec managedLinkSpec) endpointRelative() string {
	return filepath.Join(spec.parentRelative, spec.name)
}

// ManagedLinkTopology owns only Mesh's compatibility and static symlinks. It
// never adopts, overwrites, or removes another file. Callers must serialize
// Ensure and Remove with the installer StateStore lock.
type ManagedLinkTopology struct {
	mu sync.Mutex

	localPath string
	meshPath  string
	localInfo os.FileInfo
	local     *os.Root
	localDir  *os.File
	specs     []managedLinkSpec
	files     []managedFileSpec
	closed    bool

	// testCheckpoint is a subprocess fault-injection seam. Production
	// topologies leave it nil; tests use it to stop immediately after a
	// filesystem transition and deliver SIGKILL from the parent process.
	testCheckpoint func(string)
}

const (
	topologyCheckpointDirectoryCreated   = "directory-created"
	topologyCheckpointDirectoryFinalMode = "directory-final-mode"
	topologyCheckpointDirectoryPublished = "directory-published"
	topologyCheckpointFileCreated        = "file-created"
	topologyCheckpointFileContentWritten = "file-content-written"
	topologyCheckpointFileContentSynced  = "file-content-synced"
	topologyCheckpointFileFinalMode      = "file-final-mode"
	topologyCheckpointFileFinalSynced    = "file-final-synced"
	topologyCheckpointFilePublished      = "file-published"
)

func (topology *ManagedLinkTopology) checkpoint(name string) {
	if topology.testCheckpoint != nil {
		topology.testCheckpoint(name)
	}
}

// NewProductionManagedLinkTopology opens the fixed production topology rooted
// at /usr/local. It is read-only until Ensure or Remove is explicitly called.
func NewProductionManagedLinkTopology() (*ManagedLinkTopology, error) {
	if err := validateProductionTopologyConstants(); err != nil {
		return nil, err
	}
	return newManagedLinkTopology(productionLocalRoot, ProductionMeshRoot)
}

// newManagedLinkTopology is the private test seam. Production code must use
// NewProductionManagedLinkTopology so neither endpoint nor target paths are
// runtime-configurable.
func newManagedLinkTopology(localPath, meshPath string) (*ManagedLinkTopology, error) {
	if err := validateTopologyRootPath(localPath, "local"); err != nil {
		return nil, err
	}
	if err := validateTopologyRootPath(meshPath, "mesh"); err != nil {
		return nil, err
	}
	if err := validateSecureAncestorChain(localPath, false); err != nil {
		return nil, fmt.Errorf("validate managed-link ancestry: %w", err)
	}
	local, localDir, localInfo, err := openTrustedTopologyDirectory(localPath)
	if err != nil {
		return nil, err
	}
	topology := &ManagedLinkTopology{
		localPath: localPath,
		meshPath:  meshPath,
		localInfo: localInfo,
		local:     local,
		localDir:  localDir,
		specs:     topologySpecs(meshPath),
		files:     topologyFileSpecs(),
	}
	if err := topology.validateLocked(); err != nil {
		_ = topology.closeLocked()
		return nil, err
	}
	return topology, nil
}

func topologySpecs(meshPath string) []managedLinkSpec {
	return []managedLinkSpec{
		{parentRelative: "bin", name: "meshctl", target: filepath.Join(meshPath, "current/bin/meshctl")},
		{parentRelative: "bin", name: "mesh-install", target: filepath.Join(meshPath, "current/bin/mesh-install")},
		{parentRelative: "bin", name: "nebula", target: filepath.Join(meshPath, "current/bin/nebula")},
		{parentRelative: "bin", name: "nebula-cert", target: filepath.Join(meshPath, "current/bin/nebula-cert")},
		{parentRelative: "share/doc", name: "mesh", target: filepath.Join(meshPath, "current/share/doc/mesh")},
	}
}

// Unit definitions are stable installer-owned files, not release symlinks.
// systemctl enable canonicalizes a symlinked unit to its versioned release
// target, which pins the boot gate to an old release and breaks atomic current
// switching. The reviewed unit ABI itself always executes /usr/local links,
// while those links remain release-selected through /opt/mesh/current.
func topologyFileSpecs() []managedFileSpec {
	return []managedFileSpec{
		{parentRelative: "lib/systemd/system", name: agentUnitName, content: systemdassets.MeshAgentService()},
		{parentRelative: "lib/systemd/system/" + agentUnitName + ".d", name: managedTimeoutAbortDropInName, content: systemdassets.TimeoutAbortCompatibilityMask()},
		{parentRelative: "lib/systemd/system", name: nebulaUnitName, content: systemdassets.MeshNebulaService()},
		{parentRelative: "lib/systemd/system/" + nebulaUnitName + ".d", name: managedTimeoutAbortDropInName, content: systemdassets.TimeoutAbortCompatibilityMask()},
	}
}

func validateTopologyRootPath(path, label string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return fmt.Errorf("managed-link %s root must be a clean absolute non-root path", label)
	}
	return nil
}

func openTrustedTopologyDirectory(path string) (*os.Root, *os.File, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil || !trustedTopologyDirectory(before) {
		return nil, nil, nil, fmt.Errorf("managed-link directory %q must be root/effective-user-owned mode-0755", path)
	}
	if err := rejectPOSIXACL(path); err != nil {
		return nil, nil, nil, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("anchor managed-link directory %q: %w", path, err)
	}
	directory, err := os.Open(path)
	if err != nil {
		_ = root.Close()
		return nil, nil, nil, fmt.Errorf("open managed-link directory %q: %w", path, err)
	}
	rootInfo, rootErr := root.Stat(".")
	directoryInfo, directoryErr := directory.Stat()
	visible, visibleErr := os.Lstat(path)
	if rootErr != nil || directoryErr != nil || visibleErr != nil || !sameDirectoryObject(before, rootInfo) ||
		!sameDirectoryObject(before, directoryInfo) || !sameDirectoryObject(before, visible) {
		_ = directory.Close()
		_ = root.Close()
		return nil, nil, nil, fmt.Errorf("managed-link directory %q changed while anchoring", path)
	}
	return root, directory, before, nil
}

func trustedTopologyDirectory(info os.FileInfo) bool {
	if info == nil || info.Mode() != os.ModeDir|managedLayoutMode {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == 0 || stat.Uid == uint32(os.Geteuid()))
}

func (topology *ManagedLinkTopology) validateLocked() error {
	if topology == nil || topology.closed || topology.local == nil || topology.localDir == nil {
		return errors.New("managed-link topology is closed")
	}
	if err := validateSecureAncestorChain(topology.localPath, false); err != nil {
		return fmt.Errorf("managed-link ancestry changed: %w", err)
	}
	rootInfo, rootErr := topology.local.Stat(".")
	directoryInfo, directoryErr := topology.localDir.Stat()
	visible, visibleErr := os.Lstat(topology.localPath)
	if rootErr != nil || directoryErr != nil || visibleErr != nil || !sameDirectoryObject(topology.localInfo, rootInfo) ||
		!sameDirectoryObject(topology.localInfo, directoryInfo) || !sameDirectoryObject(topology.localInfo, visible) ||
		!trustedTopologyDirectory(rootInfo) {
		return errors.New("managed-link root path or anchored directory changed")
	}
	return rejectPOSIXACL(topology.localPath)
}

type topologyLinkState uint8

const (
	topologyLinkAbsent topologyLinkState = iota
	topologyLinkExact
)

type topologySnapshot struct {
	parents    map[string]*topologyParent
	linkStates []topologyLinkState
	fileStates []topologyLinkState
}

func (snapshot *topologySnapshot) close() error {
	if snapshot == nil {
		return nil
	}
	var errs []error
	keys := make([]string, 0, len(snapshot.parents))
	for key := range snapshot.parents {
		keys = append(keys, key)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	for _, key := range keys {
		if err := snapshot.parents[key].close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

type topologyParent struct {
	relative string
	path     string
	info     os.FileInfo
	root     *os.Root
	dir      *os.File
}

func (parent *topologyParent) close() error {
	if parent == nil {
		return nil
	}
	var errs []error
	if parent.dir != nil {
		if err := parent.dir.Close(); err != nil {
			errs = append(errs, err)
		}
		parent.dir = nil
	}
	if parent.root != nil {
		if err := parent.root.Close(); err != nil {
			errs = append(errs, err)
		}
		parent.root = nil
	}
	return errors.Join(errs...)
}

func (parent *topologyParent) validate(topology *ManagedLinkTopology) error {
	if parent == nil || parent.root == nil || parent.dir == nil {
		return errors.New("managed-link parent is closed")
	}
	if err := topology.validateRelativeDirectoryChainLocked(parent.relative); err != nil {
		return err
	}
	rootInfo, rootErr := parent.root.Stat(".")
	directoryInfo, directoryErr := parent.dir.Stat()
	fromAnchor, anchorErr := topology.local.Lstat(parent.relative)
	visible, visibleErr := os.Lstat(parent.path)
	if rootErr != nil || directoryErr != nil || anchorErr != nil || visibleErr != nil ||
		!sameDirectoryObject(parent.info, rootInfo) || !sameDirectoryObject(parent.info, directoryInfo) ||
		!sameDirectoryObject(parent.info, fromAnchor) || !sameDirectoryObject(parent.info, visible) ||
		!trustedTopologyDirectory(rootInfo) {
		return fmt.Errorf("managed-link parent %q changed while anchored", parent.path)
	}
	return rejectPOSIXACL(parent.path)
}

func (topology *ManagedLinkTopology) validateRelativeDirectoryChainLocked(relative string) error {
	if relative == "" || relative == "." || filepath.IsAbs(relative) || filepath.Clean(relative) != relative {
		return errors.New("managed-link relative directory chain is invalid")
	}
	prefix := ""
	for _, component := range strings.Split(filepath.ToSlash(relative), "/") {
		if component == "" || component == "." || component == ".." {
			return errors.New("managed-link relative directory component is invalid")
		}
		prefix = filepath.Join(prefix, component)
		info, err := topology.local.Lstat(prefix)
		if err != nil || !trustedTopologyDirectory(info) {
			return fmt.Errorf("managed-link directory ancestry %q is linked or untrusted", filepath.Join(topology.localPath, prefix))
		}
		if err := rejectPOSIXACL(filepath.Join(topology.localPath, prefix)); err != nil {
			return err
		}
	}
	return nil
}

func (topology *ManagedLinkTopology) snapshotLocked() (*topologySnapshot, error) {
	if err := topology.validateLocked(); err != nil {
		return nil, err
	}
	directories, err := topology.inspectDirectoriesLocked()
	if err != nil {
		return nil, err
	}
	snapshot := &topologySnapshot{
		parents:    make(map[string]*topologyParent),
		linkStates: make([]topologyLinkState, len(topology.specs)),
		fileStates: make([]topologyLinkState, len(topology.files)),
	}
	fail := func(err error) (*topologySnapshot, error) {
		_ = snapshot.close()
		return nil, err
	}
	for index, spec := range topology.specs {
		if !directories[spec.parentRelative] {
			snapshot.linkStates[index] = topologyLinkAbsent
			continue
		}
		parent := snapshot.parents[spec.parentRelative]
		if parent == nil {
			parent, err = topology.openParentLocked(spec.parentRelative)
			if err != nil {
				return fail(err)
			}
			snapshot.parents[spec.parentRelative] = parent
		}
		state, err := inspectManagedLink(topology, parent, spec)
		if err != nil {
			return fail(err)
		}
		snapshot.linkStates[index] = state
	}
	for index, spec := range topology.files {
		if !directories[spec.parentRelative] {
			snapshot.fileStates[index] = topologyLinkAbsent
			continue
		}
		parent := snapshot.parents[spec.parentRelative]
		if parent == nil {
			parent, err = topology.openParentLocked(spec.parentRelative)
			if err != nil {
				return fail(err)
			}
			snapshot.parents[spec.parentRelative] = parent
		}
		state, err := inspectManagedFile(topology, parent, spec)
		if err != nil {
			return fail(err)
		}
		snapshot.fileStates[index] = state
	}
	return snapshot, nil
}

// inspectDirectoriesLocked validates every existing component needed by the
// topology. A false entry means the directory and all descendants were absent.
func (topology *ManagedLinkTopology) inspectDirectoriesLocked() (map[string]bool, error) {
	directories := make(map[string]bool)
	for _, relative := range topologyDirectoryOrder() {
		parentRelative := filepath.Dir(relative)
		if parentRelative != "." && !directories[parentRelative] {
			directories[relative] = false
			continue
		}
		info, err := topology.local.Lstat(relative)
		if errors.Is(err, os.ErrNotExist) {
			directories[relative] = false
			continue
		}
		if err != nil || !trustedTopologyDirectory(info) {
			return nil, fmt.Errorf("managed-link parent component %q is missing, linked, writable, specially-moded, or untrusted", filepath.Join(topology.localPath, relative))
		}
		root, err := topology.local.OpenRoot(relative)
		if err != nil {
			return nil, fmt.Errorf("anchor managed-link parent component %q: %w", relative, err)
		}
		anchored, rootErr := root.Stat(".")
		visible, pathErr := os.Lstat(filepath.Join(topology.localPath, relative))
		closeErr := root.Close()
		if rootErr != nil || pathErr != nil || closeErr != nil || !sameDirectoryObject(info, anchored) || !sameDirectoryObject(info, visible) {
			return nil, fmt.Errorf("managed-link parent component %q changed while inspecting", relative)
		}
		if err := rejectPOSIXACL(filepath.Join(topology.localPath, relative)); err != nil {
			return nil, err
		}
		directories[relative] = true
	}
	return directories, nil
}

func topologyDirectoryOrder() []string {
	return []string{
		"bin",
		"lib",
		"lib/systemd",
		"lib/systemd/system",
		"lib/systemd/system/" + agentUnitName + ".d",
		"lib/systemd/system/" + nebulaUnitName + ".d",
		"share",
		"share/doc",
	}
}

func (topology *ManagedLinkTopology) openParentLocked(relative string) (*topologyParent, error) {
	if relative == "" || relative == "." || filepath.Clean(relative) != relative || filepath.IsAbs(relative) {
		return nil, errors.New("managed-link parent relative path is invalid")
	}
	info, err := topology.local.Lstat(relative)
	if err != nil || !trustedTopologyDirectory(info) {
		return nil, fmt.Errorf("managed-link parent %q is invalid", relative)
	}
	root, err := topology.local.OpenRoot(relative)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(topology.localPath, relative)
	directory, err := os.Open(path)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	parent := &topologyParent{relative: relative, path: path, info: info, root: root, dir: directory}
	if err := parent.validate(topology); err != nil {
		_ = parent.close()
		return nil, err
	}
	return parent, nil
}

func inspectManagedLink(topology *ManagedLinkTopology, parent *topologyParent, spec managedLinkSpec) (topologyLinkState, error) {
	if err := parent.validate(topology); err != nil {
		return topologyLinkAbsent, err
	}
	before, err := parent.root.Lstat(spec.name)
	if errors.Is(err, os.ErrNotExist) {
		return topologyLinkAbsent, nil
	}
	if err != nil || !trustedExactSymlink(before) {
		return topologyLinkAbsent, fmt.Errorf("managed-link endpoint %q is a conflicting noncanonical object", filepath.Join(parent.path, spec.name))
	}
	target, targetErr := parent.root.Readlink(spec.name)
	after, afterErr := parent.root.Lstat(spec.name)
	visible, visibleErr := os.Lstat(filepath.Join(parent.path, spec.name))
	if targetErr != nil || afterErr != nil || visibleErr != nil || target != spec.target ||
		!sameSymlinkObject(before, after) || !sameSymlinkObject(before, visible) {
		return topologyLinkAbsent, fmt.Errorf("managed-link endpoint %q changed or has target %q instead of %q", filepath.Join(parent.path, spec.name), target, spec.target)
	}
	return topologyLinkExact, nil
}

func trustedExactSymlink(info os.FileInfo) bool {
	if info == nil || info.Mode() != os.ModeSymlink|0o777 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == 0 || stat.Uid == uint32(os.Geteuid())) && stat.Nlink == 1
}

func sameSymlinkObject(left, right os.FileInfo) bool {
	if !trustedExactSymlink(left) || !trustedExactSymlink(right) || !os.SameFile(left, right) || left.Size() != right.Size() {
		return false
	}
	leftStat, leftOK := left.Sys().(*syscall.Stat_t)
	rightStat, rightOK := right.Sys().(*syscall.Stat_t)
	return leftOK && rightOK && leftStat.Uid == rightStat.Uid && leftStat.Gid == rightStat.Gid && leftStat.Nlink == rightStat.Nlink
}

func inspectManagedFile(topology *ManagedLinkTopology, parent *topologyParent, spec managedFileSpec) (topologyLinkState, error) {
	if err := parent.validate(topology); err != nil {
		return topologyLinkAbsent, err
	}
	before, err := parent.root.Lstat(spec.name)
	if errors.Is(err, os.ErrNotExist) {
		return topologyLinkAbsent, nil
	}
	if err != nil || !trustedExactManagedFile(before, int64(len(spec.content))) {
		return topologyLinkAbsent, fmt.Errorf("managed-file endpoint %q is a conflicting noncanonical object", filepath.Join(parent.path, spec.name))
	}
	if err := rejectPOSIXACL(filepath.Join(parent.path, spec.name)); err != nil {
		return topologyLinkAbsent, err
	}
	file, err := parent.root.Open(spec.name)
	if err != nil {
		return topologyLinkAbsent, fmt.Errorf("open managed file %q: %w", spec.endpointRelative(), err)
	}
	anchored, statErr := file.Stat()
	content, readErr := io.ReadAll(io.LimitReader(file, int64(len(spec.content))+1))
	closeErr := file.Close()
	after, afterErr := parent.root.Lstat(spec.name)
	visible, visibleErr := os.Lstat(filepath.Join(parent.path, spec.name))
	if statErr != nil || readErr != nil || closeErr != nil || afterErr != nil || visibleErr != nil ||
		!sameManagedFileObject(before, anchored) || !sameManagedFileObject(before, after) || !sameManagedFileObject(before, visible) ||
		!bytes.Equal(content, spec.content) {
		return topologyLinkAbsent, fmt.Errorf("managed-file endpoint %q changed or differs from its reviewed content", filepath.Join(parent.path, spec.name))
	}
	return topologyLinkExact, nil
}

func trustedExactManagedFile(info os.FileInfo, size int64) bool {
	if info == nil || info.Mode() != 0o444 || info.Size() != size {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == 0 || stat.Uid == uint32(os.Geteuid())) &&
		(stat.Gid == 0 || stat.Gid == uint32(os.Getegid())) && stat.Nlink == 1
}

func sameManagedFileObject(left, right os.FileInfo) bool {
	if left == nil || right == nil || !os.SameFile(left, right) || left.Mode() != right.Mode() || left.Size() != right.Size() {
		return false
	}
	leftStat, leftOK := left.Sys().(*syscall.Stat_t)
	rightStat, rightOK := right.Sys().(*syscall.Stat_t)
	return leftOK && rightOK && leftStat.Uid == rightStat.Uid && leftStat.Gid == rightStat.Gid &&
		leftStat.Nlink == rightStat.Nlink && leftStat.Mtim == rightStat.Mtim && leftStat.Ctim == rightStat.Ctim
}

// RequireAbsent proves the complete first-install endpoint surface is absent.
// It does not create missing parent directories.
func (topology *ManagedLinkTopology) RequireAbsent() error {
	topology.mu.Lock()
	defer topology.mu.Unlock()
	snapshot, err := topology.snapshotLocked()
	if err != nil {
		return err
	}
	defer snapshot.close()
	for index, state := range snapshot.linkStates {
		if state != topologyLinkAbsent {
			return fmt.Errorf("first-install endpoint %q already exists", topology.specs[index].endpointRelative())
		}
	}
	for index, state := range snapshot.fileStates {
		if state != topologyLinkAbsent {
			return fmt.Errorf("first-install endpoint %q already exists", topology.files[index].endpointRelative())
		}
	}
	return nil
}

// Ensure creates missing topology directories and symlinks, or accepts exact
// links left by the same pending transaction. Every endpoint is preflighted
// before the first link is created, so collisions cannot cause partial link
// adoption.
func (topology *ManagedLinkTopology) Ensure() error {
	topology.mu.Lock()
	defer topology.mu.Unlock()
	before, err := topology.snapshotLocked()
	if err != nil {
		return err
	}
	if err := topology.scavengeTemporariesLocked(); err != nil {
		_ = before.close()
		return err
	}
	if err := before.close(); err != nil {
		return err
	}
	if err := topology.ensureDirectoriesLocked(); err != nil {
		return err
	}
	snapshot, err := topology.snapshotLocked()
	if err != nil {
		return err
	}
	defer snapshot.close()
	for index, spec := range topology.specs {
		if snapshot.linkStates[index] == topologyLinkExact {
			continue
		}
		parent := snapshot.parents[spec.parentRelative]
		if parent == nil {
			return fmt.Errorf("managed-link parent %q was not created", spec.parentRelative)
		}
		if err := parent.validate(topology); err != nil {
			return err
		}
		state, err := inspectManagedLink(topology, parent, spec)
		if err != nil || state != topologyLinkAbsent {
			if err != nil {
				return err
			}
			return fmt.Errorf("managed-link endpoint %q changed after preflight", spec.endpointRelative())
		}
		if err := parent.root.Symlink(spec.target, spec.name); err != nil {
			return fmt.Errorf("create managed link %q: %w", spec.endpointRelative(), err)
		}
		state, err = inspectManagedLink(topology, parent, spec)
		if err != nil || state != topologyLinkExact {
			if err != nil {
				return err
			}
			return fmt.Errorf("managed link %q is not exact after creation", spec.endpointRelative())
		}
		if err := parent.dir.Sync(); err != nil {
			return fmt.Errorf("sync managed link parent %q: %w", spec.parentRelative, err)
		}
	}
	for index, spec := range topology.files {
		if snapshot.fileStates[index] == topologyLinkExact {
			continue
		}
		parent := snapshot.parents[spec.parentRelative]
		if parent == nil {
			return fmt.Errorf("managed-file parent %q was not created", spec.parentRelative)
		}
		if err := parent.validate(topology); err != nil {
			return err
		}
		state, err := inspectManagedFile(topology, parent, spec)
		if err != nil || state != topologyLinkAbsent {
			if err != nil {
				return err
			}
			return fmt.Errorf("managed-file endpoint %q changed after preflight", spec.endpointRelative())
		}
		if err := topology.createManagedFileLocked(parent, spec); err != nil {
			return err
		}
		state, err = inspectManagedFile(topology, parent, spec)
		if err != nil || state != topologyLinkExact {
			if err != nil {
				return err
			}
			return fmt.Errorf("managed file %q is not exact after creation", spec.endpointRelative())
		}
	}
	return topology.auditLocked()
}

func (topology *ManagedLinkTopology) createManagedFileLocked(parent *topologyParent, spec managedFileSpec) (returnErr error) {
	if err := parent.validate(topology); err != nil {
		return err
	}
	temporaryName, file, err := createTopologyTemporaryFile(parent.root)
	if err != nil {
		return fmt.Errorf("create managed-file temporary for %q: %w", spec.endpointRelative(), err)
	}
	temporaryOpen := true
	temporaryNamed := true
	var created os.FileInfo
	defer func() {
		if temporaryOpen {
			returnErr = errors.Join(returnErr, file.Close())
		}
		if temporaryNamed {
			returnErr = errors.Join(returnErr, cleanupTopologyTemporary(parent.root, parent.dir, temporaryName, created, false))
		}
	}()
	created, err = file.Stat()
	if err != nil || created.Mode() != stagingMode || created.Size() != 0 || !ownedTopologyTemporary(created, false) {
		return errors.New("new managed-file temporary is not an anchored private regular file")
	}
	topology.checkpoint(topologyCheckpointFileCreated)
	written, err := io.Copy(file, bytes.NewReader(spec.content))
	if err != nil {
		return err
	}
	if written != int64(len(spec.content)) {
		return io.ErrShortWrite
	}
	topology.checkpoint(topologyCheckpointFileContentWritten)
	if err := file.Sync(); err != nil {
		return err
	}
	topology.checkpoint(topologyCheckpointFileContentSynced)
	if err := file.Chmod(0o444); err != nil {
		return err
	}
	topology.checkpoint(topologyCheckpointFileFinalMode)
	if err := file.Sync(); err != nil {
		return err
	}
	topology.checkpoint(topologyCheckpointFileFinalSynced)
	final, statErr := file.Stat()
	visible, visibleErr := parent.root.Lstat(temporaryName)
	if statErr != nil || visibleErr != nil || !sameManagedFileObject(final, visible) ||
		!trustedExactManagedFile(final, int64(len(spec.content))) {
		return errors.New("managed-file temporary changed while finalizing")
	}
	if err := rejectPOSIXACL(filepath.Join(parent.path, temporaryName)); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	temporaryOpen = false
	if err := parent.validate(topology); err != nil {
		return err
	}
	if err := renameNoReplace(parent.dir, temporaryName, spec.name); err != nil {
		return fmt.Errorf("publish managed file %q without replacement: %w", spec.endpointRelative(), err)
	}
	temporaryNamed = false
	topology.checkpoint(topologyCheckpointFilePublished)
	if err := parent.dir.Sync(); err != nil {
		return fmt.Errorf("sync managed file parent %q: %w", spec.parentRelative, err)
	}
	return nil
}

func (topology *ManagedLinkTopology) ensureDirectoriesLocked() error {
	if err := topology.validateLocked(); err != nil {
		return err
	}
	for _, relative := range topologyDirectoryOrder() {
		info, err := topology.local.Lstat(relative)
		if err == nil {
			if !trustedTopologyDirectory(info) {
				return fmt.Errorf("managed-link parent component %q conflicts", relative)
			}
			if err := rejectPOSIXACL(filepath.Join(topology.localPath, relative)); err != nil {
				return err
			}
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		parentRelative := filepath.Dir(relative)
		name := filepath.Base(relative)
		var parentRoot *os.Root
		var parentDir *os.File
		if parentRelative == "." {
			parentRoot = topology.local
			parentDir = topology.localDir
		} else {
			parent, err := topology.openParentLocked(parentRelative)
			if err != nil {
				return err
			}
			parentRoot = parent.root
			parentDir = parent.dir
			defer parent.close()
		}
		parentPath := topology.localPath
		if parentRelative != "." {
			parentPath = filepath.Join(topology.localPath, parentRelative)
		}
		if err := topology.createManagedDirectoryLocked(parentRoot, parentDir, parentPath, relative, name); err != nil {
			return err
		}
	}
	return nil
}

func (topology *ManagedLinkTopology) createManagedDirectoryLocked(parentRoot *os.Root, parentDir *os.File, parentPath, relative, name string) (returnErr error) {
	temporaryName, err := createTopologyTemporaryDirectory(parentRoot)
	if err != nil {
		return fmt.Errorf("create managed-link directory temporary for %q: %w", relative, err)
	}
	temporaryNamed := true
	var child *os.File
	var created os.FileInfo
	defer func() {
		if child != nil {
			returnErr = errors.Join(returnErr, child.Close())
		}
		if temporaryNamed {
			returnErr = errors.Join(returnErr, cleanupTopologyTemporary(parentRoot, parentDir, temporaryName, created, true))
		}
	}()
	child, err = parentRoot.Open(temporaryName)
	if err != nil {
		return fmt.Errorf("anchor new managed-link directory temporary for %q: %w", relative, err)
	}
	created, err = child.Stat()
	visible, visibleErr := parentRoot.Lstat(temporaryName)
	if err != nil || visibleErr != nil || !sameDirectoryObject(created, visible) || !ownedExactDirectory(created, stagingMode) {
		return fmt.Errorf("new managed-link directory temporary for %q changed while anchoring", relative)
	}
	topology.checkpoint(topologyCheckpointDirectoryCreated)
	if err := child.Chmod(managedLayoutMode); err != nil {
		return fmt.Errorf("set managed-link directory %q mode: %w", relative, err)
	}
	topology.checkpoint(topologyCheckpointDirectoryFinalMode)
	if err := child.Sync(); err != nil {
		return fmt.Errorf("sync managed-link directory %q: %w", relative, err)
	}
	final, statErr := child.Stat()
	visible, visibleErr = parentRoot.Lstat(temporaryName)
	if statErr != nil || visibleErr != nil || !sameDirectoryObject(final, visible) || !ownedExactDirectory(final, managedLayoutMode) {
		return fmt.Errorf("managed-link directory temporary for %q changed while finalizing", relative)
	}
	if err := rejectPOSIXACL(filepath.Join(parentPath, temporaryName)); err != nil {
		return err
	}
	if err := child.Close(); err != nil {
		return err
	}
	child = nil
	if err := renameNoReplace(parentDir, temporaryName, name); err != nil {
		return fmt.Errorf("publish managed-link directory %q without replacement: %w", relative, err)
	}
	temporaryNamed = false
	topology.checkpoint(topologyCheckpointDirectoryPublished)
	if err := parentDir.Sync(); err != nil {
		return fmt.Errorf("sync parent of managed-link directory %q: %w", relative, err)
	}
	final, err = parentRoot.Lstat(name)
	if err != nil || !sameDirectoryObject(created, final) || !ownedExactDirectory(final, managedLayoutMode) {
		return fmt.Errorf("published managed-link directory %q changed", relative)
	}
	return rejectPOSIXACL(filepath.Join(parentPath, name))
}

func createTopologyTemporaryDirectory(root *os.Root) (string, error) {
	for attempt := 0; attempt < 4; attempt++ {
		suffix, err := randomLayoutSuffix()
		if err != nil {
			return "", err
		}
		name := topologyDirectoryTemporaryPrefix + suffix
		if err := root.Mkdir(name, stagingMode); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return "", err
		}
		return name, nil
	}
	return "", errors.New("could not allocate a unique managed-link directory temporary")
}

func createTopologyTemporaryFile(root *os.Root) (string, *os.File, error) {
	for attempt := 0; attempt < 4; attempt++ {
		suffix, err := randomLayoutSuffix()
		if err != nil {
			return "", nil, err
		}
		name := topologyFileTemporaryPrefix + suffix
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, stagingMode)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		return name, file, nil
	}
	return "", nil, errors.New("could not allocate a unique managed-file temporary")
}

func ownedTopologyTemporary(info os.FileInfo, directory bool) bool {
	if info == nil {
		return false
	}
	if directory {
		return ownedExactDirectory(info, stagingMode) || ownedExactDirectory(info, managedLayoutMode)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() &&
		(info.Mode() == stagingMode || info.Mode() == 0o444) &&
		info.Size() >= 0 && info.Size() <= maximumTopologyTemporaryFileSize &&
		stat.Uid == uint32(os.Geteuid()) && stat.Gid == uint32(os.Getegid()) && stat.Nlink == 1
}

// scavengeTemporariesLocked removes only exact private names and inode shapes
// that this topology publisher can leave behind if it is killed before a
// create-only rename. The scan covers the fixed directory ancestry where a
// child or reviewed unit file can be staged; it never traverses an arbitrary
// subtree and never removes a noncanonical or nonempty object.
func (topology *ManagedLinkTopology) scavengeTemporariesLocked() error {
	if err := topology.validateLocked(); err != nil {
		return err
	}
	if err := scavengeTopologyParent(topology.local, topology.localDir, topology.localPath, true, false); err != nil {
		return err
	}
	directories, err := topology.inspectDirectoriesLocked()
	if err != nil {
		return err
	}
	type temporaryKinds struct {
		directory bool
		file      bool
	}
	locations := make(map[string]temporaryKinds)
	for _, relative := range topologyDirectoryOrder() {
		parent := filepath.Dir(relative)
		if parent == "." {
			continue // The anchored /usr/local root was scanned above.
		}
		kinds := locations[parent]
		kinds.directory = true
		locations[parent] = kinds
	}
	for _, spec := range topology.files {
		kinds := locations[spec.parentRelative]
		kinds.file = true
		locations[spec.parentRelative] = kinds
	}
	relatives := make([]string, 0, len(locations))
	for relative := range locations {
		relatives = append(relatives, relative)
	}
	sort.Strings(relatives)
	for _, relative := range relatives {
		if !directories[relative] {
			continue
		}
		parent, err := topology.openParentLocked(relative)
		if err != nil {
			return err
		}
		kinds := locations[relative]
		scavengeErr := scavengeTopologyParent(parent.root, parent.dir, parent.path, kinds.directory, kinds.file)
		closeErr := parent.close()
		if err := errors.Join(scavengeErr, closeErr); err != nil {
			return err
		}
	}
	return nil
}

func scavengeTopologyParent(root *os.Root, parentDir *os.File, parentPath string, allowDirectory, allowFile bool) error {
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("enumerate managed-topology parent %q: %w", parentPath, err)
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return fmt.Errorf("enumerate managed-topology parent %q: %w", parentPath, err)
	}
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		directoryTemporary, recognized := topologyTemporaryName(name)
		if !recognized || directoryTemporary && !allowDirectory || !directoryTemporary && !allowFile {
			continue
		}
		info, err := root.Lstat(name)
		if err != nil || !ownedTopologyTemporary(info, directoryTemporary) {
			return fmt.Errorf("managed-topology temporary %q has a noncanonical shape", filepath.Join(parentPath, name))
		}
		if err := rejectPOSIXACL(filepath.Join(parentPath, name)); err != nil {
			return err
		}
		if err := root.Remove(name); err != nil {
			return fmt.Errorf("remove abandoned managed-topology temporary %q: %w", filepath.Join(parentPath, name), err)
		}
		removed = true
	}
	if removed {
		if err := parentDir.Sync(); err != nil {
			return fmt.Errorf("sync managed-topology temporary cleanup in %q: %w", parentPath, err)
		}
	}
	return nil
}

func topologyTemporaryName(name string) (directory bool, recognized bool) {
	var suffix string
	switch {
	case strings.HasPrefix(name, topologyDirectoryTemporaryPrefix):
		directory = true
		suffix = strings.TrimPrefix(name, topologyDirectoryTemporaryPrefix)
	case strings.HasPrefix(name, topologyFileTemporaryPrefix):
		suffix = strings.TrimPrefix(name, topologyFileTemporaryPrefix)
	default:
		return false, false
	}
	if len(suffix) != 32 {
		return false, false
	}
	for _, value := range []byte(suffix) {
		if value < '0' || value > '9' {
			if value < 'a' || value > 'f' {
				return false, false
			}
		}
	}
	return directory, true
}

func cleanupTopologyTemporary(root *os.Root, parentDir *os.File, name string, created os.FileInfo, directory bool) error {
	if created == nil {
		return errors.New("cannot identify managed-topology temporary")
	}
	visible, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !os.SameFile(created, visible) || !ownedTopologyTemporary(visible, directory) {
		return errors.New("managed-topology temporary changed before cleanup")
	}
	if err := root.Remove(name); err != nil {
		return err
	}
	return parentDir.Sync()
}

// Audit requires every link and stable unit file to match its reviewed shape.
func (topology *ManagedLinkTopology) Audit() error {
	topology.mu.Lock()
	defer topology.mu.Unlock()
	return topology.auditLocked()
}

func (topology *ManagedLinkTopology) auditLocked() error {
	snapshot, err := topology.snapshotLocked()
	if err != nil {
		return err
	}
	defer snapshot.close()
	for index, state := range snapshot.linkStates {
		if state != topologyLinkExact {
			return fmt.Errorf("managed-link endpoint %q is absent", topology.specs[index].endpointRelative())
		}
	}
	for index, state := range snapshot.fileStates {
		if state != topologyLinkExact {
			return fmt.Errorf("managed-file endpoint %q is absent", topology.files[index].endpointRelative())
		}
	}
	return nil
}

// Remove is the first-install rollback inverse of Ensure. It preflights every
// endpoint as absent or exact, then unlinks only exact managed links. Parent
// directories are deliberately retained because they may predate Mesh.
func (topology *ManagedLinkTopology) Remove() error {
	topology.mu.Lock()
	defer topology.mu.Unlock()
	snapshot, err := topology.snapshotLocked()
	if err != nil {
		return err
	}
	defer snapshot.close()
	if err := topology.scavengeTemporariesLocked(); err != nil {
		return err
	}
	for index, spec := range topology.specs {
		if snapshot.linkStates[index] == topologyLinkAbsent {
			continue
		}
		parent := snapshot.parents[spec.parentRelative]
		if parent == nil {
			return fmt.Errorf("managed-link parent %q disappeared", spec.parentRelative)
		}
		if err := parent.validate(topology); err != nil {
			return err
		}
		state, err := inspectManagedLink(topology, parent, spec)
		if err != nil || state != topologyLinkExact {
			if err != nil {
				return err
			}
			return fmt.Errorf("managed-link endpoint %q changed after preflight", spec.endpointRelative())
		}
		if err := parent.root.Remove(spec.name); err != nil {
			return fmt.Errorf("remove managed link %q: %w", spec.endpointRelative(), err)
		}
		if err := parent.dir.Sync(); err != nil {
			return fmt.Errorf("sync managed-link removal parent %q: %w", spec.parentRelative, err)
		}
	}
	for index, spec := range topology.files {
		if snapshot.fileStates[index] == topologyLinkAbsent {
			continue
		}
		parent := snapshot.parents[spec.parentRelative]
		if parent == nil {
			return fmt.Errorf("managed-file parent %q disappeared", spec.parentRelative)
		}
		if err := parent.validate(topology); err != nil {
			return err
		}
		state, err := inspectManagedFile(topology, parent, spec)
		if err != nil || state != topologyLinkExact {
			if err != nil {
				return err
			}
			return fmt.Errorf("managed-file endpoint %q changed after preflight", spec.endpointRelative())
		}
		if err := parent.root.Remove(spec.name); err != nil {
			return fmt.Errorf("remove managed file %q: %w", spec.endpointRelative(), err)
		}
		if err := parent.dir.Sync(); err != nil {
			return fmt.Errorf("sync managed-file removal parent %q: %w", spec.parentRelative, err)
		}
	}
	return topology.requireAbsentLocked()
}

func (topology *ManagedLinkTopology) requireAbsentLocked() error {
	snapshot, err := topology.snapshotLocked()
	if err != nil {
		return err
	}
	defer snapshot.close()
	for index, state := range snapshot.linkStates {
		if state != topologyLinkAbsent {
			return fmt.Errorf("managed-link endpoint %q survived removal", topology.specs[index].endpointRelative())
		}
	}
	for index, state := range snapshot.fileStates {
		if state != topologyLinkAbsent {
			return fmt.Errorf("managed-file endpoint %q survived removal", topology.files[index].endpointRelative())
		}
	}
	return nil
}

func (topology *ManagedLinkTopology) Close() error {
	if topology == nil {
		return nil
	}
	topology.mu.Lock()
	defer topology.mu.Unlock()
	return topology.closeLocked()
}

func (topology *ManagedLinkTopology) closeLocked() error {
	if topology.closed {
		return nil
	}
	topology.closed = true
	var errs []error
	for _, closer := range []io.Closer{topology.localDir, topology.local} {
		if closer != nil {
			if err := closer.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func validateProductionTopologyConstants() error {
	wantUnitDirectory := filepath.Join(productionLocalRoot, "lib/systemd/system")
	if managedUnitDirectory != wantUnitDirectory {
		return fmt.Errorf("systemd unit directory %q differs from managed-link topology %q", managedUnitDirectory, wantUnitDirectory)
	}
	if !strings.HasPrefix(ProductionMeshRoot, string(filepath.Separator)) {
		return errors.New("production mesh root is not absolute")
	}
	return nil
}
