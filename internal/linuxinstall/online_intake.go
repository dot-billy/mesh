//go:build linux

package linuxinstall

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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"mesh/internal/onlinerelease"
	releasetrust "mesh/internal/release"
)

const (
	productionOnlineIntakeDirectory = "/var/lib/mesh-installer/online-intake"
	onlineIntakeLockName            = "online.lock"
	onlineWorkspacePrefix           = "pending-"

	onlineChannelManifestName = "channel.json"
	onlineReleaseManifestName = "release.json"
	onlineArtifactName        = "mesh-linux-bundle.tar"
)

var (
	onlineWorkspaceNamePattern  = regexp.MustCompile(`^pending-[0-9a-f]{32}$`)
	onlineSignatureNamePattern  = regexp.MustCompile(`^(channel|release)-signature-([0-9]{3})\.json$`)
	onlineRootUpdateNamePattern = regexp.MustCompile(`^root-update-([0-9]{3})\.json$`)
)

type onlineIntakeLock struct {
	root            *os.Root
	dir             *os.File
	file            *os.File
	uid             uint32
	path            string
	rootInfo        os.FileInfo
	activeWorkspace string
}

type onlineWorkspace struct {
	parent *onlineIntakeLock
	name   string
	path   string
	root   *os.Root
	info   os.FileInfo
}

type onlineIntakeHooks struct {
	afterInspect func()
	syncParent   func(*os.Root) error
}

type onlineMaterializeHooks struct {
	chmodArtifact  func(*os.File, os.FileMode) error
	syncWorkspace  func(*onlineWorkspace) error
	beforeReadback func()
}

type onlineFileIdentity struct {
	device, inode, links uint64
	mode                 uint32
	uid, gid             uint32
	size                 int64
	mtimeSeconds         int64
	mtimeNanoseconds     int64
	ctimeSeconds         int64
	ctimeNanoseconds     int64
}

type inspectedOnlineWorkspace struct {
	name      string
	directory onlineFileIdentity
	files     map[string]onlineFileIdentity
}

func ensureOnlineIntakeDirectory(path string, expectedUID uint32) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve online intake directory: %w", err)
	}
	absolute = filepath.Clean(absolute)
	if absolute != path {
		return errors.New("online intake directory must be a canonical absolute path")
	}
	parent := filepath.Dir(absolute)
	if err := validateSecureAncestorChain(parent, false); err != nil {
		return fmt.Errorf("validate online intake parent: %w", err)
	}
	created := false
	if err := os.Mkdir(absolute, 0o700); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create online intake directory: %w", err)
		}
	} else {
		created = true
		if err := os.Chmod(absolute, 0o700); err != nil {
			return fmt.Errorf("set online intake directory mode: %w", err)
		}
	}
	if err := validateOnlinePrivateDirectoryPath(absolute, expectedUID); err != nil {
		return err
	}
	if created {
		if err := syncDirectory(parent); err != nil {
			return fmt.Errorf("sync online intake parent after creation: %w", err)
		}
	}
	return nil
}

func acquireOnlineIntake(path string, expectedUID uint32) (lock *onlineIntakeLock, returnErr error) {
	if err := ensureOnlineIntakeDirectory(path, expectedUID); err != nil {
		return nil, err
	}
	rootInfo, err := os.Lstat(path)
	if err != nil || validateOnlinePrivateDirectoryInfo(rootInfo, expectedUID, false) != nil {
		return nil, errors.New("online intake root is not a stable private directory")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("anchor online intake root: %w", err)
	}
	defer func() {
		if returnErr != nil {
			_ = root.Close()
		}
	}()
	rootedInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(rootInfo, rootedInfo) || validateOnlinePrivateDirectoryInfo(rootedInfo, expectedUID, false) != nil {
		return nil, errors.New("online intake root changed while anchoring")
	}
	directory, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open online intake directory descriptor: %w", err)
	}
	defer func() {
		if returnErr != nil {
			_ = directory.Close()
		}
	}()
	directoryInfo, err := directory.Stat()
	if err != nil || !os.SameFile(rootInfo, directoryInfo) {
		return nil, errors.New("online intake directory changed while opening")
	}

	lockFile, created, err := openOnlineIntakeLockFile(root, expectedUID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr != nil {
			_ = lockFile.Close()
			if created {
				_ = root.Remove(onlineIntakeLockName)
				_ = syncRootDirectory(root)
			}
		}
	}()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errors.New("another online install holds the intake lock")
		}
		return nil, fmt.Errorf("lock online intake: %w", err)
	}
	lock = &onlineIntakeLock{root: root, dir: directory, file: lockFile, uid: expectedUID, path: path, rootInfo: rootInfo}
	if err := lock.validateHeld(); err != nil {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		return nil, err
	}
	return lock, nil
}

func openOnlineIntakeLockFile(root *os.Root, expectedUID uint32) (file *os.File, created bool, returnErr error) {
	before, err := root.Lstat(onlineIntakeLockName)
	switch {
	case err == nil:
		if err := validateOnlinePrivateRegular(before, expectedUID, 0o600, 0, true); err != nil {
			return nil, false, fmt.Errorf("online intake lock: %w", err)
		}
		file, err = root.OpenFile(onlineIntakeLockName, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	case errors.Is(err, os.ErrNotExist):
		file, err = root.OpenFile(onlineIntakeLockName, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		created = err == nil
	default:
		return nil, false, fmt.Errorf("inspect online intake lock: %w", err)
	}
	if err != nil {
		return nil, false, fmt.Errorf("open online intake lock: %w", err)
	}
	defer func() {
		if returnErr != nil {
			_ = file.Close()
		}
	}()
	if created {
		if err := file.Chmod(0o600); err != nil {
			return nil, created, err
		}
		if err := file.Sync(); err != nil {
			return nil, created, err
		}
		if err := syncRootDirectory(root); err != nil {
			return nil, created, err
		}
		before, err = root.Lstat(onlineIntakeLockName)
		if err != nil {
			return nil, created, err
		}
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, created, errors.New("online intake lock changed while opening")
	}
	if err := validateOnlinePrivateRegular(opened, expectedUID, 0o600, 0, true); err != nil {
		return nil, created, fmt.Errorf("online intake lock: %w", err)
	}
	return file, created, nil
}

func (lock *onlineIntakeLock) validateHeld() error {
	if lock == nil || lock.root == nil || lock.dir == nil || lock.file == nil || lock.path == "" {
		return errors.New("online intake lock is not held")
	}
	pathInfo, pathErr := os.Lstat(lock.path)
	rootInfo, rootErr := lock.root.Stat(".")
	directoryInfo, directoryErr := lock.dir.Stat()
	if pathErr != nil || rootErr != nil || directoryErr != nil ||
		!os.SameFile(lock.rootInfo, pathInfo) || !os.SameFile(lock.rootInfo, rootInfo) || !os.SameFile(lock.rootInfo, directoryInfo) ||
		validateOnlinePrivateDirectoryInfo(pathInfo, lock.uid, false) != nil || validateOnlinePrivateDirectoryInfo(rootInfo, lock.uid, false) != nil {
		return errors.New("online intake root changed while the lock was held")
	}
	pathLock, pathErr := lock.root.Lstat(onlineIntakeLockName)
	openedLock, openedErr := lock.file.Stat()
	if pathErr != nil || openedErr != nil || !os.SameFile(pathLock, openedLock) || validateOnlinePrivateRegular(openedLock, lock.uid, 0o600, 0, true) != nil {
		return errors.New("online intake lock file changed while held")
	}
	return nil
}

func (lock *onlineIntakeLock) reconcile() error {
	return lock.reconcileUsing(onlineIntakeHooks{})
}

func (lock *onlineIntakeLock) reconcileUsing(hooks onlineIntakeHooks) error {
	if err := lock.validateHeld(); err != nil {
		return err
	}
	if lock.activeWorkspace != "" {
		return errors.New("cannot reconcile online intake while this invocation owns a workspace")
	}
	directory, err := lock.root.Open(".")
	if err != nil {
		return fmt.Errorf("open online intake for reconciliation: %w", err)
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil {
		return fmt.Errorf("list online intake: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close online intake listing: %w", closeErr)
	}
	inspected := make([]inspectedOnlineWorkspace, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == onlineIntakeLockName {
			if info, err := lock.root.Lstat(name); err != nil || validateOnlinePrivateRegular(info, lock.uid, 0o600, 0, true) != nil {
				return errors.New("online intake lock entry is unsafe during reconciliation")
			}
			continue
		}
		if !onlineWorkspaceNamePattern.MatchString(name) {
			return fmt.Errorf("unknown online intake entry %q; refusing cleanup", name)
		}
		workspace, err := inspectOnlineWorkspace(lock.root, name, lock.uid)
		if err != nil {
			return fmt.Errorf("inspect recognized online intake workspace %q: %w", name, err)
		}
		inspected = append(inspected, workspace)
	}
	if hooks.afterInspect != nil {
		hooks.afterInspect()
	}
	if err := lock.validateHeld(); err != nil {
		return err
	}
	for _, before := range inspected {
		after, err := inspectOnlineWorkspace(lock.root, before.name, lock.uid)
		if err != nil || !sameInspectedOnlineWorkspace(before, after) {
			return fmt.Errorf("recognized online intake workspace %q changed after inspection", before.name)
		}
	}
	for _, workspace := range inspected {
		if err := lock.validateHeld(); err != nil {
			return err
		}
		if err := lock.root.RemoveAll(workspace.name); err != nil {
			return fmt.Errorf("remove recognized online intake workspace %q: %w", workspace.name, err)
		}
	}
	if len(inspected) != 0 {
		syncParent := hooks.syncParent
		if syncParent == nil {
			syncParent = syncRootDirectory
		}
		if err := syncParent(lock.root); err != nil {
			return fmt.Errorf("sync recognized online intake cleanup: %w", err)
		}
	}
	return nil
}

func inspectOnlineWorkspace(parent *os.Root, name string, expectedUID uint32) (inspectedOnlineWorkspace, error) {
	if !onlineWorkspaceNamePattern.MatchString(name) {
		return inspectedOnlineWorkspace{}, errors.New("workspace name is not recognized")
	}
	before, err := parent.Lstat(name)
	if err != nil {
		return inspectedOnlineWorkspace{}, err
	}
	if err := validateOnlinePrivateDirectoryInfo(before, expectedUID, false); err != nil {
		return inspectedOnlineWorkspace{}, err
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return inspectedOnlineWorkspace{}, err
	}
	defer root.Close()
	anchored, err := root.Stat(".")
	if err != nil || !os.SameFile(before, anchored) {
		return inspectedOnlineWorkspace{}, errors.New("workspace changed while anchoring")
	}
	directory, err := root.Open(".")
	if err != nil {
		return inspectedOnlineWorkspace{}, err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil {
		return inspectedOnlineWorkspace{}, readErr
	}
	if closeErr != nil {
		return inspectedOnlineWorkspace{}, closeErr
	}
	files := make(map[string]onlineFileIdentity, len(entries))
	for _, entry := range entries {
		entryName := entry.Name()
		maximum, artifact, err := onlineWorkspaceFilePolicy(entryName)
		if err != nil {
			return inspectedOnlineWorkspace{}, fmt.Errorf("unknown workspace entry %q", entryName)
		}
		info, err := root.Lstat(entryName)
		if err != nil {
			return inspectedOnlineWorkspace{}, err
		}
		if err := validateOnlineWorkspaceFile(info, expectedUID, maximum, artifact); err != nil {
			return inspectedOnlineWorkspace{}, fmt.Errorf("workspace entry %q: %w", entryName, err)
		}
		file, err := root.OpenFile(entryName, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return inspectedOnlineWorkspace{}, fmt.Errorf("open workspace entry %q: %w", entryName, err)
		}
		opened, statErr := file.Stat()
		closeErr := file.Close()
		if statErr != nil || closeErr != nil || !os.SameFile(info, opened) {
			return inspectedOnlineWorkspace{}, fmt.Errorf("workspace entry %q changed while opening", entryName)
		}
		identity, ok := onlineIdentityFromInfo(opened)
		if !ok {
			return inspectedOnlineWorkspace{}, fmt.Errorf("workspace entry %q has no Linux identity", entryName)
		}
		files[entryName] = identity
	}
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) || validateOnlinePrivateDirectoryInfo(after, expectedUID, true) != nil {
		return inspectedOnlineWorkspace{}, errors.New("workspace changed during inspection")
	}
	directoryIdentity, ok := onlineIdentityFromInfo(after)
	if !ok {
		return inspectedOnlineWorkspace{}, errors.New("workspace has no Linux identity")
	}
	return inspectedOnlineWorkspace{name: name, directory: directoryIdentity, files: files}, nil
}

func sameInspectedOnlineWorkspace(left, right inspectedOnlineWorkspace) bool {
	if left.name != right.name || left.directory != right.directory || len(left.files) != len(right.files) {
		return false
	}
	for name, identity := range left.files {
		if right.files[name] != identity {
			return false
		}
	}
	return true
}

func (lock *onlineIntakeLock) newWorkspace() (workspace *onlineWorkspace, returnErr error) {
	if err := lock.validateHeld(); err != nil {
		return nil, err
	}
	if lock.activeWorkspace != "" {
		return nil, errors.New("this online intake lock already owns a workspace")
	}
	name, err := randomOnlineWorkspaceName()
	if err != nil {
		return nil, fmt.Errorf("allocate online workspace name: %w", err)
	}
	if err := lock.root.Mkdir(name, 0o700); err != nil {
		return nil, fmt.Errorf("create online workspace: %w", err)
	}
	created := true
	defer func() {
		if returnErr != nil && created {
			_ = lock.root.RemoveAll(name)
			_ = syncRootDirectory(lock.root)
		}
	}()
	if err := lock.root.Chmod(name, 0o700); err != nil {
		return nil, fmt.Errorf("set online workspace mode: %w", err)
	}
	info, err := lock.root.Lstat(name)
	if err != nil || validateOnlinePrivateDirectoryInfo(info, lock.uid, true) != nil {
		return nil, errors.New("new online workspace has unsafe metadata")
	}
	root, err := lock.root.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("anchor online workspace: %w", err)
	}
	defer func() {
		if returnErr != nil {
			_ = root.Close()
		}
	}()
	anchored, err := root.Stat(".")
	if err != nil || !os.SameFile(info, anchored) {
		return nil, errors.New("online workspace changed while anchoring")
	}
	if err := syncRootDirectory(lock.root); err != nil {
		return nil, fmt.Errorf("sync new online workspace: %w", err)
	}
	lock.activeWorkspace = name
	created = false
	return &onlineWorkspace{parent: lock, name: name, path: filepath.Join(lock.path, name), root: root, info: info}, nil
}

func (workspace *onlineWorkspace) writeFile(name string, raw []byte, mode os.FileMode) (returnErr error) {
	maximum, artifact, err := onlineWorkspaceFilePolicy(name)
	if err != nil || artifact {
		return fmt.Errorf("workspace file name %q is not allowed for metadata writes", name)
	}
	if mode != 0o400 {
		return errors.New("online workspace metadata files must use mode 0400")
	}
	if len(raw) == 0 || int64(len(raw)) > maximum {
		return fmt.Errorf("online workspace file %q size must be between 1 and %d", name, maximum)
	}
	if err := workspace.validateAnchor(); err != nil {
		return err
	}
	file, err := workspace.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return fmt.Errorf("create online workspace file %q: %w", name, err)
	}
	created := true
	defer func() {
		if returnErr != nil {
			_ = file.Close()
			if created {
				_ = workspace.root.Remove(name)
				_ = syncRootDirectory(workspace.root)
			}
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	written, err := io.Copy(file, bytes.NewReader(raw))
	if err != nil || written != int64(len(raw)) {
		return fmt.Errorf("write online workspace file %q: wrote %d bytes: %w", name, written, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync online workspace file %q: %w", name, err)
	}
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	pathInfo, err := workspace.root.Lstat(name)
	if err != nil || !os.SameFile(opened, pathInfo) || validateOnlinePrivateRegular(pathInfo, workspace.parent.uid, mode, int64(len(raw)), false) != nil || pathInfo.Size() != int64(len(raw)) {
		return fmt.Errorf("online workspace file %q changed after writing", name)
	}
	if err := workspace.sync(); err != nil {
		return fmt.Errorf("sync online workspace after writing %q: %w", name, err)
	}
	created = false
	return nil
}

func (workspace *onlineWorkspace) openArtifact() (file *os.File, returnErr error) {
	if err := workspace.validateAnchor(); err != nil {
		return nil, err
	}
	file, err := workspace.root.OpenFile(onlineArtifactName, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create online artifact: %w", err)
	}
	defer func() {
		if returnErr != nil {
			_ = file.Close()
			_ = workspace.root.Remove(onlineArtifactName)
			_ = syncRootDirectory(workspace.root)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return nil, err
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || validateOnlinePrivateRegular(info, workspace.parent.uid, 0o600, 0, true) != nil {
		return nil, errors.New("new online artifact has unsafe metadata")
	}
	if err := workspace.sync(); err != nil {
		return nil, err
	}
	return file, nil
}

func (workspace *onlineWorkspace) sealArtifact(file *os.File) error {
	_, err := workspace.sealArtifactUsing(file, onlineMaterializeHooks{})
	return err
}

func (workspace *onlineWorkspace) sealArtifactUsing(file *os.File, hooks onlineMaterializeHooks) (SourceFileIdentity, error) {
	if file == nil {
		return SourceFileIdentity{}, errors.New("online artifact file is nil")
	}
	if err := workspace.validateAnchor(); err != nil {
		return SourceFileIdentity{}, err
	}
	if err := file.Sync(); err != nil {
		return SourceFileIdentity{}, fmt.Errorf("sync online artifact: %w", err)
	}
	opened, err := file.Stat()
	pathInfo, pathErr := workspace.root.Lstat(onlineArtifactName)
	if err != nil || pathErr != nil || !os.SameFile(opened, pathInfo) || validateOnlineWorkspaceFile(pathInfo, workspace.parent.uid, releasetrust.MaxArtifactSize, true) != nil || pathInfo.Mode().Perm() != 0o600 || pathInfo.Size() == 0 {
		return SourceFileIdentity{}, errors.New("online artifact identity or metadata changed before sealing")
	}
	reader, err := workspace.root.OpenFile(onlineArtifactName, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return SourceFileIdentity{}, fmt.Errorf("reopen online artifact read-only: %w", err)
	}
	readerClosed := false
	defer func() {
		if !readerClosed {
			_ = reader.Close()
		}
	}()
	readerBefore, err := reader.Stat()
	if err != nil || !os.SameFile(opened, readerBefore) {
		return SourceFileIdentity{}, errors.New("online artifact identity changed while reopening read-only")
	}
	chmodArtifact := hooks.chmodArtifact
	if chmodArtifact == nil {
		chmodArtifact = func(file *os.File, mode os.FileMode) error { return file.Chmod(mode) }
	}
	if err := chmodArtifact(file, 0o400); err != nil {
		return SourceFileIdentity{}, fmt.Errorf("seal online artifact read-only: %w", err)
	}
	if err := file.Sync(); err != nil {
		return SourceFileIdentity{}, fmt.Errorf("sync sealed online artifact: %w", err)
	}
	after, err := file.Stat()
	pathAfter, pathErr := workspace.root.Lstat(onlineArtifactName)
	readerAfter, readerErr := reader.Stat()
	if err != nil || pathErr != nil || readerErr != nil || !os.SameFile(opened, after) || !os.SameFile(after, pathAfter) || !os.SameFile(after, readerAfter) || validateOnlinePrivateRegular(after, workspace.parent.uid, 0o400, releasetrust.MaxArtifactSize, false) != nil || after.Size() == 0 {
		return SourceFileIdentity{}, errors.New("sealed online artifact identity or metadata changed")
	}
	identity, ok := sourceIdentity(after)
	if !ok {
		return SourceFileIdentity{}, errors.New("sealed online artifact has no Linux identity")
	}
	if err := file.Close(); err != nil {
		return SourceFileIdentity{}, fmt.Errorf("close writable online artifact descriptor: %w", err)
	}
	if err := reader.Close(); err != nil {
		return SourceFileIdentity{}, fmt.Errorf("close read-only online artifact descriptor: %w", err)
	}
	readerClosed = true
	if err := workspace.sync(); err != nil {
		return SourceFileIdentity{}, err
	}
	return identity, nil
}

func (workspace *onlineWorkspace) materializeSnapshot(bundle onlinerelease.Bundle, artifact *os.File) (string, error) {
	return workspace.materializeSnapshotUsing(bundle, artifact, onlineMaterializeHooks{})
}

func (workspace *onlineWorkspace) materializeSnapshotUsing(bundle onlinerelease.Bundle, artifact *os.File, hooks onlineMaterializeHooks) (string, error) {
	if err := workspace.validateAnchor(); err != nil {
		return "", err
	}
	encoded, err := onlinerelease.Encode(bundle)
	if err != nil {
		return "", fmt.Errorf("validate online bundle before snapshot materialization: %w", err)
	}
	exact, err := onlinerelease.Parse(encoded)
	if err != nil {
		return "", fmt.Errorf("clone exact online bundle bytes: %w", err)
	}
	channelSignatures := sortOnlineSignatureBytes(exact.ChannelSignatures)
	releaseSignatures := sortOnlineSignatureBytes(exact.ReleaseSignatures)
	rootNames := make([]string, len(exact.RootUpdates))
	for index, update := range exact.RootUpdates {
		name := fmt.Sprintf("root-update-%03d.json", index)
		if err := workspace.writeFile(name, update, 0o400); err != nil {
			return "", err
		}
		rootNames[index] = name
	}

	if err := workspace.writeFile(onlineChannelManifestName, exact.ChannelManifest, 0o400); err != nil {
		return "", err
	}
	channelNames := make([]string, len(channelSignatures))
	for index, signature := range channelSignatures {
		name := fmt.Sprintf("channel-signature-%03d.json", index+1)
		if err := workspace.writeFile(name, signature, 0o400); err != nil {
			return "", err
		}
		channelNames[index] = name
	}
	if err := workspace.writeFile(onlineReleaseManifestName, exact.ReleaseManifest, 0o400); err != nil {
		return "", err
	}
	releaseNames := make([]string, len(releaseSignatures))
	for index, signature := range releaseSignatures {
		name := fmt.Sprintf("release-signature-%03d.json", index+1)
		if err := workspace.writeFile(name, signature, 0o400); err != nil {
			return "", err
		}
		releaseNames[index] = name
	}
	artifactIdentity, err := workspace.sealArtifactUsing(artifact, hooks)
	if err != nil {
		return "", err
	}
	descriptorRaw, err := EncodeInstallSnapshotDescriptor(InstallSnapshotDescriptor{
		Schema:            InstallSnapshotSchema,
		RootUpdates:       rootNames,
		ChannelManifest:   onlineChannelManifestName,
		ChannelSignatures: channelNames,
		ReleaseManifest:   onlineReleaseManifestName,
		ReleaseSignatures: releaseNames,
		Artifact:          onlineArtifactName,
	})
	if err != nil {
		return "", fmt.Errorf("encode online install snapshot descriptor: %w", err)
	}
	if err := workspace.writeFile(InstallSnapshotFile, descriptorRaw, 0o400); err != nil {
		return "", err
	}
	syncWorkspace := hooks.syncWorkspace
	if syncWorkspace == nil {
		syncWorkspace = func(workspace *onlineWorkspace) error { return workspace.sync() }
	}
	if err := syncWorkspace(workspace); err != nil {
		return "", fmt.Errorf("sync materialized online snapshot: %w", err)
	}
	if hooks.beforeReadback != nil {
		hooks.beforeReadback()
	}
	if err := workspace.validateMaterializedEntrySet(rootNames, channelNames, releaseNames, artifactIdentity); err != nil {
		return "", fmt.Errorf("materialized online snapshot readback: %w", err)
	}
	readback, err := OpenMetadataSnapshot(workspace.path)
	if err != nil {
		return "", fmt.Errorf("open materialized online snapshot readback: %w", err)
	}
	if !bytes.Equal(readback.Metadata.ChannelManifest, exact.ChannelManifest) ||
		!bytes.Equal(readback.Metadata.ReleaseManifest, exact.ReleaseManifest) ||
		!equalOnlineByteSlices(readback.RootUpdates, exact.RootUpdates) ||
		!equalOnlineByteSlices(readback.Metadata.ChannelSignatures, channelSignatures) ||
		!equalOnlineByteSlices(readback.Metadata.ReleaseSignatures, releaseSignatures) ||
		readback.Artifact.Path != filepath.Join(workspace.path, onlineArtifactName) ||
		readback.Artifact.Identity != artifactIdentity {
		return "", errors.New("materialized online snapshot readback changed exact bytes or artifact identity")
	}
	return workspace.path, nil
}

func sortOnlineSignatureBytes(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for index, value := range values {
		result[index] = append([]byte(nil), value...)
	}
	sort.Slice(result, func(left, right int) bool {
		leftDigest := sha256.Sum256(result[left])
		rightDigest := sha256.Sum256(result[right])
		if compared := bytes.Compare(leftDigest[:], rightDigest[:]); compared != 0 {
			return compared < 0
		}
		return bytes.Compare(result[left], result[right]) < 0
	})
	return result
}

func equalOnlineByteSlices(left, right [][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !bytes.Equal(left[index], right[index]) {
			return false
		}
	}
	return true
}

func (workspace *onlineWorkspace) validateMaterializedEntrySet(rootNames, channelNames, releaseNames []string, artifactIdentity SourceFileIdentity) error {
	inspected, err := inspectOnlineWorkspace(workspace.parent.root, workspace.name, workspace.parent.uid)
	if err != nil {
		return err
	}
	want := make(map[string]struct{}, 4+len(rootNames)+len(channelNames)+len(releaseNames))
	for _, name := range []string{onlineChannelManifestName, onlineReleaseManifestName, onlineArtifactName, InstallSnapshotFile} {
		want[name] = struct{}{}
	}
	for _, name := range channelNames {
		want[name] = struct{}{}
	}
	for _, name := range rootNames {
		want[name] = struct{}{}
	}
	for _, name := range releaseNames {
		want[name] = struct{}{}
	}
	if len(inspected.files) != len(want) {
		return fmt.Errorf("workspace entry count is %d, want %d", len(inspected.files), len(want))
	}
	for name := range inspected.files {
		if _, ok := want[name]; !ok {
			return fmt.Errorf("unexpected materialized workspace entry %q", name)
		}
	}
	artifactInfo, err := workspace.root.Lstat(onlineArtifactName)
	actualArtifact, ok := sourceIdentity(artifactInfo)
	if err != nil || !ok || actualArtifact != artifactIdentity {
		return errors.New("materialized artifact identity changed")
	}
	return nil
}

func (workspace *onlineWorkspace) sync() error {
	if err := workspace.validateAnchor(); err != nil {
		return err
	}
	return syncRootDirectory(workspace.root)
}

func (workspace *onlineWorkspace) validateAnchor() error {
	if workspace == nil || workspace.parent == nil || workspace.root == nil || workspace.name == "" || workspace.path == "" {
		return errors.New("online workspace is not open")
	}
	if err := workspace.parent.validateHeld(); err != nil {
		return err
	}
	pathInfo, pathErr := os.Lstat(workspace.path)
	parentInfo, parentErr := workspace.parent.root.Lstat(workspace.name)
	rootInfo, rootErr := workspace.root.Stat(".")
	if pathErr != nil || parentErr != nil || rootErr != nil ||
		!os.SameFile(workspace.info, pathInfo) || !os.SameFile(workspace.info, parentInfo) || !os.SameFile(workspace.info, rootInfo) ||
		validateOnlinePrivateDirectoryInfo(rootInfo, workspace.parent.uid, true) != nil {
		return errors.New("online workspace identity changed")
	}
	return nil
}

func (workspace *onlineWorkspace) remove() error {
	if workspace == nil || workspace.root == nil {
		return nil
	}
	if err := workspace.validateAnchor(); err != nil {
		return err
	}
	inspected, err := inspectOnlineWorkspace(workspace.parent.root, workspace.name, workspace.parent.uid)
	if err != nil {
		return fmt.Errorf("inspect owned online workspace before removal: %w", err)
	}
	if inspected.directory.device == 0 || inspected.directory.inode == 0 {
		return errors.New("owned online workspace has invalid identity")
	}
	if err := workspace.root.Close(); err != nil {
		return fmt.Errorf("close owned online workspace root: %w", err)
	}
	workspace.root = nil
	if err := workspace.parent.validateHeld(); err != nil {
		return err
	}
	current, err := inspectOnlineWorkspace(workspace.parent.root, workspace.name, workspace.parent.uid)
	if err != nil || !sameInspectedOnlineWorkspace(inspected, current) {
		return errors.New("owned online workspace changed before removal")
	}
	if err := workspace.parent.root.RemoveAll(workspace.name); err != nil {
		return fmt.Errorf("remove owned online workspace: %w", err)
	}
	if err := syncRootDirectory(workspace.parent.root); err != nil {
		return fmt.Errorf("sync owned online workspace removal: %w", err)
	}
	if workspace.parent.activeWorkspace == workspace.name {
		workspace.parent.activeWorkspace = ""
	}
	workspace.parent = nil
	workspace.name = ""
	workspace.path = ""
	workspace.info = nil
	return nil
}

func (lock *onlineIntakeLock) Close() error {
	if lock == nil {
		return nil
	}
	var unlockErr, fileErr, dirErr, rootErr error
	if lock.file != nil {
		unlockErr = syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
		fileErr = lock.file.Close()
	}
	if lock.dir != nil {
		dirErr = lock.dir.Close()
	}
	if lock.root != nil {
		rootErr = lock.root.Close()
	}
	lock.root = nil
	lock.dir = nil
	lock.file = nil
	lock.rootInfo = nil
	lock.activeWorkspace = ""
	return errors.Join(unlockErr, fileErr, dirErr, rootErr)
}

func onlineWorkspaceFilePolicy(name string) (maximum int64, artifact bool, err error) {
	switch name {
	case onlineChannelManifestName, onlineReleaseManifestName:
		return releasetrust.MaxManifestSize, false, nil
	case onlineArtifactName:
		return releasetrust.MaxArtifactSize, true, nil
	case InstallSnapshotFile:
		return maxInstallSnapshotSize, false, nil
	}
	if match := onlineRootUpdateNamePattern.FindStringSubmatch(name); match != nil {
		index, parseErr := strconv.Atoi(match[1])
		if parseErr != nil || index < 0 || index >= releasetrust.MaxRootUpdatesPerInput {
			return 0, false, errors.New("root update index is outside the supported range")
		}
		return releasetrust.MaxRootUpdateSize, false, nil
	}
	match := onlineSignatureNamePattern.FindStringSubmatch(name)
	if match == nil {
		return 0, false, errors.New("name is not in the online workspace allowlist")
	}
	index, err := strconv.Atoi(match[2])
	if err != nil || index < 1 || index > releasetrust.MaxSignatureEnvelopes {
		return 0, false, errors.New("signature index is outside the supported range")
	}
	return releasetrust.MaxEnvelopeSize, false, nil
}

func validateOnlineWorkspaceFile(info os.FileInfo, expectedUID uint32, maximum int64, artifact bool) error {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("must be a regular file, not a symlink or special object")
	}
	mode := info.Mode().Perm()
	if artifact {
		if mode != 0o600 && mode != 0o400 {
			return errors.New("artifact mode must be exactly 0600 or 0400")
		}
	} else if mode != 0o400 {
		return errors.New("metadata mode must be exactly 0400")
	}
	if info.Size() < 0 || info.Size() > maximum {
		return fmt.Errorf("size must be between 0 and %d", maximum)
	}
	identity, ok := onlineIdentityFromInfo(info)
	if !ok || identity.uid != expectedUID {
		return errors.New("file owner does not match the online intake owner")
	}
	if identity.links != 1 {
		return errors.New("file must have exactly one link")
	}
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("file must not have special mode bits")
	}
	return nil
}

func validateOnlinePrivateRegular(info os.FileInfo, expectedUID uint32, mode os.FileMode, maximum int64, allowEmpty bool) error {
	if err := validateOnlineWorkspaceFile(info, expectedUID, maximum, mode == 0o600); err != nil {
		return err
	}
	if info.Mode().Perm() != mode {
		return fmt.Errorf("mode must be exactly %04o", mode)
	}
	if !allowEmpty && info.Size() == 0 {
		return errors.New("file must not be empty")
	}
	return nil
}

func validateOnlinePrivateDirectoryPath(path string, expectedUID uint32) error {
	if err := validateSecureAncestorChain(path, true); err != nil {
		return fmt.Errorf("validate online intake ancestry: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return validateOnlinePrivateDirectoryInfo(info, expectedUID, false)
}

func validateOnlinePrivateDirectoryInfo(info os.FileInfo, expectedUID uint32, empty bool) error {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("online intake directory must be a real mode-0700 directory without special bits")
	}
	identity, ok := onlineIdentityFromInfo(info)
	if !ok || identity.uid != expectedUID {
		return errors.New("online intake directory owner does not match the expected UID")
	}
	if empty && identity.links != 2 {
		return errors.New("online workspace directory must have link count 2")
	}
	return nil
}

func onlineIdentityFromInfo(info os.FileInfo) (onlineFileIdentity, bool) {
	if info == nil {
		return onlineFileIdentity{}, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return onlineFileIdentity{}, false
	}
	return onlineFileIdentity{
		device: uint64(stat.Dev), inode: stat.Ino, links: uint64(stat.Nlink), mode: stat.Mode,
		uid: stat.Uid, gid: stat.Gid, size: stat.Size,
		mtimeSeconds: stat.Mtim.Sec, mtimeNanoseconds: stat.Mtim.Nsec,
		ctimeSeconds: stat.Ctim.Sec, ctimeNanoseconds: stat.Ctim.Nsec,
	}, true
}

func randomOnlineWorkspaceName() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", err
	}
	return onlineWorkspacePrefix + hex.EncodeToString(value[:]), nil
}

func cleanOnlineErrorText(value string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(value)
}
